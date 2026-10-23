// Package qore implements the offline, single-device encrypted vault profile.
// Its local journal is not a network authority or enrollment protocol.
package qore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/qore-project/qore-lib/internal/vaultfmt"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrInvalid  = vaultfmt.ErrInvalid
	ErrCorrupt  = vaultfmt.ErrCorrupt
	ErrPassword = vaultfmt.ErrPassword
	ErrLimit    = vaultfmt.ErrLimit
	ErrNotFound = vaultfmt.ErrNotFound
	ErrClosed   = errors.New("qore: vault closed")
	ErrConflict = errors.New("qore: unresolved item conflict")
	ErrDeleted  = errors.New("qore: item deleted")
	ErrLocked   = errors.New("qore: vault locked")
	// ErrCommitUncertain means a storage commit failed after publication may
	// have begun. The handle is closed; reopen and inspect before retrying.
	ErrCommitUncertain = errors.New("qore: storage commit outcome uncertain; reopen vault")
)

const (
	DefaultChunkSize = vaultfmt.DefaultChunkSize
	MinChunkSize     = vaultfmt.MinChunkSize
	MaxChunkSize     = vaultfmt.MaxChunkSize
)

type PutOptions struct {
	ItemID     string
	Name       string
	Kind       string
	ChunkSize  int
	Supersedes []string
}

type Revision struct {
	ID         string   `json:"id"`
	ItemID     string   `json:"item_id"`
	Name       string   `json:"name,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Size       uint64   `json:"size"`
	Deleted    bool     `json:"deleted"`
	Sequence   uint64   `json:"sequence"`
	Supersedes []string `json:"supersedes"`
	Current    bool     `json:"current"`
}

type Item struct {
	ID         string     `json:"id"`
	Candidates []Revision `json:"candidates"`
	Conflict   bool       `json:"conflict"`
}

type Info struct {
	VaultID       string `json:"vault_id"`
	RevisionCount uint64 `json:"revision_count"`
	ItemCount     int    `json:"item_count"`
}

// Vault serializes all operations, including readers and Close. Callers must
// not reenter the same Vault from a reader or writer supplied to an operation.
// Keys are cleared on Close on a best-effort basis; Go memory is not secure memory.
type Vault struct {
	mu       sync.Mutex
	db       *bolt.DB
	vault    vaultfmt.ID
	genesis  vaultfmt.ID
	keysHash vaultfmt.ID
	public   [ed25519.PublicKeySize]byte
	signing  ed25519.PrivateKey
	storage  vaultfmt.Key
	state    *vaultState
}

type storedRevision struct {
	revision Revision
	commit   vaultfmt.ID
	item     vaultfmt.ID
	ref      *vaultfmt.Ref
}

type vaultState struct {
	history   []*storedRevision
	revisions map[string]*storedRevision
	items     map[string][]*storedRevision
	tip       vaultfmt.ID
}

func emptyState() *vaultState {
	return &vaultState{
		revisions: make(map[string]*storedRevision),
		items:     make(map[string][]*storedRevision),
	}
}

func copyRevision(r Revision) Revision {
	r.Supersedes = append([]string{}, r.Supersedes...)
	return r
}

func (s *vaultState) append(r *storedRevision) {
	for _, id := range r.revision.Supersedes {
		s.revisions[id].revision.Current = false
	}
	r.revision.Current = true
	s.history = append(s.history, r)
	s.revisions[r.revision.ID] = r
	s.items[r.revision.ItemID] = append(s.items[r.revision.ItemID], r)
	s.tip = r.commit
}

func (v *Vault) ready() error {
	if v.db == nil {
		return ErrClosed
	}
	return nil
}

// Close waits for the active operation and clears retained key material.
// Repeated Close calls are harmless.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.closeLocked()
}

// closeLocked also invalidates a handle whose storage outcome is uncertain.
// Its caller owns v.mu, or is still constructing the unpublished Vault.
func (v *Vault) closeLocked() error {
	if v.db == nil {
		return nil
	}
	err := v.db.Close()
	v.db = nil
	clear(v.signing)
	v.signing = nil
	clear(v.storage[:])
	if v.state != nil {
		for _, r := range v.state.history {
			if r.ref != nil {
				clear(r.ref.Key[:])
			}
		}
	}
	v.state = nil
	return err
}

func (v *Vault) Info() (Info, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ready(); err != nil {
		return Info{}, err
	}
	return Info{VaultID: v.vault.String(), RevisionCount: uint64(len(v.state.history)), ItemCount: len(v.state.items)}, nil
}

func validContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	return ctx.Err()
}

func parseRevision(s string) (vaultfmt.ID, error) {
	if len(s) != 66 || !strings.HasSuffix(s, ":0") {
		return vaultfmt.ID{}, ErrInvalid
	}
	return vaultfmt.ParseID(s[:64])
}

func (v *Vault) bases(item vaultfmt.ID, supplied []string) ([]vaultfmt.ID, error) {
	if len(supplied) > vaultfmt.MaxBases {
		return nil, ErrLimit
	}
	out := make([]vaultfmt.ID, len(supplied))
	for i, s := range supplied {
		id, err := parseRevision(s)
		if err != nil || (i > 0 && supplied[i-1] >= s) {
			return nil, ErrInvalid
		}
		r := v.state.revisions[s]
		if r == nil || r.item != item {
			return nil, ErrInvalid
		}
		out[i] = id
	}
	return out, nil
}

// Put publishes one immutable revision. Supersedes is explicit: a stale base
// does not discard newer candidates, and an empty list intentionally branches.
func (v *Vault) Put(ctx context.Context, opts PutOptions, src io.Reader) (Revision, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ready(); err != nil {
		return Revision{}, err
	}
	if err := validContext(ctx); err != nil {
		return Revision{}, err
	}
	if src == nil || opts.Name == "" || len(opts.Name) > vaultfmt.MaxNameBytes || !utf8.ValidString(opts.Name) || (opts.Kind != "text" && opts.Kind != "file") {
		return Revision{}, ErrInvalid
	}
	if opts.ChunkSize == 0 {
		opts.ChunkSize = DefaultChunkSize
	}
	if opts.ChunkSize < MinChunkSize || opts.ChunkSize > MaxChunkSize {
		return Revision{}, ErrInvalid
	}
	if len(v.state.history) >= vaultfmt.MaxRecords {
		return Revision{}, ErrLimit
	}
	var item vaultfmt.ID
	var err error
	if opts.ItemID == "" {
		if len(opts.Supersedes) != 0 {
			return Revision{}, ErrInvalid
		}
		for {
			item, err = vaultfmt.NewID()
			if err != nil {
				return Revision{}, err
			}
			if _, exists := v.state.items[item.String()]; !exists {
				break
			}
		}
	} else {
		item, err = vaultfmt.ParseID(opts.ItemID)
		if err != nil {
			return Revision{}, err
		}
		if _, exists := v.state.items[opts.ItemID]; !exists {
			return Revision{}, ErrNotFound
		}
	}
	bases, err := v.bases(item, opts.Supersedes)
	if err != nil {
		return Revision{}, err
	}
	objects := dbObjects{owner: v, ctx: ctx}
	ref, meta, err := vaultfmt.Store(ctx, objects, v.contentContext(item), opts.Name, opts.Kind, src, opts.ChunkSize)
	if err != nil {
		return Revision{}, err
	}
	defer clear(ref.Key[:])
	return v.commit(ctx, operation{Code: 1, Item: item, Supersedes: bases, Ref: &ref}, meta)
}

func (v *Vault) Delete(ctx context.Context, itemID string, supersedes []string) (Revision, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ready(); err != nil {
		return Revision{}, err
	}
	if err := validContext(ctx); err != nil {
		return Revision{}, err
	}
	item, err := vaultfmt.ParseID(itemID)
	if err != nil {
		return Revision{}, err
	}
	if _, exists := v.state.items[itemID]; !exists {
		return Revision{}, ErrNotFound
	}
	if len(v.state.history) >= vaultfmt.MaxRecords {
		return Revision{}, ErrLimit
	}
	bases, err := v.bases(item, supersedes)
	if err != nil {
		return Revision{}, err
	}
	return v.commit(ctx, operation{Code: 2, Item: item, Supersedes: bases}, vaultfmt.Metadata{})
}

func (v *Vault) List() ([]Item, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ready(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(v.state.items))
	for id := range v.state.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Item, 0, len(ids))
	for _, id := range ids {
		item := Item{ID: id, Candidates: []Revision{}}
		for _, r := range v.state.items[id] {
			if r.revision.Current {
				item.Candidates = append(item.Candidates, copyRevision(r.revision))
			}
		}
		item.Conflict = len(item.Candidates) > 1
		out = append(out, item)
	}
	return out, nil
}

func (v *Vault) History(itemID string) ([]Revision, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ready(); err != nil {
		return nil, err
	}
	if _, err := vaultfmt.ParseID(itemID); err != nil {
		return nil, err
	}
	history, exists := v.state.items[itemID]
	if !exists {
		return nil, ErrNotFound
	}
	out := make([]Revision, 0, len(history))
	for _, r := range history {
		out = append(out, copyRevision(r.revision))
	}
	return out, nil
}

func (v *Vault) Read(ctx context.Context, itemID, revisionID string, dst io.Writer) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ready(); err != nil {
		return err
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	if dst == nil {
		return ErrInvalid
	}
	if _, err := vaultfmt.ParseID(itemID); err != nil {
		return err
	}
	history, exists := v.state.items[itemID]
	if !exists {
		return ErrNotFound
	}
	var selected *storedRevision
	if revisionID != "" {
		if _, err := parseRevision(revisionID); err != nil {
			return err
		}
		selected = v.state.revisions[revisionID]
		if selected == nil || selected.revision.ItemID != itemID {
			return ErrNotFound
		}
	} else {
		for _, r := range history {
			if r.revision.Current {
				if selected != nil {
					return ErrConflict
				}
				selected = r
			}
		}
	}
	if selected == nil {
		return ErrCorrupt
	}
	if selected.revision.Deleted {
		return ErrDeleted
	}
	return vaultfmt.Load(ctx, dbObjects{owner: v, ctx: ctx}, v.contentContext(selected.item), *selected.ref, dst)
}

// Verify revalidates the persisted journal and every historical content chunk,
// including superseded revisions. It does not assert independent freshness.
func (v *Vault) Verify(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ready(); err != nil {
		return err
	}
	if err := validContext(ctx); err != nil {
		return err
	}
	s, err := v.replay(ctx, true)
	if s != nil {
		defer clearStateKeys(s)
	}
	if err != nil {
		return err
	}
	if s.tip != v.state.tip || len(s.history) != len(v.state.history) {
		return ErrCorrupt
	}
	return nil
}

func (v *Vault) contentContext(item vaultfmt.ID) vaultfmt.Context {
	return vaultfmt.Context{Vault: v.vault, Control: v.genesis, Item: item}
}

func clearStateKeys(s *vaultState) {
	for _, r := range s.history {
		if r.ref != nil {
			clear(r.ref.Key[:])
		}
	}
}
