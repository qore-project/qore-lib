package qore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"

	"github.com/qore-project/qore-lib/internal/vaultfmt"
	bolt "go.etcd.io/bbolt"
)

var (
	metaBucket    = []byte("meta")
	objectsBucket = []byte("objects")
	historyBucket = []byte("history")
	keysKey       = []byte("keys")
	genesisKey    = []byte("genesis")
	checkpointKey = []byte("checkpoint")
)

type wrappedSecrets struct {
	_       struct{} `cbor:",toarray"`
	Seed    [32]byte
	Storage vaultfmt.Key
}

type genesisBody struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Suite   uint64
	Vault   vaultfmt.ID
	Public  [32]byte
}

type signedRecord struct {
	_         struct{} `cbor:",toarray"`
	Body      []byte
	Signature [64]byte
}

type historyBody struct {
	_        struct{} `cbor:",toarray"`
	Version  uint64
	Suite    uint64
	Vault    vaultfmt.ID
	Genesis  vaultfmt.ID
	Public   [32]byte
	Sequence uint64
	Previous vaultfmt.ID
	Nonce    vaultfmt.ID
	Envelope []byte
}

type operation struct {
	_          struct{} `cbor:",toarray"`
	Code       uint64
	Item       vaultfmt.ID
	Supersedes []vaultfmt.ID
	Ref        *vaultfmt.Ref
}

type checkpointBody struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Suite   uint64
	Vault   vaultfmt.ID
	Genesis vaultfmt.ID
	Count   uint64
	Tip     vaultfmt.ID
}

type checkpointRecord struct {
	_         struct{} `cbor:",toarray"`
	Body      []byte
	MAC       [32]byte
	Signature [64]byte
}

// Create exclusively creates a new vault without truncating an existing path.
// The parent must exist and be trusted. POSIX uses mode 0600 and synchronizes
// the parent directory. Windows uses an owner-only DACL and write-through
// creation; it cannot promise POSIX-style directory-entry power-loss durability.
func Create(path string, password []byte) (*Vault, error) {
	if path == "" || len(password) == 0 || len(password) > 1024 {
		return nil, ErrInvalid
	}
	id, err := vaultfmt.NewID()
	if err != nil {
		return nil, err
	}
	seed, err := vaultfmt.NewID()
	if err != nil {
		return nil, err
	}
	defer clear(seed[:])
	storage, err := vaultfmt.NewKey()
	if err != nil {
		return nil, err
	}
	defer clear(storage[:])
	secret := wrappedSecrets{Seed: [32]byte(seed), Storage: storage}
	defer clear(secret.Seed[:])
	defer clear(secret.Storage[:])
	plain, err := vaultfmt.Encode(secret)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	wrapped, err := vaultfmt.Wrap(password, id, plain)
	if err != nil {
		return nil, err
	}
	v := &Vault{vault: id, storage: storage, signing: ed25519.NewKeyFromSeed(seed[:]), state: emptyState()}
	copy(v.public[:], v.signing[32:])
	v.keysHash = vaultfmt.ID(sha256.Sum256(wrapped))
	ok := false
	defer func() {
		if !ok {
			if v.db != nil {
				_ = v.Close()
			} else {
				clear(v.signing)
				clear(v.storage[:])
			}
		}
	}()
	body, err := vaultfmt.Encode(genesisBody{Version: 1, Suite: 1, Vault: id, Public: v.public})
	if err != nil {
		return nil, err
	}
	genesis, err := v.signed("local-genesis", body)
	if err != nil {
		return nil, err
	}
	v.genesis = vaultfmt.Hash("local-genesis", genesis)
	checkpoint, err := v.checkpoint(0, vaultfmt.ID{})
	if err != nil {
		return nil, err
	}
	file, err := privateFile(path, true)
	if err != nil {
		return nil, err
	}
	v.db, err = openDatabase(path, file)
	if err != nil {
		return nil, err
	}
	if err = v.update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucket(metaBucket)
		if err != nil {
			return err
		}
		if _, err = tx.CreateBucket(objectsBucket); err != nil {
			return err
		}
		if _, err = tx.CreateBucket(historyBucket); err != nil {
			return err
		}
		if err = meta.Put(keysKey, wrapped); err != nil {
			return err
		}
		if err = meta.Put(genesisKey, genesis); err != nil {
			return err
		}
		return meta.Put(checkpointKey, checkpoint)
	}); err != nil {
		return nil, err
	}
	if err = v.db.Sync(); err != nil {
		return nil, err
	}
	if err = syncParent(path); err != nil {
		return nil, err
	}
	ok = true
	return v, nil
}

// Open never creates or initializes a missing or empty file. The wrapped keys
// pin the vault and signing identity before any journal operation is admitted.
func Open(path string, password []byte) (*Vault, error) {
	if path == "" || len(password) == 0 || len(password) > 1024 {
		return nil, ErrInvalid
	}
	file, err := privateFile(path, false)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() < 4096 {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrCorrupt
	}
	db, err := openDatabase(path, file)
	if err != nil {
		return nil, err
	}
	v := &Vault{db: db}
	ok := false
	defer func() {
		if !ok {
			_ = v.Close()
		}
	}()
	var wrapped []byte
	err = db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if meta == nil {
			return ErrCorrupt
		}
		var e error
		wrapped, e = boundedValue(meta, keysKey, 8192)
		return e
	})
	if err != nil {
		return nil, err
	}
	var wrappedPlain []byte
	v.vault, wrappedPlain, err = vaultfmt.Unwrap(password, wrapped)
	if err != nil {
		return nil, err
	}
	defer clear(wrappedPlain)
	var secret wrappedSecrets
	defer clear(secret.Seed[:])
	defer clear(secret.Storage[:])
	if err = vaultfmt.Decode(wrappedPlain, 4096, &secret); err != nil {
		return nil, errors.Join(ErrCorrupt, err)
	}
	v.signing = ed25519.NewKeyFromSeed(secret.Seed[:])
	copy(v.public[:], v.signing[32:])
	v.storage = secret.Storage
	v.keysHash = vaultfmt.ID(sha256.Sum256(wrapped))
	// Learn the genesis ID only after authenticating it against the wrapped pin.
	err = db.View(func(tx *bolt.Tx) error {
		encoded, e := boundedValue(tx.Bucket(metaBucket), genesisKey, vaultfmt.MaxRecordBytes)
		if e != nil {
			return e
		}
		if e = v.validateGenesis(encoded); e != nil {
			return e
		}
		v.genesis = vaultfmt.Hash("local-genesis", encoded)
		return nil
	})
	if err != nil {
		return nil, err
	}
	v.state, err = v.replay(context.Background(), false)
	if err != nil {
		return nil, err
	}
	ok = true
	return v, nil
}

func openDatabase(path string, file *os.File) (*bolt.DB, error) {
	used := false
	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout: time.Second,
		// Durable defaults are intentional: bbolt synchronizes both data and
		// metadata before accepting each transaction, including on Windows.
		OpenFile: func(_ string, _ int, _ os.FileMode) (*os.File, error) {
			if used {
				return nil, ErrInvalid
			}
			used = true
			return file, nil
		},
	})
	if !used {
		_ = file.Close()
	}
	if errors.Is(err, bolt.ErrTimeout) {
		return nil, ErrLocked
	}
	if errors.Is(err, bolt.ErrInvalid) || errors.Is(err, bolt.ErrChecksum) || errors.Is(err, bolt.ErrVersionMismatch) {
		return nil, errors.Join(ErrCorrupt, err)
	}
	return db, err
}

func boundedValue(bucket *bolt.Bucket, key []byte, max int) ([]byte, error) {
	if bucket == nil {
		return nil, ErrCorrupt
	}
	value := bucket.Get(key)
	if len(value) == 0 {
		return nil, ErrCorrupt
	}
	if len(value) > max {
		return nil, errors.Join(ErrCorrupt, ErrLimit)
	}
	return bytes.Clone(value), nil
}

func (v *Vault) signed(label string, body []byte) ([]byte, error) {
	record := signedRecord{Body: body}
	copy(record.Signature[:], vaultfmt.Sign(v.signing, label, body))
	return vaultfmt.Encode(record)
}

func (v *Vault) checkpoint(count uint64, tip vaultfmt.ID) ([]byte, error) {
	body, err := vaultfmt.Encode(checkpointBody{Version: 1, Suite: 1, Vault: v.vault, Genesis: v.genesis, Count: count, Tip: tip})
	if err != nil {
		return nil, err
	}
	record := checkpointRecord{Body: body}
	copy(record.MAC[:], vaultfmt.MAC(v.storage, v.vault, "local-state", body))
	copy(record.Signature[:], vaultfmt.Sign(v.signing, "local-checkpoint", body))
	return vaultfmt.Encode(record)
}

func (v *Vault) validateGenesis(encoded []byte) error {
	var record signedRecord
	var body genesisBody
	if vaultfmt.Decode(encoded, vaultfmt.MaxRecordBytes, &record) != nil || vaultfmt.Decode(record.Body, vaultfmt.MaxRecordBytes, &body) != nil {
		return ErrCorrupt
	}
	if body.Version != 1 || body.Suite != 1 || body.Vault != v.vault || body.Public != v.public || !vaultfmt.Verify(ed25519.PublicKey(v.public[:]), "local-genesis", record.Body, record.Signature[:]) {
		return ErrCorrupt
	}
	return nil
}

func (v *Vault) replay(ctx context.Context, full bool) (*vaultState, error) {
	state := emptyState()
	err := v.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		meta, history, objects := tx.Bucket(metaBucket), tx.Bucket(historyBucket), tx.Bucket(objectsBucket)
		if meta == nil || history == nil || objects == nil {
			return ErrCorrupt
		}
		keys, err := boundedValue(meta, keysKey, 8192)
		if err != nil {
			return err
		}
		if vaultfmt.ID(sha256.Sum256(keys)) != v.keysHash {
			return ErrCorrupt
		}
		genesis, err := boundedValue(meta, genesisKey, vaultfmt.MaxRecordBytes)
		if err != nil {
			return err
		}
		if err = v.validateGenesis(genesis); err != nil || vaultfmt.Hash("local-genesis", genesis) != v.genesis {
			return ErrCorrupt
		}
		encoded, err := boundedValue(meta, checkpointKey, vaultfmt.MaxRecordBytes)
		if err != nil {
			return err
		}
		var checkpoint checkpointRecord
		var body checkpointBody
		if vaultfmt.Decode(encoded, vaultfmt.MaxRecordBytes, &checkpoint) != nil || vaultfmt.Decode(checkpoint.Body, vaultfmt.MaxRecordBytes, &body) != nil {
			return ErrCorrupt
		}
		if body.Version != 1 || body.Suite != 1 || body.Vault != v.vault || body.Genesis != v.genesis || body.Count > vaultfmt.MaxRecords || (body.Count == 0 && body.Tip != (vaultfmt.ID{})) {
			return ErrCorrupt
		}
		if !hmac.Equal(checkpoint.MAC[:], vaultfmt.MAC(v.storage, v.vault, "local-state", checkpoint.Body)) || !vaultfmt.Verify(ed25519.PublicKey(v.public[:]), "local-checkpoint", checkpoint.Body, checkpoint.Signature[:]) {
			return ErrCorrupt
		}
		store := txObjects{bucket: objects, ctx: ctx}
		cursor := history.Cursor()
		var count uint64
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			if err = ctx.Err(); err != nil {
				return err
			}
			if count >= body.Count || count >= vaultfmt.MaxRecords || len(key) != 8 || binary.BigEndian.Uint64(key) != count || len(value) == 0 || len(value) > vaultfmt.MaxRecordBytes {
				return ErrCorrupt
			}
			r, e := v.decodeCommit(value, count, state, store)
			if e != nil {
				return e
			}
			state.append(r)
			if full && r.ref != nil {
				if e = vaultfmt.Load(ctx, store, v.contentContext(r.item), *r.ref, io.Discard); e != nil {
					return corruptionUnlessCanceled(ctx, e)
				}
			}
			count++
		}
		if count != body.Count || state.tip != body.Tip {
			return ErrCorrupt
		}
		return ctx.Err()
	})
	if err != nil {
		clearStateKeys(state)
		return nil, err
	}
	return state, nil
}

func corruptionUnlessCanceled(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(ErrCorrupt, err)
}

func (v *Vault) decodeCommit(encoded []byte, sequence uint64, state *vaultState, objects vaultfmt.Objects) (*storedRevision, error) {
	var record signedRecord
	var body historyBody
	if vaultfmt.Decode(encoded, vaultfmt.MaxRecordBytes, &record) != nil || vaultfmt.Decode(record.Body, vaultfmt.MaxRecordBytes, &body) != nil {
		return nil, ErrCorrupt
	}
	if body.Version != 1 || body.Suite != 1 || body.Vault != v.vault || body.Genesis != v.genesis || body.Public != v.public || body.Sequence != sequence || body.Previous != state.tip || !vaultfmt.Verify(ed25519.PublicKey(v.public[:]), "local-commit", record.Body, record.Signature[:]) {
		return nil, ErrCorrupt
	}
	ctx := vaultfmt.Context{Vault: v.vault, Control: v.genesis, Content: body.Nonce, Role: vaultfmt.RoleOperation, Index: sequence}
	plain, err := vaultfmt.Open(v.storage, ctx, vaultfmt.Hash("object", body.Envelope), body.Envelope, vaultfmt.MaxRecordBytes)
	if err != nil {
		return nil, errors.Join(ErrCorrupt, err)
	}
	defer clear(plain)
	var op operation
	defer func() {
		if op.Ref != nil {
			clear(op.Ref.Key[:])
		}
	}()
	if vaultfmt.Decode(plain, vaultfmt.MaxRecordBytes, &op) != nil {
		return nil, ErrCorrupt
	}
	if (op.Code != 1 && op.Code != 2) || (op.Code == 1) != (op.Ref != nil) || len(op.Supersedes) > vaultfmt.MaxBases {
		return nil, ErrCorrupt
	}
	_, existing := state.items[op.Item.String()]
	if !existing && (op.Code != 1 || len(op.Supersedes) != 0) {
		return nil, ErrCorrupt
	}
	for i, id := range op.Supersedes {
		if i > 0 && bytes.Compare(op.Supersedes[i-1][:], id[:]) >= 0 {
			return nil, ErrCorrupt
		}
		r := state.revisions[id.String()+":0"]
		if r == nil || r.item != op.Item {
			return nil, ErrCorrupt
		}
	}
	var meta vaultfmt.Metadata
	if op.Ref != nil {
		meta, err = vaultfmt.Inspect(objects, v.contentContext(op.Item), *op.Ref)
		if err != nil {
			return nil, errors.Join(ErrCorrupt, err)
		}
	}
	id := vaultfmt.Hash("local-commit", encoded)
	if state.revisions[id.String()+":0"] != nil {
		return nil, ErrCorrupt
	}
	return makeRevision(id, sequence, op, meta), nil
}

func makeRevision(id vaultfmt.ID, sequence uint64, op operation, meta vaultfmt.Metadata) *storedRevision {
	r := &storedRevision{commit: id, item: op.Item, revision: Revision{
		ID: id.String() + ":0", ItemID: op.Item.String(), Name: meta.Name, Kind: meta.Kind,
		Size: meta.Size, Deleted: op.Code == 2, Sequence: sequence, Supersedes: make([]string, len(op.Supersedes)), Current: true,
	}}
	for i, base := range op.Supersedes {
		r.revision.Supersedes[i] = base.String() + ":0"
	}
	if op.Ref != nil {
		ref := *op.Ref
		r.ref = &ref
	}
	return r
}

func (v *Vault) commit(ctx context.Context, op operation, meta vaultfmt.Metadata) (Revision, error) {
	if err := ctx.Err(); err != nil {
		return Revision{}, err
	}
	sequence := uint64(len(v.state.history))
	nonce, err := vaultfmt.NewID()
	if err != nil {
		return Revision{}, err
	}
	plain, err := vaultfmt.Encode(op)
	if err != nil {
		return Revision{}, err
	}
	defer clear(plain)
	_, envelope, err := vaultfmt.Seal(v.storage, vaultfmt.Context{Vault: v.vault, Control: v.genesis, Content: nonce, Role: vaultfmt.RoleOperation, Index: sequence}, plain)
	if err != nil {
		return Revision{}, err
	}
	body, err := vaultfmt.Encode(historyBody{Version: 1, Suite: 1, Vault: v.vault, Genesis: v.genesis, Public: v.public, Sequence: sequence, Previous: v.state.tip, Nonce: nonce, Envelope: envelope})
	if err != nil {
		return Revision{}, err
	}
	encoded, err := v.signed("local-commit", body)
	if err != nil {
		return Revision{}, err
	}
	if len(encoded) > vaultfmt.MaxRecordBytes {
		return Revision{}, ErrLimit
	}
	id := vaultfmt.Hash("local-commit", encoded)
	next, err := v.checkpoint(sequence+1, id)
	if err != nil {
		return Revision{}, err
	}
	previous, err := v.checkpoint(sequence, v.state.tip)
	if err != nil {
		return Revision{}, err
	}
	r := makeRevision(id, sequence, op, meta)
	err = v.update(func(tx *bolt.Tx) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		meta, history := tx.Bucket(metaBucket), tx.Bucket(historyBucket)
		if meta == nil || history == nil || !bytes.Equal(meta.Get(checkpointKey), previous) {
			return ErrCorrupt
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], sequence)
		if history.Get(key[:]) != nil {
			return ErrCorrupt
		}
		if e := history.Put(key[:], encoded); e != nil {
			return e
		}
		if e := meta.Put(checkpointKey, next); e != nil {
			return e
		}
		// Cancellation before publication rolls back both writes. Once bbolt
		// commits durably, return success even if cancellation races afterward.
		return ctx.Err()
	})
	if err != nil {
		if r.ref != nil {
			clear(r.ref.Key[:])
		}
		return Revision{}, err
	}
	v.state.append(r)
	return copyRevision(r.revision), nil
}

// update separates a callback rollback from a storage commit failure. bbolt
// may already have written a new metadata page when its final sync fails;
// serving the old in-memory state after that error would be incorrect.
func (v *Vault) update(fn func(*bolt.Tx) error) error {
	tx, err := v.db.Begin(true)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		// Release the transaction before Close, including unusual Commit errors.
		_ = tx.Rollback()
		return errors.Join(ErrCommitUncertain, err, v.closeLocked())
	}
	return nil
}

type dbObjects struct {
	owner *Vault
	ctx   context.Context
}

func (o dbObjects) PutObject(id vaultfmt.ID, value []byte) error {
	if err := o.ctx.Err(); err != nil {
		return err
	}
	if len(value) == 0 || len(value) > vaultfmt.MaxChunkSize+vaultfmt.MaxRecordBytes || vaultfmt.Hash("object", value) != id {
		return ErrInvalid
	}
	return o.owner.update(func(tx *bolt.Tx) error {
		if err := o.ctx.Err(); err != nil {
			return err
		}
		bucket := tx.Bucket(objectsBucket)
		if bucket == nil {
			return ErrCorrupt
		}
		if old := bucket.Get(id[:]); old != nil {
			if !bytes.Equal(old, value) {
				return ErrCorrupt
			}
			return nil
		}
		return bucket.Put(id[:], value)
	})
}

func (o dbObjects) GetObject(id vaultfmt.ID, maxBytes int) ([]byte, error) {
	var value []byte
	err := o.owner.db.View(func(tx *bolt.Tx) error {
		var err error
		value, err = (txObjects{bucket: tx.Bucket(objectsBucket), ctx: o.ctx}).GetObject(id, maxBytes)
		return err
	})
	return value, err
}

type txObjects struct {
	bucket *bolt.Bucket
	ctx    context.Context
}

func (o txObjects) PutObject(vaultfmt.ID, []byte) error { return ErrInvalid }

func (o txObjects) GetObject(id vaultfmt.ID, maxBytes int) ([]byte, error) {
	if err := o.ctx.Err(); err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > vaultfmt.MaxChunkSize+vaultfmt.MaxRecordBytes {
		return nil, ErrLimit
	}
	return boundedValue(o.bucket, id[:], maxBytes)
}
