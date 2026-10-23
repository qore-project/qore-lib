package qore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/qore-project/qore-lib/internal/vaultfmt"
	bolt "go.etcd.io/bbolt"
)

var testPassword = []byte("synthetic-test-password")

func createTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Create(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, path
}

func putText(t *testing.T, v *Vault, item, name, text string, bases ...string) Revision {
	t.Helper()
	sort.Strings(bases)
	r, err := v.Put(context.Background(), PutOptions{ItemID: item, Name: name, Kind: "text", Supersedes: bases}, strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readText(t *testing.T, v *Vault, item, revision string) string {
	t.Helper()
	var out bytes.Buffer
	if err := v.Read(context.Background(), item, revision, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestStaleBaseConflictAndExplicitResolution(t *testing.T) {
	v, path := createTestVault(t)
	a := putText(t, v, "", "name-a", "original")
	b := putText(t, v, a.ItemID, "name-b", "newer", a.ID)
	c := putText(t, v, a.ItemID, "name-c", "stale edit", a.ID)
	if err := v.Read(context.Background(), a.ItemID, "", io.Discard); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale-base branch silently resolved: %v", err)
	}
	items, err := v.List()
	if err != nil || len(items) != 1 || !items[0].Conflict || len(items[0].Candidates) != 2 {
		t.Fatalf("candidates: %#v, %v", items, err)
	}
	if items[0].Candidates[0].ID != b.ID || items[0].Candidates[1].ID != c.ID {
		t.Fatal("stale update discarded unreviewed candidate")
	}
	deleted, err := v.Delete(context.Background(), a.ItemID, []string{b.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Read(context.Background(), a.ItemID, "", io.Discard); !errors.Is(err, ErrConflict) {
		t.Fatalf("Put/Delete conflict hidden: %v", err)
	}
	resolved := putText(t, v, a.ItemID, "resolved", "reviewed both", c.ID, deleted.ID)
	if got := readText(t, v, a.ItemID, ""); got != "reviewed both" {
		t.Fatal(got)
	}
	if got := readText(t, v, a.ItemID, a.ID); got != "original" {
		t.Fatal("historical content lost")
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	history, err := reopened.History(a.ItemID)
	if err != nil || len(history) != 5 {
		t.Fatalf("history after reopen: %#v %v", history, err)
	}
	for i, r := range history {
		if r.Sequence != uint64(i) || r.Current != (r.ID == resolved.ID) {
			t.Fatalf("incorrect replay state: %#v", r)
		}
	}
	if err = reopened.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDeletionBranchesAndReturnedValuesAreIsolated(t *testing.T) {
	v, _ := createTestVault(t)
	a := putText(t, v, "", "secret-name", "retained secret")
	b := putText(t, v, a.ItemID, "updated-name", "updated", a.ID)
	b.Supersedes[0] = "mutated return"
	history, err := v.History(a.ItemID)
	if err != nil || history[1].Supersedes[0] != a.ID {
		t.Fatalf("Put result aliases state: %#v %v", history, err)
	}
	history[1].Supersedes[0] = "mutated history"
	items, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	items[0].Candidates[0].Supersedes[0] = "mutated list"
	fresh, err := v.History(a.ItemID)
	if err != nil || fresh[1].Supersedes[0] != a.ID {
		t.Fatalf("returned slices alias mutable state: %#v %v", fresh, err)
	}
	del, err := v.Delete(context.Background(), a.ItemID, []string{b.ID})
	if err != nil || !del.Deleted {
		t.Fatalf("delete: %#v %v", del, err)
	}
	if err = v.Read(context.Background(), a.ItemID, "", io.Discard); !errors.Is(err, ErrDeleted) {
		t.Fatalf("tombstone read: %v", err)
	}
	if got := readText(t, v, a.ItemID, a.ID); got != "retained secret" {
		t.Fatal(got)
	}
	items, err = v.List()
	if err != nil || len(items) != 1 || items[0].Conflict || len(items[0].Candidates) != 1 || !items[0].Candidates[0].Deleted {
		t.Fatalf("tombstone absent from list: %#v %v", items, err)
	}
	branch := putText(t, v, a.ItemID, "intentional branch", "resurrected without review")
	if err = v.Read(context.Background(), a.ItemID, "", io.Discard); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty-base branch implicitly superseded deletion: %v", err)
	}
	if got := readText(t, v, a.ItemID, branch.ID); got != "resurrected without review" {
		t.Fatal(got)
	}
	other := putText(t, v, "", "other", "other")
	if _, err = v.Delete(context.Background(), a.ItemID, []string{other.ID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-item supersession accepted: %v", err)
	}
	if _, err = v.Delete(context.Background(), a.ItemID, []string{a.ID, a.ID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate supersession accepted: %v", err)
	}
	if err = v.Read(context.Background(), a.ItemID, other.ID, io.Discard); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-item historical read accepted: %v", err)
	}
}

func TestPasswordTamperLockAndNoPlaintextPersistence(t *testing.T) {
	v, path := createTestVault(t)
	name := "distinctive-secret-name-never-persisted"
	payload := "distinctive-plaintext-content-never-persisted-73628014"
	putText(t, v, "", name, payload)
	if _, err := Open(path, testPassword); !errors.Is(err, ErrLocked) {
		t.Fatalf("second writer not bounded/locked: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte(name), []byte(payload), testPassword} {
		if bytes.Contains(raw, secret) {
			t.Fatal("plaintext persisted in database")
		}
	}
	if _, err = Open(path, []byte("incorrect password")); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	opened, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err = opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = opened.Info(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed vault still usable: %v", err)
	}
}

func TestExclusiveCreationAndNonregularRejection(t *testing.T) {
	_, path := createTestVault(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, e := Create(path, testPassword); e == nil {
		_ = duplicate.Close()
		t.Fatal("Create overwrote existing vault")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed exclusive creation changed file: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err = Open(missing, testPassword); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing Open: %v", err)
	}
	if _, err = os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Open created a missing file")
	}
	if _, err = Open(t.TempDir(), testPassword); !errors.Is(err, ErrInvalid) {
		t.Fatalf("directory accepted: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err = os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(empty, testPassword); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("empty existing file initialized: %v", err)
	}
	info, err := os.Stat(empty)
	if err != nil || info.Size() != 0 {
		t.Fatal("Open mutated empty file")
	}
	if runtime.GOOS != "windows" {
		info, err = os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("vault not private: %v %v", info, err)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err = os.Symlink(path, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err = Open(link, testPassword); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink accepted: %v", err)
	}
}

type packetReader struct {
	data   []byte
	packet int
}

func (r *packetReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) > r.packet {
		p = p[:r.packet]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestShortReadsEmptyAndFinalChunkRoundTrip(t *testing.T) {
	v, path := createTestVault(t)
	for _, size := range []int{0, MinChunkSize, 2*MinChunkSize + 37} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte((i*17 + 31) % 251)
		}
		r, err := v.Put(context.Background(), PutOptions{Name: "bounded-file", Kind: "file", ChunkSize: MinChunkSize}, &packetReader{data: data, packet: 137})
		if err != nil || r.Size != uint64(size) {
			t.Fatalf("size %d: %#v %v", size, r, err)
		}
		var out bytes.Buffer
		if err = v.Read(context.Background(), r.ItemID, "", &out); err != nil || !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("size %d round trip: %v", size, err)
		}
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type failingReader struct {
	remaining int
	failure   error
	cancel    context.CancelFunc
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		if r.cancel != nil {
			r.cancel()
		}
		return 0, r.failure
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'x'
	}
	r.remaining -= len(p)
	return len(p), nil
}

func TestFailedAndCanceledPutRetainAcceptedState(t *testing.T) {
	v, path := createTestVault(t)
	a := putText(t, v, "", "accepted", "last accepted content")
	failure := errors.New("synthetic source failure")
	opts := PutOptions{ItemID: a.ItemID, Name: "failed replacement", Kind: "file", ChunkSize: MinChunkSize, Supersedes: []string{a.ID}}
	if _, err := v.Put(context.Background(), opts, &failingReader{remaining: MinChunkSize, failure: failure}); !errors.Is(err, failure) {
		t.Fatalf("reader error was swallowed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := v.Put(ctx, opts, &failingReader{remaining: MinChunkSize, failure: io.EOF, cancel: cancel}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled source published: %v", err)
	}
	if _, err := v.Delete(ctx, a.ItemID, []string{a.ID}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Delete published: %v", err)
	}
	info, err := v.Info()
	if err != nil || info.RevisionCount != 1 {
		t.Fatalf("failed transition changed journal: %#v %v", info, err)
	}
	if got := readText(t, v, a.ItemID, ""); got != "last accepted content" {
		t.Fatal(got)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	info, err = reopened.Info()
	if err != nil || info.RevisionCount != 1 || readText(t, reopened, a.ItemID, "") != "last accepted content" {
		t.Fatalf("reopen accepted half revision: %#v %v", info, err)
	}
	if err = reopened.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSignedHistoryAndCheckpointTampering(t *testing.T) {
	for _, mutation := range []string{"signature", "aead", "missing-tail", "missing-middle", "checkpoint-mac", "checkpoint-signature", "extra-event"} {
		t.Run(mutation, func(t *testing.T) {
			v, path := createTestVault(t)
			a := putText(t, v, "", "first", "first retained content")
			putText(t, v, a.ItemID, "second", "second retained content", a.ID)
			err := v.db.Update(func(tx *bolt.Tx) error {
				history, meta := tx.Bucket(historyBucket), tx.Bucket(metaBucket)
				var first, last [8]byte
				binary.BigEndian.PutUint64(last[:], 1)
				switch mutation {
				case "missing-tail":
					return history.Delete(last[:])
				case "missing-middle":
					return history.Delete(first[:])
				case "extra-event":
					var extra [8]byte
					binary.BigEndian.PutUint64(extra[:], 2)
					return history.Put(extra[:], history.Get(last[:]))
				case "checkpoint-mac", "checkpoint-signature":
					var cp checkpointRecord
					if err := vaultfmt.Decode(meta.Get(checkpointKey), vaultfmt.MaxRecordBytes, &cp); err != nil {
						return err
					}
					if mutation == "checkpoint-mac" {
						cp.MAC[0] ^= 1
					} else {
						cp.Signature[0] ^= 1
					}
					encoded, err := vaultfmt.Encode(cp)
					if err != nil {
						return err
					}
					return meta.Put(checkpointKey, encoded)
				default:
					var record signedRecord
					if err := vaultfmt.Decode(history.Get(last[:]), vaultfmt.MaxRecordBytes, &record); err != nil {
						return err
					}
					if mutation == "signature" {
						record.Signature[0] ^= 1
					} else {
						var body historyBody
						if err := vaultfmt.Decode(record.Body, vaultfmt.MaxRecordBytes, &body); err != nil {
							return err
						}
						body.Envelope[len(body.Envelope)-1] ^= 1
						var err error
						record.Body, err = vaultfmt.Encode(body)
						if err != nil {
							return err
						}
						copy(record.Signature[:], vaultfmt.Sign(v.signing, "local-commit", record.Body))
					}
					encoded, err := vaultfmt.Encode(record)
					if err != nil {
						return err
					}
					if err = history.Put(last[:], encoded); err != nil {
						return err
					}
					// Recompute a valid checkpoint so the AEAD case cannot pass
					// merely because the outer signed state was not updated.
					cp, err := v.checkpoint(2, vaultfmt.Hash("local-commit", encoded))
					if err != nil {
						return err
					}
					return meta.Put(checkpointKey, cp)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = v.Verify(context.Background()); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("tampered state passed Verify: %v", err)
			}
			if err = v.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(path, testPassword); !errors.Is(err, ErrCorrupt) {
				if reopened != nil {
					_ = reopened.Close()
				}
				t.Fatalf("tampered state admitted on Open: %v", err)
			}
		})
	}
}

func TestVerifyChecksMissingHistoricalChunk(t *testing.T) {
	v, path := createTestVault(t)
	a := putText(t, v, "", "historical", "old chunk must remain authenticated")
	r := v.state.revisions[a.ID]
	var chunk vaultfmt.ID
	found := false
	err := v.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(objectsBucket).Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			if bytes.Equal(key, r.ref.Object[:]) {
				continue
			}
			var id vaultfmt.ID
			copy(id[:], key)
			// Before another revision exists, the three stored objects are
			// exactly this root, its page and its independently keyed chunk.
			pageContext := v.contentContext(r.item)
			pageContext.Content, pageContext.Role = r.ref.Content, vaultfmt.RolePage
			if _, err := vaultfmt.Open(r.ref.Key, pageContext, id, value, vaultfmt.MaxRecordBytes); err == nil {
				continue
			}
			chunk, found = id, true
			return nil
		}
		return errors.New("historical chunk not found")
	})
	if err != nil || !found {
		t.Fatalf("locate chunk: %v", err)
	}
	b := putText(t, v, a.ItemID, "current", "current content", a.ID)
	err = v.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(objectsBucket).Delete(chunk[:])
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := readText(t, v, b.ItemID, ""); got != "current content" {
		t.Fatal(got)
	}
	if err = v.Read(context.Background(), a.ItemID, a.ID, io.Discard); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing chunk treated as empty success: %v", err)
	}
	if err = v.Verify(context.Background()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Verify ignored superseded missing chunk: %v", err)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.Verify(context.Background()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing historical chunk undetected after reopen: %v", err)
	}
}

func TestProcessInterruptionReopen(t *testing.T) {
	if os.Getenv("QORE_ENGINE_CRASH_HELPER") == "1" {
		v, err := Create(os.Getenv("QORE_ENGINE_CRASH_PATH"), testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = v.Put(context.Background(), PutOptions{Name: "acknowledged", Kind: "text"}, strings.NewReader("durable before abrupt process exit")); err != nil {
			t.Fatal(err)
		}
		// Deliberately bypass Close and all defers, on every supported OS.
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "interrupted.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessInterruptionReopen$")
	cmd.Env = append(os.Environ(), "QORE_ENGINE_CRASH_HELPER=1", "QORE_ENGINE_CRASH_PATH="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	v, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	items, err := v.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("lost acknowledged item: %#v %v", items, err)
	}
	if got := readText(t, v, items[0].ID, ""); got != "durable before abrupt process exit" {
		t.Fatal(got)
	}
	if err = v.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionCallbackRollbackKeepsAcceptedState(t *testing.T) {
	v, path := createTestVault(t)
	r := putText(t, v, "", "accepted", "accepted before callback rollback")
	aborted := errors.New("synthetic transaction abort")
	v.mu.Lock()
	err := v.update(func(tx *bolt.Tx) error {
		var sequence [8]byte
		binary.BigEndian.PutUint64(sequence[:], r.Sequence)
		if err := tx.Bucket(historyBucket).Delete(sequence[:]); err != nil {
			return err
		}
		if err := tx.Bucket(metaBucket).Delete(checkpointKey); err != nil {
			return err
		}
		return aborted
	})
	v.mu.Unlock()
	if !errors.Is(err, aborted) || errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("callback rollback misclassified: %v", err)
	}
	if got := readText(t, v, r.ItemID, ""); got != "accepted before callback rollback" {
		t.Fatal(got)
	}
	if err := v.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := readText(t, reopened, r.ItemID, ""); got != "accepted before callback rollback" {
		t.Fatal(got)
	}
}
