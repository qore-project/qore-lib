package vaultfmt

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type ID [32]byte
type Key [32]byte

func NewID() (ID, error) {
	var id ID
	_, err := io.ReadFull(rand.Reader, id[:])
	return id, err
}

func NewKey() (Key, error) {
	var key Key
	_, err := io.ReadFull(rand.Reader, key[:])
	return key, err
}

func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 64 {
		return id, ErrInvalid
	}
	for _, c := range []byte(s) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return id, ErrInvalid
		}
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return ID{}, ErrInvalid
	}
	return id, nil
}

func (id ID) String() string { return hex.EncodeToString(id[:]) }

func domain(label string, body []byte) []byte {
	b, err := encodingMode.Marshal([]any{"qore/v2", label, body})
	if err != nil {
		panic(err) // Only built-in supported values.
	}
	return b
}

// writeDomain hashes large object envelopes without copying the ciphertext into
// another whole envelope just to add the domain-separation framing.
func writeDomain(h hash.Hash, label string, body []byte) {
	prefix, _ := encodingMode.Marshal([]any{"qore/v2", label})
	prefix[0] = 0x83
	_, _ = h.Write(prefix)
	var header [9]byte
	var n int
	length := uint64(len(body))
	switch {
	case length < 24:
		header[0], n = 0x40|byte(length), 1
	case length <= 255:
		header[0], header[1], n = 0x58, byte(length), 2
	case length <= 65535:
		header[0], n = 0x59, 3
		binary.BigEndian.PutUint16(header[1:], uint16(length))
	case length <= 4294967295:
		header[0], n = 0x5a, 5
		binary.BigEndian.PutUint32(header[1:], uint32(length))
	default:
		header[0], n = 0x5b, 9
		binary.BigEndian.PutUint64(header[1:], length)
	}
	_, _ = h.Write(header[:n])
	_, _ = h.Write(body)
}

func Hash(label string, data []byte) ID {
	h := sha256.New()
	writeDomain(h, label, data)
	var id ID
	h.Sum(id[:0])
	return id
}

func Sign(key ed25519.PrivateKey, label string, body []byte) []byte {
	if len(key) != ed25519.PrivateKeySize || len(body) > maxEncodedBytes || len(label) > MaxNameBytes {
		return nil
	}
	return ed25519.Sign(key, domain(label, body))
}

func Verify(key ed25519.PublicKey, label string, body, signature []byte) bool {
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || len(body) > maxEncodedBytes || len(label) > MaxNameBytes {
		return false
	}
	return ed25519.Verify(key, domain(label, body), signature)
}

func derive(seed Key, salt []byte, info any) (Key, error) {
	encoded, err := Encode(info)
	if err != nil {
		return Key{}, err
	}
	var key Key
	_, err = io.ReadFull(hkdf.New(sha256.New, seed[:], salt, encoded), key[:])
	return key, err
}

func MAC(key Key, vault ID, label string, body []byte) []byte {
	derived, err := derive(key, vault[:], []any{"qore/v2", uint64(1), "local-mac-key", vault, label})
	if err != nil {
		return nil
	}
	defer clear(derived[:])
	h := hmac.New(sha256.New, derived[:])
	writeDomain(h, label, body)
	return h.Sum(nil)
}

type wrapHeader struct {
	_            struct{} `cbor:",toarray"`
	Version      uint64
	Suite        uint64
	Vault        ID
	ArgonVersion uint64
	Memory       uint64
	Time         uint64
	Threads      uint64
	Salt         [16]byte
	Nonce        [24]byte
}

type wrapEnvelope struct {
	_            struct{} `cbor:",toarray"`
	Version      uint64
	Suite        uint64
	Vault        ID
	ArgonVersion uint64
	Memory       uint64
	Time         uint64
	Threads      uint64
	Salt         [16]byte
	Nonce        [24]byte
	Ciphertext   []byte
}

func (e wrapEnvelope) header() wrapHeader {
	return wrapHeader{Version: e.Version, Suite: e.Suite, Vault: e.Vault,
		ArgonVersion: e.ArgonVersion, Memory: e.Memory, Time: e.Time,
		Threads: e.Threads, Salt: e.Salt, Nonce: e.Nonce}
}

func wrapAAD(e wrapEnvelope) ([]byte, error) {
	b, err := Encode(e.header())
	if err != nil {
		return nil, err
	}
	return domain("local-key-wrap", b), nil
}

func Wrap(password []byte, vault ID, secrets []byte) ([]byte, error) {
	if len(password) == 0 || len(password) > 1024 {
		return nil, ErrInvalid
	}
	if len(secrets) > 4096 {
		return nil, ErrLimit
	}
	e := wrapEnvelope{Version: 1, Suite: 1, Vault: vault,
		ArgonVersion: argon2.Version, Memory: 65536, Time: 3, Threads: 4}
	if _, err := io.ReadFull(rand.Reader, e.Salt[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, e.Nonce[:]); err != nil {
		return nil, err
	}
	aad, err := wrapAAD(e)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey(password, e.Salt[:], 3, 65536, 4, 32)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	e.Ciphertext = aead.Seal(nil, e.Nonce[:], secrets, aad)
	encoded, err := Encode(e)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 8192 {
		return nil, ErrLimit
	}
	return encoded, nil
}

func Unwrap(password []byte, wrapped []byte) (ID, []byte, error) {
	if len(password) == 0 || len(password) > 1024 {
		return ID{}, nil, ErrInvalid
	}
	var e wrapEnvelope
	if err := Decode(wrapped, 8192, &e); err != nil {
		return ID{}, nil, err
	}
	// Validate every work factor before allowing Argon2 to allocate its memory.
	if e.Version != 1 || e.Suite != 1 || e.ArgonVersion != argon2.Version || e.Memory != 65536 || e.Time != 3 || e.Threads != 4 {
		return ID{}, nil, ErrCorrupt
	}
	if len(e.Ciphertext) < chacha20poly1305.Overhead || len(e.Ciphertext) > 4096+chacha20poly1305.Overhead {
		return ID{}, nil, ErrCorrupt
	}
	aad, err := wrapAAD(e)
	if err != nil {
		return ID{}, nil, err
	}
	key := argon2.IDKey(password, e.Salt[:], 3, 65536, 4, 32)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return ID{}, nil, err
	}
	plain, err := aead.Open(nil, e.Nonce[:], e.Ciphertext, aad)
	if err != nil {
		return ID{}, nil, ErrPassword
	}
	return e.Vault, plain, nil
}

type Context struct {
	_       struct{} `cbor:",toarray"`
	Vault   ID
	Control ID
	Item    ID
	Content ID
	Role    uint64
	Index   uint64
}

const (
	RoleOperation uint64 = 1
	RoleManifest  uint64 = 2
	RolePage      uint64 = 3
	RoleChunk     uint64 = 4
)

type envelope struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Suite      uint64
	Vault      ID
	Salt       [32]byte
	Nonce      [24]byte
	Ciphertext []byte
}

type objectBinding struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Suite   uint64
	Vault   ID
	Salt    [32]byte
	Nonce   [24]byte
	Context Context
}

func objectParams(key Key, ctx Context, e envelope) (Key, []byte, error) {
	derived, err := derive(key, ctx.Vault[:], []any{"qore/v2", uint64(1), "local-object-key", ctx, e.Salt})
	if err != nil {
		return Key{}, nil, err
	}
	aad, err := Encode([]any{"qore/v2", "local-object", objectBinding{
		Version: e.Version, Suite: e.Suite, Vault: e.Vault,
		Salt: e.Salt, Nonce: e.Nonce, Context: ctx}})
	if err != nil {
		clear(derived[:])
		return Key{}, nil, err
	}
	return derived, aad, nil
}

func validContext(ctx Context) bool {
	return ctx.Role >= RoleOperation && ctx.Role <= RoleChunk
}

func Seal(key Key, ctx Context, plain []byte) (ID, []byte, error) {
	if !validContext(ctx) {
		return ID{}, nil, ErrInvalid
	}
	if len(plain) > MaxChunkSize {
		return ID{}, nil, ErrLimit
	}
	e := envelope{Version: 2, Suite: 1, Vault: ctx.Vault}
	if _, err := io.ReadFull(rand.Reader, e.Salt[:]); err != nil {
		return ID{}, nil, err
	}
	if _, err := io.ReadFull(rand.Reader, e.Nonce[:]); err != nil {
		return ID{}, nil, err
	}
	derived, aad, err := objectParams(key, ctx, e)
	if err != nil {
		return ID{}, nil, err
	}
	defer clear(derived[:])
	aead, err := chacha20poly1305.NewX(derived[:])
	if err != nil {
		return ID{}, nil, err
	}
	e.Ciphertext = aead.Seal(nil, e.Nonce[:], plain, aad)
	encoded, err := Encode(e)
	if err != nil {
		return ID{}, nil, err
	}
	return Hash("object", encoded), encoded, nil
}

func Open(key Key, ctx Context, id ID, encoded []byte, maxPlain int) ([]byte, error) {
	if !validContext(ctx) {
		return nil, ErrInvalid
	}
	if maxPlain < 0 || maxPlain > MaxChunkSize {
		return nil, ErrLimit
	}
	if len(encoded) > maxPlain+objectOverhead {
		return nil, ErrLimit
	}
	if Hash("object", encoded) != id {
		return nil, fmt.Errorf("%w: object identity", ErrCorrupt)
	}
	var e envelope
	if err := Decode(encoded, maxPlain+objectOverhead, &e); err != nil {
		return nil, err
	}
	if e.Version != 2 || e.Suite != 1 || e.Vault != ctx.Vault || len(e.Ciphertext) < chacha20poly1305.Overhead || len(e.Ciphertext)-chacha20poly1305.Overhead > maxPlain {
		return nil, ErrCorrupt
	}
	derived, aad, err := objectParams(key, ctx, e)
	if err != nil {
		return nil, err
	}
	defer clear(derived[:])
	aead, err := chacha20poly1305.NewX(derived[:])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, e.Nonce[:], e.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: object authentication", ErrCorrupt)
	}
	return plain, nil
}

// Includes all fixed framing, random fields and the authentication tag. This
// deliberately small bound is independent of attacker-controlled CBOR lengths.
const objectOverhead = 256
