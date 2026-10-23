package vaultfmt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestEd25519RFC8032AndDomainSeparation(t *testing.T) {
	// RFC 8032 section 7.1, TEST 1 (pure Ed25519, empty message).
	seed := fromHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	public := fromHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	expected := fromHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	private := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) || !bytes.Equal(ed25519.Sign(private, nil), expected) {
		t.Fatal("RFC 8032 primitive vector mismatch")
	}
	body := []byte("payload")
	// Independently specified literal CBOR: ["qore/v2","test",h'7061796c6f6164'].
	framed := append(fromHex(t, "8367716f72652f7632647465737447"), body...)
	signature := Sign(private, "test", body)
	if !bytes.Equal(signature, ed25519.Sign(private, framed)) || !Verify(public, "test", body, signature) {
		t.Fatal("signature domain framing mismatch")
	}
	if Verify(public, "other", body, signature) || Verify(public, "test", []byte("changed"), signature) || Verify(public[:31], "test", body, signature) || Verify(public, "test", body, signature[:63]) {
		t.Fatal("accepted wrong signature context or length")
	}
	if Sign(private[:63], "test", body) != nil {
		t.Fatal("accepted short private key")
	}
	wantHash := sha256.Sum256(framed)
	if Hash("test", body) != ID(wantHash) {
		t.Fatal("streamed hash does not match domain bytes")
	}
	for _, n := range []int{0, 23, 24, 255, 256, 65535, 65536} {
		data := bytes.Repeat([]byte{0xab}, n)
		expected := sha256.Sum256(mustEncode(t, []any{"qore/v2", "object", data}))
		if Hash("object", data) != ID(expected) {
			t.Fatalf("domain byte-string framing at %d", n)
		}
	}
	var nilBytes []byte
	if !bytes.Equal(mustEncode(t, nilBytes), []byte{0x40}) || Hash("object", nilBytes) != Hash("object", []byte{}) {
		t.Fatal("nil bytes must use the same canonical byte string as empty bytes")
	}
}

func TestMACBindsVaultAndPurpose(t *testing.T) {
	key, vault := Key{1}, ID{2}
	body := []byte("checkpoint")
	info := mustEncode(t, []any{"qore/v2", uint64(1), "local-mac-key", vault, "local-state"})
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key[:], vault[:], info), derived); err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha256.New, derived)
	_, _ = h.Write(mustEncode(t, []any{"qore/v2", "local-state", body}))
	mac := MAC(key, vault, "local-state", body)
	if !hmac.Equal(mac, h.Sum(nil)) {
		t.Fatal("MAC derivation or framing mismatch")
	}
	if hmac.Equal(mac, MAC(key, ID{3}, "local-state", body)) || hmac.Equal(mac, MAC(key, vault, "other", body)) || hmac.Equal(mac, MAC(Key{3}, vault, "local-state", body)) {
		t.Fatal("MAC lacks context binding")
	}
}

func TestWrapPasswordAndBoundedParameters(t *testing.T) {
	password, vault, secret := []byte("test passphrase"), ID{7}, []byte("private secrets")
	wrapped, err := Wrap(password, vault, secret)
	if err != nil {
		t.Fatal(err)
	}
	id, plain, err := Unwrap(password, wrapped)
	if err != nil || id != vault || !bytes.Equal(plain, secret) {
		t.Fatalf("unwrap: %x %q %v", id, plain, err)
	}
	if _, plain, err := Unwrap([]byte("wrong"), wrapped); !errors.Is(err, ErrPassword) || plain != nil {
		t.Fatalf("wrong password exposed plaintext: %q, %v", plain, err)
	}
	var original wrapEnvelope
	if err := Decode(wrapped, 8192, &original); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*wrapEnvelope){
		"version":       func(e *wrapEnvelope) { e.Version++ },
		"suite":         func(e *wrapEnvelope) { e.Suite++ },
		"argon version": func(e *wrapEnvelope) { e.ArgonVersion++ },
		"memory":        func(e *wrapEnvelope) { e.Memory = ^uint64(0) },
		"time":          func(e *wrapEnvelope) { e.Time = 0 },
		"threads":       func(e *wrapEnvelope) { e.Threads = 255 },
	} {
		t.Run(name, func(t *testing.T) {
			e := original
			mutate(&e)
			if _, p, err := Unwrap(password, mustEncode(t, e)); !errors.Is(err, ErrCorrupt) || p != nil {
				t.Fatalf("accepted unsupported KDF/header: %v", err)
			}
		})
	}
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 1
	if _, plain, err := Unwrap(password, tampered); !errors.Is(err, ErrPassword) || plain != nil {
		t.Fatalf("tampered wrap exposed plaintext: %q, %v", plain, err)
	}
	if _, err := Wrap(nil, vault, secret); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted empty password")
	}
	if _, err := Wrap(password, vault, make([]byte, 4097)); !errors.Is(err, ErrLimit) {
		t.Fatal("accepted oversized secrets")
	}
}

func TestObjectBindsEveryContextFieldAndIdentity(t *testing.T) {
	key := Key{1}
	ctx := Context{Vault: ID{2}, Control: ID{3}, Item: ID{4}, Content: ID{5}, Role: RoleChunk, Index: 9}
	body := []byte("authenticated bytes")
	id, encoded, err := Seal(key, ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Open(key, ctx, id, encoded, len(body))
	if err != nil || !bytes.Equal(plain, body) {
		t.Fatalf("open: %q %v", plain, err)
	}
	for _, mutate := range []func(*Context){
		func(c *Context) { c.Vault[0]++ }, func(c *Context) { c.Control[0]++ },
		func(c *Context) { c.Item[0]++ }, func(c *Context) { c.Content[0]++ },
		func(c *Context) { c.Role = RolePage }, func(c *Context) { c.Index++ },
	} {
		other := ctx
		mutate(&other)
		if p, err := Open(key, other, id, encoded, len(body)); err == nil || p != nil {
			t.Fatal("context substitution released plaintext")
		}
	}
	if p, err := Open(Key{9}, ctx, id, encoded, len(body)); err == nil || p != nil {
		t.Fatal("wrong seed released plaintext")
	}
	if p, err := Open(key, ctx, ID{9}, encoded, len(body)); err == nil || p != nil {
		t.Fatal("wrong identity released plaintext")
	}
	changed := append([]byte(nil), encoded...)
	changed[len(changed)-1] ^= 1
	if p, err := Open(key, ctx, Hash("object", changed), changed, len(body)); err == nil || p != nil {
		t.Fatal("tampered ciphertext released plaintext")
	}
	if _, err := Open(key, ctx, id, encoded, len(body)-1); err == nil {
		t.Fatal("ignored plaintext bound")
	}
	_, next, err := Seal(key, ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	var a, b envelope
	if err := Decode(encoded, 1024, &a); err != nil {
		t.Fatal(err)
	}
	if err := Decode(next, 1024, &b); err != nil {
		t.Fatal(err)
	}
	if a.Salt == b.Salt || a.Nonce == b.Nonce || bytes.Equal(encoded, next) {
		t.Fatal("encryption reused random salt or nonce")
	}
}
