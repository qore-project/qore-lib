package vaultfmt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func fromHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustEncode(t *testing.T, value any) []byte {
	t.Helper()
	b, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCanonicalRFC8949Examples(t *testing.T) {
	// RFC 8949 Appendix A: these expected bytes are published CBOR examples,
	// not a self-roundtrip used as an invented known-answer vector.
	cases := []struct {
		value any
		hex   string
	}{
		{uint64(0), "00"}, {uint64(23), "17"}, {uint64(24), "1818"},
		{uint64(1000), "1903e8"}, {uint64(1000000), "1a000f4240"},
		{uint64(1000000000000), "1b000000e8d4a51000"},
		{false, "f4"}, {true, "f5"}, {nil, "f6"},
		{[]byte{1, 2, 3, 4}, "4401020304"}, {"IETF", "6449455446"},
		{[]any{uint64(1), uint64(2), uint64(3)}, "83010203"},
	}
	for _, tc := range cases {
		encoded := mustEncode(t, tc.value)
		if !bytes.Equal(encoded, fromHex(t, tc.hex)) {
			t.Fatalf("%#v encoded as %x, want %s", tc.value, encoded, tc.hex)
		}
		var got any
		if err := Decode(encoded, 1024, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tc.value) {
			t.Fatalf("decoded %#v, want %#v", got, tc.value)
		}
	}
}

func TestRejectNoncanonicalAndUnsupportedCBOR(t *testing.T) {
	cases := map[string]string{
		"negative": "20", "map": "a0", "tag": "c000",
		"half float": "f93c00", "float": "fa3f800000", "undefined": "f7",
		"simple": "e0", "indefinite array": "9fff", "indefinite bytes": "5fff",
		"long integer": "1800", "long length": "580100", "long true": "f815",
		"bad utf8": "61ff", "trailing": "0000", "truncated": "1b0000",
		"length overflow": "5bffffffffffffffff", "huge array": "9bffffffffffffffff",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			var out any
			if err := Decode(fromHex(t, encoded), 1024, &out); err == nil {
				t.Fatal("accepted forbidden CBOR")
			}
		})
	}
	deep := append(bytes.Repeat([]byte{0x81}, 17), 0)
	var out any
	if err := Decode(deep, 1024, &out); !errors.Is(err, ErrLimit) {
		t.Fatalf("deep input: %v", err)
	}
	if err := Decode([]byte{0x00}, 0, &out); !errors.Is(err, ErrLimit) {
		t.Fatalf("byte bound: %v", err)
	}
	for _, value := range []any{map[string]uint64{"x": 1}, int64(-1), 1.5, string([]byte{0xff})} {
		if _, err := Encode(value); err == nil {
			t.Fatalf("encoded unsupported value %T", value)
		}
	}
}

func TestFixedByteLengthsAndSchemaPreflight(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		id := ID{0xaa}
		if err := Decode(mustEncode(t, make([]byte, n)), 1024, &id); err == nil {
			t.Fatalf("accepted %d-byte identifier", n)
		}
		if id != (ID{0xaa}) {
			t.Fatal("decoder touched fixed array before rejection")
		}
	}
	type record struct {
		_     struct{} `cbor:",toarray"`
		ID    ID
		Count uint64
		Ref   *Ref
	}
	good := record{ID: ID{1}, Count: 3}
	var got record
	if err := Decode(mustEncode(t, good), 1024, &got); err != nil || !reflect.DeepEqual(got, good) {
		t.Fatalf("record decode: %#v, %v", got, err)
	}
	bad := []any{
		[]any{make([]byte, 31), uint64(3), nil},
		[]any{ID{}, nil, nil},
		[]any{ID{}, uint64(3)},
		[]any{ID{}, uint64(3), nil, true},
		[]any{ID{}, uint64(3), []any{ID{}, make([]byte, 31), ID{}}},
	}
	for _, value := range bad {
		if err := Decode(mustEncode(t, value), 1024, &got); err == nil {
			t.Fatalf("accepted bad positional schema %#v", value)
		}
	}
	var ids []ID
	if err := Decode([]byte{0xf6}, 1024, &ids); err == nil {
		t.Fatal("accepted null in place of required array")
	}
	var tiny uint8
	if err := Decode(fromHex(t, "190100"), 1024, &tiny); err == nil {
		t.Fatal("accepted unsigned overflow")
	}
}
