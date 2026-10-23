// Package vaultfmt implements the bounded, authenticated offline vault format.
package vaultfmt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

var (
	ErrInvalid  = errors.New("invalid input")
	ErrCorrupt  = errors.New("corrupt vault data")
	ErrPassword = errors.New("invalid password or key envelope")
	ErrLimit    = errors.New("format limit exceeded")
	ErrNotFound = errors.New("not found")
)

const (
	DefaultChunkSize = 1048576
	MinChunkSize     = 65536
	MaxChunkSize     = 16777216
	MaxChunks        = 65536
	MaxTextSize      = 1048576
	MaxNameBytes     = 1024
	MaxRecordBytes   = 65536
	MaxRecords       = 10000
	MaxBases         = 256
	maxNesting       = 16
	maxItems         = 65536
	maxEncodedBytes  = MaxChunkSize + 8192
)

var encodingMode = func() cbor.EncMode {
	o := cbor.CanonicalEncOptions()
	o.TagsMd = cbor.TagsForbidden
	o.IndefLength = cbor.IndefLengthForbidden
	o.NilContainers = cbor.NilContainerAsEmpty
	o.ByteArray = cbor.ByteArrayToByteSlice
	m, err := o.EncMode()
	if err != nil {
		panic(err) // Static options, not untrusted input.
	}
	return m
}()

var decodingMode = func() cbor.DecMode {
	m, err := (cbor.DecOptions{
		MaxNestedLevels:   maxNesting,
		MaxArrayElements:  maxItems,
		MaxMapPairs:       16,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// Encode emits only the format's deterministic CBOR subset. Its input is
// inspected before marshaling so oversized containers cannot allocate first.
func Encode(v any) ([]byte, error) {
	budget := maxEncodedBytes
	items := maxItems
	if err := checkValue(reflect.ValueOf(v), 0, &budget, &items); err != nil {
		return nil, err
	}
	data, err := encodingMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: CBOR encoding", ErrInvalid)
	}
	if len(data) > maxEncodedBytes {
		return nil, ErrLimit
	}
	s := scanner{data: data, items: maxItems}
	if err := s.value(nil, 0); err != nil || s.pos != len(data) {
		return nil, fmt.Errorf("%w: unsupported CBOR value", ErrInvalid)
	}
	return data, nil
}

// Decode preflights framing and destination shape before the decoder allocates.
// In particular a byte string of the wrong size never reaches a fixed Go array:
// permissive array padding/truncation would otherwise change an authenticated ID.
func Decode(data []byte, maxBytes int, out any) error {
	if maxBytes < 0 || maxBytes > maxEncodedBytes {
		return ErrLimit
	}
	if len(data) > maxBytes {
		return ErrLimit
	}
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return ErrInvalid
	}
	s := scanner{data: data, items: maxItems}
	if err := s.value(t.Elem(), 0); err != nil {
		return err
	}
	if s.pos != len(data) {
		return fmt.Errorf("%w: trailing CBOR data", ErrCorrupt)
	}
	if err := decodingMode.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: CBOR destination mismatch", ErrCorrupt)
	}
	return nil
}

type arraySchema struct {
	fields []reflect.StructField
	valid  bool
}

var arraySchemas sync.Map // reflect.Type -> immutable arraySchema

func structFields(t reflect.Type) ([]reflect.StructField, bool) {
	if cached, ok := arraySchemas.Load(t); ok {
		schema := cached.(arraySchema)
		return schema.fields, schema.valid
	}
	fields := make([]reflect.StructField, 0, t.NumField())
	toArray := false
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Name == "_" && strings.Contains(f.Tag.Get("cbor"), ",toarray") {
			toArray = true
			continue
		}
		if f.PkgPath != "" || f.Tag.Get("cbor") == "-" {
			continue
		}
		// Optional/omitted fields have no place in a fixed positional schema.
		if strings.Contains(f.Tag.Get("cbor"), ",") {
			return nil, false
		}
		fields = append(fields, f)
	}
	schema, _ := arraySchemas.LoadOrStore(t, arraySchema{fields: fields, valid: toArray})
	result := schema.(arraySchema)
	return result.fields, result.valid
}

func checkValue(v reflect.Value, depth int, budget, items *int) error {
	if depth > maxNesting || *items == 0 {
		return ErrLimit
	}
	(*items)--
	*budget -= 9 // Maximum primitive/container header.
	if *budget < 0 {
		return ErrLimit
	}
	if !v.IsValid() {
		return nil
	}
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
		depth++
		if depth > maxNesting {
			return ErrLimit
		}
	}
	switch v.Kind() {
	case reflect.Bool, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Int() < 0 {
			return ErrInvalid
		}
		return nil
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return ErrInvalid
		}
		*budget -= v.Len()
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			*budget -= v.Len()
			break
		}
		if v.Len() > maxItems {
			return ErrLimit
		}
		for i := range v.Len() {
			if err := checkValue(v.Index(i), depth+1, budget, items); err != nil {
				return err
			}
		}
	case reflect.Struct:
		fields, ok := structFields(v.Type())
		if !ok {
			return ErrInvalid
		}
		for _, f := range fields {
			if err := checkValue(v.FieldByIndex(f.Index), depth+1, budget, items); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	if *budget < 0 {
		return ErrLimit
	}
	return nil
}

type scanner struct {
	data  []byte
	pos   int
	items int
}

func (s *scanner) head() (byte, uint64, error) {
	if s.pos >= len(s.data) {
		return 0, 0, ErrCorrupt
	}
	b := s.data[s.pos]
	s.pos++
	major, ai := b>>5, b&31
	if ai < 24 {
		return major, uint64(ai), nil
	}
	var n int
	var min uint64
	switch ai {
	case 24:
		n, min = 1, 24
	case 25:
		n, min = 2, 256
	case 26:
		n, min = 4, 65536
	case 27:
		n, min = 8, 4294967296
	default:
		return 0, 0, ErrCorrupt
	}
	if n > len(s.data)-s.pos {
		return 0, 0, ErrCorrupt
	}
	var value uint64
	switch n {
	case 1:
		value = uint64(s.data[s.pos])
	case 2:
		value = uint64(binary.BigEndian.Uint16(s.data[s.pos:]))
	case 4:
		value = uint64(binary.BigEndian.Uint32(s.data[s.pos:]))
	case 8:
		value = binary.BigEndian.Uint64(s.data[s.pos:])
	}
	s.pos += n
	if value < min {
		return 0, 0, ErrCorrupt
	}
	return major, value, nil
}

func (s *scanner) value(t reflect.Type, depth int) error {
	if depth > maxNesting || s.items == 0 {
		return ErrLimit
	}
	s.items--
	major, n, err := s.head()
	if err != nil {
		return err
	}
	if major == 7 && n == 22 {
		if t != nil && t.Kind() != reflect.Interface && t.Kind() != reflect.Pointer {
			return ErrCorrupt
		}
		return nil
	}
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t != nil && t.Kind() == reflect.Interface {
		t = nil
	}
	switch major {
	case 0:
		if t != nil {
			switch t.Kind() {
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				if t.Bits() < 64 && n >= uint64(1)<<t.Bits() {
					return ErrCorrupt
				}
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if n > (uint64(1)<<(t.Bits()-1))-1 {
					return ErrCorrupt
				}
			default:
				return ErrCorrupt
			}
		}
	case 2, 3:
		if n > uint64(len(s.data)-s.pos) {
			return ErrCorrupt
		}
		if t != nil {
			if major == 3 {
				if t.Kind() != reflect.String {
					return ErrCorrupt
				}
			} else if (t.Kind() != reflect.Array && t.Kind() != reflect.Slice) || t.Elem().Kind() != reflect.Uint8 || (t.Kind() == reflect.Array && uint64(t.Len()) != n) {
				return ErrCorrupt
			}
		}
		end := s.pos + int(n)
		if major == 3 && !utf8.Valid(s.data[s.pos:end]) {
			return ErrCorrupt
		}
		s.pos = end
	case 4:
		if depth == maxNesting || n > maxItems || n > uint64(len(s.data)-s.pos) || n > uint64(s.items) {
			return ErrLimit
		}
		var fields []reflect.StructField
		if t != nil {
			switch t.Kind() {
			case reflect.Struct:
				var ok bool
				fields, ok = structFields(t)
				if !ok || uint64(len(fields)) != n {
					return ErrCorrupt
				}
			case reflect.Slice, reflect.Array:
				if t.Elem().Kind() == reflect.Uint8 || (t.Kind() == reflect.Array && uint64(t.Len()) != n) {
					return ErrCorrupt
				}
			default:
				return ErrCorrupt
			}
		}
		for i := range n {
			var child reflect.Type
			if t != nil {
				if fields != nil {
					child = fields[i].Type
				} else {
					child = t.Elem()
				}
			}
			if err := s.value(child, depth+1); err != nil {
				return err
			}
		}
	case 7:
		if (n != 20 && n != 21) || (t != nil && t.Kind() != reflect.Bool) {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	return nil
}
