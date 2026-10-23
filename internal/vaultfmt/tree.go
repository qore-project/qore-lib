package vaultfmt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

type Objects interface {
	PutObject(ID, []byte) error
	GetObject(ID, int) ([]byte, error)
}

type Ref struct {
	_       struct{} `cbor:",toarray"`
	Object  ID
	Key     Key
	Content ID
}

type Metadata struct {
	Name      string
	Kind      string
	Size      uint64
	ChunkSize int
}

const pageChunks = 256
const maxPages = MaxChunks / pageChunks

type root struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	Name        string
	Kind        string
	TotalSize   uint64
	ChunkSize   uint64
	ChunkCount  uint64
	ContentSeed Key
	Pages       []pageRef
}

type pageRef struct {
	_          struct{} `cbor:",toarray"`
	Object     ID
	PageIndex  uint64
	FirstChunk uint64
	ChunkCount uint64
	TotalSize  uint64
}

type page struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	PageIndex  uint64
	FirstChunk uint64
	ChunkCount uint64
	TotalSize  uint64
	Chunks     []chunkRef
}

type chunkRef struct {
	_          struct{} `cbor:",toarray"`
	Object     ID
	ChunkIndex uint64
	Length     uint64
}

func checkMetadata(name, kind string, chunkSize int) error {
	if name == "" || !utf8.ValidString(name) || (kind != "text" && kind != "file") {
		return ErrInvalid
	}
	if len(name) > MaxNameBytes || chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return ErrLimit
	}
	return nil
}

func contentContext(base Context, content ID, role, index uint64) Context {
	base.Content, base.Role, base.Index = content, role, index
	return base
}

// checkedReader preserves errors returned alongside a full read: io.ReadFull
// itself discards an error when the requested number of bytes has arrived.
// Checking around every call also makes cancellation observable for fragmented
// readers; cancellation cannot interrupt an underlying Read that never returns.
// A caller that needs that guarantee must supply a context-aware source.
type checkedReader struct {
	ctx      context.Context
	src      io.Reader
	terminal error
	eof      bool
	empty    int
}

func (r *checkedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		r.terminal = err
		return 0, err
	}
	if r.terminal != nil {
		return 0, r.terminal
	}
	if r.eof {
		return 0, io.EOF
	}
	n, err := r.src.Read(p)
	if n < 0 || n > len(p) {
		r.terminal = ErrInvalid
		return 0, r.terminal
	}
	if n == 0 && err == nil {
		r.empty++
		if r.empty >= 100 {
			err = io.ErrNoProgress
		}
	} else {
		r.empty = 0
	}
	if after := r.ctx.Err(); after != nil {
		err = after
	}
	if err == io.EOF {
		r.eof = true
	} else if err != nil {
		r.terminal = err
	}
	return n, err
}

func putSealed(ctx context.Context, objects Objects, key Key, binding Context, plain []byte) (ID, error) {
	if err := ctx.Err(); err != nil {
		return ID{}, err
	}
	id, encoded, err := Seal(key, binding, plain)
	if err != nil {
		return ID{}, err
	}
	if err := ctx.Err(); err != nil {
		return ID{}, err
	}
	if err := objects.PutObject(id, encoded); err != nil {
		return ID{}, err
	}
	if err := ctx.Err(); err != nil {
		return ID{}, err
	}
	return id, nil
}

func Store(ctx context.Context, objects Objects, base Context, name, kind string, src io.Reader, chunkSize int) (Ref, Metadata, error) {
	if ctx == nil || objects == nil || src == nil {
		return Ref{}, Metadata{}, ErrInvalid
	}
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	if err := checkMetadata(name, kind, chunkSize); err != nil {
		return Ref{}, Metadata{}, err
	}
	if err := ctx.Err(); err != nil {
		return Ref{}, Metadata{}, err
	}
	input := &checkedReader{ctx: ctx, src: src}
	var text []byte
	if kind == "text" {
		var err error
		text, err = io.ReadAll(io.LimitReader(input, MaxTextSize+1))
		defer clear(text)
		if input.terminal != nil {
			err = input.terminal
		}
		if err != nil {
			return Ref{}, Metadata{}, err
		}
		if len(text) > MaxTextSize {
			return Ref{}, Metadata{}, ErrLimit
		}
		if !utf8.Valid(text) {
			return Ref{}, Metadata{}, ErrInvalid
		}
	}
	var ref Ref
	var err error
	ref.Key, err = NewKey()
	if err != nil {
		return Ref{}, Metadata{}, err
	}
	ref.Content, err = NewID()
	if err != nil {
		return Ref{}, Metadata{}, err
	}
	seed, err := NewKey()
	if err != nil {
		return Ref{}, Metadata{}, err
	}
	defer clear(seed[:])
	r := root{Version: 1, Name: name, Kind: kind, ChunkSize: uint64(chunkSize), ContentSeed: seed, Pages: make([]pageRef, 0, maxPages)}
	defer clear(r.ContentSeed[:])
	p := page{Version: 1, Chunks: make([]chunkRef, 0, pageChunks)}
	flush := func() error {
		if len(p.Chunks) == 0 {
			return nil
		}
		p.ChunkCount = uint64(len(p.Chunks))
		encoded, err := Encode(p)
		if err != nil {
			return err
		}
		if len(encoded) > MaxRecordBytes {
			return ErrLimit
		}
		id, err := putSealed(ctx, objects, ref.Key, contentContext(base, ref.Content, RolePage, p.PageIndex), encoded)
		if err != nil {
			return err
		}
		r.Pages = append(r.Pages, pageRef{Object: id, PageIndex: p.PageIndex, FirstChunk: p.FirstChunk, ChunkCount: p.ChunkCount, TotalSize: p.TotalSize})
		p = page{Version: 1, PageIndex: p.PageIndex + 1, FirstChunk: r.ChunkCount, Chunks: p.Chunks[:0]}
		return nil
	}
	// Text can use its already bounded buffer directly. Files hold just one
	// plaintext chunk; the authenticated ciphertext and framing are also O(chunk).
	var buf []byte
	if kind == "file" {
		buf = make([]byte, chunkSize)
	}
	defer clear(buf)
	for {
		if r.ChunkCount == MaxChunks {
			var probe [1]byte
			n, readErr := input.Read(probe[:])
			if input.terminal != nil {
				return Ref{}, Metadata{}, input.terminal
			}
			if n != 0 {
				return Ref{}, Metadata{}, ErrLimit
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return Ref{}, Metadata{}, readErr
			}
			continue
		}
		var chunk []byte
		var readErr error
		if kind == "text" {
			start := int(r.TotalSize)
			if start == len(text) {
				break
			}
			chunk = text[start:min(start+chunkSize, len(text))]
		} else {
			var n int
			n, readErr = io.ReadFull(input, buf)
			if input.terminal != nil {
				return Ref{}, Metadata{}, input.terminal
			}
			if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
				return Ref{}, Metadata{}, readErr
			}
			chunk = buf[:n]
		}
		if err := ctx.Err(); err != nil {
			return Ref{}, Metadata{}, err
		}
		n := len(chunk)
		if n == 0 {
			break
		}
		if r.TotalSize > uint64(chunkSize)*MaxChunks-uint64(n) {
			return Ref{}, Metadata{}, ErrLimit
		}
		id, err := putSealed(ctx, objects, seed, contentContext(base, ref.Content, RoleChunk, r.ChunkCount), chunk)
		if err != nil {
			return Ref{}, Metadata{}, err
		}
		p.Chunks = append(p.Chunks, chunkRef{Object: id, ChunkIndex: r.ChunkCount, Length: uint64(n)})
		p.TotalSize += uint64(n)
		r.ChunkCount++
		r.TotalSize += uint64(n)
		if len(p.Chunks) == pageChunks {
			if err := flush(); err != nil {
				return Ref{}, Metadata{}, err
			}
		}
		if readErr != nil {
			break
		}
	}
	if err := flush(); err != nil {
		return Ref{}, Metadata{}, err
	}
	if err := ctx.Err(); err != nil {
		return Ref{}, Metadata{}, err
	}
	encoded, err := Encode(r)
	if err != nil {
		return Ref{}, Metadata{}, err
	}
	defer clear(encoded)
	if len(encoded) > MaxRecordBytes {
		return Ref{}, Metadata{}, ErrLimit
	}
	ref.Object, err = putSealed(ctx, objects, ref.Key, contentContext(base, ref.Content, RoleManifest, 0), encoded)
	if err != nil {
		return Ref{}, Metadata{}, err
	}
	return ref, Metadata{Name: name, Kind: kind, Size: r.TotalSize, ChunkSize: chunkSize}, nil
}

func getOpened(objects Objects, key Key, binding Context, id ID, maxPlain int) ([]byte, error) {
	encoded, err := objects.GetObject(id, maxPlain+objectOverhead)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%w: missing referenced object", ErrCorrupt)
		}
		return nil, err
	}
	// Defend even if an Objects implementation forgets the GetObject limit.
	if len(encoded) > maxPlain+objectOverhead {
		return nil, ErrLimit
	}
	return Open(key, binding, id, encoded, maxPlain)
}

func readRoot(objects Objects, base Context, ref Ref) (root, error) {
	plain, err := getOpened(objects, ref.Key, contentContext(base, ref.Content, RoleManifest, 0), ref.Object, MaxRecordBytes)
	if err != nil {
		return root{}, err
	}
	defer clear(plain)
	var r root
	if err := Decode(plain, MaxRecordBytes, &r); err != nil {
		return root{}, err
	}
	if r.Version != 1 || r.ChunkSize < MinChunkSize || r.ChunkSize > MaxChunkSize || r.ChunkCount > MaxChunks || r.TotalSize > r.ChunkSize*MaxChunks {
		return root{}, ErrCorrupt
	}
	if err := checkMetadata(r.Name, r.Kind, int(r.ChunkSize)); err != nil {
		return root{}, ErrCorrupt
	}
	if r.Kind == "text" && r.TotalSize > MaxTextSize {
		return root{}, ErrCorrupt
	}
	expectedChunks := r.TotalSize / r.ChunkSize
	if r.TotalSize%r.ChunkSize != 0 {
		expectedChunks++
	}
	if r.ChunkCount != expectedChunks || len(r.Pages) != int((r.ChunkCount+pageChunks-1)/pageChunks) || len(r.Pages) > maxPages {
		return root{}, ErrCorrupt
	}
	seen := make(map[ID]struct{}, len(r.Pages)+1)
	seen[ref.Object] = struct{}{}
	for i, pr := range r.Pages {
		first := uint64(i) * pageChunks
		count := min(uint64(pageChunks), r.ChunkCount-first)
		length := min(count*r.ChunkSize, r.TotalSize-first*r.ChunkSize)
		if pr.PageIndex != uint64(i) || pr.FirstChunk != first || pr.ChunkCount != count || pr.TotalSize != length {
			return root{}, ErrCorrupt
		}
		if _, ok := seen[pr.Object]; ok {
			return root{}, ErrCorrupt
		}
		seen[pr.Object] = struct{}{}
	}
	return r, nil
}

// walkPages retains only one page and a bounded identity set. Chunk lengths are
// derived independently from the authenticated root, not trusted from the page.
func walkPages(ctx context.Context, objects Objects, base Context, ref Ref, r root, visit func(chunkRef) error) error {
	seen := make(map[ID]struct{}, int(r.ChunkCount)+len(r.Pages)+1)
	seen[ref.Object] = struct{}{}
	for _, pr := range r.Pages {
		seen[pr.Object] = struct{}{}
	}
	for _, pr := range r.Pages {
		if err := ctx.Err(); err != nil {
			return err
		}
		plain, err := getOpened(objects, ref.Key, contentContext(base, ref.Content, RolePage, pr.PageIndex), pr.Object, MaxRecordBytes)
		if err != nil {
			return err
		}
		var p page
		err = Decode(plain, MaxRecordBytes, &p)
		clear(plain)
		if err != nil {
			return err
		}
		if p.Version != 1 || p.PageIndex != pr.PageIndex || p.FirstChunk != pr.FirstChunk || p.ChunkCount != pr.ChunkCount || p.TotalSize != pr.TotalSize || uint64(len(p.Chunks)) != pr.ChunkCount {
			return ErrCorrupt
		}
		var size uint64
		for i, cr := range p.Chunks {
			index := pr.FirstChunk + uint64(i)
			length := min(r.ChunkSize, r.TotalSize-index*r.ChunkSize)
			if cr.ChunkIndex != index || cr.Length != length || length == 0 {
				return ErrCorrupt
			}
			if _, ok := seen[cr.Object]; ok {
				return ErrCorrupt
			}
			seen[cr.Object] = struct{}{}
			size += cr.Length
		}
		if size != p.TotalSize {
			return ErrCorrupt
		}
		for _, cr := range p.Chunks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if visit != nil {
				if err := visit(cr); err != nil {
					return err
				}
			}
		}
	}
	return ctx.Err()
}

func Inspect(objects Objects, base Context, ref Ref) (Metadata, error) {
	if objects == nil {
		return Metadata{}, ErrInvalid
	}
	r, err := readRoot(objects, base, ref)
	if err != nil {
		return Metadata{}, err
	}
	defer clear(r.ContentSeed[:])
	if err := walkPages(context.Background(), objects, base, ref, r, nil); err != nil {
		return Metadata{}, err
	}
	return Metadata{Name: r.Name, Kind: r.Kind, Size: r.TotalSize, ChunkSize: int(r.ChunkSize)}, nil
}

func writeVerified(ctx context.Context, dst io.Writer, plain []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := dst.Write(plain)
	if n < 0 || n > len(plain) {
		return io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	if n != len(plain) {
		return io.ErrShortWrite
	}
	return ctx.Err()
}

func Load(ctx context.Context, objects Objects, base Context, ref Ref, dst io.Writer) error {
	if ctx == nil || objects == nil || dst == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r, err := readRoot(objects, base, ref)
	if err != nil {
		return err
	}
	defer clear(r.ContentSeed[:])
	var text []byte
	if r.Kind == "text" {
		text = make([]byte, 0, int(r.TotalSize))
		defer func() { clear(text) }()
	}
	var total uint64
	err = walkPages(ctx, objects, base, ref, r, func(cr chunkRef) error {
		plain, err := getOpened(objects, r.ContentSeed, contentContext(base, ref.Content, RoleChunk, cr.ChunkIndex), cr.Object, int(cr.Length))
		if err != nil {
			return err
		}
		defer clear(plain)
		if uint64(len(plain)) != cr.Length {
			return ErrCorrupt
		}
		total += uint64(len(plain))
		if r.Kind == "text" {
			text = append(text, plain...)
			return ctx.Err()
		}
		return writeVerified(ctx, dst, plain)
	})
	if err != nil {
		return err
	}
	if total != r.TotalSize {
		return ErrCorrupt
	}
	if r.Kind == "text" {
		if !utf8.Valid(text) {
			return ErrCorrupt
		}
		return writeVerified(ctx, dst, text)
	}
	return ctx.Err()
}
