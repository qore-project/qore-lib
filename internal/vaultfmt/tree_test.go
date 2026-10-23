package vaultfmt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

type memoryObjects struct {
	data   map[ID][]byte
	puts   int
	failAt int
}

var errStorage = errors.New("injected storage failure")

func newMemoryObjects() *memoryObjects { return &memoryObjects{data: make(map[ID][]byte)} }

func (m *memoryObjects) PutObject(id ID, data []byte) error {
	m.puts++
	if m.failAt != 0 && m.puts == m.failAt {
		return errStorage
	}
	m.data[id] = bytes.Clone(data)
	return nil
}

func (m *memoryObjects) GetObject(id ID, maxBytes int) ([]byte, error) {
	data, ok := m.data[id]
	if !ok {
		return nil, ErrNotFound
	}
	if len(data) > maxBytes {
		return nil, ErrLimit
	}
	return bytes.Clone(data), nil
}

func testBase() Context { return Context{Vault: ID{1}, Control: ID{2}, Item: ID{3}} }

type packetReader struct {
	src    io.Reader
	packet int
}

func (r packetReader) Read(p []byte) (int, error) { return r.src.Read(p[:min(len(p), r.packet)]) }

func storedFixture(t *testing.T) (*memoryObjects, Context, Ref, []byte) {
	t.Helper()
	objects, base := newMemoryObjects(), testBase()
	data := bytes.Repeat([]byte("abcdefgh"), MinChunkSize/4+5)
	ref, _, err := Store(context.Background(), objects, base, "fixture", "file", bytes.NewReader(data), MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	return objects, base, ref, data
}

func TestTreeChunksAreNotReaderPackets(t *testing.T) {
	for _, size := range []int{0, 1, MinChunkSize - 1, MinChunkSize, MinChunkSize + 37, 2 * MinChunkSize} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i)
			}
			objects, base := newMemoryObjects(), testBase()
			ref, meta, err := Store(context.Background(), objects, base, "input", "file", packetReader{bytes.NewReader(data), 7}, MinChunkSize)
			if err != nil {
				t.Fatal(err)
			}
			if meta.Size != uint64(size) || meta.ChunkSize != MinChunkSize {
				t.Fatalf("bad metadata: %#v", meta)
			}
			r, err := readRoot(objects, base, ref)
			if err != nil || r.ChunkCount != uint64((size+MinChunkSize-1)/MinChunkSize) {
				t.Fatalf("packet-defined chunks: %#v %v", r, err)
			}
			gotMeta, err := Inspect(objects, base, ref)
			if err != nil || gotMeta != meta {
				t.Fatalf("inspect: %#v %v", gotMeta, err)
			}
			var out bytes.Buffer
			if err := Load(context.Background(), objects, base, ref, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
				t.Fatalf("load size %d: %v (%d bytes)", size, err, out.Len())
			}
		})
	}
}

func rewriteRoot(t *testing.T, objects *memoryObjects, base Context, ref Ref, change func(*root)) Ref {
	t.Helper()
	r, err := readRoot(objects, base, ref)
	if err != nil {
		t.Fatal(err)
	}
	change(&r)
	id, encoded, err := Seal(ref.Key, contentContext(base, ref.Content, RoleManifest, 0), mustEncode(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.PutObject(id, encoded); err != nil {
		t.Fatal(err)
	}
	ref.Object = id
	return ref
}

func rewritePage(t *testing.T, objects *memoryObjects, base Context, ref Ref, change func(*page)) Ref {
	t.Helper()
	return rewriteRoot(t, objects, base, ref, func(r *root) {
		pr := &r.Pages[0]
		plain, err := getOpened(objects, ref.Key, contentContext(base, ref.Content, RolePage, 0), pr.Object, MaxRecordBytes)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := Decode(plain, MaxRecordBytes, &p); err != nil {
			t.Fatal(err)
		}
		change(&p)
		id, encoded, err := Seal(ref.Key, contentContext(base, ref.Content, RolePage, 0), mustEncode(t, p))
		if err != nil {
			t.Fatal(err)
		}
		if err := objects.PutObject(id, encoded); err != nil {
			t.Fatal(err)
		}
		pr.Object = id
	})
}

func firstPage(t *testing.T, objects *memoryObjects, base Context, ref Ref) page {
	t.Helper()
	r, err := readRoot(objects, base, ref)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := getOpened(objects, ref.Key, contentContext(base, ref.Content, RolePage, 0), r.Pages[0].Object, MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	var p page
	if err := Decode(plain, MaxRecordBytes, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuthenticatedTreeRejectsInvalidHierarchy(t *testing.T) {
	pageCases := map[string]func(*page){
		"duplicate identity":   func(p *page) { p.Chunks[1].Object = p.Chunks[0].Object },
		"wrong index":          func(p *page) { p.Chunks[1].ChunkIndex = 0 },
		"short nonfinal chunk": func(p *page) { p.Chunks[0].Length-- },
		"bad final length":     func(p *page) { p.Chunks[len(p.Chunks)-1].Length++ },
		"missing reference":    func(p *page) { p.Chunks = p.Chunks[:len(p.Chunks)-1] },
		"wrong page count":     func(p *page) { p.ChunkCount-- },
		"wrong page position":  func(p *page) { p.FirstChunk++ },
		"wrong page total":     func(p *page) { p.TotalSize++ },
	}
	for name, change := range pageCases {
		t.Run(name, func(t *testing.T) {
			objects, base, ref, _ := storedFixture(t)
			ref = rewritePage(t, objects, base, ref, change)
			if _, err := Inspect(objects, base, ref); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid authenticated page accepted: %v", err)
			}
			var out bytes.Buffer
			if err := Load(context.Background(), objects, base, ref, &out); err == nil || out.Len() != 0 {
				t.Fatalf("invalid first page released %d bytes: %v", out.Len(), err)
			}
		})
	}
	rootCases := map[string]func(*root){
		"overflow":       func(r *root) { r.TotalSize = ^uint64(0) },
		"bad chunk size": func(r *root) { r.ChunkSize = 1 },
		"bad count":      func(r *root) { r.ChunkCount++ },
		"missing page":   func(r *root) { r.Pages = nil },
		"page order":     func(r *root) { r.Pages[0].PageIndex++ },
		"page range":     func(r *root) { r.Pages[0].FirstChunk++ },
		"page length":    func(r *root) { r.Pages[0].TotalSize-- },
		"invalid kind":   func(r *root) { r.Kind = "other" },
		"empty name":     func(r *root) { r.Name = "" },
	}
	for name, change := range rootCases {
		t.Run(name, func(t *testing.T) {
			objects, base, ref, _ := storedFixture(t)
			ref = rewriteRoot(t, objects, base, ref, change)
			if _, err := Inspect(objects, base, ref); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid authenticated root accepted: %v", err)
			}
		})
	}
}

func TestMissingTamperedReorderedAndSubstitutedChunks(t *testing.T) {
	for _, mode := range []string{"missing", "tampered", "reordered", "other item", "other content"} {
		t.Run(mode, func(t *testing.T) {
			objects, base, ref, data := storedFixture(t)
			p := firstPage(t, objects, base, ref)
			switch mode {
			case "missing":
				delete(objects.data, p.Chunks[1].Object)
			case "tampered":
				objects.data[p.Chunks[1].Object][100] ^= 1
			case "reordered":
				ref = rewritePage(t, objects, base, ref, func(p *page) { p.Chunks[0].Object, p.Chunks[1].Object = p.Chunks[1].Object, p.Chunks[0].Object })
			case "other item":
				base.Item[0]++
			case "other content":
				ref.Content[0]++
			}
			var out bytes.Buffer
			if err := Load(context.Background(), objects, base, ref, &out); err == nil {
				t.Fatal("incomplete or substituted tree returned success")
			}
			if !bytes.Equal(out.Bytes(), data[:out.Len()]) {
				t.Fatal("load exposed unauthenticated or reordered data")
			}
			if (mode == "missing" || mode == "tampered") && out.Len() != MinChunkSize {
				t.Fatalf("expected only authenticated prefix, got %d", out.Len())
			}
		})
	}
}

type errorAtBoundary struct{ done bool }

func (r *errorAtBoundary) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	clear(p)
	return len(p), errStorage
}

type cancelReader struct {
	cancel context.CancelFunc
}

func (r cancelReader) Read(p []byte) (int, error) {
	clear(p)
	r.cancel()
	return len(p), nil
}

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestInputFailuresCancellationAndShortWrites(t *testing.T) {
	objects, base := newMemoryObjects(), testBase()
	ref, _, err := Store(context.Background(), objects, base, "error", "file", &errorAtBoundary{}, MinChunkSize)
	if !errors.Is(err, errStorage) || ref != (Ref{}) || objects.puts != 0 {
		t.Fatalf("discarded full-read input error: %v %#v", err, ref)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ref, _, err = Store(ctx, objects, base, "cancel", "file", cancelReader{cancel}, MinChunkSize)
	if !errors.Is(err, context.Canceled) || ref != (Ref{}) || objects.puts != 0 {
		t.Fatalf("published cancelled upload: %v", err)
	}
	ref, _, err = Store(context.Background(), objects, base, "stalled", "file", noProgressReader{}, MinChunkSize)
	if !errors.Is(err, io.ErrNoProgress) || ref != (Ref{}) {
		t.Fatalf("stalled reader: %v", err)
	}
	objects.failAt = 2 // First chunk persists, final page fails, no root is returned.
	ref, _, err = Store(context.Background(), objects, base, "failure", "file", strings.NewReader("data"), MinChunkSize)
	if !errors.Is(err, errStorage) || ref != (Ref{}) {
		t.Fatalf("published failed upload: %v", err)
	}
	objects, base, ref, _ = storedFixture(t)
	if err := Load(context.Background(), objects, base, ref, shortWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	if err := Load(ctx, objects, base, ref, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load: %v", err)
	}
}

func TestTextUTF8LimitsAndChunkBoundary(t *testing.T) {
	objects, base := newMemoryObjects(), testBase()
	text := strings.Repeat("a", MinChunkSize-1) + "€" + strings.Repeat("b", 41)
	ref, _, err := Store(context.Background(), objects, base, "text", "text", strings.NewReader(text), MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Load(context.Background(), objects, base, ref, &out); err != nil || out.String() != text {
		t.Fatalf("split UTF8 rune: %v", err)
	}
	before := objects.puts
	for _, bad := range [][]byte{{0xff}, bytes.Repeat([]byte{'a'}, MaxTextSize+1)} {
		if _, _, err := Store(context.Background(), objects, base, "text", "text", bytes.NewReader(bad), MinChunkSize); err == nil || objects.puts != before {
			t.Fatal("published invalid or oversized text")
		}
	}
	if _, _, err := Store(context.Background(), objects, base, string([]byte{0xff}), "file", strings.NewReader(""), MinChunkSize); err == nil {
		t.Fatal("accepted invalid UTF8 name")
	}
	if _, _, err := Store(context.Background(), objects, base, strings.Repeat("n", MaxNameBytes+1), "file", strings.NewReader(""), MinChunkSize); !errors.Is(err, ErrLimit) {
		t.Fatal("accepted oversized name")
	}
	// Even a correctly encrypted chunk cannot make invalid UTF8 a successful text.
	objects, base, ref, _ = storedFixture(t)
	ref = rewriteRoot(t, objects, base, ref, func(r *root) { r.Kind = "text" })
	r, err := readRoot(objects, base, ref)
	if err != nil {
		t.Fatal(err)
	}
	ref = rewritePage(t, objects, base, ref, func(p *page) {
		cr := &p.Chunks[0]
		bad := bytes.Repeat([]byte{0xff}, int(cr.Length))
		id, encoded, err := Seal(r.ContentSeed, contentContext(base, ref.Content, RoleChunk, 0), bad)
		if err != nil {
			t.Fatal(err)
		}
		if err := objects.PutObject(id, encoded); err != nil {
			t.Fatal(err)
		}
		cr.Object = id
	})
	out.Reset()
	if err := Load(context.Background(), objects, base, ref, &out); !errors.Is(err, ErrCorrupt) || out.Len() != 0 {
		t.Fatalf("invalid authenticated text exposed output: %v", err)
	}
}

type repeatedReader struct{ remaining int64 }

func (r *repeatedReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), r.remaining))
	for i := range p[:n] {
		p[i] = 0x5a
	}
	r.remaining -= int64(n)
	return n, nil
}

type patternWriter struct{ count uint64 }

func (w *patternWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0x5a {
			return 0, errors.New("wrong streamed bytes")
		}
	}
	w.count += uint64(len(p))
	return len(p), nil
}

func TestTreeCrossesPageBoundary(t *testing.T) {
	objects, base := newMemoryObjects(), testBase()
	size := int64(pageChunks)*MinChunkSize + 17
	ref, _, err := Store(context.Background(), objects, base, "pages", "file", &repeatedReader{size}, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	r, err := readRoot(objects, base, ref)
	if err != nil || len(r.Pages) != 2 || r.Pages[0].ChunkCount != pageChunks || r.Pages[1].FirstChunk != pageChunks || r.Pages[1].TotalSize != 17 {
		t.Fatalf("page boundary schema: %#v %v", r.Pages, err)
	}
	var out patternWriter
	if err := Load(context.Background(), objects, base, ref, &out); err != nil || out.count != uint64(size) {
		t.Fatalf("streamed multipage load: %d %v", out.count, err)
	}
	ref = rewriteRoot(t, objects, base, ref, func(r *root) { r.Pages[1].Object = r.Pages[0].Object })
	if _, err := Inspect(objects, base, ref); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate page accepted: %v", err)
	}
}

func TestReferencedMetadataMustExist(t *testing.T) {
	for _, which := range []string{"root", "page"} {
		t.Run(which, func(t *testing.T) {
			objects, base, ref, _ := storedFixture(t)
			id := ref.Object
			if which == "page" {
				r, err := readRoot(objects, base, ref)
				if err != nil {
					t.Fatal(err)
				}
				id = r.Pages[0].Object
			}
			delete(objects.data, id)
			if _, err := Inspect(objects, base, ref); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("missing %s: %v", which, err)
			}
			var out bytes.Buffer
			if err := Load(context.Background(), objects, base, ref, &out); !errors.Is(err, ErrCorrupt) || out.Len() != 0 {
				t.Fatalf("missing %s released output: %v", which, err)
			}
		})
	}
}

func TestActualAuthenticatedChunkLengthMustMatch(t *testing.T) {
	for _, delta := range []int{-1, 1} {
		t.Run(strconv.Itoa(delta), func(t *testing.T) {
			objects, base, ref, _ := storedFixture(t)
			r, err := readRoot(objects, base, ref)
			if err != nil {
				t.Fatal(err)
			}
			ref = rewritePage(t, objects, base, ref, func(p *page) {
				cr := &p.Chunks[0]
				plain := bytes.Repeat([]byte{'x'}, int(cr.Length)+delta)
				id, encoded, err := Seal(r.ContentSeed, contentContext(base, ref.Content, RoleChunk, 0), plain)
				if err != nil {
					t.Fatal(err)
				}
				if err := objects.PutObject(id, encoded); err != nil {
					t.Fatal(err)
				}
				cr.Object = id
			})
			var out bytes.Buffer
			if err := Load(context.Background(), objects, base, ref, &out); err == nil || out.Len() != 0 {
				t.Fatalf("authenticated length mismatch released bytes: %v", err)
			}
		})
	}
}

func TestNonPowerOfTwoChunkSize(t *testing.T) {
	objects, base := newMemoryObjects(), testBase()
	const chunkSize = MinChunkSize + 1
	data := bytes.Repeat([]byte{'z'}, chunkSize+3)
	ref, meta, err := Store(context.Background(), objects, base, "odd size", "file", bytes.NewReader(data), chunkSize)
	if err != nil || meta.ChunkSize != chunkSize {
		t.Fatalf("arbitrary supported chunk size: %v", err)
	}
	p := firstPage(t, objects, base, ref)
	if len(p.Chunks) != 2 || p.Chunks[0].Length != chunkSize || p.Chunks[1].Length != 3 {
		t.Fatalf("wrong arbitrary-size chunk boundaries: %#v", p.Chunks)
	}
	var out bytes.Buffer
	if err := Load(context.Background(), objects, base, ref, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("arbitrary-size load: %v", err)
	}
}
