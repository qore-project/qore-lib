package qore

import (
	"context"
	"errors"
	"io"
	"testing"
)

type gatedReader struct {
	entered chan struct{}
	release chan struct{}
	started bool
	data    []byte
}

func (r *gatedReader) Read(p []byte) (int, error) {
	if !r.started {
		r.started = true
		close(r.entered)
		<-r.release
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestCloseSerializesWithActiveOperation(t *testing.T) {
	v, path := createTestVault(t)
	reader := &gatedReader{entered: make(chan struct{}), release: make(chan struct{}), data: []byte("accepted before concurrent close")}
	putDone := make(chan error, 1)
	go func() {
		_, err := v.Put(context.Background(), PutOptions{Name: "serialized", Kind: "text"}, reader)
		putDone <- err
	}()
	<-reader.entered
	closeStarted, closeDone := make(chan struct{}), make(chan error, 1)
	go func() {
		close(closeStarted)
		closeDone <- v.Close()
	}()
	<-closeStarted
	select {
	case err := <-closeDone:
		close(reader.release)
		<-putDone
		t.Fatalf("Close completed during active operation: %v", err)
	default:
	}
	close(reader.release)
	if err := <-putDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if _, err := v.List(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed instance accepted operation: %v", err)
	}
	reopened, err := Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	items, err := reopened.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("serialized commit lost: %#v %v", items, err)
	}
	if got := readText(t, reopened, items[0].ID, ""); got != "accepted before concurrent close" {
		t.Fatal(got)
	}
}

func TestCanceledReadAndVerify(t *testing.T) {
	v, _ := createTestVault(t)
	r := putText(t, v, "", "cancellation", "not emitted on canceled read")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writer := &countingWriter{}
	if err := v.Read(ctx, r.ItemID, "", writer); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read ignored cancellation: %v", err)
	}
	if writer.bytes != 0 {
		t.Fatal("canceled Read emitted plaintext")
	}
	if err := v.Verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify ignored cancellation: %v", err)
	}
}

type countingWriter struct{ bytes int }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.bytes += len(p)
	return len(p), nil
}
