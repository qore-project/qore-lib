//go:build !windows

package qore

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func privateFile(path string, create bool) (*os.File, error) {
	var before os.FileInfo
	if !create {
		var err error
		before, err = os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !before.Mode().IsRegular() {
			return nil, ErrInvalid
		}
	}
	// NONBLOCK prevents a substituted FIFO from hanging before the descriptor
	// can be checked. NOFOLLOW rejects a substituted final symlink.
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || (before != nil && !os.SameFile(before, after)) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalid
	}
	return file, nil
}

func syncParent(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	// Directory sync errors are part of the creation result, not best effort.
	return errors.Join(directory.Sync(), directory.Close())
}
