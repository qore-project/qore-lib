//go:build windows

package qore

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
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
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var descriptor *windows.SECURITY_DESCRIPTOR
	var attributes *windows.SecurityAttributes
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.CREATE_NEW
		user, e := windows.GetCurrentProcessToken().GetTokenUser()
		if e != nil {
			return nil, e
		}
		// A protected DACL grants only the current user full access. Failure to
		// establish it is fatal; inherited broad ACLs are never a fallback.
		descriptor, err = windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
		if err != nil {
			return nil, err
		}
		attributes = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, attributes, disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(descriptor)
	if err != nil {
		if !create && (errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)) {
			return nil, ErrLocked
		}
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	var native windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &native); err != nil {
		_ = file.Close()
		return nil, err
	}
	if native.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = file.Close()
		return nil, ErrInvalid
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || (before != nil && !os.SameFile(before, after)) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalid
	}
	if create {
		var flags uint32
		if err = windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &flags, nil, 0); err != nil {
			_ = file.Close()
			return nil, err
		}
		if flags&windows.FILE_PERSISTENT_ACLS == 0 {
			_ = file.Close()
			return nil, ErrInvalid
		}
	}
	return file, nil
}

// Windows has no supported POSIX directory-fsync equivalent. Native creation
// uses FILE_FLAG_WRITE_THROUGH, and bbolt flushes accepted transactions. This
// does not establish a directory-entry/namespace durability guarantee across
// power loss. Process interruption still preserves acknowledged transactions.
// ACL protection requires a filesystem that enforces Windows DACLs; trusted OS
// administrators and compromised operating systems remain outside this boundary.
func syncParent(string) error { return nil }
