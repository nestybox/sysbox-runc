package libcontainer

import (
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/utils"
)

// mountSourceType indicates what type of file descriptor is being returned. It
// is used to tell rootfs_linux.go whether or not to use move_mount(2) to
// install the mount.
type mountSourceType string

const (
	// An open_tree(2)-style file descriptor that needs to be installed using
	// move_mount(2) to install.
	mountSourceOpenTree mountSourceType = "open_tree"
	// A plain file descriptor that can be mounted through /proc/thread-self/fd.
	mountSourcePlain mountSourceType = "plain-open"
)

type mountSource struct {
	Type mountSourceType `json:"type"`
	file *os.File        `json:"-"`
}

// mountError holds an error from a failed mount or unmount operation.
type mountError struct {
	op      string
	source  string
	srcFile *mountSource
	target  string
	dstFd   string
	flags   uintptr
	data    string
	err     error
}

// int32plus is a collection of int types with >=32 bits.
type int32plus interface {
	int | uint | int32 | uint32 | int64 | uint64 | uintptr
}

// stringifyMountFlags converts mount(2) flags to a string that you can use in
// error messages.
func stringifyMountFlags[Int int32plus](flags Int) string {
	flagNames := []struct {
		name string
		bits Int
	}{
		{"MS_RDONLY", unix.MS_RDONLY},
		{"MS_NOSUID", unix.MS_NOSUID},
		{"MS_NODEV", unix.MS_NODEV},
		{"MS_NOEXEC", unix.MS_NOEXEC},
		{"MS_SYNCHRONOUS", unix.MS_SYNCHRONOUS},
		{"MS_REMOUNT", unix.MS_REMOUNT},
		{"MS_MANDLOCK", unix.MS_MANDLOCK},
		{"MS_DIRSYNC", unix.MS_DIRSYNC},
		{"MS_NOSYMFOLLOW", unix.MS_NOSYMFOLLOW},
		// No (1 << 9) flag.
		{"MS_NOATIME", unix.MS_NOATIME},
		{"MS_NODIRATIME", unix.MS_NODIRATIME},
		{"MS_BIND", unix.MS_BIND},
		{"MS_MOVE", unix.MS_MOVE},
		{"MS_REC", unix.MS_REC},
		// MS_VERBOSE was deprecated and swapped to MS_SILENT.
		{"MS_SILENT", unix.MS_SILENT},
		{"MS_POSIXACL", unix.MS_POSIXACL},
		{"MS_UNBINDABLE", unix.MS_UNBINDABLE},
		{"MS_PRIVATE", unix.MS_PRIVATE},
		{"MS_SLAVE", unix.MS_SLAVE},
		{"MS_SHARED", unix.MS_SHARED},
		{"MS_RELATIME", unix.MS_RELATIME},
		// MS_KERNMOUNT (1 << 22) is internal to the kernel.
		{"MS_I_VERSION", unix.MS_I_VERSION},
		{"MS_STRICTATIME", unix.MS_STRICTATIME},
		{"MS_LAZYTIME", unix.MS_LAZYTIME},
	}
	var (
		flagSet  []string
		seenBits Int
	)
	for _, flag := range flagNames {
		if flags&flag.bits == flag.bits {
			seenBits |= flag.bits
			flagSet = append(flagSet, flag.name)
		}
	}
	// If there were any remaining flags specified we don't know the name of,
	// just add them in an 0x... format.
	if remaining := flags &^ seenBits; remaining != 0 {
		flagSet = append(flagSet, "0x"+strconv.FormatUint(uint64(remaining), 16))
	}
	return strings.Join(flagSet, "|")
}

// Error provides a string error representation.
func (e *mountError) Error() string {
	out := e.op + " "

	if e.source != "" {
		out += "src=" + e.source + ", "
		if e.srcFile != nil {
			out += "srcType=" + string(e.srcFile.Type) + ", "
			out += "srcFd=" + strconv.Itoa(int(e.srcFile.file.Fd())) + ", "
		}
	}
	out += "dst=" + e.target
	if e.dstFd != "" {
		out += ", dstFd=" + e.dstFd
	}

	if e.flags != uintptr(0) {
		out += ", flags=" + stringifyMountFlags(e.flags)
	}
	if e.data != "" {
		out += ", data=" + e.data
	}

	out += ": " + e.err.Error()
	return out
}

// Unwrap returns the underlying error.
// This is a convention used by Go 1.13+ standard library.
func (e *mountError) Unwrap() error {
	return e.err
}

// mount is a simple unix.Mount wrapper, returning an error with more context
// in case it failed.
func mount(source, target, fstype string, flags uintptr, data string) error {
	return mountViaFds(source, nil, target, "", fstype, flags, data)
}

// mountViaFds is a unix.Mount wrapper which uses srcFile instead of source,
// and dstFd instead of target, unless those are empty.
//
// If srcFile is non-nil and flags does not contain MS_REMOUNT, mountViaFds
// will mount it according to the mountSourceType of the file descriptor.
//
// The dstFd argument, if non-empty, is expected to be in the form of a path to
// an opened file descriptor on procfs (i.e. "/proc/thread-self/fd/NN").
//
// If a file descriptor is used instead of a source or a target path, the
// corresponding path is only used to add context to an error in case the mount
// operation has failed.
func mountViaFds(source string, srcFile *mountSource, target, dstFd, fstype string, flags uintptr, data string) error {
	// MS_REMOUNT and srcFile don't make sense together.
	if srcFile != nil && flags&unix.MS_REMOUNT != 0 {
		logrus.Debugf("mount source passed along with MS_REMOUNT -- ignoring srcFile")
		srcFile = nil
	}
	dst := target
	if dstFd != "" {
		dst = dstFd
	}
	src := source
	isMoveMount := srcFile != nil && srcFile.Type == mountSourceOpenTree
	if srcFile != nil {
		// If we're going to use the /proc/thread-self/... path for classic
		// mount(2), we need to get a safe handle to /proc/thread-self. This
		// isn't needed for move_mount(2) because in that case the path is just
		// a dummy string used for error info.
		srcFileFd := srcFile.file.Fd()
		if isMoveMount {
			src = "/proc/self/fd/" + strconv.Itoa(int(srcFileFd))
		} else {
			var closer utils.ProcThreadSelfCloser
			src, closer = utils.ProcThreadSelfFd(srcFileFd)
			defer closer()
		}
	}

	var op string
	var err error
	if isMoveMount {
		op = "move_mount"
		err = unix.MoveMount(int(srcFile.file.Fd()), "",
			unix.AT_FDCWD, dstFd,
			unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_SYMLINKS)
	} else {
		op = "mount"
		err = unix.Mount(src, dst, fstype, flags, data)
	}
	if err != nil {
		return &mountError{
			op:      op,
			source:  source,
			srcFile: srcFile,
			target:  target,
			dstFd:   dstFd,
			flags:   flags,
			data:    data,
			err:     err,
		}
	}
	return nil
}

// unmount is a simple unix.Unmount wrapper.
func unmount(target string, flags int) error {
	err := unix.Unmount(target, flags)
	if err != nil {
		return &mountError{
			op:     "unmount",
			target: target,
			flags:  uintptr(flags),
			err:    err,
		}
	}
	return nil
}

// syscallMode returns the syscall-specific mode bits from Go's portable mode bits.
// Copy from https://cs.opensource.google/go/go/+/refs/tags/go1.20.7:src/os/file_posix.go;l=61-75
func syscallMode(i fs.FileMode) (o uint32) {
	o |= uint32(i.Perm())
	if i&fs.ModeSetuid != 0 {
		o |= unix.S_ISUID
	}
	if i&fs.ModeSetgid != 0 {
		o |= unix.S_ISGID
	}
	if i&fs.ModeSticky != 0 {
		o |= unix.S_ISVTX
	}
	// No mapping for Go's ModeTemporary (plan9 only).
	return o
}
