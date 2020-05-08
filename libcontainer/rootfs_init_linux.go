package libcontainer

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/selinux/go-selinux/label"
	"golang.org/x/sys/unix"
)

type linuxRootfsInit struct {
	pipe *os.File
	reqs []opReq
}

// getDir returns the path to the directory that contains the file at the given path
func getDir(file string) (string, error) {
	fi, err := os.Stat(file)
	if err != nil {
		return "", fmt.Errorf("stat %s: %v", file, err)
	}
	if !fi.IsDir() {
		return filepath.Dir(file), nil
	} else {
		return file, nil
	}
}

func doBindMount(m *configs.Mount) error {

	// sysbox-runc: For some reason, when the rootfs is on shiftfs, we
	// need to do an Lstat() of the destination path prior to doing the
	// mount. Otherwise we get a "permission denied" error. It took me
	// a while to figure this out. I found out by noticing that the
	// mount cmd (not the syscall) would not hit the permission error,
	// and then did an strace of the syscalls being done by the mount
	// command, which led me to realize that the Lstat() was solving
	// the problem. FYI, in order to do the strace, I had to enable the
	// ptrace syscall inside the container (via the libsysbox's syscalls.go).

	_, err := os.Lstat(filepath.Dir(m.Source))
	if err != nil {
		return err
	}

	if err := unix.Mount(m.Source, m.Destination, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind-mount of %s to %s failed: %v", m.Source, m.Destination, err)
	}

	for _, pflag := range m.PropagationFlags {
		if err := unix.Mount("", m.Destination, "", uintptr(pflag), ""); err != nil {
			return err
		}
	}

	return nil
}

// sysbox-runc:
// Init performs container rootfs initialization actions from within the container's mount
// namespace only. By virtue of only entering the mount namespace, Init has true
// root-level access to the host and thus can perform operations that the container's init
// process is not allowed to.
func (l *linuxRootfsInit) Init() error {

	if len(l.reqs) == 0 {
		return newSystemError(fmt.Errorf("no op requests!"))
	}

	// If multiple requests are passed in the slice, they must all be
	// of the same type.

	switch l.reqs[0].Op {
	case bind:

		// The mount requests assume that the process cwd be the rootfs directory
		rootfs := l.reqs[0].Rootfs
		if err := unix.Chdir(rootfs); err != nil {
			return newSystemErrorWithCausef(err, "chdir to rootfs %s", rootfs)
		}

		for _, req := range l.reqs {
			m := &req.Mount
			mountLabel := req.Label

			if err := doBindMount(m); err != nil {
				return newSystemErrorWithCausef(err, "bind mounting %s to %s", m.Source, m.Destination)
			}

			// The bind mount won't change mount options, we need remount to make mount options effective.
			// first check that we have non-default options required before attempting a remount
			if m.Flags&^(unix.MS_REC|unix.MS_REMOUNT|unix.MS_BIND) != 0 {
				// only remount if unique mount options are set
				if err := remount(m); err != nil {
					return newSystemErrorWithCausef(err, "remount %s to %s", m.Source, m.Destination)
				}
			}

			// Apply label
			if m.Relabel != "" {
				if err := label.Validate(m.Relabel); err != nil {
					return newSystemErrorWithCausef(err, "validating label %s", m.Relabel)
				}
				shared := label.IsShared(m.Relabel)
				if err := label.Relabel(m.Source, mountLabel, shared); err != nil {
					return newSystemErrorWithCausef(err, "relabeling %s to %s", m.Source, mountLabel)
				}
			}
		}

	default:
		return newSystemError(fmt.Errorf("invalid init type"))
	}

	if err := writeSync(l.pipe, opDone); err != nil {
		return err
	}

	l.pipe.Close()
	return nil
}
