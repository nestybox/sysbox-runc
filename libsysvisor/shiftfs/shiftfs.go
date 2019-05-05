package shiftfs

import (
	"fmt"

	"github.com/opencontainers/runc/libcontainer/mount"
	"golang.org/x/sys/unix"
)

// Mount performs a shiftfs mount of the given path on the user-ns of the process with the given pid.
// The path must be a directory.
func Mount(path string, pid int) error {

	if mounted, err := mount.MountedWithFs(path, "shiftfs"); mounted || err != nil {
		return err
	}

	// If the bind source is on tmpfs, we can't mount shiftfs on it. See sysvisor github issue #123.
	if mounted, err := mount.MountedWithFs(path, "tmpfs"); mounted || err != nil {
		if err != nil {
			return err
		} else {
			return fmt.Errorf("mounting shiftfs on tmpfs at %s is not supported", path)
		}
	}

	opt := fmt.Sprintf("userns=/proc/%d/ns/user", pid)
	if err := unix.Mount(path, path, "shiftfs", 0, opt); err != nil {
		return fmt.Errorf("failed to mount shiftfs for pid %d on %s: %v", pid, path, err)
	}

	return nil
}

// Unmount performs a shiftfs umount of the given path
// The path must be a directory.
func Unmount(path string) error {

	if mounted, err := mount.MountedWithFs(path, "shiftfs"); !mounted || err != nil {
		return err
	}

	if err := unix.Unmount(path, 0); err != nil {
		return fmt.Errorf("failed to unmount %s: %v", path, err)
	}

	return nil
}
