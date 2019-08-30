//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package shiftfs

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/opencontainers/runc/libcontainer/mount"
	"golang.org/x/sys/unix"
)

// securityCheck verifies that the given shiftfs mount path meets security requirements
func securityCheck(path string) error {

	// Check that at least one path component is owned by root:root and denies all permissions to "others"
	for d := path; d != "/"; {
		fi, err := os.Stat(d)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return err
		}
		if st.Uid == 0 && st.Gid == 0 {
			if st.Mode&unix.S_IRWXO == 0 {
				return nil
			}
		}
		d = filepath.Dir(d)
	}

	return fmt.Errorf("path %v is not exclusively accessible to the root user or group", path)
}

// Mount performs a shiftfs mount of the given path on the user-ns of the process with the given pid.
// The path must be a directory. Param 'secCheck' indicates if a security check should be performed.
func Mount(path string, pid int, secCheck bool) error {

	if mounted, err := mount.MountedWithFs(path, "nbox_shiftfs"); mounted || err != nil {
		return err
	}

	if secCheck {
		if err := securityCheck(path); err != nil {
			return fmt.Errorf("shiftfs mountpoint security check failed: %v", err)
		}
	}

	opt := fmt.Sprintf("userns=/proc/%d/ns/user", pid)
	if err := unix.Mount(path, path, "nbox_shiftfs", 0, opt); err != nil {
		return fmt.Errorf("failed to mount shiftfs for pid %d on %s: %v", pid, path, err)
	}

	return nil
}

// Unmount performs a shiftfs umount of the given path
// The path must be a directory.
func Unmount(path string) error {

	if mounted, err := mount.MountedWithFs(path, "nbox_shiftfs"); !mounted || err != nil {
		return err
	}

	if err := unix.Unmount(path, 0); err != nil {
		return fmt.Errorf("failed to unmount %s: %v", path, err)
	}

	return nil
}
