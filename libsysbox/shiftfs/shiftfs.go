package shiftfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

type action int

const (
	doMark action = iota
	doUnmark
	doMount
	doUnmount
)

// IsMarked checks if the given directory has a shiftfs mark
func IsMarked(path string) (bool, error) {
	mountinfo, err := mountinfo.GetMounts(nil)
	if err != nil {
		return false, fmt.Errorf("failed to get mountinfo: %v", err)
	}

	alreadyMarked := false
	for _, info := range mountinfo {
		mountPath := filepath.Join(info.Root, info.Mountpoint)
		if strings.Contains(path, mountPath) && (info.FSType == "shiftfs") {
			opts := strings.Split(info.VFSOptions, ",")
			for _, opt := range opts {
				if opt == "mark" {
					alreadyMarked = true
				}
			}
		}
	}

	return alreadyMarked, nil
}

// apply performs the given shiftfs action on the given path
func apply(path string, action action) error {
	var (
		err    error
		marked bool
		fi     os.FileInfo
	)

	// shiftfs marks and mounts must be applied on directories
	fi, err = os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %v", path, err)
	}
	if !fi.IsDir() {
		path = filepath.Dir(path)
	}

	if action == doMark || action == doUnmark {
		marked, err = IsMarked(path)
		if err != nil {
			return err
		}
	}

	switch action {
	case doMark:
		if !marked {
			if err = unix.Mount(path, path, "shiftfs", 0, "mark"); err != nil {
				return fmt.Errorf("failed to set shiftfs mark on %s: %v", path, err)
			}
		}
	case doUnmark:
		if marked {
			if err = unix.Unmount(path, 0); err != nil {
				return fmt.Errorf("failed to remove shiftfs mark on %s: %v", path, err)
			}
		}
	case doMount:
		if err = unix.Mount(path, path, "shiftfs", 0, ""); err != nil {
			return fmt.Errorf("failed to mount shiftfs over %s: %v", path, err)
		}
	case doUnmount:
		if err = unix.Unmount(path, 0); err != nil {
			return fmt.Errorf("failed to unmount %s: %v", path, err)
		}
	}

	return nil
}

// Mark sets a shiftfs mark on the given path
func Mark(path string) error {
	return apply(path, doMark)
}

// Unmark clears a shiftfs mark on the given path
func Unmark(path string) error {
	return apply(path, doUnmark)
}

// Mount performs a shiftfs mount on the given path
func Mount(path string) error {
	return apply(path, doMount)
}

// Unmount performs a shiftfs umount on the given path
func Unmount(path string) error {
	return apply(path, doUnmount)
}
