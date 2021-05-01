//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package shiftfs

import (
	"fmt"
	"path/filepath"

	"github.com/opencontainers/runc/libcontainer/mount"
	"golang.org/x/sys/unix"
)

// Mark performs a shiftfs mark-mount for path on the given markPath
// (e.g., Mark("/a/b", "/c/d") causes "b" to be mounted on "d" and
// "d" to have a shiftfs mark).
func Mark(path, markPath string) error {
	if err := unix.Mount(path, markPath, "shiftfs", 0, "mark"); err != nil {
		return fmt.Errorf("failed to mark shiftfs on %s at %s: %v", path, markPath, err)
	}
	return nil
}

// Mount performs a shiftfs mount on the given path; the path must have a
// shiftfs mark on it already (e.g., Mount("/c/d", "/x/y") requires that
// "d" have a shiftfs mark on it and causes "d" to be mounted on "y" and
// "y" to have a shiftfs mount).
func Mount(path, mntPath string) error {
	if err := unix.Mount(path, mntPath, "shiftfs", 0, ""); err != nil {
		return fmt.Errorf("failed to mount shiftfs on %s at %s: %v", path, mntPath, err)
	}
	return nil
}

// Unmount perform a shiftfs unmount on the given path. The path must have
// a shiftfs mark or mount on it.
func Unmount(path string) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("failed to unmount %s: %v", path, err)
	}
	return nil
}

// Returns a boolean indicating if the given path has a shiftfs mount
// on it (mark or actual mount).
func Mounted(path string) (bool, error) {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}
	return mount.MountedWithFs(realPath, "shiftfs")
}
