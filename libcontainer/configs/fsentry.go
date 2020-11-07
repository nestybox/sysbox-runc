//
// Copyright 2020 Nestybox, Inc.
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

package configs

import "os"

type FsEntryKind uint32

const (
	InvalidFsKind FsEntryKind = iota
	FileFsKind
	DirFsKind
	SoftlinkFsKind
)

//
// FsEntry type is utilized to hold file-system state (e.g. dir, file, softlinks,
// etc) to be created in container's rootfs.
//
type FsEntry struct {
	Kind FsEntryKind
	Path string      // holds the path + name of the fsentry
	Mode os.FileMode // regular filemode
	Dst  string      // only relevant in SoftlinkFsKind types
}

func NewFsEntry(path, dst string, mode os.FileMode, kind FsEntryKind) *FsEntry {

	entry := &FsEntry{
		Kind: kind,
		Path: path,
		Mode: mode,
		Dst:  dst,
	}

	return entry
}

func (e *FsEntry) Add() error {

	switch e.Kind {

	case FileFsKind:
		// Check if file exists.
		var _, err = os.Stat(e.Path)

		// Create file if not exits.
		if os.IsNotExist(err) {
			file, err := os.OpenFile(e.Path, os.O_RDWR|os.O_CREATE, e.Mode)
			if err != nil {
				return err
			}
			defer file.Close()
		}

	case DirFsKind:
		if err := os.MkdirAll(e.Path, e.Mode); err != nil {
			return err
		}

	case SoftlinkFsKind:
		// Check if softlink exists.
		var _, err = os.Stat(e.Path)

		// Create softlink if not present.
		if os.IsNotExist(err) {
			// In Linux softlink permissions are irrelevant; i.e. changing a
			// permission on a symbolic link by chmod() will simply act as if it
			// was performed against the target of the symbolic link, so we are
			// obviating it here.
			if err := os.Symlink(e.Dst, e.Path); err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *FsEntry) Remove() error {
	if err := os.RemoveAll(e.Path); err != nil {
		return err
	}

	return nil
}

func (e *FsEntry) GetPath() string {
	return e.Path
}

func (e *FsEntry) GetMode() os.FileMode {
	return e.Mode
}

func (e *FsEntry) GetKind() FsEntryKind {
	return e.Kind
}

func (e *FsEntry) GetDest() string {
	return e.Dst
}
