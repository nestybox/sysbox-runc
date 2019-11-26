//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package syscont

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// stringSliceEqual compares two slices and returns true if they match
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// stringSliceRemove removes from slice 's' any elements which occur on slice 'db'.
func stringSliceRemove(s, db []string) []string {
	var r []string
	for i := 0; i < len(s); i++ {
		found := false
		for _, e := range db {
			if s[i] == e {
				found = true
				break
			}
		}
		if !found {
			r = append(r, s[i])
		}
	}
	return r
}

// stringSliceRemoveMatch removes from slice 's' any elements for which the 'match'
// function returns true.
func stringSliceRemoveMatch(s []string, match func(string) bool) []string {
	var r []string
	for i := 0; i < len(s); i++ {
		if !match(s[i]) {
			r = append(r, s[i])
		}
	}
	return r
}

// uniquify a string slice (i.e., remove duplicate elements)
func stringSliceUniquify(s []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	for _, str := range s {
		if _, ok := keys[str]; !ok {
			keys[str] = true
			result = append(result, str)
		}
	}
	return result
}

// Compares the given mount slices and returns true if the match
func mountSliceEqual(a, b []specs.Mount) bool {
	if len(a) != len(b) {
		return false
	}
	for i, m := range a {
		if m.Destination != b[i].Destination ||
			m.Source != b[i].Source ||
			m.Type != b[i].Type ||
			!stringSliceEqual(m.Options, b[i].Options) {
			return false
		}
	}
	return true
}

// mountSliceRemove removes from slice 's' any elements which occur on slice 'db'; the
// given function is used to compare elements.
func mountSliceRemove(s, db []specs.Mount, cmp func(m1, m2 specs.Mount) bool) []specs.Mount {
	var r []specs.Mount
	for i := 0; i < len(s); i++ {
		found := false
		for _, e := range db {
			if cmp(s[i], e) {
				found = true
				break
			}
		}
		if !found {
			r = append(r, s[i])
		}
	}
	return r
}

// mountSliceRemoveMatch removes from slice 's' any elements for which the 'match'
// function returns true.
func mountSliceRemoveMatch(s []specs.Mount, match func(specs.Mount) bool) []specs.Mount {
	var r []specs.Mount
	for i := 0; i < len(s); i++ {
		if !match(s[i]) {
			r = append(r, s[i])
		}
	}
	return r
}

// mountSliceRemoveStrMatch removes from slice 's' any elements matching the
// string 'str'.
func mountSliceRemoveStrMatch(
	s []specs.Mount,
	str string,
	match func(specs.Mount, string) bool) []specs.Mount {

	var r []specs.Mount
	for i := 0; i < len(s); i++ {
		if !match(s[i], str) {
			r = append(r, s[i])
		}
	}
	return r
}

// getEnvVarInfo returns the name and value of the given environment variable
func getEnvVarInfo(v string) (string, string, error) {
	tokens := strings.Split(v, "=")
	if len(tokens) != 2 {
		return "", "", fmt.Errorf("invalid variable %s", v)
	}
	return tokens[0], tokens[1], nil
}

// finds longest-common-path among the given absolute paths
func longestCommonPath(paths []string) string {

	if len(paths) == 0 {
		return ""
	} else if len(paths) == 1 {
		return paths[0]
	}

	// find the shortest and longest paths in the set
	shortest, longest := paths[0], paths[0]
	for _, p := range paths[1:] {
		if p < shortest {
			shortest = p
		} else if p > longest {
			longest = p
		}
	}

	// find the first 'i' common characters between the shortest and longest paths
	for i := 0; i < len(shortest) && i < len(longest); i++ {
		if shortest[i] != longest[i] {
			return shortest[:i]
		}
	}

	return shortest
}

// returns a list of all symbolic links under the given directory
func followSymlinksUnder(dir string) ([]string, error) {

	// walk dir; if file is symlink (use os.Lstat()), readlink() and add to slice
	symlinks := []string{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		var (
			fi       os.FileInfo
			realpath string
			link     string
		)

		if path == dir {
			return nil
		}
		fi, err = os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to lstat %s: %v", path, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return nil
		}

		link, err = os.Readlink(path)
		if err != nil {
			return fmt.Errorf("failed to resolve symlink at %s: %v", path, err)
		}

		if filepath.IsAbs(link) {
			realpath = link
		} else {
			realpath = filepath.Join(filepath.Dir(path), link)
		}

		symlinks = append(symlinks, realpath)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return symlinks, nil
}

// createMountSpec returns a mount spec with the given source, destination, type, and
// options. 'source' must an absolute path. 'dest' is absolute with respect to the
// container's rootfs. If followSymlinks is true, this function follows symlinks under the
// source path and returns additional mount specs to ensure the symlinks are valid at the
// destination. If symlinkFilt is not empty, only symlinks that resolve to paths that
// are prefixed by the symlinkFilt strings are allowed.
func createMountSpec(source, dest, mountType string, mountOpt []string, followSymlinks bool, symlinkFilt []string) ([]specs.Mount, error) {

	mounts := []specs.Mount{}
	m := specs.Mount{
		Source:      source,
		Destination: dest,
		Type:        mountType,
		Options:     mountOpt,
	}
	mounts = append(mounts, m)

	if followSymlinks {
		links, err := followSymlinksUnder(source)
		if err != nil {
			return nil, fmt.Errorf("failed to follow symlinks under %s: %v", source, err)
		}

		if len(symlinkFilt) == 0 {
			symlinkFilt = append(symlinkFilt, "")
		}

		// apply symlink filtering
		for _, filt := range symlinkFilt {
			filt = filepath.Clean(filt)
			filtLinks := stringSliceRemoveMatch(links, func(s string) bool {
				if strings.HasPrefix(s, filt+"/") {
					return false
				}
				return true
			})

			if len(filtLinks) == 0 {
				continue
			}

			lcp := longestCommonPath(filtLinks)
			lcp = filepath.Clean(lcp)

			// if the lcp is underneath the source, ignore it
			if !strings.HasPrefix(lcp, source+"/") {
				m := specs.Mount{
					Source:      lcp,
					Destination: lcp,
					Type:        mountType,
					Options:     mountOpt,
				}
				mounts = append(mounts, m)
			}
		}
	}

	return mounts, nil
}
