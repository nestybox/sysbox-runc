//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package syscont

import (
	"fmt"
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
