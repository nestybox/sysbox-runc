
package syscont

import (
	"sort"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// sortMounts sorts the sys container mounts in the given spec.
func sortMounts(spec *specs.Spec) {

	// The OCI spec requires the runtime to honor the ordering on
	// mounts in the spec. However, we deviate a bit and always order
	// the mounts in the orderList below.

	// First, sort by destination prefix
	orderList := map[string]int{
		"/sys":  1,
		"/proc": 2,
		"/dev":  3,
	}

	sort.SliceStable(spec.Mounts, func(i, j int) bool {

		// for mounts in the sort list, sort them by destination path
		d1 := spec.Mounts[i].Destination
		d2 := spec.Mounts[j].Destination

		d1Prefix := ""
		for prefix := range orderList {
			if strings.HasPrefix(d1, prefix) {
				d1Prefix = prefix
				break
			}
		}

		d2Prefix := ""
		for prefix := range orderList {
			if strings.HasPrefix(d2, prefix) {
				d2Prefix = prefix
				break
			}
		}

		if d1Prefix != "" && d2Prefix != "" {
			if d1Prefix != d2Prefix {
				return orderList[d1Prefix] < orderList[d2Prefix]
			} else {
				return d1 < d2
			}
		} else if d1Prefix != "" && d2Prefix == "" {
			return true
		} else if d1Prefix == "" && d2Prefix != "" {
			return false
		}

		// for mounts not in the sort list, leave their ordering untouched
		return false
	})

	// Now, place all the bind mounts at the end of the mount list (this improves performance
	// as it allows us to process the bind mounts in bulk (see rootfs_linux.go))
	sort.SliceStable(spec.Mounts, func(i, j int) bool {

		t1 := spec.Mounts[i].Type
		t2 := spec.Mounts[j].Type

		if t1 == "bind" && t2 == "bind" {

			// Among bind mounts, sort them such that a mount that
			// depends on another one come after that other one.
			if strings.HasPrefix(spec.Mounts[j].Destination, spec.Mounts[i].Destination) {
				return true
			}

			return false
		}

		if t2 == "bind" {
			return true
		}

		return false
	})

}
