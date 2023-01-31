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

package syscont

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nestybox/sysbox-libs/mount"
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

// sortIDMappings sorts the given ID mappings by container ID (in increasing
// order). If byHostID is true, then the mappings are sorted by host ID instead
// (in increasing order).
func sortIDMappings(idMappings []specs.LinuxIDMapping, byHostID bool) {

	if byHostID {
		sort.Slice(idMappings, func(i, j int) bool {
			return idMappings[i].HostID < idMappings[j].HostID
		})
	} else {
		sort.Slice(idMappings, func(i, j int) bool {
			return idMappings[i].ContainerID < idMappings[j].ContainerID
		})
	}
}

// mergeIDMappings coallesces the given user-ns ID mappings into a single continuous range.
// If this can't be done (because either the container IDs or host IDs are non-contiguous,
// an error is returned).
func mergeIDMappings(idMappings []specs.LinuxIDMapping) ([]specs.LinuxIDMapping, error) {

	idMappingLen := len(idMappings)

	if idMappingLen < 2 {
		return idMappings, nil
	}

	sortIDMappings(idMappings, false)

	mergedMapping := specs.LinuxIDMapping{
		ContainerID: idMappings[0].ContainerID,
		HostID:      idMappings[0].HostID,
		Size:        idMappings[0].Size,
	}

	for i := 1; i < idMappingLen; i++ {
		curr := idMappings[i]
		prev := idMappings[i-1]

		if curr.ContainerID != (prev.ContainerID + prev.Size) {
			return nil, fmt.Errorf("container ID mappings are non-contiguous: %+v", idMappings)
		}
		if curr.HostID != (prev.HostID + prev.Size) {
			return nil, fmt.Errorf("host ID mappings are non-contiguous: %+v", idMappings)
		}

		mergedMapping.Size += curr.Size
	}

	return []specs.LinuxIDMapping{mergedMapping}, nil
}

func rootfsCloningRequired(rootfs string) (bool, error) {

	// If the rootfs is on an overlayfs mount, then chown can be very slow unless
	// the overlay was mounted with "metacopy=on" (in the order of many seconds
	// because it triggers a "copy-up" of every file). If metacopy is disabled
	// then we need a solution. Note that Docker does not set metacopy=on because
	// it breaks container snapshots via "docker commit" or "docker build".
	//
	// A simple solution would be to add "metacopy=on" to the existing overlayfs
	// mount on the rootfs via a remount. However, this is not supported by
	// overlayfs. We could unmount and then remount, but the unmount may break
	// the container manager that set up the mount. We tried, it did not work
	// (Docker/containerd did not like it).
	//
	// The solution we came up with is to ask the sysbox-mgr to clone the rootfs
	// at a separate location, using two stacked overlayfs mounts, one with
	// metacopy=on to enable fast chown, the other without it to ensure container
	// snapshots work properly. Once the rootfs is cloned, we then setup the
	// container using this cloned rootfs.

	mounts, err := mount.GetMounts()
	if err != nil {
		return false, err
	}

	mi, err := mount.GetMountAt(rootfs, mounts)
	if err == nil && mi.Fstype == "overlay" && !strings.Contains(mi.Opts, "metacopy=on") {
		return true, nil
	}

	return false, nil
}
