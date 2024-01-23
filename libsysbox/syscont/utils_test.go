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
	"testing"

	utils "github.com/nestybox/sysbox-libs/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func equalIDMappings(a, b []specs.LinuxIDMapping) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func TestMergeIDMappings(t *testing.T) {

	// test merging of continuous ID mappings
	have := []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 1},
		{ContainerID: 1, HostID: 1000001, Size: 2},
		{ContainerID: 3, HostID: 1000003, Size: 65533},
	}

	want := []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 65536},
	}

	got, err := mergeIDMappings(have)

	if err != nil {
		t.Errorf("mergeIDMappings(%v) failed with error: %s", have, err)
	} else if !equalIDMappings(want, got) {
		t.Errorf("mergeIDMappings(%v) failed: got %v, want %v", have, got, want)
	}

	// test that merging on non-continuous host ID mappings fails
	have = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 1},
		{ContainerID: 1, HostID: 1000002, Size: 65535},
	}

	got, err = mergeIDMappings(have)

	if err == nil {
		t.Errorf("mergeIDMappings(%v) passed; expected to fail", have)
	}

	// test that merging on non-continuous container ID mappings fails
	have = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 1},
		{ContainerID: 2, HostID: 1000001, Size: 65535},
	}

	got, err = mergeIDMappings(have)

	if err == nil {
		t.Errorf("mergeIDMappings(%v) passed; expected to fail", have)
	}

	// test single mapping
	have = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 65536},
	}

	want = have
	got, err = mergeIDMappings(have)

	if err != nil {
		t.Errorf("mergeIDMappings(%v) failed with error: %s", have, err)
	} else if !equalIDMappings(want, got) {
		t.Errorf("mergeIDMappings(%v) failed: got %v, want %v", have, got, want)
	}

	// test empty mapping
	have = []specs.LinuxIDMapping{}
	want = have
	got, err = mergeIDMappings(have)

	if err != nil {
		t.Errorf("mergeIDMappings(%v) failed with error: %s", have, err)
	} else if !equalIDMappings(want, got) {
		t.Errorf("mergeIDMappings(%v) failed: got %v, want %v", have, got, want)
	}
}

func TestSortMounts(t *testing.T) {
	spec := new(specs.Spec)

	spec.Mounts = []specs.Mount{
		{Destination: "/dev", Type: "tmpfs"},
		{Destination: "/proc/swaps", Type: "bind"},
		{Destination: "/proc", Type: "proc"},
		{Destination: "/var/lib/docker/overlay2", Type: "bind"},
		{Destination: "/var/lib/docker", Type: "bind"},
		{Destination: "/var/lib/docker/overlay2/diff", Type: "bind"},
		{Destination: "/tmp/run", Type: "tmpfs"},
		{Destination: "/sys/fs/cgroup", Type: "cgroup"},
		{Destination: "/sys", Type: "sysfs"},
		{Destination: "/tmp/run2", Type: "tmpfs"},
	}

	wantMounts := []specs.Mount{
		{Destination: "/sys", Type: "sysfs"},
		{Destination: "/sys/fs/cgroup", Type: "cgroup"},
		{Destination: "/proc", Type: "proc"},
		{Destination: "/dev", Type: "tmpfs"},
		{Destination: "/tmp/run", Type: "tmpfs"},
		{Destination: "/tmp/run2", Type: "tmpfs"},

		// bind mounts should be grouped at the end; bind mounts
		// dependent on others must be placed after those others.

		{Destination: "/proc/swaps", Type: "bind"},
		{Destination: "/var/lib/docker", Type: "bind"},
		{Destination: "/var/lib/docker/overlay2", Type: "bind"},
		{Destination: "/var/lib/docker/overlay2/diff", Type: "bind"},
	}

	sortMounts(spec, false)

	if !utils.MountSliceEqual(spec.Mounts, wantMounts) {
		t.Errorf("sortMounts() failed: got %v, want %v", spec.Mounts, wantMounts)
	}
}

func TestSortMountsSystemd(t *testing.T) {
	spec := new(specs.Spec)

	spec.Mounts = []specs.Mount{
		{Destination: "/run/secrets/serviceaccount/token", Type: "bind"},
		{Destination: "/run/lock", Type: "tmpfs"},
		{Destination: "/var/run/secrets/serviceaccount/token", Type: "bind"},
		{Destination: "/run", Type: "tmpfs"},
	}

	wantMounts := []specs.Mount{
		{Destination: "/run", Type: "tmpfs"},
		{Destination: "/run/lock", Type: "tmpfs"},
		{Destination: "/run/secrets/serviceaccount/token", Type: "bind"},
		{Destination: "/var/run/secrets/serviceaccount/token", Type: "bind"},
	}

	sortMounts(spec, true)

	if !utils.MountSliceEqual(spec.Mounts, wantMounts) {
		t.Errorf("sortMounts() failed: got %v, want %v", spec.Mounts, wantMounts)
	}
}
