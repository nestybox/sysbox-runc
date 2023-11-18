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

func findSeccompSyscall(seccomp *specs.LinuxSeccomp, targetSyscalls []string) (allFound bool, notFound []string) {
	if seccomp == nil {
		return false, notFound
	}

	for _, target := range targetSyscalls {
		found := false
		for _, syscall := range seccomp.Syscalls {
			for _, name := range syscall.Names {
				if name == target {
					found = true
				}
			}
		}
		if !found {
			notFound = append(notFound, target)
		}
	}

	allFound = (len(notFound) == 0)
	return allFound, notFound
}

// genSeccompWhitelist generates a seccomp whitelist from the given syscall slice
func genSeccompWhitelist(syscalls []string) []specs.LinuxSyscall {
	specSyscalls := []specs.LinuxSyscall{}
	for _, s := range syscalls {
		newSpecSyscall := specs.LinuxSyscall{
			Names:  []string{s},
			Action: specs.ActAllow,
		}
		specSyscalls = append(specSyscalls, newSpecSyscall)
	}
	return specSyscalls
}

func TestCfgSeccomp(t *testing.T) {
	var seccomp *specs.LinuxSeccomp

	// Test handling of nil seccomp
	if err := cfgSeccomp(nil); err != nil {
		t.Errorf("cfgSeccomp: returned error: %v", err)
	}

	// Test handling of unsupported arch
	seccomp = &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchARM},
		Syscalls:      []specs.LinuxSyscall{},
	}
	if err := cfgSeccomp(seccomp); err != nil {
		t.Errorf("cfgSeccomp: failed to handle unsupported arch: %v", err)
	}

	// Test handling of empty syscall whitelist
	seccomp = &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
		Syscalls:      []specs.LinuxSyscall{},
	}
	if err := cfgSeccomp(seccomp); err != nil {
		t.Errorf("cfgSeccomp: returned error: %v", err)
	}
	if ok, notFound := findSeccompSyscall(seccomp, syscontSyscallWhitelist); !ok {
		t.Errorf("cfgSeccomp: empty whitelist test failed: missing syscalls: %s", notFound)
	}

	// Test handling of complete syscall whitelist
	seccomp = &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
		Syscalls:      genSeccompWhitelist(syscontSyscallWhitelist),
	}
	if err := cfgSeccomp(seccomp); err != nil {
		t.Errorf("cfgSeccomp: returned error: %v", err)
	}
	if ok, notFound := findSeccompSyscall(seccomp, syscontSyscallWhitelist); !ok {
		t.Errorf("cfgSeccomp: full whitelist test failed: missing syscalls: %s", notFound)
	}

	// Test handling of incomplete syscall whitelist
	partialList := []string{"accept", "accept4", "access", "adjtimex"}
	seccomp = &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
		Syscalls:      genSeccompWhitelist(partialList),
	}
	if err := cfgSeccomp(seccomp); err != nil {
		t.Errorf("cfgSeccomp: returned error: %v", err)
	}
	if ok, notFound := findSeccompSyscall(seccomp, syscontSyscallWhitelist); !ok {
		t.Errorf("cfgSeccomp: incomplete whitelist test failed: missing syscalls: %s", notFound)
	}

	// Test handling of whitelist with multiple syscalls per LinuxSyscall entry
	linuxSyscall := specs.LinuxSyscall{
		Names:  syscontSyscallWhitelist,
		Action: specs.ActAllow,
	}
	seccomp = &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
		Syscalls:      []specs.LinuxSyscall{linuxSyscall},
	}
	if err := cfgSeccomp(seccomp); err != nil {
		t.Errorf("cfgSeccomp: returned error: %v", err)
	}
	if ok, notFound := findSeccompSyscall(seccomp, syscontSyscallWhitelist); !ok {
		t.Errorf("cfgSeccomp: multiple syscall per entry whitelist test failed: missing syscalls: %s", notFound)
	}

	// Docker uses whitelists, so we skip the blacklist tests for now
	// TODO: Test handling of empty blacklist
	// TODO: Test handling of conflicting blacklist
	// TODO: Test handling of non-conflicting blacklist
}

// Test removal of seccomp syscall arg restrictions
func TestCfgSeccompArgRemoval(t *testing.T) {

	// The following resembles the way Docker programs seccomp syscall argument
	// restrictions for the "personality" and "clone" syscalls.

	personalityArg := specs.LinuxSeccompArg{
		Index: 0,
		Value: 131072,
		Op:    "SCMP_CMP_EQ",
	}

	cloneArg := specs.LinuxSeccompArg{
		Index: 0,
		Value: 2080505856,
		Op:    "SCMP_CMP_MASKED_EQ",
	}

	seccomp := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"personality"},
				Action: "SCMP_ACT_ALLOW",
				Args:   []specs.LinuxSeccompArg{personalityArg},
			},
			{
				Names:  []string{"clone"},
				Action: "SCMP_ACT_ALLOW",
				Args:   []specs.LinuxSeccompArg{cloneArg},
			},
		},
	}

	if err := cfgSeccomp(seccomp); err != nil {
		t.Errorf("cfgSeccomp: returned error: %v", err)
	}

	// Verify that arg restrictions for personality() where left untouched, while arg
	// restrictions for clone() were removed. See syscontSyscallAllowRestrList.

	if seccomp.Syscalls[0].Args[0] != personalityArg {
		t.Errorf("cfgSeccompArgRemoval failed: personality() syscall args invalid: want %v, got %v", personalityArg, seccomp.Syscalls[0].Args[0])
	}

	if seccomp.Syscalls[1].Args != nil {
		t.Errorf("cfgSeccompArgRemoval failed: clone() syscall args invalid: want nil, got %v", seccomp.Syscalls[1].Args)
	}
}

func TestCfgMaskedPaths(t *testing.T) {
	spec := new(specs.Spec)
	spec.Linux = new(specs.Linux)
	spec.Linux.MaskedPaths = []string{"/proc", "/some/path", "/proc/sys", "/other/path"}
	spec.Process = new(specs.Process)
	spec.Process.Args = []string{"/bin/bash"}

	cfgMaskedPaths(spec)

	for _, mp := range spec.Linux.MaskedPaths {
		for _, ep := range syscontExposedPaths {
			if mp == ep {
				t.Errorf("cfgMaskedPaths: failed to unmask path %s", ep)
			}
		}
	}

	want := []string{"/some/path", "/other/path"}
	if !utils.StringSliceEqual(spec.Linux.MaskedPaths, want) {
		t.Errorf("cfgMaskedPaths: removed unexpected path; got %v, want %v", spec.Linux.MaskedPaths, want)
	}
}

func TestCfgReadonlyPaths(t *testing.T) {
	spec := new(specs.Spec)
	spec.Linux = new(specs.Linux)
	spec.Linux.ReadonlyPaths = []string{"/proc", "/some/path", "/proc/sys", "/other/path"}
	spec.Process = new(specs.Process)
	spec.Process.Args = []string{"/bin/bash"}

	cfgReadonlyPaths(spec)

	for _, rop := range spec.Linux.ReadonlyPaths {
		for _, rwp := range syscontRwPaths {
			if rop == rwp {
				t.Errorf("cfgReadonlyPaths: failed to remove read-only on path %s", rwp)
			}
		}
	}

	want := []string{"/some/path", "/other/path"}
	if !utils.StringSliceEqual(spec.Linux.ReadonlyPaths, want) {
		t.Errorf("cfgReadonlyPaths: removed unexpected path; got %v, want %v", spec.Linux.ReadonlyPaths, want)
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

	sortMounts(spec)

	if !utils.MountSliceEqual(spec.Mounts, wantMounts) {
		t.Errorf("sortMounts() failed: got %v, want %v", spec.Mounts, wantMounts)
	}
}

func TestCfgSystemd(t *testing.T) {

	spec := new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Linux = new(specs.Linux)

	// Create a spec that has intentional conflicts with systemd resources
	spec.Process.Args = []string{"/sbin/init"}

	spec.Mounts = []specs.Mount{
		specs.Mount{
			Source:      "/somepath",
			Destination: "/run",
			Type:        "bind",
			Options:     []string{"ro", "rprivate"},
		},
		specs.Mount{
			Source:      "/otherpath",
			Destination: "/run/lock",
			Type:        "bind",
			Options:     []string{"rw"},
		},
		specs.Mount{
			Source:      "/somepath",
			Destination: "/test",
			Type:        "bind",
			Options:     []string{"ro", "rprivate"},
		},
	}

	// This call should remove the conflicting info above
	cfgSystemdMounts(spec)

	wantMounts := []specs.Mount{
		specs.Mount{
			Source:      "/somepath",
			Destination: "/test",
			Type:        "bind",
			Options:     []string{"ro", "rprivate"},
		},
		specs.Mount{
			Source:      "tmpfs",
			Destination: "/run",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "nosuid", "nodev", "mode=755", "size=64m"},
		},
		specs.Mount{
			Source:      "tmpfs",
			Destination: "/run/lock",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "size=4m"},
		},
	}

	if !utils.MountSliceEqual(spec.Mounts, wantMounts) {
		t.Errorf("cfgSystemd() failed: spec.Mounts: want %v, got %v", wantMounts, spec.Mounts)
	}
}

func TestCfgSystemdOverride(t *testing.T) {

	spec := new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Linux = new(specs.Linux)

	// Create a spec that overrides the sysbox systemd mounts (spec tmpfs mounts override
	// the sysbox tmpfs mounts for systemd).
	spec.Process.Args = []string{"/sbin/init"}

	spec.Mounts = []specs.Mount{
		specs.Mount{
			Source:      "/somepath",
			Destination: "/run",
			Type:        "tmpfs",
			Options:     []string{"rw", "nosuid", "noexec", "size=128m"},
		},
		specs.Mount{
			Source:      "/otherpath",
			Destination: "/run/lock",
			Type:        "tmpfs",
			Options:     []string{"rw", "nosuid", "noexec", "size=8m"},
		},
	}

	wantMounts := spec.Mounts

	// This call should honor the spec mount overrides.
	cfgSystemdMounts(spec)

	if !utils.MountSliceEqual(spec.Mounts, wantMounts) {
		t.Errorf("cfgSystemd() failed: spec.Mounts: want %v, got %v", wantMounts, spec.Mounts)
	}
}

func TestValidateIDMappings(t *testing.T) {
	var err error

	spec := new(specs.Spec)
	spec.Linux = new(specs.Linux)

	// Test empty user-ns ID mappings
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{}
	spec.Linux.GIDMappings = []specs.LinuxIDMapping{}

	err = validateIDMappings(spec)
	if err == nil {
		t.Errorf("validateIDMappings(): expected failure due to empty mappings, but it passed")
	}

	// Test non-contiguous container ID mappings
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 1},
		{ContainerID: 2, HostID: 1000001, Size: 65535},
	}

	spec.Linux.GIDMappings = spec.Linux.UIDMappings

	err = validateIDMappings(spec)
	if err == nil {
		t.Errorf("validateIDMappings(): expected failure due to non-contiguous container ID mappings, but it passed")
	}

	// Test non-contiguous host ID mappings
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 1},
		{ContainerID: 1, HostID: 1000002, Size: 65535},
	}

	spec.Linux.GIDMappings = spec.Linux.UIDMappings

	err = validateIDMappings(spec)
	if err == nil {
		t.Errorf("validateIDMappings(): expected failure due to non-contiguous host ID mappings, but it passed")
	}

	// Test mappings with container ID range starting above 0
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 1, HostID: 1000000, Size: 65536},
	}

	spec.Linux.GIDMappings = spec.Linux.UIDMappings

	err = validateIDMappings(spec)
	if err == nil {
		t.Errorf("validateIDMappings(): expected failure due to container ID range starting above 0, but it passed")
	}

	// Test mappings with ID range below IdRangeMin
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: IdRangeMin - 1},
	}

	spec.Linux.GIDMappings = spec.Linux.UIDMappings

	err = validateIDMappings(spec)
	if err == nil {
		t.Errorf("validateIDMappings(): expected failure due to ID range size < %d, but it passed", IdRangeMin)
	}

	// Test non-matching uid & gid mappings
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 65536},
	}

	spec.Linux.GIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 2000000, Size: 65536},
	}

	err = validateIDMappings(spec)
	if err == nil {
		t.Errorf("validateIDMappings(): expected failure due to non-matching uid & gid mappings, but it passed")
	}

	// Test mapping to host UID 0
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 0, Size: 65536},
	}

	spec.Linux.GIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 2000000, Size: 65536},
	}

	err = validateIDMappings(spec)
	if err == nil {
		t.Errorf("validateIDMappings(): expected failure due to uid mapping to host ID 0, but it passed")
	}

	// Test mapping to host GID 0
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 65536},
	}

	spec.Linux.GIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 0, Size: 65536},
	}

	err = validateIDMappings(spec)
	if err == nil {
		t.Errorf("validateIDMappings(): expected failure due to gid mapping to host ID 0, but it passed")
	}

	// Test valid single entry mapping
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 65536},
	}

	spec.Linux.GIDMappings = spec.Linux.UIDMappings

	err = validateIDMappings(spec)
	if err != nil {
		t.Errorf("validateIDMappings(): expected pass but it failed; mapping = %v", spec.Linux.UIDMappings)
	}

	// Test valid multi-entry mapping is accepted and merged into a single entry mapping
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 1},
		{ContainerID: 1, HostID: 1000001, Size: 9},
		{ContainerID: 10, HostID: 1000010, Size: 65526},
	}

	spec.Linux.GIDMappings = spec.Linux.UIDMappings
	origMapping := spec.Linux.UIDMappings

	err = validateIDMappings(spec)
	if err != nil {
		t.Errorf("validateIDMappings(): expected pass but it failed; mapping = %v", origMapping)
	}

	want := []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000000, Size: 65536},
	}

	if !equalIDMappings(want, spec.Linux.UIDMappings) {
		t.Errorf("validateIDMappings(): uid mappings are not correct; want %v, got %v",
			want, spec.Linux.UIDMappings)
	}

	if !equalIDMappings(want, spec.Linux.GIDMappings) {
		t.Errorf("validateIDMappings(): gid mappings are not correct; want %v, got %v",
			want, spec.Linux.GIDMappings)
	}
}
