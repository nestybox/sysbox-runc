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
	"reflect"
	"testing"

	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
	utils "github.com/nestybox/sysbox-libs/utils"
	"github.com/opencontainers/runc/libsysbox/sysbox"
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

func Test_getSysboxEnvVarConfigs(t *testing.T) {
	type args struct {
		p    *specs.Process
		sbox *sysbox.Sysbox
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		resSbox *sysbox.Sysbox
	}{
		{
			// Test-case 1: Unknown SYSBOX env-var. Expected error.
			name:    "unknown-sysbox-envvar",
			args:    args{p: &specs.Process{Env: []string{"SYSBOX_ENV=1"}}, sbox: &sysbox.Sysbox{}},
			wantErr: true,
		},
		{
			// Test-case 2: Invalid format for generic env-var. Error expected.
			name:    "invalid-format-generic-envvar",
			args:    args{p: &specs.Process{Env: []string{"SYSBOX_HONOR_CAPS"}}, sbox: &sysbox.Sysbox{}},
			wantErr: true,
		},
		{
			// Test-case 3: Invalid format for boolean env-var. Error expected.
			name:    "invalid-format-bool-envvar",
			args:    args{p: &specs.Process{Env: []string{"SYSBOX_HONOR_CAPS=1"}}, sbox: &sysbox.Sysbox{}},
			wantErr: true,
		},
		{
			// Test-case 4: Invalid format for string env-var. Error expected.
			name:    "invalid-format-string-envvar",
			args:    args{p: &specs.Process{Env: []string{"SYSBOX_SKIP_UID_SHIFT="}}, sbox: &sysbox.Sysbox{}},
			wantErr: true,
		},
		{
			// Test-case 5: Verify proper parsing of SYSBOX_SYSCONT_MODE. No error expected.
			name:    "syscont-mode-envvar",
			args:    args{p: &specs.Process{Env: []string{"SYSBOX_SYSCONT_MODE=FALSE"}}, sbox: &sysbox.Sysbox{Mgr: &sysbox.Mgr{Config: &ipcLib.ContainerConfig{SyscontMode: false}}}},
			wantErr: false,
			resSbox: &sysbox.Sysbox{Mgr: &sysbox.Mgr{Config: &ipcLib.ContainerConfig{SyscontMode: false}}},
		},
		{
			// Test-case 6: Verify proper parsing of SYSBOX_SKIP_UID_SHIFT. No error expected.
			name:    "skip-uid-shift-envvar",
			args:    args{p: &specs.Process{Env: []string{"SYSBOX_SKIP_UID_SHIFT=/var/lib/1,/var/lib/2,/var/lib/3"}}, sbox: &sysbox.Sysbox{}},
			wantErr: false,
			resSbox: &sysbox.Sysbox{IDshiftIgnoreList: []string{"/var/lib/1", "/var/lib/2", "/var/lib/3"}},
		},
		{
			// Test-case 7: Verify identification of SYSBOX_SKIP_UID_SHIFT's invalid (relative) path. Error expected.
			name:    "skip-uid-shift-envvar-relative-path",
			args:    args{p: &specs.Process{Env: []string{"SYSBOX_SKIP_UID_SHIFT=/var/lib/1,var/lib/2"}}, sbox: &sysbox.Sysbox{}},
			wantErr: true,
		},
		{
			// Test-case 8: Verify identification of SYSBOX_SKIP_UID_SHIFT's invalid path (with spaces). Error expected.
			name:    "skip-uid-shift-envvar-space-in-path",
			args:    args{p: &specs.Process{Env: []string{"SYSBOX_SKIP_UID_SHIFT=/var/lib/1, /var/lib/2"}}, sbox: &sysbox.Sysbox{}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := getSysboxEnvVarConfigs(tt.args.p, tt.args.sbox); (err != nil) != tt.wantErr && tt.args.sbox != tt.resSbox {
				t.Errorf("getSysboxEnvVarConfigs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_cfgSyscontMountsReadOnly(t *testing.T) {
	type args struct {
		sysMgr         *sysbox.Mgr
		spec           *specs.Spec
		expectedMounts []specs.Mount
	}

	sysMgrDefault := &sysbox.Mgr{
		Config: &ipcLib.ContainerConfig{
			RelaxedReadOnly: false,
		},
	}
	sysMgrRelaxedRO := &sysbox.Mgr{
		Config: &ipcLib.ContainerConfig{
			RelaxedReadOnly: true,
		},
	}

	// UT1: test with no overlapping mounts
	mountsUT1 := []specs.Mount{}
	expectedMountsUT1 := []specs.Mount{
		{
			Destination: "/run",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "mode=755", "size=64m"},
		},
		{
			Destination: "/tmp",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "mode=755", "size=64m"},
		},
		{
			Destination: "/sys",
			Source:      "sysfs",
			Type:        "sysfs",
			Options:     []string{"noexec", "nosuid", "nodev", "ro"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Source:      "cgroup",
			Type:        "cgroup",
			Options:     []string{"noexec", "nosuid", "nodev", "ro"},
		},
		{
			Destination: "/proc",
			Source:      "proc",
			Type:        "proc",
			Options:     []string{"noexec", "nosuid", "nodev"},
		},
		{
			Destination: "/dev",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		},
		{
			Destination: "/dev/kmsg",
			Source:      "/dev/null",
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		},
	}

	// UT2: test with overlapping ro mount (/run)
	mountsUT2 := []specs.Mount{
		{
			Destination: "/run",
			Source:      "/somepath",
			Type:        "bind",
			Options:     []string{"ro", "whatever"},
		},
	}
	expectedMountsUT2 := []specs.Mount{
		{
			Destination: "/run",
			Source:      "/somepath",
			Type:        "bind",
			Options:     []string{"ro", "whatever"},
		},
		{
			Destination: "/tmp",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "mode=755", "size=64m"},
		},
		{
			Destination: "/sys",
			Source:      "sysfs",
			Type:        "sysfs",
			Options:     []string{"noexec", "nosuid", "nodev", "ro"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Source:      "cgroup",
			Type:        "cgroup",
			Options:     []string{"noexec", "nosuid", "nodev", "ro"},
		},
		{
			Destination: "/proc",
			Source:      "proc",
			Type:        "proc",
			Options:     []string{"noexec", "nosuid", "nodev"},
		},
		{
			Destination: "/dev",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		},
		{
			Destination: "/dev/kmsg",
			Source:      "/dev/null",
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		},
	}

	// UT3: test with overlapping rw mount (/tmp)
	mountsUT3 := []specs.Mount{
		{
			Destination: "/tmp",
			Source:      "/somepath",
			Type:        "bind",
			Options:     []string{"rw", "whatever"},
		},
	}
	expectedMountsUT3 := []specs.Mount{
		{
			Destination: "/tmp",
			Source:      "/somepath",
			Type:        "bind",
			Options:     []string{"rw", "whatever"},
		},
		{
			Destination: "/run",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "mode=755", "size=64m"},
		},
		{
			Destination: "/sys",
			Source:      "sysfs",
			Type:        "sysfs",
			Options:     []string{"noexec", "nosuid", "nodev", "ro"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Source:      "cgroup",
			Type:        "cgroup",
			Options:     []string{"noexec", "nosuid", "nodev", "ro"},
		},
		{
			Destination: "/proc",
			Source:      "proc",
			Type:        "proc",
			Options:     []string{"noexec", "nosuid", "nodev"},
		},
		{
			Destination: "/dev",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		},
		{
			Destination: "/dev/kmsg",
			Source:      "/dev/null",
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		},
	}

	// UT4: relaxed-read-only setup with ro mounts (/sys)
	mountsUT4 := []specs.Mount{
		{
			Destination: "/sys",
			Source:      "sysfs",
			Options:     []string{"ro", "whatever"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Source:      "cgroup",
			Options:     []string{"ro", "whatever"},
		},
	}
	expectedMountsUT4 := []specs.Mount{
		{
			Destination: "/sys",
			Source:      "sysfs",
			Options:     []string{"ro", "whatever"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Source:      "cgroup",
			Options:     []string{"ro", "whatever"},
		},
		{
			Destination: "/run",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "mode=755", "size=64m"},
		},
		{
			Destination: "/tmp",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "mode=755", "size=64m"},
		},
	}

	tests := []struct {
		name string
		args args
	}{
		// Test-cases definition
		{
			name: "basic setup with no overlapping mounts",
			args: args{sysMgrDefault, &specs.Spec{Root: &specs.Root{Readonly: true}, Mounts: mountsUT1}, expectedMountsUT1},
		},
		{
			name: "basic setup with overlapping mount (ro)",
			args: args{sysMgrDefault, &specs.Spec{Root: &specs.Root{Readonly: true}, Mounts: mountsUT2}, expectedMountsUT2},
		},
		{
			name: "basic setup with overlapping mount (rw)",
			args: args{sysMgrDefault, &specs.Spec{Root: &specs.Root{Readonly: true}, Mounts: mountsUT3}, expectedMountsUT3},
		},
		{
			name: "relaxed-read-only setup with /sys mounts (ro)",
			args: args{sysMgrRelaxedRO, &specs.Spec{Root: &specs.Root{Readonly: true}, Mounts: mountsUT4}, expectedMountsUT4},
		},
	}

	// Test-cases execution
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgSyscontMountsReadOnly(tt.args.sysMgr, tt.args.spec)
		})

		if !reflect.DeepEqual(tt.args.spec.Mounts, tt.args.expectedMounts) {
			t.Errorf("cfgSyscontMountsReadOnly failed: unexpected mounts; got %v, want %v", tt.args.spec.Mounts, tt.args.expectedMounts)
		}
	}
}
