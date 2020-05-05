//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package syscont

import (
	"testing"

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

func TestCfgMaskedPaths(t *testing.T) {
	spec := new(specs.Spec)
	spec.Linux = new(specs.Linux)
	spec.Linux.MaskedPaths = []string{"/proc", "/some/path", "/proc/sys", "/other/path"}
	spec.Process = new(specs.Process)
	spec.Process.Args = []string{"/bin/bash"}

	cfgMaskedPaths(spec)

	for _, mp := range spec.Linux.MaskedPaths {
		for _, ep := range sysboxExposedPaths {
			if mp == ep {
				t.Errorf("cfgMaskedPaths: failed to unmask path %s", ep)
			}
		}
	}

	want := []string{"/some/path", "/other/path"}
	if !stringSliceEqual(spec.Linux.MaskedPaths, want) {
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
		for _, rwp := range sysboxRwPaths {
			if rop == rwp {
				t.Errorf("cfgReadonlyPaths: failed to remove read-only on path %s", rwp)
			}
		}
	}

	want := []string{"/some/path", "/other/path"}
	if !stringSliceEqual(spec.Linux.ReadonlyPaths, want) {
		t.Errorf("cfgReadonlyPaths: removed unexpected path; got %v, want %v", spec.Linux.ReadonlyPaths, want)
	}
}

func TestSortMounts(t *testing.T) {

	spec := new(specs.Spec)

	orig := []string{"/dev", "/proc/swaps", "/proc", "/var/lib", "/tmp/run", "/sys/fs/cgroup", "/sys", "/tmp/run2"}
	want := []string{"/sys", "/sys/fs/cgroup", "/proc", "/proc/swaps", "/dev", "/var/lib", "/tmp/run", "/tmp/run2"}

	spec.Mounts = []specs.Mount{}
	for _, s := range orig {
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: s})
	}

	wantMounts := []specs.Mount{}
	for _, s := range want {
		wantMounts = append(wantMounts, specs.Mount{Destination: s})
	}

	sortMounts(spec)

	if !mountSliceEqual(spec.Mounts, wantMounts) {
		t.Errorf("sortMounts() failed: got %v, want %v", spec.Mounts, wantMounts)
	}
}

func TestGetEnvVarInfo(t *testing.T) {

	test := []string{"a=b", "var=1", "other-var=hello", "var2="}
	name := []string{"a", "var", "other-var", "var2"}
	val := []string{"b", "1", "hello", ""}

	for i, _ := range test {
		n, v, err := getEnvVarInfo(test[i])
		if err != nil {
			t.Errorf("getEnvVarInfo(%s) failed: returned unexpected error %v", test[i], err)
		}
		if n != name[i] || v != val[i] {
			t.Errorf("getEnvVarInfo(%s) failed: want %s, %s; got %s, %s", test[i], name[i], val[i], n, v)
		}
	}

	if _, _, err := getEnvVarInfo("a=b=c"); err == nil {
		t.Errorf("getEnvVarInfo(%s) failed: expected error, got no error.", "a=b=c")
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
		specs.Mount{
			Source:      "/another/path",
			Destination: "/tmp",
			Type:        "bind",
			Options:     []string{"rw", "rprivate", "noexec"},
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
		specs.Mount{
			Source:      "tmpfs",
			Destination: "/tmp",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "size=64m"},
		},
	}

	if !mountSliceEqual(spec.Mounts, wantMounts) {
		t.Errorf("cfgSystemd() failed: spec.Mounts: want %v, got %v", wantMounts, spec.Mounts)
	}

}
