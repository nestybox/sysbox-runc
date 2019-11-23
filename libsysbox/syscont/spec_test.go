//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package syscont

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"

	"golang.org/x/sys/unix"
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

func TestCfgLibModMount(t *testing.T) {

	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		t.Errorf("cfgLibModMount: uname failed: %v", err)
	}

	n := bytes.IndexByte(utsname.Release[:], 0)
	path := filepath.Join("/lib/modules/", string(utsname.Release[:n]))
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return // skip test
	}

	spec := new(specs.Spec)

	// Test handling of spec without "/lib/modules/<kernel-release>" mount
	if err := cfgLibModMount(spec, false); err != nil {
		t.Errorf("cfgLibModMount: returned error: %v", err)
	}
	m := spec.Mounts[0]
	if (m.Destination != path) || (m.Source != path) || (m.Type != "bind") {
		t.Errorf("cfgLibModMount: failed basic mount test")
	}

	// Test handling of spec with matching "/lib/modules/<kernel-release>" mount
	if err := cfgLibModMount(spec, false); err != nil {
		t.Errorf("cfgLibModMount: failed matching mount test: %v", err)
	}

	// test config with conflicting /lib/modules mount
	spec.Mounts[0].Options = []string{}
	if err := cfgLibModMount(spec, false); err != nil {
		t.Errorf("cfgLibModMount: failed conflicting mount test: %v", err)
	}
}

func TestCfgMaskedPaths(t *testing.T) {
	spec := new(specs.Spec)
	spec.Linux = new(specs.Linux)
	spec.Linux.MaskedPaths = []string{"/proc", "/some/path", "/proc/sys", "/other/path"}

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

func TestCfgSysboxFsMounts(t *testing.T) {

	spec := new(specs.Spec)
	spec.Mounts = []specs.Mount{
		{
			Destination: "/proc",
			Type:        "bind",
			Source:      "/some/source",
			Options:     []string{"ro"},
		},
		{
			Destination: "/proc/cpuinfo",
			Type:        "bind",
			Source:      "/some/source",
			Options:     []string{"ro"},
		},
		{
			Destination: "/var/lib",
			Type:        "bind",
			Source:      "/some/source",
			Options:     []string{"rw"},
		},
		{
			Destination: "/sys/bus",
			Type:        "bind",
			Source:      "/some/source",
			Options:     []string{"rw"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Type:        "bind",
			Source:      "/some/source",
			Options:     []string{"ro"},
		},
	}

	want := append(spec.Mounts, sysboxFsMounts...)

	cfgSysboxFsMounts(spec)

	if len(spec.Mounts) != len(want) {
		t.Errorf("cfgSysboxFsMounts: got %v, want %v", spec.Mounts, want)
	}

	for i := 0; i < len(spec.Mounts); i++ {
		if spec.Mounts[i].Destination != want[i].Destination {
			t.Errorf("cfgSysboxFsMounts: got %v, want %v", spec.Mounts, want)
		}
	}
}

func testCfgCgroups(t *testing.T) {
	spec := new(specs.Spec)
	spec.Mounts = []specs.Mount{
		{
			Destination: "/proc",
			Type:        "bind",
			Source:      "/some/source",
			Options:     []string{"ro"},
		},
		{
			Destination: "/sys/bus",
			Type:        "bind",
			Source:      "/some/source",
			Options:     []string{"rw"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Type:        "cgroup",
			Source:      "/some/source",
			Options:     []string{"ro", "rbind"},
		},
	}

	want := spec.Mounts
	want[2].Options = []string{"rbind"}

	cfgCgroups(spec)

	if len(spec.Mounts) != len(want) {
		t.Errorf("cfgCfgCgroups: got %v, want %v", spec.Mounts, want)
	}

	for i := 0; i < len(spec.Mounts); i++ {
		if !stringSliceEqual(spec.Mounts[i].Options, want[i].Options) {
			t.Errorf("cfgCfgCgroups: got %v, want %v", spec.Mounts[i].Options, want[i].Options)
		}
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
	spec.Process.Env = []string{"container=docker", "a=b"}

	spec.Mounts = []specs.Mount{
		specs.Mount{
			Destination: "/run",
			Source:      "/somepath",
			Type:        "bind",
			Options:     []string{"ro", "rprivate"},
		},
		specs.Mount{
			Destination: "/run/lock",
			Source:      "/otherpath",
			Type:        "bind",
			Options:     []string{"rw"},
		},
		specs.Mount{
			Destination: "/test",
			Source:      "/somepath",
			Type:        "bind",
			Options:     []string{"ro", "rprivate"},
		},
		specs.Mount{
			Destination: "/tmp",
			Source:      "/another/path",
			Type:        "bind",
			Options:     []string{"rw", "rprivate", "noexec"},
		},
	}

	spec.Linux.MaskedPaths = []string{"/sys/kernel/debug", "/some/other/path", "/sys/kernel/config"}
	spec.Linux.ReadonlyPaths = []string{"/tmp", "/run/lock", "/yet/another/path", "/sys/kernel/debug"}

	// This call should remove the conflicting info above
	cfgSystemd(spec)

	wantEnv := []string{"a=b", "container=private-users"}
	if !stringSliceEqual(spec.Process.Env, wantEnv) {
		t.Errorf("cfgSystemd() failed: spec.Process.Env: want %v, got %v", wantEnv, spec.Process.Env)
	}

	wantMounts := []specs.Mount{
		specs.Mount{
			Destination: "/test",
			Source:      "/somepath",
			Type:        "bind",
			Options:     []string{"ro", "rprivate"},
		},
		specs.Mount{
			Destination: "/run",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "tmpcopyup", "size=65536k"},
		},
		specs.Mount{
			Destination: "/run/lock",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "tmpcopyup", "size=65536k"},
		},
		specs.Mount{
			Destination: "/tmp",
			Source:      "tmpfs",
			Type:        "tmpfs",
			Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "tmpcopyup", "size=65536k"},
		},
	}

	if !mountSliceEqual(spec.Mounts, wantMounts) {
		t.Errorf("cfgSystemd() failed: spec.Mounts: want %v, got %v", wantMounts, spec.Mounts)
	}

	wantMasked := []string{"/some/other/path"}
	if !stringSliceEqual(spec.Linux.MaskedPaths, wantMasked) {
		t.Errorf("cfgSystemd() failed: spec.Linux.MaskedPaths: want %v, got %v", wantMasked, spec.Linux.MaskedPaths)
	}

	wantRo := []string{"/yet/another/path"}
	if !stringSliceEqual(spec.Linux.ReadonlyPaths, wantRo) {
		t.Errorf("cfgSystemd() failed: spec.Linux.MaskedPaths: want %v, got %v", wantRo, spec.Linux.ReadonlyPaths)
	}

}
