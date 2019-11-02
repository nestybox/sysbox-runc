//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

package syscont

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/runc/libsysbox/sysbox"
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

func TestGetEnvVar(t *testing.T) {

	spec := new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Process.Env = []string{"A=1", "B=2", "C=hi", "SYSBOX_USERNS_REMAP=identity"}

	type testData struct {
		key   string
		val   string
		found bool
	}

	data := []testData{
		{"A", "1", true},
		{"B", "2", true},
		{"C", "hi", true},
		{"D", "", false},
		{"SYSBOX_USERNS_REMAP", "identity", true},
	}

	for _, d := range data {
		val, found := getEnvVar(spec, d.key)
		if found != d.found || val != d.val {
			t.Errorf("getEnvVar(%s) failed: want %s, %v; got %s, %v", d.key, d.val, d.found, val, found)
		}
	}
}

func TestRemoveSysboxCfgEnvVars(t *testing.T) {
	spec := new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Process.Env = []string{"A=1", "B=2", "C=hi", "SYSBOX_USERNS_REMAP=identity", "D=3"}

	removeSysboxCfgEnvVars(spec.Process)

	want := []string{"A=1", "B=2", "C=hi", "D=3"}

	if !stringSliceEqual(spec.Process.Env, want) {
		t.Errorf("removeSysboxCfgEnvVars() failed: got %v; want %v", spec.Process.Env, want)
	}
}

func TestAllocIDMappings(t *testing.T) {

	sysMgr := sysbox.NewMgr("container", false)

	spec := new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Linux = new(specs.Linux)

	// verify default allocation

	if err := allocIDMappings(sysMgr, spec); err != nil {
		t.Errorf("allocIDMappings() returned error")
	}

	wantIDMap := specs.LinuxIDMapping{
		ContainerID: 0,
		HostID:      defaultUid,
		Size:        IdRangeMin,
	}

	if spec.Linux.UIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.UIDMappings[0])
	}
	if spec.Linux.GIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.GIDMappings[0])
	}

	// verify allocation when a mount over the sys container's /var/lib/docker is detected

	spec = new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Linux = new(specs.Linux)
	spec.Mounts = []specs.Mount{
		{
			Destination: "/var/lib/docker",
			Source:      "/some/dir",
			Type:        "bind",
		},
	}

	if err := allocIDMappings(sysMgr, spec); err != nil {
		t.Errorf("allocIDMappings() returned error")
	}

	wantIDMap = specs.LinuxIDMapping{
		ContainerID: 0,
		HostID:      0,
		Size:        IdRangeMin,
	}

	if spec.Linux.UIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.UIDMappings[0])
	}
	if spec.Linux.GIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.GIDMappings[0])
	}

	// verify allocation when env var SYSBOX_USERNS_REMAP is set to "identity"

	spec = new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Process.Env = []string{"SYSBOX_USERNS_REMAP=identity"}
	spec.Linux = new(specs.Linux)

	if err := allocIDMappings(sysMgr, spec); err != nil {
		t.Errorf("allocIDMappings() returned error")
	}

	wantIDMap = specs.LinuxIDMapping{
		ContainerID: 0,
		HostID:      0,
		Size:        IdRangeMin,
	}

	if spec.Linux.UIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.UIDMappings[0])
	}
	if spec.Linux.GIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.GIDMappings[0])
	}

	// verify allocation when env var SYSBOX_USERNS_REMAP is set to "exclusive"

	spec = new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Process.Env = []string{"SYSBOX_USERNS_REMAP=exclusive"}
	spec.Linux = new(specs.Linux)

	if err := allocIDMappings(sysMgr, spec); err != nil {
		t.Errorf("allocIDMappings() returned error")
	}

	wantIDMap = specs.LinuxIDMapping{
		ContainerID: 0,
		HostID:      defaultUid,
		Size:        IdRangeMin,
	}

	if spec.Linux.UIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.UIDMappings[0])
	}
	if spec.Linux.GIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.GIDMappings[0])
	}

	// verify allocation when env var SYSBOX_USERNS_REMAP is set to "unknown"

	spec = new(specs.Spec)
	spec.Process = new(specs.Process)
	spec.Process.Env = []string{"SYSBOX_USERNS_REMAP=unknown"}
	spec.Linux = new(specs.Linux)

	if err := allocIDMappings(sysMgr, spec); err != nil {
		t.Errorf("allocIDMappings() returned error")
	}

	wantIDMap = specs.LinuxIDMapping{
		ContainerID: 0,
		HostID:      defaultUid,
		Size:        IdRangeMin,
	}

	if spec.Linux.UIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.UIDMappings[0])
	}
	if spec.Linux.GIDMappings[0] != wantIDMap {
		t.Errorf("allocIDMappings(): want %v; got %v", wantIDMap, spec.Linux.GIDMappings[0])
	}
}
