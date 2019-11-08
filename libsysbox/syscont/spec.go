//
// Copyright: (C) 2019 Nestybox Inc.  All rights reserved.
//

// +build linux

package syscont

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	mapset "github.com/deckarep/golang-set"
	"github.com/opencontainers/runc/libsysbox/sysbox"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// UID & GID Mapping Constants
const (
	IdRangeMin uint32 = 65536
	defaultUid uint32 = 231072
	defaultGid uint32 = 231072
)

// sysboxFsMounts is a list of system container mounts backed by sysbox-fs
// (please keep in alphabetical order)

var SysboxFsDir = "/var/lib/sysboxfs"

var sysboxFsMounts = []specs.Mount{

	specs.Mount{
		Destination: "/proc/sys",
		Source:      filepath.Join(SysboxFsDir, "proc/sys"),
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
	specs.Mount{
		Destination: "/proc/uptime",
		Source:      filepath.Join(SysboxFsDir, "proc/uptime"),
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},

	// XXX: In the future sysbox-fs will also handle the following

	// specs.Mount{
	// 	Destination: "/proc/cpuinfo",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/cpuinfo"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },

	// specs.Mount{
	// 	Destination: "/proc/cgroups",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/cgroups"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/devices",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/devices"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/diskstats",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/diskstats"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/loadavg",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/loadavg"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/meminfo",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/meminfo"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/pagetypeinfo",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/pagetypeinfo"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/partitions",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/partitions"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/stat",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/stat"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/swaps",
	// 	Source:      filepath.Join(SysboxFsDir, "proc/swaps"),
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
}

// sysbox's systemd mount requirements
var sysboxSystemdMounts = []specs.Mount{

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

// sysbox's systemd env-vars requirements
var sysboxSystemdEnvVars = []string{

	// Allow systemd to identify the virtualization mode to operate on (container
	// with user-namespace). See 'ConditionVirtualization' attribute here:
	// https://www.freedesktop.org/software/systemd/man/systemd.unit.html
	"container=private-users",
}

// sysbox's generic mount requirements
var sysboxMounts = []specs.Mount{
	// we don't yet support /dev/kmsg; create a dummy one.
	specs.Mount{
		Destination: "/dev/kmsg",
		Source:      "tmpfs",
		Type:        "tmpfs",
		Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "size=65536k", "mode=644"},
	},
	// we don't yet support configfs; create a dummy one.
	specs.Mount{
		Destination: "/sys/kernel/config",
		Source:      "tmpfs",
		Type:        "tmpfs",
		Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "size=65536k"},
	},
	// we don't support debugfs; create a dummy one.
	specs.Mount{
		Destination: "/sys/kernel/debug",
		Source:      "tmpfs",
		Type:        "tmpfs",
		Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "size=65536k"},
	},
}

// sysboxRwPaths list the paths within the sys container's rootfs
// that must have read-write permission
var sysboxRwPaths = []string{
	"/proc",
	"/proc/sys",
}

// sysboxExposedPaths list the paths within the sys container's rootfs
// that must not be masked
var sysboxExposedPaths = []string{
	"/proc",
	"/proc/sys",
}

// sysboxSystemdExposedPaths list the paths within the sys container's rootfs
// that must not be masked when the sys container runs systemd
var sysboxSystemdExposedPaths = []string{
	"/run",
	"/run/lock",
	"/tmp",
	"/sys/kernel/config",
	"/sys/kernel/debug",
}

// sysboxRwPaths list the paths within the sys container's rootfs
// that must have read-write permission
var sysboxSystemdRwPaths = []string{
	"/run",
	"/run/lock",
	"/tmp",
	"/sys/kernel/config",
	"/sys/kernel/debug",
}

// linuxCaps is the full list of Linux capabilities
var linuxCaps = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FSETID",
	"CAP_FOWNER",
	"CAP_MKNOD",
	"CAP_NET_RAW",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETFCAP",
	"CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE",
	"CAP_SYS_CHROOT",
	"CAP_KILL",
	"CAP_AUDIT_WRITE",
	"CAP_DAC_READ_SEARCH",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_LEASE",
	"CAP_AUDIT_CONTROL",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ",
}

// cfgNamespaces checks that the namespace config has the minimum set
// of namespaces required and adds any missing namespaces to it
func cfgNamespaces(spec *specs.Spec) error {

	// user-ns and cgroup-ns are not required; but we will add them to the spec.
	var allNs = []string{"pid", "ipc", "uts", "mount", "network", "user", "cgroup"}
	var reqNs = []string{"pid", "ipc", "uts", "mount", "network"}

	allNsSet := mapset.NewSet()
	for _, ns := range allNs {
		allNsSet.Add(ns)
	}

	reqNsSet := mapset.NewSet()
	for _, ns := range reqNs {
		reqNsSet.Add(ns)
	}

	specNsSet := mapset.NewSet()
	for _, ns := range spec.Linux.Namespaces {
		specNsSet.Add(string(ns.Type))
	}

	if !reqNsSet.IsSubset(specNsSet) {
		return fmt.Errorf("container spec missing namespaces %v", reqNsSet.Difference(specNsSet))
	}

	addNsSet := allNsSet.Difference(specNsSet)
	for ns := range addNsSet.Iter() {
		str := fmt.Sprintf("%v", ns)
		newns := specs.LinuxNamespace{
			Type: specs.LinuxNamespaceType(str),
			Path: "",
		}
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, newns)
		logrus.Debugf("added namespace %s to spec", ns)
	}

	return nil
}

// allocIDMappings performs uid and gid allocation for the system container
func allocIDMappings(sysMgr *sysbox.Mgr, spec *specs.Spec) error {
	var uid, gid uint32
	var err error

	if sysMgr.Enabled() {
		uid, gid, err = sysMgr.ReqSubid(IdRangeMin)
		if err != nil {
			return fmt.Errorf("subid allocation failed: %v", err)
		}
	} else {
		uid = defaultUid
		gid = defaultGid
	}

	uidMap := specs.LinuxIDMapping{
		ContainerID: 0,
		HostID:      uid,
		Size:        IdRangeMin,
	}

	gidMap := specs.LinuxIDMapping{
		ContainerID: 0,
		HostID:      gid,
		Size:        IdRangeMin,
	}

	spec.Linux.UIDMappings = append(spec.Linux.UIDMappings, uidMap)
	spec.Linux.GIDMappings = append(spec.Linux.GIDMappings, gidMap)

	return nil
}

// validateIDMappings checks if the spec's user namespace uid and gid mappings meet sysbox-runc requirements
func validateIDMappings(spec *specs.Spec) error {

	if len(spec.Linux.UIDMappings) != 1 {
		return fmt.Errorf("sysbox-runc requires user namespace uid mapping array have one element; found %v", spec.Linux.UIDMappings)
	}

	if len(spec.Linux.GIDMappings) != 1 {
		return fmt.Errorf("sysbox-runc requires user namespace gid mapping array have one element; found %v", spec.Linux.GIDMappings)
	}

	uidMap := spec.Linux.UIDMappings[0]
	if uidMap.ContainerID != 0 || uidMap.Size < IdRangeMin {
		return fmt.Errorf("sysbox-runc requires uid mapping specify a container with at least %d uids starting at uid 0; found %v", IdRangeMin, uidMap)
	}

	gidMap := spec.Linux.GIDMappings[0]
	if gidMap.ContainerID != 0 || gidMap.Size < IdRangeMin {
		return fmt.Errorf("sysbox-runc requires gid mapping specify a container with at least %d gids starting at gid 0; found %v", IdRangeMin, gidMap)
	}

	if uidMap.HostID != gidMap.HostID {
		return fmt.Errorf("sysbox-runc requires matching uid & gid mappings; found uid = %v, gid = %d", uidMap, gidMap)
	}

	return nil
}

// cfgIDMappings checks if the uid/gid mappings are present and valid; if they are not
// present, it allocates them. Note that we don't disallow mappings that map to the host
// root UID (i.e., identity-mappings); some runc tests use such mappings.
func cfgIDMappings(sysMgr *sysbox.Mgr, spec *specs.Spec) error {
	if len(spec.Linux.UIDMappings) == 0 && len(spec.Linux.GIDMappings) == 0 {
		return allocIDMappings(sysMgr, spec)
	}
	return validateIDMappings(spec)
}

// cfgCapabilities sets the capabilities for the process in the system container
func cfgCapabilities(p *specs.Process) {
	caps := p.Capabilities
	uid := p.User.UID

	// In a sys container, the root process has all capabilities
	if uid == 0 {
		caps.Bounding = linuxCaps
		caps.Effective = linuxCaps
		caps.Inheritable = linuxCaps
		caps.Permitted = linuxCaps
		caps.Ambient = linuxCaps
		logrus.Debugf("enabled all capabilities in the process spec")
	}
}

// cfgMaskedPaths removes from the container's config any masked paths for which
// sysbox-fs will handle accesses.
func cfgMaskedPaths(spec *specs.Spec) {
	maskedPaths := stringSliceRemove(spec.Linux.MaskedPaths, sysboxExposedPaths)
	spec.Linux.MaskedPaths = maskedPaths
}

// cfgReadonlyPaths removes from the container's config any read-only paths
// that must be read-write in the system container
func cfgReadonlyPaths(spec *specs.Spec) {
	roPaths := stringSliceRemove(spec.Linux.ReadonlyPaths, sysboxRwPaths)
	spec.Linux.ReadonlyPaths = roPaths
}

// cfgSysboxMounts adds sysbox generic mounts to the containers config.
func cfgSysboxMounts(spec *specs.Spec) {

	// Disallow all spec mounts over /proc/* or /sys/* (except for /sys/fs/cgroup); only sysbox mounts are allowed there.
	spec.Mounts = mountSliceRemoveMatch(spec.Mounts, func(m specs.Mount) bool {
		return strings.HasPrefix(m.Destination, "/proc/") ||
			(strings.HasPrefix(m.Destination, "/sys/") && (m.Destination != "/sys/fs/cgroup"))
	})

	// Add sysbox generic mounts to the spec.
	for _, mount := range sysboxMounts {

		// Eliminate any overlapping mount present in original spec.
		spec.Mounts = mountSliceRemoveStrMatch(
			spec.Mounts,
			mount.Destination,
			func(m specs.Mount, str string) bool {
				return m.Source == str || m.Destination == str
			},
		)

		spec.Mounts = append(spec.Mounts, mount)
		logrus.Debugf("added sysbox mount %v to spec", mount.Destination)
	}
}

// cfgSysboxFsMounts adds the sysbox-fs mounts to the containers config.
func cfgSysboxFsMounts(spec *specs.Spec) {

	// add sysbox-fs mounts to the config
	for _, mount := range sysboxFsMounts {
		spec.Mounts = append(spec.Mounts, mount)
		logrus.Debugf("added sysbox-fs mount %s to spec", mount.Destination)
	}
}

// cfgSystemd adds the mounts and env-vars required by systemd.
func cfgSystemd(spec *specs.Spec) {

	// Spec will be only adjusted if systemd is the sys container's init process
	if spec.Process.Args[0] != "/sbin/init" {
		return
	}

	// Add systemd mounts to the spec.
	for _, mount := range sysboxSystemdMounts {

		// Eliminate any overlapping mount present in original spec.
		spec.Mounts = mountSliceRemoveStrMatch(
			spec.Mounts,
			mount.Destination,
			func(m specs.Mount, str string) bool {
				return m.Source == str || m.Destination == str
			},
		)

		spec.Mounts = append(spec.Mounts, mount)
		logrus.Debugf("added sysbox's systemd mount %v to spec", mount.Destination)
	}

	// Remove any conflicting masked paths
	maskedPaths := stringSliceRemove(spec.Linux.MaskedPaths, sysboxSystemdExposedPaths)
	spec.Linux.MaskedPaths = maskedPaths

	// Remove any conflicting read-only paths
	roPaths := stringSliceRemove(spec.Linux.ReadonlyPaths, sysboxSystemdRwPaths)
	spec.Linux.ReadonlyPaths = roPaths

	// Add env-vars required for proper operation.
	for _, env := range sysboxSystemdEnvVars {
		spec.Process.Env = stringSliceRemove(spec.Process.Env, []string{env})
		spec.Process.Env = append(spec.Process.Env, env)
		logrus.Debugf("added sysbox's systemd env-var %v to spec", env)
	}
}

// cfgCgroups configures the system container's cgroup settings.
func cfgCgroups(spec *specs.Spec) error {

	// remove the read-only attribute from the cgroup mount; this is fine because the sys
	// container's cgroup root will be a child of the cgroup that controls the
	// sys container's resources; thus, root processes inside the sys container will be
	// able to allocate cgroup resources yet not modify the resources allocated to the sys
	// container itself.

	for i, mount := range spec.Mounts {
		if mount.Type == "cgroup" {
			mount.Options = stringSliceRemoveMatch(mount.Options, func(opt string) bool {
				return opt == "ro"
			})
		}
		spec.Mounts[i].Options = mount.Options
	}

	return nil
}

// cfgSeccomp configures the system container's seccomp settings.
func cfgSeccomp(seccomp *specs.LinuxSeccomp) error {
	if seccomp == nil {
		return nil
	}

	supportedArch := false
	for _, arch := range seccomp.Architectures {
		if arch == specs.ArchX86_64 {
			supportedArch = true
		}
	}
	if !supportedArch {
		return nil
	}

	// we don't yet support specs with default trap & trace actions
	if seccomp.DefaultAction != specs.ActAllow &&
		seccomp.DefaultAction != specs.ActErrno &&
		seccomp.DefaultAction != specs.ActKill {
		return fmt.Errorf("spec seccomp default actions other than allow, errno, and kill are not supported")
	}

	// categorize syscalls per seccomp actions
	allowSet := mapset.NewSet()
	errnoSet := mapset.NewSet()
	killSet := mapset.NewSet()

	for _, syscall := range seccomp.Syscalls {
		for _, name := range syscall.Names {
			switch syscall.Action {
			case specs.ActAllow:
				allowSet.Add(name)
			case specs.ActErrno:
				errnoSet.Add(name)
			case specs.ActKill:
				killSet.Add(name)
			}
		}
	}

	// convert sys container syscall whitelist to a set
	syscontAllowSet := mapset.NewSet()
	for _, sc := range syscontSyscallWhitelist {
		syscontAllowSet.Add(sc)
	}

	// seccomp syscall list may be a whitelist or blacklist
	whitelist := (seccomp.DefaultAction == specs.ActErrno ||
		seccomp.DefaultAction == specs.ActKill)

	// diffset is the set of syscalls that needs adding (for whitelist) or removing (for blacklist)
	diffSet := mapset.NewSet()
	if whitelist {
		diffSet = syscontAllowSet.Difference(allowSet)
	} else {
		disallowSet := errnoSet.Union(killSet)
		diffSet = disallowSet.Difference(syscontAllowSet)
	}

	if whitelist {
		// add the diffset to the whitelist
		for syscallName := range diffSet.Iter() {
			str := fmt.Sprintf("%v", syscallName)
			sc := specs.LinuxSyscall{
				Names:  []string{str},
				Action: specs.ActAllow,
			}
			seccomp.Syscalls = append(seccomp.Syscalls, sc)
		}

		logrus.Debugf("added syscalls to seccomp profile: %v", diffSet)

	} else {
		// remove the diffset from the blacklist
		var newSyscalls []specs.LinuxSyscall
		for _, sc := range seccomp.Syscalls {
			for i, scName := range sc.Names {
				if diffSet.Contains(scName) {
					// Remove this syscall
					sc.Names = append(sc.Names[:i], sc.Names[i+1:]...)
				}
			}
			if sc.Names != nil {
				newSyscalls = append(newSyscalls, sc)
			}
		}
		seccomp.Syscalls = newSyscalls

		logrus.Debugf("removed syscalls from seccomp profile: %v", diffSet)
	}

	return nil
}

// cfgAppArmor sets up the apparmor config for sys containers
func cfgAppArmor(p *specs.Process) error {

	// The default docker profile is too restrictive for sys containers (e.g., preveting
	// mounts, write access to /proc/sys/*, etc). For now, we simply ignore any apparmor
	// profile in the container's config.
	//
	// TODO: In the near future, we should develop an apparmor profile for sys-containers,
	// and have sysbox-mgr load it to the kernel (if apparmor is enabled on the system)
	// and then configure the container to use that profile here.

	p.ApparmorProfile = ""
	return nil
}

// cfgLibModMount sets up a read-only bind mount of the host's "/lib/modules/<kernel-release>"
// directory in the same path inside the system container; this allows system container
// processes to verify the presence of modules via modprobe. System apps such as Docker and
// K8s do this. Note that this does not imply module loading/unloading is supported in a
// system container (it's not). It merely lets processes check if a module is loaded.
func cfgLibModMount(spec *specs.Spec, doFhsCheck bool) error {

	if doFhsCheck {
		// only do the mount if the container's rootfs has a "/lib" dir
		rootfsLibPath := filepath.Join(spec.Root.Path, "lib")
		if _, err := os.Stat(rootfsLibPath); os.IsNotExist(err) {
			return nil
		}
	}

	kernelRel, err := sysbox.GetKernelRelease()
	if err != nil {
		return err
	}

	path := filepath.Join("/lib/modules/", kernelRel)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logrus.Warnf("could not setup bind mount for %s: %v", path, err)
		return nil
	}

	mount := specs.Mount{
		Destination: path,
		Source:      path,
		Type:        "bind",
		Options:     []string{"ro", "rbind", "rprivate"}, // must be read-only
	}

	// check if the container spec has a match or a conflict for the mount
	for _, m := range spec.Mounts {
		if (m.Source == mount.Source) &&
			(m.Destination == mount.Destination) &&
			(m.Type == mount.Type) &&
			stringSliceEqual(m.Options, mount.Options) {
			return nil
		}

		if m.Destination == mount.Destination {
			logrus.Debugf("honoring container spec override for mount of %s", m.Destination)
			return nil
		}
	}

	// perform the mount; note that the mount will appear inside the system
	// container as owned by nobody:nogroup; this is fine since the files
	// are not meant to be modified from within the system container.
	spec.Mounts = append(spec.Mounts, mount)
	logrus.Debugf("added bind mount for %s to container's spec", path)
	return nil
}

// checkSpec performs some basic checks on the system container's spec
func checkSpec(spec *specs.Spec) error {

	if spec.Root == nil || spec.Linux == nil {
		return fmt.Errorf("not a linux container spec")
	}

	if spec.Root.Readonly {
		return fmt.Errorf("root path must be read-write but it's set to read-only")
	}

	return nil
}

// needUidShiftOnRootfs checks if uid/gid shifting on the container's rootfs is required to
// run the system container.
func needUidShiftOnRootfs(spec *specs.Spec) (bool, error) {
	var hostUidMap, hostGidMap uint32

	// the uid map is assumed to be present
	for _, mapping := range spec.Linux.UIDMappings {
		if mapping.ContainerID == 0 {
			hostUidMap = mapping.HostID
		}
	}

	// the gid map is assumed to be present
	for _, mapping := range spec.Linux.GIDMappings {
		if mapping.ContainerID == 0 {
			hostGidMap = mapping.HostID
		}
	}

	// find the rootfs owner
	rootfs := spec.Root.Path

	fi, err := os.Stat(rootfs)
	if err != nil {
		return false, err
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("failed to convert to syscall.Stat_t")
	}

	rootfsUid := st.Uid
	rootfsGid := st.Gid

	// Use shifting when the rootfs is owned by true root, the containers uid/gid root
	// mapping don't match the container's rootfs owner, and the host ID for the uid and
	// gid mappings is the same.

	if rootfsUid == 0 && rootfsGid == 0 &&
		hostUidMap != rootfsUid && hostGidMap != rootfsGid &&
		hostUidMap == hostGidMap {
		return true, nil
	}

	return false, nil
}

// getSupConfig obtains supplementary config from the sysbox-mgr for the container with the given id
func getSupConfig(mgr *sysbox.Mgr, spec *specs.Spec, shiftUids bool) error {
	uid := spec.Linux.UIDMappings[0].HostID
	gid := spec.Linux.GIDMappings[0].HostID

	supMounts, err := mgr.ReqSupMounts(spec.Root.Path, uid, gid, shiftUids)
	if err != nil {
		return fmt.Errorf("failed to request supplementary mounts from sysbox-mgr: %v", err)
	}

	// Allow user-defined mounts to override sysbox-mgr mounts
	for _, m := range spec.Mounts {
		supMounts = mountSliceRemove(supMounts, []specs.Mount{m}, func(m1, m2 specs.Mount) bool {
			return m1.Destination == m2.Destination
		})
	}

	spec.Mounts = append(spec.Mounts, supMounts...)
	return nil
}

// Configure the container's process spec for system containers
func ConvertProcessSpec(p *specs.Process) error {
	cfgCapabilities(p)

	if err := cfgAppArmor(p); err != nil {
		return fmt.Errorf("failed to configure AppArmor profile: %v", err)
	}

	return nil
}

// ConvertSpec converts the given container spec to a system container spec.
func ConvertSpec(context *cli.Context, sysMgr *sysbox.Mgr, sysFs *sysbox.Fs, spec *specs.Spec) (bool, error) {

	if err := checkSpec(spec); err != nil {
		return false, fmt.Errorf("invalid or unsupported container spec: %v", err)
	}

	if err := cfgNamespaces(spec); err != nil {
		return false, fmt.Errorf("invalid namespace config: %v", err)
	}

	if err := cfgIDMappings(sysMgr, spec); err != nil {
		return false, fmt.Errorf("invalid user/group ID config: %v", err)
	}

	if err := cfgCgroups(spec); err != nil {
		return false, fmt.Errorf("failed to configure cgroup mounts: %v", err)
	}

	if err := cfgLibModMount(spec, true); err != nil {
		return false, fmt.Errorf("failed to setup /lib/module/<kernel-version> mount: %v", err)
	}

	if sysFs.Enabled() {
		cfgMaskedPaths(spec)
		cfgReadonlyPaths(spec)
		cfgSysboxMounts(spec)
		cfgSysboxFsMounts(spec)
		cfgSystemd(spec)
	}

	if err := cfgSeccomp(spec.Linux.Seccomp); err != nil {
		return false, fmt.Errorf("failed to configure seccomp: %v", err)
	}

	// Must be done after cfgIDMappings()
	shiftUids, err := needUidShiftOnRootfs(spec)
	if err != nil {
		return false, fmt.Errorf("error while checking for uid-shifting need: %v", err)
	}

	// Must be done after needUidShiftOnRootfs()
	if sysMgr.Enabled() {
		if err := getSupConfig(sysMgr, spec, shiftUids); err != nil {
			return false, fmt.Errorf("failed to get supplementary config: %v", err)
		}
	}

	if err := ConvertProcessSpec(spec.Process); err != nil {
		return false, fmt.Errorf("failed to configure process spec: %v", err)
	}

	// TODO: ensure /proc and /sys are mounted (if not present in the container spec)
	// TODO: ensure /dev is mounted

	return shiftUids, nil
}
