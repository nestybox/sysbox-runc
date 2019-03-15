// +build linux

package syscont

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	mapset "github.com/deckarep/golang-set"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"

	"golang.org/x/sys/unix"
)

// sysboxfsMounts is a list of system container mounts backed by sysbox-fs
// (please keep in alphabetical order)
var sysboxfsMounts = []specs.Mount{
	specs.Mount{
		Destination: "/proc/cpuinfo",
		Source:      "/var/lib/sysboxfs/proc/cpuinfo",
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},

	// specs.Mount{
	// 	Destination: "/proc/cgroups",
	// 	Source:      "/var/lib/sysboxfs/proc/cgroups",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/devices",
	// 	Source:      "/var/lib/sysboxfs/proc/devices",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/diskstats",
	// 	Source:      "/var/lib/sysboxfs/proc/diskstats",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/loadavg",
	// 	Source:      "/var/lib/sysboxfs/proc/loadavg",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/meminfo",
	// 	Source:      "/var/lib/sysboxfs/proc/meminfo",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/pagetypeinfo",
	// 	Source:      "/var/lib/sysboxfs/proc/pagetypeinfo",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/partitions",
	// 	Source:      "/var/lib/sysboxfs/proc/partitions",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/stat",
	// 	Source:      "/var/lib/sysboxfs/proc/stat",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/swaps",
	// 	Source:      "/var/lib/sysboxfs/proc/swaps",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },

	specs.Mount{
		Destination: "/proc/sys",
		Source:      "/var/lib/sysboxfs/proc/sys",
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
	specs.Mount{
		Destination: "/proc/uptime",
		Source:      "/var/lib/sysboxfs/proc/uptime",
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
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

// IdRangeMin represents the minimum uid/gid range required by a sys container instance
var IdRangeMin uint32 = 65536

// SupportedRootFs is the list of supported filesystems for backing the system container's
// root path
var SupportedRootFs = map[string]int64{
	"btrfs": unix.BTRFS_SUPER_MAGIC,
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

// allocateIdMappings performs uid and gid allocation for the system container
func allocateIdMappings(spec *specs.Spec) error {

	// TODO: for now we fake a uid/gid mapping; in the future we need to perform actual allocation
	// of uids/gids such that it's exclusive for each system container
	idMap := specs.LinuxIDMapping{
		ContainerID: 0,
		HostID:      231072,
		Size:        65536,
	}

	spec.Linux.UIDMappings = append(spec.Linux.UIDMappings, idMap)
	spec.Linux.GIDMappings = append(spec.Linux.GIDMappings, idMap)

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
	gidMap := spec.Linux.UIDMappings[0]
	if uidMap != gidMap {
		return fmt.Errorf("sysbox-runc requires user namespace uid and gid mappings be identical; found %v and %v", uidMap, gidMap)
	}

	if uidMap.ContainerID != 0 || uidMap.Size < IdRangeMin {
		return fmt.Errorf("sysbox-runc requires uid mapping specify a container with at least %d uids starting at uid 0; found %v", IdRangeMin, uidMap)
	}

	return nil
}

// cfgIDMappings checks if the uid/gid mappings are present and valid; if they
// are not present, it allocates them. Note that we don't disallow mappings
// that map to the host root UID (i.e., we honor the ID config). Some runc tests use
// such mappings.
func cfgIDMappings(spec *specs.Spec) error {
	if len(spec.Linux.UIDMappings) == 0 && len(spec.Linux.GIDMappings) == 0 {
		return allocateIdMappings(spec)
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
	specPaths := spec.Linux.MaskedPaths
	for i := 0; i < len(specPaths); i++ {
		for _, path := range sysboxExposedPaths {
			if specPaths[i] == path {
				specPaths = append(specPaths[:i], specPaths[i+1:]...)
				i--
				logrus.Debugf("removed masked path %s from spec", path)
				break
			}
		}
	}
	spec.Linux.MaskedPaths = specPaths
}

// cfgReadonlyPaths removes from the container's config any read-only paths
// that must be read-write in the system container
func cfgReadonlyPaths(spec *specs.Spec) {
	specPaths := spec.Linux.ReadonlyPaths
	for i := 0; i < len(specPaths); i++ {
		for _, path := range sysboxRwPaths {
			if specPaths[i] == path {
				specPaths = append(specPaths[:i], specPaths[i+1:]...)
				i--
				logrus.Debugf("removed read-only path %s from spec", path)
				break
			}
		}
	}
	spec.Linux.ReadonlyPaths = specPaths
}

// cfgSysboxfsMounts adds the sysbox-fs mounts to the containers config.
func cfgSysboxfsMounts(spec *specs.Spec) {

	// disallow all mounts over /proc/* or /sys/* (except for /sys/fs/cgroup);
	// only sysbox-fs mounts are allowed there.
	for i := 0; i < len(spec.Mounts); i++ {
		m := spec.Mounts[i]
		if strings.HasPrefix(m.Destination, "/proc/") ||
			(strings.HasPrefix(m.Destination, "/sys/") && (m.Destination != "/sys/fs/cgroup")) {
			spec.Mounts = append(spec.Mounts[:i], spec.Mounts[i+1:]...)
			i--
			logrus.Debugf("removed mount %s from spec (not compatible with sysbox-runc)", m.Destination)
		}
	}

	// add sysboxfs mounts to the config
	for _, mount := range sysboxfsMounts {
		spec.Mounts = append(spec.Mounts, mount)
		logrus.Debugf("added sysbox-fs mount %s to spec", mount.Destination)
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
			for j := 0; j < len(mount.Options); j++ {
				if mount.Options[j] == "ro" {
					mount.Options = append(mount.Options[:j], mount.Options[j+1:]...)
					j--
					logrus.Debugf("removed read-only attr for cgroup mount %s", mount.Destination)
				}
			}
			spec.Mounts[i].Options = mount.Options
		}
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

	// seccomp syscall lsit may be a whitelist or blacklist
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

	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return err
	}

	n := bytes.IndexByte(utsname.Release[:], 0)
	path := filepath.Join("/lib/modules/", string(utsname.Release[:n]))
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

// checkRootFilesys checks if the system container's rootfs is on a
// filesystem supported by sysbox
func checkRootFilesys(rootPath string) error {

	var stat syscall.Statfs_t
	if err := syscall.Statfs(rootPath, &stat); err != nil {
		fmt.Errorf("failed to find filesystem info for container root path at %s", rootPath)
	}

	for _, magic := range SupportedRootFs {
		if stat.Type == magic {
			return nil
		}
	}

	logrus.Debugf("system container root path is not on one of these filesystems: "+
		"%v; running an inner docker container won't work "+
		"unless a host volume is mounted on the system "+
		"container's /var/lib/docker",
		reflect.ValueOf(SupportedRootFs).MapKeys())

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

	if err := checkRootFilesys(spec.Root.Path); err != nil {
		return err
	}

	return nil
}

// Configure the container's process spec for system containers
func ConvertProcessSpec(p *specs.Process) error {
	cfgCapabilities(p)
	return nil
}

// ConvertSpec converts the given container spec to a system container spec.
func ConvertSpec(spec *specs.Spec, noSysboxfs bool) error {

	if err := checkSpec(spec); err != nil {
		return fmt.Errorf("invalid or unsupported system container spec: %v", err)
	}

	if err := ConvertProcessSpec(spec.Process); err != nil {
		return fmt.Errorf("failed to configure process spec: %v", err)
	}

	if err := cfgNamespaces(spec); err != nil {
		return fmt.Errorf("invalid namespace config: %v", err)
	}

	if err := cfgIDMappings(spec); err != nil {
		return fmt.Errorf("invalid user/group ID config: %v", err)
	}

	if err := cfgCgroups(spec); err != nil {
		return fmt.Errorf("failed to configure cgroup mounts: %v", err)
	}

	if err := cfgLibModMount(spec, true); err != nil {
		return fmt.Errorf("failed to setup /lib/module/<kernel-version> mount: %v", err)
	}

	if !noSysboxfs {
		cfgMaskedPaths(spec)
		cfgReadonlyPaths(spec)
		cfgSysboxfsMounts(spec)
	}

	if err := cfgSeccomp(spec.Linux.Seccomp); err != nil {
		return fmt.Errorf("failed to configure seccomp: %v", err)
	}

	// TODO: ensure /proc and /sys are mounted (if not present in the container spec)

	// TODO: ensure /dev is mounted

	return nil
}
