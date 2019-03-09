// +build linux

package syscont

import (
	"fmt"
	"os"
	"bytes"
	"path/filepath"
	"syscall"
	"strings"
	"reflect"

	"github.com/sirupsen/logrus"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/deckarep/golang-set"

	"golang.org/x/sys/unix"
)

// sysvisorfsMounts is a list of system container mounts backed by sysvisor-fs
// (please keep in alphabetical order)
var sysvisorfsMounts = []specs.Mount{
	// specs.Mount{
	// 	Destination: "/proc/cpuinfo",
	// 	Source:      "/var/lib/sysvisorfs/proc/cpuinfo",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"}
	// },
	// specs.Mount{
	// 	Destination: "/proc/cgroups",
	// 	Source:      "/var/lib/sysvisorfs/proc/cgroups",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/devices",
	// 	Source:      "/var/lib/sysvisorfs/proc/devices",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/diskstats",
	// 	Source:      "/var/lib/sysvisorfs/proc/diskstats",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/loadavg",
	// 	Source:      "/var/lib/sysvisorfs/proc/loadavg",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/meminfo",
	// 	Source:      "/var/lib/sysvisorfs/proc/meminfo",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/pagetypeinfo",
	// 	Source:      "/var/lib/sysvisorfs/proc/pagetypeinfo",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/partitions",
	// 	Source:      "/var/lib/sysvisorfs/proc/partitions",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/stat",
	// 	Source:      "/var/lib/sysvisorfs/proc/stat",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/swaps",
	// 	Source:      "/var/lib/sysvisorfs/proc/swaps",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/sys",
	// 	Source:      "/var/lib/sysvisorfs/proc/sys",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
	// specs.Mount{
	// 	Destination: "/proc/uptime",
	// 	Source:      "/var/lib/sysvisorfs/proc/uptime",
	// 	Type:        "bind",
	// 	Options:     []string{"rbind", "rprivate"},
	// },
}

// sysvisorRwPaths list the paths within the sys container's rootfs
// that must have read-write permission
var sysvisorRwPaths = []string {
	"/proc",
	"/proc/sys",
}

// sysvisorExposedPaths list the paths within the sys container's rootfs
// that must not be masked
var sysvisorExposedPaths = []string {
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

// cfgNamespaces checks that the namespace config is valid and adds any missing Linux
// namespaces to the system container config
func cfgNamespaces(spec *specs.Spec) error {

	reqNs := []specs.LinuxNamespaceType{"user", "pid", "ipc", "uts", "mount", "network"}

	// Ensure that the config has all the required namespaces
	for _, ns := range reqNs {
		found := false
		for _, cfgNs := range spec.Linux.Namespaces {
			if cfgNs.Type == ns {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("container spec missing the %s namespace", ns)
		}
	}

	// Add remaining namespaces (currently the cgroup namespace only)
	found := false
	for _, cfgNs := range spec.Linux.Namespaces {
		if cfgNs.Type == "cgroup" {
			found = true
		}
	}

	if !found {
		newns := specs.LinuxNamespace{
			Type: "cgroup",
			Path: "",
		}
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, newns)
		logrus.Debugf("added cgroupns to namespace spec")
	}

	return nil
}

// cfgIDMappings checks that the uid and gid configs are valid
func cfgIDMappings(spec *specs.Spec) error {

	if len(spec.Linux.UIDMappings) == 0 {
		return fmt.Errorf("container spec missing uid mappings")
	}

	if len(spec.Linux.GIDMappings) == 0 {
		return fmt.Errorf("container spec missing gid mappings")
	}

	// Verify the mapping is valid. Note that we don't disallow mappings that map to the host
	// root UID (i.e., we honor the ID config). Some runc tests use such mappings.

	validMapFound := false
	for _, mapping := range spec.Linux.UIDMappings {
		if mapping.ContainerID == 0 && mapping.Size >= IdRangeMin {
			validMapFound = true
		}
	}

	if !validMapFound {
		return fmt.Errorf("container spec uid mapping does not map %d uids starting at container uid 0", IdRangeMin)
	}

	validMapFound = false
	for _, mapping := range spec.Linux.GIDMappings {
		if mapping.ContainerID == 0 && mapping.Size >= IdRangeMin {
			validMapFound = true
		}
	}

	if !validMapFound {
		return fmt.Errorf("container spec gid mapping does not map %d gids starting at container gid 0", IdRangeMin)
	}

	return nil
}

// cfgCapabilities sets the capabilities for the process in the system container
func cfgCapabilities(spec *specs.Spec) {
	caps := spec.Process.Capabilities
	uid := spec.Process.User.UID

	// In a sys container, the root process has all capabilities
	if uid == 0 {
		caps.Bounding = linuxCaps;
		caps.Effective = linuxCaps;
		caps.Inheritable = linuxCaps;
		caps.Permitted = linuxCaps;
		caps.Ambient = linuxCaps;
		logrus.Debugf("enabled all capabilities in the process spec")
	}
}

// cfgMaskedPaths removes from the container's config any masked paths for which
// sysvisor-fs will handle accesses.
func cfgMaskedPaths(spec *specs.Spec) {
	specPaths := spec.Linux.MaskedPaths
	for i := 0; i < len(specPaths); i++ {
		for _, path := range sysvisorExposedPaths {
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
		for _, path := range sysvisorRwPaths {
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

// cfgSysvisorfsMounts adds the sysvisor-fs mounts to the containers config.
func cfgSysvisorfsMounts(spec *specs.Spec) {

	// disallow all mounts over /proc/* or /sys/* (except for /sys/fs/cgroup);
	// only sysvisor-fs mounts are allowed there.
	for i := 0; i < len(spec.Mounts); i++ {
		m := spec.Mounts[i]
		if strings.HasPrefix(m.Destination, "/proc/") ||
			(strings.HasPrefix(m.Destination, "/sys/") && (m.Destination != "/sys/fs/cgroup")) {
			spec.Mounts = append(spec.Mounts[:i], spec.Mounts[i+1:]...)
			i--
			logrus.Debugf("removed mount %s from spec (not compatible with sysvisor-runc)", m.Destination)
		}
	}

	// add sysvisorfs mounts to the config
	for _, mount := range sysvisorfsMounts {
		spec.Mounts = append(spec.Mounts, mount)
		logrus.Debugf("added sysvisor-fs mount %s to spec", mount.Destination)
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
	for _, arch:= range seccomp.Architectures {
		if arch == specs.ArchX86_64 {
			supportedArch = true
		}
	}
	if !supportedArch {
		return nil
	}

	// we don't yet support specs with default trap & trace actions
	if (seccomp.DefaultAction != specs.ActAllow &&
		 seccomp.DefaultAction != specs.ActErrno &&
		 seccomp.DefaultAction != specs.ActKill) {
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
				Names: []string{str},
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

// cfgLibModMount bind mounts the host's /lib/modules/<kernel-release>
// directory in the same path inside the system container; this allows
// system container processes to verify the presence of modules via
// modprobe. System apps such as Docker and K8s do this. Note that
// this does not imply module loading/unloading is supported in a
// system container. It merely lets processes check if a module is
// loaded.
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
		Options:     []string{"rbind", "rprivate"},
	}

	// check if the container spec has a match or a conflict for the mount
	for _, m := range spec.Mounts {
		if (m.Source == mount.Source) &&
			(m.Destination == mount.Destination) &&
			(m.Type == mount.Type) &&
			stringSliceEqual(m.Options, mount.Options) {
			return nil
		}

		if (m.Destination == mount.Destination) {
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
// filesystem supported by sysvisor
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

	logrus.Debugf("system container root path is not on one of these filesystems: " +
		           "%v; running an inner docker container won't work " +
		           "unless a host volume is mounted on the system " +
		           "container's /var/lib/docker",
		           reflect.ValueOf(SupportedRootFs).MapKeys())

	return nil
}

// specCheck performs some basic checks on the system container's spec
func specCheck(spec *specs.Spec) error {

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

// ConvertSpec converts the given container spec to a system container spec.
func ConvertSpec(spec *specs.Spec) error {

	if err := specCheck(spec); err != nil {
		return fmt.Errorf("invalid or unsupported system container spec: %v", err)
	}

	if err := cfgNamespaces(spec); err != nil {
		return fmt.Errorf("invalid namespace config: %v", err)
	}

	if err := cfgIDMappings(spec); err != nil {
		return fmt.Errorf("invalid user/group ID config: %v", err)
	}

	cfgCapabilities(spec)
	cfgMaskedPaths(spec)
	cfgReadonlyPaths(spec)

	if err := cfgCgroups(spec); err != nil {
		return fmt.Errorf("failed to configure cgroup mounts: %v", err)
	}

	if err := cfgLibModMount(spec, true); err != nil {
		return fmt.Errorf("failed to setup /lib/module/<kernel-version> mount: %v", err)
	}

	cfgSysvisorfsMounts(spec)

	if err := cfgSeccomp(spec.Linux.Seccomp); err != nil {
		return fmt.Errorf("failed to configure seccomp: %v", err)
	}

	return nil
}
