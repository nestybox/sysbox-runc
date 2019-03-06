// +build linux

package syscontSpec

import (
	"fmt"

	mapset "github.com/deckarep/golang-set"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

// sysboxfsMounts is a list of system container mounts backed by sysbox-fs;
// please keep in alphabetical order.
var sysboxfsMounts = []specs.Mount{
	specs.Mount{
		Destination: "/proc",
		Source:      "proc",
		Type:        "proc",
		Options:     []string{"nosuid", "noexec", "nodev"},
	},
	// specs.Mount{
	// 	Destination: "/proc/cpuinfo",
	// 	Source:      "/var/lib/sysboxfs/proc/cpuinfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate"
	// },
	// specs.Mount{
	// 	Destination: "/proc/cgroups",
	// 	Source:      "/var/lib/sysboxfs/proc/cgroups",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/devices",
	// 	Source:      "/var/lib/sysboxfs/proc/devices",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/diskstats",
	// 	Source:      "/var/lib/sysboxfs/proc/diskstats",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/loadavg",
	// 	Source:      "/var/lib/sysboxfs/proc/loadavg",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/meminfo",
	// 	Source:      "/var/lib/sysboxfs/proc/meminfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/pagetypeinfo",
	// 	Source:      "/var/lib/sysboxfs/proc/pagetypeinfo",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/partitions",
	// 	Source:      "/var/lib/sysboxfs/proc/partitions",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/stat",
	// 	Source:      "/var/lib/sysboxfs/proc/stat",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/swaps",
	// 	Source:      "/var/lib/sysboxfs/proc/swaps",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	// specs.Mount{
	// 	Destination: "/proc/sys",
	// 	Source:      "/var/lib/sysboxfs/proc/sys",
	// 	Type:        "bind",
	// 	Options:     "rbind", "rprivate",
	// },
	specs.Mount{
		Destination: "/proc/uptime",
		Source:      "/var/lib/sysboxfs/proc/uptime",
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
}

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
		if cfgNs.Type == specs.CgroupNamespace {
			found = true
		}
	}

	if !found {

		// TODO: log this event.

		newns := specs.LinuxNamespace{
			Type: specs.CgroupNamespace,
			Path: "",
		}
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, newns)
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

		// TODO: if the capabilities are being changed, log this event.

		caps.Bounding = linuxCaps
		caps.Effective = linuxCaps
		caps.Inheritable = linuxCaps
		caps.Permitted = linuxCaps
		caps.Ambient = linuxCaps
	}
}

// cfgMaskedPaths removes from the container's config any masked paths for which
// sysbox-fs will handle accesses.
func cfgMaskedPaths(spec *specs.Spec) {
	paths := spec.Linux.MaskedPaths
	for i := 0; i < len(paths); i++ {
		for _, mount := range sysboxfsMounts {
			if paths[i] == mount.Destination {

				// TODO: log this event

				paths = append(paths[:i], paths[i+1:]...)
				i--
				break
			}
		}
	}
	spec.Linux.MaskedPaths = paths
}

// cfgReadonlyPaths removes from the container's config any read-only paths for which
// sysbox-fs will handle accesses.
func cfgReadonlyPaths(spec *specs.Spec) {
	paths := spec.Linux.ReadonlyPaths
	for i := 0; i < len(paths); i++ {
		for _, mount := range sysboxfsMounts {
			if paths[i] == mount.Destination {

				// TODO: log this event

				paths = append(paths[:i], paths[i+1:]...)
				i--
				break
			}
		}
	}
	spec.Linux.ReadonlyPaths = paths
}

// cfgSysboxfsMounts adds the sysbox-fs mounts to the containers config.
func cfgSysboxfsMounts(spec *specs.Spec) {

	// remove from the config any mounts that conflict with sysboxfs mounts
	for i := 0; i < len(spec.Mounts); i++ {
		for _, mount := range sysboxfsMounts {
			if spec.Mounts[i].Destination == mount.Destination {
				spec.Mounts = append(spec.Mounts[:i], spec.Mounts[i+1:]...)
				i--
				break
			}
		}
	}

	// add sysboxfs mounts to the config
	for _, mount := range sysboxfsMounts {
		spec.Mounts = append(spec.Mounts, mount)
	}
}

// cfgCgroups configures the system container's cgroup settings.
func cfgCgroups(spec *specs.Spec) error {

	// Remove the read-only attribute from the cgroup mount; this is fine because the sys
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

		logrus.Debugf("Added syscalls to seccomp profile: %v", diffSet)

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

		logrus.Debugf("Removed syscalls from seccomp profile: %v", diffSet)
	}

	return nil
}

// ConvertSpec converts the given container spec to a system container spec.
func ConvertSpec(spec *specs.Spec, strict bool) error {

	// TODO: verify spec in not nil and contains a Linux object; bail if it doesn't

	// TODO: Modify the spec for sys containers here;
	// validate and return the modified spec. Also, modify the seccomp
	// config for sys containers. Log messages when performing conversions.
	// If comparison should be strict, report errors on incompatible configs.

	if err := cfgNamespaces(spec); err != nil {
		return fmt.Errorf("invalid namespace config: %v", err)
	}

	if err := cfgIDMappings(spec); err != nil {
		return fmt.Errorf("invalid user/group ID config: %v", err)
	}

	cfgCapabilities(spec)
	cfgMaskedPaths(spec)
	cfgReadonlyPaths(spec)

	// TODO: uncomment this once sysbox-fs comes into the picture
	// cfgSysboxfsMounts(spec)

	if err := cfgCgroups(spec); err != nil {
		return fmt.Errorf("failed to configure cgroup mounts: %v", err)
	}

	// Remove readonly root filesystem config (spec.Root.Readonly)

	// Remove prestart hooks

	// cfg process spec
	// - uid/gid must be 0
	// - entry point must be system daemon

	// cfg seccomp config
	if err := cfgSeccomp(spec.Linux.Seccomp); err != nil {
		return fmt.Errorf("failed to configure seccomp: %v", err)
	}

	return nil
}
