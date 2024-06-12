//
// Copyright 2019-2022 Nestybox, Inc.
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

//go:build linux
// +build linux

package syscont

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
	"github.com/nestybox/sysbox-libs/capability"
	sh "github.com/nestybox/sysbox-libs/idShiftUtils"
	utils "github.com/nestybox/sysbox-libs/utils"
	"github.com/opencontainers/runc/libsysbox/sysbox"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

// Exported
const (
	IdRangeMin uint32 = 65536
)

// Internal
const (
	defaultUid uint32 = 231072
	defaultGid uint32 = 231072
)

var (
	SysboxFsDir string = "/var/lib/sysboxfs"
)

// System container "must-have" mounts
var syscontMounts = []specs.Mount{
	specs.Mount{
		Destination: "/sys",
		Source:      "sysfs",
		Type:        "sysfs",
		Options:     []string{"noexec", "nosuid", "nodev"},
	},
	specs.Mount{
		Destination: "/sys/fs/cgroup",
		Source:      "cgroup",
		Type:        "cgroup",
		Options:     []string{"noexec", "nosuid", "nodev"},
	},
	specs.Mount{
		Destination: "/proc",
		Source:      "proc",
		Type:        "proc",
		Options:     []string{"noexec", "nosuid", "nodev"},
	},
	specs.Mount{
		Destination: "/dev",
		Source:      "tmpfs",
		Type:        "tmpfs",
		Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
	},
	//we don't yet support /dev/kmsg; create a dummy one
	specs.Mount{
		Destination: "/dev/kmsg",
		Source:      "/dev/null",
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
}

// Container mounts virtualized by sysbox-fs
//
// TODO: in the future get these from sysbox-fs via grpc
var sysboxFsMounts = []specs.Mount{
	//
	// procfs mounts
	//
	specs.Mount{
		Destination: "/proc/sys",
		Source:      filepath.Join(SysboxFsDir, "proc/sys"),
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
	specs.Mount{
		Destination: "/proc/swaps",
		Source:      filepath.Join(SysboxFsDir, "proc/swaps"),
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
	specs.Mount{
		Destination: "/proc/uptime",
		Source:      filepath.Join(SysboxFsDir, "proc/uptime"),
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},

	// XXX: In the future sysbox-fs will also virtualize the following

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

	//
	// sysfs mounts
	//
	specs.Mount{
		Destination: "/sys/kernel",
		Source:      filepath.Join(SysboxFsDir, "sys/kernel"),
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
	specs.Mount{
		Destination: "/sys/devices/virtual",
		Source:      filepath.Join(SysboxFsDir, "sys/devices/virtual"),
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
	specs.Mount{
		Destination: "/sys/module/nf_conntrack/parameters",
		Source:      filepath.Join(SysboxFsDir, "sys/module/nf_conntrack/parameters"),
		Type:        "bind",
		Options:     []string{"rbind", "rprivate"},
	},
}

// sys container systemd mount requirements
var syscontSystemdMounts = []specs.Mount{
	specs.Mount{
		Destination: "/run",
		Source:      "tmpfs",
		Type:        "tmpfs",
		Options:     []string{"rw", "rprivate", "nosuid", "nodev", "mode=755", "size=64m"},
	},
	specs.Mount{
		Destination: "/run/lock",
		Source:      "tmpfs",
		Type:        "tmpfs",
		Options:     []string{"rw", "rprivate", "noexec", "nosuid", "nodev", "size=4m"},
	},
}

// sys container systemd env-vars requirements
var syscontSystemdEnvVars = []string{

	// Allow systemd to identify the virtualization mode to operate on (container
	// with user-namespace). See 'ConditionVirtualization' attribute here:
	// https://www.freedesktop.org/software/systemd/man/systemd.unit.html
	"container=private-users",
}

// List of file-system paths within a sys container that must be read-write to satisfy
// system-level apps' requirements. This slide is useful in scenarios where the sys
// container is running as "read-only" as per the corresponding oci-spec attribute.
// In this mode, the sys container's rootfs is mounted read-only, which prevents RW
// operations to tmpfs paths like '/run' and '/tmp'. This slide helps us override the
// read-only attribute for these paths.
var syscontMustBeRwMounts = []specs.Mount{
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

// syscontRwPaths list the paths within the sys container's rootfs
// that must have read-write permission
var syscontRwPaths = []string{
	"/proc",
	"/proc/sys",
}

// syscontExposedPaths list the paths within the sys container's rootfs
// that must not be masked
var syscontExposedPaths = []string{
	"/proc",
	"/proc/sys",

	// Some apps need these to be exposed (or more accurately need them to not be masked
	// via a bind-mount from /dev/null, as described in sysbox issue #511). It's not a
	// security concern to expose these in sys containers, as they are either not accessible
	// or don't provide meaningful info (due to the sys container's user-ns).
	"/proc/kcore",
	"/proc/kallsyms",
	"/proc/kmsg",
}

// syscontSystemdExposedPaths list the paths within the sys container's rootfs
// that must not be masked when the sys container runs systemd
var syscontSystemdExposedPaths = []string{
	"/run",
	"/run/lock",
	"/tmp",
	"/sys/kernel",
}

// syscontRwPaths list the paths within the sys container's rootfs
// that must have read-write permission
var syscontSystemdRwPaths = []string{
	"/run",
	"/run/lock",
	"/tmp",
	"/sys/kernel",
}

// cfgNamespaces checks that the namespace config has the minimum set
// of namespaces required and adds any missing namespaces to it
func cfgNamespaces(sysMgr *sysbox.Mgr, spec *specs.Spec) error {

	// user-ns and cgroup-ns are not required per the OCI spec, but we will add
	// them to the system container spec.
	var allNs = []string{"pid", "ipc", "uts", "mount", "network", "user", "cgroup"}
	var reqNs = []string{"pid", "ipc", "uts", "mount", "network"}

	allNsSet := mapset.NewSet[string]()
	for _, ns := range allNs {
		allNsSet.Add(ns)
	}

	reqNsSet := mapset.NewSet[string]()
	for _, ns := range reqNs {
		reqNsSet.Add(ns)
	}

	specNsSet := mapset.NewSet[string]()
	for _, ns := range spec.Linux.Namespaces {
		specNsSet.Add(string(ns.Type))
	}

	if !reqNsSet.IsSubset(specNsSet) {
		return fmt.Errorf("sysbox containers can't share namespaces %v with the host (because they use the linux user-namespace for isolation)", reqNsSet.Difference(specNsSet).ToSlice())
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

	// Check if we have a sysbox-mgr override for the container's user-ns
	if sysMgr.Enabled() {
		if sysMgr.Config.Userns != "" {
			updatedNs := []specs.LinuxNamespace{}

			for _, ns := range spec.Linux.Namespaces {
				if ns.Type == specs.UserNamespace {
					ns.Path = sysMgr.Config.Userns
				}
				updatedNs = append(updatedNs, ns)
			}

			spec.Linux.Namespaces = updatedNs
		}
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

// validateIDMappings checks if the spec's user namespace uid and gid mappings meet
// sysbox-runc requirements.
func validateIDMappings(spec *specs.Spec) error {
	var err error

	if len(spec.Linux.UIDMappings) == 0 || len(spec.Linux.GIDMappings) == 0 {
		return fmt.Errorf("detected missing user-ns UID and/or GID mappings")
	}

	// Sysbox requires that the container uid & gid mappings map a continuous
	// range of container IDs to host IDs. This is a requirement implicitly
	// imposed by Sysbox's usage of shiftfs. The call to mergeIDmappings ensures
	// this is the case and returns a single ID mapping range in case the
	// container's spec gave us a continuous mapping in multiple continuous
	// sub-ranges.

	spec.Linux.UIDMappings, err = mergeIDMappings(spec.Linux.UIDMappings)
	if err != nil {
		return err
	}

	spec.Linux.GIDMappings, err = mergeIDMappings(spec.Linux.GIDMappings)
	if err != nil {
		return err
	}

	uidMap := spec.Linux.UIDMappings[0]
	gidMap := spec.Linux.GIDMappings[0]

	if uidMap.ContainerID != 0 || uidMap.Size < IdRangeMin {
		return fmt.Errorf("uid mapping range must specify a container with at least %d uids starting at uid 0; found %v",
			IdRangeMin, uidMap)
	}

	if gidMap.ContainerID != 0 || gidMap.Size < IdRangeMin {
		return fmt.Errorf("gid mapping range must specify a container with at least %d gids starting at gid 0; found %v",
			IdRangeMin, gidMap)
	}

	if uidMap.HostID != gidMap.HostID {
		return fmt.Errorf("detecting non-matching uid & gid mappings; found uid = %v, gid = %d",
			uidMap, gidMap)
	}

	if uidMap.HostID == 0 {
		return fmt.Errorf("detected user-ns uid mapping to host ID 0 (%v); this breaks container isolation",
			uidMap)
	}

	if gidMap.HostID == 0 {
		return fmt.Errorf("detected user-ns gid mapping to host ID 0 (%v); this breaks container isolation",
			uidMap)
	}

	return nil
}

// cfgIDMappings checks if the uid/gid mappings are present and valid; if they are not
// present, it allocates them.
func cfgIDMappings(sysMgr *sysbox.Mgr, spec *specs.Spec) error {

	// Honor user-ns uid & gid mapping spec overrides from sysbox-mgr; this occur
	// when a container shares the same userns and netns of another container (i.e.,
	// they must also share the mappings).
	if sysMgr.Enabled() {
		if len(sysMgr.Config.UidMappings) > 0 {
			spec.Linux.UIDMappings = sysMgr.Config.UidMappings
		}
		if len(sysMgr.Config.GidMappings) > 0 {
			spec.Linux.GIDMappings = sysMgr.Config.GidMappings
		}
	}

	// If no mappings are present, let's allocate some.
	if len(spec.Linux.UIDMappings) == 0 && len(spec.Linux.GIDMappings) == 0 {
		return allocIDMappings(sysMgr, spec)
	}

	return validateIDMappings(spec)
}

// cfgCapabilities sets the capabilities for the process in the system container
func cfgCapabilities(p *specs.Process) error {
	caps := p.Capabilities
	uid := p.User.UID

	noCaps := []string{}

	sysboxCaps, err := getSysboxEffCaps()
	if err != nil {
		return err
	}

	if uid == 0 {
		// init processes owned by root have all capabilities assigned to Sysbox itself (i.e., all root caps)
		caps.Bounding = sysboxCaps
		caps.Effective = sysboxCaps
		caps.Inheritable = sysboxCaps
		caps.Permitted = sysboxCaps
		caps.Ambient = sysboxCaps
	} else {
		// init processes owned by others have all caps disabled and the bounding caps all
		// set (just as in a regular host)
		caps.Bounding = sysboxCaps
		caps.Effective = noCaps
		caps.Inheritable = noCaps
		caps.Permitted = noCaps
		caps.Ambient = noCaps
	}

	return nil
}

// getSysboxEffCaps returns the list of capabilities assigned to sysbox-runc itself.
func getSysboxEffCaps() ([]string, error) {
	caps, err := capability.NewPid2(0)
	if err != nil {
		return nil, err
	}
	err = caps.Load()
	if err != nil {
		return nil, err
	}

	allCapsStr := caps.StringCap(capability.EFFECTIVE, capability.OCI_STRING)
	allCapsStr = strings.ReplaceAll(allCapsStr, ", ", ",")
	return strings.Split(allCapsStr, ","), nil
}

// cfgMaskedPaths adds or removes from the container's config any masked paths required by Sysbox.
func cfgMaskedPaths(spec *specs.Spec) {
	if systemdInit(spec.Process) {
		spec.Linux.MaskedPaths = utils.StringSliceRemove(spec.Linux.MaskedPaths, syscontSystemdExposedPaths)
	}
	spec.Linux.MaskedPaths = utils.StringSliceRemove(spec.Linux.MaskedPaths, syscontExposedPaths)
}

// cfgReadonlyPaths removes from the container's config any read-only paths
// that must be read-write in the system container
func cfgReadonlyPaths(spec *specs.Spec) {
	if systemdInit(spec.Process) {
		spec.Linux.ReadonlyPaths = utils.StringSliceRemove(spec.Linux.ReadonlyPaths, syscontSystemdRwPaths)
	}
	spec.Linux.ReadonlyPaths = utils.StringSliceRemove(spec.Linux.ReadonlyPaths, syscontRwPaths)
}

// cfgMounts configures the system container mounts
func cfgMounts(spec *specs.Spec, sysbox *sysbox.Sysbox) error {

	sysMgr := sysbox.Mgr
	sysFs := sysbox.Fs

	// We will modify the container's mounts; remember the original ones
	sysbox.OrigMounts = spec.Mounts

	if sysMgr.Config.SyscontMode {
		cfgSyscontMounts(sysMgr, spec)
	}

	if sysFs.Enabled() {
		cfgSysboxFsMounts(spec, sysFs)
	}

	if sysMgr.Enabled() {
		if err := sysMgrSetupMounts(sysbox, spec); err != nil {
			return err
		}
	}

	hasSystemd := false
	if systemdInit(spec.Process) && sysMgr.Config.SyscontMode {
		hasSystemd = true
		cfgSystemdMounts(spec)
	}

	sortMounts(spec, hasSystemd)

	return nil
}

// cfgSyscontMounts adds mounts required by sys containers; if the spec
// has conflicting mounts, these are replaced with the required ones.
func cfgSyscontMounts(sysMgr *sysbox.Mgr, spec *specs.Spec) {

	// Disallow mounts under the container's /sys/fs/cgroup/* (i.e., Sysbox sets those up)
	var cgroupMounts = []specs.Mount{
		specs.Mount{
			Destination: "/sys/fs/cgroup/",
		},
	}

	spec.Mounts = utils.MountSliceRemove(spec.Mounts, cgroupMounts, func(m1, m2 specs.Mount) bool {
		return strings.HasPrefix(m1.Destination, m2.Destination)
	})

	// Remove other conflicting mounts
	spec.Mounts = utils.MountSliceRemove(spec.Mounts, syscontMounts, func(m1, m2 specs.Mount) bool {
		return m1.Destination == m2.Destination
	})

	// Remove devices that conflict with sysbox mounts (e.g., /dev/kmsg)
	specDevs := []specs.LinuxDevice{}
	for _, dev := range spec.Linux.Devices {
		m := specs.Mount{Destination: dev.Path}
		if !utils.MountSliceContains(syscontMounts, m, func(m1, m2 specs.Mount) bool {
			return m1.Destination == m2.Destination
		}) {
			specDevs = append(specDevs, dev)
		}
	}
	spec.Linux.Devices = specDevs

	// In read-only scenarios, we want to adjust the syscont mounts to ensure that
	// certain container mounts are always mounted as read-write.
	if spec.Root.Readonly {
		cfgSyscontMountsReadOnly(sysMgr, spec)
		return
	}

	// Add sysbox's default syscont mounts
	spec.Mounts = append(spec.Mounts, syscontMounts...)
}

// cfgSyscontMountsReadOnly adjusts the RW/RO character of syscont mounts in
// 'read-only' container scenarios. The purpose of this function is to ensure:
//   - certain container mounts are always mounted as read-write (i.e., /run and /tmp)
//   - /sys mounts are always mounted as read-only unless the sysbox-mgr is configured
//     with the "relaxed-readonly" option.
func cfgSyscontMountsReadOnly(sysMgr *sysbox.Mgr, spec *specs.Spec) {

	// We want to ensure that certain container mounts are always mounted as
	// read-write (i.e., /run and /tmp) unless the user has explicitly marked
	// them as read-only in the container spec.
	for _, m := range syscontMustBeRwMounts {
		var found bool
		for _, p := range spec.Mounts {
			if p.Destination == m.Destination {
				found = true
				break
			}
		}
		if !found {
			spec.Mounts = append(spec.Mounts, m)
		}
	}

	// If sysbox-mgr is configured with the "relaxed-readonly" option, we allow
	// "/sys" mountpoints to be read-write, otherwise we mark them as read-only.
	if sysMgr.Config.RelaxedReadOnly {
		spec.Mounts = append(spec.Mounts, syscontMounts...)
		return
	}
	tmpMounts := []specs.Mount{}
	rwOpt := []string{"rw"}
	for _, m := range syscontMounts {
		if strings.HasPrefix(m.Destination, "/sys") {
			m.Options = utils.StringSliceRemove(m.Options, rwOpt)
			m.Options = append(m.Options, "ro")
		}
		tmpMounts = append(tmpMounts, m)
	}

	spec.Mounts = append(spec.Mounts, tmpMounts...)
}

// cfgSysboxFsMounts adds the sysbox-fs mounts to the container's config.
func cfgSysboxFsMounts(spec *specs.Spec, sysFs *sysbox.Fs) {

	spec.Mounts = utils.MountSliceRemove(spec.Mounts, sysboxFsMounts, func(m1, m2 specs.Mount) bool {
		return m1.Destination == m2.Destination
	})

	// Adjust sysboxFsMounts path attending to container-id value.
	cntrMountpoint := filepath.Join(sysFs.Mountpoint, sysFs.Id)

	for i := range sysboxFsMounts {
		sysboxFsMounts[i].Source =
			strings.Replace(
				sysboxFsMounts[i].Source,
				SysboxFsDir,
				cntrMountpoint,
				1,
			)
	}

	SysboxFsDir = sysFs.Mountpoint

	// If the spec indicates a read-only rootfs, the sysbox-fs mounts should also
	// be read-only. However, we don't mark them read-only here explicitly, so
	// that they are initially mounted read-write while setting up the container.
	// This is needed because the setup process may need to write to some of
	// these mounts (e.g., writes to /proc/sys during networking setup). Instead,
	// we add the mounts to the "readonly" paths list, so that they will be
	// remounted to read-only after the container setup completes, right before
	// starting the container's init process.
	if spec.Root.Readonly {
		for _, m := range sysboxFsMounts {
			spec.Linux.ReadonlyPaths = append(spec.Linux.ReadonlyPaths, m.Destination)
		}
	}

	spec.Mounts = append(spec.Mounts, sysboxFsMounts...)
}

// cfgSystemdMounts adds systemd related mounts to the spec
func cfgSystemdMounts(spec *specs.Spec) {

	// For sys containers with systemd inside, sysbox mounts tmpfs over certain directories
	// of the container (this is a systemd requirement). However, if the container spec
	// already has tmpfs mounts over any of these directories, we honor the spec mounts
	// (i.e., these override the sysbox mount).

	spec.Mounts = utils.MountSliceRemove(spec.Mounts, syscontSystemdMounts, func(m1, m2 specs.Mount) bool {
		return m1.Destination == m2.Destination && m1.Type != "tmpfs"
	})

	syscontSystemdMounts = utils.MountSliceRemove(syscontSystemdMounts, spec.Mounts, func(m1, m2 specs.Mount) bool {
		return m1.Destination == m2.Destination && m2.Type == "tmpfs"
	})

	spec.Mounts = append(spec.Mounts, syscontSystemdMounts...)
}

// Function parses any given 'file' looking for an 'attr' field. For the parsing
// operation to succeed, the say file is expected to conform to this layout:
// "<attr>: <val>".
//
// Examples:
//
// - Docker -> "data-root": "/var/lib/docker",
// - RKE2   -> "data-dir": "/var/lib/rancher/rke2",
func getFileAttrValue(file, attr string) (string, error) {

	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Splits on newlines by default.
	scanner := bufio.NewScanner(f)

	// Parse the 'attr' field of the passed file.
	for scanner.Scan() {
		data := scanner.Text()
		if strings.Contains(data, attr) {

			dataRootStr := strings.Split(data, ":")
			if len(dataRootStr) == 2 {
				dataRoot := dataRootStr[1]
				dataRoot = strings.TrimSpace(dataRoot)
				dataRoot = strings.Trim(dataRoot, "\",")

				if len(dataRoot) > 0 {
					return dataRoot, nil
				}

				break
			}
		}
	}

	return "", nil
}

// Obtains the docker data-root path utilized by the inner docker process to store its
// data. This is used to define the container mountpoint on which the host's docker
// volume (backing this resource) will be mounted on.
//
// Notice that even though this code habilitates the custom definition of the data-root's
// location, this will be only honored by Sysbox if this attribute is set prior to the
// container creation (i.e., at docker-image build time).
func getInnerDockerDataRootPath(spec *specs.Spec) (string, error) {

	var defaultDataRoot = "/var/lib/docker"

	rootPath, err := filepath.Abs(spec.Root.Path)
	if err != nil {
		return "", err
	}

	dockerCfgFile := filepath.Join(rootPath, "/etc/docker/daemon.json")

	val, err := getFileAttrValue(dockerCfgFile, "data-root")
	if err != nil || val == "" {
		return defaultDataRoot, nil
	}

	return val, nil
}

// Obtains the data-dir path utilized by the inner rke or k3s server/agents to
// to store their data. This is used to define the container mountpoint on which
// the host's docker volume (backing this resource) will be mounted on.
func getInnerK3sDataDirPath(spec *specs.Spec) (string, error) {

	var defaultDataDir = "/var/lib/rancher/k3s"

	rootPath, err := filepath.Abs(spec.Root.Path)
	if err != nil {
		return "", err
	}

	k3sCfgFile := filepath.Join(rootPath, "/etc/rancher/k3s/config.yaml")

	val, err := getFileAttrValue(k3sCfgFile, "data-dir")
	if err != nil || val == "" {
		return defaultDataDir, nil
	}

	return val, nil
}

// Obtains the rke2 data-dir path utilized by the inner rke2 server and agent
// processes to store their data. This is used to define the container mountpoint
// on which the host's docker volume (backing this resource) will be mounted on.
func getInnerRke2DataDirPath(spec *specs.Spec) (string, error) {

	var defaultDataDir = "/var/lib/rancher/rke2"

	rootPath, err := filepath.Abs(spec.Root.Path)
	if err != nil {
		return "", err
	}

	rke2CfgFile := filepath.Join(rootPath, "/etc/rancher/rke2/config.yaml")

	val, err := getFileAttrValue(rke2CfgFile, "data-dir")
	if err != nil || val == "" {
		return defaultDataDir, nil
	}

	return val, nil
}

func getSpecialDirs(spec *specs.Spec) (map[string]ipcLib.MntKind, error) {

	innerDockerDataRoot, err := getInnerDockerDataRootPath(spec)
	if err != nil {
		return nil, err
	}

	innerK3sDataDir, err := getInnerK3sDataDirPath(spec)
	if err != nil {
		return nil, err
	}

	innerRke2DataDir, err := getInnerRke2DataDirPath(spec)
	if err != nil {
		return nil, err
	}

	// These directories in the sys container are bind-mounted from host dirs managed by sysbox-mgr
	specialDirMap := map[string]ipcLib.MntKind{
		innerDockerDataRoot: ipcLib.MntVarLibDocker,
		"/var/lib/kubelet":  ipcLib.MntVarLibKubelet,
		"/var/lib/k0s":      ipcLib.MntVarLibK0s,
		innerK3sDataDir:     ipcLib.MntVarLibRancherK3s,
		innerRke2DataDir:    ipcLib.MntVarLibRancherRke2,
		"/var/lib/buildkit": ipcLib.MntVarLibBuildkit,
		"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs": ipcLib.MntVarLibContainerdOvfs,
	}

	return specialDirMap, nil
}

// sysMgrSetupMounts requests the sysbox-mgr to setup special container mounts
// (e.g., the implicit mounts that sysbox creates over the container's
// /var/lib/docker, /var/lib/kubelet, etc. in order to enable system software to
// run in the container seamlessly).
func sysMgrSetupMounts(sysbox *sysbox.Sysbox, spec *specs.Spec) error {

	rootfsUidShiftType := sysbox.RootfsUidShiftType
	mgr := sysbox.Mgr

	specialDirMap, err := getSpecialDirs(spec)
	if err != nil {
		return err
	}

	// If the spec has a host bind-mount over one of the special dirs, ask the
	// sysbox-mgr to prepare the mount source (e.g., chown files to match the
	// container host uid & gid).

	prepList := []ipcLib.MountPrepInfo{}

	for i := len(spec.Mounts) - 1; i >= 0; i-- {
		m := spec.Mounts[i]
		_, isSpecialDir := specialDirMap[m.Destination]

		if m.Type == "bind" && isSpecialDir {
			info := ipcLib.MountPrepInfo{
				Source:    m.Source,
				Exclusive: true,
			}

			prepList = append(prepList, info)
			delete(specialDirMap, m.Destination)
		}
	}

	uid := spec.Linux.UIDMappings[0].HostID
	gid := spec.Linux.GIDMappings[0].HostID

	if len(prepList) > 0 {
		if err := mgr.PrepMounts(uid, gid, prepList); err != nil {
			return err
		}
	}

	// If we are not in sys container mode, skip setting up the implicit sysbox-mgr mounts.
	if !mgr.Config.SyscontMode {
		return nil
	}

	// Add the special dirs to the list of implicit mounts setup by Sysbox.
	// sysbox-mgr will setup host dirs to back the mounts; it will also send us
	// a list of any other implicit mounts it needs.
	reqList := []ipcLib.MountReqInfo{}
	for dest, kind := range specialDirMap {
		info := ipcLib.MountReqInfo{
			Kind: kind,
			Dest: dest,
		}
		reqList = append(reqList, info)
	}

	m, err := mgr.ReqMounts(rootfsUidShiftType, reqList)
	if err != nil {
		return err
	}

	// If any sysbox-mgr mounts conflict with any in the spec (i.e.,
	// same dest), prioritize the spec ones
	mounts := utils.MountSliceRemove(m, spec.Mounts, func(m1, m2 specs.Mount) bool {
		return m1.Destination == m2.Destination
	})

	// If the spec indicates a read-only rootfs, the sysbox-mgr mounts should
	// also be read-only. The exception to this rule is in scenarios where the
	// sysbox-mgr is in "relaxed-read-only" mode, in which case the mounts are
	// left as read-write.
	if spec.Root.Readonly && !sysbox.Mgr.Config.RelaxedReadOnly {
		tmpMounts := []specs.Mount{}
		rwOpt := []string{"rw"}
		for _, m := range mounts {
			m.Options = utils.StringSliceRemove(m.Options, rwOpt)
			m.Options = append(m.Options, "ro")
			tmpMounts = append(tmpMounts, m)
		}
		mounts = tmpMounts
	}

	spec.Mounts = append(spec.Mounts, mounts...)

	return nil
}

// checkSpec performs some basic checks on the system container's spec
func checkSpec(spec *specs.Spec) error {

	if spec.Root == nil || spec.Linux == nil {
		return fmt.Errorf("not a linux container spec")
	}

	// Ensure the container's network ns is not shared with the host
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace && ns.Path != "" {
			var st1, st2 unix.Stat_t

			if err := unix.Stat("/proc/self/ns/net", &st1); err != nil {
				return fmt.Errorf("unable to stat sysbox's network namespace: %s", err)
			}
			if err := unix.Stat(ns.Path, &st2); err != nil {
				return fmt.Errorf("unable to stat %q: %s", ns.Path, err)
			}

			if (st1.Dev == st2.Dev) && (st1.Ino == st2.Ino) {
				return fmt.Errorf("sysbox containers can't share a network namespace with the host (because they use the linux user-namespace for isolation)")
			}

			break
		}
	}

	return nil
}

// getSysboxEnvVarConfigs collects the SYSBOX_* env vars passed to the container.
func getSysboxEnvVarConfigs(p *specs.Process, sbox *sysbox.Sysbox) error {
	var knownEnvVars = map[string]string{
		"SYSBOX_IGNORE_SYSFS_CHOWN":  "bool",
		"SYSBOX_ALLOW_TRUSTED_XATTR": "bool",
		"SYSBOX_HONOR_CAPS":          "bool",
		"SYSBOX_SYSCONT_MODE":        "bool",
		"SYSBOX_SKIP_UID_SHIFT":      "string",
	}

	for _, ev := range p.Env {
		if !strings.HasPrefix(ev, "SYSBOX_") {
			continue
		}

		tokens := strings.Split(ev, "=")
		if len(tokens) != 2 {
			return fmt.Errorf("env var %s has incorrect format; expected VAR=VALUE.", ev)
		}

		evName := tokens[0]
		evVal := tokens[1]

		// If a SYSBOX_* env var is specified, it must be one of the supported ones.
		envVarType, ok := knownEnvVars[evName]
		if !ok {
			return fmt.Errorf("invalid env var %s; must be one of %v", evName, knownEnvVars)
		}

		switch envVarType {
		case "bool":
			if err := getSysboxBoolEnvVarConfigs(sbox, evName, evVal); err != nil {
				return err
			}
		case "string":
			if err := getSysboxStringEnvVarConfigs(sbox, evName, evVal); err != nil {
				return err
			}
		}
	}

	return nil
}

func getSysboxBoolEnvVarConfigs(sbox *sysbox.Sysbox, evName string, evVal string) error {
	if evVal != "TRUE" && evVal != "FALSE" {
		return fmt.Errorf("env var %s has invalid value %s; expect [TRUE|FALSE].", evName, evVal)
	}

	switch evName {
	case "SYSBOX_IGNORE_SYSFS_CHOWN":
		sbox.Mgr.Config.IgnoreSysfsChown = (evVal == "TRUE")
	case "SYSBOX_ALLOW_TRUSTED_XATTR":
		sbox.Mgr.Config.AllowTrustedXattr = (evVal == "TRUE")
	case "SYSBOX_HONOR_CAPS":
		sbox.Mgr.Config.HonorCaps = (evVal == "TRUE")
	case "SYSBOX_SYSCONT_MODE":
		sbox.Mgr.Config.SyscontMode = (evVal == "TRUE")
	}

	return nil
}

func getSysboxStringEnvVarConfigs(sbox *sysbox.Sysbox, evName string, evVal string) error {
	if evVal == "" {
		return fmt.Errorf("env var %s has empty value", evName)
	}
	if isWhitespacePresent := regexp.MustCompile(`\s`).MatchString(evVal); isWhitespacePresent {
		return fmt.Errorf("env var %s has invalid value %s; space characters are not allowed", evName, evVal)
	}

	var err error

	switch evName {
	case "SYSBOX_SKIP_UID_SHIFT":
		if sbox.IDshiftIgnoreList, err = getSysboxEnvVarIDshiftIgnoreConfig(evName, evVal); err != nil {
			return err
		}
	}

	return nil
}

// getSysboxEnvVarIDshiftIgnoreConfig parses the SYSBOX_SKIP_UID_SHIFT env-var and returns
// a list of paths for which id-shifting operations must be avoided.
// Example: "/var/lib/mutagen,/var/lib/docker".
func getSysboxEnvVarIDshiftIgnoreConfig(evName, evVal string) ([]string, error) {
	paths := strings.Split(evVal, ",")

	// Iterate through the paths and verify they are all absolute.
	for i, p := range paths {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("env var %s has an invalid (not absolute) path: %s", evName, p)
		}
		paths[i] = p
	}

	return paths, nil
}

// removeSysboxEnvVarsForExec removes the SYSBOX_* env vars from the process spec.
// It only does this for env vars meant to be per-container (rather than per-process).
func removeSysboxEnvVarsForExec(p *specs.Process) {
	env := []string{}
	for _, envVar := range p.Env {
		if !strings.HasPrefix(envVar, "SYSBOX_IGNORE_SYSFS_CHOWN=") &&
			!strings.HasPrefix(envVar, "SYSBOX_ALLOW_TRUSTED_XATTR=") &&
			!strings.HasPrefix(envVar, "SYSBOX_SYSCONT_MODE=") &&
			!strings.HasPrefix(envVar, "SYSBOX_SKIP_UID_SHIFT=") {
			env = append(env, envVar)
		}
	}

	p.Env = env
}

func cfgOomScoreAdj(spec *specs.Spec) {

	// For sys containers we don't allow -1000 for the OOM score value, as this
	// is not supported from within a user-ns.

	if spec.Process.OOMScoreAdj != nil {
		if *spec.Process.OOMScoreAdj < -999 {
			*spec.Process.OOMScoreAdj = -999
		}
	}
}

// cfgSeccomp configures the system container's seccomp settings.
func cfgSeccomp(seccomp *specs.LinuxSeccomp) error {

	if seccomp == nil {
		return nil
	}

	supportedArch := false
	for _, arch := range seccomp.Architectures {
		if arch == specs.ArchX86_64 || arch == specs.ArchAARCH64 || arch == specs.ArchARM {
			supportedArch = true
		}
	}
	if !supportedArch {
		return nil
	}

	// we don't yet support specs with default trap, trace, or log actions
	if seccomp.DefaultAction != specs.ActAllow &&
		seccomp.DefaultAction != specs.ActErrno &&
		seccomp.DefaultAction != specs.ActKill {
		return fmt.Errorf("spec seccomp default actions other than allow, errno, and kill are not supported")
	}

	// categorize syscalls per seccomp actions
	allowSet := mapset.NewSet[string]()
	disallowSet := mapset.NewSet[string]()

	for _, syscall := range seccomp.Syscalls {
		for _, name := range syscall.Names {
			switch syscall.Action {
			case specs.ActAllow:
				allowSet.Add(name)
			case specs.ActErrno:
				fallthrough
			case specs.ActKill:
				disallowSet.Add(name)
			}
		}
	}

	// convert sys container syscall whitelist to a set
	syscontAllowSet := mapset.NewSet[string]()
	for _, sc := range syscontSyscallWhitelist {
		syscontAllowSet.Add(sc)
	}

	// seccomp syscall list may be a whitelist or blacklist
	whitelist := (seccomp.DefaultAction == specs.ActErrno ||
		seccomp.DefaultAction == specs.ActKill)

	addSet := mapset.NewSet[string]()
	rmSet := mapset.NewSet[string]()

	if whitelist {
		addSet = syscontAllowSet.Difference(allowSet)
		rmSet = disallowSet.Intersect(syscontAllowSet)
	} else {
		// Note: no addSet here since we don't have a sysbox syscall blacklist
		rmSet = disallowSet.Difference(syscontAllowSet)
	}

	// Remove syscalls from the container's error/kill lists
	if rmSet.Cardinality() > 0 {
		var newSyscalls []specs.LinuxSyscall
		for _, sc := range seccomp.Syscalls {
			if sc.Action == specs.ActErrno || sc.Action == specs.ActKill {
				n := []string{}
				for _, scName := range sc.Names {
					if !rmSet.Contains(scName) {
						n = append(n, scName)
					}
				}
				sc.Names = n
				if len(sc.Names) > 0 {
					newSyscalls = append(newSyscalls, sc)
				}
			} else {
				newSyscalls = append(newSyscalls, sc)
			}
		}
		seccomp.Syscalls = newSyscalls
	}

	// Add syscalls to the container's allowed list
	if addSet.Cardinality() > 0 {
		for syscallName := range addSet.Iter() {
			str := fmt.Sprintf("%v", syscallName)
			sc := specs.LinuxSyscall{
				Names:  []string{str},
				Action: specs.ActAllow,
			}
			seccomp.Syscalls = append(seccomp.Syscalls, sc)
		}
	}

	if whitelist {
		// Remove argument restrictions on syscalls (except those for which we
		// allow such restrictions).
		for i, syscall := range seccomp.Syscalls {
			for _, name := range syscall.Names {
				if !utils.StringSliceContains(syscontSyscallAllowRestrList, name) {
					seccomp.Syscalls[i].Args = nil
				}
			}
		}
	}

	return nil
}

// Configures which syscalls are trapped by Sysbox inside a system container
func cfgSyscontSyscallTraps(sysMgr *sysbox.Mgr) {

	if sysMgr.Config.IgnoreSysfsChown {
		chownSyscalls := []string{
			"chown", "fchown", "fchownat",
		}
		syscallTrapList = append(syscallTrapList, chownSyscalls...)
	}

	if sysMgr.Config.AllowTrustedXattr {
		xattrSyscalls := []string{
			"setxattr", "lsetxattr", "fsetxattr",
			"getxattr", "lgetxattr", "fgetxattr",
			"removexattr", "lremovexattr", "fremovexattr",
			"listxattr", "llistxattr", "flistxattr",
		}
		syscallTrapList = append(syscallTrapList, xattrSyscalls...)
	}
}

// Configures rootfs cloning (when required); returns true if rootfs was cloned.
func cfgRootfsCloning(spec *specs.Spec, sysbox *sysbox.Sysbox) (bool, error) {

	sysMgr := sysbox.Mgr
	sysbox.OrigRootfs = spec.Root.Path

	if !sysMgr.Enabled() || sysMgr.Config.NoRootfsCloning {
		return false, nil
	}

	cloneRootfs, err := rootfsCloningRequired(spec.Root.Path)
	if err != nil || !cloneRootfs {
		return false, err
	}

	newRootfs, err := sysMgr.CloneRootfs()
	if err != nil {
		return false, err
	}

	spec.Root.Path = newRootfs
	return true, nil
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

// Configure environment variables required for systemd
func cfgSystemdEnv(p *specs.Process) {

	p.Env = utils.StringSliceRemoveMatch(p.Env, func(specEnvVar string) bool {
		name, _, err := utils.GetEnvVarInfo(specEnvVar)
		if err != nil {
			return false
		}
		for _, sysboxSysdEnvVar := range syscontSystemdEnvVars {
			sname, _, err := utils.GetEnvVarInfo(sysboxSysdEnvVar)
			if err == nil && name == sname {
				return true
			}
		}
		return false
	})

	p.Env = append(p.Env, syscontSystemdEnvVars...)
}

// systemdInit returns true if the sys container is running systemd
func systemdInit(p *specs.Process) bool {
	return p.Args[0] == "/sbin/init"
}

// Configure the container's process spec for system containers
func ConvertProcessSpec(p *specs.Process, sbox *sysbox.Sysbox, isExec bool) error {

	sysMgr := sbox.Mgr

	if isExec {
		removeSysboxEnvVarsForExec(p)
		if err := getSysboxEnvVarConfigs(p, sbox); err != nil {
			return err
		}
	}

	if sysMgr.Config.SyscontMode && !sysMgr.Config.HonorCaps {
		if err := cfgCapabilities(p); err != nil {
			return err
		}
	}

	if sysMgr.Config.SyscontMode {
		if err := cfgAppArmor(p); err != nil {
			return fmt.Errorf("failed to configure AppArmor profile: %v", err)
		}
	}

	if systemdInit(p) && sysMgr.Config.SyscontMode {
		cfgSystemdEnv(p)
	}

	return nil
}

// ConvertSpec converts the given container spec to a system container spec.
func ConvertSpec(context *cli.Context, spec *specs.Spec, sbox *sysbox.Sysbox) error {

	sysMgr := sbox.Mgr

	if err := getSysboxEnvVarConfigs(spec.Process, sbox); err != nil {
		return err
	}

	if err := checkSpec(spec); err != nil {
		return fmt.Errorf("invalid or unsupported container spec: %v", err)
	}

	if err := cfgNamespaces(sysMgr, spec); err != nil {
		return fmt.Errorf("invalid or unsupported container spec: %v", err)
	}

	if err := cfgIDMappings(sysMgr, spec); err != nil {
		return fmt.Errorf("invalid user/group ID config: %v", err)
	}

	// Must do this after cfgIDMappings()
	rootfsUidShiftType, bindMntUidShiftType, err := sysbox.CheckUidShifting(sysMgr, spec)
	if err != nil {
		return err
	}

	rootfsCloned := false
	if rootfsUidShiftType == sh.Chown {
		rootfsCloned, err = cfgRootfsCloning(spec, sbox)
		if err != nil {
			return err
		}
	}

	sbox.RootfsUidShiftType = rootfsUidShiftType
	sbox.BindMntUidShiftType = bindMntUidShiftType
	sbox.RootfsCloned = rootfsCloned

	if err := cfgMounts(spec, sbox); err != nil {
		return fmt.Errorf("invalid mount config: %v", err)
	}

	if sysMgr.Config.SyscontMode {
		cfgMaskedPaths(spec)
		cfgReadonlyPaths(spec)
	}

	cfgOomScoreAdj(spec)

	if err := ConvertProcessSpec(spec.Process, sbox, false); err != nil {
		return fmt.Errorf("failed to configure process spec: %v", err)
	}

	if sysMgr.Config.SyscontMode {
		if err := cfgSeccomp(spec.Linux.Seccomp); err != nil {
			return fmt.Errorf("failed to configure seccomp: %v", err)
		}
	}

	if sysMgr.Config.SyscontMode {
		cfgSyscontSyscallTraps(sysMgr)
	}

	return nil
}
