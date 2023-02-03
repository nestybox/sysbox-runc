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

package sysbox

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	sh "github.com/nestybox/sysbox-libs/idShiftUtils"
	linuxUtils "github.com/nestybox/sysbox-libs/linuxUtils"
	libutils "github.com/nestybox/sysbox-libs/utils"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

// The min supported kernel release is chosen based on whether it contains all kernel
// fixes required to run Sysbox. Refer to the Sysbox distro compatibility doc.
type kernelRelease struct{ major, minor int }

var minKernel = kernelRelease{5, 5}       // 5.5
var minKernelUbuntu = kernelRelease{5, 0} // 5.0

func readFileInt(path string) (int, error) {

	f, err := os.Open(path)
	if err != nil {
		return -1, err
	}
	defer f.Close()

	var b []byte = make([]byte, unsafe.Sizeof(int(0)))
	_, err = f.Read(b)
	if err != nil {
		return -1, err
	}

	var val int
	_, err = fmt.Sscanf(string(b), "%d", &val)
	if err != nil {
		return -1, err
	}

	return val, nil
}

// checks if the kernel is configured to allow unprivileged users to create
// namespaces. This is necessary for running containers inside a system
// container.
func checkUnprivilegedUserns() error {

	// In Debian-based distros, unprivileged userns creation is enabled via
	// "/proc/sys/kernel/unprivileged_userns_clone". In Fedora (and related)
	// distros this sysctl does not exist. Rather, unprivileged userns creation
	// is enabled by setting a non-zero value in "/proc/sys/user/max_user_namespaces".
	// Here we check both.

	path := "/proc/sys/kernel/unprivileged_userns_clone"
	if _, err := os.Stat(path); err == nil {

		val, err := readFileInt(path)
		if err != nil {
			return err
		}

		if val != 1 {
			return fmt.Errorf("kernel is not configured to allow unprivileged users to create namespaces: %s: want 1, have %d",
				path, val)
		}
	}

	path = "/proc/sys/user/max_user_namespaces"

	val, err := readFileInt(path)
	if err != nil {
		return err
	}

	if val == 0 {
		return fmt.Errorf("kernel is not configured to allow unprivileged users to create namespaces: %s: want >= 1, have %d",
			path, val)
	}

	return nil
}

func checkKernelVersion(distro string) error {
	var (
		reqMaj, reqMin int
		major, minor   int
	)

	rel, err := linuxUtils.GetKernelRelease()
	if err != nil {
		return err
	}

	major, minor, err = linuxUtils.ParseKernelRelease(rel)
	if err != nil {
		return err
	}

	if distro == "ubuntu" {
		reqMaj = minKernelUbuntu.major
		reqMin = minKernelUbuntu.minor
	} else {
		reqMaj = minKernel.major
		reqMin = minKernel.minor
	}

	supported := false
	if major > reqMaj {
		supported = true
	} else if major == reqMaj {
		if minor >= reqMin {
			supported = true
		}
	}

	if !supported {
		s := []string{strconv.Itoa(reqMaj), strconv.Itoa(reqMin)}
		kver := strings.Join(s, ".")
		return fmt.Errorf("%s kernel release %v is not supported; need >= %v", distro, rel, kver)
	}

	return nil
}

// needUidShiftOnRootfs checks if uid/gid shifting is required on the container's rootfs.
func needUidShiftOnRootfs(spec *specs.Spec) (bool, error) {
	var hostUidMap, hostGidMap uint32

	// the uid map is assumed to be present
	for _, mapping := range spec.Linux.UIDMappings {
		if mapping.ContainerID == 0 {
			hostUidMap = mapping.HostID
			break
		}
	}

	// the gid map is assumed to be present
	for _, mapping := range spec.Linux.GIDMappings {
		if mapping.ContainerID == 0 {
			hostGidMap = mapping.HostID
			break
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

	// Use shifting when the rootfs is owned by true root and the containers uid/gid root
	// mapping don't match the container's rootfs owner.
	if rootfsUid == 0 && rootfsGid == 0 &&
		hostUidMap != rootfsUid && hostGidMap != rootfsGid {
		return true, nil
	}

	return false, nil
}

// checkUidShifting returns the type of UID shifting needed (if any) for the
// container. The first return value indicates the type of UID shifting needed
// for the container's rootfs, while the second indicates the type of UID
// shifting for bind-mounts.
func CheckUidShifting(sysMgr *Mgr, spec *specs.Spec) (sh.IDShiftType, sh.IDShiftType, error) {

	useShiftfs := sysMgr.Config.UseShiftfs
	useIDMapping := sysMgr.Config.UseIDMapping

	useIDMappingOnOvfs := sysMgr.Config.UseIDMappingOnOverlayfs
	useShiftfsOnOvfs := sysMgr.Config.UseShiftfsOnOverlayfs

	useShiftfsOnRootfs := false
	useIDMappingOnRootfs := false

	rootPathFs, err := libutils.GetFsName(spec.Root.Path)
	if err != nil {
		return sh.NoShift, sh.NoShift, err
	}

	if useIDMapping {
		if rootPathFs == "overlayfs" && useIDMappingOnOvfs {
			useIDMappingOnRootfs = true
		}
	}

	if useShiftfs {
		if rootPathFs == "overlayfs" && useShiftfsOnOvfs {
			useShiftfsOnRootfs = true
		}
	}

	needShiftOnRootfs, err := needUidShiftOnRootfs(spec)
	if err != nil {
		return sh.NoShift, sh.NoShift, fmt.Errorf("failed to check uid-shifting requirement on rootfs: %s", err)
	}

	// Check uid shifting type to be used for the container's rootfs.
	//
	// We do it via ID-mapping (preferably), or via shiftfs (if available on the
	// host), or by chown'ing the rootfs hierarchy. If both ID-mapping and
	// shiftfs are supported, we will try ID-mapping first and in case it does
	// not work, use shiftfs. Chowning is the least preferred and slowest
	// approach, but won't disrupt anything on the host since the container's
	// rootfs is dedicated to the container (no other entity in the system will
	// use it while the container is running).
	rootfsShiftType := sh.NoShift

	if needShiftOnRootfs {
		if useIDMappingOnRootfs && useShiftfsOnRootfs {
			rootfsShiftType = sh.IDMappedMountOrShiftfs
		} else if useIDMappingOnRootfs {
			rootfsShiftType = sh.IDMappedMount
		} else if useShiftfsOnRootfs {
			rootfsShiftType = sh.Shiftfs
		} else {
			rootfsShiftType = sh.Chown
		}
	}

	// Check uid shifting type to be used for the container's bind mounts.
	//
	// For bind mounts, we use ID-mapping or shiftfs, but never chown. Chowning
	// for bind mounts is not a good idea since we don't know what's being bind
	// mounted (e.g., the bind mount could be a user's home dir, a critical
	// system file, etc.).
	bindMountShiftType := sh.NoShift

	if useIDMapping && useShiftfs {
		bindMountShiftType = sh.IDMappedMountOrShiftfs
	} else if useIDMapping {
		bindMountShiftType = sh.IDMappedMount
	} else if useShiftfs {
		bindMountShiftType = sh.Shiftfs
	}

	return rootfsShiftType, bindMountShiftType, nil
}

// CheckHostConfig checks if the host is configured appropriately to run a
// container with sysbox
func CheckHostConfig(context *cli.Context, spec *specs.Spec) error {

	distro, err := linuxUtils.GetDistro()
	if err != nil {
		return err
	}

	if !context.GlobalBool("no-kernel-check") {
		if err := checkKernelVersion(distro); err != nil {
			return fmt.Errorf("kernel version check failed: %v", err)
		}
	}

	if err := checkUnprivilegedUserns(); err != nil {
		return err
	}

	return nil
}
