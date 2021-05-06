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
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	libutils "github.com/nestybox/sysbox-libs/utils"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

// The min supported kernel release is chosen based on whether it contains all kernel
// fixes required to run sysbox. Refer to the Sysbox distro compatibility doc.
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
	var kmaj, kmin int

	rel, err := libutils.GetKernelRelease()
	if err != nil {
		return err
	}

	splits := strings.SplitN(rel, ".", -1)
	if len(splits) < 2 {
		return fmt.Errorf("failed to parse kernel release %v", rel)
	}

	major, err := strconv.Atoi(splits[0])
	if err != nil {
		return fmt.Errorf("failed to parse kernel release %v", rel)
	}

	minor, err := strconv.Atoi(splits[1])
	if err != nil {
		return fmt.Errorf("failed to parse kernel release %v", rel)
	}

	if distro == "ubuntu" {
		kmaj = minKernelUbuntu.major
		kmin = minKernelUbuntu.minor
	} else {
		kmaj = minKernel.major
		kmin = minKernel.minor
	}

	supported := false
	if major > kmaj {
		supported = true
	} else if major == kmaj {
		if minor >= kmin {
			supported = true
		}
	}

	if !supported {
		s := []string{strconv.Itoa(kmaj), strconv.Itoa(kmin)}
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

func hostSupportsUidShifting() bool {

	// For now Sysbox requires the kernel shiftfs module for UID shifting
	// (present by default in recent Ubuntu desktop & server editions).
	//
	// TODO: now that ID-mapped mounts have been added to the 5.12 Linux kernel,
	// we should leverage that functionality for uid-shifting when possible. This
	// would void the need for shiftfs and thus increase the number of distros
	// supported by Sysbox.

	if err := KernelModSupported("shiftfs"); err == nil {
		return true
	}

	return false
}

// checkUidShifting checks if the host supports uid shifting.
// The first return value indicates if the host supports
// uid shifting, and the second indicates if uid shifting is
// required for the container's rootfs. If uid shifting is not
// supported but is required for this container, the function
// returns an error.
func CheckUidShifting(spec *specs.Spec) (bool, bool, error) {

	uidShiftSupported := hostSupportsUidShifting()

	uidShiftRootfs, err := needUidShiftOnRootfs(spec)
	if err != nil {
		return false, false, fmt.Errorf("failed to check uid shifting requirement on rootfs: %s", err)
	}

	if !uidShiftSupported && uidShiftRootfs {
		return false, false, fmt.Errorf("this container requires user-ID shifting but the kernel does not support it." +
			" Upgrade your kernel to include the shiftfs module, or alternatively enable Linux user-namespace" +
			" support in the the container manager (e.g., Docker userns-remap, CRI-O userns annotation, etc)." +
			" Refer to the Sysbox troubleshooting guide for more info.")
	}

	return uidShiftSupported, uidShiftRootfs, nil
}

// CheckHostConfig checks if the host is configured appropriately to run a
// container with sysbox
func CheckHostConfig(context *cli.Context, spec *specs.Spec) error {

	distro, err := libutils.GetDistro()
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

// KernelModSupported returns nil if the given module is loaded in the kernel.
func KernelModSupported(mod string) error {

	// Load the module
	exec.Command("modprobe", mod).Run()

	// Check if the module is in the kernel
	f, err := os.Open("/proc/filesystems")
	if err != nil {
		return fmt.Errorf("failed to open /proc/filesystems to check for %s module", mod)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.Contains(s.Text(), mod) {
			return nil
		}
	}

	return fmt.Errorf("%s module is not loaded in the kernel", mod)
}
