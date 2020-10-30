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
	"strconv"
	"strings"

	libutils "github.com/nestybox/sysbox-libs/utils"
	"github.com/urfave/cli"
)

// The min supported kernel release is chosen based on whether it contains all kernel
// fixes required to run sysbox. Refer to the sysbox github issues and search for
// "kernel".
type kernelRelease struct{ major, minor int }

var minKernel = kernelRelease{4, 10} // 4.10 (see issue #89)

// uid shifting requires shiftfs, currenlty present in Ubuntu only.
var uidShiftDistros = []string{"ubuntu"}

// checkUnprivilegedUserns checks if the kernel is configured to allow
// unprivileged users to create namespaces. This is necessary for
// running containers inside a system container.
func checkUnprivilegedUserns() error {

	// Debian & Ubuntu
	path := "/proc/sys/kernel/unprivileged_userns_clone"
	if _, err := os.Stat(path); err == nil {

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		var b []byte = make([]byte, 8)
		_, err = f.Read(b)
		if err != nil {
			return err
		}

		var val int
		fmt.Sscanf(string(b), "%d", &val)

		if val != 1 {
			return fmt.Errorf("kernel is not configured to allow unprivileged users to create namespaces: %s: want 1, have %d", path, val)
		}
	}

	// TODO: add other distros
	// Fedora
	// CentOS
	// Arch
	// Alpine
	// Amazon

	return nil
}

// checkDistro checks if the host has a supported distro
func checkDistro(shiftUids bool) error {

	// there are currently no distro requirements when uid shifting is not used
	if !shiftUids {
		return nil
	}

	osrelease, err := libutils.GetDistro()
	if err != nil {
		return err
	}

	for _, entry := range uidShiftDistros {
		if entry == osrelease {
			return nil
		}
	}

	return fmt.Errorf("%s is not supported when using uid shifting; supported distros are %v",
		osrelease, uidShiftDistros)
}

func checkKernel(uidShift bool) error {

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

	kmaj := minKernel.major
	kmin := minKernel.minor

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
		return fmt.Errorf("kernel release %v is not supported; need >= %v", rel, kver)
	}

	return nil
}

// CheckHostConfig checks if the host is configured appropriately to run sysbox-runc
func CheckHostConfig(context *cli.Context, shiftUids bool) error {

	if !context.GlobalBool("no-kernel-check") {
		if err := checkDistro(shiftUids); err != nil {
			return fmt.Errorf("distro support check: %v", err)
		}
		if err := checkKernel(shiftUids); err != nil {
			return fmt.Errorf("kernel support check: %v", err)
		}
	}

	if err := checkUnprivilegedUserns(); err != nil {
		return fmt.Errorf("host is not configured properly: %v", err)
	}

	return nil
}

// KernelModSupported returns nil if the given module is loaded in the kernel.
func KernelModSupported(mod string) error {

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
