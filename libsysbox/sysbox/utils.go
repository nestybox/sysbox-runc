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
	"unsafe"
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
