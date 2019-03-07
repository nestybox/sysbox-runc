package sysbox

import (
	"fmt"
	"os"
)

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
			return fmt.Errorf("%s: want 1, have %d", path, val)
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

// CheckHostConfig checks if the host is configured appropriately to run system containers.
func CheckHostConfig() error {
	errPreamble := "host is not configured properly: "

	if err := checkUnprivilegedUserns(); err != nil {
		return fmt.Errorf(errPreamble+"kernel does not allow unprivileged users to create namespaces: %v", err)
	}
	return nil
}
