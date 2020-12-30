// +build !linux !cgo !seccomp

package seccomp

import (
	"errors"

	"github.com/opencontainers/runc/libcontainer/configs"
)

var ErrSeccompNotEnabled = errors.New("seccomp: config provided but seccomp not supported")

// LoadSeccomp does nothing because seccomp is not supported.
func LoadSeccomp(config *configs.Seccomp) (int32, error) {
	if config != nil {
		return -1, ErrSeccompNotEnabled
	}
	return -1, nil
}

// IsEnabled returns false, because it is not supported.
func IsEnabled() bool {
	return false
}

// Version returns major, minor, and micro.
func Version() (uint, uint, uint) {
	return 0, 0, 0
}
