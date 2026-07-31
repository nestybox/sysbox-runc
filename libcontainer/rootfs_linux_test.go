// +build linux

package libcontainer

import (
	"testing"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func TestNeedsSetupDev(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/dev",
				Destination: "/dev",
			},
		},
	}
	if needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be false, got true")
	}
}

func TestNeedsSetupDevStrangeSource(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/devx",
				Destination: "/dev",
			},
		},
	}
	if needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be false, got true")
	}
}

func TestNeedsSetupDevStrangeDest(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/dev",
				Destination: "/devx",
			},
		},
	}
	if !needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be true, got false")
	}
}

func TestNeedsSetupDevStrangeSourceDest(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/devx",
				Destination: "/devx",
			},
		},
	}
	if !needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be true, got false")
	}
}

func TestMntDestDependsOn(t *testing.T) {
	tests := []struct {
		dest  string
		prior string
		want  bool
	}{
		{"/run", "/run", true},
		{"/run/secrets/kubernetes.io/serviceaccount", "/run", true},
		{"/run/foo", "/run/foo/bar", false},
		{"/runfoo", "/run", false},
		{"/var/run", "/run", false},
		{"/run", "/", true},
		{"/", "/", true},
	}
	for _, tc := range tests {
		if got := mntDestDependsOn(tc.dest, tc.prior); got != tc.want {
			t.Errorf("mntDestDependsOn(%q, %q) = %v, want %v", tc.dest, tc.prior, got, tc.want)
		}
	}
}
