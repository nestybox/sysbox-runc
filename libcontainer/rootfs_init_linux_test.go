//go:build linux
// +build linux

package libcontainer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOverlayMountBase(t *testing.T) {
	tests := []struct {
		name         string
		rootfs       string
		upperLayer   string
		lowerLayers  []string
		wantBase     string
		wantRelative bool
	}{
		{
			name:        "absolute lowerdirs need no base",
			rootfs:      "/var/lib/docker/overlay2/container/merged",
			upperLayer:  "/var/lib/docker/overlay2/container/diff",
			lowerLayers: []string{"/var/lib/docker/overlay2/l/layer-one"},
		},
		{
			name:         "containerd relative lowerdirs with absolute upperdir",
			rootfs:       "/run/containerd/io.containerd.runtime.v2.task/default/container/rootfs",
			upperLayer:   "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/55/fs",
			lowerLayers:  []string{"54/fs", "44/fs"},
			wantBase:     "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots",
			wantRelative: true,
		},
		{
			name:         "containerd relative lowerdir with trailing slash",
			rootfs:       "/run/containerd/io.containerd.runtime.v2.task/default/container/rootfs",
			upperLayer:   "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/55/fs",
			lowerLayers:  []string{"54/fs/"},
			wantBase:     "/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots",
			wantRelative: true,
		},
		{
			name:         "docker overlay2 relative lowerdir and upperdir",
			rootfs:       "/var/lib/docker/overlay2/container/merged",
			upperLayer:   "container/diff",
			lowerLayers:  []string{"l/layer-one", "l/layer-two"},
			wantBase:     "/var/lib/docker/overlay2",
			wantRelative: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, relative := overlayMountBase(tc.rootfs, tc.upperLayer, tc.lowerLayers)
			if base != tc.wantBase {
				t.Errorf("overlayMountBase() base = %q, want %q", base, tc.wantBase)
			}
			if relative != tc.wantRelative {
				t.Errorf("overlayMountBase() relative = %v, want %v", relative, tc.wantRelative)
			}
		})
	}
}

func TestValidateOverlayMountBase(t *testing.T) {
	base := t.TempDir()
	lowerLayer := filepath.Join("l", "layer-one")
	if err := os.MkdirAll(filepath.Join(base, lowerLayer), 0755); err != nil {
		t.Fatal(err)
	}

	if err := validateOverlayMountBase(base, lowerLayer); err != nil {
		t.Fatalf("validateOverlayMountBase() unexpected error: %v", err)
	}

	err := validateOverlayMountBase(base, filepath.Join("l", "missing-layer"))
	if err == nil {
		t.Fatal("validateOverlayMountBase() expected error")
	}
	if !strings.Contains(err.Error(), "cannot resolve relative overlay paths") {
		t.Fatalf("validateOverlayMountBase() error = %q", err)
	}
}
