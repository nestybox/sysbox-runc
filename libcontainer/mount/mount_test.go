package mount

import (
	"testing"
)

func TestGetMounts(t *testing.T) {
	allMounts, err := GetMounts()
	if err != nil {
		t.Fatalf("GetMounts() failed: %v", err)
	}
	for _, m := range allMounts {
		if m.Mountpoint == "/proc" {
			if m.Fstype != "proc" {
				t.Fatalf("GetMounts() failed: want type = proc, got %s", m.Fstype)
			}
		}
		if m.Mountpoint == "/sys" {
			if m.Fstype != "sysfs" {
				t.Fatalf("GetMounts() failed: want type = sysfs, got %s", m.Fstype)
			}
		}
	}
}

func TestMountedWithFs(t *testing.T) {
	allMounts, err := GetMounts()
	if err != nil {
		t.Fatalf("GetMounts() failed: %v", err)
	}

	ok, err := MountedWithFs("/proc", "proc", allMounts)
	if err != nil || !ok {
		t.Fatalf("MountedWithFs() failed: %v, %v", ok, err)
	}
	ok, err = MountedWithFs("/sys", "sysfs", allMounts)
	if err != nil || !ok {
		t.Fatalf("MountedWithFs() failed: %v, %v", ok, err)
	}

	// negative testing
	ok, err = MountedWithFs("/proc", "sysfs", allMounts)
	if err != nil || ok {
		t.Fatalf("MountedWithFs() failed: %v, %v", ok, err)
	}
	ok, err = MountedWithFs("/sys", "procfs", allMounts)
	if err != nil || ok {
		t.Fatalf("MountedWithFs() failed: %v, %v", ok, err)
	}
}

func TestGetMountAt(t *testing.T) {
	allMounts, err := GetMounts()
	if err != nil {
		t.Fatalf("GetMounts() failed: %v", err)
	}

	m, err := GetMountAt("/proc", allMounts)
	if err != nil {
		t.Fatalf("GetMountAt() failed: %v", err)
	}
	if m.Mountpoint == "/proc" {
		if m.Fstype != "proc" {
			t.Fatalf("GetMountAt() failed: want type = proc, got %s", m.Fstype)
		}
	}

	m, err = GetMountAt("/sys", allMounts)
	if err != nil {
		t.Fatalf("GetMountAt() failed: %v", err)
	}
	if m.Mountpoint == "/sys" {
		if m.Fstype != "sysfs" {
			t.Fatalf("GetMountAt() failed: want type = sysfs, got %s", m.Fstype)
		}
	}
}
