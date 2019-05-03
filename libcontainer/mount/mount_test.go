package mount

import (
	"io/ioutil"
	"log"
	"os"
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

func TestMounted(t *testing.T) {
	ok, err := Mounted("/proc")
	if err != nil || !ok {
		t.Fatalf("Mounted() failed: %v, %v", ok, err)
	}
	ok, err = Mounted("/sys")
	if err != nil || !ok {
		t.Fatalf("Mounted() failed: %v, %v", ok, err)
	}

	// negative testing
	dir, err := ioutil.TempDir("", "TestMounted")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	ok, err = Mounted("dir")
	if err != nil || ok {
		t.Fatalf("Mounted() failed: %v, %v", ok, err)
	}
}

func TestMountedWithFs(t *testing.T) {
	ok, err := MountedWithFs("/proc", "proc")
	if err != nil || !ok {
		t.Fatalf("MountedWithFs() failed: %v, %v", ok, err)
	}
	ok, err = MountedWithFs("/sys", "sysfs")
	if err != nil || !ok {
		t.Fatalf("MountedWithFs() failed: %v, %v", ok, err)
	}

	// negative testing
	ok, err = MountedWithFs("/proc", "sysfs")
	if err != nil || ok {
		t.Fatalf("MountedWithFs() failed: %v, %v", ok, err)
	}
	ok, err = MountedWithFs("/sys", "procfs")
	if err != nil || ok {
		t.Fatalf("MountedWithFs() failed: %v, %v", ok, err)
	}
}

func TestGetMountAt(t *testing.T) {
	m, err := GetMountAt("/proc")
	if err != nil {
		t.Fatalf("GetMountAt() failed: %v", err)
	}
	if m.Mountpoint == "/proc" {
		if m.Fstype != "proc" {
			t.Fatalf("GetMountAt() failed: want type = proc, got %s", m.Fstype)
		}
	}

	m, err = GetMountAt("/sys")
	if err != nil {
		t.Fatalf("GetMountAt() failed: %v", err)
	}
	if m.Mountpoint == "/sys" {
		if m.Fstype != "sysfs" {
			t.Fatalf("GetMountAt() failed: want type = sysfs, got %s", m.Fstype)
		}
	}
}
