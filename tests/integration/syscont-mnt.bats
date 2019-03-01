#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

@test "syscont: sysvisor-fs mounts" {
  skip "not written yet"
  # launch the sys container
  # verify that sysvisor-fs was mounted at the expected locations
}

@test "syscont: sysvisor-fs can't be unmount" {
  skip "wait until sysvisor implements intercept of mount syscall"
  # Verify that the sys container root can't unmount sysvisor-fs mounts
}

@test "syscont: procfs remount" {
  skip "wait until sysvisor implements intercept of mount syscall"
  # Verify that unmounting and remounting procfs inside the sys container
  # causes the sysvisor-fs mounts to be setup
}
