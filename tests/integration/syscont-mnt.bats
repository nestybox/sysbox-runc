#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

@test "syscont: sysbox-fs mounts" {
  skip "not written yet"
  # launch the sys container
  # verify that sysbox-fs was mounted at the expected locations
}

@test "syscont: sysbox-fs can't be unmount" {
  skip "wait until sysbox implements intercept of mount syscall"
  # Verify that the sys container root can't unmount sysbox-fs mounts
}

@test "syscont: procfs remount" {
  skip "wait until sysbox implements intercept of mount syscall"
  # Verify that unmounting and remounting procfs inside the sys container
  # causes the sysbox-fs mounts to be setup
}
