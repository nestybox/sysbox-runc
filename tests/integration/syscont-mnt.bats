#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

@test "syscont: /lib/modules/<kernel-release> mount" {
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  runc exec test_busybox sh -c 'mount | grep "/lib/modules"'
  [ "$status" -eq 0 ]
  [[ "${output}" =~ "/lib/modules/$(uname -r)" ]]
}

@test "syscont: disallowed mounts" {
  skip "not written yet"
  # add some disallowed mounts to the container's spec
  # launch the sys container
  # verify that sysbox-runc removed the disallowed mounts
}

@test "syscont: sysbox-fs mounts" {
  skip "not written yet"
  # launch the sys container
  # verify that sysbox-fs was mounted at the expected locations
}

@test "syscont: sysbox-fs can't be unmounted" {
  skip "wait until sysboxd implements intercept of mount syscall"
  # Verify that the sys container root can't unmount sysbox-fs mounts
}

@test "syscont: procfs remount" {
  skip "wait until sysboxd implements intercept of umount syscall"
  # Verify that unmounting procfs inside the sys container is not allowed
}
