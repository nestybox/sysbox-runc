#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

# Verify the sys-container init process has full capabilities
@test "syscont: init process caps" {
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  for capType in CapInh CapPrm CapEff CapBnd CapAmb
  do
    runc exec test_busybox grep "$capType" /proc/1/status
    [ "$status" -eq 0 ]
    [[ "${output}" == *"0000003fffffffff"* ]]
  done
}

# Verify a non-init sys-container root process has full capabilities
@test "syscont: root process caps" {
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  for capType in CapInh CapPrm CapEff CapBnd CapAmb
  do
    runc exec test_busybox grep "$capType" /proc/self/status
    [ "$status" -eq 0 ]
    [[ "${output}" == *"0000003fffffffff"* ]]
  done
}

# Verify a non-root process does not have any capabilities
@test "syscont: non-root process caps" {

  # TODO: this test fails due to a bug in sysvisor-runc; fix it
  skip "This test currently fails and needs investigation"

  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  for capType in CapInh CapPrm CapEff CapAmb
  do
    runc exec --user 1000:1000 test_busybox grep "$capType" /proc/self/status
    [ "$status" -eq 0 ]
    [[ "${output}" == *"0000000000000000"* ]]
  done

  runc exec --user 1000:1000 test_busybox grep capBnd /proc/self/status
  [ "$status" -eq 0 ]
  [[ "${output}" == *"0000003fffffffff"* ]]
}
