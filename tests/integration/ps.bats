#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

@test "ps" {
  # ps is not supported, it requires cgroups
  requires root

  # start busybox detached
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  # check state
  testcontainer test_busybox running

  runc ps test_busybox
  [ "$status" -eq 0 ]
  [[ ${lines[0]} =~ UID\ +PID\ +PPID\ +C\ +STIME\ +TTY\ +TIME\ +CMD+ ]]
  [[ "${lines[1]}" == *"$UID_MAP"*[0-9]* ]]
}

@test "ps -f json" {
  # ps is not supported, it requires cgroups
  requires root

  # start busybox detached
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  # check state
  testcontainer test_busybox running

  runc ps -f json test_busybox
  [ "$status" -eq 0 ]
  [[ ${lines[0]} =~ [0-9]+ ]]
}

@test "ps -e" {
  # ps is not supported, it requires cgroups
  requires root

  # start busybox detached
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  # check state
  testcontainer test_busybox running

  # sysvisor-runc: -e -x yields 0 processes because sys container uid
  # is not the same as the uid of the process executing ps.
  runc ps test_busybox -e
  [ "$status" -eq 0 ]
  [[ ${lines[0]} =~ \ +PID\ +TTY\ +TIME\ +CMD+ ]]
  [[ "${lines[1]}" =~ [0-9]+ ]]
}
