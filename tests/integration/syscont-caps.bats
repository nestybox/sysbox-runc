#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

# A sys container root process has full caps (regardless of the container spec)
@test "syscont: root process caps" {

  sed -i "/\"CAP_SYS_ADMIN\",/d"  ${BUSYBOX_BUNDLE}/config.json
  sed -i "/\"CAP_NET_ADMIN\",/d"  ${BUSYBOX_BUNDLE}/config.json

  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  # Ensure init is a root process in this container
  runc exec test_busybox grep Uid /proc/1/status
  [ "$status" -eq 0 ]

  for i in `seq 2 5`
  do
    id=$(echo "$output" | awk -v var=$i '{print $var}')
    [ "$id" -eq "0" ]
  done

  # Ensure init has all caps
  for capType in CapInh CapPrm CapEff CapBnd CapAmb
  do
    runc exec test_busybox grep "$capType" /proc/1/status
    [ "$status" -eq 0 ]
    [[ "${output}" == *"0000003fffffffff"* ]]
  done
}

# A sys container root process has all caps when entered via exec
@test "syscont: exec root process caps" {

  sed -i "/\"CAP_SYS_ADMIN\",/d"  ${BUSYBOX_BUNDLE}/config.json
  sed -i "/\"CAP_NET_ADMIN\",/d"  ${BUSYBOX_BUNDLE}/config.json

  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  for capType in CapInh CapPrm CapEff CapBnd CapAmb
  do
    runc exec test_busybox grep "$capType" /proc/self/status
    [ "$status" -eq 0 ]
    [[ "${output}" == *"0000003fffffffff"* ]]
  done
}

# A sys container non-root init process caps are set per the container's spec
@test "syscont: exec non-root process caps" {

  sed -i "/\"CAP_SYS_ADMIN\",/d"  ${BUSYBOX_BUNDLE}/config.json
  sed -i "/\"CAP_NET_ADMIN\",/d"  ${BUSYBOX_BUNDLE}/config.json

  sed -i "s/\"uid\": 0/\"uid\": 1000/" ${BUSYBOX_BUNDLE}/config.json
  sed -i "s/\"gid\": 0/\"gid\": 1000/" ${BUSYBOX_BUNDLE}/config.json

  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  for capType in CapInh CapPrm CapEff CapBnd CapAmb
  do
    runc exec test_busybox grep "$capType" /proc/1/status
    [ "$status" -eq 0 ]
    [[ "${output}" == *"0000003fffdfefff"* ]]
  done
}

# A sys container non-root process caps are set per the container's spec when entered via exec
@test "syscont: exec non-root process caps" {

  sed -i "/\"CAP_SYS_ADMIN\",/d"  ${BUSYBOX_BUNDLE}/config.json
  sed -i "/\"CAP_NET_ADMIN\",/d"  ${BUSYBOX_BUNDLE}/config.json

  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  for capType in CapInh CapPrm CapEff CapBnd CapAmb
  do
    runc exec --user 1000:1000 test_busybox grep "$capType" /proc/self/status
    [ "$status" -eq 0 ]
    [[ "${output}" == *"0000003fffdfefff"* ]]
  done
}


# TODO: Verify sysvisor-runc exec caps are set correctly when giving exec a process.json


# TODO: Verify that sysvisor-runc exec cap override works
# - create spec without any caps and run sys container
# - exec into sys container as user 0 with --cap=CAP_SYS_ADMIN; verify root has all caps
# - exec into sys container as user 1000 with --cap=CAP_SYS_ADMIN; verify root has CAP_SYS_ADMIN only


# TODO: Verify specs without capabilities object are handled correctly
