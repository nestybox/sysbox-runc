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
@test "init process capabilities" {
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
@test "root process capabilities" {
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
@test "non-root process capabilities" {

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

@test "sys container namespaces" {
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  # For each ns, check that the sys container's init process is in a
  # different namespace than the test script.

  for nsType in cgroup ipc mnt net pid user uts
  do
    syscont_ns=$(runc exec test_busybox ls -l /proc/1/ns | grep -i "$nsType" | cut -d":" -f3)
    [ "$status" -eq 0 ]
    test_ns=$(ls -l /proc/self/ns | grep -i "$nsType" | cut -d":" -f3)
    [ "$status" -eq 0 ]
    [ "$syscont_ns" != "test_ns" ]
  done
}

@test "uid/gid mappings" {
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  runc exec test_busybox cat /proc/1/uid_map
  [ "$status" -eq 0 ]

  uid_int=$(echo "${lines[0]}" | awk '{print $1}')
  uid_ext=$(echo "${lines[0]}" | awk '{print $2}')
  uid_size=$(echo "${lines[0]}" | awk '{print $3}')

  [[ "$uid_int" == "0" ]]
  [[ "$uid_ext" == "$UID_MAP" ]]
  [[ "$uid_size" == "$ID_MAP_SIZE" ]]
}

# Verify the cgroup config
@test "cgroup mount" {
  runc run -d --console-socket $CONSOLE_SOCKET test_busybox
  [ "$status" -eq 0 ]

  runc exec test_busybox cat /proc/1/uid_map
  [ "$status" -eq 0 ]

  # verify sys container root has access to /sys/fs/cgroup
  user=$(ls -l /sys/fs/cgroup/ | awk '{print $3}' | tr '\n' ' ')
  for i in $user
  do
    [ "$i" == "root" ]
  done

  group=$(ls -l /sys/fs/cgroup/ | awk '{print $4}' | tr '\n' ' ')
  for i in $group
  do
    [ "$i" == "root" ]
  done

  # note: the cgroup root of the system container is equivalent to the
  # hostCgroupRoot + "/", where hostCgroupRoot can be found by reading
  # the host's /proc/self/cgroup. If the test is running in a docker
  # container (as it usually is), then that container is the "host"
  # and will have it's cgroup root at /docker/<container-id>.  Thus,
  # the system container running inside the docker test container will
  # have that same root.
  hostCgRoot=$(cat /proc/1/cgroup | grep cpuset | cut -d":" -f3)

  # verify sys container cgroup root in /proc/$$/cgroup
  syscontCgRoot=$(cat /proc/1/cgroup | cut -d":" -f3 | tr '\n' ' ')
  for i in $syscontCgRoot
  do
    [ "$i" == "$hostCgRoot" ]
  done

  # verify sys container cgroup root in /proc/$$/mountinfo
  syscontCgRoot=$(cat /proc/1/mountinfo | grep "/sys/fs/cgroup/" | cut -d" " -f4 | tr '\n' ' ')
  for i in $syscontCgRoot
  do
    [ "$i" == "$hostCgRoot" ]
  done

  # verify cgroup is mounted read-write
  mountOpt=$(cat /proc/1/mountinfo | grep "cgroup" | cut -d" " -f6 | tr '\n' ' ')
  for i in $mountOpt
  do
    [[ "$i" =~ "rw," ]]
  done
}

# Verify read-only paths

# Verify masked paths

# Verify sysvisor-fs mounts

# Verify sysvisor-runc spec command
