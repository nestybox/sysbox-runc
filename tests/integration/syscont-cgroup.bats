#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

# Verify the cgroup mounts inside the sys container
@test "syscont: cgroup mounts" {
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

# Verify that sys container root can create cgroups
@test "syscont: cgroup create" {
  skip "not written yet"
}
