#!/usr/bin/env bats

load helpers

function setup_busybox_tmpfs() {
  mkdir -p /tmp/busyboxtest/rootfs
  tar --exclude './dev/*' -C /tmp/busyboxtest/rootfs -xf "$BUSYBOX_IMAGE"

  # sysbox-runc: set bundle ownership to match system
  # container's uid/gid map, except if using uid-shifting
  if [ -z "$SHIFT_UIDS" ]; then
      chown -R "$UID_MAP":"$GID_MAP" /tmp/busyboxtest
  fi

  cd /tmp/busyboxtest
  runc_spec
}

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
	teardown_running_container test_bind_mount
}

@test "runc run [bind mount]" {

	run touch /mnt/test-file
	[ "$status" -eq 0 ]

	update_config ' .mounts += [{"source": "/mnt", "destination": "/tmp/bind", "options": ["bind"]}]
			| .process.args |= ["ls", "/tmp/bind/"]'

	runc run test_bind_mount
	[ "$status" -eq 0 ]
   [[ "${lines[0]}" =~ 'test-file' ]]
}

@test "runc run [ro tmpfs mount]" {
	update_config ' .mounts += [{"source": "tmpfs", "destination": "/mnt", "type": "tmpfs", "options": ["ro", "nodev", "nosuid", "mode=755"]}]
			| .process.args |= ["grep", "^tmpfs /mnt", "/proc/mounts"]'

	runc run test_ro_tmpfs_mount
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" == *'ro,'* ]]
}

@test "runc runc [bind mount above rootfs]" {

	# test: bind mount source path is above but not directly above rootfs
	run mkdir bindSrc
	[ "$status" -eq 0 ]

	run touch bindSrc/test-file
	[ "$status" -eq 0 ]

	update_config ' .mounts |= . + [{"source": "bindSrc", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]'

	runc run test_bind_mount
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ 'test-file' ]]
}

@test "runc run [bind mount directly above rootfs]" {

	update_config ' .mounts |= . + [{"source": ".", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]'

	runc run test_bind_mount

	if [ -z "$SHIFT_UIDS" ]; then
      [ "$status" -eq 0 ]
      [[ "${lines[0]}" =~ 'config.json' ]]
	else
		[ "$status" -eq 1 ]
	fi
}

@test "bind mount below the rootfs" {

  CONFIG=$(jq '.mounts |= . + [{"source": "rootfs/root", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["/bin/sh"]' config.json)
  echo "${CONFIG}" >config.json

  runc run -d --console-socket $CONSOLE_SOCKET test_bind_mount
  [ "$status" -eq 0 ]

  runc exec test_bind_mount touch /root/test-file.txt
  [ "$status" -eq 0 ]

  runc exec test_bind_mount ls /root
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" =~ 'test-file.txt' ]]

  runc exec test_bind_mount ls /tmp/bind
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" =~ 'test-file.txt' ]]

  runc exec test_bind_mount rm /tmp/bind/test-file.txt
  [ "$status" -eq 0 ]

  runc exec test_bind_mount ls /root
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" =~ '' ]]
}

@test "rootfs on tmpfs" {
  setup_busybox_tmpfs

  runc run -d --console-socket $CONSOLE_SOCKET test_bind_mount
  if [ -z "$SHIFT_UIDS" ]; then
      [ "$status" -eq 0 ]
  else
    [ "$status" -eq 1 ]
  fi
}
