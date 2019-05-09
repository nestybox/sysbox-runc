#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

@test "bind mount" {

  run touch /mnt/test-file
  [ "$status" -eq 0 ]

  CONFIG=$(jq '.mounts |= . + [{"source": "/mnt", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]' config.json)
  echo "${CONFIG}" >config.json

  runc run test_bind_mount
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" =~ 'test-file' ]]
}

@test "bind mount above rootfs" {

  # test: bind mount source path is above but not directly above rootfs
  run mkdir bindSrc
  [ "$status" -eq 0 ]

  run touch bindSrc/test-file
  [ "$status" -eq 0 ]

  CONFIG=$(jq '.mounts |= . + [{"source": "bindSrc", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]' config.json)
  echo "${CONFIG}" >config.json

  runc run test_bind_mount
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" =~ 'test-file' ]]
}

@test "bind mount directly above rootfs" {

  CONFIG=$(jq '.mounts |= . + [{"source": ".", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]' config.json)
  echo "${CONFIG}" >config.json

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
