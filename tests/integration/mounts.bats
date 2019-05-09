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
  else
    [ "$status" -eq 1 ]
  fi
}
