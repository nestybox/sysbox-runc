#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

@test "runc run [bind mount]" {

  run touch /mnt/test-file
  [ "$status" -eq 0 ]

  CONFIG=$(jq '.mounts |= . + [{"source": "/mnt", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]' config.json)
  echo "${CONFIG}" >config.json

  runc run test_bind_mount
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" =~ 'test-file' ]]
}
