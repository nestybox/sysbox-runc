#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
}

function teardown() {
  teardown_busybox
}

# TODO: namespace nesting tests

# TODO: cgroup nesting tests

# TODO: container nesting tests

@test "syscont: inner container procfs" {
  skip "wait until sysvisor implements intercept of mount syscall"
  # Verify that mounting procfs inside an nested container
  # does not expose resources outside of the system container
}
