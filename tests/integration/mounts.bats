#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
	teardown_running_container test_bind_mount
}

@test "runc run [bind mount]" {

	# test: bind mount source path has nothing in common with rootfs path
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

@test "runc run [bind mount source path] " {

	# test: bind mount source path has something in common with rootfs path
	run mkdir bindSrc
	[ "$status" -eq 0 ]

	run touch bindSrc/test-file
	[ "$status" -eq 0 ]

	update_config ' .mounts |= . + [{"source": "bindSrc", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]'

	runc run test_bind_mount
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ 'test-file' ]]
}

@test "runc run [bind mount invalid source path]" {

	update_config ' .mounts |= . + [{"source": ".", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]'

	runc run test_bind_mount
	[ "$status" -eq 1 ]

	update_config ' .mounts |= . + [{"source": "/", "destination": "/tmp/bind", "options": ["bind"]}] | .process.args = ["ls", "/tmp/bind/"]'

	runc run test_bind_mount
	[ "$status" -eq 1 ]
}
