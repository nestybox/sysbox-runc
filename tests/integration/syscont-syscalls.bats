#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
}

@test "syscont: syscall: mount and umount" {
	runc run -d --console-socket $CONSOLE_SOCKET test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "mkdir /root/test"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "mount --bind /root/test /root/test"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c 'mount | grep "test"'
	[ "$status" -eq 0 ]
	[[ "${output}" =~ "/root/test" ]]

	runc exec test_busybox sh -c "umount /root/test"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "rmdir /root/test"
	[ "$status" -eq 0 ]
}
