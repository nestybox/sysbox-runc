#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox

	# Create fake rootfs.
	mkdir rootfs/testdir
	echo "Forbidden information!" >rootfs/testfile

	# sysbox-runc
	if [ -z "$SHIFT_UIDS" ]; then
		chown "$UID_MAP":"$GID_MAP" rootfs/testdir
		chown "$UID_MAP":"$GID_MAP" rootfs/testfile
	fi

	# add extra masked paths
	update_config '(.. | select(.maskedPaths? != null)) .maskedPaths += ["/testdir", "/testfile"]'
}

function teardown() {
	teardown_busybox
}

@test "mask paths [file]" {

	skip "NEEDS FIX"

	# run busybox detached
	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox cat /testfile
	[ "$status" -eq 0 ]
	[[ "${output}" == "" ]]

	runc exec test_busybox rm -f /testfile
	[ "$status" -eq 1 ]
	[[ "${output}" == *"Device or resource busy"* ]]

	# TODO: this operation passes in sys containers, but problably should
	# fail; we don't want to allow unmasking of a masked path.

	runc exec test_busybox umount /testfile
	[ "$status" -eq 1 ]
	[[ "${output}" == *"Device or resource busy"* ]]
}

@test "mask paths [directory]" {
	# run busybox detached
	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox ls /testdir
	[ "$status" -eq 0 ]
	[[ "${output}" == "" ]]

	runc exec test_busybox touch /testdir/foo
	[ "$status" -eq 1 ]
	[[ "${output}" == *"Read-only file system"* ]]

	runc exec test_busybox rm -rf /testdir
	[ "$status" -eq 1 ]
	[[ "${output}" == *"Device or resource busy"* ]]
}

# sysbox-runc: this test is expected to fail until sysbox can intercept
# the mount syscall to prevent umounting of mounts for masked paths
# @test "mask path umounting" {
# 	run busybox detached
# 	runc run -d --console-socket $CONSOLE_SOCKET test_busybox
# 	[ "$status" -eq 0 ]
#
# 	runc exec test_busybox umount /testfile
# 	[ "$status" -eq 1 ]
# 	[[ "${output}" == *"Operation not permitted"* ]]
#
# 	runc exec test_busybox umount /testdir
# 	[ "$status" -eq 1 ]
# 	[[ "${output}" == *"Operation not permitted"* ]]
# }
