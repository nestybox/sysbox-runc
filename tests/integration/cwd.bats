#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
}

# Test case for https://github.com/opencontainers/runc/pull/2086
@test "runc exec --user with no access to cwd" {
	requires root

	# sysbox-runc: containers always user the user-ns. If uid-shifting is not
	# used, the rootfs ownership must be within the range of host uids assigned
	# to the container.
	local uid
   if [ -z "$SHIFT_UIDS" ]; then
		uid=$(($UID_MAP+42))
	else
		uid=42
	fi

	chown $uid rootfs/root
	chmod 700 rootfs/root

	update_config '	  .process.cwd = "/root"
			| .process.user.uid = 42
			| .process.user.gid = 42
			| .process.args |= ["sleep", "1h"]'

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec --user 0 test_busybox true
	[ "$status" -eq 0 ]
}
