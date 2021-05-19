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
	if [ -z "$SHIFT_ROOTFS_UIDS" ]; then
		uid=$((UID_MAP + 42))
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

# Verify a cwd owned by the container user can be chdir'd to,
# even if runc doesn't have the privilege to do so.
@test "runc create sets up user before chdir to cwd" {
	requires rootless rootless_idmap

	# Some setup for this test (AUX_DIR and AUX_UID) is done
	# by rootless.sh. Check that setup is done...
	if [[ ! -d "$AUX_DIR" || -z "$AUX_UID" ]]; then
		skip "bad/unset AUX_DIR/AUX_UID"
	fi
	# ... and is correct, i.e. the current user
	# does not have permission to access AUX_DIR.
	if ls -l "$AUX_DIR" 2>/dev/null; then
		skip "bad AUX_DIR permissions"
	fi

	update_config '   .mounts += [{
				source: "'"$AUX_DIR"'",
				destination: "'"$AUX_DIR"'",
				options: ["bind"]
			    }]
			| .process.user.uid = '"$AUX_UID"'
			| .process.cwd = "'"$AUX_DIR"'"
			| .process.args |= ["ls", "'"$AUX_DIR"'"]'

	runc run test_busybox
	[ "$status" -eq 0 ]
}
