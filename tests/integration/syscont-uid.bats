#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
}

@test "syscont uid/gid mappings" {
	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox cat /proc/1/uid_map
	[ "$status" -eq 0 ]

	uid_int=$(echo "${lines[0]}" | awk '{print $1}')
	uid_ext=$(echo "${lines[0]}" | awk '{print $2}')
	uid_size=$(echo "${lines[0]}" | awk '{print $3}')

	[[ "$uid_int" == "0" ]]
	[[ "$uid_ext" == "$UID_MAP" ]]
	[[ "$uid_size" == "$ID_MAP_SIZE" ]]
}
