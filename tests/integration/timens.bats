#!/usr/bin/env bats
# Tests for time namespace support (CLONE_NEWTIME, Linux 5.6+).
# Ported from opencontainers/runc tests/integration/timens.bats.

load helpers

function setup() {
	setup_busybox
}

function teardown() {
	teardown_busybox
}

# Specifying time offsets without a time namespace must fail.
@test "runc run [timens offsets with no timens]" {
	requires timens

	update_config '.process.args = ["cat", "/proc/self/timens_offsets"]'
	update_config '.linux.namespaces = (.linux.namespaces | map(select(.type != "time")))'
	update_config '.linux.timeOffsets = {
			"monotonic": { "secs": 7881, "nanosecs": 2718281 },
			"boottime":  { "secs": 1337, "nanosecs": 3141519 }
		}'

	runc run --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -ne 0 ]
}

# A time namespace with no offsets should show zeros in timens_offsets.
@test "runc run [timens with no offsets]" {
	requires timens

	update_config '.process.args = ["sleep", "inf"]'
	update_config '.linux.namespaces += [{"type": "time"}]
		| .linux.timeOffsets = null'

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox cat /proc/self/timens_offsets
	[ "$status" -eq 0 ]
	grep -E '^monotonic\s+0\s+0$' <<<"$output"
	grep -E '^boottime\s+0\s+0$' <<<"$output"
}

# Basic time namespace with explicit offsets.
@test "runc run [simple timens]" {
	requires timens

	update_config '.process.args = ["sleep", "inf"]'
	update_config '.linux.namespaces += [{"type": "time"}]
		| .linux.timeOffsets = {
			"monotonic": { "secs": 7881, "nanosecs": 2718281 },
			"boottime":  { "secs": 1337, "nanosecs": 3141519 }
		}'

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox cat /proc/self/timens_offsets
	[ "$status" -eq 0 ]
	grep -E '^monotonic\s+7881\s+2718281$' <<<"$output"
	grep -E '^boottime\s+1337\s+3141519$' <<<"$output"
}

# exec into a running container must see the same timens offsets.
@test "runc exec [simple timens]" {
	requires timens

	update_config '.process.args = ["sleep", "inf"]'
	update_config '.linux.namespaces += [{"type": "time"}]
		| .linux.timeOffsets = {
			"monotonic": { "secs": 7881, "nanosecs": 2718281 },
			"boottime":  { "secs": 1337, "nanosecs": 3141519 }
		}'

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox cat /proc/self/timens_offsets
	[ "$status" -eq 0 ]
	grep -E '^monotonic\s+7881\s+2718281$' <<<"$output"
	grep -E '^boottime\s+1337\s+3141519$' <<<"$output"
}
