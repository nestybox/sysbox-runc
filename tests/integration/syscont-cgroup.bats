#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
}

# Verify the cgroup mounts inside the sys container
@test "syscont: cgroup mounts" {
	runc run -d --console-socket $CONSOLE_SOCKET test_busybox
	[ "$status" -eq 0 ]

	# verify /sys/fs/cgroup has root:root ownership
	#
	# (dev note: single quotes in a single-quote delimited script is '\'' ; use
	# 'echo' instead of 'sh -c' to see shell interpretation)

	runc exec test_busybox sh -c 'ls -l /sys/fs/cgroup/ | grep -v rdma | awk '\''{print $3}'\'' | tr '\''\n'\'' '\'' '\'' '
	[ "$status" -eq 0 ]

	for i in ${lines[0]}; do
		[ "$i" == "root" ]
	done

	runc exec test_busybox sh -c 'ls -l /sys/fs/cgroup/ | grep -v rdma | awk '\''{print $4}'\'' | tr '\''\n'\'' '\'' '\'' '
	[ "$status" -eq 0 ]

	for i in ${lines[0]}; do
		[ "$i" == "root" ]
	done

	# verify sys container cgroup root in /proc/$$/cgroup is "/"
	runc exec test_busybox sh -c 'cat /proc/1/cgroup | cut -d":" -f3 | tr '\''\n'\'' '\'' '\'' '
	[ "$status" -eq 0 ]

	for i in ${lines[0]}; do
		[ "$i" == "/" ]
	done

	# verify sys container cgroup root in /proc/$$/mountinfo
	runc exec test_busybox sh -c 'cat /proc/1/mountinfo | grep "/sys/fs/cgroup/" | cut -d" " -f4 | tr '\''\n'\'' '\'' '\'' '
	[ "$status" -eq 0 ]

	for i in ${lines[0]}; do
		[ "$i" == "/" ]
	done

	# verify cgroup is mounted read-write
	runc exec test_busybox sh -c 'cat /proc/1/mountinfo | grep "cgroup" | cut -d" " -f6 | tr '\''\n'\'' '\'' '\'' '
	[ "$status" -eq 0 ]

	for i in ${lines[0]}; do
		[[ "$i" =~ "rw," ]]
	done
}

# Verify that sys container root can create cgroups
@test "syscont: cgroup create" {
	runc run -d --console-socket $CONSOLE_SOCKET test_busybox
	[ "$status" -eq 0 ]

	cgList=$(runc exec test_busybox ls /sys/fs/cgroup)
	for cg in $cgList; do
		runc exec test_busybox mkdir /sys/fs/cgroup/$cg/subCgroup
		[ "$status" -eq 0 ]

		runc exec test_busybox ls /sys/fs/cgroup/$cg/subCgroup/cgroup.procs
		[ "$status" -eq 0 ]

		runc exec test_busybox rmdir /sys/fs/cgroup/$cg/subCgroup
		[ "$status" -eq 0 ]
	done
}
