#!/usr/bin/env bats

load helpers

function setup_busybox_tmpfs() {

	mkdir -p /tmp/busyboxtest/rootfs
	mount -t tmpfs tmpfs /tmp/busyboxtest/rootfs

	tar --exclude './dev/*' -C /tmp/busyboxtest/rootfs -xf "$BUSYBOX_IMAGE"

	# sysbox-runc: set bundle ownership to match system
	# container's uid(gid) map, except if using uid-shifting
	if [ -z "$SHIFT_UIDS" ]; then
		chown -R "$UID_MAP":"$GID_MAP" /tmp/busyboxtest
	fi

	cd /tmp/busyboxtest
	runc_spec
}

function cleanup_busybox_tmpfs() {
	cd
	teardown_running_container "$1"

	run sh -c 'findmnt -o TARGET | grep /tmp/busyboxtest/rootfs'
	if [ "$status" -eq 0 ]; then
		umount /tmp/busyboxtest/rootfs
	fi

	rm -rf /tmp/busyboxtest
}

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
}

@test "runc run [bind mount]" {
	mkdir -p /mnt/test-dir
	touch /mnt/test-dir/test-file

	update_config ' .mounts |= . + [{
												 source: "/mnt/test-dir",
												 destination: "/mnt/test-dir",
												 options: ["bind"]
											 }]
						 | .process.args = ["ls", "/mnt/test-dir/"]'

	runc run test_busybox
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ 'test-file' ]]

	rm -rf /mnt/test-dir
}

@test "runc run [ro tmpfs mount]" {
	update_config ' .mounts += [{
											source: "tmpfs",
											destination: "/mnt",
											type: "tmpfs",
											options: ["ro", "nodev", "nosuid", "mode=755"]
										}]
						  | .process.args |= ["grep", "^tmpfs /mnt", "/proc/mounts"]'

	runc run test_busybox
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" == *'ro,'* ]]
}

@test "runc runc [bind mount above rootfs]" {

	# test: bind mount source path is above but not directly above rootfs
	run mkdir bindSrc
	[ "$status" -eq 0 ]

	run touch bindSrc/test-file
	[ "$status" -eq 0 ]

	update_config ' .mounts |= . + [{
												 source: "bindSrc",
												 destination: "/tmp/bind",
												 options: ["bind"]
											  }]
						 | .process.args = ["ls", "/tmp/bind/"]'

	runc run test_busybox
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ 'test-file' ]]
}

@test "runc run [bind mount directly above rootfs]" {

	update_config ' .mounts |= . + [{
												 source: ".",
												 destination: "/tmp/bind",
												 options: ["bind"]
											  }]
						 | .process.args = ["ls", "/tmp/bind/"]'

	runc run test_busybox

	if [ -z "$SHIFT_UIDS" ]; then
		[ "$status" -eq 0 ]
		[[ "${lines[0]}" =~ config.json ]]
	else
		[ "$status" -eq 1 ]
	fi
}

@test "runc run [bind mount below the rootfs]" {

	update_config ' .mounts |= . + [{
												 source: "rootfs/root",
												 destination: "/tmp/bind",
												 options: ["bind"]
											 }]
						 | .process.args = ["/bin/sh"]'

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox touch /root/test-file.txt
	[ "$status" -eq 0 ]

	runc exec test_busybox ls /root
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ test-file.txt ]]

	runc exec test_busybox ls /tmp/bind
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ test-file.txt ]]

	runc exec test_busybox rm /tmp/bind/test-file.txt
	[ "$status" -eq 0 ]

	runc exec test_busybox ls /root
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ '' ]]
}

@test "runc run [rootfs on tmpfs]" {
	setup_busybox_tmpfs

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc kill test_busybox
	[ "$status" -eq 0 ]

	cleanup_busybox_tmpfs test_busybox
}

@test "runc run [bind mount on tmpfs]" {
	mkdir -p /tmp/busyboxtest/test-dir
	mount -t tmpfs tmpfs /tmp/busyboxtest/test-dir
	touch /tmp/busyboxtest/test-dir/test-file

	update_config ' .mounts |= . + [{
												 source: "/tmp/busyboxtest/test-dir",
												 destination: "/tmp/bind",
												 options: ["bind"]
											 }]
						 | .process.args = ["ls", "/tmp/bind"]'

	runc run test_busybox
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ 'test-file' ]]

	umount /tmp/busyboxtest/test-dir
	[ "$status" -eq 0 ]

	rm -rf /tmp/busyboxtest
}
