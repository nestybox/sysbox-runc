#!/usr/bin/env bats

load helpers

function setup_busybox_tmpfs() {

	mkdir -p /tmp/busyboxtest/rootfs
	mount -t tmpfs tmpfs /tmp/busyboxtest/rootfs

	tar --exclude './dev/*' -C /tmp/busyboxtest/rootfs -xf "$BUSYBOX_IMAGE"

	# sysbox-runc: set bundle ownership to match system
	# container's uid(gid) map, except if using uid-shifting
	if [ -z "$SHIFT_ROOTFS_UIDS" ]; then
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

	# Bind mounting a dir located directly above container's rootfs into the
	# container leads to shiftfs-on-shiftfs, and this is not allowed by
	# shiftfs. To solve this, the sysbox-mgr marks shiftfs mounts by creating
	# mark points under /var/lib/sysbox, which prevents the shiftfs-on-shiftfs
	# scenario.
	#
	# Thus, this test requires the sysbox-mgr, so we can't run it (since sysbox-mgr
	# is not present in sysbox-runc integration tests).
	#
	# Though sysbox-runc has a mock shiftfs mark code in setupShiftfsMarkLocal()
	# (see container_linux.go), this code does not prevent the shiftfs-on-shiftfs
	# scenario so the test would fail. We can re-enable this test if and when
	# the mock shiftfs mark code handles the shiftfs-on-shiftfs scenario.

	if [ -n "$SHIFT_ROOTFS_UIDS" ]; then
		skip "Requires sysbox-mgr; skip"
	fi

	update_config ' .mounts |= . + [{
												 source: ".",
												 destination: "/tmp/bind",
												 options: ["bind"]
											  }]
						 | .process.args = ["ls", "/tmp/bind/"]'

	runc run test_busybox

	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ config.json ]]
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

@test "runc run [tmpfs mount with absolute symlink]" {
	# in container, /conf -> /real/conf
	mkdir -p rootfs/real/conf

	if [ -z "$SHIFT_ROOTFS_UIDS" ]; then
		chown -R "$UID_MAP":"$GID_MAP" rootfs/real/conf
	fi

	ln -s /real/conf rootfs/conf

	update_config '  .mounts += [{
					type: "tmpfs",
					source: "tmpfs",
					destination: "/conf/stack",
					options: ["ro", "nodev", "nosuid"]
				}]
			| .process.args |= ["true"]'
	runc run test_busybox
	[ "$status" -eq 0 ]
}
