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

@test "runc run [bind mount dest nested in prior mount via symlink]" {
	# Repro for the K8s service-account token mount failure: a bind mount
	# whose destination resolves (through a symlink in the container image)
	# to a path nested inside the destination of a prior bind mount in the
	# mount list, and which does not exist inside the prior mount's source.
	#
	# This mimics K8s mounting an emptyDir volume at /run and the projected
	# service-account token at /var/run/secrets/kubernetes.io/serviceaccount,
	# on an image where /var/run is a symlink to /run.

	mkdir -p /tmp/busyboxtest/emptydir
	mkdir -p /tmp/busyboxtest/token
	touch /tmp/busyboxtest/token/token-file

	# in container, /var/run -> /run
	mkdir -p rootfs/run
	mkdir -p rootfs/var
	rm -rf rootfs/var/run
	ln -s /run rootfs/var/run

	if [ -z "$SHIFT_ROOTFS_UIDS" ]; then
		chown "$UID_MAP":"$GID_MAP" rootfs/run rootfs/var
		chown -h "$UID_MAP":"$GID_MAP" rootfs/var/run
	fi

	update_config ' .mounts |= . + [{
												 source: "/tmp/busyboxtest/emptydir",
												 destination: "/run",
												 options: ["bind", "rw"]
											 },
											 {
												 source: "/tmp/busyboxtest/token",
												 destination: "/var/run/secrets/kubernetes.io/serviceaccount",
												 options: ["bind", "ro"]
											 }]
						 | .process.args = ["ls", "/run/secrets/kubernetes.io/serviceaccount"]'

	runc run test_busybox
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ 'token-file' ]]

	rm -rf /tmp/busyboxtest
}

@test "runc run [bind mount dest inside prior mount via symlink under it]" {
	# Mirror image of the previous test: here the symlink is *inside* the
	# prior mount's destination (image symlink /run/shm -> /dev/shm, as
	# shipped by older Ubuntu images). The mount at /run/shm/foo must land
	# on top of the /run mount (matching inline, in-order mounting), not at
	# /dev/shm/foo where the image symlink (about to be shadowed by the
	# /run mount) points before the mounts are performed.

	mkdir -p /tmp/busyboxtest/emptydir
	mkdir -p /tmp/busyboxtest/vol
	touch /tmp/busyboxtest/vol/vol-file

	# in container image, /run/shm -> /dev/shm
	mkdir -p rootfs/run
	rm -rf rootfs/run/shm
	ln -s /dev/shm rootfs/run/shm

	if [ -z "$SHIFT_ROOTFS_UIDS" ]; then
		chown "$UID_MAP":"$GID_MAP" rootfs/run
		chown -h "$UID_MAP":"$GID_MAP" rootfs/run/shm
	fi

	update_config ' .mounts |= . + [{
												 source: "/tmp/busyboxtest/emptydir",
												 destination: "/run",
												 options: ["bind", "rw"]
											 },
											 {
												 source: "/tmp/busyboxtest/vol",
												 destination: "/run/shm/foo",
												 options: ["bind", "rw"]
											 }]
						 | .process.args = ["sh", "-c", "ls /run/shm/foo && ls /dev/shm/"]'

	runc run test_busybox
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" =~ 'vol-file' ]]

	# The mount must not have leaked to where the image symlink pointed.
	[[ "$output" != *'foo'* ]]

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
