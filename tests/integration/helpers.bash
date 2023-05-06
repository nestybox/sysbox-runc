#!/bin/bash

# Root directory of integration tests.
INTEGRATION_ROOT=$(dirname "$(readlink -f "$BASH_SOURCE")")

. ${INTEGRATION_ROOT}/multi-arch.bash

RUNC_BUILDROOT=build
RUNC_BUILDDIR=${RUNC_BUILDROOT}/${TARGET_ARCH}
RUNC_TARGET=sysbox-runc

RUNC=${INTEGRATION_ROOT}/../../${RUNC_BUILDDIR}/${RUNC_TARGET}
RUNC_FLAGS="--no-sysbox-mgr --no-sysbox-fs --no-kernel-check"

RECVTTY="${INTEGRATION_ROOT}/../../contrib/cmd/recvtty/recvtty"
GOPATH="$(mktemp -d --tmpdir runc-integration-gopath.XXXXXX)"

# Test data path.
TESTDATA="${INTEGRATION_ROOT}/testdata"

# Work dir
WORK_DIR="/root"
chmod 777 "/root"

# Busybox image
BUSYBOX_IMAGE="$WORK_DIR/busybox.tar"
BUSYBOX_BUNDLE="$WORK_DIR/busyboxtest"

# hello-world in tar format
HELLO_FILE=$(get_hello)
HELLO_IMAGE="$TESTDATA/$HELLO_FILE"
HELLO_BUNDLE="$WORK_DIR/hello-world"

# debian image
DEBIAN_BUNDLE="$BATS_TMPDIR/debiantest"

# CRIU PATH
CRIU="$(which criu 2>/dev/null || true)"

# Kernel version
KERNEL_VERSION="$(uname -r)"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
KERNEL_MINOR="${KERNEL_VERSION#$KERNEL_MAJOR.}"
KERNEL_MINOR="${KERNEL_MINOR%%.*}"

# Root state path.
ROOT=$(mktemp -d "$WORK_DIR/runc.XXXXXX")

# Path to console socket.
CONSOLE_SOCKET="$WORK_DIR/console.sock"

# Check if we're in rootless mode.
ROOTLESS=$(id -u)

# sysbox-runc
UID_MAP=100000
GID_MAP=100000
ID_MAP_SIZE=65536

# Call this from setup() to run a single test
#
# E.g.,
# function setup() {
#    run_only_test "disable_ipv6 lookup"
#    other_setup_actions
# }
#
# or
#
# function setup() {
#    run_only_test_num 2
#    other_setup_actions
# }

run_only_test() {
	if [ "$BATS_TEST_DESCRIPTION" != "$1" ]; then
		skip
	fi
}

run_only_test_num() {
	if [ "$BATS_TEST_NUMBER" -ne "$1" ]; then
		skip
	fi
}

# Wrapper for runc.
function runc() {
	run __runc "$@"

	# Some debug information to make life easier. bats will only print it if the
	# test failed, in which case the output is useful.
	echo "runc $@ (status=$status):" >&2
	echo "$output" >&2
}

# Raw wrapper for runc.
function __runc() {
	"$RUNC" ${RUNC_USE_SYSTEMD+--systemd-cgroup} ${RUNC_FLAGS} --root "$ROOT" "$@"
}

# Wrapper for runc spec, which takes only one argument (the bundle path).
function runc_spec() {
	! [[ "$#" > 1 ]]

	local args=()
	local bundle=""

	if [ "$ROOTLESS" -ne 0 ]; then
		args+=("--rootless")
	fi
	if [ "$#" -ne 0 ]; then
		bundle="$1"
		args+=("--bundle" "$bundle")
	fi

	# sysbox-runc: sys container spec takes id mappings
	$RUNC spec "${args[@]}" --id-map "$UID_MAP $GID_MAP $ID_MAP_SIZE"

	# Always add additional mappings if we have idmaps.
	if [[ "$ROOTLESS" -ne 0 ]] && [[ "$ROOTLESS_FEATURES" == *"idmap"* ]]; then
		runc_rootless_idmap "$bundle"
	fi

	# Ensure config.json contains linux.resources
	if [[ "$ROOTLESS" -ne 0 ]] && [[ "$ROOTLESS_FEATURES" == *"cgroup"* ]]; then
		runc_rootless_cgroup "$bundle"
	fi
}

# Helper function to reformat config.json file. Input uses jq syntax.
function update_config() {
	bundle="${2:-.}"
	jq "$1" "$bundle/config.json" | awk 'BEGIN{RS="";getline<"-";print>ARGV[1]}' "$bundle/config.json"
}

# Shortcut to add additional uids and gids, based on the values set as part of
# a rootless configuration.
function runc_rootless_idmap() {
	bundle="${1:-.}"
	update_config ' .mounts |= map((select(.type == "devpts") | .options += ["gid=5"]) // .)
			| .linux.uidMappings += [{"hostID": '"$ROOTLESS_UIDMAP_START"', "containerID": 1000, "size": '"$ROOTLESS_UIDMAP_LENGTH"'}]
			| .linux.gidMappings += [{"hostID": '"$ROOTLESS_GIDMAP_START"', "containerID": 100, "size": 1}]
			| .linux.gidMappings += [{"hostID": '"$(($ROOTLESS_GIDMAP_START + 10))"', "containerID": 1, "size": 20}]
			| .linux.gidMappings += [{"hostID": '"$(($ROOTLESS_GIDMAP_START + 100))"', "containerID": 1000, "size": '"$(($ROOTLESS_GIDMAP_LENGTH - 1000))"'}]' $bundle
}

# Shortcut to add empty resources as part of a rootless configuration.
function runc_rootless_cgroup() {
	bundle="${1:-.}"
	update_config '.linux.resources += {"memory":{},"cpu":{},"blockio":{},"pids":{}}' $bundle
}

# Returns systemd version as a number (-1 if systemd is not enabled/supported).
function systemd_version() {
	if [ -n "${RUNC_USE_SYSTEMD}" ]; then
		systemctl --version | awk '/^systemd / {print $2; exit}'
		return
	fi

	echo "-1"
}

function init_cgroup_paths() {
	# init once
	test -n "$CGROUP_UNIFIED" && return

	if [ -n "${RUNC_USE_SYSTEMD}" ]; then
		SD_UNIT_NAME="runc-cgroups-integration-test.scope"
		if [ $(id -u) = "0" ]; then
			REL_CGROUPS_PATH="/machine.slice/$SD_UNIT_NAME"
			OCI_CGROUPS_PATH="machine.slice:runc-cgroups:integration-test"
		else
			REL_CGROUPS_PATH="/user.slice/user-$(id -u).slice/user@$(id -u).service/machine.slice/$SD_UNIT_NAME"
			# OCI path doesn't contain "/user.slice/user-$(id -u).slice/user@$(id -u).service/" prefix
			OCI_CGROUPS_PATH="machine.slice:runc-cgroups:integration-test"
		fi
	else
		REL_CGROUPS_PATH="/runc-cgroups-integration-test/test-cgroup/"
		OCI_CGROUPS_PATH=$REL_CGROUPS_PATH
	fi

	if stat -f -c %t /sys/fs/cgroup | grep -qFw 63677270; then
		CGROUP_UNIFIED=yes
		# "pseudo" controllers do not appear in /sys/fs/cgroup/cgroup.controllers.
		# - devices (since kernel 4.15) we must assume to be supported because
		#   it's quite hard to test.
		# - freezer (since kernel 5.2) we can auto-detect by looking for the
		#   "cgroup.freeze" file a *non-root* cgroup.
		CGROUP_SUBSYSTEMS=$(
			cat /sys/fs/cgroup/cgroup.controllers
			echo devices
		)
		CGROUP_BASE_PATH=/sys/fs/cgroup
		CGROUP_PATH=${CGROUP_BASE_PATH}${REL_CGROUPS_PATH}

		# Find any cgroup.freeze files...
		if [ -n "$(find "$CGROUP_BASE_PATH" -type f -name "cgroup.freeze" -print -quit)" ]; then
			CGROUP_SUBSYSTEMS+=" freezer"
		fi
	else
		CGROUP_UNIFIED=no
		CGROUP_SUBSYSTEMS=$(awk '!/^#/ {print $1}' /proc/cgroups)
		for g in ${CGROUP_SUBSYSTEMS}; do
			base_path=$(gawk '$(NF-2) == "cgroup" && $NF ~ /\<'${g}'\>/ { print $5; exit }' /proc/self/mountinfo)
			test -z "$base_path" && continue
			eval CGROUP_${g^^}_BASE_PATH="${base_path}"
			eval CGROUP_${g^^}="${base_path}${REL_CGROUPS_PATH}"
		done
	fi
}

# Helper function to set cgroupsPath to the value of $OCI_CGROUPS_PATH
function set_cgroups_path() {
	bundle="${1:-.}"
	init_cgroup_paths
	update_config '.linux.cgroupsPath |= "'"${OCI_CGROUPS_PATH}"'"' $bundle
}

# Helper to check a value in cgroups.
function check_cgroup_value() {
	source=$1
	expected=$2

	if [ "x$CGROUP_UNIFIED" = "xyes" ]; then
		cgroup=$CGROUP_PATH
	else
		ctrl=${source%%.*}
		eval cgroup=\$CGROUP_${ctrl^^}
	fi

	current=$(cat $cgroup/$source)
	echo $cgroup/$source
	echo "current" $current "!?" "$expected"
	[ "$current" = "$expected" ]
}

# Helper to check a value in systemd.
function check_systemd_value() {
	[ -z "${RUNC_USE_SYSTEMD}" ] && return
	local source=$1
	[ "$source" = "unsupported" ] && return
	local expected="$2"
	local expected2="$3"
	local user=""
	[ $(id -u) != "0" ] && user="--user"

	current=$(systemctl show $user --property $source $SD_UNIT_NAME | awk -F= '{print $2}')
	echo "systemd $source: current $current !? $expected $expected2"
	[ "$current" = "$expected" ] || [ -n "$expected2" -a "$current" = "$expected2" ]
}

function check_cpu_quota() {
	local quota=$1
	local period=$2
	local sd_quota=$3

	if [ "$CGROUP_UNIFIED" = "yes" ]; then
		if [ "$quota" = "-1" ]; then
			quota="max"
		fi
		check_cgroup_value "cpu.max" "$quota $period"
	else
		check_cgroup_value "cpu.cfs_quota_us" $quota
		check_cgroup_value "cpu.cfs_period_us" "$period"
	fi
	# systemd values are the same for v1 and v2
	check_systemd_value "CPUQuotaPerSecUSec" "$sd_quota"

	# CPUQuotaPeriodUSec requires systemd >= v242
	[ "$(systemd_version)" -lt 242 ] && return

	local sd_period=$((period / 1000))ms
	[ "$sd_period" = "1000ms" ] && sd_period="1s"
	local sd_infinity=""
	# 100ms is the default value, and if not set, shown as infinity
	[ "$sd_period" = "100ms" ] && sd_infinity="infinity"
	check_systemd_value "CPUQuotaPeriodUSec" $sd_period $sd_infinity
}

# Works for cgroup v1 and v2, accepts v1 shares as an argument.
function check_cpu_shares() {
	local shares=$1

	if [ "$CGROUP_UNIFIED" = "yes" ]; then
		local weight=$((1 + ((shares - 2) * 9999) / 262142))
		check_cpu_weight "$weight"
	else
		check_cgroup_value "cpu.shares" "$shares"
		check_systemd_value "CPUShares" "$shares"
	fi
}

# Works only for cgroup v2, accept v2 weight.
function check_cpu_weight() {
	local weight=$1

	check_cgroup_value "cpu.weight" $weight
	check_systemd_value "CPUWeight" $weight
}

# Helper function to set a resources limit
function set_resources_limit() {
	bundle="${1:-.}"
	update_config '.linux.resources.pids.limit |= 100' $bundle
}

# Helper function to make /sys/fs/cgroup writable
function set_cgroup_mount_writable() {
	bundle="${1:-.}"
	update_config '.mounts |= map((select(.type == "cgroup") | .options -= ["ro"]) // .)' \
		$bundle
}

# Fails the current test, providing the error given.
function fail() {
	echo "$@" >&2
	exit 1
}

# Allows a test to specify what things it requires. If the environment can't
# support it, the test is skipped with a message.
function requires() {
	for var in "$@"; do
		local skip_me
		case $var in
		criu)
			if [ ! -e "$CRIU" ]; then
				skip_me=1
			fi
			;;
		root)
			if [ "$ROOTLESS" -ne 0 ]; then
				skip_me=1
			fi
			;;
		rootless)
			if [ "$ROOTLESS" -eq 0 ]; then
				skip_me=1
			fi
			;;
		rootless_idmap)
			if [[ "$ROOTLESS_FEATURES" != *"idmap"* ]]; then
				skip_me=1
			fi
			;;
		rootless_cgroup)
			if [[ "$ROOTLESS_FEATURES" != *"cgroup"* ]]; then
				skip_me=1
			fi
			;;
		rootless_no_cgroup)
			if [[ "$ROOTLESS_FEATURES" == *"cgroup"* ]]; then
				skip_me=1
			fi
			;;
		rootless_no_features)
			if [ "$ROOTLESS_FEATURES" != "" ]; then
				skip_me=1
			fi
			;;
		cgroups_freezer)
			init_cgroup_paths
			if [[ "$CGROUP_SUBSYSTEMS" != *"freezer"* ]]; then
				skip_me=1
			fi
			;;
		cgroups_rt)
			init_cgroup_paths
			if [ ! -e "${CGROUP_CPU_BASE_PATH}/cpu.rt_period_us" ]; then
				skip_me=1
			fi
			;;
		cgroups_swap)
			init_cgroup_paths
			if [ $CGROUP_UNIFIED = "no" -a ! -e "${CGROUP_MEMORY_BASE_PATH}/memory.memsw.limit_in_bytes" ]; then
				skip_me=1
			fi
			;;
		cgroupns)
			if [ ! -e "/proc/self/ns/cgroup" ]; then
				skip_me=1
			fi
			;;
		cgroups_v1)
			init_cgroup_paths
			if [ "$CGROUP_UNIFIED" != "no" ]; then
				skip_me=1
			fi
			;;
		cgroups_v2)
			init_cgroup_paths
			if [ "$CGROUP_UNIFIED" != "yes" ]; then
				skip_me=1
			fi
			;;
		smp)
			local cpu_count=$(grep -c '^processor' /proc/cpuinfo)
			if [ "$cpu_count" -lt 2 ]; then
				skip_me=1
			fi
			;;
		systemd)
			if [ -z "${RUNC_USE_SYSTEMD}" ]; then
				skip_me=1
			fi
			;;
		no_systemd)
			if [ -n "${RUNC_USE_SYSTEMD}" ]; then
				skip_me=1
			fi
			;;
		*)
			fail "BUG: Invalid requires $var."
			;;
		esac
		if [ -n "$skip_me" ]; then
			skip "test requires $var"
		fi
	done
}

# Retry a command $1 times until it succeeds. Wait $2 seconds between retries.
function retry() {
	local attempts=$1
	shift
	local delay=$1
	shift
	local i

	for ((i = 0; i < attempts; i++)); do
		run "$@"
		if [[ "$status" -eq 0 ]]; then
			return 0
		fi
		sleep $delay
	done

	echo "Command \"$@\" failed $attempts times. Output: $output"
	false
}

# retry until the given container has state
function wait_for_container() {
	local attempts=$1
	local delay=$2
	local cid=$3
	# optionally wait for a specific status
	local wait_for_status="${4:-}"
	local i

	for ((i = 0; i < attempts; i++)); do
		runc state $cid
		if [[ "$status" -eq 0 ]]; then
			if [[ "${output}" == *"${wait_for_status}"* ]]; then
				return 0
			fi
		fi
		sleep $delay
	done

	echo "runc state failed to return state $statecheck $attempts times. Output: $output"
	false
}

# retry until the given container has state
function wait_for_container_inroot() {
	local attempts=$1
	local delay=$2
	local cid=$3
	# optionally wait for a specific status
	local wait_for_status="${4:-}"
	local i

	for ((i = 0; i < attempts; i++)); do
		ROOT=$4 runc state $cid
		if [[ "$status" -eq 0 ]]; then
			if [[ "${output}" == *"${wait_for_status}"* ]]; then
				return 0
			fi
		fi
		sleep $delay
	done

	echo "runc state failed to return state $statecheck $attempts times. Output: $output"
	false
}

function testcontainer() {
	# test state of container
	runc state $1
	if [ $2 == "checkpointed" ]; then
		[ "$status" -eq 1 ]
		return
	fi
	[ "$status" -eq 0 ]
	[[ "${output}" == *"$2"* ]]
}

function setup_recvtty() {
	# We need to start recvtty in the background, so we double fork in the shell.
	("$RECVTTY" --pid-file "$WORK_DIR/recvtty.pid" --mode null "$CONSOLE_SOCKET" &) &
}

function teardown_recvtty() {
	# When we kill recvtty, the container will also be killed.
	if [ -f "$WORK_DIR/recvtty.pid" ]; then
		kill -9 $(cat "$WORK_DIR/recvtty.pid")
	fi

	# Clean up the files that might be left over.
	rm -f "$WORK_DIR/recvtty.pid"
	rm -f "$CONSOLE_SOCKET"
}

function setup_busybox() {
	setup_recvtty
	mkdir -p "$BUSYBOX_BUNDLE"/rootfs

	if [ -e "/testdata/busybox.tar" ]; then
		BUSYBOX_IMAGE="/testdata/busybox.tar"
	fi
	if [ ! -e $BUSYBOX_IMAGE ]; then
		curl -o $BUSYBOX_IMAGE -sSL $(get_busybox)
	fi
	tar --exclude './dev/*' -C "$BUSYBOX_BUNDLE"/rootfs -xf "$BUSYBOX_IMAGE"

	# sysbox-runc: set bundle ownership to match system
	# container's uid/gid map, except if using uid-shifting
	if [ -z "$SHIFT_ROOTFS_UIDS" ]; then
		chown -R "$UID_MAP":"$GID_MAP" "$BUSYBOX_BUNDLE"
	fi

	cd "$BUSYBOX_BUNDLE"

	runc_spec
}

function setup_hello() {
	setup_recvtty

	mkdir -p "$HELLO_BUNDLE"/rootfs
	tar --exclude './dev/*' -C "$HELLO_BUNDLE"/rootfs -xf "$HELLO_IMAGE"

	# sysbox-runc: set bundle ownership to match system
	# container's uid/gid map, except if using uid-shifting
	if [ -z "$SHIFT_ROOTFS_UIDS" ]; then
		chown -R "$UID_MAP":"$GID_MAP" "$HELLO_BUNDLE"
	fi

	cd "$HELLO_BUNDLE"
	runc_spec
	update_config '(.. | select(.? == "sh")) |= "/hello"'
}

function setup_debian() {
	# skopeo and umoci are not installed on the travis runner
	if [ -n "${RUNC_USE_SYSTEMD}" ]; then
		return
	fi

	setup_recvtty
	mkdir -p "$DEBIAN_BUNDLE"

	if [ ! -d "$DEBIAN_ROOTFS/rootfs" ]; then
		get_and_extract_debian "$DEBIAN_BUNDLE"
	fi

	# Use the cached version
	if [ ! -d "$DEBIAN_BUNDLE/rootfs" ]; then
		cp -r "$DEBIAN_ROOTFS"/* "$DEBIAN_BUNDLE/"
	fi

	cd "$DEBIAN_BUNDLE"
}

function teardown_running_container() {
	__runc delete -f "$1"
}

function teardown_running_container_inroot() {
	ROOT="$2" __runc delete -f "$1"
}

function teardown_busybox() {
	cd "$INTEGRATION_ROOT"
	teardown_recvtty
	teardown_running_container test_busybox
	rm -f -r "$BUSYBOX_BUNDLE"
}

function teardown_hello() {
	cd "$INTEGRATION_ROOT"
	teardown_recvtty
	teardown_running_container test_hello
	rm -f -r "$HELLO_BUNDLE"
}

function teardown_debian() {
	cd "$INTEGRATION_ROOT"
	teardown_recvtty
	teardown_running_container test_debian
	rm -f -r "$DEBIAN_BUNDLE"
}
