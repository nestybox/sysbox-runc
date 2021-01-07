#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_busybox
}

@test "syscont: default oom_score_adj" {

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	# verify default setting
	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "0" ]]

	# verify min setting
	runc exec test_busybox sh -c "echo -999 > /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "-999" ]]

	# verify max setting
	runc exec test_busybox sh -c "echo 999 > /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "999" ]]

	# verify -1000 (unkillable) not allowed
	runc exec test_busybox sh -c "echo -1000 > /proc/1/oom_score_adj"
	[ "$status" -eq 1 ]

}

@test "syscont: custom oom_score_adj" {

	CONFIG=$(jq '.process.oomScoreAdj = 100' config.json)
	echo "${CONFIG}" >config.json

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	# verify default setting
	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "100" ]]

	# verify min setting
	runc exec test_busybox sh -c "echo -999 > /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "-999" ]]

	# verify max setting
	runc exec test_busybox sh -c "echo 999 > /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "999" ]]

	# verify -1000 (unkillable) not allowed
	runc exec test_busybox sh -c "echo -1000 > /proc/1/oom_score_adj"
	[ "$status" -eq 1 ]

}

@test "syscont: oom_score_adj inherit" {

	# adjust test's OOM score
	echo 200 >/proc/self/oom_score_adj

	# sys container should inherit test's OOM score
	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "200" ]]

	# verify min setting
	runc exec test_busybox sh -c "echo -999 > /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "-999" ]]

	# verify max setting
	runc exec test_busybox sh -c "echo 999 > /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]

	runc exec test_busybox sh -c "cat /proc/1/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "999" ]]

	# verify -1000 (unkillable) not allowed
	runc exec test_busybox sh -c "echo -1000 > /proc/1/oom_score_adj"
	[ "$status" -eq 1 ]

}

@test "syscont: exec oom_score_adj" {

	CONFIG=$(jq '.process.oomScoreAdj = 300' config.json)
	echo "${CONFIG}" >config.json

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	# exec process inherits container's configure oom score adjustment
	runc exec test_busybox sh -c "cat /proc/self/oom_score_adj"
	[ "$status" -eq 0 ]
	[[ "$output" == "300" ]]
}
