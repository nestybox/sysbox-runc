#!/usr/bin/env bats

load helpers

@test "runc version" {
	runc -v
	[ "$status" -eq 0 ]
	[[ ${lines[0]} =~ runc\ version\ [0-9]+\.[0-9]+\.[0-9]+ ]]

        # For sysbox, we use the Git commit of the parent sysbox repo, not the commit of the sysbox-runc repo
	#[[ ${lines[1]} =~ commit:+ ]]

	[[ ${lines[1]} =~ spec:\ [0-9]+\.[0-9]+\.[0-9]+ ]]
}
