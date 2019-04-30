# sysbox-runc

## Introduction

`sysbox-runc` is a fork of the OCI runc, modified for spawning and running system containers.

`sysbox-runc` tracks the OCI [runc](https://github.com/opencontainers/runc) repository
as well as the OCI [runtime-spec](https://github.com/opencontainers/runtime-spec)
repository.


## Integration with other Sysvisor components

sysbox-runc is tightly integrated with sysbox-fs and sysbox-mgr via
gRPC. Refer to the sysbox documentation for details.

## Building

`sysbox-runc` currently supports the Linux platform with various architecture support.
It must be built with Go version 1.13 or higher.

In order to enable seccomp support you will need to install `libseccomp` on your platform.
> e.g. `libseccomp-devel` for CentOS, or `libseccomp-dev` for Ubuntu

```bash
make
sudo make install
```

`sysbox-runc` will be installed to `/usr/local/sbin/sysbox-runc` on your system.


#### Build Tags

`sysbox-runc` supports optional build tags for compiling support of various features.
To add build tags to the make option the `BUILDTAGS` variable must be set.

```bash
make BUILDTAGS='seccomp apparmor'
```

| Build Tag | Feature                            | Enabled by default | Dependency |
|-----------|------------------------------------|--------------------|------------|
| seccomp   | Syscall filtering                  | yes                | libseccomp |
| selinux   | selinux process and mount labeling | yes                | <none>     |
| apparmor  | apparmor profile support           | yes                | <none>     |
| nokmem    | disable kernel memory accounting   | no                 | <none>     |


### Running the test suite

`sysbox-runc` currently supports running its test suite via Docker.
To run the suite just type `make test`.

```bash
make test
```

There are additional make targets for running the tests outside of a container but this is
not recommended as the tests are written with the expectation that they can write and
remove anywhere.

You can run a specific test case by setting the `TESTFLAGS` variable.

```bash
# make test TESTFLAGS="-run=SomeTestFunction"
```

You can run a specific integration test by setting the `TESTPATH` variable.

```bash
# make test TESTPATH="/checkpoint.bats"
```

You can run a specific rootless integration test by setting the `ROOTLESS_TESTPATH` variable.

```bash
# make test ROOTLESS_TESTPATH="/checkpoint.bats"
```

You can run a test using your container engine's flags by setting `CONTAINER_ENGINE_BUILD_FLAGS` and `CONTAINER_ENGINE_RUN_FLAGS` variables.

```bash
# make test CONTAINER_ENGINE_BUILD_FLAGS="--build-arg http_proxy=http://yourproxy/" CONTAINER_ENGINE_RUN_FLAGS="-e http_proxy=http://yourproxy/"
```

### Test Shell

You can get a shell in the test container with:

```bash
# make shell
```

To run a specific integration test:

```bash
# bats -t tests/integration/sometest.bats
```

To run a specific unit test, point to the go package and test.

```bash
# go test "-mod=vendor" -timeout 3m -tags "seccomp selinux apparmor"  -v github.com/opencontainers/runc/libcontainer/integration -run TestEnter
```

You can get the list of go packages with:

```bash
# go list ./...
```

The delve debugger is installed in the test container. You can attach it to a sysbox-runc process with:

```bash
# dlv attach <pid>
```

where `<pid>` is the pid of the sysbox-runc process.

### Dependencies Management

`sysbox-runc` uses [Go Modules](https://github.com/golang/go/wiki/Modules) for dependencies management.
Please refer to [Go Modules](https://github.com/golang/go/wiki/Modules) for how to add or update
new dependencies. When updating dependencies, be sure that you are running Go `1.14` or newer.

```
# Update vendored dependencies
make vendor
# Verify all dependencies
make verify-dependencies
```

## Using sysbox-runc

### Creating an OCI Bundle

In order to use sysbox-runc you must have your system container in the format of an OCI bundle.
If you have Docker installed you can use its `export` method to acquire a root filesystem from an existing Docker container.

```bash
# create the top most bundle directory
mkdir /mycontainer
cd /mycontainer

# create the rootfs directory
mkdir rootfs

# export busybox via Docker into the rootfs directory
docker export $(docker create busybox) | tar -C rootfs -xvf -
```

After a root filesystem is populated you just generate a system container spec in the
format of a `config.json` file inside your bundle.  `sysbox-runc` provides a `spec`
command to generate a base template spec that you are then able to edit.  To find features
and documentation for fields in the spec please refer to the
[specs](https://github.com/opencontainers/runtime-spec) repository.

```bash
sysbox-runc spec
```

### Running System Containers

Assuming you have an OCI bundle from the previous step you can execute the system container in two different ways.

The first way is to use the convenience command `run` that will handle creating, starting, and deleting the container after it exits.

```bash
# run as root
cd /mycontainer
sysbox-runc run mycontainerid
```

If you used the unmodified `sysbox-runc spec` template this should give you a `sh` session inside the system container.

The second way to start a container is using the specs lifecycle operations.
This gives you more power over how the container is created and managed while it is running.
This will also launch the system container in the background so you will have to edit the `config.json` to remove the `terminal` setting for the simple examples here.
Your process field in the `config.json` should have `"terminal": false` and `"args": ["sleep", "5"]`.

These are the lifecycle operations in your shell.


```bash
# run as root
cd /mycontainer
sysbox-runc create mycontainerid

# view the container is created and in the "created" state
sysbox-runc list

# start the process inside the container
sysbox-runc start mycontainerid

# after 5 seconds view that the container has exited and is now in the stopped state
sysbox-runc list

# now delete the container
sysbox-runc delete mycontainerid
```

This allows higher level systems to augment the containers creation logic with setup of various settings after the container is created and/or before it is deleted. For example, the container's network stack is commonly set up after `create` but before `start`.

#### Supervisors

`sysbox-runc` can be used with process supervisors and init systems to ensure that containers are restarted when they exit.
An example systemd unit file looks something like this.

```systemd
[Unit]
Description=Start My Container

[Service]
Type=forking
ExecStart=/usr/local/sbin/sysbox-runc run -d --pid-file /run/mycontainerid.pid mycontainerid
ExecStopPost=/usr/local/sbin/sysbox-runc delete mycontainerid
WorkingDirectory=/mycontainer
PIDFile=/run/mycontainerid.pid

[Install]
WantedBy=multi-user.target
```

#### cgroup v2
See [`./docs/cgroup-v2.md`](./docs/cgroup-v2.md).

## License

The code and docs are released under the [Apache 2.0 license](LICENSE).
