# sysvisor-runc

## Introduction

`sysvisor-runc` is a fork of the OCI runc, modified for spawning and running system containers.

`sysvisor-runc` tracks the OCI [runc](https://github.com/opencontainers/runc) repository
as well as the OCI [runtime-spec](https://github.com/opencontainers/runtime-spec)
repository.


## Integration with sysvisor-fs

sysvisor-runc is tightly integrated with sysvisor-fs via
gRPC. sysvisor-runc mounts sysvisor-fs in the system container's root
filesystem as needed to create the system container abstraction.


## Building

`sysvisor-runc` currently supports the Linux platform with various architecture support.
It must be built with Go version 1.6 or higher in order for some features to function properly.

In order to enable seccomp support you will need to install `libseccomp` on your platform.
> e.g. `libseccomp-devel` for CentOS, or `libseccomp-dev` for Ubuntu

Otherwise, if you do not want to build `runc` with seccomp support you can add `BUILDTAGS=""` when running make.

```bash
make
sudo make install
```

`sysvisor-runc` will be installed to `/usr/local/sbin/sysvisor-runc` on your system.


#### Build Tags

`sysvisor-runc` supports optional build tags for compiling support of various features.
To add build tags to the make option the `BUILDTAGS` variable must be set.

```bash
make BUILDTAGS='seccomp apparmor'
```

| Build Tag | Feature                            | Dependency  |
|-----------|------------------------------------|-------------|
| seccomp   | Syscall filtering                  | libseccomp  |
| selinux   | selinux process and mount labeling | <none>      |
| apparmor  | apparmor profile support           | <none>      |
| ambient   | ambient capability support         | kernel 4.3  |
| nokmem    | disable kernel memory account      | <none>      |


### Running the test suite

`sysvisor-runc` currently supports running its test suite via Docker.
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
# make integration TESTPATH="/checkpoint.bats"
```

You can run a test in your proxy environment by setting `DOCKER_BUILD_PROXY` and `DOCKER_RUN_PROXY` variables.

```bash
# make test DOCKER_BUILD_PROXY="--build-arg HTTP_PROXY=http://yourproxy/" DOCKER_RUN_PROXY="-e HTTP_PROXY=http://yourproxy/"
```

### Dependencies Management

`sysvisor-runc` uses [vndr](https://github.com/LK4D4/vndr) for dependencies management.
Please refer to [vndr](https://github.com/LK4D4/vndr) for how to add or update
new dependencies.

## Using sysvisor-runc

### Creating an OCI Bundle

In order to use sysvisor-runc you must have your system container in the format of an OCI bundle.
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
format of a `config.json` file inside your bundle.  `sysvisor-runc` provides a `spec`
command to generate a base template spec that you are then able to edit.  To find features
and documentation for fields in the spec please refer to the
[specs](https://github.com/opencontainers/runtime-spec) repository.

```bash
sysvisor-runc spec
```

### Running System Containers

Assuming you have an OCI bundle from the previous step you can execute the system container in two different ways.

The first way is to use the convenience command `run` that will handle creating, starting, and deleting the container after it exits.

```bash
# run as root
cd /mycontainer
sysvisor-runc run mycontainerid
```

If you used the unmodified `sysvisor-runc spec` template this should give you a `sh` session inside the system container.

The second way to start a container is using the specs lifecycle operations.
This gives you more power over how the container is created and managed while it is running.
This will also launch the system container in the background so you will have to edit the `config.json` to remove the `terminal` setting for the simple examples here.
Your process field in the `config.json` should have `"terminal": false` and `"args": ["sleep", "5"]`.

These are the lifecycle operations in your shell.


```bash
# run as root
cd /mycontainer
sysvisor-runc create mycontainerid

# view the container is created and in the "created" state
sysvisor-runc list

# start the process inside the container
sysvisor-runc start mycontainerid

# after 5 seconds view that the container has exited and is now in the stopped state
sysvisor-runc list

# now delete the container
sysvisor-runc delete mycontainerid
```

This allows higher level systems to augment the containers creation logic with setup of various settings after the container is created and/or before it is deleted. For example, the container's network stack is commonly set up after `create` but before `start`.

#### Supervisors

`sysvisor-runc` can be used with process supervisors and init systems to ensure that containers are restarted when they exit.
An example systemd unit file looks something like this.

```systemd
[Unit]
Description=Start My Container

[Service]
Type=forking
ExecStart=/usr/local/sbin/sysvisor-runc run -d --pid-file /run/mycontainerid.pid mycontainerid
ExecStopPost=/usr/local/sbin/sysvisor-runc delete mycontainerid
WorkingDirectory=/mycontainer
PIDFile=/run/mycontainerid.pid

[Install]
WantedBy=multi-user.target
```
