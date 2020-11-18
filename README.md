# sysbox-runc

## Introduction

sysbox-runc is part of [Sysbox](../README.md).

sysbox-runc is the program that does the low level kernel setup for execution of
system containers. It's the "front-end" of Sysbox: higher layers (e.g., Docker &
containerd) invoke sysbox-runc to launch system containers.

sysbox-runc is tightly integrated with sysbox-fs and sysbox-mgr via
gRPC. Refer to the [Sysbox design doc](../docs/user-guide/design.md) for
further info.

sysbox-runc is a fork of the excellent [OCI runc](https://github.com/opencontainers/runc),
modified for running system containers. It was forked in early 2019 and has undergone
significant changes since then.

sysbox-runc is mostly (but not 100%) compatible with the OCI runtime specification (more on this
[here](https://github.com/nestybox/sysbox/blob/master/docs/user-guide/design.md#sysbox-oci-compatibility)).

## Building

sysbox-runc is built as part of the Sysbox build process. Refer to the Sysbox
[developer's guide](../docs/developers-guide.md) for more on this.

### Running the test suite

sysbox-runc is normally tested as part of the [Sysbox test suite](../docs/developers-guide.md#sysbox-testing). That test
suite has Makefile targets to run sysbox-runc unit and integration tests.

Alternatively, you can run the sysbox-runc tests directly as follows:

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

## Using sysbox-runc

See the [Sysbox User Guide](../docs/user-guide/deploy.md) for more info on this.

## Libcontainer

The libcontainer package in sysbox-runc is not meant to be usable as a
standalone library (unlike the libcontainer package in the OCI runc). It has
undergone changes that tie it deeply into sysbox-runc.
