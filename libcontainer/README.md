# sysvisor-runc libcontainer

The sysvisor-runc libcontainer is a fork of the OCI runc libcontainer
library. It has been modified (minimally and only when absolutely
required) to support creation and management of system containers.

The OCI runc libcontainer provides a native Go implementation for
creating containers with namespaces, cgroups, capabilities, and
filesystem access controls.  It allows you to manage the lifecycle of
the container performing additional operations after the container is
created.
