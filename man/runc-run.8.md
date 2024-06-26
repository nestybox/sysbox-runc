% runc-run "8"

# NAME
   runc run - create and run a container

# SYNOPSIS
   runc run [command options] `<container-id>`

Where "`<container-id>`" is your name for the instance of the container that you
are starting. The name you provide for the container instance must be unique on
your host.

# DESCRIPTION
   The run command creates an instance of a container for a bundle. The bundle
is a directory with a specification file named "config.json" and a root
filesystem.

The specification file includes an args parameter. The args parameter is used
to specify command(s) that get run when the container is started. To change the
command(s) that get executed on start, edit the args parameter of the spec. See
"runc spec --help" for more explanation.

# OPTIONS
    --bundle value, -b value  path to the root of the bundle directory, defaults to the current directory
    --console-socket value    path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal
    --detach, -d              detach from the container's process
    --keep                    keep the container's state directory and cgroup. This can be helpful if a user wants to check the state (e.g., of cgroup controllers) after the container has exited. If this option is used, a manual **runc delete** is needed afterwards to clean the exited container's artifacts.
    --pid-file value          specify the file to write the process id to
    --no-subreaper            disable the use of the subreaper used to reap reparented processes
    --no-pivot                do not use pivot root to jail process inside rootfs.  This should be used whenever the rootfs is on top of a ramdisk
    --no-new-keyring          do not create a new session keyring for the container.  This will cause the container to inherit the calling processes session key
    --preserve-fds value      Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total) (default: 0)
