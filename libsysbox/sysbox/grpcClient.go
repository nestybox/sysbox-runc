package sysbox

import (
	"context"
	"log"
	"time"

	pb "github.com/opencontainers/runc/libsysbox/sysbox_protobuf"
	"google.golang.org/grpc"
)

const sysbox_address = "localhost:50052"

//
// Establishes grpc connection to sysbox-fs' remote-end.
//
func sysboxfs_connect() *grpc.ClientConn {

	// Set up a connection to the server.
	// TODO: Secure me through TLS.
	conn, err := grpc.Dial(sysbox_address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Could not connect to sysboxfs: %v", err)
		return nil
	}

	return conn
}

//
// Registers container creation in sysbox-fs. Notice that this
// is a blocking call that can potentially have a minor impact
// on container's boot-up speed.
//
func SendContainerRegistration(data *pb.ContainerData) bool {

	// Set up sysboxfs pipeline.
	conn := sysboxfs_connect()
	if conn == nil {
		return false
	}
	defer conn.Close()

	cntrChanIntf := pb.NewContainerStateChannelClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := cntrChanIntf.ContainerRegistration(ctx, data)
	if err != nil {
		log.Fatalf("Could not interact with sysboxfs: %v", err)
		return false
	}
	log.Println("Response: ", r.Success)

	return true
}

//
// Unregisters container from sysboxfs.
//
func SendContainerUnregistration(data *pb.ContainerData) bool {

	// Set up sysboxfs pipeline.
	conn := sysboxfs_connect()
	if conn == nil {
		return false
	}
	defer conn.Close()

	cntrChanIntf := pb.NewContainerStateChannelClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Generate a container-unregistration message to sysboxfs
	r, err := cntrChanIntf.ContainerUnregistration(ctx, data)
	if err != nil {
		log.Fatalf("Could not interact with sysboxfs: %v", err)
		return false
	}
	log.Println("Response: ", r.Success)

	return true
}

//
// Sends creation-time attribute to sysbox-fs end.
//
func SendContainerCreationTime(time time.Time) bool {

	// TBD
	return true
}
