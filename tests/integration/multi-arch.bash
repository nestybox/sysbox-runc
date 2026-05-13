#!/bin/bash
get_busybox() {
	case $(go env GOARCH) in
	arm64)
		echo 'https://github.com/docker-library/busybox/raw/8141f5b047a1fbeefd842388244c045825a61c90/latest/glibc/arm64v8/rootfs.tar.gz'
		;;
	*)
		echo 'https://github.com/docker-library/busybox/raw/9c2d0c6fbaaf2ca1b4c19027fa515d9e797e7199/latest/glibc/amd64/rootfs.tar.gz'
		;;
	esac
}

get_hello() {
	case $(go env GOARCH) in
	arm64)
		echo 'hello-world-aarch64.tar'
		;;
	*)
		echo 'hello-world.tar'
		;;
	esac
}

get_and_extract_debian() {
	tmp=$(mktemp -d)
	cd "$tmp"

	debian="debian:3.11.6"

	case $(go env GOARCH) in
	arm64)
		skopeo copy docker://arm64v8/debian:buster "oci:$debian"
		;;
	*)
		skopeo copy docker://amd64/debian:buster "oci:$debian"
		;;
	esac

	args="$([ -z "${ROOTLESS_TESTPATH+x}" ] && echo "--rootless")"
	umoci unpack $args --image "$debian" "$1"

	cd -
	rm -rf "$tmp"
}
