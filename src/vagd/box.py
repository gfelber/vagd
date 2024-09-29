class Box:
  """constants class for recommended images and boxes"""

  QEMU_NOBLE = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
  QEMU_JAMMY = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  QEMU_FOCAL = "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"
  QEMU_BIONIC = "https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img"
  QEMU_UBUNTU = QEMU_NOBLE

  QEMU_NOBLE_ARM = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"
  QEMU_JAMMY_ARM = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img"

  DOCKER_NOBLE = "ubuntu:noble"
  DOCKER_JAMMY = "ubuntu:jammy"
  DOCKER_FOCAL = "ubuntu:focal"
  DOCKER_BIONIC = "ubuntu:bionic"
  DOCKER_XENIAL = "ubuntu:xenial"
  DOCKER_UBUNTU = DOCKER_NOBLE

  DOCKER_I386_FOCAL = "i386/ubuntu:focal"
  DOCKER_I386_BIONIC = "i386/ubuntu:bionic"
  DOCKER_I386_XENIAL = "i386/ubuntu:xenial"

  DOCKER_ALPINE_320 = "alpine:3.20"
  DOCKER_ALPINE = DOCKER_ALPINE_320

  # DEPRECATED
  VAGRANT_JAMMY64 = "ubuntu/jammy64"
  VAGRANT_FOCAL64 = "ubuntu/focal64"
  VAGRANT_BIONIC64 = "ubuntu/bionic64"
  VAGRANT_XENIAL64 = "ubuntu/xenial64"
