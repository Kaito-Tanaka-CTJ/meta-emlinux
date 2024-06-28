#
# EMLinux distro common file
#
# Copyright (c) Cybertrust Japan Co., Ltd. 
#
# Authors:
#  Masami Ichikawa <masami.ichikawa@miraclelinux.com>
#
# SPDX-License-Identifier: MIT
#

require include/security_flags.inc

INHERIT += "sdk-installer"

DISTRO_KERNELS ?= "linux-cip"
KERNEL_NAME ?= "cip"

DISTRO_APT_SOURCES = "conf/distro/emlinux-bookworm.list"

IMAGER_INSTALL:wic = "parted \
  gdisk \
  util-linux \
  dosfstools \
  mtools \
  e2fsprogs \
  python3-distutils \
  bmap-tools \
  tar \
  fdisk"

WKS_FILE ?= "${MACHINE}.wks"

SDK_PREINSTALL += " \
    linux-headers-${KERNEL_NAME} \
    bc \
"