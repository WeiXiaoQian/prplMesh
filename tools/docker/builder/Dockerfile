###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# Copyright (c) 2019 Tomer Eliyahu (Intel)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

ARG image=ubuntu:18.04
FROM $image

# Update Software repository
RUN apt-get update && apt-get install -y \
	curl \
	gcc \
	cmake \
	ninja-build \
	binutils \
	git \
	autoconf \
	autogen \
	libtool \
	pkg-config \
	libreadline-dev \
	libncurses-dev \
	libssl-dev \
	libjson-c-dev \
	libnl-genl-3-dev \
	libssl-dev \
	libzmq3-dev \
	python \
	python-yaml \
	python3 \
	python3-yaml \
	vim \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["./prplMesh/tools/maptools.py", "build"]
