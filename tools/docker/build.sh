#!/bin/sh
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# Copyright (c) 2019 Tomer Eliyahu (Intel)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

scriptdir="$(cd "${0%/*}"; pwd)"
topdir="${scriptdir%/*/*/*}"

. ${topdir}/prplMesh/tools/docker/functions.sh

main() {
    docker image inspect prplmesh-builder >/dev/null 2>&1 || {
        echo "Image prplmesh-build does not exist, creating..."
        run ${scriptdir}/image-build.sh
    }

    run docker container run --workdir=$topdir --user=${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)} \
        -e USER=${SUDO_USER:-${USER}} -v ${topdir}:${topdir} \
        --interactive --tty --rm prplmesh-builder $@
}

main $@
