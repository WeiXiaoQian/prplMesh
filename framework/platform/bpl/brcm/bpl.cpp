/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "../bpl.h"

#include <easylogging/easylogging++.h>

// Use easylogging++ instance of the main application
SHARE_EASYLOGGINGPP(el::Helpers::storage())

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

int bpl_init()
{
    // Do nothing
    return 0;
}

void bpl_close()
{
    // Do nothing
}
