/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bpl_dhcp.h>

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static bpl_dhcp_mon_cb s_pCallback = NULL;
static int m_fd_ext_events         = -1;

int bpl_dhcp_mon_start(bpl_dhcp_mon_cb cb)
{
#ifdef IN_NONBLOCK
    m_fd_ext_events = inotify_init1(IN_NONBLOCK);
#else
    m_fd_ext_events = inotify_init();
#endif
    if (m_fd_ext_events < 0)
        return -1;

    mkdir(DHCP_EVENT_PATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    inotify_add_watch(m_fd_ext_events, DHCP_EVENT_PATH, (IN_CREATE | IN_DELETE | IN_MODIFY));

    // Store the callback
    s_pCallback = cb;

    return m_fd_ext_events;
}

int bpl_dhcp_mon_handle_event()
{
    const size_t event_size = sizeof(struct inotify_event) + NAME_MAX + 1;
    static char buffer[1024];
    char filename[256] = {'\0'};
    char *arrTok[4]    = {0};
    char *tmpTok, *line = NULL;
    int numTok = 0;
    size_t len = 0;
    FILE *fp;

    int length = read(m_fd_ext_events, buffer, sizeof(buffer));
    if (length < 0)
        return -1;

    sprintf(filename, "%s%s", DHCP_EVENT_PATH, "/EVENT");
    fp = fopen(filename, "rw");
    if (getline(&line, &len, fp) == -1)
        return -1;

    //Parse parameters: <op: {"add","del", "old"}>,<client_mac>,<IP>,<hostname>
    tmpTok = strtok(line, ",");
    while (tmpTok != NULL && numTok < 4) {
        arrTok[numTok++] = tmpTok;
        tmpTok           = strtok(NULL, ",");
    }

    // Execute the callback
    if (s_pCallback)
        s_pCallback((arrTok[0]) ? arrTok[0] : "", (arrTok[1]) ? arrTok[1] : "",
                    (arrTok[2]) ? arrTok[2] : "", (arrTok[3]) ? arrTok[3] : "");

    fclose(fp);
    if (line)
        free(line);
    return 0;
}

int bpl_dhcp_mon_stop() { return 0; }
