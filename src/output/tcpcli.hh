/*
 * Copyright (c) 2018, OARC, Inc.
 * All rights reserved.
 *
 * This file is part of dnsjit.
 *
 * dnsjit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dnsjit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.
 */

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")
//lua:require("dnsjit.core.producer_h")
//lua:require("dnsjit.core.object.payload_h")
//lua:require("dnsjit.core.timespec_h")

typedef struct output_tcpcli {
    core_log_t _log;
    size_t     pkts, errs;
    int        fd, nonblocking;

    uint8_t               recvbuf[64 * 1024];
    core_object_payload_t pkt;
    uint16_t              dnslen;
    uint8_t               have_dnslen, have_pkt;
    size_t                recv, pkts_recv;

    core_timespec_t timeout;
} output_tcpcli_t;

core_log_t* output_tcpcli_log();

void output_tcpcli_init(output_tcpcli_t* self);
void output_tcpcli_destroy(output_tcpcli_t* self);
int output_tcpcli_connect(output_tcpcli_t* self, const char* host, const char* port);
int output_tcpcli_nonblocking(output_tcpcli_t* self);
int output_tcpcli_set_nonblocking(output_tcpcli_t* self, int nonblocking);
ssize_t output_tcpcli_send(output_tcpcli_t* self, const core_object_t* obj, size_t sent);

core_receiver_t output_tcpcli_receiver(output_tcpcli_t* self);
core_producer_t output_tcpcli_producer(output_tcpcli_t* self);
