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

//lua:require("dnsjit.core.object_h")

typedef struct core_object_ieee802 {
    unsigned short        obj_type;
    const core_object_t*  obj_prev;
    core_object_refcall_t obj_ref;
    void*                 obj_refctx;

    uint16_t       tpid;
    unsigned short pcp : 3;
    unsigned short dei : 1;
    unsigned short vid : 12;
    uint16_t       ether_type;
} core_object_ieee802_t;