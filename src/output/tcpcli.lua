-- Copyright (c) 2018, OARC, Inc.
-- All rights reserved.
--
-- This file is part of dnsjit.
--
-- dnsjit is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- dnsjit is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.

-- dnsjit.output.tcpcli
-- Simple, length aware, TCP client
--   local output = require("dnsjit.output.tcpcli").new("127.0.0.1", "53")
--
-- Simple TCP client that takes any payload you give it, sends the length of
-- the payload as an unsigned 16 bit integer and then sends the payload.
-- When receiving it will first retrieve the length of the payload as an
-- unsigned 16 bit integer and it will stall until it gets, even if
-- nonblocking mode is used.
-- Then it will retrieve at least that amount of bytes, if nonblocking mode
-- is used here then it will return a payload object with length zero if
-- there was nothing to receive or if the full payload have not been received
-- yet.
-- Additional calls will continue retrieving the payload.
-- .SS Attributes
-- .TP
-- timeout
-- A
-- .I core.timespec
-- that is used when producing objects.
module(...,package.seeall)

require("dnsjit.output.tcpcli_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_tcpcli_t"
local output_tcpcli_t = ffi.typeof(t_name)
local Tcpcli = {}

-- Create a new Tcpcli output.
function Tcpcli.new()
    local self = {
        obj = output_tcpcli_t(),
    }
    C.output_tcpcli_init(self.obj)
    ffi.gc(self.obj, C.output_tcpcli_destroy)
    return setmetatable(self, { __index = Tcpcli })
end

-- Set the timeout when producing objects.
function Tcpcli:timeout(seconds, nanoseconds)
    self.obj.timeout.sec = seconds
    self.obj.timeout.nsec = nanoseconds
end

-- Connect to the
-- .I host
-- and
-- .I port
-- and return 0 if successful.
function Tcpcli:connect(host, port)
    return C.output_tcpcli_connect(self.obj, host, port)
end

-- Enable (true) or disable (false) nonblocking mode and
-- return 0 if successful, if
-- .I bool
-- is not specified then return if nonblocking mode is on (true) or off (false).
function Tcpcli:nonblocking(bool)
    if bool == nil then
        if C.output_tcpcli_nonblocking(self.obj) == 1 then
            return true
        end
        return false
    elseif bool == true then
        return C.output_tcpcli_set_nonblocking(self.obj, 1)
    else
        return C.output_tcpcli_set_nonblocking(self.obj, 0)
    end
end

-- Send a core.object.payload or core.object.dns and optionally continue
-- sending after
-- .I sent
-- bytes.
-- Unlike the receive interface this function lets you know if the sending was
-- successful or not which might be needed on nonblocking connections.
-- Returns -1 on error, 0 if timed out or unable to send due to nonblocking, or
-- the number of bytes sent.
-- .B Note
-- if the object sent is a payload or if it's a DNS without dnslen included in
-- the payload then the returned number of bytes sent will include the sent
-- dnslen (payload.len + 2).
function Tcpcli:send(object, sent)
    if sent == nil then
        sent = 0
    end
    return C.output_tcpcli_send(self.obj, object)
end

-- Return the C functions and context for receiving objects, these objects
-- will be sent.
function Tcpcli:receive()
    return C.output_tcpcli_receiver(self.obj), self.obj
end

-- Return the C functions and context for producing objects, these objects
-- are received.
-- If nonblocking mode is enabled the producer will return a payload object
-- with length zero if there was nothing to receive or if the full payload
-- have not been received yet.
-- If nonblocking mode is disabled the producer will wait for data and if
-- timed out (see
-- .IR timeout )
-- it will return a payload object with length zero.
-- If a timeout happens during during the first stage, getting the length, it
-- will fail and return nil.
-- Additional calls will continue retrieving the payload.
-- The producer returns nil on error.
function Tcpcli:produce()
    return C.output_tcpcli_producer(self.obj), self.obj
end

-- Return the number of "packets" sent, actually the number of completely sent
-- payloads.
function Tcpcli:packets()
    return tonumber(self.obj.pkts)
end

-- Return the number of "packets" received, actually the number of completely
-- received DNS messages.
function Tcpcli:received()
    return tonumber(self.obj.pkts_recv)
end

-- Return the number of errors when sending.
function Tcpcli:errors()
    return tonumber(self.obj.errs)
end

return Tcpcli
