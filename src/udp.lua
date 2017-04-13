--
-- Based on https://github.com/tarantool/tarantool/issues/1444
--

local socket = require('socket')
local errno  = require('errno')
local fiber  = require('fiber')
local log    = require('log')

local function udp_server_usage()
    error('Usage: socket.udp_server(host, port, handler | opts)')
end

local function udp_server_loop(server, s, addr)
    fiber.name(('%s/%s:%s'):format(server.name, addr.host, addr.port))
    log.info('started')

    while true do
        local msg, peer = s:recvfrom()
        if msg == '' then
            break
        elseif msg ~= nil then
            server.handler(s, peer, msg)
        else
            if s:errno() == errno.EAGAIN or s:errno() == errno.EINTR then
                s:readable()
            else
                local err = s:error()
                s:close()
                error('UDP socket error: ' .. err)
            end
        end
    end
end

local function udp_server_bind(s, addr)
    if s:bind(addr.host, addr.port) then
        return true
    end

    if errno() ~= errno.EADDRINUSE then
        return false
    end

    return s:bind(addr.host, addr.port)
end

local function udp_server(host, port, opts)
    local server = {}

    if type(opts) == 'function' then
        server.handler = opts
    elseif type(opts) == 'table' then
        if type(opts.handler) ~= 'function' then
            udp_server_usage()
        end
        for k, v in pairs(opts) do
            server[k] = v
        end
    else
        udp_server_usage()
    end

    local addr = {
        host = host, port = port
    }
    server.name = server.name or 'udp_server'

    local s = socket('AF_INET', 'SOCK_DGRAM', 'udp')

    if not s then
        return nil
    end

    if not udp_server_bind(s, addr) then
        local e = errno()
        s:close()
        errno(e)
        return nil
    end

    fiber.create(udp_server_loop, server, s, addr)
    return s, addr
end

return {
    udp_server = udp_server
}
