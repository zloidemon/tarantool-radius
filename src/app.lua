#!/usr/bin/env tarantool

dofile('tarantool.lua')

log    = require('log')
radius = require('radius')

-- Change me
radius.host = '127.0.0.1'

-- Init servers
if (radius.auth == nil) then
	radius.run(radius, 'auth')
end
if (radius.acct == nil) then
	radius.run(radius, 'acct')
end
