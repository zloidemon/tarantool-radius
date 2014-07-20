#!/usr/bin/env tarantool

dofile('tarantool.lua')

radius = require('radius')

-- You can change that options
-- radius.host = '127.0.0.1'
-- radius.port.acct = 1813
-- radius.port.auth = 1812

-- Init servers
if (radius.auth == nil) then
	radius.run(radius, 'auth')
end
if (radius.acct == nil) then
	radius.run(radius, 'acct')
end
