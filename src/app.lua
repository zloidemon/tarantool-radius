#!/usr/bin/env tarantool

dofile('tarantool.lua')

local radius = require('radius')
local spaces = require('spaces')

box.once('radius:spaces', function ()
    spaces:init()
end)

-- Init servers

acct = radius:run('acct', '127.0.0.1', 1813)
auth = radius:run('auth', '127.0.0.1', 1812)

require('console').start()
