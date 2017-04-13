local log = require ('log')

local spaces = {}

function spaces:init()
	local spaces = {'servers', 'users', 'sessions'}
	for _, space in pairs(spaces) do
		if not box.space[space] then
			log.info('space[%s] do not exist, creating space and indexes', space)
            if not box.space[space] then
    			local s = box.schema.create_space(space)
    			if 'servers' == space then
	    			s:create_index('ip', {unique = true, parts = {1, 'string'}})
		    	elseif 'users' == space then
			    	s:create_index('username', {unique = true, parts = {1, 'string'}})
    			elseif 'sessions' == space then
	    			s:create_index('sid', {unique = true, parts = {1, 'string'}})
		    		s:create_index('username', {unique = false, parts = {2, 'string'}})
			    	s:create_index('ip', {unique = false, parts = {3, 'string'}})
				    s:create_index('session', {unique = true, parts = {1, 'string', 2, 'string', 3, 'string'}})
    			end
            end
		end
		self[space] = box.space[space]
	end
end

function spaces:demo()
	log.info('Init demo configuration')
	box.space.servers:insert{'127.0.0.1', 'password'}
	box.space.users:insert{'test', 'password'}
end

return spaces
