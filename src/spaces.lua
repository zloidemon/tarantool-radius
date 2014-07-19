spaces = {}

function spaces:init()
	local spaces = {'servers', 'users', 'sessions'}
	for _, space in pairs(spaces) do
		if not box.space[space] then
			log.info('space[%s] do not exist, creating space and indexes', space)
			s = box.schema.create_space(space)
			if 'servers' == space then
				s:create_index('ip', {unique = true, parts = {1, 'STR'}})
			elseif 'users' == space then
				s:create_index('username', {unique = true, parts = {1, 'STR'}})
			elseif 'sessions' == space then
				s:create_index('sid', {unique = true, parts = {1, 'STR'}})
				s:create_index('username', {unique = false, parts = {2, 'STR'}})
				s:create_index('ip', {unique = false, parts = {3, 'STR'}})
				s:create_index('session', {unique = true, parts = {1, 'STR', 2, 'STR', 3, 'STR'}})
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
