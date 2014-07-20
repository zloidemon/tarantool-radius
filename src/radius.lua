log    = require('log')
pickle = require('pickle')
digest = require('digest')
socket = require('socket')
fiber  = require('fiber')
spaces = require('spaces')

radius = {
	version = 0.1,
	port = {
		acct = 1813,
		auth = 1812,
	},
	host = '0.0.0.0',

	-- Servers objects
	acct = nil,
	auth = nil,
	rp = require('rp'),
}

function radius:sxor(a,b)
	local x,y,x1,y1,out = a,b,0,0,''
	while(#x >= 4) do
		x1,x = pickle.unpack('ia',x)
		y1,y = pickle.unpack('ia',y)
		local topack = bit.bxor(x1,y1)
		if 0 > topack then
			return nil
		end
		out = out .. pickle.pack('i',topack)
	end
	while (#x > 0) do
		x1,x = pickle.unpack('ba',x)
		y1,y = pickle.unpack('ba',y)
		out = out .. pickle.pack('b',bit.bxor(x1,y1))
	end 
	return out
end

function radius:bintohex(s)
	return (s:gsub('(.)', function(c)
		return string.format('%02x', string.byte(c))
	end))
end

function radius:hextobin(s)
	return (s:gsub('(%x%x)', function(hex)
		return string.char(tonumber(hex, 16))
	end))
end

function radius:decode_password(pw, last, secret)
	local out = ''
	while (#pw > 0) do 
		local pw1 = string.sub(pw, 1, 16)
		local sx  = self:sxor(pw1, digest.md5(secret .. last))
		if not sx then
			return nil
		end
		out  = out .. sx
		last = pw1
		pw   = string.sub(pw, 17)
	end
	return string.format("%s", out)
end

function radius:intip_to_strip(ip)
	local o0, o1, o2, o3 = pickle.unpack('bbbb', string.sub(attrdat, 3, 6))
	o0 = bit.band(o0, 0xff)
	o1 = bit.band(o1, 0xff)
	o2 = bit.band(o2, 0xff)
	o3 = bit.band(o3, 0xff)

	return string.format("%d.%d.%d.%d", o0, o1, o2, o3)
end

function radius:unpack(msg, host, secret)
	local datagramm = nil

	local code, id, len, tail  = pickle.unpack('bbna', msg)
	local authenticator        = pickle.unpack('a', string.sub(tail, 0, 16))
	local startlen, atype, var = 16, 0, nil

	local Code = self.rp.codes[code]
	local attributes = {}

	while (startlen + 5) < len  do
		attrdat      = string.sub(tail, startlen + 1)
		atype, atlen = pickle.unpack('bb', string.sub(attrdat, 0, 2))
		
		local txtatype = self.rp.attr[atype]

		if
			txtatype == 'Acct-Status-Type'	    or
			txtatype == 'Acct-Output-Octets'    or
			txtatype == 'Acct-Input-Octets'     or
			txtatype == 'Acct-Session-Time'     or
			txtatype == 'Acct-Input-Gigawords'  or
			txtatype == 'Acct-Output-Gigawords' or
			txtatype == 'Framed-IP-Address'	    or
			txtatype == 'NAS-IP-Address'	    or
			txtatype == 'NAS-Port'		    or
			txtatype == 'NAS-Port-Type'	    or
			txtatype == 'Framed-Protocol'       or
			txtatype == 'Framed-Compression'    or
			txtatype == 'Acct-Interim-Interval' or
			txtatype == 'Service-Type'	 then

			if
				txtatype == 'NAS-IP-Address' or
				txtatype == 'Framed-IP-Address' then
				var = self:intip_to_strip(attrdat)
			else
				var = pickle.unpack('N', string.sub(attrdat, 3, atlen))
			end
			if
				txtatype == 'Service-Type' or
				txtatype == 'Acct-Status-Type' or
				txtatype == 'Framed-Protocol' or
				txtatype == 'NAS-Port-Type' then
				var = self.rp[txtatype][var]
			end
		else
			var = pickle.unpack('a', string.sub(attrdat, 3, atlen))
			if 'User-Password' == txtatype then
				var = self:decode_password(var, authenticator, secret)
			end
		end

		startlen = startlen + atlen
		log.debug('%10d\t%5s\t[%2s]\t%20s\t%s\t', id, atlen, atype, self.rp.attr[atype], var)
		attributes[self.rp.attr[atype]] = var
	end

	if Code == 'Access-Request' then
		local username = attributes['User-Name']
		local userpass = attributes['User-Password']
		local user = spaces.users:get{username}

		if not userpass then
			log.error('Incorrect radius client %s passsword', host)
			datagramm = self:pack(secret, id, authenticator, 3, 20)
		elseif not user then
			log.error('User not found in db: %s', username)
			datagramm = self:pack(secret, id, authenticator, 3, 20)
		else
			if user[2] ~= userpass then
				log.error('Incorrect password user: %s', username)
				datagramm = self:pack(secret, id, authenticator, 3, 20)
			else
				local attr = {
					[7]  = 1,  -- Framed-Protocol
					[13] = 1,  -- Framed-Compression
					[85] = 60, -- Acct-Interim-Interval
					[6]  = 2   -- Service-Type
				}
				datagramm = self:pack(secret, id, authenticator, 2, 44, attr)
				log.info('User %s has authenticated', username)
			end
		end
	elseif Code == 'Accounting-Request' then
		local accstatus = attributes['Acct-Status-Type']
		local accsid    = attributes['Acct-Session-Id']

		log.info('Incomming accounting request sid: %s\t%s', accsid, accstatus)

		if 'Start' == accstatus then
			spaces.sessions:insert{
				accsid, attributes['User-Name'],
				attributes['Calling-Station-Id'],
				host, attributes['NAS-Identifier'],
				0, 0, 0,      -- Session time, In, Out
				os.time(), 0, -- Start time, End time
			}
		elseif 'Interim-Update' == accstatus or 'Stop' == accstatus then
			local stime  = attributes['Acct-Session-Time']
			local sinoc  = attributes['Acct-Input-Octets']
			local soutoc = attributes['Acct-Output-Octets']
			local sidata = {
				{'=', 6, stime}, {'+', 7, sinoc},
				{'+', 8, soutoc}
			}
			if 'Stop' == accstatus then
				local endtime = os.time()
				table.insert(sidata, {'=', 10, endtime})
				log.info("Session %s ended at %s", accsid, os.date('%c', endtime))
			end
			spaces.sessions:update(accsid, sidata)
		else
			log.error('%s called not implimented command: %s', accsid, accstatus)
		end
		-- 5 is Accounting-Response
		datagramm = self:pack(secret, id, authenticator, 5, 20)
	else
		log.error('Not implimented code: %s', Code)
		-- 3 is Access-Reject
		datagramm = self:pack(secret, id, authenticator, 3, 20)
	end

	return datagramm
end

function radius:pack(secret, id, authenticator, code, length, attr)
	log.debug('Packing response to %s', id)
	local attr_p = nil

	if attr == nil then
		attr = {}
	end

	for atype, var in pairs(attr) do
		log.debug('%10d\t%5s\t[%2s]\t%20s\t%s\t', id, 6, atype, self.rp.attr[atype], var)
		local attr_header = pickle.pack('bb', atype, 6)
		local attr_packed = pickle.pack('aN', attr_header, var)
		if attr_p ~= nil then
			attr_p = pickle.pack('aa', attr_p, attr_packed)
		else
			attr_p = pickle.pack('a', attr_packed)
		end
	end

	local datagramm = pickle.pack('bbna', code, id, length, authenticator)

	if attr_p then
		datagramm = pickle.pack('aa', datagramm, attr_p)
	end

	local sum = digest.md5(datagramm .. secret)

	datagramm = pickle.pack('bbna', code, id, length, sum)

	if attr_p then
		datagramm = pickle.pack('aa', datagramm, attr_p)
	end

	return datagramm
end

function radius:server(name)
	fiber.name(name)
	local server = self[name]
	log.info('listening RADIUS(%s)', name)
	while true do
		local msg, status, host, port = server:recvfrom(10000)
		local rclient = spaces.servers:get{host}
		if rclient then
			local datagramm = self:unpack(msg, host, rclient[2])
			log.info('connection from %s on port %d', host, port)

			if not server:sendto(datagramm, host, port, 1) then
				log.error("code: %s text: %s", server:errno(), server:error())
			end
		end
	    end
end

function radius:run(name)
	spaces:init()
	local sock = socket.udp()
	local port = self.port[name]
	log.info('running RADIUS(%s) server on: %s:%d', name, radius.host, port)
	sock:bind(radius.host, port, 1);
	sock:listen()
	self[name] = sock;

	log.info("bound to udp port: %d", port)
	local f = fiber.create(self.server, self, name)
end

return radius
