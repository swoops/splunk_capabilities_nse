description = [[
Attempts to identify and get basic information from splunk reciever ports.
]]

--TODO
--@usage
--@args
--@output

local nmap = require("nmap")
local stdnse = require("stdnse")

author = "bemodtwz"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "safe"}

-- TODO stricter requirements for running
portrule = function(host, port)
	-- stdnse.debug("port.service: %s", port.service)
	-- stdnse.debug("service_dtype: %s", port.version.service_dtype)
	return port.state == "open" and port.protocol == "tcp"
end

null_pad_too = function(st, size)
	return st .. string.rep("\x00", size - string.len(st))
end

get_spl_sig = function(hostname, port)
	local ret = null_pad_too("--splunk-cooked-mode-v3--", 0x80)
	ret = ret .. null_pad_too(hostname, 0x100)
	ret = ret .. null_pad_too(string.format("%d", port), 0x10)
	return ret
end

get_caps = function()
	return "\x00\x00\x00@\x00\x00\x00\x01\x00\x00\x00\x13__s2s_capabilities\x00\x00\x00\x00\x14ack=0;compression=0\x00\x00\x00\x00\x00\x00\x00\x00\x05_raw\x00"
end

big32 = function(buf)
	local len = string.unpack(">I4", buf)
	return len, buf:sub(5)
end

big32_str = function(buf)
	local len, buf = big32(buf)
	return buf:sub(1,len - 1), buf:sub(len + 1)
end

parse_resp = function(buf)
	if string.len(buf) < 4 then
		return ""
	end

	local size, buf = big32(buf)
	stdnse.debug("msg size: 0x%x", size)

	if buf:len() ~= size then
		stdnse.debug("msg size != buffer len + 4", size)
		return ""
	end

	local count, buf = big32(buf)
	if count ~= 1 then
		stdnse.debug("Unexpected count %d", count)
        return ""
	end

	-- actually building output string
	local out = "\n\t"
	for i=1,count do
		local key, value
		key, buf = big32_str(buf) 
		value, buf = big32_str(buf) 
		out = out .. value:gsub(";", "\n\t"):gsub("=", " -> ")
	end

	return out
end

action = function(host, port)
    local sock = nmap.new_socket()
    local catch = function()
            sock:close()
    end
    local try = nmap.new_try(catch)
    try(sock:connect(host.ip, port.number))
    try(sock:send(get_spl_sig("nmap_scan", 8089)))
    try(sock:send(get_caps()))

    local buf = try(sock:receive())
    try(sock:close())
    local data = parse_resp(buf)
    if data:len() > 0 then
        -- Detected
        port.version.name = "Splunk Reciver Port"
        port.version.product = "Splunk"
        nmap.set_port_version(host, port)
    end
	return data
end
