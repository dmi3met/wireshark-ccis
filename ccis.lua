ccis_protocol = Proto("CCIS",  "CCIS NEC Protocol")

message_length = ProtoField.int32("ccis.message_length", "messageLength", base.DEC)
from_ip = ProtoField.int32("ccis.from_ip","from_ip", base.DEC)
from_port = ProtoField.int32("ccis.from_port","from_port", base.DEC)
opcode_number = ProtoField.int32("ccis.message","message", base.DEC)

ccis_protocol.fields = {message_length, from_ip, from_port, opcode_number}

function ccis_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = ccis_protocol.name
  
    local subtree = tree:add(ccis_protocol, buffer(), "CCIS NEC Protocol Data")
    -- subtree:add(message_length, buffer(11,2))
  
    if length>26 then
      
        local from_ip = bytes_to_ip(buffer,26)
	    local from_port = buffer(42,2):uint()
	    local FromSubtree = subtree:add(ccis_protocol, buffer(), "From "..from_ip..":"..from_port)
        --FromSubtree:add("IP " .. from_ip, buffer(26,4))
	    --FromSubtree:add("Port: " .. from_port, buffer(42,2))
	  
	  
	    local to_ip = bytes_to_ip(buffer,30)
	    local to_port = buffer(44,2):uint()
	    local ToSubtree = subtree:add(ccis_protocol, buffer(), "To "..to_ip..":"..to_port)
	    --ToSubtree:add("IP " .. to_ip, buffer(30,4))
	    --ToSubtree:add("Port: " .. to_port, buffer(44,2))
	  
	    --udp_ip_local = bytes_to_ip(buffer,48)
	    --udp_ip_remote = bytes_to_ip(buffer,62)
	    -- subtree:add_le("UDP IP Local: " .. udp_ip_local)
	    -- subtree:add_le("UDP IP Remote: " .. udp_ip_remote)
	  
	    local opcode_number = buffer(94,1):le_uint()
        local opcode_name = get_opcode_name(opcode_number)
        pinfo.cols.info = opcode_name
	    subtree:add_le(opcode_number,         buffer(12,4)):append_text(" " .. opcode_name .. "")
	    local opc = buffer(96,1)
	    subtree:add_le("OPC " .. opc)
	  	  
	    if opcode_name == "INVITE" then
	      
	        local number_b_length = tonumber("0x"..(tostring(buffer(104,1)):sub(0,1)))
		    -- subtree:add("Number B len: " .. number_b_length,buffer(104,1))
		  
		    local bytes_to_read = math.floor((number_b_length+1)/2)
		    -- subtree:add("bytes_to_read: " .. bytes_to_read)
		  
		    local number_b_reversed = buffer(105,bytes_to_read)
		    local number_b = byte_reverse(number_b_reversed):sub(0,number_b_length)
		    subtree:add("Number B: " .. number_b,buffer(105,bytes_to_read))
		  
		    local number_a_reversed = buffer(109+bytes_to_read,2)
		    local number_a = (byte_reverse(number_a_reversed)):gsub("a", "0")
		    subtree:add("Number A: " .. number_a)
        end
  end
  
    --subtree:add(ip_address,buffer(159,4))
  
end

function byte_reverse(reversed)
    local result=""
	local rev_string = tostring(reversed)
	for i = 1, rev_string:len(), 2 do
            result = result .. rev_string:sub(i+1,i+1) .. rev_string:sub(i,i)
	end
    return result
end

function bytes_to_ip(buffer,start)
    local oct_1 = buffer(start,1):le_uint()
    local oct_2 = buffer(start+1,1):le_uint()
    local oct_3 = buffer(start+2,1):le_uint()
    local oct_4 = buffer(start+3,1):le_uint()
    local ip = oct_1 .. "." .. oct_2 .. "." .. oct_3 .. "." .. oct_4
    return ip
end

function get_opcode_name(opcode)
  local opcode_name = "Unknown"

      if opcode == 63 then opcode_name = "INVITE"
  elseif opcode ==  8 then opcode_name = "OK"
  elseif opcode ==  7 then opcode_name = "BYE"
  elseif opcode == 26 then opcode_name = "DESCRIPTION 1"
  elseif opcode == 27 then opcode_name = "DESCRIPTION 2"
      end

  return opcode_name
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(57000, ccis_protocol)
--local udp_port = DissectorTable.get("udp.port")
--udp_port:add(56000, ccis_protocol)
