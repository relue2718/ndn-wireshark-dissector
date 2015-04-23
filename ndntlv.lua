-- create ndnproto protocol and its fields
p_ndnproto = Proto ("ndntlv","NDN-TLV")
local f_packet_type = ProtoField.uint16("ndntlv.packettype", "Packet type", base.DEC_HEX)
local f_packet_size = ProtoField.uint16("ndntlv.packetsize", "Packet size", base.DEC_HEX)
local f_data = ProtoField.string("ndntlv.data", "Data", FT_STRING)
 
p_ndnproto.fields = {f_packet_type, f_packet_size, f_data}

-- test

-- http://lua-users.org/wiki/HexDump
--   function hex_dump(buf)
--      for i=1,math.ceil(#buf/16) * 16 do
--         if (i-1) % 16 == 0 then io.write(string.format('%08X  ', i-1)) end
--         io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
--         if i %  8 == 0 then io.write(' ') end
--         if i % 16 == 0 then io.write( buf:sub(i-16+1, i):gsub('%c','.'), '\n' ) end
--      end
--   end

 
-- ndnproto dissector function
function p_ndnproto.dissector (buf, pkt, root)
  print("-- dissector start --")
  print("buffer.length = "..buf:len())
--  hex_dump(buf)
  
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_ndnproto.name
 
  -- create subtree for ndnproto
  subtree = root:add(p_ndnproto, buf())
  -- add protocol fields to subtree
  subtree:add(f_packet_type, buf(0,1))
  local payload_offset = 2 -- by default
  local packet_size_preliminary = buf(1,1):int()
  local packet_size=0
  if(packet_size_preliminary<253) then
    packet_size=packet_size_preliminary
  elseif(packet_size_preliminary==253) then
    payload_offset = 3 -- the length of the packet size field is 2
    packet_size = buf(2, 2):int64()
    print("######"..packet_size)
  elseif(packet_size_preliminary==254) then
    payload_offset = 5 -- the length of the packet size field is 4
    packet_size = buf(2,4):int64()
  elseif(packet_size_preliminary==255) then
   payload_offset = 9 -- the length of the packet size field is 8.
   packet_size = buf(2,8):int64()
  end
  

  subtree:add(f_packet_size, packet_size)
 
  -- description of payload
  subtree:append_text(", Command details here or in the tree below")

  print("-- dissector finished --")
end
 
-- Initialization routine
function p_ndnproto.init()
	print("initialized")
end
 
-- register a chained dissector for port 8002
local udp_dissector_table = DissectorTable.get("udp.port")
dissector = udp_dissector_table:get_dissector(6363)
  -- you can call dissector from function p_ndnproto.dissector above
  -- so that the previous dissector gets called
udp_dissector_table:add(6363, p_ndnproto)

print("finished")

print("end")

