-- create ndnproto protocol and its fields
p_ndnproto = Proto ("ndntlv","NDN-TLV")
local f_command = ProtoField.uint16("ndntlv.command", "Command", base.HEX)
local f_data = ProtoField.string("ndntlv.data", "Data", FT_STRING)
 
p_ndnproto.fields = {f_command}

-- test

-- http://lua-users.org/wiki/HexDump
   function hex_dump(buf)
         print(#buf)
      for i=1,math.ceil(#buf/16) * 16 do

         if (i-1) % 16 == 0 then print(string.format('%08X  ', i-1)) end
         print( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
         if i %  8 == 0 then print(' ') end
         if i % 16 == 0 then print( buf:sub(i-16+1, i):gsub('%c','.'), '\n' ) end
      end
   end

 
-- ndnproto dissector function
function p_ndnproto.dissector (buf, pkt, root)
  print("-- dissector start --")
  print("buffer.length = "..buf:len())

  local first_byte = buf:range(0,1)
  local ndn_interest_ver = first_byte:bitfield(0, 4)
  local ndn_interest_msg = first_byte:bitfield(4, 4)

  print(ndn_interest_ver)
  print(ndn_interest_msg)
  --print(buf:byte(1):bitfield(0,3))
  --hex_dump(buf)
  
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_ndnproto.name
 
  -- create subtree for ndnproto
  subtree = root:add(p_ndnproto, buf(0))
  -- add protocol fields to subtree
  subtree:add(f_command, buf(0,2)):append_text(" [Command text]")
 
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

