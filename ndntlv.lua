-- create ndnproto protocol and its fields
p_ndnproto = Proto ("ndn","NDN")
local f_packet_type = ProtoField.uint16("ndn.type", "Type", base.DEC_HEX)
local f_packet_size = ProtoField.uint16("ndn.length", "Length", base.DEC_HEX)
local f_interest = ProtoField.string("ndn.interest", "Interest Packet", FT_STRING)
local f_data = ProtoField.string("ndn.data", "Data", FT_STRING)
local f_name = ProtoField.string("ndn.name", "Name", FT_STRING)
local f_interest_selector = ProtoField.string("ndn.selector", "Selector", FT_STRING)
local f_interest_nonce = ProtoField.uint16("ndn.nonce", "Nonce", base.DEC_HEX)
local f_interest_scope = ProtoField.string("ndn.scope", "Scope", FT_STRING)
local f_interest_interestlifetime = ProtoField.string("ndn.interestlifetime", "Interest Life Time", FT_STRING)

local f_interest_selector_minsuffix = ProtoField.uint16("ndn.minsuffix", "Min Suffix Components", base.DEC_HEX)
local f_interest_selector_maxsuffix = ProtoField.uint16("ndn.maxsuffix", "Max Suffix Components", base.DEC_HEX)
local f_interest_selector_keylocator = ProtoField.string("ndn.keylocator", "Publisher Public Key Locator", base.DEC_HEX)
local f_interest_selector_exclude = ProtoField.string("ndn.exclude", "Exclude", base.DEC_HEX)
local f_interest_selector_childselector = ProtoField.string("ndn.childselector", "Child Selector", base.DEC_HEX)
local f_interest_selector_mustbefresh = ProtoField.string("ndn.mustbefresh", "Must Be Fresh", base.DEC_HEX)
local f_interest_selector_any = ProtoField.string("ndn.any", "Any", base.DEC_HEX)

p_ndnproto.fields = {f_packet_type, f_packet_size, f_data, f_interest, f_name, f_interest_selector, f_interest_nonce, f_interest_scope, f_interest_interestlifetime, f_interest_selector_mustbefresh, f_interest_selector_minsuffix, f_interest_selector_maxsuffix, f_interest_selector_keylocator, f_interest_selector_exclude, f_interest_selector_childselector, f_interest_selector_any}

function dump_buf(buf)
  print("-- dump buffer --")
  print("buffer.length = "..buf:len())
  
  -- Before doing extractions, we need to read NDN-TLV specification.
  -- http://named-data.net/doc/ndn-tlv/tlv.html
  -- ** Note that NDN packet format does not have a fixed packet header nor does it encode a protocol version number. **
  -- http://named-data.net/doc/ndn-tlv/types.html

  -- dissector start --
  -- buffer.length = 47
  -- 0000 : 05 2d 07 21 08 03 6e 64 6e 08 03 65 64 75 08 03 
  --        IN 45 [ --- PAYLOAD OF AN INTEREST PACKET ---
  -- 0016 : 75 63 69 08 04 70 69 6e 67 08 0a 31 30 36 36 32 
  -- 0032 : 32 37 35 32 36 09 02 12 00 0a 04 46 57 8d 3f 
  -- -- dissector finished --
  -- -- dissector start --
  -- buffer.length = 405
  -- 0000 : 06 fd 01 91 07 21 08 03 6e 64 6e 08 03 65 64 75 
  --        DA 
  --
  --        fd means 253 -> two octet value
  --        01 -> 256
  --        91 -> 144 + 1 = 145 
  --
  --        256+145 = 401
  --        
  --        the remaining bytes are the payload of the data packet.
  --
  -- 0016 : 08 03 75 63 69 08 04 70 69 6e 67 08 0a 31 30 36 
  -- 0032 : 36 32 32 37 35 32 36 14 04 19 02 03 e8 15 16 4e 
  -- 0048 : 44 4e 20 54 4c 56 20 50 69 6e 67 20 52 65 73 70 
  -- 0064 : 6f 6e 73 65 00 16 4a 1b 01 01 1c 45 07 43 08 09 
  -- 0080 : 6c 6f 63 61 6c 68 6f 73 74 08 07 64 61 65 6d 6f 
  -- 0096 : 6e 73 08 0c 6e 64 6e 2d 74 6c 76 2d 70 69 6e 67 
  -- 0112 : 08 03 4b 45 59 08 11 6b 73 6b 2d 31 34 30 36 34 
  -- 0128 : 32 31 33 38 33 36 35 33 08 07 49 44 2d 43 45 52 
  -- 0144 : 54 17 fd 01 00 88 1b c9 c3 60 dd be 5a 56 48 92 
  -- 0160 : 74 fd 7a 38 2f 6d c5 5f 37 a3 dd d3 69 96 44 9b 
  -- 0176 : a5 9d f1 a7 11 46 b3 3e c1 d0 cb ff 4d 1d 92 b9 
  -- 0192 : 77 d3 43 8d 8c a9 a1 44 d7 2a ea 63 32 ab a6 a6 
  -- 0208 : f1 b2 71 dc 74 c1 e8 ee 90 80 b3 65 08 4c 09 03 
  -- 0224 : 54 23 e2 c3 ff c0 7e 04 d0 d0 3f 9d b3 0e d4 9c 
  -- 0240 : 14 2c 6b d4 e0 df 43 f3 60 6e 5a af 19 11 54 5f 
  -- 0256 : 84 82 67 c4 9c 6d 7e b4 c9 53 62 44 80 f7 95 8c 
  -- 0272 : 91 ce e7 21 bf 71 5e 3e a2 f2 e3 09 e9 86 01 14 
  -- 0288 : 3e 31 41 ce 7c 97 cf f0 78 da d7 95 8c ff 6f a3 
  -- 0304 : 69 9d 5c 64 f6 3d 6b 1a 3a 6d d8 44 98 09 c5 4c 
  -- 0320 : db 30 6c 2d 62 c3 a3 1b 54 81 24 fe fe 51 0f b0 
  -- 0336 : 29 d0 62 87 6b bc e5 e1 59 7d 79 ed b9 bf ee 89 
  -- 0352 : da e8 cd bb e6 14 fb d0 b6 d7 2d 70 c1 ad 00 50 
  -- 0368 : fb 41 ec 56 eb 09 e6 4b 2d e6 98 49 78 44 b5 dc 
  -- 0384 : 75 c7 9f a6 05 ee 0e cf d3 06 b5 34 04 02 0e c9 
  -- 0400 : d5 82 5c c7 62 

  local tmp = ""
  for i=0, buf:len()-1 do
      if i % 16 == 0 then
          tmp = tmp .. string.format("%04d",i) .. " : "
      end
      tmp = tmp .. (buf:range(i,1).." ")
      if (i+1) % 16 == 0 then
        tmp = tmp .. ("\n")
      end
  end
  print(tmp)
end

function add_subtree_for_ndn( buf, subtree )
  local length = buf:len()
  local current_pos = 0

  while ( current_pos < length ) do
    -- extract TYPE
    local _type = buf( current_pos, 1 )
    local _type_uint = _type:uint()
    subtree:add( f_packet_type, _type )
    current_pos = current_pos + 1

    -- extract SIZE
    local _size = buf( current_pos, 1 )
    local _size_num = _size:uint()
    current_pos = current_pos + 1

    if ( _size_num == 253 ) then
      _size = buf( current_pos, 2 )
      _size_num = _size:uint()
      current_pos = current_pos + 2
    elseif ( _size_num == 254 ) then
      _size = buf( current_pos, 4 )
      _size_num = _size:uint()
      current_pos = current_pos + 4
    elseif ( _size_num == 255 ) then
      print("### error ###")
      _size = buf( current_pos, 8 )
      _size_num = _size:uint64() -- can lua number be larger than 32 bits? -- the type 'userdata'
      current_pos = current_pos + 8
    end

    subtree:add( f_packet_size, _size )


    if ( _type_uint == 18 ) then
      return true
    end

    local _payload = buf( current_pos, _size_num )
    current_pos = current_pos + _size_num

    if ( _type_uint == 5 ) then -- interest packet can contain sub NDN-TLV packets
      local child_tree = subtree:add( f_interest, "Interest packet" )
      add_subtree_for_ndn( _payload, child_tree )
    elseif ( _type_uint == 7 ) then
      subtree:add( f_name, _payload, _payload:string(ENC_UTF_8) )
    elseif ( _type_uint == 9 ) then
      local child_tree = subtree:add( f_interest_selector, "Selectors" )
      add_subtree_for_ndn( _payload, child_tree )
    elseif ( _type_uint == 10 ) then
      subtree:add( f_interest_nonce, _payload )
    elseif ( _type_uint == 11 ) then
      subtree:add( f_interest_scope, _payload )
    elseif ( _type_uint == 12 ) then
      subtree:add( f_interest_interestlifetime, _payload )
    elseif ( _type_uint == 13 ) then
      subtree:add( f_interest_selector_minsuffix, _payload )
    elseif ( _type_uint == 14 ) then
      subtree:add( f_interest_selector_maxsuffix, _payload )
    elseif ( _type_uint == 15 ) then
      local child_tree = subtree:add( f_interest_selector_keylocator, "Key Locator" )
      add_subtree_for_ndn( _payload, child_tree )
    elseif ( _type_uint == 18 ) then
      subtree:add( f_interest_selector_mustbefresh, _payload )
    else
      subtree:add( f_data, _payload )
    end
  end
end

-- ndnproto dissector function
function p_ndnproto.dissector (buf, pkt, root)
  print("-- dissector begins --")
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_ndnproto.name
 
  -- create subtree for ndnproto
  subtree = root:add(p_ndnproto, buf())
 
  add_subtree_for_ndn( buf, subtree )

  -- description of payload
  -- subtree:append_text(", Command details here or in the tree below")
  print("-- dissector finishes --")
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

