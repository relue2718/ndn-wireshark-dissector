-- for a debugging purpose
-- http://stackoverflow.com/questions/15175859/how-to-inspect-userdata-in-lua
local inspect = require('inspect')

-- NDN protocol
p_ndnproto = Proto ("ndn","Named Data Network (NDN)") -- to create a 'Proto' object

-- Type and Length fields
local f_packet_type = ProtoField.uint16("ndn.type", "Type", base.DEC_HEX)
local f_packet_size = ProtoField.uint16("ndn.length", "Length", base.DEC_HEX)

-- Interest or Data packets
local f_interest = ProtoField.string("ndn.interest", "Interest", FT_STRING)
local f_data = ProtoField.string("ndn.data", "Data", FT_STRING)

-- Name field
local f_name = ProtoField.string("ndn.name", "Name", FT_STRING)
local f_namecomponent = ProtoField.string("ndn.namecomponent", "Name Component", FT_STRING)
local f_implicitSHA = ProtoField.string("ndn.implicitsha", "Implicit SHA 256 Digest Component", FT_STRING)

-- Sub-fields of Interest packet
local f_interest_selector = ProtoField.string("ndn.selector", "Selector", FT_STRING)
local f_interest_nonce = ProtoField.uint16("ndn.nonce", "Nonce", base.DEC_HEX)
local f_interest_scope = ProtoField.string("ndn.scope", "Scope", FT_STRING)
local f_interest_interestlifetime = ProtoField.uint16("ndn.interestlifetime", "Interest Life Time", base.DEC_HEX)

-- Sub-fields of Interest/Selector field
local f_interest_selector_minsuffix = ProtoField.uint16("ndn.minsuffix", "Min Suffix Components", base.DEC_HEX)
local f_interest_selector_maxsuffix = ProtoField.uint16("ndn.maxsuffix", "Max Suffix Components", base.DEC_HEX)
local f_interest_selector_keylocator = ProtoField.string("ndn.keylocator", "Publisher Public Key Locator", FT_STRING)
local f_interest_selector_exclude = ProtoField.string("ndn.exclude", "Exclude", FT_STRING)
local f_interest_selector_childselector = ProtoField.uint16("ndn.childselector", "Child Selector", base.DEC_HEX)
local f_interest_selector_mustbefresh = ProtoField.string("ndn.mustbefresh", "Must Be Fresh", FT_STRING)
local f_interest_selector_any = ProtoField.string("ndn.any", "Any", FT_STRING)

-- Sub-fields of Data packet
local f_data_metainfo = ProtoField.string("ndn.metainfo", "Meta Info", FT_STRING)
local f_data_content = ProtoField.string("ndn.content", "Content", FT_STRING)
local f_data_signatureinfo = ProtoField.string("ndn.signatureinfo", "Signature Info", FT_STRING)
local f_data_signaturevalue = ProtoField.string("ndn.signaturevalue", "Signature Value", FT_STRING)

-- Sub-fields of Data/MetaInfo field
local f_data_metainfo_contenttype = ProtoField.uint16("ndn.contenttype", "Content Type", base.DEC_HEX)
local f_data_metainfo_freshnessperiod = ProtoField.uint16("ndn.freshnessperiod", "Freshness Period", base.DEC_HEX)
local f_data_metainfo_finalblockid = ProtoField.string("ndn.finalblockid", "Final Block ID", FT_STRING)

-- Sub-fields of Data/Signature field
local f_data_signature_signaturetype = ProtoField.uint16("ndn.signaturetype", "Signature Type", base.DEC_HEX)
local f_data_signature_keylocator = ProtoField.string("ndn.keylocator", "Key Locator", FT_STRING)
local f_data_signature_keydigest = ProtoField.string("ndn.keydigest", "Key Digest", FT_STRING)

-- Add protofields in NDN protocol
p_ndnproto.fields = {f_packet_type, f_packet_size, f_data, f_interest, f_name, f_namecomponent, f_implicitSHA, f_interest_selector, f_interest_nonce, f_interest_scope, f_interest_interestlifetime, f_interest_selector_mustbefresh, f_interest_selector_minsuffix, f_interest_selector_maxsuffix, f_interest_selector_keylocator, f_interest_selector_exclude, f_interest_selector_childselector, f_interest_selector_any, f_data_metainfo, f_data_content, f_data_signatureinfo, f_data_signaturevalue, f_data_metainfo_contenttype, f_data_metainfo_freshnessperiod, f_data_metainfo_finalblockid, f_data_signature_signaturetype, f_data_signature_keylocator, f_data_signature_keydigest}

-- ndntlv_info = { data: { field, type, string }, children: {} }

-- To handle the fragmented packets
-- type: map
-- * key: (host ip address, host port number)
-- * value: type: map
--          * key: packet number
--          * value: packet status
local pending_packets = {}

function set_packet_status( packet_key, packet_number, status_key, status_value )
  if type( pending_packets[ packet_key ] ) ~= "table" then
    pending_packets[ packet_key ] = {}
  end
  if type( pending_packets[ packet_key ][ packet_number ] ) ~= "table" then
    pending_packets[ packet_key ][ packet_number ] = {}
  end
  pending_packets[ packet_key ][ packet_number ][ status_key ] = status_value
end

function get_packet_status( packet_key, packet_number, status_key )
  return pending_packets[ packet_key ][ packet_number ][ status_key ] -- how can we get the number of a previous packet?
end

function parse_ndn_tlv( packet_key, packet_number, max_size, buf, ndntlv_info )
  local length = buf:len()

  print( packet_number .. ".." .. max_size )

  local current_pos = 0

  local ret = true

  while ( current_pos < length ) do
    -- extract TYPE
    local _type = buf( current_pos, 1 )
    local _type_uint = _type:uint()
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
      print("## error ## lua doesn't support 8 bytes of number variables.")
      _size = buf( current_pos, 8 )
      _size_num = _size:uint64() -- can lua number be larger than 32 bits? -- the type 'userdata'
      current_pos = current_pos + 8
    end

    -- subtree:add( f_packet_size, _size )
    local type_size_info = " (Type: " .. _type_uint .. ", Size: " .. _size_num .. ")"

    if ( max_size ~= -1 and max_size < _size_num ) then
      ret = false
      break
    end

    if ( _type_uint == 18 ) then
      return ret
    end

    if ( current_pos + _size_num > length ) then
      ret = false
      break
    end

    local _payload = buf( current_pos, _size_num )
    current_pos = current_pos + _size_num

    if ( _type_uint == 5 ) then -- interest packet can contain sub NDN-TLV packets
      -- Interest packet
      local child_tree = add_subtree( ndntlv_info, { f_interest, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 6 ) then
      -- Data packet
      local child_tree = add_subtree( ndntlv_info, { f_data, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 7 ) then
      -- Name
      local child_tree = add_subtree( ndntlv_info, { f_name, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 8 ) then
      -- Name Component
      add_subtree( ndntlv_info, { f_namecomponent, _payload, _payload:string(ENC_UTF_8) .. type_size_info } )
    elseif ( _type_uint == 1 ) then
      -- Implicit SHA 256 Digest Component
      add_subtree( ndntlv_info, { f_implicitSHA, _payload, _payload:string() .. type_size_info } )
    elseif ( _type_uint == 9 ) then
      -- Selectors
      local child_tree = add_subtree( ndntlv_info, { f_interest_selector, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 10 ) then
      -- Nonce
      add_subtree( ndntlv_info, { f_interest_nonce, _payload, _payload:uint(), nil, type_size_info } )
    elseif ( _type_uint == 11 ) then
      -- Scope
      add_subtree( ndntlv_info, { f_interest_scope, _payload, _payload:string() .. type_size_info } )
    elseif ( _type_uint == 12 ) then
      -- Interest Lifetime
      add_subtree( ndntlv_info, { f_interest_interestlifetime, _payload, _payload:uint(), nil, type_size_info } )
    elseif ( _type_uint == 13 ) then
      -- Selectors / Min Suffix Components
      add_subtree( ndntlv_info, { f_interest_selector_minsuffix, _payload, _payload:uint(), nil, type_size_info } )
    elseif ( _type_uint == 14 ) then
      -- Selectors / Max Suffix Components
      add_subtree( ndntlv_info, { f_interest_selector_maxsuffix, _payload, _payload:uint(), nil, type_size_info } )
    elseif ( _type_uint == 15 ) then
      -- Selectors / Publish Key Locator
      local child_tree = add_subtree( ndntlv_info, { f_interest_selector_keylocator, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 16 ) then
      -- Selectors / Exclude
      local child_tree = add_subtree( ndntlv_info, { f_interest_selector_exclude, _payload, type_size_info } )
      parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 17 ) then
      -- Selectors / Child Selector
      add_subtree( ndntlv_info, { f_interest_selector_childselector, _payload, _payload:uint(), nil, type_size_info } )
    elseif ( _type_uint == 18 ) then
      -- Selectors / Must be Fresh
      add_subtree( ndntlv_info, { f_interest_selector_mustbefresh, _payload, _payload:string() .. type_size_info } )
    elseif ( _type_uint == 19 ) then
      -- Selectors / Any
      add_subtree( ndntlv_info, { f_interest_selector_any, _payload, _payload:string() .. type_size_info } )
    elseif ( _type_uint == 20 ) then
      -- MetaInfo
      local child_tree = add_subtree( ndntlv_info, { f_data_metainfo, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 21 ) then
      -- Content
      add_subtree( ndntlv_info, { f_data_content, _payload, _payload:string() .. type_size_info } )
    elseif ( _type_uint == 22 ) then
      -- SignatureInfo
      local child_tree = add_subtree( ndntlv_info, { f_data_signatureinfo, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 23 ) then
      -- SignatureValue
      add_subtree( ndntlv_info, { f_data_signaturevalue, _payload, _payload:string() .. type_size_info } )
    elseif ( _type_uint == 24 ) then
      -- MetaInfo / ContentType
      add_subtree( ndntlv_info, { f_data_metainfo_contenttype, _payload, _payload:uint(), nil, type_size_info } )
    elseif ( _type_uint == 25 ) then
      -- MetaInfo / FreshnessPeriod
      add_subtree( ndntlv_info, { f_data_metainfo_freshnessperiod, _payload, _payload:uint(), nil, type_size_info } )
    elseif ( _type_uint == 26 ) then
      -- MetaInfo / FinalBlockId
      local child_tree = add_subtree( ndntlv_info, { f_data_metainfo_finalblockid, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 27 ) then
      -- Signature / SignatureType
      add_subtree( ndntlv_info, { f_data_signature_signaturetype, _payload, _payload:uint(), nil, type_size_info } )
    elseif ( _type_uint == 28 ) then
      -- Signature / KeyLocator
      local child_tree = add_subtree( ndntlv_info, { f_data_signature_keylocator, _payload, type_size_info } )
      ret = ret and parse_ndn_tlv( packet_key, packet_number, _size_num, _payload, child_tree )
    elseif ( _type_uint == 29 ) then
      -- Signature / KeyDigest
      add_subtree( ndntlv_info, { f_data_signature_keydigest, _payload, _payload:string() .. type_size_info } );
    else
      print("## warning ## unhandled type_uint: ", _type_uint)
      ret = false
      -- if the packet seems to be a NDN packet, it would be better idea to add some warning messages in the subtress instead of returning false.
    end
  end
  return ret
end

function create_subtree_from( info, subtree )
  for k, v in pairs( info["children"] ) do
    local data = v["data"]
    if type(data) == "table" then
      local child_tree = subtree:add( unpack( data ) )
      create_subtree_from( v, child_tree )
    end
  end
end

function add_subtree( info, data )
  local child_tree = { ["data"] = data, ["children"] = {} }
  table.insert( info["children"], child_tree )
  return child_tree
end

-- ndnproto dissector function
function p_ndnproto.dissector( buf, pkt, root )
  -- validate packet length is adequate, otherwise quit
  local length = buf:len()
  local packet_number = pkt.number -- an unique serial for each packet
  local packet_key = tostring(pkt.src) .. ":" .. tostring(pkt.src_port) .. ":" .. tostring(pkt.dst) .. ":" .. tostring(pkt.dst_port)
  print("## info ## packet[" .. packet_number .. "], length = " .. length )

  if length == 0 then
  else
    local ndntlv_info = { ["data"] = nil, ["children"] = {} }
    local was_ndntlv_packet = parse_ndn_tlv( packet_key, packet_number, -1, buf, ndntlv_info )

    -- It needs to check whether the packet type is NDN-TLV.
    if was_ndntlv_packet == true then
      pkt.cols.protocol = p_ndnproto.name -- set the protocol name to NDN

      local subtree = root:add( p_ndnproto, buf() ) -- create subtree for ndnproto
      create_subtree_from( ndntlv_info, subtree )
    end
  end
end

-- Initialization routine
function p_ndnproto.init()
end

local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add("6363", p_ndnproto)

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add("6363", p_ndnproto)

local websocket_dissector_table = DissectorTable.get("ws.port")
websocket_dissector_table:add("9696", p_ndnproto)

print("ndntlv.lua is successfully loaded.")

----------------------------------------------------------------------
-- helper functions
----------------------------------------------------------------------
function dump_buf(buf)
  print("buffer.length = "..buf:len())
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

function print_table(tbl, indent)
  if not indent then indent = 0 end
  for k, v in pairs(tbl) do
    formatting = string.rep("  ", indent) .. k .. ": "
    if type(v) == "table" then
      print(formatting)
      print_table(v, indent+1)
    elseif type(v) == 'boolean' then
      print(formatting , tostring(v))      
    else
      print(formatting , v)
    end
  end
end