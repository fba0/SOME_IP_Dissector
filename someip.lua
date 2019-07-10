-- File : someip.lua
-- Who  : x-Felix-x
-- Based on: https://github.com/jamores/eth-ws-someip/blob/master/someip.lua
-- What : SOMEIP dissector

-- SOME/IP Message Types
local msg_types = {
    [0]     = "REQUEST",                -- 0x00
    [1]     = "REQUEST_NO_RETURN",      -- 0x01
    [2]     = "NOTIFICATION",           -- 0x02
    [64]    = "REQUEST_ACK",            -- 0x40
    [65]    = "REQUEST_NO_RETURN_ACK",  -- 0x41
    [66]    = "NOTIFICATION_ACK",       -- 0x42
    [128]   = "RESPONSE",               -- 0x80
    [129]   = "ERROR",                  -- 0x81
    [192]   = "RESPONSE_ACK",           -- 0xc0
    [193]   = "ERROR_ACK",              -- 0xc1

    -- SOME/IP - Transport Protocol (SOME/IP-TP)
    [32]    = "REQUEST Segment",                -- 0x20
    [33]    = "REQUEST_NO_RETURN Segment",      -- 0x21
    [34]    = "NOTIFICATION Segment",           -- 0x22
    [96]    = "REQUEST_ACK Segment",            -- 0x60
    [97]    = "REQUEST_NO_RETURN_ACK Segment",  -- 0x61
    [98]    = "NOTIFICATION_ACK Segment",       -- 0x62
    [160]   = "RESPONSE Segment",               -- 0xa0
    [161]   = "ERROR Segment",                  -- 0xa1
    [224]   = "RESPONSE_ACK Segment",           -- 0xe0
    [225]   = "ERROR_ACK Segment"               -- 0xe1
}

-- SOME/IP Return Codes
local ret_codes = {
    [0]     = "E_OK",
    [1]     = "E_NOT_OK",
    [2]     = "E_UNKNOWN_SERVICE",
    [3]     = "E_UNKNOWN_METHOD",
    [4]     = "E_NOT_READY",
    [5]     = "E_NOT_REACHABLE",
    [6]     = "E_TIMEOUT",
    [7]     = "E_WRONG_PROTOCOL_VERSION",
    [8]     = "E_WRONG_INTERFACE_VERSION",
    [9]     = "E_MALFORMED_MESSAGE",
    [10]    = "E_WRONG_MESSAGE_TYPE"
}

-- bitwise ops helpers
local band, bor = bit.band, bit.bor
local lshift, rshift = bit.lshift, bit.rshift
local tohex = bit.tohex

-- SOME/IP Service Discovery offset
local SOMEIP_SD_OFFSET = 16

-- SOME/IP Header lenght
local SOMEIP_HDR_LEN = 16

-- SOME/IP max length (from AUTOSAR SOME/IP Spec)
local SOMEIP_MAX_LEN  = 4095

-- SOME/IP Protocol
p_someip = Proto("someip", "SOME/IP")

-- SOME/IP fields
local f_msg_id     = ProtoField.uint32("someip.messageid", "MessageID", base.HEX)
local f_len        = ProtoField.uint32("someip.length", "Length", base.HEX)
local f_req_id     = ProtoField.uint32("someip.requestid", "RequestID", base.HEX)
local f_pv         = ProtoField.uint8("someip.protoversion", "ProtocolVersion", base.HEX)
local f_iv         = ProtoField.uint8("someip.ifaceversion", "InterfaceVersion", base.HEX)
local f_mt         = ProtoField.uint8("someip.msgtype", "MessageType", base.HEX)
local f_rc         = ProtoField.uint8("someip.returncode", "ReturnCode", base.HEX)
local f_payload    = ProtoField.bytes("someip.payload", "Payload")

-- add SOME/IP fields
p_someip.fields = {f_msg_id, f_len, f_req_id, f_pv, f_iv, f_mt, f_rc, f_payload}

p_someip.prefs["udp_port"] = Pref.uint("UDP Port", 30490, "UDP Port for SOME/IP")

-- dissect message_id into service_id and method_id
function field_msgid(subtree, buf, offset)

    msg_id = subtree:add(f_msg_id, buf(offset + 0, 4))
    
    local msg_id_uint = buf(offset + 0, 4):uint()

    msg_id:append_text( " (" .. tohex(buf(offset + 0, 2):uint(), 4) ..
                        ":" .. band(rshift(msg_id_uint, 15), 0x01) ..
                        ":" .. tohex(band(msg_id_uint, 0x7fff), 4) .. ")")

    msg_id:add("service_id : " .. tohex(buf(offset + 0, 2):uint(), 4))
    
    if band(buf(offset + 0, 2):uint(), 0x80) == 0 then
        msg_id:add("method_id : " .. tohex(band(msg_id_uint,0x7fff), 4))
    else
        msg_id:add("event_id : " .. tohex(band(msg_id_uint,0x7fff), 4))
    end
    
end

-- dissect request_id into client_id and session_id
function field_reqid(subtree, buf, offset)

    req_id = subtree:add(f_req_id, buf(offset + 8, 4))
    
    local req_id_uint = buf(offset + 8, 4):uint()

    req_id:append_text(" (" .. buf(offset + 8, 2) .. ":" .. buf(offset + 10, 2) .. ")")

    req_id:add("client_id : " .. tohex(rshift(req_id_uint, 16), 4))
    req_id:add("session_id : " .. tohex(req_id_uint, 4))
    
end

-- check SOME/IP Length field
function checkSOMEIPLength(tvbuf, offset)

    -- "msglen" is the number of bytes remaining in the Tvb buffer which we
    -- have available to dissect in this run
    local msglen = tvbuf:len() - offset

    -- check if capture was only capturing partial packet size
    if msglen ~= tvbuf:reported_length_remaining(offset) then
        -- Captured packet was shorter than original, can't reassemble
        return 0
    end

    if msglen < SOMEIP_HDR_LEN then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT
    end


    -- get the TvbRange of bytes from length field
    local length_tvbr = tvbuf:range(offset + 4, 4)

    -- get the length as an unsigned integer, in network-order (big endian)
    local length_val  = length_tvbr:uint()

    -- check if message is to long
    if length_val > SOMEIP_MAX_LEN then
        -- too many bytes, invalid message
        return 0
    end

    -- not enough bytes in current TCP segment
    if msglen < length_val then
        -- we need more bytes to get the whole SOME/IP message
        return -((length_val + 8) - msglen)
    end

    return length_val, length_tvbr
    
end

-- dissect SOME/IP function
function dissect_some_ip(buf, pinfo, root, offset)

    -- get info about the amount of bytes given
    local length_val, length_tvbr = checkSOMEIPLength(buf, offset)
    
    -- check if we need more bytes to get the whole SOME/IP message
    if length_val <= 0 then
        return length_val
    end

    -- add protocol name
    pinfo.cols.protocol = p_someip.name

    -- create subtree
    subtree = root:add(p_someip, buf(offset + 0))

    -- add protocol fields to subtree
    -- Message ID
    field_msgid(subtree, buf, offset)
    -- Length
    subtree:add(f_len, length_tvbr)
    -- Request ID
    field_reqid(subtree, buf, offset)
    -- Protocol Version
    subtree:add(f_pv, buf(offset + 12, 1))
    -- Interface Version
    subtree:add(f_iv, buf(offset + 13, 1))

    -- Message type
    local type = subtree:add(f_mt, buf(offset + 14, 1))
    if msg_types[buf(offset + 14, 1):uint()] ~= nil then
        type:append_text(" (" .. msg_types[buf(offset + 14, 1):uint()] .. ")")
    end

    -- Return Code
    local rcode = subtree:add(f_rc, buf(offset + 15, 1))
    if ret_codes[buf(offset + 15, 1):uint()] ~= nil then
        rcode:append_text(" (" .. ret_codes[buf(offset + 15, 1):uint()] .. ")")
    end
    
    -- Payload
    pl_length = length_val - 8 -- length field contains also 8 bytes from the header
    
    if (buf(offset + 0, 4):uint() == 0xffff8100) then
        -- SOME/IP SD payload
        Dissector.get("sd"):call(buf(offset + SOMEIP_SD_OFFSET):tvb(), pinfo, root)
    elseif band(buf(offset + 14, 1):uint(), 0x20) ~= 0 then
        -- SOME/IP TP payload
        Dissector.get("someip_tp"):call(buf(offset + SOMEIP_HDR_LEN):tvb(), pinfo, root)
    else
        -- other payload
        subtree:add(f_payload, buf(offset + SOMEIP_HDR_LEN, pl_length))
    end
    
    return (length_val + 8)

end


-- dissection function
function p_someip.dissector(buf, pinfo, root)

    -- get the length of the packet buffer (Tvb).
    local pktlen = buf:len()

    local bytes_consumed = 0
    
    -- we do this in a while loop, because there could be multiple SOME/IP messages
    -- inside a single TCP segment, and thus in the same tvbuf - but our
    -- fpm_proto.dissector() will only be called once per TCP segment, so we
    -- need to do this loop to dissect each SOME/IP message in it
    while bytes_consumed < pktlen do

        -- We're going to call our "dissect()" function
        -- The dissect() function returns the length of the SOME/IP message 
        -- it dissected as a positive number, or if it's a negative number 
        -- then it's the number of additional bytes it needs if the Tvb doesn't have them all.
        --If it returns a 0, it's a dissection error.
        local result = dissect_some_ip(buf, pinfo, root, bytes_consumed)

        if result > 0 then
           
           -- we successfully processed an SOME/IP message, of 'result' length
            bytes_consumed = bytes_consumed + result
            
        elseif result == 0 then
        
            -- If the result is 0, then it means we hit an error of some kind,
            -- so return 0. Returning 0 tells Wireshark this packet is not for
            -- us, and it will try heuristic dissectors or the plain "data"
            -- one, which is what should happen in this case.
            return 0
            
        else
        
            -- we need more bytes, so set the desegment_offset to what we
            -- already consumed, and the desegment_len to how many more
            -- are needed
            pinfo.desegment_offset = bytes_consumed

            -- invert the negative result so it's a positive number
            result = -result

            pinfo.desegment_len = result

            -- even though we need more bytes, this packet is for us, so we
            -- tell wireshark all of its bytes are for us by returning the
            -- number of Tvb bytes we "successfully processed", namely the
            -- length of the Tvb
            return pktlen
            
        end -- if
        
    end -- while

    -- In a TCP dissector, you can either return nothing, or return the number of
    -- bytes of the tvbuf that belong to this protocol, which is what we do here.
    -- Do NOT return the number 0, or else Wireshark will interpret that to mean
    -- this packet did not belong to your protocol, and will try to dissect it
    -- with other protocol dissectors (such as heuristic ones)
    return bytes_consumed

end

-- initialization routine
function p_someip.init()

    -- register protocol
    local udp_dissector_table = DissectorTable.get("udp.port")
    local tcp_dissector_table = DissectorTable.get("tcp.port")

    -- Register dissector to multiple ports
    for i,port in ipairs{29173, 29174, 30490, 30491, 30501, 30502, 30503, 30504} do
    
        udp_dissector_table:add(port, p_someip)
        tcp_dissector_table:add(port, p_someip)
        
    end -- for
    
end


