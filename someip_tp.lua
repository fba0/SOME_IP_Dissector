-- File : someip_tp.lua
-- Who  : x-Felix-x
-- What : SOME/IP-TP dissector

-- bitwise ops helpers
local band, bor = bit.band,bit.bor
local lshift, rshift = bit.lshift,bit.rshift
local tohex = bit.tohex

-- SOME/IP-TP Header
SOME_IP_TP_HEADER_LEN = 4

-- SOME/IP-TP protocol
p_someip_tp = Proto("someip_tp","SOME/IP-TP")

-- SOME/IP-TP
-- 28 bits Offset + 3 bits Reserved + 1 bit More Segment Flag
local f_header = ProtoField.uint32("someip_tp.tp_header", "Header", base.HEX) 
local f_pl     = ProtoField.bytes("someip_tp.tp_payload", "Payload")

p_someip_tp.fields = {f_header, f_pl}

-- SOME/IP-TP dissector
function p_someip_tp.dissector(buf, pinfo, root)

    pinfo.cols.protocol = "SOME/IP-TP"
    
    pl_length = buf:len() - SOME_IP_TP_HEADER_LEN
    
    -- create subtree
    local subtree = root:add(p_someip_tp, buf(0))
    -- add protocol fields to subtree
    tree = subtree:add(f_header, buf(0))
    
    -- get single bit infos
    local tp_offset = band(buf(0, 4):uint(), 0xfffffff0)
    local tp_reserved = band(buf(3, 1):uint(), 0x0e)
    local tp_more_seg = band(buf(3, 1):uint(), 0x01)
    
    -- add to tree
    tree:add("Offset: 0x" .. tohex(tp_offset, 4))
    tree:add("Reserved: 0x" .. tohex(tp_reserved, 1))
    tree:add("More Segment Flag: 0x" .. tohex(tp_more_seg, 1))
    
    if band(buf(3, 1):uint(), 0x01) == 0 then
        tree:append_text(" (Last Segment)")
        pinfo.cols.info = "TP Segment Offset=" .. tp_offset .. " More=False"
    else
        tree:append_text(" (Another segment follows)")
        pinfo.cols.info = "TP Segment Offset=" .. tp_offset .. " More=True"
    end
    
    subtree:add(f_pl, buf(SOME_IP_TP_HEADER_LEN, pl_length))

end