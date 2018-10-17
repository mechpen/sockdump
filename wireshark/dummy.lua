local dummy_proto = Proto("dummy", "Dummy Protocol")

local dst_field = ProtoField.uint64("dummy.dst", "Destination")
local src_field = ProtoField.uint64("dummy.src", "Source")
dummy_proto.fields = { dst_field, src_field }

local dummy_pdu_proto = Dissector.get("http")

function dummy_proto.dissector(buf, pinfo, tree)
    local subtree = tree:add(dummy_proto, buf(), "Dummy Protocol Data")
    local dst = subtree:add(dst_field, buf(0, 8))
    local src = subtree:add(src_field, buf(8, 8))

    pinfo.cols.protocol = "DUMMY"
    pinfo.cols.dst = tostring(buf(0, 8):uint64())
    pinfo.cols.src = tostring(buf(8, 8):uint64())

    dummy_pdu_proto:call(buf(16):tvb(), pinfo, tree)
end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER0, dummy_proto)
