local dummy_proto = Proto("dummy", "Dummy Protocol")

local pathname_field = ProtoField.string("dummy.pathname", "Socket Pathname")
local dst_field = ProtoField.uint64("dummy.dst", "Destination")
local src_field = ProtoField.uint64("dummy.src", "Source")
dummy_proto.fields = { pathname_field, dst_field, src_field }

local dummy_pdu_proto = Dissector.get("http")

local pathname_length_len = 1
local max_pathname_len = 108
local pid_len = 8

function dummy_proto.dissector(buf, pinfo, tree)
    local subtree = tree:add(dummy_proto, buf(), "Dummy Protocol Data")
    local offset = 0

    local pathname_len = buf(offset, pathname_length_len):uint()
    offset = offset + pathname_length_len

    local pathname_string = buf(offset, pathname_len):raw()
    local pathname = subtree:add(pathname_field, buf(0, max_pathname_len + pathname_length_len), pathname_string)
    offset = offset + max_pathname_len

    local src_pid = buf(offset, pid_len):uint64()
    local src = subtree:add(src_field, buf(offset, pid_len))
    offset = offset + pid_len

    local dst_pid = buf(offset, pid_len):uint64()
    local dst = subtree:add(dst_field, buf(offset, pid_len))
    offset = offset + pid_len

    pinfo.cols.protocol = "DUMMY (" .. pathname_string .. ")"
    pinfo.cols.dst = tostring(dst_pid)
    pinfo.cols.src = tostring(src_pid)

    dummy_pdu_proto:call(buf(offset):tvb(), pinfo, tree)
end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER0, dummy_proto)
