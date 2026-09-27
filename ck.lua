--[[
    CKPROBE - CKProbe dissector
    由 ProtoForge v0.10.0 生成于 2026-09-28
    目标：Wireshark 4.4+（Lua 5.3/5.4）
    授权：使用 Wireshark Lua 绑定的脚本须按 GPLv2+ 分发
    （官方 wiki「Beware the GPL」口径）；可自由使用与修改。
--]]

local proto = Proto("ckprobe", "CKProbe")

local pf_payload = ProtoField.bytes("ckprobe.payload", "payload")
local pf_crc = ProtoField.uint16("ckprobe.crc", "crc", base.HEX, nil)

proto.fields = {
    pf_payload,
    pf_crc,
}

local pe_crc_bad    = ProtoExpert.new("ckprobe.crc.bad",    "CRC-16 mismatch",   expert.group.CHECKSUM, expert.severity.ERROR)
local pe_const_bad  = ProtoExpert.new("ckprobe.const.bad", "Constant mismatch", expert.group.PROTOCOL, expert.severity.WARN)
local pe_len_bad    = ProtoExpert.new("ckprobe.len.bad",   "Length mismatch",   expert.group.MALFORMED, expert.severity.WARN)
local pe_too_short  = ProtoExpert.new("ckprobe.short",     "Packet too short",  expert.group.MALFORMED, expert.severity.ERROR)
proto.experts = { pe_crc_bad, pe_const_bad, pe_len_bad, pe_too_short }

-- CRC-16/MODBUS（reflected, poly 0xA001, init 0xFFFF，传输低字节在前）
local function crc16_modbus(bytes, from, to)
    local crc = 0xFFFF
    for i = from, to do
        crc = (crc ~ bytes:get_index(i)) & 0xFFFF
        for _ = 1, 8 do
            if (crc & 1) ~= 0 then
                crc = (crc >> 1) ~ 0xA001
            else
                crc = crc >> 1
            end
        end
    end
    return crc
end

function proto.dissector(buffer, pinfo, tree)
    local len = buffer:len()
    if len < 11 then
        tree:add_proto_expert_info(pe_too_short, string.format("packet too short: %d bytes (need >= 11)", len))
        return 0
    end
    pinfo.cols.protocol = "CKPROBE"
    local st = tree:add(proto, buffer())
    local off = 0
    st:add(pf_payload, buffer(off, 9))
    off = off + 9
    local v_crc = buffer(off, 2):le_uint()
    local c_crc = crc16_modbus(buffer:bytes(), 0, off - 1)
    local it_crc = st:add(pf_crc, buffer(off, 2))
    if c_crc == v_crc then
        it_crc:append_text(" [correct]")
    else
        it_crc:append_text(string.format(" [incorrect, expected 0x%04X]", c_crc))
        st:add_proto_expert_info(pe_crc_bad, string.format("got 0x%04X, computed 0x%04X", v_crc, c_crc))
    end
    off = off + 2
    if off ~= len then
        st:add_proto_expert_info(pe_len_bad, string.format("%d trailing bytes", len - off))
    end
    return len
end

local tbl_udp_port = DissectorTable.get("udp.port")
tbl_udp_port:add(5592, proto)

