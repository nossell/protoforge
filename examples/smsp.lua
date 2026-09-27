--[[
    SMSP - SmartMesh Sensor Protocol dissector
    由 ProtoForge v0.10.0 生成于 2026-09-28
    目标：Wireshark 4.4+（Lua 5.3/5.4）
    授权：使用 Wireshark Lua 绑定的脚本须按 GPLv2+ 分发
    （官方 wiki「Beware the GPL」口径）；可自由使用与修改。
--]]

local proto = Proto("smsp", "SmartMesh Sensor Protocol")

local vs_msgType = {
    [1] = "Telemetry",
    [2] = "Config",
    [3] = "Event",
}
local vs_quality = {
    [0] = "Poor",
    [1] = "Fair",
    [2] = "Good",
    [3] = "Excellent",
}
local vs_eventCode = {
    [1] = "Boot",
    [2] = "Reset",
    [3] = "Low Battery",
    [4] = "Sensor Failure",
}

local pf_magic = ProtoField.uint16("smsp.magic", "Magic", base.HEX, nil)
local pf_version = ProtoField.uint8("smsp.version", "Protocol Version", base.DEC, nil, 0xF0)
local pf_msgType = ProtoField.uint8("smsp.msgType", "Message Type", base.DEC, vs_msgType, 0x0F)
local pf_seqNum = ProtoField.uint8("smsp.seqNum", "Sequence Number", base.DEC, nil)
local pf_payloadLen = ProtoField.uint16("smsp.payloadLen", "Payload Length", base.DEC, nil)
local pf_payload = ProtoField.none("smsp.payload", "Payload")
local pf_sensorCount = ProtoField.uint8("smsp.sensorCount", "Sensor Count", base.DEC, nil)
local pf_sensors = ProtoField.none("smsp.sensors", "Sensor")
local pf_sensorId = ProtoField.uint16("smsp.sensorId", "Sensor ID", base.HEX, nil)
local pf_online = ProtoField.bool("smsp.online", "Online", 8, nil, 0x80)
local pf_batteryLow = ProtoField.bool("smsp.batteryLow", "Battery Low", 8, nil, 0x40)
local pf_calibrated = ProtoField.bool("smsp.calibrated", "Calibrated", 8, nil, 0x20)
local pf_flagsRsv = ProtoField.uint8("smsp.flagsRsv", "Flags Rsv", base.DEC, nil, 0x1F)
local pf_value = ProtoField.int16("smsp.value", "Raw Value", base.DEC, nil)
local pf_quality = ProtoField.uint8("smsp.quality", "Quality", base.DEC, vs_quality)
local pf_cfgVersion = ProtoField.uint8("smsp.cfgVersion", "Config Version", base.DEC, nil)
local pf_intervalMs = ProtoField.uint16("smsp.intervalMs", "Report Interval (ms)", base.DEC, nil)
local pf_thresholds = ProtoField.none("smsp.thresholds", "Threshold")
local pf_threshold = ProtoField.int16("smsp.threshold", "Alert Threshold", base.DEC, nil)
local pf_eventCode = ProtoField.uint8("smsp.eventCode", "Event Code", base.DEC, vs_eventCode)
local pf_timestamp = ProtoField.uint32("smsp.timestamp", "Timestamp (UTC)", base.DEC, nil)
local pf_crc16 = ProtoField.uint16("smsp.crc16", "CRC-16/CCITT", base.HEX, nil)

proto.fields = {
    pf_magic,
    pf_version,
    pf_msgType,
    pf_seqNum,
    pf_payloadLen,
    pf_payload,
    pf_sensorCount,
    pf_sensors,
    pf_sensorId,
    pf_online,
    pf_batteryLow,
    pf_calibrated,
    pf_flagsRsv,
    pf_value,
    pf_quality,
    pf_cfgVersion,
    pf_intervalMs,
    pf_thresholds,
    pf_threshold,
    pf_eventCode,
    pf_timestamp,
    pf_crc16,
}

local pe_crc_bad    = ProtoExpert.new("smsp.crc.bad",    "CRC-16 mismatch",   expert.group.CHECKSUM, expert.severity.ERROR)
local pe_const_bad  = ProtoExpert.new("smsp.const.bad", "Constant mismatch", expert.group.PROTOCOL, expert.severity.WARN)
local pe_len_bad    = ProtoExpert.new("smsp.len.bad",   "Length mismatch",   expert.group.MALFORMED, expert.severity.WARN)
local pe_too_short  = ProtoExpert.new("smsp.short",     "Packet too short",  expert.group.MALFORMED, expert.severity.ERROR)
proto.experts = { pe_crc_bad, pe_const_bad, pe_len_bad, pe_too_short }

-- CRC-16/CCITT-FALSE（poly 0x1021, init 0xFFFF）
local function crc16_ccitt(bytes, from, to)
    local crc = 0xFFFF
    for i = from, to do
        crc = (crc ~ (bytes:get_index(i) << 8)) & 0xFFFF
        for _ = 1, 8 do
            if (crc & 0x8000) ~= 0 then
                crc = ((crc << 1) ~ 0x1021) & 0xFFFF
            else
                crc = (crc << 1) & 0xFFFF
            end
        end
    end
    return crc
end

function proto.dissector(buffer, pinfo, tree)
    local len = buffer:len()
    if len < 8 then
        tree:add_proto_expert_info(pe_too_short, string.format("packet too short: %d bytes (need >= 8)", len))
        return 0
    end
    pinfo.cols.protocol = "SMSP"
    local st = tree:add(proto, buffer())
    local off = 0
    local v_magic = buffer(off, 2):uint()
    st:add(pf_magic, buffer(off, 2))
    if v_magic ~= 0x5a5a then
        st:add_proto_expert_info(pe_const_bad, string.format("expected 0x5a5a, got 0x%04X", v_magic))
    end
    off = off + 2
    st:add(pf_version, buffer(off, 1))
    local v_msgType = buffer(off, 1):bitfield(4, 4)
    st:add(pf_msgType, buffer(off, 1))
    off = off + 1
    local v_seqNum = buffer(off, 1):uint()
    st:add(pf_seqNum, buffer(off, 1))
    off = off + 1
    local v_payloadLen = buffer(off, 2):uint()
    st:add(pf_payloadLen, buffer(off, 2))
    off = off + 2
    pinfo.cols.info = table.concat({string.format("%s", vs_msgType[v_msgType] or string.format("Unknown(%d)", v_msgType)), string.format("Seq=%d", v_seqNum)}, ", ")
    if v_payloadLen ~= len - 6 - 2 then
        st:add_proto_expert_info(pe_len_bad, string.format("payloadLen=%d, 但按帧长 %d 应为 %d", v_payloadLen, len, len - 6 - 2))
    end
    local st_payload = st:add(pf_payload, buffer(off, math.max(0, len - off - 2)))
    if v_msgType == 1 then
        local v_sensorCount = buffer(off, 1):uint()
        st_payload:add(pf_sensorCount, buffer(off, 1))
        off = off + 1
        for i = 1, v_sensorCount do
            local st_sensors = st_payload:add(buffer(off, 6), "Sensor [" .. (i - 1) .. "]")
            st_sensors:add(pf_sensorId, buffer(off, 2))
            off = off + 2
            st_sensors:add(pf_online, buffer(off, 1))
            st_sensors:add(pf_batteryLow, buffer(off, 1))
            st_sensors:add(pf_calibrated, buffer(off, 1))
            st_sensors:add(pf_flagsRsv, buffer(off, 1))
            off = off + 1
            st_sensors:add(pf_value, buffer(off, 2))
            off = off + 2
            st_sensors:add(pf_quality, buffer(off, 1))
            off = off + 1
        end
    elseif v_msgType == 2 then
        st_payload:add(pf_cfgVersion, buffer(off, 1))
        off = off + 1
        st_payload:add(pf_intervalMs, buffer(off, 2))
        off = off + 2
        for i = 1, 3 do
            local st_thresholds = st_payload:add(buffer(off, 2), "Threshold [" .. (i - 1) .. "]")
            st_thresholds:add(pf_threshold, buffer(off, 2))
            off = off + 2
        end
    elseif v_msgType == 3 then
        st_payload:add(pf_eventCode, buffer(off, 1))
        off = off + 1
        st_payload:add(pf_timestamp, buffer(off, 4))
        off = off + 4
    else
        st_payload:append_text(string.format(" (unknown msgType %d)", v_msgType))
    end
    local v_crc16 = buffer(off, 2):uint()
    local c_crc16 = crc16_ccitt(buffer:bytes(), 0, off - 1)
    local it_crc16 = st:add(pf_crc16, buffer(off, 2))
    if c_crc16 == v_crc16 then
        it_crc16:append_text(" [correct]")
    else
        it_crc16:append_text(string.format(" [incorrect, expected 0x%04X]", c_crc16))
        st:add_proto_expert_info(pe_crc_bad, string.format("got 0x%04X, computed 0x%04X", v_crc16, c_crc16))
    end
    off = off + 2
    if off ~= len then
        st:add_proto_expert_info(pe_len_bad, string.format("%d trailing bytes", len - off))
    end
    return len
end

local tbl_udp_port = DissectorTable.get("udp.port")
tbl_udp_port:add(5566, proto)
tbl_udp_port:add(5567, proto)

