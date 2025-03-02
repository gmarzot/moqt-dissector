-- Media over QUIC Transport (MoQT) Protocol Dissector
-- Based on draft-ietf-moq-transport-latest

-- Debug logging setup
local debug = true  -- Always start with debug enabled

-- Create logging function that works reliably with tshark
local function log(text)
    if debug then
        -- Use both print and stderr to maximize chances of seeing output
        io.stderr:write("[MoQT Dissector] " .. text .. "\n")
        io.stderr:flush()  -- Force flush to ensure output appears
    end
end

-- Plugin Info
local moqt_info =
{
    version = "0.1",
    author = "Giovanni Marzot <gmarzot@marzresearch.net>",
    description = "MoQT Protocol Dissector",
}

set_plugin_info(moqt_info)

-- Print during loading to verify script is loaded
log("Creating protocol...")
local moqt = Proto("moqt", "Media over QUIC Transport")

local control_streams = {}

-- PREFERENCES
log("Setting prefs...")
moqt.prefs.debug = Pref.bool("Enable debug logging", true, "Show debug logs in console")
moqt.prefs.udp_port = Pref.uint("UDP Port", 9448, "UDP port for direct MoQT testing")

-- Fields for the MoQT protocol
log("Defining fields and types...")
local fields = {
    -- Common fields
    message_type = ProtoField.uint8("moqt.message_type", "Message Type", base.DEC),
    message_length = ProtoField.uint32("moqt.message_length", "Message Length", base.DEC),
    
    -- Control message common fields
    subscribe_id = ProtoField.uint32("moqt.subscribe_id", "Subscribe ID", base.DEC),
    track_alias = ProtoField.uint32("moqt.track_alias", "Track Alias", base.DEC),
    namespace_tuple_len = ProtoField.uint32("moqt.namespace_tuple_len", "Namespace Tuple Length", base.DEC),
    namespace_field = ProtoField.bytes("moqt.namespace_field", "Namespace Field"),
    track_name_length = ProtoField.uint32("moqt.track_name_length", "Track Name Length", base.DEC),
    track_name = ProtoField.string("moqt.track_name", "Track Name", base.ASCII),
    subscriber_priority = ProtoField.uint8("moqt.subscriber_priority", "Subscriber Priority"),
    group_order = ProtoField.uint8("moqt.group_order", "Group Order"),
    filter_type = ProtoField.uint8("moqt.filter_type", "Filter Type"),
    start_group = ProtoField.uint32("moqt.start_group", "Start Group", base.DEC),
    start_object = ProtoField.uint32("moqt.start_object", "Start Object", base.DEC),
    end_group = ProtoField.uint32("moqt.end_group", "End Group", base.DEC),
    end_object = ProtoField.uint32("moqt.end_object", "End Object", base.DEC),
    
    -- SUBSCRIBE_OK fields
    expires = ProtoField.uint32("moqt.expires", "Expires", base.DEC),
    content_exists = ProtoField.uint8("moqt.content_exists", "Content Exists"),
    largest_group_id = ProtoField.uint32("moqt.largest_group_id", "Largest Group ID", base.DEC),
    largest_object_id = ProtoField.uint32("moqt.largest_object_id", "Largest Object ID", base.DEC),
    
    -- Error fields
    error_code = ProtoField.uint32("moqt.error_code", "Error Code", base.DEC),
    reason_phrase_length = ProtoField.uint32("moqt.reason_phrase_length", "Reason Phrase Length", base.DEC),
    reason_phrase = ProtoField.string("moqt.reason_phrase", "Reason Phrase", base.ASCII),
    
    -- GOAWAY fields
    uri_length = ProtoField.uint32("moqt.uri_length", "URI Length", base.DEC),
    uri = ProtoField.string("moqt.uri", "URI", base.ASCII),
    
    -- SUBSCRIBE_DONE fields
    status_code = ProtoField.uint32("moqt.status_code", "Status Code", base.DEC),
    stream_count = ProtoField.uint32("moqt.stream_count", "Stream Count", base.DEC),
    
    -- Setup fields
    num_supported_versions = ProtoField.uint32("moqt.num_supported_versions", "Number of Supported Versions", base.DEC),
    supported_version = ProtoField.uint32("moqt.supported_version", "Supported Version", base.HEX),
    selected_version = ProtoField.uint32("moqt.selected_version", "Selected Version", base.HEX),
    num_parameters = ProtoField.uint32("moqt.num_parameters", "Number of Parameters", base.DEC),
    
    -- Parameter fields
    parameter_type = ProtoField.uint32("moqt.parameter_type", "Parameter Type", base.DEC),
    parameter_length = ProtoField.uint32("moqt.parameter_length", "Parameter Length", base.DEC),
    parameter_value = ProtoField.bytes("moqt.parameter_value", "Parameter Value"),
    
    -- Data stream fields - common
    group_id = ProtoField.uint32("moqt.group_id", "Group ID", base.DEC),
    object_id = ProtoField.uint32("moqt.object_id", "Object ID", base.DEC),
    subgroup_id = ProtoField.uint32("moqt.subgroup_id", "Subgroup ID", base.DEC),
    publisher_priority = ProtoField.uint8("moqt.publisher_priority", "Publisher Priority"),
    extension_headers_length = ProtoField.uint32("moqt.extension_headers_length", "Extension Headers Length", base.DEC),
    object_payload_length = ProtoField.uint32("moqt.object_payload_length", "Object Payload Length", base.DEC),
    object_status = ProtoField.uint8("moqt.object_status", "Object Status"),
    
    -- Extension header fields
    header_type = ProtoField.uint32("moqt.header_type", "Header Type", base.DEC),
    header_value = ProtoField.uint32("moqt.header_value", "Header Value", base.DEC),
    header_length = ProtoField.uint32("moqt.header_length", "Header Length", base.DEC),
    
    -- Generic
    payload = ProtoField.bytes("moqt.payload", "Payload"),
}

-- Add fields to protocol
moqt.fields = fields

-- Message type mappings
local message_types = {
    [0x2] = "SUBSCRIBE_UPDATE",
    [0x3] = "SUBSCRIBE",
    [0x4] = "SUBSCRIBE_OK",
    [0x5] = "SUBSCRIBE_ERROR",
    [0x6] = "ANNOUNCE",
    [0x7] = "ANNOUNCE_OK",
    [0x8] = "ANNOUNCE_ERROR",
    [0x9] = "UNANNOUNCE",
    [0xA] = "UNSUBSCRIBE",
    [0xB] = "SUBSCRIBE_DONE",
    [0xC] = "ANNOUNCE_CANCEL",
    [0xD] = "TRACK_STATUS_REQUEST",
    [0xE] = "TRACK_STATUS",
    [0x10] = "GOAWAY",
    [0x11] = "SUBSCRIBE_ANNOUNCES",
    [0x12] = "SUBSCRIBE_ANNOUNCES_OK",
    [0x13] = "SUBSCRIBE_ANNOUNCES_ERROR",
    [0x14] = "UNSUBSCRIBE_ANNOUNCES",
    [0x15] = "MAX_SUBSCRIBE_ID",
    [0x1A] = "SUBSCRIBES_BLOCKED",
    [0x16] = "FETCH",
    [0x17] = "FETCH_CANCEL",
    [0x18] = "FETCH_OK",
    [0x19] = "FETCH_ERROR",
    [0x40] = "CLIENT_SETUP",
    [0x41] = "SERVER_SETUP"
}

-- Stream type mappings
local stream_types = {
    [0x4] = "SUBGROUP_HEADER",
    [0x5] = "FETCH_HEADER"
}

-- Datagram type mappings
local datagram_types = {
    [0x1] = "OBJECT_DATAGRAM",
    [0x2] = "OBJECT_DATAGRAM_STATUS"
}

-- Filter type mappings
local filter_types = {
    [0x2] = "Latest Object",
    [0x3] = "AbsoluteStart",
    [0x4] = "AbsoluteRange"
}

-- Group order mappings
local group_order_values = {
    [0x0] = "Use Publisher Order",
    [0x1] = "Ascending",
    [0x2] = "Descending"
}

-- Object status mappings
local object_status_values = {
    [0x0] = "Normal",
    [0x1] = "Object Does Not Exist",
    [0x3] = "End of Group",
    [0x4] = "End of Track and Group",
    [0x5] = "End of Track"
}

-- Setup parameter mappings
local setup_param_types = {
    [0x01] = "PATH",
    [0x02] = "MAX_SUBSCRIBE_ID"
}

-- Version-specific parameter mappings
local version_param_types = {
    [0x02] = "AUTHORIZATION_INFO",
    [0x03] = "DELIVERY_TIMEOUT",
    [0x04] = "MAX_CACHE_DURATION"
}

-- Error code mappings
local error_codes = {
    [0x0] = "Internal Error",
    [0x1] = "Unauthorized",
    [0x2] = "Timeout",
    [0x3] = "Not Supported",
    [0x4] = "Track Does Not Exist",
    [0x5] = "Invalid Range",
    [0x6] = "Retry Track Alias"
}

-- Status code mappings
local status_codes = {
    [0x0] = "Internal Error",
    [0x1] = "Unauthorized",
    [0x2] = "Track Ended",
    [0x3] = "Subscription Ended",
    [0x4] = "Going Away",
    [0x5] = "Expired",
    [0x6] = "Too Far Behind"
}

-- VARINT decoding helper function
local function decode_varint(tvb, offset)
    if offset >= tvb:len() then
        return nil, offset
    end
    
    local first_byte = tvb(offset, 1):uint()
    local len = 1
    
    if bit.band(first_byte, 0xc0) == 0x40 then -- 01xxxxxx
        len = 2
    elseif bit.band(first_byte, 0xc0) == 0x80 then -- 10xxxxxx
        len = 4
    elseif bit.band(first_byte, 0xc0) == 0xc0 then -- 11xxxxxx
        len = 8
    end
    
    if offset + len > tvb:len() then
        return nil, offset
    end
    
    -- Calculate the value based on the length
    local mask = 0x3f -- 00111111
    if len == 1 then
        mask = 0x7f -- 01111111
    end
    
    local value = bit.band(first_byte, mask)
    
    for i = 1, len - 1 do
        value = bit.bor(bit.lshift(value, 8), tvb(offset + i, 1):uint())
    end
    
    return value, offset + len
end

-- Parse track namespace tuple
local function parse_namespace_tuple(tvb, offset, tree)
    -- Parse number of tuple elements
    local tuple_len, new_offset = decode_varint(tvb, offset)
    if not tuple_len then return offset end
    tree:add(fields.namespace_tuple_len, tvb(offset, new_offset - offset), tuple_len)
    offset = new_offset
    
    -- Parse each tuple element
    for i = 1, tuple_len do
        local field_length, new_offset = decode_varint(tvb, offset)
        if not field_length then return offset end
        offset = new_offset
        
        if offset + field_length > tvb:len() then
            return offset  -- Not enough data
        end
        
        tree:add(fields.namespace_field, tvb(offset, field_length))
        offset = offset + field_length
    end
    
    return offset
end

-- Parse a string field with length prefix
local function parse_string(tvb, offset, tree, length_field, string_field)
    local str_len, new_offset = decode_varint(tvb, offset)
    if not str_len then return offset end
    tree:add(length_field, tvb(offset, new_offset - offset), str_len)
    offset = new_offset
    
    if str_len > 0 then
        if offset + str_len > tvb:len() then
            return offset  -- Not enough data
        end
        tree:add(string_field, tvb(offset, str_len))
        offset = offset + str_len
    end
    
    return offset
end

-- Parse parameters
local function parse_parameters(tvb, offset, tree, num_parameters, is_setup)
    local param_types = is_setup and setup_param_types or version_param_types
    
    for i = 1, num_parameters do
        local param_tree = tree:add(moqt, tvb(offset), "Parameter")
        
        -- Parse parameter type
        local param_type, new_offset = decode_varint(tvb, offset)
        if not param_type then return offset end
        local param_type_item = param_tree:add(fields.parameter_type, tvb(offset, new_offset - offset), param_type)
        if param_types[param_type] then
            param_type_item:append_text(" (" .. param_types[param_type] .. ")")
        end
        offset = new_offset
        
        -- Parse parameter length
        local param_length, new_offset = decode_varint(tvb, offset)
        if not param_length then return offset end
        param_tree:add(fields.parameter_length, tvb(offset, new_offset - offset), param_length)
        offset = new_offset
        
        -- Add parameter value
        if param_length > 0 then
            if offset + param_length > tvb:len() then
                return offset  -- Not enough data
            end
            param_tree:add(fields.parameter_value, tvb(offset, param_length))
            offset = offset + param_length
        end
    end
    
    return offset
end

-- Parse extension headers
local function parse_extension_headers(tvb, offset, tree, total_length)
    local end_offset = offset + total_length
    
    while offset < end_offset do
        local header_tree = tree:add(moqt, tvb(offset), "Extension Header")
        
        -- Parse header type
        local header_type, new_offset = decode_varint(tvb, offset)
        if not header_type then return offset end
        header_tree:add(fields.header_type, tvb(offset, new_offset - offset), header_type)
        offset = new_offset
        
        -- Parse header value based on type (even or odd)
        if bit.band(header_type, 1) == 0 then
            -- Even type - single varint value
            local value, new_offset = decode_varint(tvb, offset)
            if not value then return offset end
            header_tree:add(fields.header_value, tvb(offset, new_offset - offset), value)
            offset = new_offset
        else
            -- Odd type - length followed by value
            local length, new_offset = decode_varint(tvb, offset)
            if not length then return offset end
            header_tree:add(fields.header_length, tvb(offset, new_offset - offset), length)
            offset = new_offset
            
            if offset + length > tvb:len() then
                return offset  -- Not enough data
            end
            
            header_tree:add(fields.parameter_value, tvb(offset, length))
            offset = offset + length
        end
    end
    
    return offset
end

-- Parse CLIENT_SETUP message
local function parse_client_setup(tvb, offset, subtree)
    -- Parse number of supported versions
    local num_versions, new_offset = decode_varint(tvb, offset)
    if not num_versions then return offset end
    subtree:add(fields.num_supported_versions, tvb(offset, new_offset - offset), num_versions)
    offset = new_offset
    
    -- Parse supported versions
    for i = 1, num_versions do
        local version, new_offset = decode_varint(tvb, offset)
        if not version then return offset end
        subtree:add(fields.supported_version, tvb(offset, new_offset - offset), version)
        offset = new_offset
    end
    
    -- Parse number of parameters
    local num_params, new_offset = decode_varint(tvb, offset)
    if not num_params then return offset end
    subtree:add(fields.num_parameters, tvb(offset, new_offset - offset), num_params)
    offset = new_offset
    
    -- Parse parameters
    return parse_parameters(tvb, offset, subtree, num_params, true)
end

-- Parse SERVER_SETUP message
local function parse_server_setup(tvb, offset, subtree)
    -- Parse selected version
    local version, new_offset = decode_varint(tvb, offset)
    if not version then return offset end
    subtree:add(fields.selected_version, tvb(offset, new_offset - offset), version)
    offset = new_offset
    
    -- Parse number of parameters
    local num_params, new_offset = decode_varint(tvb, offset)
    if not num_params then return offset end
    subtree:add(fields.num_parameters, tvb(offset, new_offset - offset), num_params)
    offset = new_offset
    
    -- Parse parameters
    return parse_parameters(tvb, offset, subtree, num_params, true)
end

-- Parse SUBSCRIBE message
local function parse_subscribe(tvb, offset, subtree)
    -- Parse Subscribe ID
    local subscribe_id, new_offset = decode_varint(tvb, offset)
    if not subscribe_id then return offset end
    subtree:add(fields.subscribe_id, tvb(offset, new_offset - offset), subscribe_id)
    offset = new_offset
    
    -- Parse Track Alias
    local track_alias, new_offset = decode_varint(tvb, offset)
    if not track_alias then return offset end
    subtree:add(fields.track_alias, tvb(offset, new_offset - offset), track_alias)
    offset = new_offset
    
    -- Parse Track Namespace
    offset = parse_namespace_tuple(tvb, offset, subtree)
    
    -- Parse Track Name
    offset = parse_string(tvb, offset, subtree, fields.track_name_length, fields.track_name)
    
    -- Parse Subscriber Priority
    if offset + 1 > tvb:len() then return offset end
    subtree:add(fields.subscriber_priority, tvb(offset, 1))
    offset = offset + 1
    
    -- Parse Group Order
    if offset + 1 > tvb:len() then return offset end
    local group_order = tvb(offset, 1):uint()
    local group_order_item = subtree:add(fields.group_order, tvb(offset, 1))
    if group_order_values[group_order] then
        group_order_item:append_text(" (" .. group_order_values[group_order] .. ")")
    end
    offset = offset + 1
    
    -- Parse Filter Type
    local filter_type, new_offset = decode_varint(tvb, offset)
    if not filter_type then return offset end
    local filter_type_item = subtree:add(fields.filter_type, tvb(offset, new_offset - offset), filter_type)
    if filter_types[filter_type] then
        filter_type_item:append_text(" (" .. filter_types[filter_type] .. ")")
    end
    offset = new_offset
    
    -- Parse additional fields based on filter type
    if filter_type == 0x3 or filter_type == 0x4 then
        -- Parse StartGroup and StartObject for AbsoluteStart and AbsoluteRange
        local start_group, new_offset = decode_varint(tvb, offset)
        if not start_group then return offset end
        subtree:add(fields.start_group, tvb(offset, new_offset - offset), start_group)
        offset = new_offset
        
        local start_object, new_offset = decode_varint(tvb, offset)
        if not start_object then return offset end
        subtree:add(fields.start_object, tvb(offset, new_offset - offset), start_object)
        offset = new_offset
    end
    
    if filter_type == 0x4 then
        -- Parse EndGroup for AbsoluteRange
        local end_group, new_offset = decode_varint(tvb, offset)
        if not end_group then return offset end
        subtree:add(fields.end_group, tvb(offset, new_offset - offset), end_group)
        offset = new_offset
    end
    
    -- Parse number of parameters
    local num_params, new_offset = decode_varint(tvb, offset)
    if not num_params then return offset end
    subtree:add(fields.num_parameters, tvb(offset, new_offset - offset), num_params)
    offset = new_offset
    
    -- Parse parameters
    return parse_parameters(tvb, offset, subtree, num_params, false)
end

-- Parse SUBSCRIBE_OK message
local function parse_subscribe_ok(tvb, offset, subtree)
    -- Parse Subscribe ID
    local subscribe_id, new_offset = decode_varint(tvb, offset)
    if not subscribe_id then return offset end
    subtree:add(fields.subscribe_id, tvb(offset, new_offset - offset), subscribe_id)
    offset = new_offset
    
    -- Parse Expires
    local expires, new_offset = decode_varint(tvb, offset)
    if not expires then return offset end
    subtree:add(fields.expires, tvb(offset, new_offset - offset), expires)
    offset = new_offset
    
    -- Parse Group Order
    if offset + 1 > tvb:len() then return offset end
    local group_order = tvb(offset, 1):uint()
    local group_order_item = subtree:add(fields.group_order, tvb(offset, 1))
    if group_order_values[group_order] then
        group_order_item:append_text(" (" .. group_order_values[group_order] .. ")")
    end
    offset = offset + 1
    
    -- Parse ContentExists
    if offset + 1 > tvb:len() then return offset end
    local content_exists = tvb(offset, 1):uint()
    subtree:add(fields.content_exists, tvb(offset, 1))
    offset = offset + 1
    
    -- Parse Largest Group ID and Largest Object ID if content exists
    if content_exists == 1 then
        local largest_group, new_offset = decode_varint(tvb, offset)
        if not largest_group then return offset end
        subtree:add(fields.largest_group_id, tvb(offset, new_offset - offset), largest_group)
        offset = new_offset
        
        local largest_object, new_offset = decode_varint(tvb, offset)
        if not largest_object then return offset end
        subtree:add(fields.largest_object_id, tvb(offset, new_offset - offset), largest_object)
        offset = new_offset
    end
    
    -- Parse number of parameters
    local num_params, new_offset = decode_varint(tvb, offset)
    if not num_params then return offset end
    subtree:add(fields.num_parameters, tvb(offset, new_offset - offset), num_params)
    offset = new_offset
    
    -- Parse parameters
    return parse_parameters(tvb, offset, subtree, num_params, false)
end

-- Parse SUBSCRIBE_ERROR message
local function parse_subscribe_error(tvb, offset, subtree)
    -- Parse Subscribe ID
    local subscribe_id, new_offset = decode_varint(tvb, offset)
    if not subscribe_id then return offset end
    subtree:add(fields.subscribe_id, tvb(offset, new_offset - offset), subscribe_id)
    offset = new_offset
    
    -- Parse Error Code
    local error_code, new_offset = decode_varint(tvb, offset)
    if not error_code then return offset end
    local error_code_item = subtree:add(fields.error_code, tvb(offset, new_offset - offset), error_code)
    if error_codes[error_code] then
        error_code_item:append_text(" (" .. error_codes[error_code] .. ")")
    end
    offset = new_offset
    
    -- Parse Reason Phrase
    offset = parse_string(tvb, offset, subtree, fields.reason_phrase_length, fields.reason_phrase)
    
    -- Parse Track Alias
    local track_alias, new_offset = decode_varint(tvb, offset)
    if not track_alias then return offset end
    subtree:add(fields.track_alias, tvb(offset, new_offset - offset), track_alias)
    offset = new_offset
    
    return offset
end

-- Parse ANNOUNCE message
local function parse_announce(tvb, offset, subtree)
    -- Parse Track Namespace
    offset = parse_namespace_tuple(tvb, offset, subtree)
    
    -- Parse number of parameters
    local num_params, new_offset = decode_varint(tvb, offset)
    if not num_params then return offset end
    subtree:add(fields.num_parameters, tvb(offset, new_offset - offset), num_params)
    offset = new_offset
    
    -- Parse parameters
    return parse_parameters(tvb, offset, subtree, num_params, false)
end

-- Parse UNANNOUNCE message
local function parse_unannounce(tvb, offset, subtree)
    -- Parse Track Namespace
    return parse_namespace_tuple(tvb, offset, subtree)
end

-- Parse UNSUBSCRIBE message
local function parse_unsubscribe(tvb, offset, subtree)
    -- Parse Subscribe ID
    local subscribe_id, new_offset = decode_varint(tvb, offset)
    if not subscribe_id then return offset end
    subtree:add(fields.subscribe_id, tvb(offset, new_offset - offset), subscribe_id)
    return new_offset
end

-- Parse SUBSCRIBE_DONE message
local function parse_subscribe_done(tvb, offset, subtree)
    -- Parse Subscribe ID
    local subscribe_id, new_offset = decode_varint(tvb, offset)
    if not subscribe_id then return offset end
    subtree:add(fields.subscribe_id, tvb(offset, new_offset - offset), subscribe_id)
    offset = new_offset
    
    -- Parse Status Code
    local status_code, new_offset = decode_varint(tvb, offset)
    if not status_code then return offset end
    local status_code_item = subtree:add(fields.status_code, tvb(offset, new_offset - offset), status_code)
    if status_codes[status_code] then
        status_code_item:append_text(" (" .. status_codes[status_code] .. ")")
    end
    offset = new_offset
    
    -- Parse Stream Count
    local stream_count, new_offset = decode_varint(tvb, offset)
    if not stream_count then return offset end
    subtree:add(fields.stream_count, tvb(offset, new_offset - offset), stream_count)
    offset = new_offset
    
    -- Parse Reason Phrase
    return parse_string(tvb, offset, subtree, fields.reason_phrase_length, fields.reason_phrase)
end

-- Parse GOAWAY message
local function parse_goaway(tvb, offset, subtree)
    -- Parse New Session URI Length and URI
    return parse_string(tvb, offset, subtree, fields.uri_length, fields.uri)
end

-- Parse SUBSCRIBE_UPDATE message
local function parse_subscribe_update(tvb, offset, subtree)
    -- Parse Subscribe ID
    local subscribe_id, new_offset = decode_varint(tvb, offset)
    if not subscribe_id then return offset end
    subtree:add(fields.subscribe_id, tvb(offset, new_offset - offset), subscribe_id)
    offset = new_offset
    
    -- Parse StartGroup
    local start_group, new_offset = decode_varint(tvb, offset)
    if not start_group then return offset end
    subtree:add(fields.start_group, tvb(offset, new_offset - offset), start_group)
    offset = new_offset
    
    -- Parse StartObject
    local start_object, new_offset = decode_varint(tvb, offset)
    if not start_object then return offset end
    subtree:add(fields.start_object, tvb(offset, new_offset - offset), start_object)
    offset = new_offset
    
    -- Parse EndGroup
    local end_group, new_offset = decode_varint(tvb, offset)
    if not end_group then return offset end
    subtree:add(fields.end_group, tvb(offset, new_offset - offset), end_group)
    offset = new_offset
    
    -- Parse Subscriber Priority
    if offset + 1 > tvb:len() then return offset end
    subtree:add(fields.subscriber_priority, tvb(offset, 1))
    offset = offset + 1
    
    -- Parse number of parameters
    local num_params, new_offset = decode_varint(tvb, offset)
    if not num_params then return offset end
    subtree:add(fields.num_parameters, tvb(offset, new_offset - offset), num_params)
    offset = new_offset
    
    -- Parse parameters
    return parse_parameters(tvb, offset, subtree, num_params, false)
end

-- Parse OBJECT_DATAGRAM message
local function parse_object_datagram(tvb, offset, subtree)
    -- Parse Track Alias
    local track_alias, new_offset = decode_varint(tvb, offset)
    if not track_alias then return offset end
    subtree:add(fields.track_alias, tvb(offset, new_offset - offset), track_alias)
    offset = new_offset
    
    -- Parse Group ID
    local group_id, new_offset = decode_varint(tvb, offset)
    if not group_id then return offset end
    subtree:add(fields.group_id, tvb(offset, new_offset - offset), group_id)
    offset = new_offset
    
    -- Parse Object ID
    local object_id, new_offset = decode_varint(tvb, offset)
    if not object_id then return offset end
    subtree:add(fields.object_id, tvb(offset, new_offset - offset), object_id)
    offset = new_offset
    
    -- Parse Publisher Priority
    if offset + 1 > tvb:len() then return offset end
    subtree:add(fields.publisher_priority, tvb(offset, 1))
    offset = offset + 1
    
    -- Parse Extension Headers Length
    local ext_headers_len, new_offset = decode_varint(tvb, offset)
    if not ext_headers_len then return offset end
    subtree:add(fields.extension_headers_length, tvb(offset, new_offset - offset), ext_headers_len)
    offset = new_offset
    
    -- Parse Extension Headers if present
    if ext_headers_len > 0 then
        if offset + ext_headers_len > tvb:len() then return offset end
        local ext_tree = subtree:add(moqt, tvb(offset, ext_headers_len), "Extension Headers")
        offset = parse_extension_headers(tvb, offset, ext_tree, ext_headers_len)
    end
    
    -- The rest is the payload
    if offset < tvb:len() then
        subtree:add(fields.payload, tvb(offset))
    end
    
    return offset
end

-- Main dissection function
-- Define fields to extract
local f_udp_port = Field.new("udp.port")
local f_quic_initiator = Field.new("quic.stream.initiator")
local f_quic_direction = Field.new("quic.stream.direction")
local f_quic_stream_id = Field.new("quic.stream.stream_id")
local f_quic_stream_data = Field.new("quic.stream_data")

function moqt.dissector(tvb, pinfo, tree)
    log("MoQT dissector called with " .. tvb:len() .. " bytes")
    
    if tvb:len() == 0 then return 0 end

    local udp_port = f_udp_port()
    local quic_initiator = f_quic_initiator()
    local quic_direction = f_quic_direction()
    local quic_stream_id = f_quic_stream_id()

    if not quic_stream_id or quic_stream_id.value == 0 then return 0 end
    if not udp_port or udp_port.value ~= moqt.prefs.udp_port then return 0 end
    if not quic_initiator or not quic_initiator.display:find("^Client%-initiated") then return 0 end
    if not quic_direction or not quic_direction.display:find("^Bidirectional") then return 0 end

    local stream_id = quic_stream_id.value
    local quic_stream_data = f_quic_stream_data()
    local tvb = quic_stream_data.range()

    local val, offset
    if not control_streams[stream_id] then
        val, offset = decode_varint(tvb, 0)
        val, offset = decode_varint(tvb, offset)
        control_streams[stream_id] = true
    end

    -- Check if first byte matches a known message type
    local first_byte = tvb(offset,1):uint()
    if message_types[first_byte] == nil then
        --    and stream_types[first_byte] ~= nil
        --    and datagram_types[first_byte] ~= nil
        log("unable to detect MoQT Control Message: " .. stream_id)
        return 0
    end

    pinfo.cols.protocol = "MoQT"
    local moqt_tree = tree:add(moqt, "Media over QUIC Transport")
    
    -- Parse message type
    local msg_type, new_offset = decode_varint(tvb, 0)
    if not msg_type then 
        log("Failed to decode varint for message type")
        return 0 
    end
    
    local msg_type_item = moqt_tree:add(fields.message_type, tvb(0, new_offset - 0), msg_type)
    local msg_name = nil
    
    if message_types[msg_type] then
        msg_name = message_types[msg_type]
        msg_type_item:append_text(" (" .. msg_name .. ")")
    elseif stream_types[msg_type] then
        msg_name = stream_types[msg_type]
        msg_type_item:append_text(" (" .. msg_name .. ")")
    elseif datagram_types[msg_type] then
        msg_name = datagram_types[msg_type]
        msg_type_item:append_text(" (" .. msg_name .. ")")
    end
    
    if msg_name then
        pinfo.cols.info = msg_name
    else
        pinfo.cols.info = "Unknown MoQT message type: " .. msg_type
    end
    
    -- For now, just add the rest as payload
    if new_offset < tvb:len() then
        moqt_tree:add(fields.payload, tvb(new_offset))
    end
end

register_postdissector(moqt)

log("Registration complete")

return moqt