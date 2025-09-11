-- Copyright (C) Anjia (anjia0532)

local json = require('cjson')
local resty_rsa = require("resty.rsa")
local str = require("resty.string")
local base64_encode = ngx.encode_base64
local json_encode = json.encode
local json_decode = json.decode
json.encode_empty_table_as_object(false)

local _M = {}

local ASNKEY = [[
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALecq3BwAI4YJZwhJ+snnDFj3lF3DMqNPorV6y5ZKXCiCMqj8OeOmxk4YZW9aaV9
ckl/zlAOI0mpB3pDT+Xlj2sCAwEAAQJAW6/aVD05qbsZHMvZuS2Aa5FpNNj0BDlf38hOtkhDzz/h
kYb+EBYLLvldhgsD0OvRNy8yhz7EjaUqLCB0juIN4QIhAOeCQp+NXxfBmfdG/S+XbRUAdv8iHBl+
F6O2wr5fA2jzAiEAywlDfGIl6acnakPrmJE0IL8qvuO3FtsHBrpkUuOnXakCIQCqdr+XvADI/UTh
TuQepuErFayJMBSAsNe3NFsw0cUxAQIgGA5n7ZPfdBi3BdM4VeJWb87WrLlkVxPqeDSbcGrCyMkC
IFSs5JyXvFTreWt7IQjDssrKDRIPmALdNjvfETwlNJyY
-----END RSA PRIVATE KEY-----
]]

local PCKS8KEY = [[
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAND3cI/pKMSd4OLMIXU/8xoEZ/nz
a+g00Vy7ygyGB1Nn83qpro7tckOvUVILJoN0pKw8J3E8rtjhSyr9849qzaQKBhxFL+J5uu08QVn/
tMt+Tf0cu5MSPOjT8I2+NWyBZ6H0FjOcVrEUMvHt8sqoJDrDU4pJyex2rCOlpfBeqK6XAgMBAAEC
gYBM5C+8FIxWxM1CRuCs1yop0aM82vBC0mSTXdo7/3lknGSAJz2/A+o+s50Vtlqmll4drkjJJw4j
acsR974OcLtXzQrZ0G1ohCM55lC3kehNEbgQdBpagOHbsFa4miKnlYys537Wp+Q61mhGM1weXzos
gCH/7e/FjJ5uS6DhQc0Y+QJBAP43hlSSEo1BbuanFfp55yK2Y503ti3Rgf1SbE+JbUvIIRsvB24x
Ha1/IZ+ttkAuIbOUomLN7fyyEYLWphIy9kUCQQDSbqmxZaJNRa1o4ozGRORxR2KBqVn3EVISXqNc
UH3gAP52U9LcnmA3NMSZs8tzXhUhYkWQ75Q6umXvvDm4XZ0rAkBoymyWGeyJy8oyS/fUW0G63mIr
oZZ4Rp+F098P3j9ueJ2k/frbImXwabJrhwjUZe/Afel+PxL2ElUDkQW+BMHdAkEAk/U7W4Aanjpf
s1+Xm9DUztFicciheRa0njXspvvxhY8tXAWUPYseG7L+iRPh+Twtn0t5nm7VynVFN0shSoCIAQJA
Ljo7A6bzsvfnJpV+lQiOqD/WCw3A2yPwe+1d0X/13fQkgzcbB3K0K81Euo/fkKKiBv0A7yR7wvrN
jzefE9sKUw==
-----END PRIVATE KEY-----
]]

_M._VERSION = '0.0.4'

local mt = { __index = _M }

-- 创建使用PKCS1格式私钥和MD5算法的RSA签名实例
-- 用于处理JRebel相关请求的签名验证
local priv1, err = resty_rsa:new({
  private_key = ASNKEY,
  key_type = resty_rsa.KEY_TYPE.PKCS1,
  algorithm = "md5"
})

-- 创建使用PKCS8格式私钥和SHA1算法的RSA签名实例
-- 用于处理IDEA相关请求的签名验证
local priv8, err = resty_rsa:new({
  private_key = PCKS8KEY,
  key_type = resty_rsa.KEY_TYPE.PKCS8,
  algorithm = "SHA1"
})

-- 使用PKCS1私钥对内容进行签名，并将结果转换为十六进制字符串
-- @param content 需要签名的内容
-- @return 签名结果的十六进制字符串表示，如果签名失败则返回nil和错误信息
local function sign1(content)
  local sig, err = priv1:sign(content)
  if not sig then
    ngx.log(ngx.ERR, "failed to sign:", err)
    return nil, err
  end
  return str.to_hex(sig), nil
end

-- 使用PKCS8私钥对内容进行签名，并将结果进行Base64编码
-- @param content 需要签名的内容
-- @return 签名结果的Base64编码字符串，如果签名失败则返回nil和错误信息
local function sign8(content)
  local sig, err = priv8:sign(content)
  if not sig then
    ngx.log(ngx.ERR, "failed to sign:", err)
    return nil, err
  end
  return base64_encode(sig), nil
end

local function random_string(length)
  local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  local result = {}
  for i = 1, length do
    local randIndex = math.random(1, #chars)
    result[i] = chars:sub(randIndex, randIndex)
  end
  return table.concat(result)
end

-- 生成UUID4格式的随机字符串
-- @return UUID4格式的字符串，例如: 550e8400-e29b-41d4-a716-446655440000
local function uuid4()
  local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
  return string.gsub(template, '[xy]', function(c)
    local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
    return string.format('%x', v)
  end)
end

-- 处理根路径请求，显示使用说明信息
-- 返回HTML格式的使用说明，包括不同版本的激活地址格式
local function index_handler()
  ngx.header.content_type = "text/html; charset=utf-8"
  local req = ngx.var.scheme .. "://" .. ngx.var.host
  -- .. ":" .. ngx.var.server_port
  if not ((ngx.var.scheme == 'https' and ngx.var.server_port == '443') or (ngx.var.scheme == 'http' and ngx.var.server_port == '80')) then
    req = req .. ":" .. ngx.var.server_port
  end
  req = req .. "/"

  ngx.print("<h3>JetBrains Activation address was: " .. req .. "</h3>")
  ngx.print("<h3>JRebel 7.1 and earlier version Activation address was: " .. req .. "{tokenname}, with any email.</h3>")
  ngx.print("<h3>JRebel 2018.1 and later version Activation address was:" .. req .. "{guid}(eg:" .. req .. uuid4() .. "), with any email.</h3>")
end

-- 生成JRebel许可的签名内容
-- @param client_randomness 客户端随机数
-- @param guid 全局唯一标识符
-- @param offline 是否离线模式
-- @param valid_from 有效期开始时间
-- @param valid_until 有效期结束时间
-- @return 签名结果的Base64编码字符串
local function to_lease_create_json(client_randomness, server_randomness, guid, offline, valid_from, valid_until)
  local tab = { client_randomness, server_randomness, guid, tostring(offline) }
  if offline then
    tab[#tab + 1] = valid_from
    tab[#tab + 1] = valid_until
  end
  local s2 = table.concat(tab, ";")
  return sign8(s2)
end

-- 处理JRebel许可请求
-- 解析请求参数，生成许可信息并返回JSON格式响应
local function jrebel_leases_handler()
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.req.read_body()
  local args, err = ngx.req.get_post_args()

  local username = args["username"]
  local offline = args["offline"] or false

  if args["product"] == "XRebel" then
    offline = false
  end

  local guid = args["guid"]
  local offline_days = args["offlineDays"]
  local valid_from = "null"
  local valid_until = "null"
  if offline then
    local client_time = args["clientTime"] or 0
    -- 86400000 = 24 * 60 * 60 * 1000 = 1 days
    valid_from = client_time
    valid_until = client_time + (offline_days or 180) * 86400000
  end

  local client_randomness = args["randomness"]

  local resp = [[
    {
      "serverVersion":"3.2.4",
      "serverProtocolVersion":"1.1",
      "serverGuid":"a1b4aea8-b031-4302-b602-670a990272cb",
      "groupType":"managed",
      "id":1,
      "licenseType":1,
      "evaluationLicense":false,
      "signature":"OJE9wGg2xncSb+VgnYT+9HGCFaLOk28tneMFhCbpVMKoC/Iq4LuaDKPirBjG4o394/UjCDGgTBpIrzcXNPdVxVr8PnQzpy7ZSToGO8wv/KIWZT9/ba7bDbA8/RZ4B37YkCeXhjaixpmoyz/CIZMnei4q7oWR7DYUOlOcEWDQhiY=",
      "serverRandomness":"%s",
      "seatPoolType":"standalone",
      "statusCode":"SUCCESS",
      "offline":%s,
      "validFrom":%s,
      "validUntil":%s,
      "company":"Administrator",
      "orderId":"",
      "zeroIds":[],
      "licenseValidFrom":1490544001000,
      "licenseValidUntil":1691839999000
    }
  ]]

  if not client_randomness or not username or not guid then
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
  local server_randomness = random_string(11) .. "="
  resp = string.format(resp, server_randomness, offline, valid_from, valid_until)
  local json_obj = json_decode(resp)
  local signature = to_lease_create_json(client_randomness, server_randomness, guid, offline, valid_from, valid_until)
  json_obj["signature"] = signature
  json_obj["company"] = username
  ngx.log(ngx.ERR, "jrebel_leases_handler:", json_encode(json_obj))
  return json_encode(json_obj)
end

-- 处理JRebel许可验证请求
-- 返回简化版的许可信息
local function jrebel_leases1_handler()
  ngx.header.content_type = "application/json; charset=utf-8"
  local args, err = ngx.req.get_uri_args()
  local username = args['username']
  local resp = {
    ["serverVersion"] = "3.2.4",
    ["serverProtocolVersion"] = "1.1",
    ["serverGuid"] = "a1b4aea8-b031-4302-b602-670a990272cb",
    ["groupType"] = "managed",
    ["statusCode"] = "SUCCESS",
    ["msg"] = "null",
    ["statusMessage"] = "null",
    ["signature"] = "dGVzdA=="
  }
  if username then
    resp["company"] = username
  end
  return json_encode(resp)
end

-- 处理JRebel连接验证请求
-- 返回连接验证成功的响应信息
local function jrebel_validate_handler()
  ngx.header.content_type = "application/json; charset=utf-8"
  local resp = [[{
      "serverVersion": "3.2.4",
      "serverProtocolVersion": "1.1",
      "serverGuid": "a1b4aea8-b031-4302-b602-670a990272cb",
      "groupType": "managed",
      "statusCode": "SUCCESS",
      "company": "Administrator",
      "canGetLease": true,
      "licenseType": 1,
      "evaluationLicense": false,
      "seatPoolType": "standalone"
  }]]
  return resp
end

-- 处理获取票据请求
-- 生成并返回带签名的票据信息
local function obtain_ticket_handler()
  ngx.header.content_type = "text/html;charset=UTF-8"
  ngx.req.read_body()
  local args, err = ngx.req.get_uri_args()
  local salt = args["salt"];
  local username = args["userName"];
  local prolongation_period = "607875500";
  if not username or not salt then
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
  local xml_content = "<ObtainTicketResponse><message></message><prolongationPeriod>" .. prolongation_period .. "</prolongationPeriod><responseCode>OK</responseCode><salt>" .. salt .. "</salt><ticketId>1</ticketId><ticketProperties>licensee=" .. username .. "\tlicenseType=0\t</ticketProperties></ObtainTicketResponse>";

  local xml_signature = sign1(xml_content)
  return "<!-- " .. xml_signature .. " -->\n" .. xml_content
end

-- 处理释放票据和ping请求的通用函数
-- @param type 响应类型，"PingResponse"或"ReleaseTicketResponse"
-- @return 带签名的XML格式响应
local function release_and_ping_handler(type)
  ngx.header.content_type = "text/html; charset=utf-8"
  local args, err = ngx.req.get_uri_args()
  local salt = args["salt"]
  if not salt then
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
  local xml_content = "<" .. type .. "><message></message><responseCode>OK</responseCode><salt>" .. salt .. "</salt></" .. type .. ">"
  local xml_signature = sign1(xml_content)
  return "<!-- " .. xml_signature .. " -->\n" .. xml_content
end

-- 处理ping请求
-- 调用通用处理函数处理ping响应
local function ping_handler()
  return release_and_ping_handler("PingResponse")
end

-- 处理释放票据请求
-- 调用通用处理函数处理释放票据响应
local function release_ticket_handler()
  return release_and_ping_handler("ReleaseTicketResponse")
end

-- 路由映射表，将URI路径映射到相应的处理函数
local routes = {
  ["/"] = index_handler,
  ["/jrebel/leases"] = jrebel_leases_handler,
  ["/jrebel/leases/1"] = jrebel_leases1_handler,
  ["/agent/leases"] = jrebel_leases_handler,
  ["/agent/leases/1"] = jrebel_leases1_handler,
  ["/jrebel/validate-connection"] = jrebel_validate_handler,
  ["/rpc/ping.action"] = ping_handler,
  ["/rpc/obtainTicket.action"] = obtain_ticket_handler,
  ["/rpc/releaseTicket.action"] = release_ticket_handler
}

-- 主处理函数，根据请求URI调用相应的处理函数
-- 通过路由表查找对应的处理函数并执行，未找到则返回403错误
function _M.handler()
  local uri = ngx.var.uri
  local handler = routes[uri]

  if handler then
    return handler()
  else
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

return _M;
