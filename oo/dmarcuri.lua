--[[
#
# Module: DMARCuri class
#
]]--

local oo = require('loop.base')

module('DMARCuri', oo.class, package.seeall)
--#ootab.copy(oo, _M)

local ootab = require('loop.table')
local tostring = tostring
local tonumber = tonumber
local string = string
local format = string.format
local gsub = string.gsub
require('lib.str')
local split = string.split
local print = print
local ipairs = ipairs

local CLASSVAR = {
  protocol = nil,  -- 'mailto' | 'http[s]'
  uri = nil,       -- <decoded email> | <URL>
  szlimit = 0,     -- optional: #bytes, 0=unlimited
  factor = 1,      -- numical factor of unit
  unit = nil       -- optional: '[k|m|g|t]{1}'
}

local function uriparse(self)
  local lim, fac, unit = 0, 1, nil
  local proto,uri = self.uri:match('^%s*([^:%s]+):(%S+)%s*$')
  self.uri = nil
  if proto and uri then
    if proto:match('^https?') then
      self.protocol = proto
      self.uri = uri
    elseif proto == 'mailto' then
      self.protocol = proto
      local uripart = uri:split('%!')
      self.uri = gsub(uripart[1]:gsub('%%2c',','),'%%21','!')
      if #uripart == 2 then
        lim, unit = uripart[2]:match('^(%d+)(%S?)$')
        if #unit <= 0 then fac = 1
        elseif unit == 'm' then fac = 1024^2
        elseif unit == 'k' then fac = 1024
        elseif unit == 'g' then fac = 1024^3
        elseif unit == 't' then fac = 1024^4
        else fac = 1 end
      end
    end
    self.szlimit = lim * fac
    self.factor = fac
    self.unit = unit
  end
end


function __init(self, encodeduri)
  local instvar = ootab.copy(CLASSVAR)
  instvar.uri = encodeduri
  uriparse(instvar)
  return oo.rawnew(self,instvar)
end

function new(self, encodeduri)
  return self:__init(encodeduri)
end


function __tostring(self)
  local uri = gsub(self.uri:gsub('!','%%21'),',','%%2C')
  if self.szlimit>0 then
    if #(self.unit) > 0 then
      uri = format('%s!%d%s', uri, self.szlimit/self.factor, self.unit)
    else
      uri = format('%s!%d', uri, self.szlimit/self.factor)
    end
  end

  return format('%s:%s', self.protocol, uri)
end


function emailLHS(self)
  local uripart = self.uri:split('@')
  if #uripart == 2 then
    return uripart[1]
  end
  return ''
end


function emailRHS(self)
  local uripart = self.uri:split('@')
  if #uripart == 2 then
    return uripart[2]
  end
  return ''
end


function mailto(self)
  return (self.protocol and self.protocol=='mailto')
end

function http(self)
  return (self.protocol and self.protocol:match('^https?'))
end
