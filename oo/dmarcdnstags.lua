--[[
#
# Module: DMARCdnstags class
#
]]--

local oo = require('loop.base')

module('DMARCdnstags', oo.class, package.seeall)

local require = require
local ootab = require('loop.table')
require('msys.core')
require('lua.tdc.str')

local tostring = tostring
local tonumber = tonumber
local print = print
local ipairs = ipairs
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local sub = string.sub
local lower = string.lower
local trimspace = string.trimspace
local format = string.format

local dnsLookup = msys.dnsLookup


local CLASSVAR = {
  domain = nil,  -- domain resolved
  dnstxt = '',   -- DMARC1 TXT rr of domain
  v = nil,       -- various parsed tags of dnstxt
  p = nil,
  sp = nil,
  rua = nil,
  ruf = nil,
  adkim = 'r',
  aspf = 'r',
  fo = '0',
  pct = 100,
  rf = 'afrf',
  ri = 86400,
}


local function dnstxt(self)

  local r, e = dnsLookup('_dmarc.'..self.domain, 'TXT')
  if r ~= nil then
    --# TODO: possible as per RFC6591, unfold here all TXT rr before parsing...
    local k, v
    for k,v in ipairs(r) do
      if match(v, '^v=DMARC1%s*;%s*p%s*=%s*%S+') then
        self.dnstxt = trimspace(lower(v))
        break
      end
    end
  end
  return (self.dnstxt ~= '')
end


local function dnsparse(self)

  local kvpat = '([^=%s]+)%s*=%s*(.+)'
  for tag in gmatch(self.dnstxt, '[^;]+') do
    tag = gsub(tag, '^%s*(.-)%s*$', '%1')
    local k,v = match(tag, kvpat)
    if k and v then
      local numval = tonumber(v)
      if numval==nil then numval = -1; end
      --# look for known valid tags & values of v=DMARC1, ignore others
      if (k=='p' or k=='sp') then
        if v=='reject' or v=='quarantine' then
          self[k] = v
        else
          self[k] = 'none'
        end
      elseif k=='adkim' or k=='aspf' and (v=='r' or v=='s' or v=='strict') then
        self[k] = sub(v,1,1)
      elseif (k=='pct' and 0 <= numval and numval <= 100) or (k=='ri' and numval >= 3600) then
        self[k] = numval
      elseif k=='v' or k=='rua' or k=='ruf' or k=='fo' then
        self[k] = v
      elseif k=='rf' and (v=='afrf' or v=='iodef') then
        self[k] = v
      else
        print(format('DMARC: %s: ignored tag %s of %s',self.domain,k,self.dnstxt))
      end
    else
      print(format('DMARC: %s: key: %s val: %s',self.domain,tostring(k),tostring(v)))
    end
  end

  --# sp defaults to p
  if self.sp == nil then self.sp = self.p; end
end


function __init(self,dom)
  local instvar = ootab.copy(CLASSVAR)
  instvar.domain = dom
  if dnstxt(instvar) then
    dnsparse(instvar)
  end
  return oo.rawnew(self,instvar)
end


function valid(self)
  return (self.v=='dmarc1' and self.p!=nil)
end


function __tostring(self)
  if self:valid() then
    return self.dnstxt
  end
  return 'invalid'
end
