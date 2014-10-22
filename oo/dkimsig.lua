--[[
#
# Module: DKIMsig class, to parse a RFC6376 DKIM signature
#
]]--

local oo = require('loop.base')

module('DKIMsig', oo.class, package.seeall)

local require = require
local ootab = require('loop.table')
require('lib.str')
local trimspace = string.trimspace
local split = string.split

local print = print
local type = type
local tonumber = tonumber
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local lower = string.lower
local format = string.format


local CLASSVAR = {
  signature = nil,
  v = nil,       -- various parsed tags of signature given
  a = nil,
  b = nil,
  bh = nil,
  c = nil,
  d = nil,
  h = nil,
  i = nil,
  l = nil,
  q = nil,
  s = nil,
  t = nil,
  x = nil,
  z = nil
}


local function sigparse(self)

  local invalidate = false

  local kvpat = '([^=%s]+)%s*=%s*(.+)'
  for tag in gmatch(self.signature, '[^;]+') do
    tag = gsub(tag, '^%s*(.-)%s*$', '%1')
    local k,v = match(tag, kvpat)
    if k and v then
      if self[v] then  --# dublet?
        invalidate = true
        break
      end
      local numval = tonumber(v)
      if numval==nil then numval = -1; end
      --# look for known valid tags & values of signature
      if k=='v' and numval==1 then --# only v=1 supported & required
        self[k] = numval
      elseif k=='a' or k=='b' or k=='bh' or k=='d' or k=='h' or k=='s' then --# required
        self[k] = v
      elseif k=='t' or k=='x' then  --# recommended
        self[k] = numval
      elseif k=='c' or k=='i' or k=='l' or k=='q' or k=='z' then --# optional
        self[k] = v
      else
        print(format('DKIMsig: ignored tag %s of %s',k,self.signature))
      end
    else
      print(format('DKIMsig: invalid key: %s val: %s',tostring(k),tostring(v)))
    end
  end

  if invalidate or
     self.a==nil or self.b==nil or self.bh==nil or
     self.d==nil or self.h==nil or self.s==nil then
    self.v = nil --# no v => not valid
  end
end


function __init(self,signature)
  local instvar = ootab.copy(CLASSVAR)
  instvar.signature = signature
  if type(instvar.signature)=='string' then
    instvar.signature = trimspace(instvar.signature)
    sigparse(instvar)
  end
  local obj = nil
  if instvar.v then
    obj = oo.rawnew(self,instvar)
  end
  return obj
end


function valid(self)
  return (self.v!=nil)
end


function __tostring(self)
  if self:valid() then
    return self.signature
  end
  return 'invalid'
end


function ddom(self)
  if self.d then
    return self.d
  end
  return ''
end

function idom(self)
  if self.i then
    local ipart = self.i:split('@')
    if #ipart == 2 then
      return ipart[2]
    end
  end
  return ''
end
