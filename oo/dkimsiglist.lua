--[[
#
# Module: DMARCurilist class
#
]]--

local require = require
local oo = require('loop.base')
local ootab = require('loop.table')

require('lib.str')
require('oo.dkimsig')

module('DKIMsiglist', oo.class, package.seeall)

local tostring = tostring
local type = type
local ipairs = ipairs
local split = string.split

local CLASSVAR = {
  list = {}
}

local function listparse(self, sigtab)
  self.list = {} --# stupid empty table can't be clone, so alloc instance var here
  for i,s in ipairs(sigtab) do
    local sig = DKIMsig(s)
    if sig then
      self.list[#self.list+1] = sig  --# table.insert doesn't work here :|
    end
  end
end


function __init(self, sigtable)
  local instvar = ootab.clone(CLASSVAR)
  if type(sigtable)=='table' then
    listparse(instvar, sigtable)
  end
  return oo.rawnew(self,instvar)
end

function new(self, sigtable)
  return self:__init(sigtable)
end


function __del(self)
  ootab.clear(self.list)
end

function del(self)
  self:__del()
end


function __tostring(self)
  local str,sep = '',''
  if self.list then
    for i,v in ipairs(self.list) do
      str = str..sep..tostring(v)
      sep = ' '
    end
  end
  return str
end


function doms(self)
  local str,sep = '',''
  if self.list then
    for i,v in ipairs(self.list) do
      if #v:idom() > 0 then
        str = str..sep..v:idom()
      else
        str = str..sep..v:ddom()
      end
      sep = ' '
    end
  end
  return str
end


function tabdoms(self)
  return split(self:doms(), ' ')
end