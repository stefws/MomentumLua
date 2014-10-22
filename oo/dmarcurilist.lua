--[[
#
# Module: DMARCurilist class
#
]]--

local require = require
local oo = require('loop.base')
local ootab = require('loop.table')

require('oo.dmarcuri')

module('DMARCurilist', oo.class, package.seeall)

local tostring = tostring
local tonumber = tonumber
local string = string
local find = string.find
local format = string.format
local sub = string.sub
require('lib.str')
local split = string.split
local print = print
local ipairs = ipairs

local CLASSVAR = {
  list = {}
}

local function listparse(self, combineduris, dom)
  self.list = {} --# stupid, empty table can't be clone, so alloc instance var here
  local urisets = combineduris:split(',')
  local dotdom = '.'..dom
  for i,uri in ipairs(urisets) do
    local dmuri = DMARCuri(uri)
    if dmuri:mailto() then
      local doturidom = '.'..dmuri:emailRHS()
      if dotdom:find(doturidom,1,true) then
        self.list[#self.list+1] = dmuri  --# table.insert doesn't work here :|
      else
        local rr,e=msys.dnsLookup(format('%s._report._dmarc%s',dom,doturidom),'txt')
        if rr then
          --# TODO: possible as per RFC6591, unfold here all TXT rr before parsing...
          for k,v in ipairs(rr) do
            if sub(v,1,8) == 'v=DMARC1' then
              self.list[#self.list+1] = dmuri
              break;
            end
          end
        end
      end
    --[[ so far we only allow mailto URIs
    else
      self.list[#self.list+1] = dmuri
    ]]--
    end
  end
end


function __init(self, encodeduris, domain)
  local instvar = ootab.clone(CLASSVAR)
  listparse(instvar, encodeduris, domain)
  return oo.rawnew(self,instvar)
end

function new(self, encodeduris, domain)
  return self:__init(encodeduris, domain)
end


function __del(self)
  ootab.clear(self.list)
end

function del(self)
  self:__del()
end


function __tostring(self)
  local str,sep = '',''
  for i,v in ipairs(self.list) do
    str = str..sep..tostring(v)
    sep = ','
  end
  return str
end


function uris(self)
  local str,sep = '',''
  for i,v in ipairs(self.list) do
    str = str..sep..v.uri
    sep = ','
  end
  return str
end
