--[[
# Perform various none std string operations
# input: varies
# output: varies
# action: -
# discon: -
]]--

local table = require('table')
local insert = table.insert
local pairs = pairs
local sub = string.sub
local gsub = string.gsub
local find = string.find


module('nonstd_str', package.seeall);


function string.joinhash(list, delim, prepkey, kvdelim)
  assert(type(list) == 'table','string.joinhash: list must be a hashed table of strings');
  prepkey = prepkey or true;
  kvdelim = kvdelim or ': ';
  local k, v;
  local str = '';
  local dl = ''
  for k,v in pairs(list) do
    if not prepkey then k = ''; end
    str = str .. dl .. k .. kvdelim .. v;
    dl = delim;
  end
  return str;
end


function string.join(list, delim, ifrom)
  assert(type(list) == 'table','string.join: list must be a table');
  ifrom = ifrom or 1;
  local len = #list;
  if len == 0 then 
    return '';
  end
  assert(ifrom <= len);

  local str = list[ifrom];
  for i = ifrom+1, len do 
    str = str .. delim .. list[i] ;
  end
  return str;
end


function string.split(str, pat, plain)
  assert(type(str) == 'string','split: object/first arg must be a string');
  assert(type(pat) == 'string','split: pattern must be a string');
  plain = plain or false;
  local t = {};
  local fpat = "(.-)" .. pat;
  local last_end = 1;
  local s, e, cap = find(str, fpat, 1, plain);
  while s do
    if s ~= 1 or cap ~= "" then
      insert(t, cap);
    end
    last_end = e+1;
    s, e, cap = find(str, fpat, last_end, plain);
  end
  if last_end <= #str then
    cap = sub(str, last_end);
    insert(t, cap);
  end
  return t;
end

function string.trimspace(str)
  return gsub(str, "^%s*(.-)%s*$", "%1");
end
