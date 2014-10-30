--[[
#
# Module: rfc532x verification class
#
]]--

local require = require
local oo = require('loop.base')
local ootab = require('loop.table')


module('rfc532x', oo.class, package.seeall)

local dnsLookup = msys.dnsLookup
local regexp = msys.pcre.match
local tostring = tostring
local type = type
local ipairs = ipairs
local split = string.split
local gsub = string.gsub
local find = string.find
local match = string.match
local lower = string.lower
local format = string.format

--# class public constants/enums
c_VALID = 0  --# validation results
c_SYNTAXERR = -1
c_NXDOMAIN = -2
c_MXBADIP = -3

c_NOVERIFY = 1  --# Domaion DNS verifications
c_VERIFYEXIST = 2
c_VERIFYVALIDMX = 3

c_BASIC   = 1  --# RFC validation scheme
c_RFC5321 = 5321
c_RFC5322 = 5322

c_RFC5321_nolimit = 0  --# component lenght contraints
c_RFC5321_locallen = 65
c_RFC5321_totallen = 256


local CLASSVAR = {
  --# state member vars
  m_groupaddr = false,
  m_multipleaddr = false,
  m_rawemail = '',
  m_email = 'not-found',
  m_localpart = 'not-found',
  m_dompart = 'not-found',

  --# control member vars
  m_locallen_limit = c_RFC5321_nolimit,
  m_totallen_limit = c_RFC5321_nolimit,
  m_quoted_string = false,
  m_obsolete = false,
  m_basic_domain_name = true,
  m_domain_literal = false,
  m_ipv6 = false,
  m_cfws = false,

  --# runtime state
  m_cfws_define,
  m_fws_define
}

local function _strip2coreEmail(self, rawEmail)

  --# strip possible group syntax
  local groupaddr = rawEmail:match('^[^:]+:%s*(.*)%s*;%s*$')
  if groupaddr then
    rawEmail = groupaddr       --# drop group syntax
    self.m_groupaddr = true    --# but note it seen
  end

  --# Drop possible [first] pretty name
  --#   this fails for strings with both \" + \q but what's the likelyhood of this...
  local escqoute = false
  if rawEmail:find('\\\"') and not rawEmail:find('\\\q') then
    escqoute = true
    rawEmail = rawEmail:gsub('\\\"', '\\\q')
  end
  --# drop quoted pretty name as it might hold "*<*"
  rawEmail = rawEmail:gsub('^%s*".-"%s*(.*)', '%1')   --# [ ]".-"[ ]<email* -> <email*
  --# then drop anything before first angle
  rawEmail = rawEmail:gsub('^.-<(.*)', '<%1')         --# .*<email*[ ]  -> <email*
  if escquote == true then
    rawEmail = rawEmail:gsub('\\\q', '\\\"')
  end

  --# drop possible further multiple addresses
  local multipleaddr = rawEmail:match('([^,%s]+)%s*,.+')
  if multipleaddr then
    rawEmail = multipleaddr    --# only use first addr
    self.m_multipleaddr = true --# but note more seen
  end

  --# drop possible comment
  rawEmail = rawEmail:gsub('(.-)%s*%(.*%)%s*$', '%1')       --# <email> (Cron Daemon)[ *]  -> <email>

   --# chase to the core, allowing some of most seen odities :)
  local coreaddr = rawEmail:match('<?.*<(.*)>>?%s*$') --# [<].*<email>[>][ *] -> email
  if coreaddr then rawEmail = coreaddr; end

  --# drop any leading/trailing white space$
  return rawEmail:gsub('^%s*(.*)%s*$', '%1'))
end

function __init(self, email, rfc)
  rfc = rfc or c_BASIC

  local instvar = ootab.clone(CLASSVAR)

  if type(email)=='string' then
    instvar.m_rawemail = email
    instvar.m_email = _strip2coreEmail(instvar, email)
    local part = instvar.m_email:split('@')
    if #part == 2 then
      instvar.m_localpart = part[1]
      instvar.m_dompart = part[2]
    end
  end
  obj = oo.rawnew(self,instvar)
  if rfc == c_RFC5321 then
    obj:setRfc5321()
  elseif rfc == c_RFC5322 then
    obj:setRfc5322()
  end

  return obj
end

function new(self, email, rfc)
  return self:__init(email, rfc)
end

function __del(self)
end

function del(self)
  self:__del()
end

function __tostring(self)
  return self.m_rawemail .. ' => ' .. self.m_email .. ' <=> ' .. self.m_localpart .. '@' .. self.m_dompart
end

--# setters

function setRfc5321(self)
  self.m_quoted_string = true
  self.m_obsolete = false
  self.m_basic_domain_name = false
  self.m_domain_literal = true
  self.m_cfws = false
  self.m_locallen_limit = c_RFC5321_locallen
  self.m_totallen_limit = c_RFC5321_totallen
end

function setRfc5322(self)
  self.m_quoted_string = false
  self.m_obsolete = true
  self.m_basic_domain_name = false
  self.m_domain_literal = true
  self.m_cfws = true
  self.m_locallen_limit = c_RFC5321_nolimit
  self.m_totallen_limit = c_RFC5321_nolimit
end

function setQuotedString(self, allow)
  allow = (allow == nil and true) or allow
  --# Either allow or not a quoted string local part
  self.m_quoted_string = allow
end

function setObsolete(self, allow)
  allow = (allow == nil and true) or allow
  --# Either allow or not an obsolete local part
  self.m_obsolete = allow
end

function setBasicDomainName(self, allow)
  allow = (allow == nil and true) or allow
  --# Either require a basic domain name or n ot
  self.m_basic_domain_name = allow
end

function setDomainLiteral(self, allow)
  allow = (allow == nil and true) or allow
  --# Either allow or not a domain literal domain part
  self.m_domain_literal = allow
end

function setIPv6(self, supported)
  supported = (supported == nil and true) or supported
  --# Either support or not IPv6
  self.m_ipv6 = supported
end

function setCfws(self, allow)
  allow = (allow == nil and true) or allow
  --# Either allow or not comments and folding white spaces
  self.m_cfws = allow
end

function setLocalPartLimit(self, limit)
  limit = limit or c_RFC5321_locallen
  self.m_locallen_limit = limit
end

function setEmailLimit(self, limit)
  limit = limit or c_RFC5321_locallen
  self.m_totallen_limit = limit
end


--# [local] getters

function groupaddress(self)
  return self.m_groupaddr
end

function multipleaddresses(self)
  return self.m_multipleaddr
end

function nulladdress(self)
  return self.m_rawemail == nil or #self.m_rawemail == 0 or #self.m_email == 0
end

function LHS(self)
  return self.m_localpart
end

function RHS(self)
  return self.m_dompart
end

function localpart(self)
  return LHS(self)
end

function domainpart(self)
  return RHS(self)
end

function domain(self)
  return RHS(self)
end

function email(self)
  return self.m_email
end

local function _getFWS(self)
  local pattern = ''
  --# Return the backreference if $define is set to FALSE otherwise return the regular expression
  if self.m_cfws then
    if self.m_fws_define then
      pattern = '(?P<fws>(?>(?>(?>\x0D\x0A)?[\t ])+|(?>[\t ]*\x0D\x0A)?[\t ]+))'
      self.m_fws_define = false
    else
      pattern = '(?&fws)'
    end
  end

  return pattern
end

local function _getComments(self)
  return '(?P<cmnt>\((?>' ..  _getFWS(self) ..
    "(?>[\x01-\x08\x0B\x0C\x0E-\'*-\\[\\]-\x7F]|\\\[\x00-\x7F]|(?&cmnt)))*" ..
    _getFWS(self) .. '\))'
end

local function _getCFWS(self)
  local pattern = ''
  --# Return the backreference if $define is set to FALSE
  if self.m_cfws then
    if self.m_cfws_define then
      pattern = '(?P<cfws>(?>(?>(?>' ..  _getFWS(self) ..  _getComments(self) ..  ')+' ..  _getFWS(self) ..  ')|' ..  _getFWS(self) ..  '))'
      self.m_cfws_define = false
    else
      pattern =  '(?&cfws)'
    end
  end

  return pattern
end

local function _getDotAtom(self)
  return "(?P<dotatom>(?P<atxt>(?i)[!#-'*+\/-9=?^-~-]+)(?>\.(?&atxt))*)"
  --#return "([!#-'*+\/-9=?^-~-]+)(?>\.(?1))*"
end

local function _getQuotedString(self)
  return '(?>"(?>[ !#-\\[\\]-~]|\\\[ -~])*")'
end

local function _getObsolete(self)
  return '(?P<otxt>([!#-\'*+\/-9=?^-~-]+|"(?>' ..
    _getFWS(self) ..
    '(?>[\x01-\x08\x0B\x0C\x0E-!#-\\[\\]-\x7F]|\\\[\x00-\xFF]))*' ..
    _getFWS(self) ..
    '"))(?>' ..
    _getCFWS(self) ..
    '\.' ..
    _getCFWS(self) ..
    '(?&otxt))*'
end

local function _getEmailAddressLengthLimit(self)
  local len = ''

  if self.m_totallen_limit > c_RFC5321_nolimit then
    len = '(?!(?>' .. _getCFWS(self) .. '"?(?>\\\[ -~]|[^"])"?' .. _getCFWS(self) .. format('){%d,})', self.m_totallen_limit)
  elseif self.m_cfws then
    len = '(?!(?>' .. _getCFWS(self) .. '))'
  end
  return len
end

local function _getLocalPartLengthLimit(self)
  local len = ''

  if self.m_locallen_limit > c_RFC5321_nolimit then
    len = '(?!(?>' .. _getCFWS(self) .. '"?(?>\\\[ -~]|[^"])"?' .. _getCFWS(self) .. format('){%d,}@)', self.m_locallen_limit)
  end
  return len
end

local function _getDomainNameLengthLimit(self)
  return '(?!' .. _getCFWS(self) .. '[a-z0-9-]{64,})'
end

local function _getDomainName(self)
  local pattern

  if self.m_basic_domain_name then
    pattern = '(>?' .. _getDomainNameLengthLimit(self) ..
          '(?P<dtxt>[a-z0-9](?>[a-z0-9-]*[a-z0-9])?)' ..
          _getCFWS(self) ..
          '\.' ..
          _getCFWS(self) ..
          '){1,126}[a-z]{2,6}'
  else
    pattern = _getDomainNameLengthLimit(self) ..
      '(?P<dtxt>[a-z0-9](?>[a-z0-9-]*[a-z0-9])?)(?>' ..
      _getCFWS(self) ..
      '\.' ..
      _getDomainNameLengthLimit(self) ..
      _getCFWS(self) ..
      '(?&dtxt)){0,126}'
  end

  return '(?P<domain>(?i)' .. pattern .. ')'
end

local function _getIPv6(self)
  return '(?>(?P<v6dg>(?P<hexd>(?i)[a-f0-9]){1,4})(?>:(?&v6dg)){7}|(?!(?:.*(?&hexd)[:\]]){8,})(?P<v6ap>(?&v6dg)(?>:(?&v6dg)){0,6})?::(?&v6ap)?)'
end

local function _getIPv4MappedIPv6(self)
  return '(?>(?&v6dg)(?>:(?&v6dg)){5}|(?!(?:.*(?&hexd):){6,})(?P<v46ap>(?&v6dg)(?>:(?&v6dg)){0,4})::(?&v6dg))?:)?'
end

local function _getIPv4(self)
  return '(?P<ipv4adr>(?P<v4dg>(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))(?>\.(?&v4dg)){3})'
end

local function _getDomainLiteral(self)
  local pat
  if self.m_ipv6 then
    pat = '(?:(?>IPv6:' .. _getIPv6(self) .. ')|(?>IPv6:' .. _getIPv4MappedIPv6(self) .. _getIPv4(self) ..  ')'
  else
   pat = _getIPv4(self)
  end
  return '\\[' .. pat ..  '\\]'
end

local function _getLocalPart(self)
  local pattern

  --# The local part may be obsolete if allowed
  if self.m_obsolete then
    pattern = _getObsolete(self)
    --# Otherwise the local part must be either a dot atom or a quoted string if the latter is allowed
  elseif self.m_quoted_string then
    pattern = _getDotAtom(self) .. '|' .. _getQuotedString(self)
  else
    --# Otherwise the local part must be a dot atom
    pattern = _getDotAtom(self)
  end

  return '(?P<lpart>' .. pattern .. ')'
end

local function _getDomain(self)
  local pattern

  --# The domain must be either a domain name or a domain literal if the latter is allowed
  if self.m_domain_literal then
    pattern = _getDomainName(self) .. '|' .. _getDomainLiteral(self)
  else
    --# Otherwise the domain must be a domain name
    pattern = _getDomainName(self)
  end

  return '(?P<dpart>' .. pattern .. ')'
end

local function _verifyDomain(dom, verify)
  --# verify: 0=don't, 1=exist, 2=full mx->a verification

  local result = c_VALID

  if verify >= c_VERIFYEXIST then
    local dnsres = nil
    local res, err = dnsLookup(dom, 'MX')

    if res == nil and (err == 'NXDOMAIN' or err == 'SERVFAIL') then
      result = c_NXDOMAIN
    elseif verify == c_VERIFYVALIDMX and res ~= nil then
      local key, mx

      --# bugger, we can't lookup CNAME, so RHS = CNAME fails though rfc valid :(
      for key,mx in ipairs(res) do
        local r, err = dnsLookup(mx, 'A')
        if r then
          if type(r) == 'table' then
            dnsres = r[1]
          else
            dnsres = r
          end
          break
--[[  TODO: test for MX RHS -> IPv6
       elseif self.m_ipv6 then
	  r, err = dnsLookup(mx, 'AAAA')
          if r then
            if type(r) == 'table' then
              dnsres = r[1]
            else
              dnsres = r
            end
            break
          end
  ]]--
        end
      end
      if dnsres == nil then  --# if no MX found try looking for A
        dnsres, err = dnsLookup(dom, 'A')
--[[  TODO: optional test for possible AAAA if ipv6 is allowed
        if not dnsres and self.m_ipv6 then
          dnsres, err = dnsLookup(dom, 'AAAA')
        end
  ]]--
      end
      if type(dnsres) == 'table' and dnsres[1] ~= nil then
        dnsres = dnsres[1];
      end
      if dnsres == nil or type(dnsres) ~= 'string' or tdc_ip.isPrivate(dnsres) then
        result = c_MXBADIP
      end
--[[
      if result != c_VALID then
        if dnsres then
          local privip = tdc_ip.isPrivate(dnsres)
          print(format('RFC532X: dom %s not verified (%s,%s)', dom, dnsres, tostring(privip)))
        else
	   print(format('RFC532X: dom %s not verified (%s)', dom, type(dnsres)))
        end
      end
]]--
    end
  end

  return result;
end

function regexpPat(self)
  self.m_cfws_define = true
  self.m_fws_define = true
  return '^' ..
        _getEmailAddressLengthLimit(self) ..
        _getLocalPartLengthLimit(self) ..
        _getCFWS(self) ..
        _getLocalPart(self) ..
        _getCFWS(self) ..
        '@' ..
        _getCFWS(self) ..
        _getDomain(self) ..
        _getCFWS(self) ..
        '$'
end

function valid(self, verifydns)
  verifydns = verifydns or c_VERIFYVALIDMX

  local valid = c_SYNTAXERR
  local mat, estr, enum = regexp(self.m_email, self:regexpPat())

--[[ only when debugging pattern matching
  if mat and type(mat) == 'table' then
    tdc_lib.dumptable(mat)
  elseif estr and #estr > 0 then
    print('pattern: '..self:regexpPat()..format(' => %s on: %s', estr, self.m_email))
  else
    print('pattern: '..self:regexpPat()..format(' => match (%s) of: %s', type(mat), self.m_email))
  end
]]--

  if mat then
    if self.m_domain_literal and regexp(self.m_dompart, _getDomainLiteral(self)) then
      valid = c_VALID
    else
      valid = _verifyDomain(self.m_dompart, verifydns)
    end
  end

  return valid
end
