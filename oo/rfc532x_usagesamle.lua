--[[

Just samle code to illustrate usafe of rfc532x class

]]--

...
require('oo.rfc532x')

function mod:validate_data(msg, acc, vctx)

  local fromhdr = msg:header('From')
  if not (type(fromhdr) == 'table' and #fromhdr == 1) then
    local fhdr = '<missing>'
    if #fromhdr > 0 then
      fhdr = fromhdr[1]
    end
    custlog:write('Bad From hdr(%d): %s mfrom: %s in msg(%s)', #fromhdr, fhdr, msg:mailfrom(), tostring(msg.id))
    vctx:disconnect(550, '5.7.1 missing/multiple From not allowed')
    return core.VALIDATE_DONE
  end
  fromhdr = fromhdr[1]

  local em = rfc532x:new(fromhdr, rfc532x.c_RFC5321)
  --# optional aler default settings from strict 5321 validation
  em:setLocalpartLimit(rfc532x.c_RFC5321_nolimit) --# no length constraint on local part
  em:setIPv6(false) --# don't allow IPv6 literaaly domain part
  if not (em:nulladdress() or em:valid(rfc532x.c_VERIFYEXIST)) then
     custlog:write('RFC532X Bad From: %s mfrom: %s in msg(%s)', tostring(em), msg:mailfrom(), tostring(msg.id))
  end

  local replyto = msg:header('Reply-To')
  if replyto then
    local em = rfc532x:new(replyto, rfc532x.c_RFC5321)
    em:setIPv6(true)  --# allow literally IPv6 domains
    em:setLocalLimit(rfc532x.c_RFC5321_nolimit)  --# no length limit on @-LHS ie localpart 
    if not em:valid(rfc532x.c_VERIFYEXIST) then
       custlog:write('RFC532X Bad Reply-To: %s', em:email())
    end
  end

...

end

