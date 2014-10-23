MomentumLua
===========

Various shared/sample Lua scripts to be used with Message Systems Momentum MTA

lib/ holds various library utilities
oo/ holds various Object Oriented classes
All OO classes are based on Project: LOOP - Lua Object-Oriented Programming by Author: Renato Maia (look else where for this)

Sorry doc are poor at the moment, here's a brief overview:

Classes possible usable when creating a DMARC policy:

oo/dmarcdnstags.lua  - class to lookup and verify DMARC dns records

oo/dmarcuri.lua      - class to represent a DMARC URI aka like rua:mailto:<email>

oo/dmarcurilist.lua  - class of a list of dmarcuri's

oo/dkimsig.lua       - class to represent a dkim signature

oo/dkimsiglist.lua   - class of a list of dkim signatures


Class(es) possible usable when creating a policy:

oo/rfc532x.lua       - class to represent and validate rfc532x email addresses

oo/rfc532x_usagesample.lua - example of usage of rfc532x class

Enjoy a your leisure!
