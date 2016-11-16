---
-- Port nmap nse script to: /usr/share/nmap/scripts
-- Update database: sudo nmap --script-updatedb
-- Usage: sudo nmap --script-help joomla-3_4_5.nse
-- Usage: sudo nmap -sV -Pn -p 80 --script joomla-3_4_5.nse <target>
---


-- Dependencies (Lua libs)
local http = require('http')
local string = require('string')
local shortport = require('shortport')
local stdnse = require ('stdnse')
local vulns = require ('vulns')


description = [[

author: r00t-3xp10it
Detects for joomla 3.4.5 vulnerable applications

Some syntax examples:
nmap -sV -Pn -p 80 --script vuln <target>
nmap -sV -Pn -p 80 --script joomla-3_4_5.nse <target>
nmap -sS -sV -T3 -iR 30 -Pn -p 80,443,631,5800 --open --reason --script joomla-3_4_5.nse -oN /root/nmap-report.log
]]

---
-- @usage
-- nmap --script-help ms15-034.nse
-- nmap -sV -Pn -p 80 --script vuln <target>
-- nmap -sS -Pn -p 80 --script joomla-3_4_5.nse <target>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_joomla-3_4_5:
-- |   State: VULNERABLE
-- |     IDs: CVE-2015-1635
-- |     Response: 416 (exploitable)
-- |     Disclosure date: 2015-06-17
-- |     Author: r00t-3xp10it
-- |
-- |     Description:
-- |     http.sys 'remote code execution vulnerability' and 'denial-of-service' vulnerabilitys on
-- |     HTTP protocol stack (Microsoft IIS), affected versions are Windows 7, Windows Server 2008 R2,
-- |     Windows 8, Windows Server 2012, Windows 8.1, and Windows Server 2012 R2.
-- |     Exploit: nmap -sV -p 80 --script ms15-034.nse --script-args D0S=exploit <target>
-- |     Exploit: msf > use auxiliary/dos/http/ms15_034_ulonglongadd
-- |
-- |     References:
-- |     http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635
-- |     https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
-- |     http://www.rapid7.com/db/modules/auxiliary/dos/http/ms15_034_ulonglongadd
-- |_
-- @args joomla-3_4_5.uri URI to use in request. Default: /
---


author = "r00t-3xp10it"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln"}
