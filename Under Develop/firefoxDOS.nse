---
-- Nmap firefoxDOS - Version 1.6
-- Copy script to: /usr/share/nmap/scripts/phpipam.nse
-- Update NSE database: sudo nmap --script-updatedb
-- executing: nmap --script-help phpipam.nse
-- executing: nmap -sV -Pn -p 80 --open --script phpipam.nse <target or domain>
-- executing: nmap -sV -Pn -p 80 --open --reason --script phpipam.nse --script-args uri=/phpipam.php <target or domain>
-- executing: nmap -sV -Pn -p 80 --script phpipam.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
---


-- SCRIPT BANNER DESCRIPTION --
description = [[

Module Author: r00t-3xp10it
Vuln discover: Saeed reza
NSE script to detect multiple vulnerabilitys in phpipam (1.2.1 & 1.1.010) versions
of open-source web IP address management application (IPAM). by default phpipam.nse
searches for phpipam.html on target webserver, If target respondes 200 OK then my
script will verify the version installed and If the 2 condictions are true it will
display a vulnerable output.


Some Syntax examples:
nmap --script-help phpipam.nse
nmap -sV -Pn -p 80 --open --script phpipam.nse <target or domain>
nmap -sV -Pn -p 80 --open --reason --script phpipam.nse 192.168.1.0/24
nmap -sV -Pn -p 80 --open --script phpipam.nse --script-args uri=/phpipam.php <target or domain>
nmap -sV -Pn -p 80 --open --script phpipam.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
nmap -sV -T4 -iR 400 -Pn -p 80 --open --reason --script phpipam.nse --script-args uri=/phpipam/ -oN IPAMreport.log

]]

---
-- @usage
-- nmap --script-help phpipam.nse
-- nmap -sV -Pn -p 80 --open --script phpipam.nse <target or domain>
-- nmap -sV -Pn -p 80 --open --reason --script phpipam.nse 192.168.1.0/24
-- nmap -sV -Pn -p 80 --open --script phpipam.nse --script-args uri=/phpipam.php <target or domain>
-- nmap -sV -Pn -p 80 --open --script phpipam.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
-- nmap -sV -T4 -iR 400 -Pn -p 80 --open --reason --script phpipam.nse --script-args uri=/phpipam/ -oN IPAMreport.log
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    phpipam 1.2.1
-- | phpipam:
-- |   STATUS: VULNERABLE
-- |   VERSION: 1.2.1 (likelly exploitable)
-- |     Disclosure date: 28 set 2016
-- |     Vuln discover: Saeed reza
-- |     Module Author: r00t-3xp10it
-- |
-- |     Description:
-- |       phpipam is an open-source web IP address management application, its goal is to provide light
-- |       modern and useful IP address management. It is php-based application with MySQL database backend,
-- |       using jQuery libraries, ajax and some HTML5/CSS3 features.
-- |       [SQLI GET] => http://[Site]/phpipam/?page=tools&section=changelog&subnetId=a&sPage=50'
-- |       [XSS POST] => http://[Site]/phpipam/app/admin/widgets/edit.php/wid=1><SCRIPT>ALERT(DOCUMENT.COOKIE);</SCRIPT>&action=edit
-- |
-- |     References:
-- |       Vendor: http://phpipam.net/
-- |       Vuln Discover: http://0day.today/exploit/25375
-- |       Vuln Discover: https://www.exploit-db.com/exploits/39171/
-- |       Module Author: https://sourceforge.net/u/peterubuntu10/profile/
-- |_
-- @args payload.uri the path name to search. Default: /phpipam.html
-- @args payload.agent User-agent to send in request - Default: iPhone,safari
---

author = "r00t-3xp10it"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}



-- DEPENDENCIES (lua nse libraries) --
local stdnse = require ('stdnse') --> required to use nse arguments
local shortport = require "shortport"
local string = require "string"
local http = require "http"



  -- THE RULE SECTION --
  -- portrule = shortport.http --> updated to scan only the selected ports/proto/services
  portrule = shortport.port_or_service({80, 443}, "http, https", "tcp", "open")
  -- local uri = "/phpipam.html" --> updated to use script @args payload.uri
  local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/phpipam.html"



-- THE ACTION SECTION --
action = function(host, port)
-- Manipulate TCP packet 'header' with false information about attacker :D
local options = {header={}}   --> manipulate 'header' request ..
local useragent = options['header']['User-Agent']
-- read response from target (http.get)
local response = http.get(host, port, uri, options)


  -- check if target its phpipam based website
  if ( response.status == 200 ) then
    local title = string.match(response.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>phpipam ([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

    -- check firefox version installed (headers)
    if ( useragent == "Mozilla/5.0" ) then
      -- VULNERABLE nse module output display
      return "\n   STATUS: VULNERABLE\n   VERSION: "..title.." (likelly exploitable)\n     Disclosure date: 28 set 2016\n     Vuln discover: Saeed reza\n     Module Author: r00t-3xp10it\n\n     Description:\n       phpipam is an open-source web IP address management application, its goal is to provide light\n       modern and useful IP address management. It is php-based application with MySQL database backend,\n       using jQuery libraries, ajax and some HTML5/CSS3 features.\n       [SQLI GET] => http://[Site]/phpipam/?page=tools&section=changelog&subnetId=a&sPage=50'\n       [XSS POST] => http://[Site]/phpipam/app/admin/widgets/edit.php/wid=1><SCRIPT>ALERT(DOCUMENT.COOKIE);</SCRIPT>&action=edit\n\n     References:\n       Vendor: http://phpipam.net/\n       Vuln Discover: http://0day.today/exploit/25375\n       Vuln Discover: https://www.exploit-db.com/exploits/39171/\n       Module Author: https://sourceforge.net/u/peterubuntu10/profile/\n\n"
    else
      -- NOT VULNERABLE version install found (1.2.1) of phpipam in target system
      return "\n  STATUS: NOT VULNERABLE\n    index: "..uri..": 200 Found\n    VERSION: "..title.." (wrong version)\n    Module Author: r00t-3xp10it\n\n"
    end

  -- check for diferent google return codes
  -- to display a NON VULNERABLE output...
  elseif ( response.status == 404 ) then
    return "\n  index: "..uri.."\n  STATUS: "..response.status.." NOT FOUND\n    module author: r00t-3xp10it\n\n"
  elseif ( response.status == 400 ) then
    return "\n  index: "..uri.."\n  STATUS: "..response.status.." BAD REQUEST\n    module author: r00t-3xp10it\n\n"
  elseif ( response.status == 401 ) then
    return "\n  index: "..uri.."\n  STATUS: "..response.status.." UNAUTHORIZED\n    module author: r00t-3xp10it\n\n"
  elseif ( response.status == 302 ) then
    return "\n  index: "..uri.."\n  STATUS: "..response.status.." REDIRECTED\n    module author: r00t-3xp10it\n\n"
  else
    -- I dont want to write more response.status ... so i let my module displays the returned code :D
    return "\n  index: "..uri.."\n  STATUS: "..response.status.." response code\n    module author: r00t-3xp10it\n\n"
  end
end
