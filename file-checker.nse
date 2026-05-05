---
-- Nmap NSE file-checker.nse - Version 1.6
-- [linux:admin] Copy to: /usr/share/nmap/scripts/file-checker.nse
-- [linux:admin] Update NSE database: sudo nmap --script-updatedb
-- [windows:admin] copy to: C:\Program Files (x86)\nmap\scripts\file-checker.nse
-- [windows:admin] Update NSE database: nmap --script-updatedb
-- executing: nmap --script-help file-checker.nse
---

description = [[

Author: r00t-3xp10it
NSE script to check/read contents of the selected file/path in target webserver.
This module will search if 'index' exists, and if used --script-args read=true
then file-checker.nse script will read/display the contents of the 'index' file.

This script also gives you the ability to search for a diferent 'index' (files or directory)
using --script-args index=/file-to-search or index=/directory-to-search, or set a diferent
User-agent to send in the ofending tcp packet --script-args agent=<User-agent>
'Default behavior its to search for robots.txt file in webserver'

This script also gives to is users the ability to use the lost '--interactive' nmap
switch, that allow us to interact with the bash shell inside of nmap funtions using:
nmap -sV -Pn -p 80 --script file-checker.nse --script-args "command=/bin/sh -i" <target>
'WARNING: The 'command' argument does not work together with other script arguments'


Some Syntax examples:
nmap -sS -Pn -p 80 --open --script file-checker.nse <target or domain>
nmap -sS -p 8080 --open --script file-checker --script-args strsearch="500",index="/globalSIPsettings.html" 162.14.226.94
nmap -sS -p 8080 --open --script file-checker --script-args strsearch="No static",index="/globalSIPsettings.html",read="true" 162.14.226.94
nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args strsearch="Disallow:" 23.37.165.175
nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "command=/bin/sh -i" <target or domain>
nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "index=/robots.txt,read=true" <target or domain>
nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "index=/index.html,read=true" --spoof-mac Apple <target or domain>
nmap -sV -Pn -T4 -iR 400 -p 80 --open --reason --script file-checker.nse --script-args "index=/etc/passwd,read=true" -oN creds.log
nmap -sI -Pn -p 80 --scan-delay 8 --script file-checker.nse --script-args "index=/robots.txt,read=true" <zombie>,<target or domain>

]]

---
-- @usage
-- nmap --script-help file-checker.nse
-- nmap -sS -Pn -p 80 --open --script file-checker.nse <target or domain>
-- nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "index=/etc/passwd" 23.37.165.175
-- nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "command=/bin/sh -i" <target or domain>
-- nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "index=/robots.txt,read=true" <target or domain>
-- nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" <target or domain>
-- nmap -sS -Pn -p 80 --open --script file-checker.nse --script-args "index=/index.html,read=true" --spoof-mac Apple <target or domain>
-- nmap -sV -Pn -T4 -iR 400 -p 80 --open --reason --script file-checker.nse --script-args "index=/etc/passwd,read=true" -oN creds.log
-- nmap -sI -Pn -p 80 --scan-delay 8 --script file-checker.nse --script-args "index=/robots.txt,read=true" <zombie>,<target or domain>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | file-checker:
-- |   index: /robots.txt
-- |   STATUS: 200 OK FOUND
-- |     module author: r00t-3xp10it
-- |       user-agent : Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; ko; rv:1.9.1b2) Gecko/20081201 Firefox/3.1b2
-- |
-- | CONTENTS:
-- | # robots.txt of youtube since the time dinosaurs walk the hearth
-- | # This file should be placed into your website webroot directory.
-- |
-- | User-agent: *
-- | Disallow: /SSA/
-- | Disallow: /porn/
-- | Disallow: /login/
-- | Disallow: /cache/
-- | Disallow: /search/
-- | Disallow: /privacy/
-- | Disallow: /includes/
-- | Disallow: /credentials/
-- |_
-- @args search.index   -> The file/path name to search -> Default: /robots.txt
-- @args fakeUser.agent -> The User-agent to send in header request -> Default: iPhone,safari
-- @args contents.read  -> Read contents of the 'index' file selected ? -> Default: false
-- @args local.command  -> intercative bash shell -> Default: false
---

author = "r00t-3xp10it"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- DEPENDENCIES (lua nse libraries) --
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local http = require "http"
local os = require "os"

-- nse @args declarations
local read = stdnse.get_script_args(SCRIPT_NAME..".read") or "false"
local command = stdnse.get_script_args(SCRIPT_NAME..".command") or "false"
local index = stdnse.get_script_args(SCRIPT_NAME..".index") or "/robots.txt"
local strsearch = stdnse.get_script_args(SCRIPT_NAME..".strsearch") or "false"
local agent_string = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; ko; rv:1.9.1b2) Gecko/20081201 Firefox/3.1b2"

-- Port rule will only execute if port 80/443 tcp http/https its on open state
portrule = shortport.port_or_service({80, 8080, 8081, 8082, 8083}, "http, http-proxy", "tcp", "open")

-- THE ACTION SECTION --
if (command == "false") then
   action = function(host, port)

     -- Manipulate TCP packet 'header' with false information about attacker :D
     local options = {header={}}   --> manipulate 'header' request ..
     options['header']['User-Agent'] = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; ko; rv:1.9.1b2) Gecko/20081201 Firefox/3.1b2" --> use MAC OSX,Firefox User-agent OR your own...
     options['header']['Accept-Language'] = "en-GB,en;q=0.8,sv" --> use en-GB as attacker default install language
     options['header']['Cache-Control'] = "no-store" -->  Instruct webserver to not write it to disk (do not cache it)

     -- read response from target (http.get)
     local response = http.get(host, port, index, options)

     if (response.status == 200 ) then
       if (read == "true") then

         if (strsearch ~= "false") then
           if (string.match(response.body, strsearch)) then
             return "\n  index: "..index.."\n  STATE: "..response.status.." [found]\n  stringSearch: "..strsearch.." [found]\n\nCONTENTS:\n"..response.body.."\n"
           else
             return "\n  index: "..index.."\n  STATE: "..response.status.." [found]\n  stringSearch: "..strsearch.." [not found]\n\nCONTENTS:\n"..response.body.."\n"
           end
         else
           -- dont search string --- just read contents
           return "\n  index: "..index.."\n  STATE: "..response.status.." [found]\n\nCONTENTS:\n"..response.body.."\n"
         end

       elseif (strsearch ~= "false") then
         if (string.match(response.body, strsearch)) then
           return "\n  index: "..index.."\n  STATE: "..response.status.." [found]\n  stringSearch: "..strsearch.." [found]"
         else
           return "\n  index: "..index.."\n  STATE: "..response.status.." [found]\n  stringSearch: "..strsearch.." [not found]"
         end
       else
         -- just search @args.index
         return "\n  index: "..index.."\n  STATE: "..response.status.." [found]"
       end

       -- more error codes
     elseif (response.status == 400 ) then
       return "\n  index: "..index.."\n  STATUS: "..response.status.." BAD REQUEST\n    module author: r00t-3xp10it\n"
     elseif (response.status == 302 ) then
       return "\n  index: "..index.."\n  STATUS: "..response.status.." REDIRECTED\n    module author: r00t-3xp10it\n"
     elseif (response.status == 401 ) then
       return "\n  index: "..index.."\n  STATUS: "..response.status.." UNAUTHORIZED\n    module author: r00t-3xp10it\n"
     elseif (response.status == 404 ) then
       return "\n  index: "..index.."\n  STATUS: "..response.status.." NOT FOUND\n    module author: r00t-3xp10it\n"
     elseif (response.status == 403 ) then
       return "\n  index: "..index.."\n  STATUS: "..response.status.." FORBIDDEN\n    module author: r00t-3xp10it\n"
     elseif (response.status == 503 ) then
       return "\n  index: "..index.."\n  STATUS: "..response.status.." UNAVAILABLE\n    module author: r00t-3xp10it\n"
     else
       -- Undefined error code (NOT FOUND)...
       return "\n  index: "..index.."\n  STATUS: "..response.status.." UNDEFINED ERROR\n    module author: r00t-3xp10it\n"
     end
   end
else
     -- Execute local system command (args)
     action = function(host, port)
        os.execute(command)
        return "\n  module author: r00t-3xp10it\n    sys-command: "..command.."\n"
     end
end
