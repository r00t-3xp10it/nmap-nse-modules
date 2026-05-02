---
-- Nmap NSE AXISwebcam-enum.nse - Version 1.16
-- [linux:admin] Copy to: /usr/share/nmap/scripts/AXISwebcam-enum.nse
-- [linux:admin] Update NSE database: sudo nmap --script-updatedb
-- [windows:admin] copy to: C:\Program Files (x86)\nmap\scripts\AXISwebcam-enum.nse
-- [windows:admin] Update NSE database: nmap --script-updatedb
-- Help: nmap --script-help AXISwebcam-enum.nse
--
-- Version 1.15 update
-- [1] fix: nse script color scheme (output colorization) throws errors (deleted)
-- [2] fix: use library stdnse.sleep(1.5) to invoke sleep() functions insted of invoking io.sleep()
-- [3] @args.logfile = "C:\Users\Nmap_scan.txt" --> create or appends scan data to existing logfile.txt
-- [4] URI's added: /img/video.asf, /axis-cgi/mjpg/video.cgi, /axis-media/media.amp, /axis-cgi/media.cgi
--
-- Version 1.16 update
-- [1] fix: res.status == nil --> host webserver stop responding to our probes after a while
-- [2] URI's added: /fullsize.jpg?camera=, /hugesize.jpg?camera=, /axis-cgi/basicdeviceinfo.cgi
--                  /mjpg/video.mjpg, /mjpg/1/video.mjpg, /mpeg4/media.amp, /videostream.asf?user=
--                  /cgi-bin/viewer/video.jpg, /videostream.cgi?user=, /control/faststream.jpg?stream=
---

description = [[

Module Author: r00t-3xp10it & Cleiton Pinheiro
NSE script to detect if target [ip]:[port][/url] its an AXIS Network Camera transmiting (live).
This script also allow is users to send a fake User-Agent in the tcp packet <agent=User-Agent-String>
also allow is users to input a diferent uri= [/url] link to be scan, IF none uri= value its inputed, then
this script tests a List of AXIS default [/url's] available in our database to brute force url access link.
remark: 'This nse script does not brute force any authentication login of webcams found (only enumeration)'

how detection works
AXISwebcam-enum.nse attempts to find the webcam access link [uri] by comparing links in its internal database
against the target host:port/uri - If a match is found, the script attempts to extract the webcam's model and
manufacturer from the http <title> tag as a final check before identifying the target as an active AXIS webcam
remark: 'This nse script will NOT produce outputs while brute forcing webcam version\vendor from <title> tag'

Syntax examples
nmap --script-help AXISwebcam-enum.nse
nmap -sS -T4 222.155.98.15 -p 8081 --open --script AXISwebcam-enum
nmap -sS -T3 183.95.71.129 -p 8081 --open --script AXISwebcam-enum --script-args logfile="$pwd\Nmap_scan.txt"
nmap -sS -T4 192.46.209.62 -p 8082 --script AXISwebcam-enum --script-args agent="Mozilla/5.0 (compatible; EvilMonkey)"
nmap -sS -T4 193.93.22.133 -p 8080 --open --script AXISwebcam-enum --script-args agent="Mozilla/5.0",uri="/camera.shtml"
nmap -sS -T4 161.81.122.107 -p 8080-8082 --open --script AXISwebcam-enum --script-args uri="/CgiStart/loadingpage=cam.shtml"
nmap -sS -v -T5 -iR 800 -p 8080-8082 --open --script AXISwebcam-enum -D 4.207.247.138,52.123.131.14

Outputs
|AXISwebcam-enum:
|  Brute force AXIS network camera URL:
|    [404] 216.99.115.136:8080 => /axis-cgi/media.cgi
|    [404] 216.99.115.136:8080 => /axis-media/media.amp
|    [200] 216.99.115.136:8080 => /view/index.shtml
|
|  STATUS: AXIS WEBCAM FOUND
|    TITLE: Live view  - AXIS 211 Network Camera version 4.11
|      WEBCAM ACCESS: http://216.99.115.136:8080/view/index.shtml
|        Module Author: r00t-3xp10it & Cleiton Pinheiro
|_

]]

---
-- @usage
-- nmap --script-help AXISwebcam-enum.nse
-- nmap -sS -T4 222.155.98.15 -p 8081 --open --script AXISwebcam-enum
-- nmap -sS -T3 183.95.71.129 -p 8081 --open --script AXISwebcam-enum --script-args logfile="$pwd\Nmap_scan.txt"
-- nmap -sS -T4 192.46.209.62 -p 8082 --script AXISwebcam-enum --script-args agent="Mozilla/5.0 (compatible; EvilMonkey)"
-- nmap -sS -T4 193.93.22.133 -p 8080 --open --script AXISwebcam-enum --script-args agent="Mozilla/5.0",uri="/camera.shtml"
-- nmap -sS -T4 161.81.122.107 -p 8080-8082 --open --script AXISwebcam-enum --script-args uri="/CgiStart/loadingpage=cam.shtml"
-- nmap -sS -v -T5 -iR 800 -p 8080-8082 --open --script AXISwebcam-enum -D 4.207.247.138,52.123.131.14
-- @output
-- |AXISwebcam-enum:
-- |  Brute force AXIS network camera URL:
-- |    [404] 216.99.115.136:8080 => /axis-cgi/media.cgi
-- |    [404] 216.99.115.136:8080 => /axis-media/media.amp
-- |    [200] 216.99.115.136:8080 => /view/index.shtml
-- |
-- |  STATUS: AXIS WEBCAM FOUND
-- |    TITLE: Live view  - AXIS 211 Network Camera version 4.11
-- |      WEBCAM ACCESS: http://216.99.115.136:8080/view/index.shtml
-- |        Module Author: r00t-3xp10it & Cleiton Pinheiro
-- |_
-- @args payload.uri the path name to search. default: /indexFrame.shtml
-- @args payload.agent User-agent to send in request - default: iPhone,safari
-- @args payload.logfile logfile.txt to create or append data - default: false
----

author = "r00t-3xp10it & Cleiton Pinheiro"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

-- required (lua librarys)
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local http = require "http"

-- nse script @arguments declarations
local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/indexFrame.shtml"
local logfile = stdnse.get_script_args(SCRIPT_NAME..".logfile") or "false"

local options = {header={}}
-- Manipulate TCP packet 'header' with false information about attacker :D
options['header']['User-Agent'] = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (iPhone; CPU iPhone OS 6_1_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25"
options['header']['Accept-Language'] = "en-GB,en;q=0.8,sv"
options['header']['Cache-Control'] = "no-store"


portrule = shortport.port_or_service({80, 81, 82, 83, 84, 85, 86, 92, 8080, 8081, 8082, 8083, 55752, 55754}, "http, http-proxy", "tcp", "open")

action = function(host, port)
    print("|AXISwebcam-enum:")
    print("|  Brute force AXIS network camera URL:")

    -- Check target host http.response.codes
    local check_uri = http.get(host, port, uri, options)
    if ( check_uri.status == 401 ) then   --> uri auth login found
        print("|    ["..check_uri.status.."] => http://"..host.ip..":"..port.number..uri.." (AUTH LOGIN FOUND)")
        print("|")
        print("|  STATUS: POSSIBLE AXIS WEBCAM FOUND?")
        print("|    WEBCAM ACCESS: http://"..host.ip..":"..port.number..uri.." [LOGIN]")
        print("|      ABORT SCANS: webcam access requires authentication login")
        print("|        Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] => http://"..host.ip..":"..port.number..uri.." (AUTH LOGIN FOUND)\n")
            file:write("|\n")
            file:write("|  STATUS: POSSIBLE AXIS WEBCAM FOUND?\n")
            file:write("|    WEBCAM ACCESS: http://"..host.ip..":"..port.number..uri.." [LOGIN]\n")
            file:write("|      ABORT SCANS: webcam access requires authentication login\n")
            file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end
    return

    elseif ( check_uri.status == 404 ) then  --> uri not found
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        -- Source: https://www.ispyconnect.com/camera/axis
        -- Source: https://camera-sdk.com/p_6646-how-to-connect-to-a-axis-camera.html
        uril = {"/CgiStart?page=", "/axis-cgi/media.cgi", "/axis-media/media.amp", "/axis-cgi/mjpg/video.cgi", "/axis-cgi/basicdeviceinfo.cgi", "/cgi-bin/viewer/video.jpg", "/videostream.cgi?user=", "/videostream.asf?user=", "/hugesize.jpg?camera=", "/fullsize.jpg?camera=", "/control/faststream.jpg?stream=", "/webcam_code.php", "/view/view.shtml", "/indexFrame.shtml", "/view/index.shtml", "/view/index2.shtml", "/webcam/view.shtml", "/ViewerFrame.shtml", "/RecordFrame?Mode=", "/MultiCameraFrame?Mode=", "/view/viewer_index.shtml", "/visitor_center/i-cam.html", "/index.shtml", "/mjpg/video.mjpg", "/mpeg4/media.amp", "/mjpg/1/video.mjpg", "/stadscam/Live95j.asp", "/sub06/cam.php", "/img/video.asf"}

        limmit = 0
        -- loop Through {table} of uri url's
        for i, intable in pairs(uril) do
            local res = http.get(host, port, intable)
            if ( res.status == 200 ) then  --> he found one alive [200 = OK]
                print("|    ["..res.status.."] "..host.ip..":"..port.number.." => "..intable.." [online]")
                uri = intable
                break
            else
                limmit = limmit+1
                if ( res.status == nil ) then
                    print("|    [NIL] "..host.ip..":"..port.number.." => [connection failed]")
                    print("|")
                    print("|  STATUS: NONE AXIS WEBCAM URI FOUND")
                    print("|    REASON: webserver have stop responding to our probes")
                    print("|        Module Author: r00t-3xp10it & Cleiton Pinheiro")
                    print("|_\n")

                    -- append data to logfile?
                    if ( logfile ~= "false" ) then
                        local file = io.open(logfile, "a")
                        file:write("|AXISwebcam-enum:\n")
                        file:write("|  Brute force AXIS network camera URL:\n")
                        file:write("|    [NIL] "..host.ip..":"..port.number.." => "..intable.."\n")
                        file:write("|\n")
                        file:write("|  STATUS: NONE AXIS WEBCAM URI FOUND\n")
                        file:write("|    REASON: webserver have stop responding to our probes\n")
                        file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
                        file:write("|_\n")
                        file:close()
                    end
                    return
                else
                    print("|    ["..res.status.."] "..host.ip..":"..port.number.." => "..intable)
                end

                if ( limmit == 29 ) then --> why 29? Because its the number of URI links present in the {uril} list.
                    print("|")
                    print("|  STATUS: NONE AXIS WEBCAM URI FOUND")
                    print("|    REASON: script didnt find any uri matches in our database")
                    print("|      HELP: nmap --script AXISwebcam-enum --script-args uri='/another/index-name.shtml'")
                    print("|        Module Author: r00t-3xp10it & Cleiton Pinheiro")
                    print("|_\n")

                    -- append data to logfile
                    if ( logfile ~= "false" ) then
                        local file = io.open(logfile, "a")
                        file:write("|AXISwebcam-enum:\n")
                        file:write("|  Brute force AXIS network camera URL:\n")
                        file:write("|    ["..res.status.."] "..host.ip..":"..port.number.." => "..intable.."\n")
                        file:write("|\n")
                        file:write("|  STATUS: NONE AXIS WEBCAM URI FOUND\n")
                        file:write("|    REASON: script didn't find any uri matches in our database\n")
                        file:write("|      HELP: nmap --script AXISwebcam-enum --script-args uri='/another/index-name.shtml'\n")
                        file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
                        file:write("|_\n")
                        file:close()
                    end
                    return
                end
            end
        end

    -- diferent Http response codes
    elseif ( check_uri.status == nil ) then
        print("|    [NIL] "..host.ip..":"..port.number.." => [socket error]")
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: NIL [socket error]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    [NIL] "..host.ip..":"..port.number.." => [socket error]\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: NIL [socket error]\n")
            file:write("|      Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    elseif ( check_uri.status == 200 ) then
        -- we have a possitive http.response.code [200 = OK]
        -- send uri for second test (search webcam version\vendor from <title> tag)
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
    elseif ( check_uri.status == 301 ) then
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [Moved Permanently]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [Moved Permanently]\n")
            file:write("|      Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    elseif ( check_uri.status == 307 ) then
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [Temporary Redirect]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [Temporary Redirect]\n")
            file:write("|      Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    elseif ( check_uri.status == 400 ) then
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [Bad Request]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    WEBCAM ACCESS: http://"..host.ip..":"..port.number..uri.." [LOGIN]\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [Bad Request]\n")
            file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    elseif ( check_uri.status == 403 ) then
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [Forbidden]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [Forbidden]\n")
            file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    elseif ( check_uri.status == 405 ) then
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [Method Not Allowed]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [Method Not Allowed]\n")
            file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    elseif ( check_uri.status == 500 ) then
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [Internal Server Error]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [Internal Server Error]\n")
            file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    elseif ( check_uri.status == 502 ) then
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [Bad Gateway]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [Bad Gateway]\n")
            file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    elseif ( check_uri.status == 503 ) then
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [Service Unavailable]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [Service Unavailable]\n")
            file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end

        do return end
    else
        print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => [unknown]")
        print("|")
        print("|  STATUS: NONE AXIS WEBCAM FOUND")
        print("|    ABORT: http response code: "..check_uri.status.." [unknown]")
        print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
        print("|_\n")

        -- append data to logfile?
        if ( logfile ~= "false" ) then
            local file = io.open(logfile, "a")
            file:write("|AXISwebcam-enum:\n")
            file:write("|  Brute force AXIS network camera URL:\n")
            file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => [unknown]\n")
            file:write("|\n")
            file:write("|  STATUS: NONE AXIS WEBCAM FOUND\n")
            file:write("|    ABORT: http response code: "..check_uri.status.." [unknown]\n")
            file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
            file:write("|_\n")
            file:close()
        end
    end

    -- Read response from target (http.get)
    -- search for webcam version\vendor from <title> tag
    local response = http.get(host, port, uri, options)
    if ( response.status == 200 ) then
        local title = string.match(response.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

        -- List {table} of HTTP TITLE tags
        tbl = {"TL-WR740N",
               "AXIS Video Server",
               "Live View / - AXIS",
               "AXIS 2400 Video Server",
               "Axis 2420 Video Server",
               "Network Camera TUCCAM1",
               "AXIS F34 Network Camera",
               "AXIS 243Q(2) Blade 4.45",
               "Axis 2120 Network Camera",
               "Axis 2420 Network Camera",
               "Network Camera Capitanía",
               "AXIS Q7401 Video Encoder",
               "AXIS M3004 Network Camera",
               "AXIS P1353 Network Camera",
               "AXIS P5514 Network Camera",
               "AXIS Q1615 Network Camera",
               "AXIS P1357 Network Camera",
               "AXIS M5013 Network Camera",
               "AXIS M3026 Network Camera",
               "AXIS M1124 Network Camera",
               "Network Camera Hwy285/cr43",
               "AXIS M1145-L Network Camera",
               "AXIS 214 PTZ Network Camera",
               "Login - Residential Gateway",
               "AXIS Q6045-E Network Camera",
               "AXIS Q6044-E Network Camera",
               "Axis 2130 PTZ Network Camera",
               "Network Camera NetworkCamera",
               "AXIS P1435-LE Network Camera",
               "AXIS P1425-LE Network Camera",
               "AXIS M2025-LE Network Camera",
               "AXIS Q1765-LE Network Camera",
               "AXIS V5914 PTZ Network Camera",
               "AXIS P1354 Fixed Network Camera",
               "AXIS P1365 Mk II Network Camera",
               "AXIS P5635-E Mk II Network Camera",
               "AXIS Q6045-E Mk II Network Camera",
               "AXIS P5534 PTZ Dome Network Camera",
               "Live view / - AXIS 205 version 4.03",
               "Live view  - AXIS 240Q Video Server",
               "AXIS Q6042-E PTZ Dome Network Camera",
               "Live view  - AXIS 221 Network Camera",
               "Live view  - AXIS 211 Network Camera",
               "AXIS Q6034-E PTZ Dome Network Camera",
               "AXIS P3354 Fixed Dome Network Camera",
               "AXIS Q3505 Fixed Dome Network Camera",
               "Live view  - AXIS P1354 Network Camera",
               "Live view  - AXIS P1344 Network Camera",
               "Live view  - AXIS M1114 Network Camera",
               "Live view  - AXIS M1103 Network Camera",
               "Live view  - AXIS M1025 Network Camera",
               "Live view - AXIS P5534-E Network Camera",
               "Live view  - AXIS 215 PTZ Network Camera",
               "Live view  - AXIS 214 PTZ Network Camera",
               "Live view  - AXIS 213 PTZ Network Camera",
               "Live view - AXIS 206M Network Camera version",
               "Live view  - AXIS 211 Network Camera version",
               "Live view / - AXIS 205 Network Camera version",
               "Live view / - AXIS 205 Network Camera version",
               "AXIS P5635-E Mk II PTZ Dome Network Camera",
               "Live view / - AXIS 205 Network Camera version",
               "Live view - AXIS 213 PTZ Network Camera version"}

        -- nil error handling
        -- cant find any <title> tag
        if ( title == nil ) then
            print("|")
            print("|  STATUS: AXIS WEBCAM MATCHING URI FOUND")
            print("|    TITLE: webpage doesn't have a <title> tag? [response:nil]")
            print("|      URI ACCESS: http://"..host.ip..":"..port.number..uri)
            print("|        Module Author: r00t-3xp10it & Cleiton Pinheiro")
            print("|_\n")

            -- append data to logfile?
            if ( logfile ~= "false" ) then
                local file = io.open(logfile, "a")
                file:write("|AXISwebcam-enum:\n")
                file:write("|  Brute force AXIS network camera URL:\n")
                file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
                file:write("|\n")
                file:write("|  STATUS: AXIS WEBCAM MATCHING URI FOUND\n")
                file:write("|    TITLE: webpage doesn't have a <title> tag? [response:nil]\n")
                file:write("|      URI ACCESS: http://"..host.ip..":"..port.number..uri.."\n")
                file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
                file:write("|_\n")
                file:close()
            end
            do return end
        end

        titletag = 0
        -- Loop Through {table} of HTTP TITLE tags
        for i, intable in pairs(tbl) do
            local validar = string.match(title, intable)
            if ( validar ~= nil or title == intable ) then  --> uri found + version-vendor retrieved from <title>
                print("|")
                print("|   STATUS: AXIS WEBCAM FOUND")
                print("|     TITLE: "..intable)
                print("|       WEBCAM ACCESS: http://"..host.ip..":"..port.number..uri)
                print("|         Module Author: r00t-3xp10it & Cleiton Pinheiro")
                print("|_\n")

                -- append data to logfile?
                if ( logfile ~= "false" ) then
                    local file = io.open(logfile, "a")
                    file:write("|AXISwebcam-enum:\n")
                    file:write("|  Brute force AXIS network camera URL:\n")
                    file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
                    file:write("|\n")
                    file:write("|  STATUS: AXIS WEBCAM FOUND\n")
                    file:write("|    TITLE: "..intable.."\n")
                    file:write("|      URI ACCESS: http://"..host.ip..":"..port.number..uri.."\n")
                    file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
                    file:write("|_\n")
                    file:close()
                end
                break
            else
                titletag = titletag+1
                if (titletag == 68) then   --> uri found - but failed to match version-vendor from <title>
                    print("|")
                    print("|   STATUS: AXIS WEBCAM MATCHING URI FOUND")
                    print("|     TITLE: failed to match version-vendor from <title>")
                    print("|       URI ACCESS: http://"..host.ip..":"..port.number..uri)
                    print("|         Module Author: r00t-3xp10it & Cleiton Pinheiro")
                    print("|_\n")

                    -- append data to logfile?
                    if ( logfile ~= "false" ) then
                        local file = io.open(logfile, "a")
                        file:write("|AXISwebcam-enum:\n")
                        file:write("|  Brute force AXIS network camera URL:\n")
                        file:write("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri.."\n")
                        file:write("|\n")
                        file:write("|  STATUS: AXIS WEBCAM MATCHING URI FOUND\n")
                        file:write("|    TITLE: failed to match version-vendor from <title>\n")
                        file:write("|      URI ACCESS: http://"..host.ip..":"..port.number..uri.."\n")
                        file:write("|        Module Author: r00t-3xp10it & Cleiton Pinheiro\n")
                        file:write("|_\n")
                        file:close()
                    end
                    do return end
                end
            end
        end
    end
end
