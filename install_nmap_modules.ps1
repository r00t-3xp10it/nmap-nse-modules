<#
.SYNOPSIS
   Author: @r00t-3xp10it
   Helper - install nse scripts into nmap database - v1.3

   This script identifys if the nse script its installed in nmap
   database then presents two options to user: install or update
   
   [nse list]
   vulners.nse
   abb-cve-2019-7226
   CVE-2025-11833.nse
   AXISwebcam-enum.nse
   CVE-2026-7633-enum.nse
   dlink-cve-2019-13101.nse
   http-livestreet-brute.nse
   smtp-vuln-cve2020-28017-through-28026-21nails.nse

.NOTES
   Administrator privileges required to install\update modules
   .\install_nmap_modules.ps1 -nmapinstallpath 'C:\Nmap\Install\directory' --> input nmap install location
#>


[CmdletBinding(PositionalBinding=$false)] param(
   [string]$NmapInstallPath="C:\Program Files (x86)\Nmap",
   [switch]$tcpinspector
)

$ErrorActionPreference = "SilentlyContinue"
$host.UI.RawUI.WindowTitle = "@install_nmap_nse_modules"

$FirtBanner = @"

   __ \    __|   _ \
   |   | \__ \   __/
  _|  _| ____/ \___| [Nmap Scripting Engine]
  install\update nmap non-official nse scripts

"@;

## check for admin privileges
If([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") -match "false")
{
   Write-Host "[" -NoNewline
   Write-Host "ABORT" -ForegroundColor DarkRed -NoNewline
   Write-Host "]: " -NoNewline
   Write-Host "administrator privileges required to install nse modules..`n" -ForegroundColor DarkRed
   Start-Sleep -Seconds 2
   return
}

## check nmap install directory
If(-not(Test-Path -Path "$NmapInstallPath"))
{
   Write-Host "[" -NoNewline
   Write-Host "ABORT" -ForegroundColor DarkRed -NoNewline
   Write-Host "]: " -NoNewline
   Write-Host "nmap directory not found in: $NmapInstallPath" -ForegroundColor DarkRed
   Write-Host "Input nmap directory: " -NoNewline -ForegroundColor Blue
   $NmapInstallPath = Read-Host

   If(-not(Test-Path -Path "$NmapInstallPath"))
   {
      Write-Host "[" -NoNewline
      Write-Host "ABORT" -ForegroundColor DarkRed -NoNewline
      Write-Host "]: " -NoNewline
      Write-Host "nmap directory not found in: $NmapInstallPath`n" -ForegroundColor DarkRed
      return
   }
}


## Modules description
$VulnsBanner = @"

vulners.nse:
For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

Its work is pretty simple:
* work only when some software version is identified for an open port
* take all the known CPEs for that software (from the standard nmap -sV output)
* make a request to a remote server (vulners.com API) to learn whether any known vulns exist for that CPE
* if no info is found this way, try to get it using the software name alone
* print the obtained info out

@Output
PORT    STATE SERVICE VERSION 
22/tcp  open  ssh     OpenSSH 9.6p1 Ubuntu 3Ubuntu13.16 (Ubuntu Linux; Protocol 2.0)
|vulners:
|   ISC BIND DNS:
|     CVE-2012-1667    8.5    https://vulners.com/cve/CVE-2012-1667
|     CVE-2002-0651    7.5    https://vulners.com/cve/CVE-2002-0651
|     CVE-2002-0029    7.5    https://vulners.com/cve/CVE-2002-0029  *EXPLOIT*
|     CVE-2015-5986    7.1    https://vulners.com/cve/CVE-2015-5986
|     CVE-2010-3615    5.0    https://vulners.com/cve/CVE-2010-3615  *EXPLOIT*
|     CVE-2006-0987    5.0    https://vulners.com/cve/CVE-2006-0987  *EXPLOIT*
|_    CVE-2014-3214    5.0    https://vulners.com/cve/CVE-2014-3214

"@;

$AXISWebCamBanner = @"

AXISwebcam-enum:
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

@Output
|AXISwebcam-enum:
|  Brute force AXIS network camera URL:
|    [404] 216.99.115.136:8080 => /axis-cgi/media.cgi
|    [404] 216.99.115.136:8080 => /axis-media/media.amp
|    [200] 216.99.115.136:8080 => /view/index.shtml
|
|  STATUS: AXIS WEBCAM FOUND
|    ID: CVE:CVE-2025-30026
|    Risk factor: Medium CVSSv2: 5.3 (MEDIUM) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
|      A flaw in the Axis Camera Station Server that could lead to an authentication
|      bypass by default password settings or by brute force user:password credentials
|
|  Disclosure date: 2025-07-11
|  Exploit results:
|    TITLE: Live view  - AXIS 211 Network Camera version 4.11
|    WEBCAM ACCESS: http://216.99.115.136:8080/view/index.shtml
|      module Author: r00t-3xp10it & Cleiton Pinheiro
|
|  Referencies:
|    https://www.cisa.gov/news-events/ics-advisories/icsa-25-352-08
|    https://thehackernews.com/2025/08/6500-axis-servers-expose-remoting.html
|_

"@;

$TotoLinkBanner = @"

CVE-2026-7633-enum:
A vulnerability was identified in Totolink N300RH 6.1c.1353_B20190305, this impacts the function
setUploadSetting of the file /cgi-bin/cstecgi.cgi, such manipulation of the @argument FileName
leads to file inclusion, remote code execution, buffer overflow or modification of configurations

how detection works
CVE-2026-7633-enum.nse searchs for /cgi-bin/cstecgi.cgi [uri] on target host has first vulnerability
test, has second test it searchs for string.match(response.body,"Totolink N300RH 6.1c.13(53|90)") to
confirm vulnerable versions, has final test sends one http.post() request to test for @args.filename
access [read access] confirming that the vulnerability is 100% present and public exploitable

test if we have read access to /etc/passwd
nmap -sS -T2 <target> -p 80 --open --script CVE-2026-7633-enum --script-args filename="/etc/passwd"
IDS evasion: --script-args filename="/etc/passwd" -D 4.207.247.138,52.123.131.14 --data-length "28"

Output
|Totolink N300RH V6.1c
|  STATE: VULNERABLE
|    ID: CVE:CVE-2026-7633
|    Risk factor: 6.4 (MEDIUM) (AV:N/AC:L/Au:N/C:N/I:P/A:P)
|      A vulnerability was identified in Totolink N300RH 6.1c.1353_B20190305, this impacts the function
|      setUploadSetting of the file /cgi-bin/cstecgi.cgi, such manipulation of the argument FileName leads
|      to file inclusion, remote code execution, buffer overflow or modification of configurations
|
|  Disclosure date: 2026-05-01
|  Exploit results:
|    Uri: http://216.99.115.136:8080/cgi-bin/cstecgi.cgi [found]
|    _firmware version: N300RH 6.1c.1390 [vulnerable version]
|      filename access: /etc/passwd [read access]
|      filename contents: root:x:0:0:root:/root:/bin/bash
|        module Author: r00t-3xp10it
|
|  Referencies:
|    https://www.tenable.com/cve/CVE-2026-7633
|    https://github.com/xyh4ck/iot_poc/tree/main/TOTOLINK/N300RHv4/03_setUploadSetting_ECFNP
|_

"@;

$DlinkBanner = @"

dlink-cve-2019-13101.nse:
Detects whether the D-Link DIR-600 or DIR-615 router is vulnerable to Incorrect Access Control Vulnerability (CVE-2019-13101).
A remote vulnerability was discovered on D-Link DIR-600M/DIR-615 Wireless Home Router in multiple respective firmware versions
(3.02 up to 3.06). The vulnerability provides unauthenticated remote access to the routers WAN configuration page i.e. '/wan.htm'
which leads to disclosure of sensitive user info about the WAN, including but not limited to PPPoE, DNS configuration etc, also
allowing us to change the router configuration settings.

@Output
dlink-cve-2019-13101:
|   D-Link DIR-600/615 Wireless Home Router
|   State: VULNERABLE
|   IDs:  CVE:CVE-2019-13101
|   Risk factor: Medium  CVSSv2: 7.5 (MEDIUM) (AV:N/AC:L/Au:N/C:P/I:P/A:P)
|     A remote vulnerability was discovered on D-Link DIR-600/DIR-615 Wireless Home Router in multiple respective firmware
|     versions (3.02 up to 3.06). The vulnerability provides unauthenticated remote access to the routers WAN configuration
|     page i.e. '/wan.htm', which leads to disclosure of sensitive info about the WAN, including but not limited to PPPoE,
|     DNS configuration etc, also allowing us to change the router configuration settings.
|
|   Disclosure date: 2019-Ago-08
|   Exploit results:
|     Uri: http://37.99.213.95:443/
|     DLink version: DIR-600 Ver 2.17
|     Found a match between (TITLE|PPPoE)
|       module Author: r00t-3xp10it
|
|   Referencies:
|     https://nvd.nist.gov/vuln/detail/CVE-2019-13101
|     https://www.cybersecurity-help.cz/vdb/SB2019081001
|     https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13101
|_

"@;

$ABBBanner = @"

abb-cve-2019-7226:
NSE script to detect if target [ip]:[port][/url] its affected by CVE-2019-7226 (Improper Authentication)
The ABB IDAL HTTP server CGI interface contains a URL that allows an unauthenticated attacker to bypass authentication
and gain access to privileged functions. Specifically, /cgi/loginDefaultUser creates a session in an authenticated state
and returns the session ID along with what may be the username and cleartext password of the user. An attacker can then
supply an IDALToken value in a cookie, which will allow them to perform privileged operations such as restarting the service
with /cgi/restart.

@output
PORT     STATE SERVICE VERSION
80/tcp open  http  Apache httpd 2.4.38
| abb-cve-2019-7226:
|   ABB IDAL HTTP server CGI (Improper Authentication)
|   State: VULNERABLE
|   IDs:  CVE:CVE-2019-7226
|   Risk factor: Higth  CVSSv2: 8.8 HIGH (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
|     The ABB IDAL HTTP server CGI interface contains a URL that allows an unauthenticated attacker to bypass
|     authentication and gain access to privileged functions. Specifically, /cgi/loginDefaultUser creates a session
|     in an authenticated state and returns the session ID along with what may be the username and cleartext password
|     of the user. An attacker can then supply an IDALToken value in a cookie, which will allow them to perform privileged
|     operations such as restarting the service with /cgi/restart. A GET request to /cgi/loginDefaultUser may result in
|     '1 #S_OK IDALToken=532c8632b86694f0232a68a0897a145c admin admin' or a similar response.
|
|   Disclosure date: 2019-Fev-04
|   Exploit results:
|     Uri: http://192.168.1.71:80/cgi/loginDefaultUser
|     Auth-Cookie: IDALToken=008b1047k72068r6100a69b0381d007p
|     Credentials: inconspicuous => MyS3cr3t
|       module Author: r00t-3xp10it
|
|   Referencies:
|     https://nvd.nist.gov/vuln/detail/CVE-2019-7226
|     https://www.akaoma.com/ressources/cve/gain-privilege/cve-2019-7226
|     https://packetstormsecurity.com/files/153402/ABB-IDAL-HTTP-Server-Authentication-Bypass.html
|_

"@;

$LiveBanner = @"

http-livestreet-brute.nse:
performs brute force password auditing against livestreet CMS installations.

This script uses the unpwdb and brute libraries to perform password guessing.
Any successful guesses are stored using the credentials library.

@usage
nmap -sV --script http-livestreet-brute <target>
nmap -sV --script http-livestreet-brute
     --script-args 'userdb=users.txt,passdb=passwds.txt,http-livestreet-brute.hostname=domain.com,
                    http-livestreet-brute.threads=3,brute.firstonly=true' <target>

referencies:
   https://nvd.nist.gov/vuln/detail/cve-2017-5638
   https://github.com/Z-0ne/ScanS2-045-Nmap

@output
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack
| http-livestreet-brute:
|   Accounts
|     admin:qwerty => Login correct
|   Statistics
|_    Perfomed 103 guesses in 17 seconds, average tps: 6

"@;

$SecretFinder = @"

secret-finder.nse:
Detects exposed sensitive files, misconfigured backups, version control
directories, environment files and private resources that may cause critical
information leakage on web servers. [scan ports: 80 tcp, 443 tcp]

PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
| secret-finder:  [INFO]  [200]  /
|  [INFO]  [200]  /images
|  [CRITICAL]  [403]  /.svn
|  [CRITICAL]  [403]  /.svn/
|  [CRITICAL]  [403]  /.htaccess
|  [CRITICAL]  [403]  /.htpasswd
|  [CRITICAL]  [403]  /.htaccess.bak
|_ [CRITICAL]  [403]  /.htpasswd.bak

"@;

$install11833 = @"

CVE-2025-11833:
The Post SMTP - Complete SMTP Solution with Logs, Alerts, Backup SMTP & Mobile App plugin
for WordPress is vulnerable to unauthorized access of data due to a missing capability check
on the __construct function in all versions up to and including, 3.6.0 This makes it possible
for unauthenticated attackers to read arbitrary logged emails sent through the Post SMTP plugin,
including password reset emails containing password reset links which can lead to account takeover

Remark: --script-args exploit="true" argument sends a http.post() request with a link to reset
the wordpress admin password, then checks if target host responds with the recuperation link to
confirm that system its 100% vulnerable to CVE-2025-11833 wordpress reset link vulnerability.

Some web developers have moved /wp-login.php landing webpage further ahead in the website directory
structure like: 'http://host:port/website/plugins/wp-login.php' in that case invoke CVE-2025-1183.nse:
--script-args uri="/website/plugins/wp-login.php" (required if invoked: --script-args exploit="true")

Output
PORT   STATE SERVICE   VERSION
25/tcp open  post smtp 3.6.0
CVE-2025-11833-enum:
|  TITLE: post-smtp
|  STATE: VULNERABLE
|   ID: CVE:CVE-2025-11833
|   Risk factor: 9.8 (CRITICAL) (AV:N/AC:L/Au:N/C:N/I:P/A:P)
|     unauthenticated attackers can access logged emails in Post SMTP plugin including
|     password reset links, enabling full WordPress account takeover without authentication.
|
|  Disclosure date: 2025-11-01
|  Exploit results:
|   smtp detection: post smtp 3.6.0 [vulnerable version]
|   _post request: /wp-login.php?action=lostpassword&page=postman_email_log&view=log&log_id=1&print=1
|   _response: password reset link found in response [vulnerable]
|     module author: r00t-3xp10it
|
| Referencies:
|   https://www.sentinelone.com/vulnerability-database/cve-2025-11833
|_

"@;

$installsmtpvuln = @"

smtp-vuln-cve2020-28017:
Exim remote code execution via CVE-2020-28017 through CVE-2020-28026 also known as 21Nails

We check for the presence of the vulnerability via:
  - Connecting to port 25
  - Receiving the banner
  - Checking the version
  - Returning the state

This check may have False Positives if:
  - Patches are back ported but the version number is not updated

This check may have False Negatives if:
  - the Exim server is configured to remove Exim and/or the version number

Output
PORT   STATE SERVICE
25/tcp open  smtp
smtp-vuln-cve2020-28017:
|  TITLE: Exim remote code execution via CVE-2020-28017 through CVE-2020-28026 also known as 21Nails
|  STATE: VULNERABLE
|   ID: CVE:CVE-2020-28017
|   Risk factor: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
|     In May 2021 21 vulnerabilities were disclosed in the Exim mailserver. Of these 10 were remote
|     vulnerabilities that could yield among other things remote code execution and memory contents
|     revelation remotely. For a significant majority of the vulnerabilities they have been present
|     since at least 2004 in the code base.
|
|  Disclosure date: 2021-05-04
|
| Referencies:
|   https://www.qualys.com/2021/05/04/21nails/21nails.txt
|_

"@;

## Main Menu
function Invoke-Menu() 
{
   Do
   {
      Clear-Host
      Write-Host $FirtBanner -ForegroundColor DarkRed
      Write-Host "  option  module                   disclosure  CVE             severity"
      Write-Host "  ------  ------                   ----------  ---             --------" -ForegroundColor Blue
      Write-Host "  1       vulners                  ***         ***             ***"
      Write-Host "  2       AXISwebcam-enum          2025-07-11  CVE-2025-30026  MEDIUM 5.3 "
      Write-Host "  3       CVE-2026-7633-enum       2026-05-01  CVE-2026-7633   MEDIUM 6.4"
      Write-Host "  4       dlink-cve-2019-13101     2019-08-08  CVE-2019-13101  MEDIUM 7.5"
      Write-Host "  5       smtp-vuln-cve2020-28017  2020-04-13  CVE-2020-28017  CRITICAL 9.8"
      Write-host "  6       abb-cve-2019-7226        2019-02-04  CVE-2019-7226   HIGH 8.8"
      Write-Host "  7       http-livestreet-brute    2017-10-03  CVE-2017-5638   CRITICAL 9.8"
      Write-Host "  8       CVE-2025-11833.nse       2025-11-01  CVE-2025-11833  CRITICAL 9.8"
      Write-Host "  9       secret-finder            2026-o1-10  ***             ***"
      If(-not($tcpinspector.IsPresent))
      {
         Write-Host "  manual  install one nse script   [<https://raw.git/..> OR <C:\Users\..>]" -ForegroundColor White -BackgroundColor DarkGray
      }
      Write-Host "  Q       exit script execution" -ForegroundColor Green
      Write-Host "`nChose Option: " -NoNewline -ForegroundColor Blue
      $Choise = Read-Host
 
      switch ($Choise) 
      {
         1 
         {
            ## INSTALL VULNERS
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $VulnsBanner
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $InstallVulners = Read-Host
            If($InstallVulners -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: vulners.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/vulners.nse" -OutFile "$Env:TMP\vulners.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving vulners.nse to $NmapInstallPath\scripts\vulners.nse"
               Move-Item -Path "$Env:TMP\vulners.nse" -Destination "$NmapInstallPath\scripts\vulners.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with vulners.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help vulners.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\vulners.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\vulners.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving vulners.nse to nmap scripts directory`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($InstallVulners -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }

               ## delete script
               Remove-Item -Path "$NmapInstallPath\scripts\vulners.nse" -Force
               ## update database
               nmap.exe --script-updatedb
               Start-Sleep -Seconds 2
            }
            ## end of function
         }
         2 
         {
            ## INSTALL AXISwebcam-enum
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $AXISWebCamBanner
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $InstallAXIS = Read-Host
            If($InstallAXIS -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: AXISwebcam-enum.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/AXISwebcam-enum.nse" -OutFile "$Env:TMP\AXISwebcam-enum.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving AXISwebcam-enum.nse to $NmapInstallPath\scripts\AXISwebcam-enum.nse"
               Move-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Destination "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with AXISwebcam-enum.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help AXISwebcam-enum.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\AXISwebcam-enum.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\AXISwebcam-enum.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving AXISwebcam-enum.nse to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($InstalSecret -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }

               ## delete script
               Remove-Item -Path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -Force
               ## update database
               nmap.exe --script-updatedb
               Start-Sleep -Seconds 2
            }
            ## end of function
         }
         3 
         {
            ## INSTALL CVE-2020-7633-enum
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $TotoLinkBanner
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $InstallTotoLink = Read-Host
            If($InstallTotoLink -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: CVE-2026-7633-enum.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/nmap-nse-modules/refs/heads/master/CVE-2026-7633-enum.nse" -OutFile "$Env:TMP\CVE-2026-7633-enum.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving CVE-2026-7633-enum.nse to $NmapInstallPath\scripts\CVE-2026-7633-enum.nse"
               Move-Item -Path "$Env:TMP\CVE-2026-7633-enum.nse" -Destination "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with CVE-2026-7633-enum.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help CVE-2026-7633-enum.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving CVE-2026-7633-enum.nse to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($InstallTotoLink -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }

               ## delete script
               Remove-Item -Path "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -Force
               ## update database
               nmap.exe --script-updatedb
               Start-Sleep -Seconds 2
            }
            ## end of function
         }
         4
         {
            ## INSTALL dlink-cve-2019-13101
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $DlinkBanner
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $InstallDlink = Read-Host
            If($InstallDlink -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: dlink-cve-2019-13101.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/dlink-cve-2019-13101.nse" -OutFile "$Env:TMP\dlink-cve-2019-13101.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving dlink-cve-2019-13101.nse to $NmapInstallPath\scripts\dlink-cve-2019-13101.nse"
               Move-Item -Path "$Env:TMP\dlink-cve-2019-13101.nse" -Destination "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with dlink-cve-2019-13101.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help dlink-cve-2019-13101.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving dlink-cve-2019-13101.nse to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($InstallDlink -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }

               ## delete script
               Remove-Item -Path "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -Force
               ## update database
               nmap.exe --script-updatedb
               Start-Sleep -Seconds 2
            }
            ## end of function    
         }
         5
         {
            ## INSTALL smtp-vuln-cve2020-28017-through-28026-21nails.nse
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $installsmtpvuln
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $InstallSMTP = Read-Host
            If($InstallSMTP -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: dlink-cve-2019-13101.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/smtp-vuln-cve2020-28017-through-28026-21nails.nse" -OutFile "$Env:TMP\smtp-vuln-cve2020-28017-through-28026-21nails.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving smtp-vuln-cve2020-28017-through-28026-21nails.nse to $NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse"
               Move-Item -Path "$Env:TMP\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -Destination "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with smtp-vuln-cve2020-28017-through-28026-21nails.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help smtp-vuln-cve2020-28017-through-28026-21nails.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving smtp-vuln-cve2020-28017-through-28026-21nails.nse to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($InstallSMTP -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }

               ## delete script
               Remove-Item -Path "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -Force
               ## update database
               nmap.exe --script-updatedb
               Start-Sleep -Seconds 2
            }
            ## end of function
         }
         6
         {
            ## INSTALL abb-cve-2019-7226.nse
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\abb-cve-2019-7226.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $ABBBanner
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $InstallABB = Read-Host
            If($InstallABB -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: abb-cve-2019-7226.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/abb-cve-2019-7226.nse" -OutFile "$Env:TMP\abb-cve-2019-7226.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving abb-cve-2019-7226.nse to $NmapInstallPath\scripts\abb-cve-2019-7226.nse"
               Move-Item -Path "$Env:TMP\abb-cve-2019-7226.nse" -Destination "$NmapInstallPath\scripts\abb-cve-2019-7226.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\abb-cve-2019-7226.nse" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with abb-cve-2019-7226.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help abb-cve-2019-7226.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\abb-cve-2019-7226.nse " -ForegroundColor Green
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\abb-cve-2019-7226.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving abb-cve-2019-7226.nse to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($InstallABB -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\abb-cve-2019-7226.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }

               ## delete script
               Remove-Item -Path "$NmapInstallPath\scripts\abb-cve-2019-7226.nse" -Force
               ## update database
               nmap.exe --script-updatedb
               Start-Sleep -Seconds 2
            }
            ## end of function
         }
         7
         {
            ## install http-livestreet-brute.nse
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\http-livestreet-brute.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $LiveBanner
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $InstallLIve = Read-Host
            If($InstallLIve -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: http-livestreet-brute.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/http-livestreet-brute.nse" -OutFile "$Env:TMP\http-livestreet-brute.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving http-livestreet-brute.nse to $NmapInstallPath\scripts\http-livestreet-brute.nse"
               Move-Item -Path "$Env:TMP\http-livestreet-brute.nse" -Destination "$NmapInstallPath\scripts\http-livestreet-brute.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\http-livestreet-brute.nse" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with http-livestreet-brute.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help http-livestreet-brute.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\http-livestreet-brute.nse " -ForegroundColor Green
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\http-livestreet-brute.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving http-livestreet-brute.nse to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($InstallLIve -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\http-livestreet-brute.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }

               ## delete script
               Remove-Item -Path "$NmapInstallPath\scripts\http-livestreet-brute.nse" -Force
               ## update database
               nmap.exe --script-updatedb
               Start-Sleep -Seconds 2
            }
            ## end of function
         }
         8
         {
            ## install CVE-2025-11833
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\CVE-2025-11833.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $install11833
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $Instal11833 = Read-Host
            If($Instal11833 -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: CVE-2025-11833.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/nmap-nse-modules/refs/heads/master/CVE-2025-11833.nse" -OutFile "$Env:TMP\CVE-2025-11833.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving CVE-2025-11833.nse to $NmapInstallPath\scripts\CVE-2025-11833.nse"
               Move-Item -Path "$Env:TMP\CVE-2025-11833.nse" -Destination "$NmapInstallPath\scripts\CVE-2025-11833.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\CVE-2025-11833.nse" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with CVE-2025-11833.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help CVE-2025-11833.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\CVE-2025-11833.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\CVE-2025-11833.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving CVE-2025-11833.nse to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($Instal11833 -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\CVE-2025-11833.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }
            }
            ## end of function    
         }
         9
         {
            ## install secret-finder
            $UpDateNse = "false"
            If(Test-path -path "$NmapInstallPath\scripts\secret-finder.nse" -PathType Leaf)
            {
               $UpDateNse = "true"
            }

            write-host $SecretFinder
            If($UpDateNse -match '^(true)$')
            {
               write-host "[" -NoNewline
               write-host "UPDATE" -NoNewline -ForegroundColor DarkRed
               write-host "] " -NoNewline
               write-host "nmap database with this module? (yes|no|delete): " -NoNewline -ForegroundColor Blue
            }
            Else
            {
               write-host "[" -NoNewline
               write-host "INSTALL" -NoNewline -ForegroundColor Green
               write-host "] " -NoNewline
               write-host "this module into nmap database? (yes|no): " -NoNewline -ForegroundColor Blue
            }

            $InstalSecret = Read-Host
            If($InstalSecret -imatch '^(y|yes)$')
            {
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: secret-finder.nse"
               iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/secret-finder.nse" -OutFile "$Env:TMP\secret-finder.nse"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving secret-finder.nse to $NmapInstallPath\scripts\secret-finder.nse"
               Move-Item -Path "$Env:TMP\secret-finder.nse" -Destination "$NmapInstallPath\scripts\secret-finder.nse" -Force

               If(Test-path -path "$NmapInstallPath\scripts\secret-finder.nse" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with secret-finder.nse"
                  nmap.exe --script-updatedb
                  nmap --script-help secret-finder.nse

                  If($UpDateNse -match '^(true)$')
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\secret-finder.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "updated" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  Else
                  {
                     write-host "`n[" -NoNewline
                     write-host "*" -ForegroundColor Green -NoNewline
                     write-host "] " -NoNewline
                     write-host "$NmapInstallPath\scripts\secret-finder.nse " -ForegroundColor Green -NoNewline
                     write-host "[" -NoNewline
                     write-host "installed" -ForegroundColor Green -NoNewline
                     write-host "]"
                  }
                  cmd /c 'pause'
               }
               Else
               {
                  Write-Host "[ERROR]: moving secret-finder.nse to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }
            }
            ElseIf($InstalSecret -imatch '^(delete)$')
            {
               If(-not(Test-path -path "$NmapInstallPath\scripts\secret-finder.nse" -PathType Leaf))
               {
                  write-host "[" -NoNewline
                  write-host "X" -ForegroundColor DarkRed -NoNewline
                  write-host "] " -NoNewline
                  write-host "error, nse not installed in nmap database..`n" -ForegroundColor DarkRed
                  cmd /c 'pause'
                  Invoke-Menu
               }

               ## delete script
               Remove-Item -Path "$NmapInstallPath\scripts\secret-finder.nse" -Force
               ## update database
               nmap.exe --script-updatedb
               Start-Sleep -Seconds 2
            }
            ## end of function
         }
         manual
         {
            ## install ONE nse script manually
            Write-Host "input nse absoluct path: " -ForegroundColor Blue -NoNewline
            $ManualInstallNse = Read-Host

            ## check user inputs
            If([string]::IsNullOrEmpty($ManualInstallNse))
            {
               write-host "| Invalid option [empty], please try again .." -ForegroundColor DarkRed
               write-host "|   help: this function accepts links <http(s)://raw.githubusercontent.com/..>"
               write-host "|_        or absoluct paths <C:\users\desktop\module.nse>`n"
               cmd /c 'pause'
               Invoke-Menu
            }

            If($ManualInstallNse -iNotMatch '(.nse)$')
            {
               write-host "| Invalid option [not .nse], please try again .." -ForegroundColor DarkRed
               write-host "|_  help: script to import to database must be in [.NSE] format"
               cmd /c 'pause'
               Invoke-Menu            
            }

            If($ManualInstallNse -match '^(htt(p|ps)://)')
            {
               If($ManualInstallNse -NotMatch '^(htt(p|ps)://raw)')
               {
                  write-host "| Invalid option, wrong url format.." -ForegroundColor DarkRed
                  write-host "|   help: this function only accepts [RAW] url links"
                  write-host "|_  example: <https://raw.githubusercontent.com/../module.nse>`n"
                  cmd /c 'pause'
                  Invoke-Menu
               }

               $nsename = ($ManualInstallNse).Split('/')[-1]
               Write-Host "`n[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] downloading: $nsename"
               iwr -Uri "$ManualInstallNse" -OutFile "$Env:TMP\$nsename"|Unblock-File
               Write-Host "[" -NoNewline
               Write-Host "2" -NoNewline -ForegroundColor Green
               Write-Host "] moving $nsename to $NmapInstallPath\scripts\$nsename"
               Move-Item -Path "$Env:TMP\$nsename" -Destination "$NmapInstallPath\scripts\$nsename" -Force

               If(Test-path -path "$NmapInstallPath\scripts\$nsename" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "3" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with $nsename"

                  nmap.exe --script-updatedb
                  nmap.exe --script-help $nsename

                  write-host "`n[" -NoNewline
                  write-host "*" -ForegroundColor Green -NoNewline
                  write-host "] " -NoNewline
                  write-host "$NmapInstallPath\scripts\$nsename " -ForegroundColor Green -NoNewline
                  write-host "[" -NoNewline
                  write-host "installed" -ForegroundColor Green -NoNewline
                  write-host "]"
               }
               Else
               {
                  Write-Host "[ERROR]: moving $nsename to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }

               cmd /c 'pause'
               Invoke-Menu
            }
            ElseIf($ManualInstallNse -imatch '(.nse)$')
            {
               $nsename = ($ManualInstallNse).Split('\\')[-1]
               If(-not(Test-Path -Path "$ManualInstallNse" -PathType Leaf))
               {
                   write-host "| Invalid option, nse path not found.." -ForegroundColor DarkRed
                   write-host "|   help: this function accepts links <http(s)://raw.githubusercontent.com/../module.nse>"
                   write-host "|_        or absoluct paths <C:\users\desktop\module.nse>`n"
                   cmd /c 'pause'
                   Invoke-Menu
               }

               Write-Host "[" -NoNewline
               Write-Host "1" -NoNewline -ForegroundColor Green
               Write-Host "] Copy $nsename to $NmapInstallPath\scripts\$nsename"
               Copy-Item -Path "$ManualInstallNse" -Destination "$NmapInstallPath\scripts\$nsename" -Force

               If(Test-path -path "$NmapInstallPath\scripts\$nsename" -PathType Leaf)
               {
                  Write-Host "[" -NoNewline
                  Write-Host "2" -NoNewline -ForegroundColor Green
                  Write-Host "] updating nmap nse database with $nsename"

                  nmap.exe --script-updatedb
                  nmap.exe --script-help $nsename

                  write-host "`n[" -NoNewline
                  write-host "*" -ForegroundColor Green -NoNewline
                  write-host "] " -NoNewline
                  write-host "$NmapInstallPath\scripts\$nsename " -ForegroundColor Green -NoNewline
                  write-host "[" -NoNewline
                  write-host "installed" -ForegroundColor Green -NoNewline
                  write-host "]"
               }
               Else
               {
                  Write-Host "[ERROR]: moving $nsename to nmap scripts directory" -ForegroundColor DarkRed
                  cmd /c 'pause'
               }

               cmd /c 'pause'
               Invoke-Menu
            }
            Else
            {
               write-host "| Invalid option, please try again.." -ForegroundColor DarkRed
               write-host "|   help: this function accepts links <http(s)://raw.githuvusercontent.com/../module.nse>"
               write-host "|_        or absoluct paths <C:\users\desktop\module.nse>`n"
               cmd /c 'pause'
               Invoke-Menu
            }
         }
         Q
         {
            Exit
         }   
         default
         {
            write-host "[" -NoNewline
            write-host "X" -ForegroundColor DarkRed -NoNewline
            write-host "] " -NoNewline
            write-host "Invalid option, please try again .." -ForegroundColor DarkRed
            Start-Sleep -Seconds 3
         }
      }
   }
   until($Choise -eq 'q')
}  

## invoke menu
Invoke-Menu

exit
