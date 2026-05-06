<#
.SYNOPSIS
   Author: @r00t-3xp10it
   Helper - install nse scripts into nmap database
   
   [nse list]
   vulners.nse,
   AXISwebcam-enum.nse,
   CVE-2026-7633-enum.nse,
   dlink-cve-2019-13101.nse
   smtp-vuln-cve2020-28017-through-28026-21nails.nse

.NOTES
   Administrator privileges required to install\update modules
   .\install_nmap_modules.ps1 -mode 'install' --> install the 5 nse scripts in nmap database
   .\install_nmap_modules.ps1 -mode 'update'  --> update nmap databse with AXISwebcam-enum.nse again
   .\install_nmap_modules.ps1 -nmapinstallpath 'C:\Nmap\Install\directory' --> nmap install location
#>

[CmdletBinding(PositionalBinding=$false)] param(
   [string]$NmapInstallPath="C:\Program Files (x86)\Nmap",
   [string]$Mode="install"
)

$ErrorActionPreference = "SilentlyContinue"
$host.UI.RawUI.WindowTitle = "@install_nmap_nse_modules"

echo ""
## check for admin privileges
If([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") -match "false")
{
   Write-Host "[ABORT]: " -NoNewline
   Write-Host "administrator privileges required to install nse modules..`n" -ForegroundColor Red
   Start-Sleep -Seconds 2
   return
}

## check nmap install directory
If(-not(Test-Path -Path "$NmapInstallPath"))
{
   Write-Host "[ABORT]: nmap directory not found in: $NmapInstallPath" -ForegroundColor Red
   Write-Host "Input nmap directory: " -NoNewline
   $NmapInstallPath = Read-Host

   If(-not(Test-Path -Path "$NmapInstallPath"))
   {
      Write-Host "[ABORT]: nmap directory not found in: $NmapInstallPath" -ForegroundColor Red
      return
   }
}


## Install 5 nse modules into nse database
# TCPinspector.ps1 requires this modules
If($Mode -imatch '^(install)$')
{
   Write-Host "[*] installing nmap nse scripts" -ForegroundColor Green
   Start-Sleep -Seconds 1
   clear-host

   ## install Vulners.nse
   If (Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf)
   {
      write-host "[" -NoNewline
      write-host "x" -ForegroundColor Red -NoNewline
      write-host "] " -NoNewline
      write-host "$NmapInstallPath\scripts\vulners.nse" -ForegroundColor Red -NoNewline
      write-host " already installed"
   }
   Else
   {
$StartBanner = @"

vulners.nse:
For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

Its work is pretty simple:
* work only when some software version is identified for an open port
* take all the known CPEs for that software (from the standard nmap -sV output)
* make a request to a remote server (vulners.com API) to learn whether any known vulns exist for that CPE
* if no info is found this way, try to get it using the software name alone
* print the obtained info out

Output
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

      write-host $StartBanner
      write-host "[+] install vulners.nse (yes|no): " -NoNewline -ForegroundColor Green
      $InstallVulners = Read-Host
      If ($InstallVulners -imatch '^(y|yes)$')
      {
         Write-Host "`n[*] downloading: vulners.nse"
         iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/vulners.nse" -OutFile "$Env:TMP\vulners.nse"|Unblock-File
         Write-Host "[*] move vulners.nse to $NmapInstallPath\scripts\vulners.nse"
         Move-Item -Path "$Env:TMP\vulners.nse" -Destination "$NmapInstallPath\scripts\vulners.nse" -Force

         If (Test-path -path "$NmapInstallPath\scripts\vulners.nse" -PathType Leaf)
         {
            Write-Host "[*] moved vulners.nse to nmap scripts directory"
            Write-Host "[+] updating nmap nse database with vulners.nse"
            nmap.exe --script-updatedb
            Write-Host ""

            Start-Sleep -Seconds 4
            clear-host
         }
         Else
         {
            Write-Host "[-] ERROR: moving vulners.nse to nmap scripts directory" -ForegroundColor Red
            start-sleep -seconds 4
            clear-host
         }
      }
      else
      {
         Clear-Host
      }
   }

   ## install CVE-2026-7633-enum.nse
   If (Test-path -path "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -PathType Leaf)
   {
      write-host "[" -NoNewline
      write-host "x" -ForegroundColor Red -NoNewline
      write-host "] " -NoNewline
      write-host "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -ForegroundColor Red -NoNewline
      write-host " already installed"
   }
   Else
   {

$StartBanner = @"

CVE-2026-7633-enum:
A vulnerability was identified in Totolink N300RH 6.1c.1353_B20190305, this impacts the function
setUploadSetting of the file /cgi-bin/cstecgi.cgi, such manipulation of the @argument FileName
leads to file inclusion, remote code execution, buffer overflow or modification of configurations

how detection works
CVE-2026-7633-enum.nse searchs for /cgi-bin/cstecgi.cgi [uri] on target host has first vulnerability check
has second test it searchs for 'setUploadSetting' vulnerable function (inside /cgi-bin/cstecgi.cgi) then it
searchs for string.match(response.body,"Totolink N300RH 6.1c.13(53|90)") to confirm vulnerable versions

Output
|CVE-2026-7633-enum:
|  Totolink N300RH V6.1c
|  STATE: VULNERABLE
|    ID: CVE:CVE-2026-7633
|    Risk factor: 6.4 (MEDIUM) (AV:N/AC:L/Au:N/C:N/I:P/A:P)
|      A vulnerability was identified in Totolink N300RH 6.1c.1353_B20190305, this impacts the function
|      setUploadSetting of the file /cgi-bin/cstecgi.cgi, such manipulation of the argument FileName leads
|      to file inclusion, remote code execution, buffer overflow or modification of configurations
|
|  Disclosure date: 2026-05-01
|  Exploit results:
|    Uri: http://216.99.115.136:8080/cgi-bin/cstecgi.cgi
|    attack vector: setUploadSetting [vulnerable]
|    firmware version: N300RH 6.1c.1390 [vulnerable]
|    affected versions: V6.1c.1353, V6.1c.1390
|      module Author: r00t-3xp10it
|
|  Referencies:
|    https://www.tenable.com/cve/CVE-2026-7633
|    https://github.com/xyh4ck/iot_poc/tree/main/TOTOLINK/N300RHv4/03_setUploadSetting_ECFNP
|_

"@;

      write-host $StartBanner
      write-host "[+] install CVE-2026-7633-enum.nse (yes|no): " -NoNewline -ForegroundColor Green
      $InstallVulners = Read-Host
      If ($InstallVulners -imatch '^(y|yes)$')
      {
         Write-Host "`n[*] downloading: CVE-2026-7633-enum.nse"
         iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/nmap-nse-modules/refs/heads/master/CVE-2026-7633-enum.nse" -OutFile "$Env:TMP\CVE-2026-7633-enum.nse"|Unblock-File
         Write-Host "[*] move CVE-2026-7633-enum.nse to $NmapInstallPath\scripts\CVE-2026-7633-enum.nse"
         Move-Item -Path "$Env:TMP\CVE-2026-7633-enum.nse" -Destination "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -Force

         If (Test-path -path "$NmapInstallPath\scripts\CVE-2026-7633-enum.nse" -PathType Leaf)
         {
            Write-Host "[*] moved CVE-2026-7633-enum.nse to nmap scripts directory"
            Write-Host "[+] updating nmap nse database with CVE-2026-7633-enum.nse"
            nmap.exe --script-updatedb
            Write-Host ""

            Start-Sleep -Seconds 4
            clear-host
         }
         Else
         {
            Write-Host "[-] ERROR: moving CVE-2026-7633-enum.nse to nmap scripts directory" -ForegroundColor Red
            start-sleep -seconds 4
            clear-host
         }
      }
      else
      {
         Clear-Host
      }
   }

   ## install AXISwebcam-enum.nse
   If (Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
   {
      write-host "[" -NoNewline
      write-host "x" -ForegroundColor Red -NoNewline
      write-host "] " -NoNewline
      write-host "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -ForegroundColor Red -NoNewline
      write-host " already installed"
   }
   Else
   {

$StartBanner = @"

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

Outputs
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
|      Module Author: r00t-3xp10it & Cleiton Pinheiro
|
|  Referencies:
|    https://www.cisa.gov/news-events/ics-advisories/icsa-25-352-08
|    https://thehackernews.com/2025/08/6500-axis-servers-expose-remoting.html
|_

"@;

      write-host $StartBanner
      write-host "[+] install AXISwebcam-enum.nse (yes|no): " -NoNewline -ForegroundColor Green
      $InstallAXIS = Read-Host
      If ($InstallAXIS -imatch '^(y|yes)$')
      {
         Write-Host "`n[*] downloading: AXISwebcam-enum.nse"
         iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/AXISwebcam-enum.nse" -OutFile "$Env:TMP\AXISwebcam-enum.nse"|Unblock-File
         Write-Host "[*] move AXISwebcam-enum.nse to $NmapInstallPath\scripts\AXISwebcam-enum.nse"
         Move-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Destination "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -Force

         If (Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
         {
            Write-Host "[*] moved AXISwebcam-enum.nse to nmap scripts directory"
            Write-Host "[+] updating nmap nse database with AXISwebcam-enum.nse"
            nmap.exe --script-updatedb
            Write-Host ""

            Start-Sleep -Seconds 4
            clear-host
         }
         Else
         {
            Write-Host "[-] ERROR: moving AXISwebcam-enum.nse to nmap scripts directory" -ForegroundColor Red
            Start-Sleep -Seconds 4
            clear-host
         }
      }
      else
      {
         Clear-Host
      }
   }

   ## install dlink-cve-2019-13101.nse
   If (Test-path -path "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -PathType Leaf)
   {
      write-host "[" -NoNewline
      write-host "x" -ForegroundColor Red -NoNewline
      write-host "] " -NoNewline
      write-host "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -ForegroundColor Red -NoNewline
      write-host " already installed"
   }
   Else
   {
$StartBanner = @"

dlink-cve-2019-13101.nse:
Detects whether the D-Link DIR-600 or DIR-615 router is vulnerable to Incorrect Access Control Vulnerability (CVE-2019-13101).
A remote vulnerability was discovered on D-Link DIR-600M/DIR-615 Wireless Home Router in multiple respective firmware versions
(3.02 up to 3.06). The vulnerability provides unauthenticated remote access to the routers WAN configuration page i.e. '/wan.htm'
which leads to disclosure of sensitive user info about the WAN, including but not limited to PPPoE, DNS configuration etc, also
allowing us to change the router configuration settings.

@output
dlink-cve-2019-13101:
|   VULNERABLE:
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
|       Uri: http://37.99.213.95:443/
|       DLink version: DIR-600 Ver 2.17
|       Found a match between (TITLE|PPPoE)
|
|   Referencies:
|     https://nvd.nist.gov/vuln/detail/CVE-2019-13101
|     https://www.cybersecurity-help.cz/vdb/SB2019081001
|     https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13101
|_

"@;

      write-host $StartBanner
      write-host "[+] install dlink-cve-2019-13101.nse (yes|no): " -NoNewline -ForegroundColor Green
      $InstallDlink = Read-Host
      If ($InstallDlink -imatch '^(y|yes)$')
      {
         Write-Host "[*] downloading: dlink-cve-2019-13101.nse"
         iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/nmap-nse-modules/refs/heads/master/dlink-cve-2019-13101.nse" -OutFile "$Env:TMP\dlink-cve-2019-13101.nse"|Unblock-File
         Write-Host "[*] move dlink-cve-2019-13101.nse to $NmapInstallPath\scripts\dlink-cve-2019-13101.nse"
         Move-Item -Path "$Env:TMP\dlink-cve-2019-13101.nse" -Destination "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -Force

         If (Test-path -path "$NmapInstallPath\scripts\dlink-cve-2019-13101.nse" -PathType Leaf)
         {
            Write-Host "[*] moved dlink-cve-2019-13101.nse to nmap scripts directory"
            Write-Host "[+] updating nmap nse database with dlink-cve-2019-13101.nse"
            nmap.exe --script-updatedb
            Write-Host ""

            Start-Sleep -Seconds 4
            clear-host
         }
         Else
         {
            Write-Host "[-] ERROR: moving dlink-cve-2019-13101.nse to nmap scripts directory" -ForegroundColor Red
            Start-Sleep -Seconds 4
            clear-host
         }
      }
      else
      {
         Clear-Host
      }
   }

   ## install smtp-vuln-cve2020-28017-through-28026-21nails.nse
   If (Test-path -path "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -PathType Leaf)
   {
      write-host "[" -NoNewline
      write-host "x" -ForegroundColor Red -NoNewline
      write-host "] " -NoNewline
      write-host "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -ForegroundColor Red -NoNewline
      write-host " already installed"
   }
   Else
   {
$StartBanner = @"

smtp-vuln-cve2020-28017-through-28026-21nails.nse:
Exim remote code execution via CVE-2020-28017 through CVE-2020-28026 also known as 21Nails

We check for the presence of the vulnerability via:
  - Connecting to port 25
  - Receiving the banner
  - Checking the version
  - Returning the state

This check is not intrusive, because:
 - We only complete a TCP connection to the port
 - We do not complete the SMTP protocol handshake

This check may have False Positives if:
  - Patches are back ported but the version number is not updated

This check may have False Negatives if:
  - the Exim server is configured to remove Exim and/or the version number

How to use:
  nmap --script ./smtp-vuln-cve2020-28017-through-28026-21nails.nse [target]

References:
* https://www.qualys.com/2021/05/04/21nails/21nails.txt

"@;

      write-host $StartBanner
      write-host "[+] install smtp-vuln-cve2020-28017-through-28026-21nails.nse (yes|no): " -NoNewline -ForegroundColor Green
      $InstallSmtp = Read-Host
      If ($InstallSmtp -imatch '^(y|yes)$')
      {
         Write-Host "`n[*] downloading: smtp-vuln-cve2020-28017-through-28026-21nails.nse"
         iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/nmap-nse-modules/refs/heads/master/smtp-vuln-cve2020-28017-through-28026-21nails.nse" -OutFile "$Env:TMP\smtp-vuln-cve2020-28017-through-28026-21nails.nse"|Unblock-File
         Write-Host "[*] move smtp-vuln-cve2020-28017-through-28026-21nails.nse to $NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse"
         Move-Item -Path "$Env:TMP\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -Destination "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -Force

         If (Test-path -path "$NmapInstallPath\scripts\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -PathType Leaf)
         {
            Write-Host "[*] moved smtp-vuln-cve2020-28017-through-28026-21nails.nse to nmap scripts directory"
            Write-Host "[+] updating nmap nse database with smtp-vuln-cve2020-28017-through-28026-21nails.nse"
            nmap.exe --script-updatedb
            Write-Host ""

            Start-Sleep -Seconds 4
            clear-host
         }
         Else
         {
            Write-Host "[-] ERROR: moving smtp-vuln-cve2020-28017-through-28026-21nails.nse to nmap scripts directory" -ForegroundColor Red
            Start-Sleep -Seconds 4
            clear-host
         }
      }
      else
      {
         Clear-Host
      }
   }
}

## Update AXISwebcam-enum.nse
If($Mode -imatch '^(update)$')
{
   <#
   .SYNOPSIS
      Author: @r00t-3xp10it
      Helper - update nmap nse database with AXISwebcam-enum.nse script
               even if AXISwebcam-enum.nse its are allready present in db

   .NOTES
      Administrator privileges required to update modules
      .\install_nmap_modules.ps1 -mode 'update'  --> update nmap databse with AXISwebcam-enum.nse again
      .\install_nmap_modules.ps1 -nmapinstallpath 'C:\Nmap\Install\directory' --> nmap install location
   #>

   Write-Host "[*] updating nmap nse database" -ForegroundColor Green
   Start-Sleep -Seconds 1

   ## Updating AXISwebcam-enum.nse
   Write-Host "[*] downloading: AXISwebcam-enum.nse"
   iwr -Uri "https://raw.githubusercontent.com/r00t-3xp10it/hacking-material-books/refs/heads/master/nmap-NSE/AXISwebcam-enum.nse" -OutFile "$Env:TMP\AXISwebcam-enum.nse"|Unblock-File

   Write-Host "[*] move AXISwebcam-enum.nse to $NmapInstallPath\scripts\AXISwebcam-enum.nse"
   Move-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Destination "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -Force

   If(Test-path -path "$NmapInstallPath\scripts\AXISwebcam-enum.nse" -PathType Leaf)
   {
      Write-Host "[*] moved AXISwebcam-enum.nse to nmap scripts directory"
      Write-Host "[+] updating nmap nse database with AXISwebcam-enum.nse"
      nmap.exe --script-updatedb
   }
   Else
   {
      Write-Host "[-] ERROR: moving AXISwebcam-enum.nse to nmap scripts directory" -ForegroundColor Red
   }

   ## Display modules description
   If($Description.IsPresent)
   {
      nmap --script-help AXISwebcam-enum.nse
   }
}

## cleanup
Remove-Item -Path "$Env:TMP\vulners.nse" -Force
Remove-Item -Path "$Env:TMP\AXISwebcam-enum.nse" -Force
Remove-Item -Path "$Env:TMP\dlink-cve-2019-13101.nse" -Force
Remove-Item -Path "$Env:TMP\smtp-vuln-cve2020-28017-through-28026-21nails.nse" -Force

echo ""
exit