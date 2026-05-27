<b><i><H1>my collection of nmap non-official nse scripts</H1></b></i>

<br />

### Install [windows]

  [admin] copy to: `C:\Program Files (x86)\nmap\scripts\<script_name.nse>` <br />
  [admin] Update NSE database: `nmap --script-updatedb`

<br />

### Install [linux]

[admin] Copy to: `/usr/share/nmap/scripts/<script_name.nse>` <br />
[admin] Update NSE database: `sudo nmap --script-updatedb`

<br />

### Script help
Help: `nmap --script-help <script_name.nse>`

<br />

### use `install_nmap_modules.ps1` to install\update\delete nse scripts
`waening: execute install_nmap_modules.ps1 with administrator privileges`
```
iwr -uri "https://raw.githubusercontent.com/r00t-3xp10it/nmap-nse-modules/refs/heads/master/install_nmap_modules.ps1" -outfile "install_nmap_modules.ps1"|Unblock-File;.\install_nmap_modules.ps1
```
