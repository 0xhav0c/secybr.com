---
title: Shodan.io Tutorials for Best Practices
categories: [red team, reconing]
tags: [shodan.io, shodan tutorials, shodan best practicies, enumeration with shodan, shodan usage, red-team]
comments: true
---
# What is Shodan?

![Untitled](/assets/img/pitcures/red-team/shodan.png)

Shodan (Sentient-Hyper-Optimized-Data-Access-Network) is a search engine. Shodan is a search engine that enables many computer-based systems to be found in the light of various filters. With Shodan, you can scan the internet and detect the systems, devices, devices (desktop, switch, router, servers, etc.) that are open to the internet, and the results you find can be determined by port, type. You can classify them according to their location, port information, banner and service information.

# Shodan Command-Line Interface

Once you have installed shodan CLI tool, to setup your API token just do

```shell
shodan init <YOUR_API_KEY>
```

Help menu

```shell
alert       Manage the network alerts for your account.
convert     Convert the given input data file into a different
format.
count       Returns the number of results for a search.
data        Bulk data access to Shodan.
domain      View all available information for a domain.
download    Download search results and save them in a compressed
JSON file.
honeyscore  Check whether the IP is a honeypot or not.
host        View all available information for an IP address.
info        Shows general information about your account.
init        Initialize the Shodan command-line.
myip        Print your external IP address.
org         Manage your organization’s access to Shodan.
parse       Extract information out of compressed JSON files.
radar       Real-Time Map of some results as Shodan finds them.
scan        Scan an IP/ netblock using Shodan.
search      Search the Shodan database.
stats       Provide summary information about a search query.
stream      Stream data in real-time.
version     Print version of this tool.
```

See information about the host such as where it’s located, what ports are open and which organization owns the IP.

```shell
shodan host 192.168.x.x
```

![Untitled](/assets/img/pitcures/red-team/shodan1.png)

Example shodan command-line query

```shell
shodan search --fields location.country_code3,ip_str,hostnames --separator ::  "Server: gSOAP/2.8" "Content-Length: 583"
```

![Untitled](/assets/img/pitcures/red-team/shodan2.png)

Output:

![Untitled](/assets/img/pitcures/red-team/shodan3.png)

Download and parse the search fields

```shell
shodan download mikrotik streetlight
shodan parse --fields location.country_code3,ip_str,hostnames --separator :: mikrotik.json.gz
shodan download myresults.json.gz 'org:"Qatar General Electricty and Water Corporation"'
shodan parse --fields ip_str --separator :: myresults.json.gz
```

![Untitled](/assets/img/pitcures/red-team/shodan4.png)

# Shodan Filters

## General Filters

| Name | Description | Type |
| --- | --- | --- |
| after | Only show results after the given date (dd/mm/yyyy) string | string |
| asn | Autonomous system number string | string |
| before | Only show results before the given date (dd/mm/yyyy) string | string |
| category | Available categories: ics, malware string | string |
| city | Name of the city string | string |
| country | 2-letter country code string | string |
| geo | Accepts between 2 and 4 parameters. If 2 parameters: latitude,longitude. If 3 parameters: latitude,longitude,range. If 4 parameters: top left latitude, top left longitude, bottom right latitude, bottom right longitude. | string |
| hash | Hash of the data property integer | integer |
| has_ipv6 | True/ False boolean | boolean |
| has_screenshot | True/ False boolean | boolean |
| hostname | Full hostname for the device string | string |
| ip | Alias for net filter string | string |
| isp | ISP managing the netblock string | string |
| net | Network range in CIDR notation (ex. 199.4.1.0/24) string | string |
| org | Organization assigned the netblock string | string |
| os | Operating system string | string |
| port | Port number for the service integer | string |
| postal | Postal code (US-only) string | string |
| product | Name of the software/ product providing the banner string | string |
| region | Name of the region/ state string | string |
| state | Alias for region string | string |
| version | Version for the product string | string |
| vuln | CVE ID for a vulnerability string | string |

## Telnet Filters

| Name | Description | Type |
| --- | --- | --- |
| telnet.option | Search all the options | string |
| telnet.do | The server requests the client do support these options | string |
| telnet.dont | The server requests the client to not support these options | string |
| telnet.will | The server supports these options | string |
| telnet.wont | The server doesnt support these options | string |

## HTTP Filters

| Name | Description | Type |
| --- | --- | --- |
| http.component | Name of web technology used on the website | string |
| http.component_category | Category of web components used on the website | string |
| http.html | HTML of web banners | string |
| http.html_hash | Hash of the website HTML | integer |
| http.status | Response status code | integer |
| http.title | Title for the web banners website | string |

## SSL Filters

| Name | Description | Type |
| --- | --- | --- |
| has_ssl | True / False | boolean |
| ssl | Search all SSL data | string |
| ssl.alpn | Application layer protocols such as HTTP/2 ("h2") | string |
| ssl.chain_count | Number of certificates in the chain | integer |
| ssl.version | Possible values: SSLv2, SSLv3, TLSv1,TLSv1.1, TLSv1.2 | string |
| ssl.cert.alg | Certificate algorithm | string |
| ssl.cert.expired | True / False | boolean |
| ssl.cert.extension | vNames of extensions in the certificate | string |
| ssl.cert.serial | Serial number as an integer or hexadecimal string | integer / string |
| ssl.cert.pubkey.bits | Number of bits in the public key | integer |
| ssl.cert.pubkey.type | Public key type | string |
| ssl.cipher.version | SSL version of the preferred cipher | string |
| ssl.cipher.bits | Number of bits in the preferred cipher | integer |
| ssl.cipher.name | Name of the preferred cipher | string |

## NTP Filters

| Name | Description | Type |
| --- | --- | --- |
| ntp.ip | IP addresses returned by monlist | string |
| ntp.ip_count | Number of IPs returned by initial monlist | integer |
| ntp.more | True/ False; whether there are more IP addresses to be gathered from monlist | boolean |
| ntp.port | Port used by IP addresses in monlist | integer |

# Awesome Shodan Queries

## Industrial control systems

```shell
"[1m[35mWelcome on console"  #  C4 Max Commercial Vehicle GPS Trackers
"[2J[H Encartele Confidential"  #  Prison Pay Phones
"Cisco IOS" "ADVIPSERVICESK9_LI-M"  #  Telcos Running Cisco Lawful Intercept Wiretaps
"Cobham SATCOM" OR ("Sailor" "VSAT")  #  Maritime Satellites
"DICOM Server Response" port:104  #  DICOM Medical X-Ray Machines
"HID VertX" port:4070  #  Door / Lock Access Controllers
"in-tank inventory" port:10001  #  Gas Station Pump Controllers
"log off" "select the appropriate"  #  Railroad Management
"Server: CarelDataServer" "200 Document follows"  #  CAREL PlantVisor Refrigeration Units
"Server: EIG Embedded Web Server" "200 Document follows"  #  GaugeTech Electricity Meters 
"Server: gSOAP/2.8" "Content-Length: 583"  #  We can also find electric vehicle chargers
"Server: Microsoft-WinCE" "Content-Length: 12581"  #  Siemens HVAC Controllers
"Server: Prismview Player"  #  Samsung Electronic Billboards
"Siemens, SIMATIC" port:161  #  Siemens Industrial Automation
"voter system serial" country:US  #  Voting Machines in the United States
http.title:"Nordex Control" "Windows 2000 5.0 x86" "Jetty/3.1 (JSP 1.1; Servlet 2.2; java 1.6.0_14)"  #  Nordex Wind Turbine Farms
http.title:"Tesla PowerPack System" http.component:"d3" -ga3ca4f2  #  Tesla PowerPack Charging Status
mikrotik streetlight  #  Traffic Light Controllers / Red Light Cameras
P372 "ANPR enabled"  #  Automatic License Plate Readers
port:5006,5007 product:mitsubishi  #  And for Mitsubishi Electric, the MELSEC-Q protocol is commonly used by control system machines/networks
title:"Slocum Fleet Mission Control"  #  Submarine Mission Control Dashboards
title:"xzeres wind"  #  to find XZERES Wind Turbines
```

![Untitled](/assets/img/pitcures/red-team/shodan5.png)

## Webcams

```shell
ACTi  #  various IP camera and video management system products.
has_screenshot:true IP Webcam  #  another version of the above search, see how the results might differ?
Netwave IP Camera Content-Length: 2574  #  access to the Netwave make IP cameras.
product:Yawcam has_screenshot:true  #  Yawcam stands for Yet Another WebCAM, free live streaming and webcam software.
server: GeoHttpServer  #  GeoVision (GeoHttpServer) Webcams, older webcam software with some had well documented vulnerabilities.
server: VVTK-HTTP-Server  #  Vivotek IP cameras.
server: webcamxp  #  webcamXP is one of the most popular and commonly encountered network camera software for Windows OS. 
server: i-Catcher Console  #  another example of an IP-based CCTV system.
server: "webcam 7"  #  webcam 7 cameras; not as popular as the above type, but still they are still popular and encountered out there.
title:camera  #  general search for anything matching the “camera” keyword.
title:tm01  #  unsecured Linksys webcams, a lot of them with screenshots.
title:”Avigilon”  #  access to the Avigilion brand camera and monitoring devices.
Network Camera VB-M600  #  Canon manufactured megapixel security cameras.
title:ui3  #  UI3 is a  HTML5 web interface for Blue Iris mentioned above.
webcam has_screenshot:true  #  a general search for any IoT device identified as a webcam that has screenshots available.
WVC80N  #  Linksys WVC80N cameras.
WWW-Authenticate: “Merit LILIN Ent. Co., Ltd.”  #  a UK-based house automation / IP camera provider.
```

![Untitled](/assets/img/pitcures/red-team/shodan6.png)

## Database Searches

```shell
product:MySQL  #  broad search for MySQL databases.
mongodb port:27017  #  MongoDB databases on their default port. Unsecured by default.
"MongoDB Server Information" port:27017  #  another variation of the above search.
"MongoDB Server Information" port:27017 -authentication # To find MongoDB database servers which have open authentication over the public internet within Shodan, the following search query can be used:
"MongoDB Server Information { "metrics":"  #  fully open MongoDBs.
"Set-Cookie: mongo-express=" "200 OK"  #  MongoDB open databases.
kibana content-length:217  #  Kibana dashboards accessible without authentication.
port:"9200" all:elastic  #  Elasticsearch open databases.
port:5432 PostgreSQL  #  remote connections to PostgreSQL servers.
product:"CouchDB"  #  Apache CouchDB databases listed.
port:"5984"+Server: "CouchDB/2.1.0"  #  vulnerable CouchDB where remote code execution may be possible.
```

![Untitled](/assets/img/pitcures/red-team/shodan7.png)

## Network Infrastructure

```shell
title:"Weave Scope" http.favicon.hash:567176827  #  Weave Scope Dashboards
"Docker Containers:" port:2375  #  Docker APIs
"Docker-Distribution-Api-Version: registry" "200 OK" -gitlab  #  Docker Private Registries
"dnsmasq-pi-hole" "Recursion: enabled"  #  Pi-hole Open DNS Servers
"root@" port:23 -login -password -name -Session  #  Already Logged-In as root via Telnet
"Android Debug Bridge" "Device" port:5555  #  Android Root Bridges
Lantronix password port:30718 -secured  #  Lantronix Serial-to-Ethernet Adapter Leaking Telnet Passwords
"Citrix Applications:" port:1604  #  Citrix Virtual Apps
"smart install client active"  #  Cisco Smart Install
PBX "gateway console" -password port:23  #  PBX IP Phone Gateways
http.title:"- Polycom" "Server: lighttpd"  #  Polycom Video Conferencing
"Polycom Command Shell" -failed port:23  #  Telnet Configuration
"Server: Bomgar" "200 OK"  #  Bomgar Help Desk Portal
"Intel(R) Active Management Technology" port:623,664,16992,16993,16994,16995  #  Intel Active Management CVE-2017-5689
HP-ILO-4 !"HP-ILO-4/2.53" !"HP-ILO-4/2.54" !"HP-ILO-4/2.55" !"HP-ILO-4/2.60" !"HP-ILO-4/2.61" !"HP-ILO-4/2.62" !"HP-iLO-4/2.70" port:1900  #  HP iLO 4 CVE-2017-12542
"x-owa-version" "IE=EmulateIE7" "Server: Microsoft-IIS/7.0"  #  Exchange 2007
"x-owa-version" "IE=EmulateIE7" http.favicon.hash:442749392  #  Exchange 2010
"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"  #  Exchange 2013 / 2016
"X-MS-Server-Fqdn"  #  Lync / Skype for Business
```

## Files & Directories

```shell
http.title:"Index of /"  #  open lists of files and directories on various servers.
port:80 title:"Index of /"  #  slight variation of the above, note how the results might differ.
http.title:"Index of /" http.html:".pem"  #  Apache Directory Listings
"220" "230 Login successful." port:21  #  FTP resources potentially accessible without login credentials.
230 "anonymous@ login ok"  #  anonymous login allowed to FTP resources.
"Anonymous+access+allowed" port:"21"  #  as above.
vsftpd 2.3.4  #  legacy Linux based FTP service with a widely known security vulnerability
ftp port:"10000" #  Network Data Management Protocol (NDMP), used for backup of network-attached storage (NAS) devices.
"Authentication: disabled" port:445 product:"Samba"  #  SMB file sharing
"QuickBooks files OverNetwork" -unix port:445  #  default settings for sharing QuickBooks files.
filezilla port:"21"  #  popular file sharing software Filezilla.
proftpd port:21  #  For FTP, querying for proftpd, a popular FTP server
```

## Network Attached Storage (NAS)

```shell
"Authentication: disabled" port:445  #  SMB (Samba) File Shares
"Authentication: disabled" NETLOGON SYSVOL -unix port:445  #  Specifically domain controllers
"Authentication: disabled" "Shared this folder to access QuickBooks files OverNetwork" -unix port:445  #  Concerning default network shares of QuickBooks files
"Set-Cookie: iomega=" -"manage/login.html" -http.title:"Log In"  #  Iomega / LenovoEMC NAS Drives 
Redirecting sencha port:9000  #  Buffalo TeraStation NAS Drives
"Server: Logitech Media Server" "200 OK"  #  Logitech Media Servers 
"X-Plex-Protocol" "200 OK" port:32400  #  Plex Media Servers
"CherryPy/5.1.0" "/home"  #  Tautulli / PlexPy Dashboards
```

## VOIP Devices

```shell
39 voip  #  some more VoIP services, mostly behind login screens
AddPac  #  an older VoIP provider, nearly exclusively legacy devices.
device:"voip phone"  #  more specific search for anything VoIP containing a “phone” keyword.
device:"voip"  #  general search for Voice over IP devices.
mcu: tandberg  #  Tandberg is a hardware manufacturer of multi-point control units for video conferencing.
Server: MSOS/2.0 mawebserver/1.1  #  VoIP media gateway, commonly used by services such as Patton SN4112 FXO.
server: snom  #  Snom is a VoIP provider with some legacy devices online.
title:"openstage"  #  Siemens Openstage brand IP phones.
title:"polycom"  #  Polycom is another VoIP communication brand.
```

## Maritime devices

```shell
ECDIS  #  abbreviation for Electronic Chart Display and Information Systems, used in navigation and autopilot systems.
inmarsat  #  as above, but a slightly less known equipment vendor.
maritime  #  general search for anything related to maritime devices.
org:marlink  #  general search; Marlink is the world’s largest maritime satellite communications provider.
sailor  #  another wide search, could yield unrelated results!
satcom  #  another maritime satellite communications services provider.
ssl:"Cobham SATCOM"  #  maritime radio and locations systems.
title:"Slocum Fleet Mission Control"  #  maritime mission control software.
uhp vsat terminal software -password  #  satellite network router without a password.
vsat  #  abbreviation for “very-small-aperture terminal”, a data transmitter / receiver commonly used by maritime vessels.
```

## SSL certificates

```shell
ssl.cert.subject.cn:*.example.com  #  to find the IP addresses of company-owned certificates.
```

## Legacy Windows operating systems

```shell
os:"Windows 5.0"  #  Windows 2000; support ended in 2010.
os:"Windows 5.1"  #  Windows XP; support ended in 2014.
os:Windows 2003  #  Windows Server 2003; support ended in 2015.
os:"Windows Vista"  #  Windows Vista; support ended in 2017.
os:Windows 2008  #  Windows Server 2008; support ended in 2020.
os:"Windows 7"  #  Windows 7; support ended in 2020.
os:"Windows 8"  #  Windows 8; support ended in 2016.
os:Windows 2011  #  Windows Home Server 2011; support ended in 2016.
os:"Windows 8.1"  #  Windows 8.1; support ended in 2018.
os:Windows 2012  #  Windows Server 2012; support ended in 2018.
```

## Default - Generic credentials

```shell
admin 1234  #  basic very unsecure credentials.
html:"def_wirelesspassword"  #  default login pages for routers.
port:23 console gateway  #  remote access via Telnet, no password required.
test test port:"80"  #  generic test credentials over HTTP.
"authentication disabled" port:5900,5901  #  VNC services without authentication.
"authentication disabled" "RFB 003.008"  #  no authentication necessary.
"default password"  #  speaks for itself…
"polycom command shell"  #  possible authentication bypass to Polycom devices.
"root@" port:23 -login -password -name -Session  #  accounts already logged in with root privilege over Telnet, port 23.
"server: Bomgar" "200 OK"  #  Bomgar remote support service.
```

# Printers

```shell
http 200 server epson -upnp  #  HTTP accessible Epson printers.
port:161 hp  #  HP printers that can be restarted remotely via port 161.
port:23 "Password is not set"  #  open access via Telnet to printers without set passwords.
Printer Type: Lexmark  #  access to control panels for Lexmark make printers.
printer  #  general search for printers.
ssl:"Xerox Generic Root"  #  remote access to Xerox printers.
title:"syncthru web service"  #  older Samsung printers, not secured by default.
"HP-ChaiSOE" port:"80"  #  HP LaserJet printers accessible through HTTP.
"Laser Printer FTP Server"  #  printers accessible via FTP with anonymous login allowed.
"Location: /main/main.html" debut  #  admin pages of Brother printers, not secured.
"Server: CANON HTTP Server"  #  Canon printer servers through HTTP connection.
"Server: EPSON-HTTP" "200 OK"  #  another variation of the above search.
```

## Compromised devices and websites

```shell
bitcoin has_screenshot:true  #  searches for the ‘bitcoin’ keyword, where a screenshot is present (useful for RDP screens of endpoints infected with ransomware).
hacked  #  general search for the ‘hacked’ label.
http.title:"0wn3d by"  #  resourced labelled as ‘owned’ by a threat agent, hacker group, etc.
http.title:"Hacked by"  #  another variation of the same search filter.
port:4444 system32  #  compromised legacy operating systems. Port 4444 is the default port for Meterpreter  #  a Metasploit attack payload with an interactive shell for remote code execution.
port:"27017" "send_bitcoin_to_retrieve_the_data"  #  databases affected by ransomware, with the ransom demand still associated with them.
"attention"+"encrypted"+port:3389  #  ransomware infected RDP services.
"hacked by"  #  another variation of the above search.
"HACKED FTP server"  #  compromised FTP servers.
"HACKED-ROUTER-HELP-SOS-HAD-DEFAULT-PASSWORD"  #  compromised hosts with the name changed to that phrase.
"HACKED-ROUTER"  #  compromised routers, labelled accordingly.
```

## Miscellaneous

```shell
http.html:"* The wp-config.php creation script uses this file"  #  misconfigured WordPress websites.
http.title:"control panel"  #  as above, but whatever is labelled as control panels.
http.title:"dashboard"  #  literally anything labelled ‘dashboard’, with many not accessible due to security by default.
http.title:"Nordex Control"  #  searches for Nordex wind turbine farms.
http.title:"Tesla"  #   anything with the term “Tesla” in the banner.
solar  #  controls for solar panels and similar solar devices.
"DICOM Server Response" port:104  #  DICOM medical machinery.
"ETH  #  Total speed"  #  Ethereum cryptocurrency miners.
"in-tank inventory" port:10001  #  petrol pumps, including their physical addresses.
"Server: EIG Embedded Web Server" "200 Document follows"  #  EIG electricity meters.
port:"11211" product:"Memcached"  # UDP amplification attacks leading to huge DDoS attacks
"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"  #  often the starting point of any software being built for release
"port: 53" Recursion: Enabled  #  DNS servers with recursion enabled can be a huge source of network threats.
title:"OctoPrint" -title:"Login" http.favicon.hash:1307375944  #  OctoPrint 3D Printer Controllers
"ETH - Total speed"  #  Etherium Miners
http.html:"* The wp-config.php creation script uses this file"  #  Misconfigured WordPress
"Minecraft Server" "protocol 340" port:25565  #  Too Many Minecraft Servers
net:175.45.176.0/22,210.52.109.0/24,77.94.35.0/24  #  Literally Everything in North Korea
TCP Quote of the Day  #  TCP Quote of the Day
```

Or you can get help about what you are looking for here. (Use ctrl + F.)


| Vendor | Product | Comment | Dorks |
| --- | --- | --- | --- |
| ABB | AC 800M | Controller | ABB AC 800M |
| ABB | RTU560 | Substation automation product | ABB RTU560 |
| ABB | RTU500 | Remote Terminal Unit | ABB RTU-Helpdesk |
| ABB | SREA-01 | Ethernet Adapter Module | ABB SREA-01 |
| ABB | Generic | Multiple Devices | ABB Webmodule |
| ACKP | Generic | Multiple Devices, often data center monitoring | AKCP Embedded Web Server |
| Adcon Telemetry | A440 Wireless Modem | Base Station | A440 Wireless Modem |
| Adcon Telemetry | A850 Telemetry Gateway | Base Station for Adcon Wireless Sensor Networks | A850 Telemetry Gateway |
| Adcon Telemetry | addUPI-OPC Server | . | addUPI Server |
| Adcon Telemetry | addVANTAGE Pro 6.X | HMI | addVANTAGE |
| Adcon Telemetry | Generic | Generic | title:adcon |
| Beck IPC | IPC@CHIP | PLC | IPC@CHIP |
| Cimetrics | Eplus - B/IP to B/WS Gateway Firewall | networking products for distributed monitoring and control systems | Cimetrics Eplus Web Server |
| Clorius Controls A/S | ISC SCADA | SCADA Software | ISC SCADA Service HTTPserv:00001 |
| Codesys | WebVisu | . | Webvisu |
| CodeSys | WebVisu | . | Visu Remote Login |
| Codesys | . | . | port:2455 operating system |
| CodeSys | . | . | 3S-Smart Software Solutions |
| Delta Controls | enteliTOUCH | HMI Building automation | DELTA enteliTOUCH |
| Echelon | i.LON SmartServer 2.0 | Building Energy Management Solution,  LonWorks/IP Server,  Internet Server | i.LON |
| General Electric | CIMPLICITY WebView | CIMPLICITY is HMI/SCADA | CIMPLICITY WebView |
| General Electric | Cimplicity | CIMPLICITY is HMI/SCADA | CIMPLICITY-HttpSvr |
| General Electric | Proficy | Historian (now named GE Digital) | ProficyPortal |
| General Electric | . | Service Request Transport Protocol (GE-SRTP) | port:18245,18246 product:"general electric" |
| Generic | . | Modus | port:502 |
| Generic | . | dnp | port:20000 source address |
| Generic | . | BACnet protocol (Data Communication Protocol for Building Automation and Control Networks) | port:47808 |
| Generic | - | EtherNet/IP | port:44818 |
| Generic | . | The HART Communications Protocol (Highway Addressable Remote Transducer Protocol) is an early implementation of Fieldbus, a digital industrial automation protocol. | port:5094 hart-ip |
| Generic | goAhead embedded webserver | . | GoAhead-Webs InitialPage.asp |
| Generic | . | . | Modbus Bridge |
| Generic | . | . | ModbusGW |
| Generic | Generic | Generic | PLC type |
| Generic | Generic | Generic | PLC name |
| Generic | Industrial Ethernet system, open-source used by various vendoes | openPowerlink, ethernet-powerlink.org devices (PLC HMI ..) | Powerlink |
| Generic | . | . | SCADA |
| Generic | . | . | webSCADA |
| HMS | EtherNet/IP / Modbus-TCP Interface | Generic | HMS AnyBus-S WebServer |
| Honeywell EnergyICT | eiPortal | Energy Monitoring Software | eiPortal |
| Honeywell EnergyICT | RTU | Remote Data Concentrator | EnergyICT RTU |
| KW Software, Inc. | . | ProConOS / PLC | port:20547 PLC |
| Lantronix | . | . | lantronix |
| Lantronix | . | default telnet port | lantronix port:9999 |
| Lantronix | . | . | port:30718 lantronix |
| Mitsubishi Electric | MELSEC-Q Series | . | port:5006,5007 product:mitsubishi |
| Motorola | Moscad | . | Moscad ACE |
| Movicon/Progea | . | Web-Client | MovWebClientX |
| Moxa | ioLogik Web Server | SCADA Software | ioLogik Web Server |
| Moxa | Nport and OnCell devices | . | port:4800 'Moxa Nport' |
| Moxa | Nport devices | . | title:'NPort web console' |
| Moxa | AirWorks AWK-3131-RCC/Railway Remote I/O (ioLogik E12xx)/Cellular Micro RTU Controller (ioLogik W53xx, ioLogik)/VPort 461 Industrial Video Encoder/IA240 Embedded computer/IA241 Embedded computer/OnCell Central Manager/EDS-505A Series/EDS-508A Series/OnCell G3100 Series/Generic | generic | MoxaHttp |
| Moxa | OnCell devices | . | port:4800 'OnCell' |
| NRG Systems | WindCube | Wind Speed Meter | WindWeb |
| Omron | . | FINS, Factory Interface Network Service, | port:9600 response code |
| Phoenix Contact GmbH | . | SCADA visualization system | Visu+ Web Client |
| Phonix Contact | . | PCWorxs | port:1962 PLC |
| Phonix Contact | AXC is a modular small-scale controller for the Axioline I/O system | PCWorxs | PLC Type: AXC |
| Phonix Contact | ILC controllers | PCWorxs | PLC Type: ILC |
| Quantum | . | Multiple Devices | Quantum BACnet |
| Rabbit | Z-World Rabbit | Multiple Devices | title:phasefale Z-World Rabbit |
| Rabbit | Generic | Multiple Devices | Z-World Rabbit |
| Red Lion Controls | . | Red Lion Controls G306a human machine interface (HMI). | port:789 product:"Red Lion Controls" |
| Reliance | Reliance 4 SCADA/HMI system | SCADA/HMI  Software | Reliance 4 Control Server |
| Rockwell Automation | Generic | Generic | Rockwell Automation |
| Rockwell Automation / Allen-Bradley | Generic | Generic | Allen-Bradley |
| Rockwell Automation / Allen-Bradley | . | small programmable logic controller solution | Micrologix |
| Rockwell Automation / Allen-Bradley | Generic | Generic | Series C Revision |
| RTS Services | General | SCADA Software | RTS SCADA Server |
| SBC | . | Saia Burgess Control Applet | IMasterSaia5_15_03.jar |
| SBC | . | . | Saia PG5 Web Editor |
| Schleifenbauer | SPbus gateway | Network Gateway | Schleifenbauer SPbus gateway |
| Schneider Electric | CitectSCADA | HMI / SCADA software package | CitectSCADA |
| Schneider Electric | Generic | SCADA software | ClearSCADA |
| Schneider Electric | PowerLogic EGX | EGX100MG | EGX100MG |
| Schneider Electric | Modicon | generic | Modicon |
| Schneider Electric | Modicon M340 | PLC | Modicon M340 |
| Schneider Electric | PowerLogic ION7650 Energy and power meter | Energy and power meter | port:23 'Meter ION' |
| Schneider Electric | Generic | Energy and power meter | Power Measurement Ltd |
| Schneider Electric | PowerLogic Series | Power Monitoring Module | PowerLogic |
| Schneider Electric | generic | generic | Schneider Electric |
| Schneider Electric | General | Multiple Devices | Schneider-WEB |
| Schneider Electric | Modicon | generic | TELEMECANIQUE BMX |
| Schneider Electric | Generic | Generic | title:PowerLogic |
| Schneider Electric | EGX300 | . | Schneider Electric EGX300 |
| Siemens | Simatic HMI | HMI | HMI XP277 |
| Siemens | Simatic S7-1200 | PLC | Portal0000 |
| Siemens | Simatic S7-300 (pre-2009 versions) | PLC | Portal0000.htm |
| Siemens | Simatic S7-200 | PLC | S7-200 |
| Siemens | Simatic S7-300 | PLC | S7-300 |
| Siemens | Scalance generic | SCALANCE X  Industrial Ethernet switches / SCALANCE W  Industrial Wireless LAN / SCALANCE M  Industrial routers / SCALANCE S  Industrial Security | Scalance |
| Siemens | Generic | Generic | Copyright: Original Siemens Equipment |
| Siemens | Simatic HMI | Generic | Simatic |
| Siemens | Simatic HMI | Generic | Welcome to the Windows CE Telnet Service on HMI_Panel |
| Siemens | Simatic | . | XP277 |
| Siemens | PLC | port can not be deactivated by user | port:102 |
| Sierra Wireless | . | . | /gc/flash.php |
| SoftPLC | . | . | SoftPLC |
| Somfy | General | Smart Home Devices | title:Somfy |
| SpiderControl | Generic | HMI | SpiderControl |
| Stulz GmbH | Generic | Generic | Stulz GmbH Klimatechnik |
| Trend | IQ3xcite | Controller | server: iq3 |
| Tridium | . | Fox protocol developed as part of Niagara framework | port:1911,4911 product:Niagara |
| Tridium | NiagaraAX (ver 1) | Software for JACE-2  JACE-403 or JACE-545 | Niagara Web Server |
| Tridium | NiagaraAX (ver 2) | Software for JACE-2  JACE-403 or JACE-545 | niagara_audit |
| Tridium | NiagaraAX (ver 3) | Software for JACE-2  JACE-403 or JACE-545 | niagara_audit -login |
| Tridium | Niagara Framework | . | Niagara-Platform: QNX |
| Tridium | Niagara Framework | . | os.name=s:QNX |
| Trihedral | . | VTScada ODBC Server | Server: VTScada |
| Wago | Generic | Generic | title:WAGO |
| Wind River | VxWorks | SCADA Software | VxWorks |
| Wind River | Generic | Generic | WindRiver-WebServer |
| Xzeres | 442SR | small wind turbine | title:'xzeres wind' |
| Generic | . | IEC 60870 part 5 is one of the IEC 60870 set of standards which define systems used for SCADA in electrical engineering and power system automation applications. | port:2404 asdu address |
| Carel | pCO sistema | pCOWeb is used to interface pCO Sistema to networks that use the HVAC protocols like BACnet IP  Modbus TCP/IP or SNMP | title:'Carel pCOWeb Home Page' |
| Heatmiser | . | wireless room thermostats | title:'Heatmiser Wifi Thermostat' |
| generic | . | searching tag values requires suitable account | tag:ics |
| generic | . | searching tag values requires suitable account | tag:iot |
| Tridium | BACNet Devices | . | "Local BACnet Device object" "Tridium" |
| Carel | BACNet Devices | . | "Carel BACnet Gateway" |
| Siemens | BACNET Devices | . | "Siemens BACnet Field Panel" |
| generic | BACNet Devices | . | "BACnet Broadcast Management Device" |
| Veeder-root | . | Automated Tank Gauge (Vendor most likely Veeder-Root but not guaranteed) results typically contain a lot of honyepots (conpot) | I20100 port:10001 |
| Generic | . | Screenshots tagged as ICS (will contain some false positives) | screenshot.label:ics |
| Generic | . | standard port for MQTT + MQTT banner / MQTT -> MQ Telemetry Transport | port:1883 "MQTT Connection Code" |
| Generic | . | standard port for MQTT over SSL + MQTT banner / MQTT -> MQ Telemetry Transport / UNTESTED | port:8883  "MQTT Connection Code" |
| Fronius | Generic | solar energy, most likely inverters | port:1883 Fronius |
| Lantronix | . | default telnet port without password enabled  hint: Lantronix includes MAC address in banner which can be used for extra validation | "Press Enter for Setup Mode" port:9999 |
| Carel | PlantVisor | . | "Server: CarelDataServer" "200 Document follows" |
| Nordex | . | Wind Farm Portal | http.title:"Nordex Control" "Windows 2000 5.0 x86" "Jetty/3.1 (JSP 1.1 Servlet 2.2 java 1.6.0_14)" |
| dministration |  | .edu US SSH | hostname:edu country:us port:22 |
| Administration |  | admin/1234 | admin 1234 |
| Administration |  | admin | port:80 admin |
| Administration |  | Allegro | 200 OK -Microsoft -Virata -Apache Allegro |
| Administration |  | AMX Control Systems | 1.1-rr-std-b12 port:80 |
| Administration |  | Anonymous Access Allowed | Anonymous+access+allowed |
| Administration |  | Anonymous Access Granted | anonymous access granted |
| Administration |  | APC Management Card | APC Management Card |
| Administration |  | apc | apc |
| Administration |  | Barracuda targets | barracuda |
| Administration |  | bigfix | bigfix |
| Administration |  | CarelDataServer | CarelDataServer |
| Administration |  | Cern 3.0 | CERN 3.0 |
| Administration |  | Coldfusion Developer Edition | a license exception |
| Administration |  | CPU | computershare |
| Administration |  | Dell Remote Access Controller | Remote Access Controller port:80 |
| Administration |  | Delta Networks Inc | delta |
| Administration |  | DNS | fast dns port:80 |
| Administration |  | etcd | etcd |
| Administration |  | Firewalls | firewall 200 |
| Administration |  | General SSH | port:22 |
| Administration |  | Hewlett Packard print ftp | 230-Hewlett-Packard |
| Administration |  | hitbox | HitboxGateway9 |
| Administration |  | HP LaserJet 4250 | HP-ChaiSOE |
| Administration |  | JetDirect HP Printer | jetdirect |
| Administration |  | Liebert Devices | liebert - liebert.com |
| Administration |  | Micro$oft Exchange | Exchange |
| Administration |  | ngamil | nga.mil |
| Administration |  | Nortel SIP devices | port:5060 Nortel |
| Administration |  | ossim | ossim |
| Administration |  | Root shell | port:23 "list of built-in commands" |
| Administration |  | SAPHIR | wince Content-Length: 12581 |
| Administration |  | SimpleShare NAS | SimpleShare |
| Administration |  | Snom | snom embedded |
| Administration |  | test | admin 1234 |
| Administration |  | Watchguard fierwalls | firewall 200 - date -Internet -netgear -proxy -charset -length -220 |
| Administration |  | ZENworks | ZENworks |
| Administration |  | Zhone Single-Line Multi-Service | Zhone SLMS |
| Cisco |  | Cisco Devices | cisco-ios |
| Cisco |  | cisco elnet web | cisco port:23,80 |
| Cisco |  | CISCO IOS India | cisco-ios country:IN |
| Cisco |  | Cisco Iso in Algeria | cisco-ios country:DZ |
| Cisco |  | cisco no brasil | cisco-ios "last-modified" country:BR |
| Cisco |  | Cisco Open Web Boxs | cisco last-modified Accept-Ranges: none |
| Cisco |  | Cisco VPN Concentrator - admin | Cisco VPN Concentrator admin.html |
| Cisco |  | Cisco VPN Concentrator | Cisco VPN Concentrator |
| Cisco |  | CiscoPhone 7912 | 7912 cisco |
| Cisco |  | CiscoPhone 7940 | 7940 cisco |
| Cisco |  | IOS HACK - old | 1993 "cisco-ios" + "last-modified" |
| CMS |  | Drupal | drupal |
| CMS |  | Joomla | joomla |
| CMS |  | Wordpress | wordpress |
| Common Files |  | Proxy.php | proxy.php |
| Default Credentials |  | default password | default password |
| Default Credentials |  | Passwords | Default Login Authenticate |
| DNS Server |  | PowerDNS | PowerDNS |
| Firewall |  | dotDefender WAF | X-dotDefender-denied |
| FTP |  | Anonymous FTP | port:21 230 |
| FTP |  | China FTP | country:CN port:21 |
| FTP |  | Filezilla | filezilla |
| FTP |  | FTP anon successful | Anonymous user logged in |
| FTP |  | FTP anon successful | Anonymous+access+allowed  connected |
| FTP |  | FTP anonymous or guest access | ftp 230 -unknown -print |
| FTP |  | GoldenFTP 4.70 | GoldenFTP |
| FTP |  | GoldenFTP Server | Golden FTP Server |
| Languages |  | PHP | X-Powered-By: PHP |
| Operating System |  | CentOS | centos |
| Operating System |  | Fedora | Fedora |
| Operating System |  | IPCop | IPCop |
| Operating System |  | RedHat | RedHat |
| Operating System |  | Ubuntu | Ubuntu |
| Operating System |  | Windows 2000 | Windows 2000 |
| Operating System |  | Windows 2003 | Windows 2003 |
| Printer |  | Fuji Xerox Servers | Fuji Xerox |
| Printer |  | JetDirect | jetdirect |
| Printer |  | Xerox 4150 | Xerox 4150 |
| Router |  | Airstation | Airstation |
| Router |  | DD-WRT | dd-wrt port:80 |
| Router |  | HUAWEI Routers | SmartAX MT882 |
| Router |  | HUAWEI ROUTERS | SmartAX MT882 country:RU |
| Router |  | netgear routers | netgear |
| Router |  | netgear | netgear |
| Router |  | Network Switches | Network Switch |
| Router |  | OpenWRT | OpenWRT |
| Router |  | Router w/ Default Info | admin+1234 |
| SCADA and ICS |  | BACnet devices | bacnet |
| SCADA and ICS |  | Electro Industries GaugeTech | EIG Embedded Web Server |
| SCADA and ICS |  | Open SCADA Niagara systems | niagara_audit -login |
| SCADA and ICS |  | Photovoltaic | sunny webbox port:80 |
| SCADA and ICS |  | Rockwell SLC-505 PLC | slc 505 |
| SCADA and ICS |  | SCADA USA | scada country:US |
| SCADA and ICS |  | SCADA | Niagara Web Server |
| SCADA and ICS |  | SCADA | scada |
| SCADA and ICS |  | Siemens s7 | siemens s7 |
| SCADA and ICS |  | Siemens SIMATIC | port:161 simatic |
| SCADA and ICS |  | Simatic NET | Simatic -S7 -HMI |
| SCADA and ICS |  | Simatic S7 SCADA | Simatic+S7 |
| SCADA and ICS |  | Simatic S7 | Simatic S7 |
| SCADA and ICS |  | Telemetry Gateway | telemetry gateway |
| Server Modules |  | W3 Total Cache | X-Powered-By:W3 Total Cache |
| Television |  | Allied telesyn equipment | allied telesys port:23 |
| Television |  | Dreambox SE | dreambox SE |
| Television |  | Dreambox/Enigma2 WebInterface | Enigma2 WebInterface Server |
| Television |  | Dreambox | dreambox |
| Television |  | spinetix hyper media player | spinetix |
| Television |  | Tandberg Television  Web server | Tandberg Television Web server |
| Television |  | Ubicom | Ubicom -401 |
| VOIP |  | AddPac Technology | AddPac |
| VOIP |  | AddPac VoIP | AddPac |
| VOIP |  | airtel | airtel |
| VOIP |  | asterisk | asterisk |
| VOIP |  | BT Home Hub | SIP User-Agent BT Home Hub |
| VOIP |  | Cisco 7940 | 7940 cisco |
| VOIP |  | Cisco SIP proxy | CISCO 200 port:5060 |
| VOIP |  | firmex.com | hostname:firmex.com |
| VOIP |  | Nortel SIP devices | port:5060 Nortel |
| VOIP |  | Snom phones without passwords | snom embedded 200 OK |
| VOIP |  | Snom SIP | port:5060 snom |
| VOIP |  | Snom VOIP phones with no authentication | snom embedded |
| VOIP |  | Tenor | Tenor |
| VOIP |  | trixbox sip server | trixbox port:5060 |
| VOIP |  | Web interface for Huawei IP phones--no authentication required | huawei -301 -302 -400 -401 |
| Web Server |  | Virata-EmWeb | Virata-EmWeb |
| Web Server |  | AFHCAN Telehealth | apache 0.9* port:80 |
| Web Server |  | Centos apache | country:in apache centos hostname:exacttouch.com |
| Web Server |  | Commodore 64 Web servers | Commodore 64 |
| Web Server |  | Default IIS Web Pages | iisstart.htm |
| Web Server |  | F5 Traffic Shield | F5-TrafficShield |
| Web Server |  | Google | google |
| Web Server |  | Gordian Embedded | Gordian Embedded |
| Web Server |  | i.LON | 200 OK i.LON |
| Web Server |  | IBM HTTP Server | IBM-HTTP-Server |
| Web Server |  | IIS 3.0 webservers | IIS 3.0  -"6.0" -"7.0" -"7.5" -"5.0" -"5.1" |
| Web Server |  | IIS 4.0 in AU | iis4.0  country:AU |
| Web Server |  | IIS 4.0 webservers | IIS 4.0  -"6.0" -"7.0" -"7.5" -"5.0" -"5.1" -"404" -"403" -"302" |
| Web Server |  | IIS 4.0 | IIS 4.0  -"6.0" -"7.0" -"7.5" -"5.0" -"5.1" -"404" -"403" -"302" |
| Web Server |  | IIS 4.0 | IIS 4.0  -"6.0" -"7.0" -"7.5" -"5.0" -"5.1" -"404" -"403" -"302" port:80 country:IN |
| Web Server |  | iis 5.0 | iis 5.0 |
| Web Server |  | iis 6.0 webDav | iis 6.0 webdav |
| Web Server |  | IIS in the US with CSP | port:80 country:US X-Content-Security-Policy asp.net |
| Web Server |  | iWeb | Server: iWeb HTTP |
| Web Server |  | KM MFP HTTP Server | KM-MFP-http |
| Web Server |  | lighttpd on iphones | iPhone lighttpd |
| Web Server |  | LiteSpeed | Server: LiteSpeed |
| Web Server |  | mod_antiloris | mod_antiloris |
| Web Server |  | mod_security | mod_security |
| Web Server |  | Oracle Web Listener | Oracle_Web_Listener |
| Web Server |  | Profense | Profense |
| Web Server |  | SkyX HTTPS gateway | SkyX HTTPS |
| Web Server |  | SUCKUP.de: Mein IT-Blog | nginx de country:DE |
| Web Server |  | Synology Disk Station | apache 2.2.13 302 5000 |
| Web Server |  | Test Apache | apache |
| Web Server |  | Windows CE | wince |
| Web Server |  | WindWeb server | WindWeb |
| Web Server |  | Xerver HTTP Server | Xerver |
| Web Server |  | z/oS | (zOS) -Apache -IIS -Extraweb -kerio -sestbc510 |
| Webcam |  | AVTech IP Camera | linux upnp avtech |
| Webcam |  | Belkin NetCam | netcam |
| Webcam |  | DCS-5220 | dcs 5220 |
| Webcam |  | GeoHttpServer WebCam | Server: GeoHttpServer |
| Webcam |  | TeleEye | TeleEye |
| Webcam |  | Vivotek Network Camera | Vivotek Network Camera 200 |
| Webcam |  | webcam imagiatek | imagiatek ipcam |
| Webcam |  | webcam VIDEO WEB SERVER | sq-webcam |
| Webcam |  | webcam vipcap vilar | Boa ipcam |
| Webcam |  | Webcam | Server: SQ-WEBCAM |
| Windows |  | win | country:BG port:443 os:windows |
| ZENworks |  | Remote Access Controller | RAC_ONE_HTTP |