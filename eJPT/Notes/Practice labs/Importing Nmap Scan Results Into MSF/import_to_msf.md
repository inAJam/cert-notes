# Importing Nmap Scan Results Into MSF

## Objective:
To import Nmap scan results into MSF

## Tools used:
* `nmap`
* `msfconsole`

---
Let's start with a simple `nmap` scan. 
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn demo.ine.local
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-08 16:55 IST
Nmap scan report for demo.ine.local (10.5.16.222)
Host is up (0.0026s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49154/tcp open  unknown
49155/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 4.71 seconds
```
So we can see that the rdp service is running on port **3389**. We focus on this port and do a service scan and export the result to XML so that it can be fed into the `msfconsole`.  
```bash
┌──(root㉿INE)-[~]
└─# nmap -Pn -p3389 -sV demo.ine.local -oX lab_rdp.xml
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-08 16:59 IST
Nmap scan report for demo.ine.local (10.5.16.222)
Host is up (0.0026s latency).

PORT     STATE SERVICE            VERSION
3389/tcp open  ssl/ms-wbt-server?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.17 seconds 
```
Now we start the **postgresql** service and start-up `msfconsole`.
```bash
┌──(root㉿INE)-[~]                                                                                                                                                                                                                         
└─# service postgresql start
Starting PostgreSQL 16 database server: main.                                                                                                                                                                                              
                                                                                                                                                                                                                                           
┌──(root㉿INE)-[~]                                                                                                                                                                                                                         
└─# msfconsole                                                                                                                                                                                                                             
Metasploit tip: Network adapter names can be used for IP options set LHOST                                                                                                                                                                 
eth0                                                                                                                                                                                                                                       
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
*Neutrino_Cannon*PrettyBeefy*PostalTime*binbash*deadastronauts*EvilBunnyWrote*L1T*Mail.ru*() { :;}; echo vulnerable*                                                                                                                       
*Team sorceror*ADACTF*BisonSquad*socialdistancing*LeukeTeamNaam*OWASP Moncton*Alegori*exit*Vampire Bunnies*APT593*                                                                                                                         
*QuePasaZombiesAndFriends*NetSecBG*coincoin*ShroomZ*Slow Coders*Scavenger Security*Bruh*NoTeamName*Terminal Cult*
*edspiner*BFG*MagentaHats*0x01DA*Kaczuszki*AlphaPwners*FILAHA*Raffaela*HackSurYvette*outout*HackSouth*Corax*yeeb0iz*
*SKUA*Cyber COBRA*flaghunters*0xCD*AI Generated*CSEC*p3nnm3d*IFS*CTF_Circle*InnotecLabs*baadf00d*BitSwitchers*0xnoobs*
*ItPwns - Intergalactic Team of PWNers*PCCsquared*fr334aks*runCMD*0x194*Kapital Krakens*ReadyPlayer1337*Team 443*
*H4CKSN0W*InfOUsec*CTF Community*DCZia*NiceWay*0xBlueSky*ME3*Tipi'Hack*Porg Pwn Platoon*Hackerty*hackstreetboys*
*ideaengine007*eggcellent*H4x*cw167*localhorst*Original Cyan Lonkero*Sad_Pandas*FalseFlag*OurHeartBleedsOrange*SBWASP*
*Cult of the Dead Turkey*doesthismatter*crayontheft*Cyber Mausoleum*scripterz*VetSec*norbot*Delta Squad Zero*Mukesh*
*x00-x00*BlackCat*ARESx*cxp*vaporsec*purplehax*RedTeam@MTU*UsalamaTeam*vitamink*RISC*forkbomb444*hownowbrowncow*
*etherknot*cheesebaguette*downgrade*FR!3ND5*badfirmware*Cut3Dr4g0n*dc615*nora*Polaris One*team*hail hydra*Takoyaki*
*Sudo Society*incognito-flash*TheScientists*Tea Party*Reapers of Pwnage*OldBoys*M0ul3Fr1t1B13r3*bearswithsaws*DC540*
*iMosuke*Infosec_zitro*CrackTheFlag*TheConquerors*Asur*4fun*Rogue-CTF*Cyber*TMHC*The_Pirhacks*btwIuseArch*MadDawgs*
*HInc*The Pighty Mangolins*CCSF_RamSec*x4n0n*x0rc3r3rs*emehacr*Ph4n70m_R34p3r*humziq*Preeminence*UMGC*ByteBrigade*
*TeamFastMark*Towson-Cyberkatz*meow*xrzhev*PA Hackers*Kuolema*Nakateam*L0g!c B0mb*NOVA-InfoSec*teamstyle*Panic*
*B0NG0R3*                                                                                    *Les Cadets Rouges*buf*
*Les Tontons Fl4gueurs*                                                                      *404 : Flag Not Found*
*' UNION SELECT 'password*      _________                __                                  *OCD247*Sparkle Pony* 
*burner_herz0g*                 \_   ___ \_____  _______/  |_ __ _________   ____            *Kill$hot*ConEmu*
*here_there_be_trolls*          /    \  \/\__  \ \____ \   __\  |  \_  __ \_/ __ \           *;echo"hacked"*
*r4t5_*6rung4nd4*NYUSEC*        \     \____/ __ \|  |_> >  | |  |  /|  | \/\  ___/           *karamel4e*
*IkastenIO*TWC*balkansec*        \______  (____  /   __/|__| |____/ |__|    \___  >          *cybersecurity.li*
*TofuEelRoll*Trash Pandas*              \/     \/|__|                           \/           *OneManArmy*cyb3r_w1z4rd5*
*Astra*Got Schwartz?*tmux*                  ___________.__                                   *AreYouStuck*Mr.Robot.0*
*\nls*Juicy white peach*                    \__    ___/|  |__   ____                         *EPITA Rennes*
*HackerKnights*                               |    |   |  |  \_/ __ \                        *guildOfGengar*Titans*
*Pentest Rangers*                             |    |   |   Y  \  ___/                        *The Libbyrators*
*placeholder name*bitup*                      |____|   |___|  /\___  >                       *JeffTadashi*Mikeal*
*UCASers*onotch*                                            \/     \/                        *ky_dong_day_song*
*NeNiNuMmOk*                              ___________.__                                     *JustForFun!*
*Maux de tête*LalaNG*                     \_   _____/|  | _____     ____                     *g3tsh3Lls0on*
*crr0tz*z3r0p0rn*clueless*                 |    __)  |  | \__  \   / ___\                    *Phở Đặc Biệt*Paradox*
*HackWara*                                 |     \   |  |__/ __ \_/ /_/  >                   *KaRIPux*inf0sec*
*Kugelschreibertester*                     \___  /   |____(____  /\___  /                    *bluehens*Antoine77*
*icemasters*                                   \/              \//_____/                     *genxy*TRADE_NAMES*
*Spartan's Ravens*                       _______________   _______________                   *BadByte*fontwang_tw*
*g0ldd1gg3rs*pappo*                     \_____  \   _  \  \_____  \   _  \                   *ghoti*
*Les CRACKS*c0dingRabbits*               /  ____/  /_\  \  /  ____/  /_\  \                  *LinuxRiders*   
*2Cr4Sh*RecycleBin*                     /       \  \_/   \/       \  \_/   \                 *Jalan Durian*
*ExploitStudio*                         \_______ \_____  /\_______ \_____  /                 *WPICSC*logaritm*
*Car RamRod*0x41414141*                         \/     \/         \/     \/                  *Orv1ll3*team-fm4dd*
*Björkson*FlyingCircus*                                                                      *PwnHub*H4X0R*Yanee*
*Securifera*hot cocoa*                                                                       *Et3rnal*PelarianCP*
*n00bytes*DNC&G*guildzero*dorko*tv*42*{EHF}*CarpeDien*Flamin-Go*BarryWhite*XUcyber*FernetInjection*DCcurity*
*Mars Explorer*ozen_cfw*Fat Boys*Simpatico*nzdjb*Isec-U.O*The Pomorians*T35H*H@wk33*JetJ*OrangeStar*Team Corgi*
*D0g3*0itch*OffRes*LegionOfRinf*UniWA*wgucoo*Pr0ph3t*L0ner*_n00bz*OSINT Punchers*Tinfoil Hats*Hava*Team Neu*
*Cyb3rDoctor*Techlock Inc*kinakomochi*DubbelDopper*bubbasnmp*w*Gh0st$*tyl3rsec*LUCKY_CLOVERS*ev4d3rx10-team*ir4n6*
*PEQUI_ctf*HKLBGD*L3o*5 bits short of a byte*UCM*ByteForc3*Death_Geass*Stryk3r*WooT*Raise The Black*CTErr0r*
*Individual*mikejam*Flag Predator*klandes*_no_Skids*SQ.*CyberOWL*Ironhearts*Kizzle*gauti*
*San Antonio College Cyber Rangers*sam.ninja*Akerbeltz*cheeseroyale*Ephyra*sard city*OrderingChaos*Pickle_Ricks*
*Hex2Text*defiant*hefter*Flaggermeister*Oxford Brookes University*OD1E*noob_noob*Ferris Wheel*Ficus*ONO*jameless*
*Log1c_b0mb*dr4k0t4*0th3rs*dcua*cccchhhh6819*Manzara's Magpies*pwn4lyfe*Droogy*Shrubhound Gang*ssociety*HackJWU*
*asdfghjkl*n00bi3*i-cube warriors*WhateverThrone*Salvat0re*Chadsec*0x1337deadbeef*StarchThingIDK*Tieto_alaviiva_turva*
*InspiV*RPCA Cyber Club*kurage0verfl0w*lammm*pelicans_for_freedom*switchteam*tim*departedcomputerchairs*cool_runnings*
*chads*SecureShell*EetIetsHekken*CyberSquad*P&K*Trident*RedSeer*SOMA*EVM*BUckys_Angels*OrangeJuice*DemDirtyUserz*
*OpenToAll*Born2Hack*Bigglesworth*NIS*10Monkeys1Keyboard*TNGCrew*Cla55N0tF0und*exploits33kr*root_rulzz*InfosecIITG*
*superusers*H@rdT0R3m3b3r*operators*NULL*stuxCTF*mHackresciallo*Eclipse*Gingabeast*Hamad*Immortals*arasan*MouseTrap*
*damn_sadboi*tadaaa*null2root*HowestCSP*fezfezf*LordVader*Fl@g_Hunt3rs*bluenet*P@Ge2mE*



       =[ metasploit v6.4.12-dev                          ]
+ -- --=[ 2426 exploits - 1250 auxiliary - 428 post       ]
+ -- --=[ 1468 payloads - 47 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > 
```
Now we just import the xml file created via `nmap`.
```bash
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
msf6 > db_
db_connect        db_disconnect     db_export         db_import         db_nmap           db_rebuild_cache  db_remove         db_save           db_stats          db_status         
msf6 > db_import lab_rdp.xml
[*] Importing 'Nmap XML' data
[*] Import: Parsing with 'Nokogiri v1.13.10'
[*] Importing host 10.5.16.222
[*] Successfully imported /root/lab_rdp.xml
msf6 > 
```
We can check the status via the **hosts** and **services** command.
```bash
msf6 > hosts

Hosts
=====

address      mac  name            os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----            -------  ---------  -----  -------  ----  --------
10.5.16.222       demo.ine.local  Unknown                    device

msf6 > services
Services
========

host         port  proto  name               state  info
----         ----  -----  ----               -----  ----
10.5.16.222  3389  tcp    ssl/ms-wbt-server  open

msf6 > 
```