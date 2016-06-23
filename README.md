# ETAC - Evil Twin Auth Capture

Poisonous transparent HTTP proxy that facilitates Windows SMB auth capture

## This program

Primarily created in order to fulfil the requirements of an MSc thesis.  The thesis focuses on the use of unencrypted wireless access points in public locations and how this can affect the level of security of a business/organisation's network.  Specifically, this application aims to take advantage of the Evil Twin wireless access points created by the WiFiPineapple and then create conditions conducive to the capture of Microsoft Windows authentication requests.

This project ignores the fact that SMB can work over NetBIOS (i.e. port 139).  It would be nice one day to add the functionality, but hopefully this will become less and less relevant with time.

## Author details, credits, and licenses

Original work by Felix Ryan - f at felixrr dot pro

Inspiration from xxx

Code used from the Responder project: Author: Laurent Gaffie <laurent.gaffie@gmail.com > https://github.com/SpiderLabs/Responder

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANT; without even the implied warrnty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>. 


## Features ##

- Built-in SMB Auth server.
	
Supports NTLMv1, NTLMv2 hashes with Extended Security NTLMSSP by default. Successfully tested from Windows 95 to Server 2012 RC, Samba and Mac OSX Lion. Clear text password is supported for NT4, and LM hashing downgrade when the --lm option is set. This functionality is enabled by default when the tool is launched.

- Browser Listener

This module allows to find the PDC in stealth mode.

- Analyze mode.

This module allows you to see NBT-NS, BROWSER, LLMNR, DNS requests on the network without poisoning any responses. Also, you can map domains, MSSQL servers, workstations passively, see if ICMP Redirects attacks are plausible on your subnet. 

## Hashes ##

All hashes are printed to stdout and dumped in an unique file John Jumbo compliant, using this format:

    (MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt

Log files are located in the "logs/" folder. Hashes will be logged and printed only once per user per hash type, unless you are using the Verbose mode (-v).

- Responder will logs all its activity to Responder-Session.log
- Analyze mode will be logged to Analyze-Session.log
- Poisoning will be logged to Poisoners-Session.log

Additionally, all captured hashed are logged into an SQLite database which you can configure in Responder.conf


## Considerations ##

- This tool listens on several ports: UDP 137, UDP 138, TCP 139, TCP 445, TCP 3128.

- If you run Samba on your system, stop smbd and nmbd and all other services listening on these ports.

- For Ubuntu users:

Edit this file /etc/NetworkManager/NetworkManager.conf and comment the line: `dns=dnsmasq`. Then kill dnsmasq with this command (as root): `killall dnsmasq -9`

- Any rogue server can be turned off in Responder.conf.

- This tool is not meant to work on Windows.

- For OSX, the Resonder project did provide some guidance (below), however, this application has not been tested at all on OSX.

Please note: Responder must be launched with an IP address for the -i flag (e.g. -i YOUR_IP_ADDR). There is no native support in OSX for custom interface binding. Using -i en1 will not work. Also to run Responder with the best experience, run the following as root:

    launchcl unload /System/Library/LaunchDaemons/com.apple.Kerberos.kdc.plist

    launchctl unload /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist

    launchctl unload /System/Library/LaunchDaemons/com.apple.smbd.plist

    launchctl unload /System/Library/LaunchDaemons/com.apple.netbiosd.plist

## Usage ##

First of all, please take a look at Responder.conf and tweak it for your needs.

Running the tool:

    ./ETAC.py [options]

Typical Usage Example:

    ./ETAC.py -I br-lan -AH

## Copyright ##

Copyright Felix Ryan (C) 2016, this project is licensed under the GNU GPL (see below).  Authors sole request: if you do something cool or interesting with this work, please let him know.  

This project takes advantage of code from the NBT-NS/LLMNR Responder Created by Laurent Gaffie Copyright (C) 2013 Trustwave Holdings, Inc. Which was licensed under the terms of the GNU Public License (see license statement below).
 
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>
