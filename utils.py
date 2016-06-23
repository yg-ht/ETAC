#!/usr/bin/env python
# This file was part of Responder and now is part of ETAC
# ETAC work by Felix Ryan
# Responder work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
import sys
import re
import logging
import socket
import time
import settings
import struct
try:
	import sqlite3
except:
	print "[!] Please install python-sqlite3 extension."
	sys.exit(0)

def color(txt, code = 1, modifier = 0):

	if txt.startswith('[*]'):
		settings.Config.PoisonersLogger.warning(txt)
	
	elif 'Analyze' in txt:
		settings.Config.AnalyzeLogger.warning(txt)

	# No colors for windows...
	if os.name == 'nt':
		return txt

	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def text(txt):
	logging.info(txt)

	if os.name == 'nt':
		return txt

	return '\r'+re.sub(r'\[([^]]*)\]', "\033[1;34m[\\1]\033[0m", txt)

def IsOsX():
	return True if settings.Config.Os_version == "darwin" else False

def OsInterfaceIsSupported():
	if settings.Config.Interface != "Not set":
		return False if IsOsX() else True
	else:
		return False

def IsOsX():
    Os_version = sys.platform
    if Os_version == "darwin":
        return True
    else:
        return False

def FindLocalIP(Iface, OURIP):

	if Iface == 'ALL':
		return '0.0.0.0'

	try:
		if IsOsX():
			return OURIP
		elif OURIP == None:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.setsockopt(socket.SOL_SOCKET, 25, Iface+'\0')
			s.connect(("127.0.0.1",9))#RFC 863
			ret = s.getsockname()[0]
			s.close()
			return ret
		else:
			return OURIP
                    
	except socket.error:
		print color("[!] Error: %s: Interface not found" % Iface, 1)
		sys.exit(-1)

# Function used to write captured hashs to a file.
def WriteData(outfile, data, user):

	logging.info("[*] Captured Hash: %s" % data)

	if not os.path.isfile(outfile):
		with open(outfile,"w") as outf:
			outf.write(data)
			outf.write("\n")
			outf.close()

	else:
		with open(outfile,"r") as filestr:
			if re.search(user.encode('hex'), filestr.read().encode('hex')):
				filestr.close()
				return False
			if re.search(re.escape("$"), user):
				filestr.close()
				return False

		with open(outfile,"a") as outf2:
			outf2.write(data)
			outf2.write("\n")
			outf2.close()

def SaveToDb(result):

	# Creating the DB if it doesn't exist
	if not os.path.exists(settings.Config.DatabaseFile):
		cursor = sqlite3.connect(settings.Config.DatabaseFile)
		cursor.execute('CREATE TABLE responder (timestamp varchar(32), module varchar(16), type varchar(16), client varchar(32), hostname varchar(32), user varchar(32), cleartext varchar(128), hash varchar(512), fullhash varchar(512))')
		cursor.commit()
		cursor.close()

	for k in [ 'module', 'type', 'client', 'hostname', 'user', 'cleartext', 'hash', 'fullhash' ]:
		if not k in result:
			result[k] = ''

	if len(result['user']) < 2:
		return

	if len(result['cleartext']):
		fname = '%s-%s-ClearText-%s.txt' % (result['module'], result['type'], result['client'])
	else:
		fname = '%s-%s-%s.txt' % (result['module'], result['type'], result['client'])
	
	timestamp = time.strftime("%d-%m-%Y %H:%M:%S")
	logfile = os.path.join(settings.Config.ResponderPATH, 'logs', fname)

	cursor = sqlite3.connect(settings.Config.DatabaseFile)
        # We add a text factory to support different charsets
	cursor.text_factory = sqlite3.Binary
	res = cursor.execute("SELECT COUNT(*) AS count FROM responder WHERE module=? AND type=? AND LOWER(user)=LOWER(?)", (result['module'], result['type'], result['user']))
	(count,) = res.fetchone()

	if count == 0:
		
		# If we obtained cleartext credentials, write them to file
		# Otherwise, write JtR-style hash string to file
		with open(logfile,"a") as outf:
			if len(result['cleartext']):
				outf.write('%s:%s' % (result['user'], result['cleartext']))
			else:
				outf.write(result['fullhash'])
			outf.write("\n")
			outf.close()

		# Update database
		cursor.execute("INSERT INTO responder VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", (timestamp, result['module'], result['type'], result['client'], result['hostname'], result['user'], result['cleartext'], result['hash'], result['fullhash']))
		cursor.commit()

	cursor.close()

	# Print output
	if count == 0 or settings.Config.Verbose:

		if len(result['client']):
			print text("[%s] %s Client   : %s" % (result['module'], result['type'], color(result['client'], 3)))
		if len(result['hostname']):
			print text("[%s] %s Hostname : %s" % (result['module'], result['type'], color(result['hostname'], 3)))
		if len(result['user']):
			print text("[%s] %s Username : %s" % (result['module'], result['type'], color(result['user'], 3)))
		
		# Bu order of priority, print cleartext, fullhash, or hash
		if len(result['cleartext']):
			print text("[%s] %s Password : %s" % (result['module'], result['type'], color(result['cleartext'], 3)))
		elif len(result['fullhash']):
			print text("[%s] %s Hash     : %s" % (result['module'], result['type'], color(result['fullhash'], 3)))
		elif len(result['hash']):
			print text("[%s] %s Hash     : %s" % (result['module'], result['type'], color(result['hash'], 3)))

		# Appending auto-ignore list if required
		# Except if this is a machine account's hash
		if settings.Config.AutoIgnore and not result['user'].endswith('$'):

			settings.Config.AutoIgnoreList.append(result['client'])
			print color('[*] Adding client %s to auto-ignore list' % result['client'], 4, 1)

	else:
		print color('[*]', 3, 1), 'Skipping previously captured hash for %s' % result['user']


def Parse_IPV6_Addr(data):

	if data[len(data)-4:len(data)][1] =="\x1c":
		return False

	elif data[len(data)-4:len(data)] == "\x00\x01\x00\x01":
		return True

	elif data[len(data)-4:len(data)] == "\x00\xff\x00\x01":
		return True

	else:
		return False

def Decode_Name(nbname):
	#From http://code.google.com/p/dpkt/ with author's permission.
	try:
		from string import printable

		if len(nbname) != 32:
			return nbname
		
		l = []
		for i in range(0, 32, 2):
			l.append(chr(((ord(nbname[i]) - 0x41) << 4) | ((ord(nbname[i+1]) - 0x41) & 0xf)))
		
		return filter(lambda x: x in printable, ''.join(l).split('\x00', 1)[0].replace(' ', ''))
	
	except:
		return "Illegal NetBIOS name"

def banner():

	banner = "\n".join([
		'\n',
		r'__/\\\\\\\\\\\\\\\__/\\\\\\\\\\\\\\\_____/\\\\\\\\\___________/\\\\\\\\\_        ',
		r' _\/\\\///////////__\///////\\\/////____/\\\\\\\\\\\\\______/\\\////////__       ',
  		r'  _\/\\\___________________\/\\\________/\\\/////////\\\___/\\\/___________      ',
   		r'   _\/\\\\\\\\\\\___________\/\\\_______\/\\\_______\/\\\__/\\\_____________     ',
   		r'    _\/\\\///////____________\/\\\_______\/\\\\\\\\\\\\\\\_\/\\\_____________    ',
 		r'     _\/\\\___________________\/\\\_______\/\\\/////////\\\_\//\\\____________   ',
		r'      _\/\\\___________________\/\\\_______\/\\\_______\/\\\__\///\\\__________  ',
		r'       _\/\\\\\\\\\\\\\\\_______\/\\\_______\/\\\_______\/\\\____\////\\\\\\\\\_ ',
		r'        _\///////////////________\///________\///________\///________\/////////__'
	])

	print banner
	print "\n \033[1;33m         MitM HTML poisoner & SMB Auth capture built for the WiFiPineapple mkV\033[0m"
	print ""
	print "  Version: " + settings.__version__
	print "  Author: Felix Ryan (f@felixrr.pro)"
	print "  Uses code from the Responder project, authored by: Laurent Gaffie (laurent.gaffie@gmail.com)"
	print "  To kill this script hit CTRL-C"
	print ""

def StartupMessage():
	enabled  = color('[ON]', 2, 1) 
	disabled = color('[OFF]', 1, 1)

	print ""
	print color("[+] ", 2, 1) + "Poisoners:"
	print '    %-27s' % "HTML" + enabled
	print ""

	print color("[+] ", 2, 1) + "Servers:"
	print '    %-27s' % "SMB server" + (enabled if settings.Config.SMB_On_Off else disabled)
	print ""

	print color("[+] ", 2, 1) + "Poisoning Options:"
	print '    %-27s' % "Analyze Mode" + (enabled if settings.Config.AnalyzeMode else disabled)
	print '    %-27s' % "Force WPAD auth" + (enabled if settings.Config.Force_WPAD_Auth else disabled)
	print '    %-27s' % "Force Basic Auth" + (enabled if settings.Config.Basic else disabled)
	print '    %-27s' % "Force LM downgrade" + (enabled if settings.Config.LM_On_Off == True else disabled)
	print '    %-27s' % "Fingerprint hosts" + (enabled if settings.Config.Finger_On_Off == True else disabled)
	print ""

	print color("[+] ", 2, 1) + "Generic Options:"
	print '    %-27s' % "Service NIC" + color('[%s]' % settings.Config.Interface, 5, 1)
	print '    %-27s' % "Service IP" + color('[%s]' % settings.Config.Bind_To, 5, 1)
	print '    %-27s' % "Challenge set" + color('[%s]' % settings.Config.NumChal, 5, 1)

	if settings.Config.Upstream_Proxy:
		print '    %-27s' % "Upstream Proxy" + color('[%s]' % settings.Config.Upstream_Proxy, 5, 1)

	print ""
	print ""
