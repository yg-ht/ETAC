#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
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
import socket
import utils
import logging
import ConfigParser

__version__ = 'ETAC 0.9'

class Settings:
	
	def __init__(self):
		self.ResponderPATH = os.path.dirname(__file__)
		self.Bind_To = '0.0.0.0'

	def __str__(self):
		ret = 'Settings class:\n'
		for attr in dir(self):
			value = str(getattr(self, attr)).strip()
			ret += "    Settings.%s = %s\n" % (attr, value)
		return ret

	def toBool(self, str):
		return True if str.upper() == 'ON' else False

	def ExpandIPRanges(self):
		def expand_ranges(lst):
			ret = []
			for l in lst:
				tab = l.split('.')
				x = {}
				i = 0
				for byte in tab:
					if '-' not in byte:
						x[i] = x[i+1] = int(byte)
					else:
						b = byte.split('-')
						x[i] = int(b[0])
						x[i+1] = int(b[1])
					i += 2
				for a in range(x[0], x[1]+1):
					for b in range(x[2], x[3]+1):
						for c in range(x[4], x[5]+1):
							for d in range(x[6], x[7]+1):
								ret.append('%d.%d.%d.%d' % (a, b, c, d))
			return ret

	def populate(self, options):

		if options.Interface is None and utils.IsOsX() is False:
			print utils.color("Error: -I <if> mandatory option is missing", 1)
			sys.exit(-1)

		# Config parsing
		config = ConfigParser.ConfigParser()
		config.read(os.path.join(self.ResponderPATH, 'ETAC.conf'))

		# Servers
		self.SMB_On_Off      = self.toBool(config.get('ETAC Core', 'SMB'))
		self.Krb_On_Off      = self.toBool(config.get('ETAC Core', 'Kerberos'))

		# Db File
		self.DatabaseFile    = os.path.join(self.ResponderPATH, config.get('ETAC Core', 'Database'))

		# Log Files
		self.LogDir = os.path.join(self.ResponderPATH, 'logs')

		if not os.path.exists(self.LogDir):
			os.mkdir(self.LogDir)

		self.SessionLogFile      = os.path.join(self.LogDir, config.get('ETAC Core', 'SessionLog'))
		self.PoisonersLogFile    = os.path.join(self.LogDir, config.get('ETAC Core', 'PoisonersLog'))
		self.AnalyzeLogFile      = os.path.join(self.LogDir, config.get('ETAC Core', 'AnalyzeLog'))

		self.SMBClearLog     = os.path.join(self.LogDir, 'SMB-Clear-Text-Password-%s.txt')
		self.KerberosLog     = os.path.join(self.LogDir, 'MSKerberos-Client-%s.txt')
		self.SMBNTLMv1Log    = os.path.join(self.LogDir, 'SMB-NTLMv1-Client-%s.txt')
		self.SMBNTLMv2Log    = os.path.join(self.LogDir, 'SMB-NTLMv2-Client-%s.txt')
		self.SMBNTLMSSPv1Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv1-Client-%s.txt')
		self.SMBNTLMSSPv2Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv2-Client-%s.txt')

		# Auto Ignore List
		self.AutoIgnore        = self.toBool(config.get('ETAC Core', 'AutoIgnoreAfterSuccess'))
		self.AutoIgnoreList    = []

		# CLI options
		self.LM_On_Off       = options.LM_On_Off
		self.WPAD_On_Off     = options.WPAD_On_Off
		self.Wredirect       = options.Wredirect
		self.NBTNSDomain     = options.NBTNSDomain
		self.Basic           = options.Basic
		self.Finger_On_Off   = options.Finger
		self.Interface       = options.Interface
		self.OURIP           = options.OURIP
		self.Force_WPAD_Auth = options.Force_WPAD_Auth
		self.HTML_On_Off     = options.HTML_On_Off
		self.Upstream_Proxy  = options.Upstream_Proxy
		self.AnalyzeMode     = options.Analyze
		self.Verbose         = options.Verbose
		self.CommandLine     = str(sys.argv)

		self.Bind_To = utils.FindLocalIP(self.Interface, self.OURIP)

		self.IP_aton         = socket.inet_aton(self.Bind_To)
		self.Os_version      = sys.platform

		# Set up Challenge
		self.NumChal = config.get('ETAC Core', 'Challenge')

		if len(self.NumChal) is not 16:
			print utils.color("[!] The challenge must be exactly 16 chars long.\nExample: 1122334455667788", 1)
			sys.exit(-1)

		self.Challenge = ""
		for i in range(0, len(self.NumChal),2):
			self.Challenge += self.NumChal[i:i+2].decode("hex")

		# Set up logging
		logging.basicConfig(filename=self.SessionLogFile, level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
		logging.warning('ETAC Started: %s' % self.CommandLine)
		logging.warning('ETAC Config: %s' % str(self))

		Formatter = logging.Formatter('%(asctime)s - %(message)s')
		PLog_Handler = logging.FileHandler(self.PoisonersLogFile, 'w')
		ALog_Handler = logging.FileHandler(self.AnalyzeLogFile, 'a')
		PLog_Handler.setLevel(logging.INFO)
		ALog_Handler.setLevel(logging.INFO)
		PLog_Handler.setFormatter(Formatter)
		ALog_Handler.setFormatter(Formatter)

		self.PoisonersLogger = logging.getLogger('Poisoners Log')
		self.PoisonersLogger.addHandler(PLog_Handler)

		self.AnalyzeLogger = logging.getLogger('Analyze Log')
		self.AnalyzeLogger.addHandler(ALog_Handler)

def init():
	global Config
	Config = Settings()
