#!/usr/bin/env python
#
# This file is part of Responder which was originally written by
# Laurent Gaffie - Trustwave Holdings
#
# This poisoner is original work by Felix Ryan
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

HOST = "0.0.0.0"
PORTS = [3128]
VERBOSE = True
TESTING = True

TESTING_FILE_clientreq = 'HTMLpoisoner.clientreq.raw'
TESTING_FILE_clientres = 'HTMLpoisoner.clientres.raw'
TESTING_FILE_serverreq = 'HTMLpoisoner.serverreq.raw'
TESTING_FILE_serverres = 'HTMLpoisoner.serverres.raw'

# library imports
from thread import *
import socket
import sys
import os

def cleanup():
    try:  # delete the smb.bin file if it exists - this is used for raw connection testing
        os.remove(TESTING_FILE_clientreq)
        os.remove(TESTING_FILE_clientres)
        os.remove(TESTING_FILE_serverreq)
        os.remove(TESTING_FILE_serverres)
    except:
        pass

def createSocketListener(host, port):
    try:
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #attempt to avoid socket lock problems
        if VERBOSE:
            print "Socket build complete ("+host+":"+str(port)+")"
    except socket.error as errMsg:
        print "[!] Failed to create socket ("+host+":"+str(port)+")\n" + str(errMsg)
        sys.exit()

    try:
        ServerSocket.bind((host, port))
        if VERBOSE:
            print "Socket bind complete ("+host+":"+str(port)+")"
    except socket.error as errMsg:
        print "[!] Failed to bind socket ("+host+":"+str(port)+")\n" + str(errMsg)
        sys.exit()
    ServerSocket.listen(10)
    return ServerSocket

def connectionHandler(connection):
    sendWelcome(connection)
    data = acceptConnection(connection)
    if TESTING:
        writeRawData(TESTING_FILE_clientreq)
    dataType = detectReqType(data)
    if dataType != False:
        print dataType

def sendBanner(connection):
    connection.send("The HTML Poisoner service at your service maam...")
    if TESTING:
        print "Welcome sent to potential victim"

def acceptConnection(connection):
    data = connection.recv(4096)
    if TESTING:
        print str(len(data))+" bytes received"
        connection.close()
    return str(data)

def writeRawData(data, filename):
    if VERBOSE:
        print "Attempting to write raw data to disk ("+filename+") for testing purposes"
    outputFile = open(filename, "ab")
    outputFile.write(data)
    outputFile.close()

def detectReqType(data):
    if data[5:8] == "SMB":
        return True
    else:
        if TESTING:
            print data[5:8]
        return False

def main():
    if TESTING:
        cleanup() #make sure no previous raw file captures are present
    SMBsocket = createSocketListener(HOST, PORTS[1])
    if VERBOSE:
        print "SMB Socket listen complete"


    while True:
        connection, address = SMBsocket.accept()
        if VERBOSE:
            print "Connection from: " + address[0] + ":" + str(address[1])
        start_new_thread(connectionHandler, (connection,))

    SMBsocket.close



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print 'User signaled exit...'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)