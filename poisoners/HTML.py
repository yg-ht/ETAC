#!/usr/bin/env python

HOST = "0.0.0.0"
PORT = 3128
VERBOSE = True
TESTING = True
MAX_CONN = 5
BUFFER_SIZE = 4096

TESTING_FILE_clientreq = 'HTMLpoisoner.clientreq.raw'
TESTING_FILE_clientres = 'HTMLpoisoner.clientres.raw'
TESTING_FILE_serverreq = 'HTMLpoisoner.serverreq.raw'
TESTING_FILE_serverres = 'HTMLpoisoner.serverres.raw'

import socket, sys
from thread import *
import os

def acceptConnection(connection):
    data = connection.recv(BUFFER_SIZE)
    if TESTING:
        print str(len(data))+" bytes received"
    return str(data)

def cleanup():
    try:  # delete the smb.bin file if it exists - this is used for raw connection testing
        os.remove(TESTING_FILE_clientreq)
        os.remove(TESTING_FILE_clientres)
        os.remove(TESTING_FILE_serverreq)
        os.remove(TESTING_FILE_serverres)
    except:
        pass


def getConnectionString(HeaderOne):
    method = HeaderOne.split(' ')[0]
    transport = HeaderOne.split(' ')[1].split('://')[0]
    try:
        hostAndPort = HeaderOne.split(' ')[1].split('://')[1].split('/', 1)[0]
        host = hostAndPort.split(':')[0]
        port = hostAndPort.split(':')[1]
    except IndexError:
        host = HeaderOne.split(' ')[1].split('://')[1].split('/',1)[0]
        port = 80
    URI = '/' + HeaderOne.split(' ')[1].split('://')[1].split('/',1)[1]
    connString = {'method' : method, 'transport' : transport, 'host' : host, 'port' : port, 'URI' : URI}
    return connString

def connectionHandler(connection,data,address):
    HTTPHeaders = getHeaders(data)
    if TESTING:
        print HTTPHeaders
    # if HTTPHeaders is not a dictionary, it probably isn't an HTTP request so send the banner
    if HTTPHeaders == False:
        sendBanner(connection)
    connectionString = getConnectionString(HTTPHeaders[0])
    realWebSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    realWebSocket.connect((connectionString['host'],connectionString['port']))
    realWebSocket.send(data)
    #carry on from here

def createSocketListener(host, port):
    try:
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #attempt to avoid socket lock problems
        if VERBOSE:
            print "Socket build complete ("+host+":"+str(port)+")"
    except socket.error as errMsg:
        print "[!] Failed to build socket ("+host+":"+str(port)+")\n" + str(errMsg)
        sys.exit(2)
    try:
        ServerSocket.bind((host, port))
        ServerSocket.listen(MAX_CONN)
        if VERBOSE:
            print "Socket bind complete ("+host+":"+str(port)+")"
    except socket.error as errMsg:
        print "[!] Failed to bind socket ("+host+":"+str(port)+")\n" + str(errMsg)
        sys.exit(2)
    return ServerSocket

def getHeaders(reqData):
    #Split out the data section from the headers / preamble
    HTTPData = reqData.split("\r\n\r\n", 1)
    #Split each line
    HTTPHeadersList = HTTPData[0].split("\r\n")
    try:
        # First line is the HTTP method and request
        HTTPHeadersDict = {HTTPHeadersList[0].split(' ', 1)[0] : HTTPHeadersList[0].split(' ', 1)[1]}
        #The rest are colon separated headers and can be turned into a dictionary
        headerIndex = 0
        for header in HTTPHeadersList:
            if headerIndex > 0:
                headerParts = header.split(":", 1)
                HTTPHeadersDict[headerParts[0]] = headerParts[1]
            headerIndex += 1
        if TESTING:
            print HTTPHeadersDict
        return HTTPHeadersDict
    except IndexError:
        return False

def sendBanner(connection):
    connection.send("The HTML Poisoner at your service ma'am...")
    if TESTING:
        print "Banner sent"

def writeRawData(data, filename):
    if VERBOSE:
        print "Attempting to write raw data to disk ("+filename+") for testing purposes"
    outputFile = open(filename, "ab")
    outputFile.write(data)
    outputFile.close()

#get the thing up and running
def main():
    if TESTING:
        cleanup() #make sure no previous raw file captures are present
    PoisonSocket = createSocketListener(HOST, PORT)

    #always try and keep a socket open
    while True:
        connection, address = PoisonSocket.accept()
        data = acceptConnection(connection)
        if TESTING:
            writeRawData(data, TESTING_FILE_clientreq)
        if VERBOSE:
            print "Connection from: " + address[0] + ":" + str(address[1])
        #when new connections are received, spawn a new thread to handle it
        start_new_thread(connectionHandler, (connection,data,address))
    PoisonSocket.close

if __name__ == '__main__':
    try:
        main()
    #attempt, though don't hold your breath, to shutdown gracefully when told to do so
    except KeyboardInterrupt:
        print 'User signaled exit...'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
