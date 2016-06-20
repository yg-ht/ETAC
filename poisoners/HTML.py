#!/usr/bin/env python

HOST = "0.0.0.0"
PORT = 3128
VERBOSE = False
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
    # Example HeaderOne value:
    # GET http://www.google.com:8080/path/to/resource/index.php?q=example HTTP/1.1
    # the below splits the above into its component parts and creates a dictionary
    # from example should result in: "GET"
    try:
        method = HeaderOne.split(' ')[0]
        if TESTING:
            print "Method: " + method
        # from example should result in: "http"
        transport = HeaderOne.split(' ')[1].split('://')[0]
        if TESTING:
            print "Transport: " + transport
        # from example should result in: "www.google.com:8080"
        hostAndPort = HeaderOne.split(' ')[1].split('://')[1].split('/', 1)[0]
        if TESTING:
            print "Host and Port: " + hostAndPort
        try:
            # from example should result in: "8080" (do this first to trigger the except earlier)
            port = hostAndPort.split(':')[1]
            if TESTING:
                print "Port: " + str(port)
            # from example should result in: "www.google.com"
            host = hostAndPort.split(':')[0]
            if TESTING:
                print "Host: " + host
        except IndexError:
            # from example should result in: "www.google.com"
            host = HeaderOne.split(' ')[1].split('://')[1].split('/',1)[0]
            if TESTING:
                print "Host: " + host
            port = 80
            if TESTING:
                print "Port: " + str(port)
        URI = '/' + HeaderOne.split(' ')[1].split('://')[1].split('/',1)[1]
        if TESTING:
            print "URI: " +  URI
    except IndexError as ErrMsg:
        print 'RxHeaderOne issue detected: ' + str(ErrMsg)
        sys.exit(2)
    connString = {'method' : method, 'transport' : transport, 'host' : host, 'port' : port, 'URI' : URI}
    return connString

def connectionHandler(RxConnection,RxData,RxAddress):
    HTTPHeaders = getHeaders(RxData)
    # if HTTPHeaders is not a dictionary, it probably isn't an HTTP request so send the banner
    if HTTPHeaders == False:
        sendBanner(RxConnection)
    connectionString = getConnectionString(HTTPHeaders['Req'])

    TxData = weakenRequest(RxData)

    # Connect to real web server
    TxSocket = createSocketTx(connectionString)
    # Send data to real web server
    TxSocket.send(TxData)

    while True:
        # get data response
        TxResponse = TxSocket.recv(BUFFER_SIZE)

        # if the response exists process it, otherwise don't
        if len(TxResponse) > 0:

            RxResponse = weakenResponse(TxResponse)
            RxConnection.send(RxResponse)
            if TESTING and VERBOSE:
                print 'Server response sent to proxy client at ' + str(RxAddress)
        else:
            break
    TxSocket.close()

def createSocketTx(connectionString):
    try:
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerSocket.connect((connectionString['host'], connectionString['port']))
        return ServerSocket
    except socket.error as errMsg:
        print "[!] Failed to connect to server (" + connectionString['transport'] + "://" + connectionString['host'] + ":" + connectionString['port'] + "/" + connectionString['URI'] + ")\n" + str(errMsg)
        return False

def createSocketRx(host, port):
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
        HTTPHeadersDict = {'Req' : HTTPHeadersList[0]}
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

def weakenRequest(RxData): #placeholder for future function xxx
    return RxData

def weakenResponse(TxResponse): #placeholder for future function xxx
    return TxResponse

#get the thing up and running
def main():
    if TESTING:
        cleanup() #make sure no previous raw file captures are present
    RxSocket = createSocketRx(HOST, PORT)

    #always try and keep a socket open
    while True:
        RxConnection, RxAddress = RxSocket.accept()
        RxData = acceptConnection(RxConnection)
        if TESTING:
            writeRawData(RxData, TESTING_FILE_clientreq)
        if VERBOSE:
            print "Connection from: " + RxAddress[0] + ":" + str(RxAddress[1])
        #when new connections are received, spawn a new thread to handle it
        start_new_thread(connectionHandler, (RxConnection,RxData,RxAddress))
        RxSocket.close

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
