import socket
import os.path
import random
import time
import threading
import pandas as pd
import signal
import ctypes
from filelock import FileLock
from uuid import getnode as getmac
import random

import sys
import os

if os.path.dirname(os.path.dirname(os.path.abspath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utilities.network import *

from twisted.internet import reactor, protocol, tcp
from twisted.protocols import basic
from twisted.web import server
from twisted.web.resource import Resource
from readerwriterlock import rwlock

"""
GLOBAL DATA
"""
lock = rwlock.RWLockFairD()
bpf_hash_P2P_IPs = None
GBD_lock = []

connections = []
listener = None
nodeID = None
directory = None
logPath = None
logFile = None
IP = None
port = 8000
serverPort = None
initiating = True
msgID = 0
msgRoutes = {}
msgTimeout = 3.0
netData = []

MIN_CONNS = 3
MAX_CONNS = 10
UNDER_PROB = 50
OVER_PROB = 10


"""
p2p TWISTED CLASSES
"""
class p2pProtocol(basic.LineReceiver):
    def __init__(self):
        self.output = None
        self.normalizeNewlines = True
        self.initiator = False
    
    def setInitiator(self):
        self.initiator = True
    
    def connectionMade(self):
        connections.append(self)
        peer = self.transport.getPeer()
        writeLog("Connected to {0}:{1}\n".format(peer.host, peer.port))

        if self.initiator:
            self.sendPing()
        host = self.transport.getHost()
        global IP
        IP = host.host

    
    def connectionLost(self, reason):
        connections.remove(self)
        peer = self.transport.getPeer()
        writeLog("Disconnected with {0}:{1}\n".format(peer.host, peer.port))
        makePeerConnection()
        

    def dataReceived(self, data):
        peer = self.transport.getPeer()
        writeLog("\nData received from %s: %s" % (peer.port, data))
        try:
            lines = data.decode("utf-8").split(";")
            for line in lines:
                if (len(line) > 0):
                    self.handleMessage(line)
        except Exception as e:
            print("P2P ERROR:", str(e))

    
    def handleMessage(self, data):
        peer = self.transport.getPeer()
        writeLog("\nIncoming message: {0}\n".format(data))
        writeLog("\n")
        message = data.split('&', 3)
        msgid = message[0]
        pldescrip = int(message[1])
        ttl = int(message[2])
        payload = message[3]
        if (pldescrip == 0):
            writeLog("Received PING: msgid={0} ttl={1}\n".format(msgid, ttl))
            self.handlePing(msgid, ttl, payload)
        elif(pldescrip == 1):
            writeLog("Received PONG: msgid={0} payload={1}\n".format(msgid, payload))
            self.handlePong(msgid, payload)

    
    def buildHeader(self, descrip, ttl):
        global msgID
        header = "{0}{1:03}".format(nodeID, msgID)
        msgID += 1
        if(msgID > 999):
            msgID = 0
        return "{0}&{1}&{2}&".format(header, descrip, ttl) 
    
    def sendPing(self, msgid=None, ttl=3, payload=None):
        global port
        IP = self.transport.getHost().host
        if(ttl <= 0):
            return
        if msgid:
            header = "{0}&{1}&{2}&".format(msgid, "00", ttl)
            message = "{0}{1}".format(header, payload)
            writeLog("Forwarding PING: {0}\n".format(message))
        else:
            header = self.buildHeader("00", ttl)
            message = "{0}{1}&{2}".format(header, port, IP)
            writeLog("Sending PING: {0}\n".format(message))
        message = "{0};".format(message)
        for cn in connections:
            if (msgid == None or cn != self):
                cn.transport.write(message.encode("utf-8"))
    
    def sendPong(self, msgid, payload=None):
        global port
        IP = self.transport.getHost().host
        header = "{0}&{1}&{2}&".format(msgid, "01", 7)
        if payload:
            message = "{0}{1};".format(header, payload)
            writeLog("Forwarding PONG: {0}\n".format(message))
        else:
            message = "{0}{1}&{2};".format(header, port, IP)
            writeLog("Sending PONG: {0}\n".format(message))
        global msgRoutes
        msgRoutes[msgid][0].transport.write(message.encode("utf-8"))
    
    def handlePing(self, msgid, ttl, payload):
        IP = self.transport.getHost().host
        info = payload.split("&")
        
        if (info[1] != IP):
            global bpf_hash_P2P_IPs
            bpf_hash_P2P_IPs[ctypes.c_uint(ip2int(info[1]))] = ctypes.c_uint(0)

        if isValid(msgid):
            return
        global msgRoutes
        msgRoutes[msgid] = (self, time.time())
        self.sendPong(msgid)
        self.sendPing(msgid, ttl-1, payload)
    
    def handlePong(self, msgid, payload):
        global nodeID
        global netData
        IP = self.transport.getHost().host
        info = payload.split("&")
        
        if (info[1] != IP):
            global bpf_hash_P2P_IPs
            bpf_hash_P2P_IPs[ctypes.c_uint(ip2int(info[1]))] = ctypes.c_uint(0)
        
        node_data = (int(info[0]), info[1])
        if info not in netData:
            netData.append(node_data)
        if(msgid.startswith(nodeID)):
            makePeerConnection(node_data[1], node_data[0])
        else:
            self.sendPong(msgid, payload)
            makePeerConnection()


class p2pFactory(protocol.ReconnectingClientFactory):
    def __init__(self, isInitiator=False):
        self.initiator = False
        if isInitiator:
            self.initiator = True
    
    def buildProtocol(self, addr):
        prot = p2pProtocol()
        if self.initiator:
            prot.setInitiator()
        return prot
    
    def startedConnecting(self, connector):
        self.host = connector.host
        self.port = connector.port
        writeLog("Trying to connect to {0}:{1}\n".format(self.host, self.port))
    
    def clientConnectionFailed(self, transport, reason):
        time.sleep(1)
        writeLog("Retrying connection with %s:%s\n" % (transport.host, transport.port))
        global connections
        numConns = len(connections)
        if numConns == 0:
            reactor.connectTCP(transport.host, int(transport.port), p2pFactory(True))



class Server(Resource):
    isLeaf = True
    
    def render_POST(self, request):
        try:
            x = threading.Thread(target=store_traffic, args=(str(request.content.read().decode('utf-8'))[1:-1], request.transport.getPeer().host, ))
            x.start()
        except:
            pass
        request.finish()
        return server.NOT_DONE_YET


class CustomPort(tcp.Port):

    def __init__(self, port, factory, backlog=50, interface='', reactor=None, reuse=False):
        tcp.Port.__init__(self, port, factory, backlog, interface, reactor)
        self._reuse = reuse

    def createInternetSocket(self):
        s = tcp.Port.createInternetSocket(self)

        if self._reuse:
            #
            # reuse IP Port
            #
            if 'bsd' in sys.platform or \
                    sys.platform.startswith('linux') or \
                    sys.platform.startswith('darwin'):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            elif sys.platform == 'win32':
                # on Windows, REUSEADDR already implies REUSEPORT
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            else:
                raise Exception("don't know how to set SO_REUSEPORT on platform {}".format(sys.platform))

        return s


"""
GLOBAL HELPER FUNCTIONS
"""

def store_traffic(traffic, ip_host):
    global GBD_lock

    t = traffic.replace("\\\"", "\"")
    df = pd.read_json(t)

    path_traffic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/global_P2P_traffic"

    lock = FileLock(path_traffic_dir+"/traffic.csv.lock")
    with lock:
        df.to_csv(path_traffic_dir+"/traffic.csv", mode='a', header=False, index=False)
        
        if ip_host not in GBD_lock:
            GBD_lock.append(ip_host)



def makePeerConnection(IP=None, port=None):
    global MAX_CONNS
    global netData
    global connections
    cleanPeerList()
    numConns = len(connections)
    if (numConns < MAX_CONNS and len(netData) > 0):
        if numConns == 0 or shouldConnect(numConns):
            randNode = netData[random.randint(0, len(netData)-1)]
            if (not IP and not port):
                IP = randNode[1] 
                port = randNode[0]
                netData.remove(randNode)
            reactor.connectTCP(IP, port, p2pFactory(True))

def shouldConnect(numConns):
    global MIN_CONNS
    global UNDER_PROB
    global OVER_PROB
    prob = random.randint(0, 99)
    if (numConns < MIN_CONNS):
        if (prob < UNDER_PROB):
            return True
    elif (prob < OVER_PROB):
        return True
    return False 


def cleanPeerList():
    global netData
    global connections
    for conn in connections:
        peer = conn.transport.getPeer()
        peer_info = (peer.port, peer.host)
        if peer_info in netData:
            netData.remove(peer_info)

def writeLog(line):
    global logFile
    global logPath
    logFile = open(logPath, "a")
    logFile.write(line)
    logFile.close()


def printLine(line):
    print(line)
    writeLog("{0}\n".format(line))


def isValid(msgid):
    global msgRoutes
    global msgTimeout
    now = time.time()
    if msgid in msgRoutes.keys() and now - msgRoutes[msgid][1] < msgTimeout:
        msgRoutes[msgid] = (msgRoutes[msgid][0], now)
        return True
    return False


"""
MAIN FUNCTION
"""
def Start_P2P(GraphBasedDetection_lock, bpf, targetIP):
    global logFile
    global logPath
    global directory
    global listener
    global IP
    global port
    global nodeID
    global serverPort
    global bpf_hash_P2P_IPs
    global GBD_lock

    def signal_handler(signalNumber, frame):
        try:
            reactor.callFromThread(connector.disconnect)
        except:
            pass
        try:
            reactor.callFromThread(usedPort.stopListening)
            reactor.callFromThread(trafficServer.stopListening)
            reactor.callFromThread(reactor.stop) 
        except:
            pass

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)

    #must redeclare variables as globals within function
    #otherwise, python recreates a local variable 
    targetPort = 8000
    serverPort = 9020
    directory = os.path.dirname(os.path.abspath(__file__))+"/log"
    bpf_hash_P2P_IPs = bpf['P2P_IPs']
    bpf_hash_P2P_IPs.clear()
    GBD_lock = GraphBasedDetection_lock


    if directory:
        #Set up directories and log file
        if not os.path.isdir(directory):
            os.makedirs(directory)

        logPath = directory+"/output.log"
        open(logPath, "w").close() #Create or empty current log file
        logFile = open(directory+"/output.log", "w")
        print("  * Run \"tail -c +0 -f {0}\" in another terminal to see output".format(logPath))
        printLine("  * Using directory: {0}".format(directory))

        #Set up Twisted clients
        if targetIP != None and targetIP != socket.gethostbyname(socket.gethostname()):
            printLine("  * Connecting to: {0}".format(targetIP))
            connector = reactor.connectTCP(targetIP, targetPort, p2pFactory(initiating))
        
        listener = p2pFactory()
        usedPort = CustomPort(8000, listener, reuse=True)
        usedPort.startListening()

        host = usedPort.getHost()
        IP = host.host
        port = host.port
        nodeID = "{0}{1:05}".format(getmac(), port)
        printLine("  * IP address: {0}:{1}".format(host.host, host.port))
        
        # Initialize the Server for receiving the traffic of the other hosts of the P2P network
        trafficServer = CustomPort(serverPort, server.Site(Server()), reuse=True)
        trafficServer.startListening()

        serverPort = trafficServer.getHost().port
        printLine("  * Server port: {0}".format(serverPort))
        printLine("  * Node ID: {0}\n".format(nodeID))
        reactor.run()

        logFile.close()
    else:
        print("Must give a directory path")