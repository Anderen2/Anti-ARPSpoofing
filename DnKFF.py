#DetectAndKillAllFlipFlops!
from base64 import b64decode
from string import split
from time import sleep
import sh
from twisted.internet.protocol import ClientFactory, Protocol
from string import split
from twisted.internet import reactor

#FlipFlop Detector

Verbose=True

notifysend = sh.Command("notify-send")

pwfile=open("/etc/a2/DDWRTPASS", "r")
GPW=pwfile.read()

syslog=open("/var/log/syslog", "r")
syslog.seek(0,2)

gwmac="c0:c1:c0:fb:ed:3e"

def ParseFF(line):
	MacAttack=None
	foo=split(line, " ")
	IP1=foo[8]
	IP2=foo[9].strip("(").strip(")")

	print("IP 1: "+IP1)
	print("IP 2: "+IP2)

	if IP1!=gwmac:
		print("Conflicting IP is: "+IP1)
		MacAttack=IP1

	elif IP2!=gwmac:
		print("Conflicting IP is: "+IP2)
		MacAttack=IP2
	else:
		print("No IP is inpersonating gateway!")

	if MacAttack!=None:
		#notifysend("'ARP Attack Detected!'", "'Attacking MAC is: "+MacAttack+"\nKilling his connection...'")
		Fact=DDWRTFactory()
		Fact.blacklistmac=MacAttack
		reactor.connectTCP(IP, PORT, Fact)

def ArpAttactNotif(TF, MAC):
	if TF:
		notifysend("'ARP Attack Detected!'", "'Attacking MAC is: "+MAC+"\nKilling his connection...'", "--urgency=critical")
	else:
		notifysend("'ARP Attack Averted!'", "'MAC: "+MAC+" got blacklisted\nGateway have regained control", "--urgency=normal")


def Notif(line):
	fineline=line
	notifysend("'Network Information'", "'"+fineline+"'", "--urgency=low")

def CheckSysLog():
	#print("Checking Log..")
	where = syslog.tell()
	line = syslog.readline()
	if not line:
		sleep(1)
		syslog.seek(where)
	else:
		if "flip flop" in line:
			ParseFF(line)
		elif "mismatch" in line:
			Notif(line)
	reactor.callLater(2, CheckSysLog)

reactor.callWhenRunning(CheckSysLog)

class DDWRTProto(Protocol):
	def __init__(self, factory):
		self.factory=factory
		self.SG=0

	def connectionMade(self):
		print("Connection to DD-WRT made")
		self.transport.write("")

	def connectionLost(self, reason):
		if Verbose:
			print("Connection to DD-WRT lost", reason)
		else:
			print("Connection to DD-WRT lost/closed")

	def Ins2(self):
		instruction2="nvram set 'wl0_maclist="+self.factory.macliststr+" "+self.factory.blacklistmac+"' && nvram commit && rc start"
		self.transport.write(instruction2+"\n")
	def Flush(self):
		self.transport.write("\r\n")
	def SignOut(self):
		self.transport.loseConnection()

	def dataReceived(self, data):
		if Verbose:
			print data
		if self.factory.hostname+" login: " in data:
			print("DDWRTPROTO: Logging in with "+self.factory.username)
			self.transport.write(self.factory.username+"\n")
		elif "Password:" in data:
			print("DDWRTPROTO: Sending password..")
			self.transport.write(self.factory.password+"\n")
		elif self.factory.username+"@"+self.factory.hostname+":~# " in data and self.SG==0:
			print("DDWRTPROTO: Sending instruction..")
			self.transport.write(self.factory.instruction1+"\n")
			self.SG=1
		elif "wl0_maclist" in data and not "set" in data:
			for x in split(data, "\n"):
				if "wl0_maclist" in x:
					self.factory.maclist=split(x.strip("\r").strip("wl0_maclist="), " ")
					self.factory.macliststr=x.strip("\r").strip("wl0_maclist=")
					if Verbose:
						print(self.factory.maclist)
			if not self.factory.blacklistmac in self.factory.maclist:
				print("Mac not in list.. Blacklisting")
				ArpAttactNotif(True, self.factory.blacklistmac)
				reactor.callLater(2, self.Ins2)
				reactor.callLater(3, self.Flush)
			else:
				print("Mac already in list! Probleary just a bounceback.")
				ArpAttactNotif(False, self.factory.blacklistmac)
			reactor.callLater(5, self.SignOut)

class DDWRTFactory(ClientFactory):
	def __init__(self):
		self.hostname="CiscoNet"
		self.username="root"
		self.password=b64decode(GPW)
		self.blacklistmac=None
		self.instruction1="nvram show | grep wl0_maclist"
		#self.instruction2="nvram set wl0_maclist="+self.blacklistmac+" && nvram commit && rc start"

	def buildProtocol(self, addr):
		return DDWRTProto(self)

IP="192.168.1.1"
PORT=23

reactor.run()