#FlipFlop Killer
from twisted.internet.protocol import ClientFactory, Protocol
from time import sleep
from string import split
from twisted.internet import reactor

class DDWRTProto(Protocol):
	def __init__(self, factory):
		self.factory=factory
		self.SG=0

	def connectionMade(self):
		print("Connection to DD-WRT made")
		self.transport.write("")

	def connectionLost(self, reason):
		print("Connection to DD-WRT lost", reason)

	def lineReceived(self, line):
		pass

	def dataReceived(self, data):
		print data
		if self.factory.hostname+" login: " in data:
			print("DDWRTPROTO: Logging in with "+self.factory.username)
			self.transport.write(self.factory.username+"\n")
		elif "Password:" in data:
			print("DDWRTPROTO: Sending password..")
			self.transport.write(self.factory.password+"\n")
		elif self.factory.username+"@"+self.factory.hostname+":~# " in data and self.SG==0:
			print("DDWRTPROTO: Sending instruction..")
			sleep(1)
			self.transport.write(self.factory.instruction1+"\n")
			self.SG=1
		elif "wl0_maclist" in data:
			for x in split(data, "\n"):
				if "wl0_maclist" in x:
					self.factory.maclist=split(x.strip("\r").strip("wl0_maclist="), " ")
					print(self.factory.maclist)
			if not self.factory.blacklistmac in self.factory.maclist:
				print("Mac not in list.. Blacklisting")
				sleep(1)
				self.transport.write(self.factory.instruction2+"\n")
			else:
				print("Mac already in list! Probleary just a bounceback.")
			sleep(10)
			#self.transport.loseConnection()

class DDWRTFactory(ClientFactory):
	def __init__(self):
		self.hostname="CiscoNet"
		self.username="root"
		self.password="xxx"
		self.blacklistmac="78:d6:f0:b2:76:54"
		self.instruction1="nvram show | grep wl0_maclist"
		self.instruction2="nvram set wl0_maclist="+self.blacklistmac+" && nvram commit && rc start"

	def buildProtocol(self, addr):
		return DDWRTProto(self)

IP="192.168.1.1"
PORT=23
reactor.connectTCP(IP, PORT, DDWRTFactory())
reactor.run()
