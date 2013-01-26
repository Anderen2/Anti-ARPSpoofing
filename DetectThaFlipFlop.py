#FlipFlop Detector
from string import split
import time
import sh

notifysend = sh.Command("notify-send")

syslog=open("/var/log/syslog", "r")
syslog.seek(0,2)

gwmac="c0:c1:c0:fb:ed:3e"

def ParseFF(line):
	foo=split(line, " ")
	IP1=foo[8]
	IP2=foo[9].strip("(").strip(")")

	print("IP 1: "+IP1)
	print("IP 2: "+IP2)

	if IP1!=gwmac:
		print("Conflicting IP is: "+IP1)
	elif IP2!=gwmac:
		print("Conflicting IP is: "+IP2)
	else:
		print("No IP is inpersonating gateway!")

def Notif(line):
	fineline=line
	notifysend("'Network Information'", "'"+fineline+"'", "--urgency=normal")

while 1:
	where = syslog.tell()
	line = syslog.readline()
	if not line:
		time.sleep(1)
		syslog.seek(where)
	else:
		if "flip flop" in line:
			ParseFF(line)
		elif "mismatch" in line:
			Notif(line)