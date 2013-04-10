Anti-ARPSpoofing
================

This is a small python script to be used on a client on the network, together with a DD-WRT router. It monitors ARP activity, and blacklists macaddresses who behave suspicious. It also notifies the client with the notify-send command. 

This software requires the following additions:

OS:
  Linux/Unix variant on client, 
  DD-WRT / Other SSH compatible router

Pythonmodules:
  sh,
  twisted

Other programs:
  notify-send,
  arpwatch
  
The whole program is in the file AntiArp.py, and all you need to do after installing the required packages is to open it with python. Some modification on the code to make it fit with your router may be nessesary, but it should detect ARP-attacks properly out of the box together with arpwatch

DISCLAIMER: Keep in mind that the code on this were written by me when I was half-asleep, so its nowhere near pretty, or stable for that sake.
