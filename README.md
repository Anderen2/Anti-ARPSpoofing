Anti-ARPSpoofing
================

This is a small python script to be used on a client on the network, together with a DD-WRT router. It monitors ARP activity, and blacklists macaddresses who behave suspicious. It also notifies the client with the notify-send command. 

This software requires the following additions:
OS:
  Linux/Unix variant

Pythonmodules:
  sh
  twisted

Other programs:
  notify-send
  arpwatch

DISCLAIMER: Keep in mind that the code on this were written by me when I was half-asleep, so its nowhere near pretty, or stable for that sake.
