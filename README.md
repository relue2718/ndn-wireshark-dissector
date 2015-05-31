# ndn-wireshark-dissector
A Wireshark dissector for NDN(Named Data Networking)-TLV packets

# Trouble-shootings
Due to security issues, loading a customized lua script with root privileges is not allowed. You may need to follow this instruction to enable non-root users to be able to capture packets via network interface cards.

http://anonscm.debian.org/viewvc/collab-maint/ext-maint/wireshark/trunk/debian/README.Debian?view=markup
