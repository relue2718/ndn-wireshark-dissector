# ndn-wireshark-dissector
A Wireshark dissector plugin for analyzing NDN (Named Data Networking) TLV packets.

# Announcement
The tools for NDN are actively being managed by [named-data](https://github.com/named-data) group. You may find the most recent update of this plugin on [this link](https://github.com/named-data/ndn-tools/tree/master/tools/dissect-wireshark).

# Known Issues
Due to security issues, loading a customized lua script with root privileges is not allowed by default. You may need to follow this instruction to enable non-root users to be able to capture packets via network interface cards. [(Instruction)](http://anonscm.debian.org/viewvc/collab-maint/ext-maint/wireshark/trunk/debian/README.Debian?view=markup)

