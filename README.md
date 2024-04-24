# NetworkSecurity
How to corrupt an IP checksum using C++ from a pcap file.

#The title is how to corrupt an IP checksum. First generate the IP checksum using Wireshark by surfing the internet. Next, create a code that allows it to read the original checksum : 0xa5eb from the pcap file. Next, corrupt the checksum using C++ to display the corrupted code in the terminal corrupted IP checksum: 0xa4eb. Next convert the corrupted checksum value back into a pcap file (Wireshark form). This way u can trick the user into thinking he is using the correct checksum value, however he is using the corrupted checksum value that you have created. 
