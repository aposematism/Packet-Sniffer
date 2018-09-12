# packet-sniffer
Packet Sniffer written in C, presents the data with both hex and normal data

This project uses pcap files captured from wireshark to read the data. 
You can pass commands to the file using bash with the command ./sniffer [file] [number of packets]

Relatively straightforward design, primarily designed to present information cleanly.
Must be compiled with lpcap. Compile with gcc -o sniffer packetsniffer.c -lpcap
