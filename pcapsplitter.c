//Author : Diksha Thakur
/*PCAP splitter : This program splits given pcab into multiple pca fiels
It filter outs TCP connection and output packets from different TCP connections
in different pcap files.
Input Options:
-i file_path: (Mandatory) Specifies a pcap file as input
-o directory_path : (Mandatory) Specifies a directory to output pcap files to
-f src_ip: (Optional) If this option is given, ignore all traffice which is not from specified IP Address
-j file_path: (Optional) If this option is given, all non-TCP traffic should be stored into a single pcap file. Otherwise all non-TCP traffice should be ignored.
*/
