//Author : Diksha Thakur
/*PCAP splitter : This program splits given pcap files into multiple pcap fiels each containing single TCP connection
It filter outs TCP connection and output packets from different TCP connections
in different pcap files.
Input Options:
-i file_path: (Mandatory) Specifies a pcap file as input
-o directory_path : (Mandatory) Specifies a directory to output pcap files to
-f src_ip: (Optional) If this option is given, ignore all traffice which is not from specified IP Address
-j file_path: (Optional) If this option is given, all non-TCP traffic should be stored into a single pcap file. Otherwise all non-TCP traffice should be ignored.
*/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

char *input_file_name, *output_dir_tcp, *given_ip, *output_file_nontcp;
int iflag=0, oflag=0, fflag=0, jflag=0; /*Flags to check what inputs are given*/
pcap_t *handle;
int counter =0;
int num_count = 0;
int nontcp_count = 0;
int tcp_count = 0;

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
 
/* IP header */
 struct sniff_ip {
          u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
          u_char  ip_tos;                 /* type of service */
          u_short ip_len;                 /* total length */
          u_short ip_id;                  /* identification */
          u_short ip_off;                 /* fragment offset field */
          #define IP_RF 0x8000            /* reserved fragment flag */
          #define IP_DF 0x4000            /* dont fragment flag */
          #define IP_MF 0x2000            /* more fragments flag */
          #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
          u_char  ip_ttl;                 /* time to live */
          u_char  ip_p;                   /* protocol */
          u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
 
      };
 
struct sniff_icmp
{
    u_char icmp_type;
    u_char icmp_code;
    u_short icmp_checksum;
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define IP_Flag(ip)                (((ip)->ip_off) & 0xD0)
#define IP_off(ip)                (((ip)->ip_off) & 0x1F)
/* TCP header */
typedef u_int tcp_seq;
 
struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
       // tcp_seq th_syn;
       // tcp_seq th_fin;
        //tcp_seq th_urg;
        u_char  th_offx2;               /* data offset, rsvd */
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};



//----------------------------------------------declaring variables


struct flow_s {

	char *SOURCE_IP;
	char *DEST_IP;
	unsigned short SOURCE_PORT;
	unsigned short DEST_PORT;
	int flag;
	pcap_dumper_t * pc;
	char *filename;
	struct flow_s *next;
};

struct flow_s *list_of_flows = NULL;

void add_to_list(struct flow_s *f)
{
	f->next = list_of_flows;
	list_of_flows = f;
}

struct flow_s*
find_flow(char *SOURCE_IP, char *DEST_IP, unsigned short SOURCE_PORT,unsigned short DEST_PORT ){
	
	struct flow_s *temp;
	temp = list_of_flows;
	
	while (temp!=NULL){
	
		if (((strcmp(temp->SOURCE_IP,SOURCE_IP)==0) && (strcmp(temp->DEST_IP,DEST_IP)==0) && (temp->SOURCE_PORT==SOURCE_PORT) && (temp->DEST_PORT==DEST_PORT) && temp->flag!=2) 
		||( (strcmp(temp->SOURCE_IP,DEST_IP)==0) && (strcmp(temp->DEST_IP,SOURCE_IP)==0) && (temp->SOURCE_PORT==DEST_PORT) && (temp->DEST_PORT==SOURCE_PORT) && temp->flag!=2) ){
			return (temp);
		}
		temp = temp->next;
	}
	return (NULL);
}



/* Callback function for pcap_loop() */	
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr,const u_char* packet){
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    int size_ip;
    int size_tcp;
    int size_payload;
    int size_udp;
    char *SOURCE_IP = (char *)malloc(255);
    char *DEST_IP = (char *)malloc(255);
    char *filename = (char *)malloc(255);
    unsigned short SOURCE_PORT;
    unsigned short DEST_PORT;
    struct flow_s *flow = malloc(sizeof (struct flow_s));
     
        /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    //printf("\npacket number  %d\n",num_count++);
    //printf("\nNo. of TCP Connections  %d\n",counter);

    /*compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;

    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
         
    }
    /* print source and destination IP addresses */
    strcpy(SOURCE_IP , inet_ntoa(ip->ip_src));
    strcpy(DEST_IP ,inet_ntoa(ip->ip_dst));
    switch(ip->ip_p) 
    {
	case 6:
		tcp_count =tcp_count+1;
		//printf("TCP Connection Found\n");
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20)
		{
			//printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		SOURCE_PORT = ntohs(tcp->th_sport);
		DEST_PORT = ntohs(tcp->th_dport);
                     
		if(((tcp->th_flags)&TH_SYN) == 2 )
		{
			//Checking for Active file
			    
			flow = find_flow(SOURCE_IP,DEST_IP,SOURCE_PORT,DEST_PORT );
			if (flow){
				pcap_dump(( u_char*)flow->pc,  pkthdr, packet);
				return;
			    }   
	                
			sprintf(filename,"%d.pcap",counter);
			char *dir = (char *)malloc(strlen(output_dir_tcp)+ strlen(filename)+2);
			sprintf(dir,"%s/%s",output_dir_tcp,filename);
			DIR *odir =opendir(output_dir_tcp);;
			if(ENOENT==errno)
			{
				printf("\nWrong Output directory \n");
				exit(8);		
			}
			
			pcap_dumper_t * pc = pcap_dump_open(handle,dir);
			if (pc == NULL)
			{
				printf("\nError opening savefile  for writing: %s\n",dir);
				exit(7);
			} 

			flow = malloc(sizeof (struct flow_s));
			flow->SOURCE_IP = SOURCE_IP;
			flow->DEST_IP = DEST_IP;
			flow->SOURCE_PORT = SOURCE_PORT;
			flow->DEST_PORT = DEST_PORT;
			flow->flag = 0;
			flow->pc = pc;
			flow->filename = filename;
			add_to_list(flow);
			counter = counter+1;
                            
			pcap_dump(( u_char*)flow->pc,pkthdr, packet);

			//it is a SYN packet
			return;
                             
                       }

		//printf("Not a SYN Packet\n");
		// If TCP connection is active from one side, Flag = 1        
		flow = find_flow(SOURCE_IP,DEST_IP,SOURCE_PORT,DEST_PORT );
		if (flow){
			//printf("Active TCP connection found but not in SYN packet: %s\n",flow->filename);
			//pcap_dumper_t * pc = pcap_dump_open(handle,flow->filename);
			pcap_dump(( u_char*)flow->pc,  pkthdr, packet);
			//pcap_dump_flush(pc);
		}


		if(((tcp->th_flags)&TH_FIN) == 1 |((tcp->th_flags)&TH_RST) == 4 )
		{
			if(((tcp->th_flags)&TH_FIN) == 1 )
				{ //printf("\n closing since it is a FIN packet");
				}
			else if(((tcp->th_flags)&TH_RST) == 1 )
				{ //printf("\n closing since it is a RST packet");
				}
			if (flow){
				flow->flag = flow->flag+1;
				if (flow->flag == 2){
					//printf("-----connection ending here----");  
					pcap_dump_close(flow->pc); 
					//printf("total number of packets in this connection %d  ", i);
			  	}
			}
			else{
				//printf("\nFIN Packet recieved but have not pcap active file for this\n");
			}
		}
		else{
			//printf("Not a FIN Packet as well\n");
		}

			   
		
                        
                       break;

        default: 
		nontcp_count = nontcp_count+1;
		break;
    }

}


void pcap_splitter(char *input_file_name)
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	char *filter_exp = (char *)malloc(50) ;  //The filter expression
	if (fflag == 1)
	{
		sprintf(filter_exp,"src %s and tcp",given_ip);	
	}
	else
	{
		sprintf(filter_exp,"tcp");
	}
	struct bpf_program fp;  // Compiled filter expression
	handle = pcap_open_offline(input_file_name,error_buffer);
		
	if (handle == NULL){
		//printf("Error Reading file %s\n",input_file_name);	
	}
	
	//Compile filter condition
	if(pcap_compile(handle, &fp, filter_exp,0,0)==-1){
		//printf("Compile filter expression error: %s\n",pcap_geterr(handle));
		exit(3);
	}

	//setting filter
	if (pcap_setfilter(handle, &fp)==-1){
		//printf("Setting filter error: %s\n",pcap_geterr(handle));
		exit(4);
	}

	//using pcap_loop to traverse each packet and call pcap_handler function
	if (pcap_loop(handle,0,packetHandler,NULL)<0){
		//printf("pcap_loop() failed: %s\n",pcap_geterr(handle));
		exit(5);
	}	
	pcap_close(handle);
}

void nonTcp(u_char *userData, const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	//printf("\nNon TCP packet found\n");
	pcap_dumper_t * pc = pcap_dump_open(handle,output_file_nontcp);
	pcap_dump(( u_char*)pc,  pkthdr, packet);
	pcap_dump_close(pc);
}

int nonTcpPacketHandler()
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	char filter_exp[50] = "udp or icmp";  //The filter expression
	struct bpf_program fp; 
	handle = pcap_open_offline(input_file_name,error_buffer);
		
	if (handle == NULL){
		printf("\nError Reading file %s\n",input_file_name);
		exit(1);	
	}

	//Compile filter condition
	if(pcap_compile(handle, &fp, filter_exp,0,0)==-1){
		//printf("Compile filter expression error: %s\n",pcap_geterr(handle));
		exit(3);
	}

 	//setting filter
	if (pcap_setfilter(handle, &fp)==-1){
		//printf("Setting filter error: %s\n",pcap_geterr(handle));
		exit(4);
	}
	
	
	//using pcap_loop to traverse each packet and call nonTcp function
	if (pcap_loop(handle,0,nonTcp,NULL)<0){
		//printf("pcap_loop() failed: %s\n",pcap_geterr(handle));
		exit(5);
	}

	pcap_close(handle);

	

}


int main(int argc,char **argv)
{
	
	extern char *optarg;
	extern int optind, optopt, opterr;
	int c;
	
	//char *input_file_name, *output_dir_tcp, *given_ip, *output_dir_nontcp;
	

	while ((c = getopt(argc, argv, "i:o:f:j:")) != -1){
		switch(c){
		case 'i':
			iflag =1;
			input_file_name = optarg;
			printf("input file name %s\n",input_file_name);
			break;
		case 'o':
			oflag = 1;
			output_dir_tcp = optarg;
			break;
		case 'f':
			fflag = 1;
			given_ip = optarg;
			break;
		case 'j':
			jflag = 1;
			output_file_nontcp = optarg;
			break;
		case ':':
			printf("-%c without filename \n",optopt);
			break;
		case '?':
			printf("unknown arg %c\n",optopt);
			break;

		}
	}
	
	if (iflag == 0){  //-i is mandatory
		printf("missing -i option");
		exit(1);
	}	
	printf("Input File: %s\n",input_file_name);

	if (oflag == 0){  //-o is mandatory
		printf("missing -o option");
		exit(1);
	}
	printf("Output Files Directory: %s \n",output_dir_tcp);
	
	if (fflag == 1) { // -f is optional
		printf("Source IP Addr to monitor: %s \n",given_ip);
	}
	if (jflag == 1) { // -j is optional
		printf("Filename for non_TCP Traffic: %s\n",output_file_nontcp);
	}	
	printf("Understood Input \n");
	
	//----------------------Starting reading pcap file--------------
	
	pcap_splitter(input_file_name);
	printf("Non TCP Packets %d\n",nontcp_count);
	printf("TCP Packet %d\n",tcp_count);
	printf("\nNo. of TCP Connections  %d\n",counter);
	

	if (jflag==1)
	{
		//printf("\nPrinting non TCP packets %d \n");
		nonTcpPacketHandler();
	}
	
	
}
