/*
* 
* Authors:
*	Minal Kondawar (mkondawa)
*	Saketh Babu Palla (spalla)    
*
*/


#include<stdio.h>
#include<stdlib.h>
#include<iostream>
#include<string>
#include<pcap/pcap.h>
#include<pcap/bpf.h>
#include<netinet/ether.h>
#include<arpa/inet.h>
#include<linux/if_ether.h>
#include<net/if_arp.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include<map>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<sstream>
#include<sys/time.h>
#include<getopt.h>
#include<iomanip>
using namespace std;

#define SIZE_ETHERNET 14
#define IP_HL(ip) (((ip)->ihl) & 0x0f)
#define TCP_HEADER 20

//Link layer maps
map<string, int> ether_source_addr;
map<string, int> ether_dest_addr;

//Network layer
string network_proto;
//Network layer maps
map<string,int> network_protocols;
map<string, int> net_src_ip;
map<string, int> net_dest_ip;
map<string, int> net_arp;

//Transport layer
string transport_proto;
//Transport layer maps
map<string, int> transport_protocols;

//TCP maps
map<string, int> tcpflags;
map<int, int> tcpSrcPort;
map<int, int> tcpDestPort;
map<int, int> tcpOptions;
map<int, int> tcp_opt_len;

//UDP maps
map<int, int> udpSrcPort;
map<int, int> udpDestPort;

//Icmp maps
map<int,int> icmpType;
map<int,int> icmpCode;

//Iterators
map<string, int>::iterator itr;
map<int, int>::iterator itr1;

char buff[INET_ADDRSTRLEN];
char buffer[1000];

int openFlag = 0;
char *pcap_file_name;
int packetsCaptured = 0;
time_t start_time = 0;
time_t end_time = 0;
int min_pkt_size = 0;
int max_pkt_size = 0; 
float total_pkt_size = 0;
string rawString;

//Extracting mac address in the string format from arp_sha (arp's source hardware address)
string extractMacAddr(u_char *arp_sha)
{
    stringstream output;
    int intValue;
    for(int i = 0; i < 6; i++)
    {
	intValue = (int)arp_sha[i];
	
	output << setw(2) << setfill('0') << hex <<  intValue;
	if(i < 5)
	{	
	    output << ":";
	}
    }
    return output.str();
}

string parse_string(string rawString)
{
	istringstream iss(rawString);
	stringstream ss;
	string token;
	int count = 0;

	while(getline(iss, token, ':'))
	{
		//Append ":" at the beginning of each token starting from the second token
		if(count++ != 0) 
			ss << ":" << setw(2) << setfill('0') << token;
		else
			ss << setw(2) << setfill('0') << token;
	}
	return ss.str();
}

//Initializing tcp flags
void initTcpFlags()
{
    tcpflags["ACK"] = 0;
    tcpflags["FIN"] = 0;
    tcpflags["PSH"] = 0;
    tcpflags["RST"] = 0;
    tcpflags["SYN"] = 0;
    tcpflags["URG"] = 0;
  
}
void packet_parser(u_char* args, const struct pcap_pkthdr *header, const u_char *pkt)
{
	packetsCaptured++;
	int packet_size = header->len;
	string parsedString;
	struct ethhdr *e = (struct ethhdr *)pkt;
	stringstream net_proto_type;

//Collecting the summary information
	if(packetsCaptured == 1)
	{ //For the first packet, initialize start time, min and max packet sizes
		start_time = header->ts.tv_sec;
		min_pkt_size = header->len;
		max_pkt_size = header->len;
	}	
	//Updating end time for every packet
	if(header->ts.tv_sec > end_time)
	{
		end_time = header->ts.tv_sec;
	}
	//Updating min and max packet sizes
	if(header -> len < min_pkt_size)
	{
		min_pkt_size = header->len;
	}
	if(header->len > max_pkt_size)
	{
		max_pkt_size = header->len;
	}

	//Updating total packet size till now
	total_pkt_size += header->len;


	//Link Layer
//Inserting the source addresses into the map (ether_source_addr)
	rawString =  ether_ntoa((const struct ether_addr *)e->h_source); 	
	parsedString = parse_string(rawString);

	itr = ether_source_addr.find(parsedString);
	if(itr !=  ether_source_addr.end())
		 ether_source_addr[parsedString] += 1;
	else
		ether_source_addr[parsedString] = 1;	

//Inserting the destination addresses into the map (ether_dest_addr)
	rawString = ether_ntoa((const struct ether_addr *)e->h_dest);
	parsedString = parse_string(rawString);
	itr = ether_dest_addr.find(parsedString);
	if(itr != ether_dest_addr.end())
		 ether_dest_addr[parsedString] += 1;
	else
		ether_dest_addr[parsedString] = 1;	

	
//Network Layer
//Inserting the protocol type of the packets into the map(network_protocols)	
	network_proto = ntohs(e -> h_proto);
	if(ntohs(e->h_proto) == ETH_P_IP)
	{
	    network_proto = "IP";
	}
	else if(ntohs(e -> h_proto) == ETH_P_ARP)
	{
	   network_proto = "ARP";
	}
	else
	{

	    net_proto_type << ntohs(e->h_proto) << " (0x" << hex << ntohs(e->h_proto) << ")";
	    network_proto = net_proto_type.str();

	}

	itr = network_protocols.find(network_proto);
	if(itr != network_protocols.end())
		 network_protocols[network_proto] = network_protocols[network_proto] + 1;
	else
		network_protocols[network_proto] = 1;	

	
	
	  //get ip information
	  
	  if(ntohs(e->h_proto)== ETH_P_IP) //IP 
	  {
	    
		 struct iphdr *iph = (struct iphdr *)(pkt+SIZE_ETHERNET); //Pointing to the actual data of the packet which is present after the header(SIZE_ETHERNET = header size)
	
		inet_ntop(AF_INET, &((*iph).saddr), buff, INET_ADDRSTRLEN); //converting the packet's source address (IPv4) from binary to text and Storing it in the buffer
		
		//Storing it in the map (net_src_ip)
		itr = net_src_ip.find(buff);
		if(itr !=  net_src_ip.end())
			 net_src_ip[buff] = net_src_ip[buff] + 1;
		else
			net_src_ip[buff] = 1;	

		inet_ntop(AF_INET, &((*iph).daddr), buff, INET_ADDRSTRLEN);//converting the packet's destination address (IPv4) from binary to text and Storing it in the buffer
		
		//Storing it in the map (net_dest_ip)
		itr = net_dest_ip.find(buff);
		if(itr !=  net_dest_ip.end())
			 net_dest_ip[buff] = net_dest_ip[buff] + 1;
		else
			net_dest_ip[buff] = 1;

	      //Transport Layer
	      //Inserting transport layer protocols into the map(transport_protocols)
	      stringstream trans_proto_type;
	      if((*iph).protocol == IPPROTO_TCP) //TCP
	      {
		transport_proto = "TCP";
	      }
	      else if((*iph).protocol == IPPROTO_UDP) //UDP
	      {
		transport_proto = "UDP";
	      }
	      else if((*iph).protocol == IPPROTO_ICMP) //ICMP
	      {
		transport_proto = "ICMP";
	      }
	      else
	      {
		trans_proto_type << (int)(*iph).protocol;
		transport_proto = trans_proto_type.str();
	      }
		itr = transport_protocols.find(transport_proto);
		if(itr != transport_protocols.end())
			 transport_protocols[transport_proto] += 1;
		else
			transport_protocols[transport_proto] = 1;		
	
		int iph_size;
		iph_size = IP_HL(iph)*4;
		if (iph_size < 20) {
			cout<<"Invalid IP header Size:"<<iph_size<<"bytes"<<endl;
			exit(1);
		}

//Handling TCP details
		if((*iph).protocol==IPPROTO_TCP) //tcp
		{
			 struct tcphdr *tcp_h = (struct tcphdr *)(pkt+SIZE_ETHERNET+iph_size); //pointing to TCP information which is present after header and ip information
			struct tcp_info *tcp_inf = (struct tcp_info*)(pkt+SIZE_ETHERNET+iph_size);
			//Inserting Source TCP ports into the map(tcpSrcPort)
			itr1 = tcpSrcPort.find( ntohs((*tcp_h).source) );
			if(itr1 != tcpSrcPort.end())
			    tcpSrcPort[ntohs((*tcp_h).source)] = tcpSrcPort[ntohs((*tcp_h).source)] + 1;
			else
			    tcpSrcPort[ntohs((*tcp_h).source)] = 1;
  
			//Inserting Destination TCP ports into the map(tcpDestPort)
			itr1 = tcpDestPort.find(ntohs((*tcp_h).dest));
			if(itr1 != tcpDestPort.end())
			    tcpDestPort[ntohs((*tcp_h).dest)] = tcpDestPort[ntohs((*tcp_h).dest)] + 1;
			else
			    tcpDestPort[ntohs((*tcp_h).dest)] = 1;
    

			if((*tcp_h).ack!=0)
			{
				itr = tcpflags.find("ACK");
				if(itr !=  tcpflags.end())
			 		tcpflags["ACK"] = tcpflags["ACK"] + 1;
				else
					tcpflags["ACK"] = 1;
			}
			
			if((*tcp_h).fin!=0)
			{
				itr = tcpflags.find("FIN");
				if(itr !=  tcpflags.end())
			 		tcpflags["FIN"] = tcpflags["FIN"] + 1;
				else
					tcpflags["FIN"] = 1;
			}
			
			if((*tcp_h).syn!=0)
			{
				itr = tcpflags.find("SYN");
				if(itr !=  tcpflags.end())
			 		tcpflags["SYN"] = tcpflags["SYN"] + 1;
				else
					tcpflags["SYN"] = 1;
			}
			
			if((*tcp_h).urg!=0)
			{
				itr = tcpflags.find("URG");
				if(itr !=  tcpflags.end())
			 		tcpflags["URG"] = tcpflags["URG"] + 1;
				else
					tcpflags["URG"] = 1;
			}
			
			if((*tcp_h).rst!=0)
			{
				itr = tcpflags.find("RST");
				if(itr !=  tcpflags.end())
			 		tcpflags["RST"] = tcpflags["RST"] + 1;
				else
					tcpflags["RST"] = 1;
			}
			
			if((*tcp_h).psh!=0)
			{
				itr = tcpflags.find("PSH");
				if(itr !=  tcpflags.end())
			 		tcpflags["PSH"] = tcpflags["PSH"] + 1;
				else
					tcpflags["PSH"] = 1;
			}
			
		//tcp options
			
			char *tcp_readfp;		
			int tcp_option_length=(tcp_h->doff*4)-TCP_HEADER;
			int counter=0;
			tcp_opt_len[2]=4;
			tcp_opt_len[3]=3;
			tcp_opt_len[4]=2;
			tcp_opt_len[6]=6;
			tcp_opt_len[7]=6;
			tcp_opt_len[8]=10;
			tcp_opt_len[9]=2;
			tcp_opt_len[10]=3;
			tcp_opt_len[14]=3;
			tcp_opt_len[18]=3;
			tcp_opt_len[19]=18;
			tcp_opt_len[27]=8;
			tcp_opt_len[28]=4;
			
			
		
			int flag;
			if((tcp_h->doff*4)>20){
				flag=0;
				while(counter<tcp_option_length){
					
					tcp_readfp=(char *)(pkt+SIZE_ETHERNET+iph_size+TCP_HEADER+counter);	
					int type=(int)tcp_readfp[0];
					
					if (tcp_opt_len.find(type) == tcp_opt_len.end())
						counter += 1;
					else
						counter += tcp_opt_len[type];
					
					itr1 = tcpOptions.find(type);
					if(itr1 != tcpOptions.end()){
						if(type==1&& flag==0){
							tcpOptions[type] = tcpOptions[type];
							flag=1;
						}
						else{
							tcpOptions[type] = tcpOptions[type] + 1;
						}
					}
					else
						if(type==1&&flag==0){
							tcpOptions[type] = 2;
						}
						else{
							tcpOptions[type] = 1;
						}
				}
			}
		}

//Handling UDP details
		if((*iph).protocol==IPPROTO_UDP) //udp
		{
			struct udphdr *udp_h = (struct udphdr *)(pkt+SIZE_ETHERNET+iph_size);
			
			itr1 = udpSrcPort.find( ntohs((*udp_h).source) );
			if(itr1 != udpSrcPort.end())
			    udpSrcPort[ntohs((*udp_h).source)] = udpSrcPort[ntohs((*udp_h).source)] + 1;
			else
			    udpSrcPort[ntohs((*udp_h).source)] = 1;

			itr1 = udpDestPort.find(ntohs((*udp_h).dest));
		      if(itr1 != udpDestPort.end())
			    udpDestPort[ntohs((*udp_h).dest)] = udpDestPort[ntohs((*udp_h).dest)] + 1;
		      else
			    udpDestPort[ntohs((*udp_h).dest)] = 1;
		}

//Handling icmp types and codes
		if((*iph).protocol==IPPROTO_ICMP) //icmp
		{
			
			struct icmphdr *icmp = (struct icmphdr *)(pkt+SIZE_ETHERNET+iph_size);

			itr1 = icmpType.find(icmp->type);
	        
			if(itr1 != icmpType.end())
			  icmpType[icmp->type] += 1;
			else
			  icmpType[icmp->type] = 1;

			itr1 = icmpCode.find( ntohs((*icmp).code) );
			if(itr1 != icmpCode.end())
			  icmpCode[ntohs((*icmp).code)] = icmpCode[ntohs((*icmp).code)] + 1;
			else
			  icmpCode[ntohs((*icmp).code)] = 1;
			
		 }
	

	}

//Handling ARP participants
	if(ntohs(e->h_proto)==ETH_P_ARP)//ARP
	{
		
		//arp stuff
		struct ether_arp *arphdr = (struct ether_arp *)(pkt + SIZE_ETHERNET); //pointing to arp information which is present after the header

		string arp_ip_addr = inet_ntoa(*(struct in_addr *) arphdr -> arp_spa); //Source Ip address
		string arp_mac_addr = extractMacAddr(arphdr->arp_sha); //Source Hardware Address
		
		stringstream arp_addr;
		arp_addr <<  arp_mac_addr << "\t/\t " << arp_ip_addr;
		
		itr = net_arp.find(arp_addr.str());
		if(itr != net_arp.end())
		{
		    net_arp[arp_addr.str()] += 1;
		}
		else
		{
		    net_arp[arp_addr.str()] = 1;
		}
		
	}
}

void print_summary()
{

	cout << "=============Packet Capture Summary======" << endl;
	cout << endl;
	tzset(); //Setting the timezone to local timezone
	cout << "Capture start date: " << asctime(localtime(&start_time)) << tzname[1]<< endl;
	cout << "Capture duration: " << (end_time - start_time) << " seconds" << endl;
	cout << "Packets in capture: " << packetsCaptured << endl;
	cout << "Minimum packet size: " << min_pkt_size << endl;
	cout << "Maximum packet size: " << max_pkt_size << endl;
	cout << "Average packet size: " << (total_pkt_size/packetsCaptured) << endl;
  	cout << endl;
}


void print_info()
{
	cout << "==============Link layer=================="<<endl;

	//printing the source ethernet addresses
	cout << "-----------Source Ethernet Address-------------------"<< endl;
	if(ether_source_addr.begin() == ether_source_addr.end())
	{
	    cout << "No results found for source Ethernet address" << endl;
	}
	for(itr = ether_source_addr.begin(); itr != ether_source_addr.end(); itr++)
	{
		cout << itr->first <<"\t\t\t" << itr->second << endl;
	}
	
	//printing the Destination ethernet addresses
	cout << "----------Destination Ethernet Address------------------"<< endl;
	if(ether_dest_addr.begin() == ether_dest_addr.end())
	{
	    cout << "No results found for Destination Ethernet address" << endl;
	}
	for(itr = ether_dest_addr.begin(); itr != ether_dest_addr.end(); itr++)
	{
		cout << itr->first << "\t\t\t"<< itr->second << endl;
	}
	
	cout << "===================Network Layer============="<< endl;
	
	cout<<"--------Network layer protocol--------"<<endl;
	if(network_protocols.begin() == network_protocols.end())
	{
	    cout << "No results found for Network layer protocol" << endl;
	}
	for(itr = network_protocols.begin(); itr != network_protocols.end(); itr++)
	{
		cout << itr->first << "\t\t\t"<< itr->second << endl;
	}
	
	cout<<"--------Source Ip Address--------"<<endl;
	if(net_src_ip.begin() == net_src_ip.end())
	{
	    cout << "No results found for source Ip address" << endl;
	}
	for(itr = net_src_ip.begin(); itr != net_src_ip.end(); itr++)
	{
		cout << itr->first << "\t\t\t"<< itr->second << endl;
	}
	
	cout<<"--------Destination Ip Address--------"<<endl;
	if(net_dest_ip.begin() == net_dest_ip.end())
	{
	    cout << "No results found for Destination ip address" << endl;
	}
	for(itr = net_dest_ip.begin(); itr != net_dest_ip.end(); itr++)
	{
		cout << itr->first << "\t\t\t"<< itr->second << endl;
	}
	
	cout<<"--------Unique ARP participants--------"<<endl;
	if(net_arp.begin() == net_arp.end())
	{
	    cout << "No results found for ARP participants" << endl;
	}
	for(itr = net_arp.begin(); itr != net_arp.end(); itr++)
	{
	    
	    cout << itr->first << "\t\t\t" << itr->second << endl;
	}
	
	cout<<"================Transport layer================="<<endl<<endl;
	
	cout<<"--------Transport layer protocol--------"<<endl;
	if(transport_protocols.begin() == transport_protocols.end())
	{
	    cout << "No results found for Transport layer protocols" << endl;
	}
	for(itr = transport_protocols.begin(); itr != transport_protocols.end(); itr++)
	{
		cout << itr->first << "\t\t\t"<< itr->second << endl;
	}
	
	cout<<"============ Transport Layer TCP====================="<<endl;
	cout<<"--------Source TCP Port--------"<<endl;
	if(tcpSrcPort.begin() == tcpSrcPort.end())
	{
	    cout << "No results found for source TCP port" << endl;
	}
	for(itr1 = tcpSrcPort.begin(); itr1 != tcpSrcPort.end(); itr1++)
	{
		cout << itr1->first << "\t\t\t"<< itr1->second << endl;
	}

	cout<<"--------Destination TCP Port--------"<<endl;
	if(tcpDestPort.begin() == tcpDestPort.end())
	{
	    cout << "No results found for Destination TCP port" << endl;
	}
	for(itr1 = tcpDestPort.begin(); itr1 != tcpDestPort.end(); itr1++)
	{
		cout << itr1->first << "\t\t\t"<< itr1->second << endl;
	}

	cout << "----------TCP Flags-----------------"<< endl;
	if(tcpflags.begin() == tcpflags.end())
	{
	    cout << "No results found for TCP flags" << endl;
	}
	for(itr = tcpflags.begin(); itr != tcpflags.end(); itr++)
	{
		cout << itr->first << "\t\t\t"<< itr->second << endl;
	}
	cout<<"----------TCP options---------------"<<endl;
	if(tcpOptions.begin() == tcpOptions.end())
        {
            cout << "No results found for TCP options" << endl;
        }
        for(itr1 = tcpOptions.begin(); itr1 != tcpOptions.end(); itr1++)
        {
                cout << itr1->first << "\t\t\t"<< itr1->second << endl;
        }

	cout<<"============ Transport Layer UDP====================="<<endl;
	cout<<"--------Source UDP Ports--------"<<endl;
	if(udpSrcPort.begin() == udpSrcPort.end())
	{
	    cout << "No results found for UDP source ports" << endl;
	}
	for(itr1 = udpSrcPort.begin(); itr1 != udpSrcPort.end(); itr1++)
	{
		cout << itr1->first << "\t\t\t"<< itr1->second << endl;
	}

	cout<<"--------Destination UDP Ports--------"<<endl;
	if(udpDestPort.begin() == udpDestPort.end())
	{
	    cout << "No results found for UDP destination port" << endl;
	}
	for(itr1 = udpDestPort.begin(); itr1 != udpDestPort.end(); itr1++)
	{
		cout << itr1->first << "\t\t\t"<< itr1->second << endl;
	}

	cout<<"============Transport layer: ICMP====================="<<endl;
	cout<<"--------ICMP types--------"<<endl;
	if(icmpType.begin() == icmpType.end())
	{
	    cout << "No results found for ICMP types" << endl;
	}
	for(itr1 = icmpType.begin(); itr1 != icmpType.end(); itr1++)
	{
		cout << itr1->first << "\t\t\t"<< itr1->second << endl;
	}

	cout<<"--------ICMP codes--------"<<endl;
	if(icmpCode.begin() == icmpCode.end())
	{
	    cout << "No results found for ICMP codes" << endl;
	}
	for(itr1 = icmpCode.begin(); itr1 != icmpCode.end(); itr1++)
	{
		cout << itr1->first << "\t\t\t"<< itr1->second << endl;
	}



}

void usage(FILE *file)
{
	if(file == NULL)
		file = stdout;
	 fprintf(file,
          "wiretap [OPTIONS] file.pcap\n"
          "  --help            			\t Print this help screen\n"
	  "  --open <capture file to open>	\t Opens and parses the given capture file\n");
}



void parse_args(int argc, char **argv)
{

	if(argc < 2)
	{	
		cout << "Error: Incorrect number of arguments" << endl;
		usage(stdout);
		exit(1);
	}
	char ch;
        int option_index = 0;
        static struct option long_options[] =
        {
                {"help", 0, NULL, 'h'},
                {"open", 0, NULL, 'o'},
                { 0, 0, 0, 0 }
        };
        while((ch =  getopt_long(argc, argv, "ho:", long_options, &option_index)) != -1)
        {
                switch(ch)
                {
                        case 'h':
				usage(stdout);
                                break;

                        case 'o':
				openFlag = 1;
				if(argv[optind] == NULL)
				{
					cout << "Please provide the input file name!!!" << endl;
					exit(1);
				}
				
                                pcap_file_name = argv[optind];
                                break;
                        default:

				cout << "Usage:"<< endl;
				usage(stdout);
				exit(1);
                }

        }
	
}
int main(int argc, char **argv)
{

	char errbuf[PCAP_ERRBUF_SIZE]; //Used to hold the error messages returned by the pcap_open_offline()
	int returnValue;
	int datalink = 0;
	u_char *user_arg = NULL;
	FILE *fp;
	
	parse_args(argc, argv);

//If open option is enabled
	if(openFlag == 1)
	{
		fp = fopen(pcap_file_name, "r");
		if(fp == NULL)
		{	
			cout << "File doesn't exist!!"<<endl;
			exit(1);
		}
		
		
		pcap_t * pcap_handle = pcap_fopen_offline(fp, errbuf);
		if(pcap_handle == NULL)
		{
			cout << "Cannot open the file!!";
			exit(1);
		}
	
		datalink = pcap_datalink(pcap_handle);
		if(datalink != (DLT_EN10MB))
		{
			cout << "Not an Ethernet Packet" << endl;
			exit(1);
		}
		
		//Initializing the TCP flags
		initTcpFlags();
	
		//Looping through each packet
		pcap_loop(pcap_handle, -1, packet_parser, user_arg);
	
		print_summary();
		print_info();
		pcap_close(pcap_handle);
	}
	return 0;
}

