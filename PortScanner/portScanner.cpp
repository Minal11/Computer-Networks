/*
Author: Minal Kondawar (mkondawa)
	Saketh Babu Palla (spalla)
Project4:PortScanner


*/

#include<sys/time.h>
#include<queue>
#include<errno.h> 
#include<iostream>
#include<getopt.h>
#include<stdio.h>
#include<sstream>
#include<vector>
#include<set>
#include<map>
#include<math.h>
#include<cstring>
#include<bitset>
#include<pcap/pcap.h>
#include<fstream>
#include<iterator>
#include<algorithm>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<string.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netdb.h>
#include<pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <iomanip>


#define PKT_SIZE 4096
#define SOURCE_PORT 2345
#define IP_HDR_LEN 5
#define IP_VERSION 4
#define IP_HL(ip) (((ip)->ihl) & 0x0f)

#define BUF_LEN 1024


#define SSH 0
#define SMTP 1
#define WHOIS 2
#define HTTP 3
#define POP 4
#define IMAP 5

pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
bool threaded = false;

using namespace std;

typedef struct{
	FILE *ip_fname;
	set<int> ports; //to store all the given ports
	set<string> scans; //to store all the given scan types
	set<string> ip_address; //to store all the ip addresses
	int thread_count;
}ps_args_t;

typedef struct dnshdr{
	unsigned short id; //id
	unsigned char qr; //query/response flag
	unsigned char opcode; // operation code
	unsigned char aa; // Authoritative answer flag
	unsigned char tc; //Truncation flag
	unsigned char rd; //Recursion desired
	unsigned char ra;//Recursion available
	unsigned char z;// Zero (three reserved bits set to zero)
	unsigned char rcode; //Response Code
	unsigned short qdcount; // Question count
	unsigned short ancount; // Answer Record Count
	unsigned short nscount; //Authority Record Count
	unsigned short arcount; //Additional Record Count
}dnshdr_t;

typedef struct dnsquery{
	unsigned short query_type;
	unsigned short query_class;
}dnsquery_t;


struct pseudo_header
{
	u_int32_t src;          /* 32bit source ip address*/
	u_int32_t dst;          /* 32bit destination ip address */	
	u_char mbz;             /* 8 reserved bits (all 0) 	*/
	u_char proto;           /* protocol field of ip header */
	u_int16_t len;          /* tcp length (both header and data */

	struct tcphdr tcph;
};
struct pseudo_header_udp
{
	u_int32_t src;          /* 32bit source ip address*/
	u_int32_t dst;          /* 32bit destination ip address */	
	u_char mbz;             /* 8 reserved bits (all 0) 	*/
	u_char proto;           /* protocol field of ip header */
	u_int16_t len;          /* tcp length (both header and data */
 
	struct udphdr udph;
};

struct service_ver{
	char ip[INET_ADDRSTRLEN];
	char version[6][50];
	struct service_ver *next;
};

typedef struct tasks
{
	string ip;
	int port;
	string scan;
}task;
typedef struct scan_res
{
        string scan;
        string res;
}scan_res_t;

typedef struct port_res
{
        string serv_name;
        vector<scan_res_t> results;
        string conclusion;
}port_res_t;

typedef map<int, port_res_t> map1;
map1 ip_res;

map<string, map1> output;

queue<task> task_queue;

set<string>::iterator itr_s; //iterator to iterate over string
set<int>::iterator itr; //iterator to iterate over int
set<string>::iterator itr_s1;
int scan_count = 6;//default value for scan_count = Total number of scan types

char source_ip[20]; //source ip of local machine
struct service_ver *sv_mainlist= NULL;
int service_ports[6] = {22,24,43,80,110,143}; //List of port numbers for which service detetcion is needed

int progress_bar = 0;
//function to check for valid ip

void display_progress()
{
        if(progress_bar != 5)
        {
                cout << ".";
        }
        else
        {
                cout.flush();
        }
}


int valid_ip_add(string ipAdd)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAdd.c_str(), &(sa.sin_addr));
    return result;            

}

/*
 * function to draw conclusion from the list of results of various scans
 *
 * We interpreted the priority order as follows
 *  
 *  Open > Closed > Filtered > Open|Filtered > Unfiltered
 *
 */
string draw_conclusion(vector<scan_res_t> results)
{
        string scan_result;
        int open_count = 0;
        int filtered_count = 0;
        int open_filt_count = 0;
        int closed_count = 0;
        int unfiltered_count = 0;
        int max;
        string conlusion;
        for(int i = 0; i < results.size(); i++)
        {
                scan_result = results[i].res;
                if(scan_result.compare("Open") == 0)
                        open_count++;
                else if(scan_result.compare("Closed") == 0)
                        closed_count++;
                else if(scan_result.compare("Filtered") == 0)
                        filtered_count++;
                else if(scan_result.compare("Unfiltered") == 0)
                        unfiltered_count++;
                else if(scan_result.compare("Open|Filtered") == 0)
                        open_filt_count++;
        }

        if(open_count >= 1)
        {
                return "Open";
        }
        else if(closed_count >= 1)
        {
                return "Closed";
        }
        else if(filtered_count >= 1)
        {
                return "Filtered";
        }
        else if(open_filt_count >= 1)
        {
                return "Open|Filtered";
        }
	 else
        {
                return "Unfiltered";
        }

}


//function to print the final results
void print_results()
{
	map1::iterator itr_ip_res; 
	map<string, map1>::iterator itr_output;
	port_res_t pr2;
        vector<scan_res> results2;
        scan_res_t sr2;


	for(itr_output = output.begin(); itr_output != output.end(); itr_output++)
        {
                cout << "Ip Address: " << itr_output->first << endl;
                cout << "Port \t\t\t Service Name (if applicable) \t\t\tResults\t\t\t\t\t\tConclusion" << endl;
/*              for(int i = 0; i < 2 * scan_count; i++)
                {
                        cout << "\t";
                }

                cout << "Conclusion" << endl;
*/
                cout << "------------------------------------------------------------------------------------------------------------------------------" << endl;
                for(itr_ip_res = (itr_output->second).begin(); itr_ip_res != (itr_output->second).end(); itr_ip_res++)
                {
                        cout << itr_ip_res->first << "\t\t";
                        pr2 = itr_ip_res->second; //Storing the results of the current port in port_res_t structure
			cout << pr2.serv_name << "\t\t"; //printing the service name of the current port if applicable
                        results2 = pr2.results;
                        for(int j = 0; j < results2.size(); j++)
                        {
                                sr2 = results2[j];
                                cout << sr2.scan << "(" << sr2.res << ")" << "\t";
                        }
                        cout << draw_conclusion(results2) << endl; //printing the conclusion status of the current port
		}

        }

}


//function to print the service version
void print_service_version()
{
	
	struct service_ver *res = sv_mainlist;

	if(res == NULL)
	{
		cout<<"No service verification required for the given ports!!"<<endl;
	
	}
	else
	{
		cout<<"Service Verification"<<endl;
		
		while(res)
		{
			cout<<"IP address: "<<res->ip<<endl;
			cout<<"---------------------------------------"<<endl;
			cout<<"Port"<<"\t\t"<<"Version"<<endl;
			cout<<"---------------------------------------"<<endl;
		
			for(int i=0;i<6;i++)
			{
				if (strlen(res->version[i]) != 0)
					cout<<service_ports[i]<<"\t\t"<<std::right<<res->version[i]<<endl;
			}
			cout<<"---------------------------------------"<<endl;
		
			res = res->next;
		}
	}
}

void destroy_service()
{
	struct service_ver *node = NULL;
	struct service_ver *prev_node = NULL;
	node = sv_mainlist;
	sv_mainlist = NULL;

	while(node != NULL)
	{
		prev_node = node;
		node = node->next;
		free(prev_node);
	}
}

int send_data(int sockfd, char *buff, int len)
{	
		char *data = buff;
		int bytes_sent = 0;
		int total_bytes_sent = 0;
		int bytes_to_send = len;

	
		while (bytes_to_send > 0)
		{
			bytes_sent = write(sockfd, data, bytes_to_send);
			if (bytes_sent > 0)
			{
				
				total_bytes_sent += bytes_sent;
				bytes_to_send -= bytes_sent;
				data += bytes_sent;
			}
			else
			{
				perror("Sending data failed!!");
				return 1;
			}
		}

	return 0;

}


//Receive data from the socket and return 0/1 status
int recv_data(int sockfd, char *data, int no_bytes)
{
	void *recvbuffer = data;

	int bytesRead = 0;
	bytesRead = recv(sockfd, recvbuffer, no_bytes, 0);
	if (bytesRead < 0)
	{
		cout<<"reading failed"<<endl;
		return 1;
	}
	else if (bytesRead == 0)
	{
		cout<<"No data "<<sockfd;
		return 1;
	}
		
	return 0;
}


void insert_to_list(struct service_ver *list, int pos)
{
	struct service_ver *temp = NULL;
	struct service_ver *result = sv_mainlist;

	while(result)
	{
		if((strcmp(result->ip,list->ip) == 0))
			break;
		result= result->next;
	}

	if(result == NULL)
	{
		temp = (struct service_ver *)malloc(sizeof(struct service_ver));
		memcpy(temp->ip,list->ip,INET_ADDRSTRLEN);
		for(int i=0;i<6;i++)
			bzero(temp->version[i],50);
		temp->next = sv_mainlist;
		sv_mainlist = temp;
	}
	else
		temp = result;
	
	memcpy(temp->version[pos],list->version[pos],50);
	free(list);
}


int check_for_services(const char * dest_ipaddr, int port_no)
{
	
	char *recvbuffer=NULL;
	recvbuffer=(char *)malloc(400);
	bzero(recvbuffer,400);

	struct service_ver *curr=NULL;
	curr=(struct service_ver *)malloc(sizeof(struct service_ver));
	memcpy(curr->ip,dest_ipaddr,INET_ADDRSTRLEN);
	curr->next=NULL;
	
	int sockfd;
	struct sockaddr_in destaddr;
	struct hostent *hostinfo;
	if((sockfd=socket(AF_INET,SOCK_STREAM,0))<0)
	{
		perror("Socket creation failed");
		return 0;
	}
	if(!(hostinfo = gethostbyname(dest_ipaddr)))
	{
		fprintf(stderr,"Invalid host name %s",dest_ipaddr);
		return 0;
	}

	destaddr.sin_family = hostinfo->h_addrtype; //AF_INET
	bcopy((char *) hostinfo->h_addr,(char *) &(destaddr.sin_addr.s_addr),hostinfo->h_length);
   	destaddr.sin_port = htons(port_no);

	if (connect(sockfd,(struct sockaddr *)&destaddr,sizeof(destaddr)) < 0)
	{
		
		for(int i=0;i<6;i++)
		{
			if(service_ports[i] == port_no)
			{
				strcpy(curr->version[i],"Unknown");
				insert_to_list(curr,i);
				return 0;
					
			}		 
		}
		return 0;			
	}

	char *token=NULL;
	char *buff=NULL;
	char *ptr=NULL;
	int i;
	char version[6][50];
	char datasend[BUF_LEN];
	strcpy(datasend,"HEAD / HTTP/1.1\r\n\r\n");
	char data_to_send[10];
	strcpy(data_to_send,"portscan");
	
	switch(port_no)
	{

		case 22:
			{
				if(recv_data(sockfd, recvbuffer, 250) == 1)
				{
					free(recvbuffer);
					return 0;
				}
					
				for (i=0;i<=(strlen((char *)recvbuffer));i++)
				{
					if (recvbuffer[i] == '\n')
						break;
					version[SSH][i] = recvbuffer[i]; //ssh 0
			    	}
				version[SSH][i] = '\0';
				  
				strcpy(curr->version[SSH],version[SSH]);
				insert_to_list(curr,SSH);
			}		  
			break;
		case 24:
			{
				if(recv_data(sockfd, recvbuffer, 250) == 1)
				{
					free(recvbuffer);
					return 0;
				}
				buff=recvbuffer;
				
				if(strlen(buff)>0)
				{
					token=strtok(buff," ");
					if(token!=NULL)
					{
						token=strtok(NULL," ");
						if(token!=NULL)
						{
					//		strcat(version[1],token); //case2
					//		strcat(version[1]," ");
							token=strtok(NULL," ");
							if(token!=NULL)
							{
								
								strcat(version[SMTP],token); //stmp
								strcat(version[SMTP]," ");  //case3 
								token=strtok(NULL," ");
								if(token!=NULL)
								{
									strcat(version[SMTP],token);
									strcat(version[SMTP]," "); //case 4
									token=strtok(NULL," ");
									if(token!=NULL)
									{
										strcat(version[SMTP],token);
										strcat(version[SMTP]," ");
										token=strtok(NULL," ");
										if(token!=NULL)
										{

											strcat(version[SMTP],token);

										}
									}
								}
						
							}	
						}
					}


				}
				else
					strcpy(version[SMTP],"Unknown");
				strcpy(curr->version[SMTP],version[SMTP]);
				insert_to_list(curr,SMTP);
	
			}
			break;
		case 43:
			{
				
				if (send_data(sockfd,data_to_send,10) == 1) 
					return 0;
				if (recv_data(sockfd, recvbuffer, 250) == 1)
				{
					free(recvbuffer);
					return 0;
				}
				ptr = strstr(recvbuffer, "Server Version");
				
				if (ptr == NULL)
				 {
					cout<<"String not found"<<endl;
	    	                 }
				 else	
				 {
					ptr += 15;
				
					for (i=0;i<=(strlen(ptr));i++)
					{
					    if (ptr[i] == '\n') 
						break;
					    version[WHOIS][i] = ptr[i]; //whois 2
					     
					}
					version[WHOIS][i] = '\0';
				
				  }
				  strcpy(curr->version[WHOIS],version[WHOIS]);
				  insert_to_list(curr,WHOIS);
			}
			break;
		case 80:
			{
				
				
				if (send_data(sockfd,datasend,strlen(datasend))==1)
				{
					cout<<"send failed"<<endl;
					 return 0;
				}
				if (recv_data(sockfd, recvbuffer, 250) == 1)
				{
					cout<<"recieved failed"<<endl;
					free(recvbuffer);
					return 0;
				}
					
				
				ptr = strstr(recvbuffer, "Server");
				if (ptr == NULL)
				{
				   cout<<"No Http server name string "<<endl;
				}
				else	
				{
					
				 	ptr += 8;
					for (i=0;i<=(strlen(ptr));i++)
					{
						if (ptr[i] == '\n')
							 break;
						version[HTTP][i] = ptr[i];
					}
					version[HTTP][i] = '\0'; //http=3
				 }
				strcpy(curr->version[HTTP],version[HTTP]);
				insert_to_list(curr,HTTP);
			}
			
			break;
		case 110:
			{
				if (recv_data(sockfd, recvbuffer, 250) == 1)
				{
					free(recvbuffer);
					return 0;
				}
				
				buff = recvbuffer;
						
				if(strlen(buff)>0)
				{
					token=strtok(buff," ");
					if(token!=NULL)
					{
							token=strtok(NULL," ");
							if(token!=NULL)
							{
								strcpy(version[POP],token);
							
							}
					}
			
				}
			
				strcpy(curr->version[POP],version[POP]);
				insert_to_list(curr,POP);
			}
			break;
		case 143:
			{
				if (recv_data(sockfd, recvbuffer, 250) == 1)
				{
					free(recvbuffer);
					return 0;
				}
				
				char *temp = (char *)malloc(strlen(recvbuffer));
				memcpy(temp,recvbuffer,strlen(recvbuffer));
			
				
				strcpy(version[IMAP],"Version:");
				if(strlen(recvbuffer)>0)
				{
					token=strtok(temp," ");
					if(token!=NULL)
					{
						token=strtok(NULL," ");
						if(token!=NULL)
						{
							token=strtok(NULL," ");
							if(token!=NULL)
							{
								token=strtok(NULL," ");
								if(token!=NULL)
								{
									strcat(version[IMAP],token); //imap=5
									
									
								}
							}
						}
					}
				}
			
				strcpy(curr->version[IMAP],version[IMAP]);
				insert_to_list(curr,IMAP);

				free(temp);
			}
			break;
		defualt:
			break;
	}
	free(recvbuffer);
	close(sockfd);
	return 1;
		
}

unsigned short CheckSum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size)
        cksum += *(unsigned char *)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}


string packet_parser2(const u_char *pkt, string scan_type, const char *dest_ipaddr, int dest_port)
{
	string dest_ip(dest_ipaddr);
	string result_from_scan;

	struct ethhdr *e = (struct ethhdr *)pkt;
        struct iphdr *iph = (struct iphdr *)(pkt+14);
        int iph_size;
	iph_size =  IP_HL(iph)*4;

	if(dest_port<=1024)
	{
		struct servent *serv_name;
		short nport = htons(dest_port); 

	  	/* get the service record */
	  	
		if(scan_type.compare("UDP")==0)
		{
			
			if(threaded)
				pthread_mutex_lock(&thread_mutex);
			serv_name = getservbyport(nport,"UDP");			
			if(serv_name!=NULL)	
				output[dest_ip][dest_port].serv_name.assign(serv_name->s_name);
			else
				output[dest_ip][dest_port].serv_name = "Unassigned";
			if(threaded)
				pthread_mutex_unlock(&thread_mutex);
		}
		else
		{
			
			if(threaded)
				pthread_mutex_lock(&thread_mutex);
			serv_name = getservbyport(nport,"TCP");			
			if(serv_name!=NULL)
			{
				char *tmp_src=serv_name->s_name;
				output[dest_ip][dest_port].serv_name.assign(serv_name->s_name);
			}			
			else
			{
				output[dest_ip][dest_port].serv_name = "Unassigned";
			}
			if(threaded)
				pthread_mutex_unlock(&thread_mutex);
		}
	}
	else
	{
		if(threaded)
				pthread_mutex_lock(&thread_mutex);
		output[dest_ip][dest_port].serv_name = "Unknown";
		if(threaded)
				pthread_mutex_unlock(&thread_mutex);
	}
        if(scan_type.compare("SYN")==0)
	{
	      	struct tcphdr *tcp_h = (struct tcphdr *)(pkt+14+iph_size); //size of ethernet = 14
		
		if(pkt == NULL)
		{	
			result_from_scan = "Filtered";
		}
		else
		{
			if(((*tcp_h).syn && (*tcp_h).ack) || (*tcp_h).syn ) //rare case
			{
				result_from_scan = "Open";
				if(dest_port==22 || dest_port==24 || dest_port==43 || dest_port==80 || dest_port==110 || dest_port==143) 
					check_for_services((char *)dest_ipaddr,dest_port);
			}
			else if((*tcp_h).rst)
			{
				result_from_scan = "Closed";
			}
			else
			{
				if(iph->protocol==1)
				{
					struct icmphdr *icmph=(struct icmphdr*)(pkt+14+iph_size);
					if((icmph->type==3) && (icmph->code==1 || icmph->code==2 || icmph->code==3 || icmph->code==9 || icmph->code==10 || icmph->code==13))
					{
						result_from_scan = "Filtered";
					}

				}
				else
				{
					result_from_scan = "Unfiltered";
				}
			}
		}
		
	}
	if(scan_type.compare("FIN")==0 || scan_type.compare("NULL")==0 || scan_type.compare("Xmas")==0)
	{
		if(pkt == NULL)
		{
			result_from_scan = "Open|Filtered";
			if(dest_port==22 || dest_port==24 || dest_port==43 || dest_port==80 || dest_port==110 || dest_port==143) 
					check_for_services((char *)dest_ipaddr,dest_port);
		}
		else
		{
			struct tcphdr *tcp_h = (struct tcphdr *)(pkt+14+iph_size);
			if((*tcp_h).rst)
			{
				result_from_scan = "Closed";
			}
			else
			{
				if(iph->protocol==1)
				{
					struct icmphdr *icmph=(struct icmphdr*)(pkt+14+iph_size);
					if((icmph->type==3) && (icmph->code==1 || icmph->code==2 || icmph->code==3 || icmph->code==9 || icmph->code==10 || icmph->code==13))		{
//						cout<<"icmp error code"<<endl;
						result_from_scan = "Filtered";
					}
				}
				else
				{
					result_from_scan = "Unfiltered";
				}
			}
		}

	}
	
	if(scan_type.compare("ACK")==0)
	{
		if(pkt == NULL)
		{	
			result_from_scan = "Filtered";
		}
		else
		{
			struct tcphdr *tcp_h = (struct tcphdr *)(pkt+14+iph_size);
			if((*tcp_h).rst)
			{
				result_from_scan = "Unfiltered";
			}
			else
			{
				if(iph->protocol==1)
				{
					struct icmphdr *icmph=(struct icmphdr*)(pkt+14+iph_size);
					if((icmph->type==3) && (icmph->code==1 || icmph->code==2 || icmph->code==3 || icmph->code==9 || icmph->code==10 || icmph->code==13))
					{
						result_from_scan = "Filtered";
					}
				}
				else
				{
					result_from_scan = "Unfiltered";
				}
			}


		}

	}
	if(scan_type.compare("UDP")==0)
	{
		if(pkt==NULL)
		{
			result_from_scan = "Open|Filtered";
			if(dest_port==22 || dest_port==24 || dest_port==43 || dest_port==80 || dest_port==110 || dest_port==143) 
					check_for_services(dest_ipaddr,dest_port);
		}

		if(iph->protocol==17)
		{
			result_from_scan = "Open";
			if(dest_port==22 || dest_port==24 || dest_port==43 || dest_port==80 || dest_port==110 || dest_port==143) 
					check_for_services(dest_ipaddr,dest_port);
			
		}
		else if(iph->protocol==1)
		{
			struct icmphdr *icmph=(struct icmphdr*)(pkt+14+iph_size);
			if((icmph->type==3) && (icmph->code==3))
			{
				result_from_scan = "Closed";
			}
			else if((icmph->type==3) && (icmph->code==1 || icmph->code==2  || icmph->code==9 || icmph->code==10 || icmph->code==13))
			{
				result_from_scan = "Filtered";
			}
			else
			{
				result_from_scan = "Unfiltered";
			}	
		}
		

	}
	return result_from_scan;
}
int do_tcp_scan(const char *dest_ipaddr, int dest_port,  string scan_type, int source_port)
{
	string dest_ip(dest_ipaddr);
	scan_res_t curr_scan_res;
	curr_scan_res.scan = scan_type;
	string result_from_scan;	

	char buf[PKT_SIZE];
	int sockfd;
	struct tcphdr *tcph;
	struct sockaddr_in destaddr;
	destaddr.sin_family = AF_INET;
	destaddr.sin_port = htons(dest_port);
	destaddr.sin_addr.s_addr = inet_addr(dest_ipaddr); 
	memset(buf,0,PKT_SIZE);
	struct iphdr* iph=(struct iphdr *)buf;
	iph->ihl = IP_HDR_LEN;
	iph->version = IP_VERSION;
	iph -> tos = 0;
	iph -> tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph -> id = htons(34644);
	iph -> frag_off = 0;
	iph -> ttl = 128;
	iph -> protocol = IPPROTO_TCP;
	iph -> check = 0;
	iph -> saddr = inet_addr (source_ip);	
	iph -> daddr = destaddr.sin_addr.s_addr;
	
		
	tcph = (struct tcphdr *) ( buf + sizeof( struct ip ));
	tcph->source = htons(source_port);
        tcph->dest = htons(dest_port);
        srand(time(NULL));
        tcph->seq = htonl(12);
	tcph->ack_seq =0;
        tcph->window = htons(14600);
        tcph -> check = 0;
        tcph -> urg_ptr = 0;
	tcph -> doff = sizeof(struct tcphdr) / 4;
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->ack = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->urg = 0;
	if(scan_type == "SYN")
	{
		tcph->syn = 1;
	}
	else if(scan_type == "ACK")
	{
		tcph->ack = 1;
	}
	else if(scan_type == "FIN")
	{
		tcph->fin = 1;
	}
	else if(scan_type == "Xmas")
	{
		tcph->fin = 1;
		tcph->psh = 1;
		tcph->urg = 1;
	}
	else if(scan_type == "NULL")
	{
		//do nothing..all the flags are already reset above
	}
	// fill pseudo header
	struct pseudo_header pseudohead;
	
	bzero((void *) &pseudohead, sizeof(struct pseudo_header));

	pseudohead.src    = inet_addr(source_ip);	
	pseudohead.dst    = destaddr.sin_addr.s_addr;
	pseudohead.mbz    =  0;
	pseudohead.proto  = IPPROTO_TCP;
	pseudohead.len =  htons(sizeof(struct tcphdr));
	memcpy(&pseudohead.tcph,tcph,sizeof(struct tcphdr));
	tcph->check = CheckSum((unsigned short *) &pseudohead, sizeof(struct pseudo_header));
	
	//creating raw_socket
	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) 
	{
		perror("TCP SCAN: Socket creation error");
		return -1;
	}
	int opt_val = 1;
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, &opt_val, sizeof(opt_val)) < 0)
	{
		perror("setsockopt failed!");
		return -1;
	}
	

	char errbuf[PCAP_ERRBUF_SIZE]; //Used to hold the error messages returned by the pcap_open_offline()
        int returnValue;
	u_char *user_arg = NULL;
//	char *device = "eth0";
	char *device;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if(threaded)
		pthread_mutex_lock(&thread_mutex);
	device = pcap_lookupdev(errbuf);

	if(device == NULL)
	{
		cout << "Couldn't find the default device " << errbuf << endl;
		return -1;
	}
//	cout << "device found successfully = " << device << endl;
	pcap_pkthdr *pcap_header = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr));

	pcap_t *pcap_handle = pcap_open_live(device, BUFSIZ, 0, 10000, errbuf);//pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
	if(pcap_handle ==  NULL)
	{
		printf("Error opening the device %s: %s\n", device, errbuf);
		pcap_header = NULL;
		free(pcap_header);
		if(threaded)
			pthread_mutex_unlock(&thread_mutex);
		return -1;
	}
	char *filter_str;
	filter_str=(char *)malloc(sizeof(char *)*4096);
	memset(filter_str, 0, sizeof(filter_str)*4096);
	sprintf(filter_str," src host %s and dst host %s and tcp port %d ", dest_ipaddr,source_ip, dest_port);
	
	struct bpf_program filter;
	if(pcap_compile(pcap_handle, &filter, filter_str, 0, 0) == -1)
	{

		perror("pcap compile failed");
		pcap_header = NULL;
		free(pcap_header);
		pcap_close(pcap_handle);
		if(threaded)
			pthread_mutex_unlock(&thread_mutex);
		return -1;
	}
	if(pcap_setfilter(pcap_handle, &filter) == -1)
	{
		perror("pcap setfilter failed");
		pcap_header = NULL;
                free(pcap_header);
		pcap_close(pcap_handle);
		if(threaded)
			pthread_mutex_unlock(&thread_mutex);
                return -1;

	}
	if(threaded)
		pthread_mutex_unlock(&thread_mutex);
	int retcode;
	
        if(retcode=sendto(sockfd, buf, sizeof(struct ip) + sizeof(struct tcphdr),0,(struct sockaddr*)&destaddr, sizeof(destaddr)) < 0)
        {
                perror("Unsuccessful send");
		pcap_header = NULL;
                free(pcap_header);
                pcap_close(pcap_handle);
		close(sockfd);
                return -1;
        }
	const u_char* pkt_resp;
	int pcap_ret_val;
	int attempt = 3;
	while((pcap_ret_val = pcap_next_ex(pcap_handle,&pcap_header,&pkt_resp)) >= 0)
	{
		if(pcap_ret_val == 0)
		{
			if(attempt > 0)
			{
				attempt--;
//				cout<<"No response received for " <<  dest_ip << " at " << dest_port << " with " << scan_type << ". Retrying....Attempt "<<attempt<<endl;
				continue;
			}
			else
			{
//				cout << "no response";
				result_from_scan = "Open|Filtered";
				struct servent *serv_name;
				short nport = htons(dest_port); 

				
				if(threaded)
					pthread_mutex_lock(&thread_mutex);
				serv_name = getservbyport(nport, "TCP");
				if(serv_name!=NULL)
				{	
					output[dest_ip][dest_port].serv_name.assign(serv_name->s_name);
				}
				else
					output[dest_ip][dest_port].serv_name = "Unassigned";
				if(threaded)
					pthread_mutex_unlock(&thread_mutex);
				break;
			}
		}
		else
		{
			result_from_scan = packet_parser2(pkt_resp, scan_type,dest_ipaddr, dest_port);
			break;
		}
	}

	curr_scan_res.res = result_from_scan;
	if(threaded)
		pthread_mutex_lock(&thread_mutex);
	output[dest_ip][dest_port].results.push_back(curr_scan_res);
	if(threaded)
		pthread_mutex_unlock(&thread_mutex);
	free(filter_str);
	pcap_close(pcap_handle);
	close(sockfd);
	return 1;

}



int do_udp_scan(const char *dest_ipaddr, int dest_port, string scan_type, int source_port)
{
	string dest_ip(dest_ipaddr);
	scan_res_t curr_scan_res;
	curr_scan_res.scan = scan_type;
	string result_from_scan;

	char buf[PKT_SIZE];
	int sockfd;
	struct sockaddr_in destaddr;
	destaddr.sin_family = AF_INET;
	destaddr.sin_port = htons(dest_port);
	destaddr.sin_addr.s_addr = inet_addr(dest_ipaddr); 
	
	//creating raw_socket

	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
	{

		perror("UDP SCAN: Socket creation error");
		return -1;
	}
	int opt_val = 1;
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, &opt_val, sizeof(opt_val)) < 0)
	{
		perror("setsockopt failed!");
		close(sockfd);
		return -1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	int returnValue;
	u_char *user_arg = NULL;
//	char *device = "eth0";
	char *device;
	if(threaded)
		pthread_mutex_lock(&thread_mutex);
	device = pcap_lookupdev(errbuf);
	if (device == NULL) 
	{
		cout <<  "Couldn't find default device" <<  errbuf << endl;
		return -1;
	}

//	cout << "device found successfully = " << device << endl;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	pcap_pkthdr *pcap_header = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr));


	pcap_t *pcap_handle = pcap_open_live(device, BUFSIZ, 0, 10000, errbuf);//pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
	if(pcap_handle ==  NULL)
	{
		printf("Error opening the device %s: %s\n", device, errbuf);
		close(sockfd);
		if(threaded)
			pthread_mutex_unlock(&thread_mutex);
		return -1;
	}
	char *filter_str;
	filter_str = (char *)malloc(sizeof(char *) * 4096);
	memset(filter_str, 0, sizeof(char *) * 4096);
	sprintf(filter_str,"src host %s and dst host %s and  udp port %d or ip proto \\icmp",dest_ipaddr, source_ip, dest_port);
	struct bpf_program filter;
	if(pcap_compile(pcap_handle, &filter, filter_str, 0, 0) == -1)
	{
		perror("pcap compile failed");
		pcap_header = NULL;
		free(pcap_header);
		pcap_close(pcap_handle);
		close(sockfd);
		if(threaded)
			pthread_mutex_unlock(&thread_mutex);
		return -1;
	}
	if(pcap_setfilter(pcap_handle, &filter) == -1)
	{
		perror("pcap setfilter failed");
		pcap_header = NULL;
                free(pcap_header);
		pcap_close(pcap_handle);
		close(sockfd);
		if(threaded)
			pthread_mutex_unlock(&thread_mutex);
		return -1;
	}
	if(threaded)
		pthread_mutex_unlock(&thread_mutex);

	memset(buf,0,PKT_SIZE);
	struct iphdr* iph=(struct iphdr *)buf;
	iph->ihl = IP_HDR_LEN;
	iph->version = IP_VERSION;
	iph -> tos = 0;
	iph -> id = htons(34643);
	iph -> frag_off = 0;
	iph -> ttl = 128;
	iph -> protocol = IPPROTO_UDP;
	iph -> check = 0;
	iph -> saddr = inet_addr (source_ip);	
	iph -> daddr = destaddr.sin_addr.s_addr;
	

	 struct udphdr* udph = (struct udphdr *) (buf + sizeof( struct ip));
         udph->source = htons(source_port);
         udph->dest = htons(dest_port);
         udph->check = htons(0);

	if(dest_port == 53)
	{
		unsigned char *query_name;

		//Filling the dns header
		dnshdr_t *dnsh = (struct dnshdr *)(buf + sizeof(struct ip) + sizeof(struct udphdr));
		dnsh->id = htons(1234); //random id
		dnsh->qr = 0;//query flag
		dnsh->opcode = 0; //standard query
		dnsh->aa = 0; //server is not authoritative 
		dnsh->tc = 0;// Message is not truncated
		dnsh->rd = 1; //Recursion is desired
		dnsh->ra = 0; //(Recursion Available) To be set by the server in the response
		dnsh->z = 0; //Zero
		dnsh->rcode = 0;//Response code
		dnsh->qdcount = htons(1); //Question count;
		dnsh->ancount = 0; //Answer Record count
		dnsh->nscount = 0; //Authority Record count
		dnsh->arcount = 0; //Additional record count

		unsigned char *host = (unsigned char *)"www.google.com";
		query_name = (unsigned char *)(buf + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dnshdr));
		iph -> tot_len = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dnshdr) + (strlen((const char*) query_name) + 1)+ sizeof(struct dnsquery);
		udph->len = htons(sizeof(struct udphdr) + sizeof(struct dnshdr)+ (strlen((const char*) query_name) + 1) + sizeof(struct dnsquery));
		strcpy((char *)query_name, (char *)host);
		//Preparing DNS query structure with the payload
		dnsquery_t *dnsq = (struct dnsquery *)(buf + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dnshdr) + (strlen((const char *)query_name) + 1));
		dnsq->query_type= htons(1); //IPv4 address
		dnsq->query_class = htons(1); //Internet
		
		if(sendto(sockfd, buf, sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dnshdr) + (strlen((const char *)query_name) + 1) + sizeof(struct dnsquery), 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) < 0)
		{
			cout << "Sending DNS packet failed" << endl;
			pcap_header = NULL;
	                free(pcap_header);
			pcap_close(pcap_handle);
			close(sockfd);
			return -1;
		}
	}
	if(dest_port!=53)
	{		

		iph -> tot_len  = sizeof(struct ip) + sizeof(struct udphdr);
		udph -> len = htons(sizeof(udphdr));
	
		int retcode;
		if(retcode=sendto(sockfd, buf, sizeof(struct ip) + sizeof(struct udphdr),0,(struct sockaddr*)&destaddr, sizeof(destaddr)) < 0)
		{
		        perror("Unsuccessful send for non-DNS ports in UDP scan");
			pcap_header = NULL;
	                free(pcap_header);
			pcap_close(pcap_handle);
			close(sockfd);
		        return -1;
		}
	}
	int n;
	const u_char* pkt_resp;
	int pcap_ret_value;
	int attempt = 3;
	while((pcap_ret_value = pcap_next_ex(pcap_handle,&pcap_header,&pkt_resp)) >= 0)
	{
	
		if(pcap_ret_value == 0)
		{	
			if(attempt > 0)
			{
				attempt--;
//				cout<<"No response received for " <<  dest_ip << " at " << dest_port << " with " << scan_type << ". Retrying....Attempt "<<attempt<<endl;
				continue;
			}
			else
			{
//				cout << "no response"<<endl;
				result_from_scan = "Open|Filtered";
				struct servent *serv_name;
				short nport = htons(dest_port); 
				if(threaded)
					pthread_mutex_lock(&thread_mutex);
	  	
				serv_name = getservbyport(nport,"UDP");
				if(serv_name!=NULL)	
					output[dest_ip][dest_port].serv_name.assign(serv_name->s_name);
				else
					output[dest_ip][dest_port].serv_name = "Unassigned";
				if(threaded)
					pthread_mutex_unlock(&thread_mutex);
				break;
			}
			
		}
		else
		{
				result_from_scan = packet_parser2(pkt_resp, scan_type, dest_ipaddr, dest_port);
				break;
		}
        }
	
	
	curr_scan_res.res = result_from_scan;
	if(threaded)
		pthread_mutex_lock(&thread_mutex);
	output[dest_ip][dest_port].results.push_back(curr_scan_res);
	if(threaded)
		pthread_mutex_unlock(&thread_mutex);
	
	free(filter_str);
	pcap_header = NULL;
	free(pcap_header);
	pcap_close(pcap_handle);
	close(sockfd);
	return 1;
}

void *process_task_queue(void* thread_args)
{
	int thread_id= *((int *)thread_args);
	int thread_portno;
	bool is_empty = false;
	
	pthread_mutex_lock(&thread_mutex);
	thread_portno = SOURCE_PORT + thread_id;
	pthread_mutex_unlock(&thread_mutex);

	pthread_mutex_lock(&thread_mutex);
	is_empty = task_queue.empty();
	pthread_mutex_unlock(&thread_mutex);

	while(!is_empty)
	{
		pthread_mutex_lock(&thread_mutex);
		task tmp = task_queue.front();
		task_queue.pop();
		pthread_mutex_unlock(&thread_mutex);
		if(((tmp.scan).compare("SYN")==0)||((tmp.scan).compare("FIN")==0)||((tmp.scan).compare("ACK")==0)||((tmp.scan).compare("Xmas")==0)||((tmp.scan).compare("NULL")==0))
		{
			if((do_tcp_scan((tmp.ip).c_str(),tmp.port,tmp.scan, thread_portno)) == -1)
			{
				cout << "Error processing current task. Moving to next task...." << endl;
			}
			pthread_mutex_lock(&thread_mutex);
 			progress_bar++;
 			display_progress();
 			pthread_mutex_unlock(&thread_mutex);
		}
		else if((tmp.scan).compare("UDP")==0)
		{
			if((do_udp_scan((tmp.ip).c_str(),tmp.port,tmp.scan, thread_portno)) == -1)
			{
				cout << "Error processing current task. Moving onto next task..." << endl;
			}
			pthread_mutex_lock(&thread_mutex);
 			progress_bar++;
 			display_progress();
 			pthread_mutex_unlock(&thread_mutex);
		}
		else
		{
			cout << "Invalid Scan " << endl;
			//do nothing
		}	
		
		pthread_mutex_lock(&thread_mutex);
	        is_empty = task_queue.empty();
	        pthread_mutex_unlock(&thread_mutex);
	}
	cout.flush();
	pthread_exit(NULL);
	
}


void usage(FILE * file){
	if(file == NULL){
		file = stdout;
  	}

  	fprintf(file,
          "./portScanner [OPTIONS]\n"
          "  --help            					\t Print this help screen\n"
          "  --ports<ports to scan>				\t Example: \"./portScanner --ports 1,2,3-5\"\n"
          "  --ip<IP address to scan>				\t Example: \"./portScanner --ip 127.0.0.1\"\n"
	  "  --prefix<IP prefix to scan>			\t Example: \"./portScanner --prefix 127.143.151.123/24\"\n"
	  "  --file<file name containing IP addresses to scan>	\t Example: \"./portScanner --file filename.txt\"\n"
	  "  --speedup<parallel threads to use>			\t Example: \"./portScanner --speedup 10\"\n"
	  "  --scan<one or more scans>				\t Example: \"./portScanner --scan SYN NULL FIN XMAS\"\n"
	);
}

//function to parse the ports
void parse_ports(char *ports_args, ps_args_t *ps_args)
{

	string str(ports_args);
	stringstream ss(str);
	string token;
	int dash_pos;
	int first_port, last_port; //Used when the ports are given in range format
	int port;
	set<int>::iterator itr;
	//Allocating memory for ps_args struct
	while(getline(ss, token, ','))
	{
		dash_pos = token.find('-');
		if(dash_pos != string::npos) //Range of port numbers are given
		{
			stringstream(token.substr(0,dash_pos)) >> first_port;
			stringstream(token.substr(dash_pos+1)) >> last_port;
			while(first_port <= last_port)
			{
				port = first_port++;
				ps_args->ports.insert(port);
			}
		}
		else //Individual Port numbers are given
		{
			stringstream(token) >> port;
			ps_args->ports.insert(port);
		}
	}
	//printing the port numbers stored in ps_args->ports set using iterator
/*	for(itr = ps_args->ports.begin(); itr != ps_args->ports.end(); itr++)
	{
		cout << *itr << endl;
	}
*/
}

//function to print address

void print_addr(int addr_array[],ps_args_t *ps_args)
{
	stringstream iss;
	for(int i = 0; i < 4; i++)
	{
		iss << addr_array[i];
                if(i < 3) //Not appending . at the end of the string
                {
			iss<<".";
                }

	}
	ps_args->ip_address.insert(iss.str());

}

//function to print all ip address calculated from prefix
/*
	* Step 1) Here,we are incrementing each octet(starting from lower most octet) of the first_ip_addr until we either reach last_ip_addr or 255(the maximum value).
	*
	* Step 2) For any octet, "once we reach 255", we check for the previous octet value if it matches with that of last_ip_addr. If they don't match, we would repeat the above process
	* 		  for this octet.
	*
	* Step 3) We repeat this untill we reach last_ip_addr!!
*/
void print_all_ipaddr(int first_ip_addr[], int last_ip_addr[], ps_args_t *ps_args)
{
	
	
	for( ;first_ip_addr[0] <= last_ip_addr[0]; first_ip_addr[0]++)	
	{	
		for(;first_ip_addr[1] <= last_ip_addr[1]; first_ip_addr[1]++)
		{
			for(;first_ip_addr[2] <= last_ip_addr[2]; first_ip_addr[2]++)
			{
				for(;first_ip_addr[3] <= last_ip_addr[3]; first_ip_addr[3]++)
				{
					print_addr(first_ip_addr,ps_args);
				}
				first_ip_addr[3] = 0;
			}
			first_ip_addr[2] = 0;
		}
		first_ip_addr[1] = 0;
	}
}


//function to calculate range of ip address from prefix
void parse_prefix(string cdir, ps_args_t* ps_args)
{
	string token;
        stringstream iss;
        int network_prefix;
        int ipaddr[4];
        int first_ip[4];
        int last_ip[4];
        int rem;
        int netmask[4] = {0, 0, 0, 0};
        int wildcard[4];
        int shift_result;
        int i;
        int index = cdir.find('/');
        stringstream(cdir.substr(index+1)) >> network_prefix;
        iss << cdir.substr(0, index);
	if(valid_ip_add(iss.str()))
	{
		i = 0;
		while(getline(iss, token, '.'))
		{
		        stringstream(token) >> ipaddr[i];
		        i++;
		}

		//Netmask calculation
		for(i = 0; i < (network_prefix / 8); i++)
		{
		        netmask[i] = pow(2, 8) - 1;
		}
		rem = network_prefix % 8;
		if(rem != 0)
		{
		        shift_result = 255 << (8 - rem);
		        netmask[i] = shift_result % 256;
		}
		//printing netmask
		cout << "netmask = ";
		print_addr(netmask,ps_args);
		
		//Wildcard calculation
		for(i = 0 ; i < 4; i++)
		{
		        wildcard[i] = 255 - netmask[i];
		}
		//printing wildcard
		cout << "wildcard = ";
		print_addr(wildcard,ps_args);

		//Finding the first ip address
		for(i = 0; i < 4; i++)
		{
		        first_ip[i] = ipaddr[i] & netmask[i];
		}
		//Printing first_ip address
		cout << "first ip address = ";
		print_addr(first_ip,ps_args);

		//Finding the last ip address
		for(i = 0; i < 4; i++)
		{
		        last_ip[i] = first_ip[i] + wildcard[i];
		}
		//printing last_ip address
		cout << "Last ip address = ";
		print_addr(last_ip,ps_args);

		print_all_ipaddr(first_ip, last_ip,ps_args);
	}
	else
	{
		cout<<"Enter valid ip address"<<endl;
		
	}
}

//function to read from file
void readFile(char *fp, ps_args_t *ps_args)
{
	ifstream in_stream;
	string line;
	vector<string> list;
	
	in_stream.open(fp);

	while(!in_stream.eof())
	{
	    in_stream >> line;
	    bool exists = line.find("/") != std::string::npos;
	    if(!exists){
		if(valid_ip_add(line))
		{
			ps_args->ip_address.insert(line);
			list.push_back(line); //only ip address (stored in vector)
		}
            }
	    else
		parse_prefix(line,ps_args); //if it is in prefix format
	}

	in_stream.close();
 	std::copy(list.begin(), list.end(), std::ostream_iterator<string>(std::cout, "\n"));
}


void parse_args(int argc, char **argv, ps_args_t *ps_args)
{
	char ch;
	int option_index = 0;
	string prefix;
	int count=1;
	bool host_avaliable=false;
	bool ports_avaliable=false;
	bool scans_avaliable=false;
	static struct option long_options[] = 
	{
		{"help", no_argument, NULL, 'h'}, 
		{"ports", required_argument, NULL, 'p'},
		{"ip", required_argument, NULL, 'i'},
		{"prefix", required_argument, NULL, 'r'},
		{"file", required_argument, NULL, 'f'},
		{"speedup", required_argument, NULL, 't'}, //t = thread
		{"scan", required_argument, NULL, 's'},
		{NULL, 0, NULL, 0}
	};	
	
	while((ch = getopt_long(argc, argv, "hp:i:r:f:t:s:", long_options, &option_index)) != -1)
	{
		switch(ch)
		{
			case 'h':
				usage(stdout);
				count++;
				break;
			case 'p':
			
				ports_avaliable=true;
				parse_ports(optarg,ps_args);
				count=count+2;
				break;
	
			case 'i':
				{
				
				host_avaliable=true;
				string str(optarg);
				std::stringstream ss(str);
   				std::string item;
				
   				while (std::getline(ss, item, ',')) {
						int res=valid_ip_add(item);
					if(res)
					{	
    					 	ps_args->ip_address.insert(item);
					}
					else
					{
						cout<<"incorrect host"<<endl;
						exit(1);
					}
				   				 
				}
		
				count=count+2;
				}
				break;
			case 'r':
				host_avaliable=true;
			
				prefix = optarg;
				parse_prefix(prefix,ps_args);
				
				count=count+2;
				break;
			case 'f':
				host_avaliable=true;
				readFile(optarg,ps_args);
			
				count=count+2;
				break;
			case 't':
				{
					threaded = true;
			
					int threads=atoi(optarg);
					if ( threads > 450)
		            			threads=450;
					ps_args->thread_count=threads;
		                    
					count=count+2;
				}
				break;
			case 's':
				{
					
					scans_avaliable=true;
							
					optind--;
					for( ;optind < argc && *argv[optind] != '-'; optind++){
		      				
						ps_args->scans.insert(argv[optind]);        
					}
			
				
				}
				count=count+2;
				break;
			default:
				cout << "No mode selected" << endl;
				count=count+2;
				break;
		}

	}
	if(argc==1)
	{
		usage(stdout);
		exit(1);
	}
		
	if(!host_avaliable)
	{
		if(argc>count){
			ps_args->ip_address.insert(argv[argc-1]);

		}
		else
		{
			cout<<"NO host provided"<<endl;
			exit(1);

		}
	}
	if(!ports_avaliable)
	{
				
		for(int i=1;i<=1024;i++)
			ps_args->ports.insert(i);
		
		for(itr = ps_args->ports.begin(); itr != ps_args->ports.end(); itr++)
		{
			cout << *itr << endl;
		}
	}

	if(!scans_avaliable)
	{
			
		ps_args->scans.insert("SYN");
		ps_args->scans.insert("FIN");
		ps_args->scans.insert("ACK");
		ps_args->scans.insert("UDP");
		ps_args->scans.insert("NULL");
		ps_args->scans.insert("Xmas");
		

	}
	
	if(!threaded)
	{
		ps_args->thread_count=0;
	}
	return;
}

// Reference http://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
int get_local_ip(char * buffer) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	const char* google_dns_ip = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(google_dns_ip);
	serv.sin_port = htons(dns_port);

	int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
	

	close(sock);
}

int main(int argc, char **argv)
{

	ps_args_t ps_args; 
	
	parse_args(argc, argv, &ps_args); 
	
	struct timeval tim;
	task t;
	int tcp_scan_ret;//Return value for TCP scan fucntion
	int udp_scan_ret;//Return value for UDP scan function


	
	cout<<"*************Starting Port Scanner*********************"<<endl;
	cout<<"Scanning";
	gettimeofday(&tim, NULL);  
	double t1=tim.tv_sec+(tim.tv_usec/1000000.0);  

    	get_local_ip( source_ip );
     
    	

	if(ps_args.thread_count==0)
	{
		
	
		for(itr_s = ps_args.ip_address.begin(); itr_s != ps_args.ip_address.end(); itr_s++)
		{
			for(itr = ps_args.ports.begin(); itr != ps_args.ports.end(); itr++)	
			{
				for(itr_s1 = ps_args.scans.begin(); itr_s1 != ps_args.scans.end(); itr_s1++)
				{
//					cout << "For ip address = " << *itr_s << " and port = " << *itr << " and scan = " << *itr_s1 << endl;
					if((*itr_s1).compare("SYN") == 0 || (*itr_s1).compare("NULL") == 0 || (*itr_s1).compare("FIN") == 0 || (*itr_s1).compare("ACK") == 0 || (*itr_s1).compare("Xmas") == 0)
					{
				
						tcp_scan_ret = do_tcp_scan((*itr_s).c_str(), *itr, *itr_s1, SOURCE_PORT);
						if(tcp_scan_ret == -1)
						{
							cout << "Error processing the curren task...Moving to next task.... " << endl;
							
						}
						
 						progress_bar++;
 						display_progress();
 			
					}
					if((*itr_s1).compare("UDP") == 0)
					{
						
			 			udp_scan_ret = do_udp_scan((*itr_s).c_str(), *itr, *itr_s1, SOURCE_PORT);
						if(udp_scan_ret == -1)
						{
							cout << "Error processing the curren task...Moving to next task.... " << endl;
						}
						progress_bar++;
 						display_progress();
 			
					}				
					cout.flush();
				}
			}
		}

	}
	else
	{

		pthread_t threads[ps_args.thread_count];
		int thread_id[ps_args.thread_count];

		for(itr_s = ps_args.ip_address.begin(); itr_s != ps_args.ip_address.end(); itr_s++)
		{
			for(itr = ps_args.ports.begin(); itr != ps_args.ports.end(); itr++)	
			{
				for(itr_s1 = ps_args.scans.begin(); itr_s1 != ps_args.scans.end(); itr_s1++)
				{
					
					t.ip=*itr_s;
					t.port=*itr;
					t.scan=*itr_s1;
					task_queue.push(t);
				

				}
			}
		}

	

	
			//init the mutex
		if (pthread_mutex_init(&thread_mutex, NULL))
		{
			perror("pthread_mutex_init");
			exit(1);
		}

	
	
		for (int i = 0; i < ps_args.thread_count; i++) {

			thread_id[i]=i;
			if((pthread_create(&threads[i], NULL, &process_task_queue, (void *)&thread_id[i]))!=0)
			{
				cout << "Error:unable to create thread " << endl;
			
			}

		}

	
		for (int i = 0; i < ps_args.thread_count; i++) {

			pthread_join(threads[i], NULL);
		}



	}

	
    	gettimeofday(&tim, NULL);  
    	double t2=tim.tv_sec+(tim.tv_usec/1000000.0);  
    	cout << endl << "Scanning took " << t2-t1<< " seconds" << endl;  

	print_results();
	print_service_version();
	destroy_service();

	return 0;
}
