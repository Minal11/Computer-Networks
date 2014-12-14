#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <openssl/sha.h> //hashing pieces

#include <math.h>
#include <poll.h>
#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

#define TRUE             1
#define FALSE            0
struct tor_data
{
	int lenght;
	char name[100];
	int piece_len;
	char pieces[400];

}td;

int wrong_torrent;
struct handshake
{
	char protocol[20];
	char res[8];
	char infohash[20];
	char peer_id[20];
};

int get_file_4m_seeder(int sockfd,int no_of_pcs,int csize,bt_args_t bt_args,struct tor_data td,char *logname);
void start_seeder(bt_args_t bt_args,struct tor_data td, char *digest,unsigned char *my_id,int no_of_pcs);
void start_leecher(bt_args_t bt_args,struct tor_data td,char *digest,unsigned char *my_id,int no_of_pcs,char * logname);
void compute_hash(bt_args_t,struct tor_data,int no_of_pcs);
void my_dump(be_node *node,char *str);
int main (int argc, char * argv[]){

	bt_args_t bt_args;
	be_node * node; // top node in the bencoding
	int i;
	int no_of_pcs;
	parse_args(&bt_args, argc, argv);

	if(bt_args.verbose)
	{
		printf("Args:\n");
		printf("verbose: %d\n",bt_args.verbose);
		printf("save_file: %s\n",bt_args.save_file);
		printf("log_file: %s\n",bt_args.log_file);
		printf("torrent_file: %s\n", bt_args.torrent_file);

		for(i=0;i<MAX_CONNECTIONS;i++)
		{
			if(bt_args.peers[i] != NULL)
			{
				print_peer(bt_args.peers[i]);

			}
		}


	}

	//read and parse the torent file
	node = load_be_node(bt_args.torrent_file);
	my_dump(node,NULL);

	//Calculate the number of pieces required
	if(td.lenght%td.piece_len==0)
	{

		no_of_pcs=td.lenght/td.piece_len;

	}
	else
	{

		no_of_pcs=td.lenght/td.piece_len+1;
	}

	if(bt_args.verbose)
	{
		be_dump(node);
	}


	//Find the hostname to send it to leecher when required
	char hostname[128];
	gethostname(hostname,128);


	struct hostent *he;
	he=gethostbyname(hostname);
	char *hname;
	hname = strtok (hostname,".");
	short port=4646;

	char data2[256];
	int len;
	len = sprintf(data2,"%s%u",hname,port);
	char my_id[20];

	unsigned char mid[20];
	calc_id(hname,port,my_id);
	memcpy(mid, my_id, ID_SIZE);


	//Calculate the digest for info value from the parsed torrent file
	char *data;
	char temp[500];

	data = (char *)&td;
	strcpy(temp,data);
	char  digest[20];

	//Compute the digest with SHA1
	SHA1( (unsigned char *)temp, strlen(temp), (unsigned char *)digest);


	//Find if the client is called as a seeder or leecher
	if(bt_args.peers[1]->id ==  NULL)
	{
		//Call the seeder and initialize it
		printf("\nSeeder Initialized\n");
		FILE *log;
		log =fopen("mylog_server.log","w");
		fputs("\nServer Log file started",log);
		fclose(log);
		while(1)
		{
			start_seeder(bt_args,td,digest,mid,no_of_pcs);//Need to replace it with b2,hostname with my_id
		}
		printf("\nExiting seeder mode\n");


	}
	else
	{
		//Call the leecher function
		FILE *log1;
		char logname[50];
		strcpy(logname,bt_args.save_file);
		strcat(logname,"_log.log");
		log1 =fopen(logname,"a+");
		fseek(log1,0,SEEK_END);
		fputs("\nLeecher Log file started",log1);
		fclose(log1);

		printf("\nIn leecher mode\n");

		start_leecher(bt_args,td,digest,mid,no_of_pcs,logname);

		if(wrong_torrent==0)
			compute_hash(bt_args,td,no_of_pcs);

		log1 =fopen(logname,"a+");
		fseek(log1,0,SEEK_END);
		fputs("\nHash computed and verified. File transfer successful",log1);
		fclose(log1);

	}


	return 0;


}



void start_seeder(bt_args_t bt_args,struct tor_data td, char *digest,unsigned char *my_id,int no_of_pcs)
{


	FILE *log;

	//Declare all the variables
	int    new_sd = -1;
	int sockfd,  portno;

	int timeout;
	struct pollfd fds[5];
	struct sockaddr_in serv_addr;
	//struct sockaddr_in client_addr;
	int c;
	//socklen_t client_lt;

	struct handshake *rec_info;
	int flag[5];
	struct handshake send_to_leecher;

	int end_server = FALSE;
	int    close_conn;

	//Flag argument to check if handshake is required or not
	int rr;

	for(rr=0;rr<5;rr++)
	{
		flag[rr]=0;
	}

	/* First call to socket() function */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
	{
		perror("ERROR opening socket");
		exit(1);
	}
	/* Initialize socket structure */
	bzero((char *) &serv_addr, sizeof(serv_addr));
	portno = 4646;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	/* Now bind the host address using bind() call.*/
	if (bind(sockfd, (struct sockaddr *) &serv_addr,
		sizeof(serv_addr)) < 0)
	{
		perror("ERROR on binding");
		exit(1);
	}

	log =fopen("mylog_server.log","a+");
	fseek(log,0,SEEK_END);
	fputs("\nSocket succesfully bounded",log);
	fclose(log);


	listen(sockfd,5);

	//Intialize the poll fd structure
	memset(fds, 0 , sizeof(fds));

	//Setup the inital listening socket
	fds[0].fd = sockfd;
	fds[0].events = POLLIN;
	timeout = (3 * 60 * 1000);
	int rc;
	int nfds =1;
	int current_size = 0;
	FILE *fp;
	char tempo[50];//for sprintf
	log =fopen("mylog_server.log","a+");
	fseek(log,0,SEEK_END);
	fputs("\nIntialized poll structure",log);

	fclose(log);

	fp = fopen(td.name,"r");

	do
	{

		rc = poll(fds, nfds, timeout);

		if (rc < 0)
		{
			perror("  poll() failed");
			break;
		}
		if (rc == 0)
		{
			perror("  poll()timeout");
			break;
		}

		current_size = nfds;
		for (c = 0; c < current_size; c++)
		{

			if(fds[c].revents == 0)
				continue;

			if(fds[c].revents != POLLIN)
			{
				printf(" ---- Error! revents = %d\n", fds[c].revents);
				end_server = FALSE;
			
				close(fds[c].fd);
				fds[c].fd = -1;
				flag[c]=0;
					break;

			}
			int flag1=0;
			if (fds[c].fd == sockfd)
			{
				new_sd = accept(sockfd, NULL,NULL);
				if (new_sd < 0)
				{

					perror("  accept() failed");
					end_server = TRUE;

					//break;
				}


				fds[nfds].fd = new_sd;
				fds[nfds].events = POLLIN;

				nfds++;

				flag1=1;

				new_sd=-1;

			}
			else

			{
				close_conn = FALSE;

				char buf2[1024];
				int n;char tmp[20];

				if(flag[c]==0)
				{

					//Clear the buffer
					bzero(buf2,1024);

					//REcive the handhsake
					n = recv( fds[c].fd,buf2,sizeof(struct handshake),0);

					rec_info = (struct handshake *)(buf2);

					strncpy(tmp,rec_info->infohash,20);
					//Check if the infohash is same
					if(strncmp(digest,tmp,20)!=0)
					{
						printf("Terminating connection since peer requesting a different file.");
						close_conn = TRUE;
						close(fds[c].fd);
						fds[c].fd = -1;
						flag[c]=0;
						break;

					}

					if(bt_args.verbose)
					{
						printf("\nHandshake recieved from client");
					}

					log =fopen("mylog_server.log","a+");
					fseek(log,0,SEEK_END);
					sprintf(tempo,"\nHandshake recieved on descriptor %d",fds[c].fd);
					fputs(tempo,log);
					fclose(log);

					//On successful infohash comparision, send the handshake from the seeder's side
					send_to_leecher.protocol[0]=19;
					strcpy(&send_to_leecher.protocol[1],"BitTorrent Protocol");
					bzero(send_to_leecher.res,8);
					strcpy(send_to_leecher.infohash,digest);
					strcpy(send_to_leecher.peer_id,(char *)my_id);

					char *test;
					test = (char *)&send_to_leecher;
					n = send(fds[c].fd,test,sizeof(send_to_leecher),0);

					flag[c]=1;
				}

				long int actual_offset;

				bt_msg_t msg_frm_leecher;

				bt_msg_t msg_to_leecher;

				long int j=0;

				int i;

				int rand1;


				n = recv( fds[c].fd,&msg_frm_leecher,sizeof(msg_frm_leecher),0);

				if(msg_frm_leecher.bt_type==4)
				{
					log =fopen("mylog_server.log","a+");
					fseek(log,0,SEEK_END);
					sprintf(tempo,"\nRecieved have message from client for piece - %d",msg_frm_leecher.payload.have);
					fputs(tempo,log);
					fclose(log);
					printf(tempo,"\nRecieved have message from client for piece - %d",msg_frm_leecher.payload.have);
				}
				if(msg_frm_leecher.bt_type==6)
				{
					//Keep logging the messages at random times
					rand1=rand()%1000;
					if(rand1%37==0)
					{
						log =fopen("mylog_server.log","a+");
						fseek(log,0,SEEK_END);
						sprintf(tempo,"\nServicing client on descriptor %d, Request for piece - %d, index - %d, lenght %d",fds[c].fd,msg_frm_leecher.payload.request.index,msg_frm_leecher.payload.request.begin,msg_frm_leecher.payload.request.length);
						fputs(tempo,log);
						fclose(log);

						if(bt_args.verbose)
							printf("\nServicing client on descriptor %d, Request for piece - %d, index - %d, lenght %d",fds[c].fd,msg_frm_leecher.payload.request.index,msg_frm_leecher.payload.request.begin,msg_frm_leecher.payload.request.length);
					}

					actual_offset= msg_frm_leecher.payload.request.index*td.piece_len+msg_frm_leecher.payload.request.begin;
					fseek(fp,actual_offset,SEEK_SET);
					//Send the file to the leecher
					msg_to_leecher.bt_type=7;
					msg_to_leecher.payload.piece.begin=msg_frm_leecher.payload.request.begin;
					msg_to_leecher.payload.piece.index=msg_frm_leecher.payload.request.index;
					for(i=0;i<msg_frm_leecher.payload.request.length;i++)
						msg_to_leecher.payload.piece.piece[i]=fgetc(fp);

					if(msg_frm_leecher.payload.request.length==1023)
						msg_to_leecher.payload.piece.piece[i]=fgetc(fp);
					else
						msg_to_leecher.payload.piece.piece[msg_frm_leecher.payload.request.length]='\0';
					send(fds[c].fd,&msg_to_leecher,sizeof(msg_to_leecher),0);
					if(msg_frm_leecher.payload.request.length!=1024)
					{

						log =fopen("mylog_server.log","a+");
						fseek(log,0,SEEK_END);
						sprintf(tempo,"\nClosing file descriptor %d",fds[c].fd);
						fputs(tempo,log);
						fclose(log);


						printf("\nClosing file descriptor %d",fds[c].fd);
						close_conn = TRUE;
						close(fds[c].fd);
						fds[c].fd = -1;
						flag[c]=0;

					}

					j++;
				}


				if (rc < 0)
				{
					perror("  send() failed");
					close_conn = TRUE;

				}


			}
		}

	} while (TRUE);

	/* End of serving running.    */
	/*************************************************************/
	/* Clean up all of the sockets that are open                 */
	/*************************************************************/
	for (c = 0; c < nfds; c++)
	{
		if(fds[c].fd >= 0)
			close(fds[c].fd);
	}

	printf("\nClosing Server");
	exit(0);
}





void start_leecher(bt_args_t bt_args,struct tor_data td,char *digest,unsigned char *my_id,int no_of_pcs,char * logname)
{
	//Declare al the variables
	FILE *log;
	int sockfd;
	int n;
	char buffer[1024];
	wrong_torrent=0;
	sockfd = socket(AF_INET,SOCK_STREAM,0);

	//Checking for errors while opening the socket
	if (sockfd == -1)
	{
		fprintf(stderr,"ERROR opening the socket");
		exit(1);
	}
	//Connect on to the socket
	if (connect(sockfd,(const struct sockaddr *)&bt_args.peers[1]->sockaddr,sizeof(bt_args.peers[1]->sockaddr)) == -1)
	{
		fprintf(stdout,"ERROR connecting to the socket");
		exit(1);
	}


	if(bt_args.verbose)
	{
		printf("\nConnection successful with the seeder");
	}

	log =fopen(logname,"a+");
	fseek(log,0,SEEK_END);
	fputs("\nConnection successfully established with the seeder",log);
	fclose(log);


	char *test;
	long int csize=1024;//chunk size
	struct handshake to_seeder;

	//Initialize Handshake
	to_seeder.protocol[0]=19;
	strcpy(&to_seeder.protocol[1],"BitTorrent Protocol");
	bzero(to_seeder.res,8);
	strcpy(to_seeder.infohash,digest);
	strcpy(to_seeder.peer_id,(char *)my_id);
	test = (char *)&to_seeder;

	n = send(sockfd,test,sizeof(to_seeder),0);
	if(bt_args.verbose)
	{
		printf("\nHandshake sent to the seeder");
	}
	bzero(buffer,1024);
	log =fopen(logname,"a+");
	fseek(log,0,SEEK_END);
	fputs("\nHandshake sent to the seeder",log);
	fclose(log);


	//Recieve the handshake from seeder
	n = recv( sockfd,buffer,sizeof(struct handshake),0);

	struct handshake *from_seeder;
	from_seeder=(struct handshake *) buffer;

	//Compare peerid to the expected peerid value
	if(strncmp((const char *)from_seeder->peer_id,(const char *)bt_args.peers[1]->id,20)!=0)
	{
		printf("\nPeer id did not match the expected value");
		log =fopen(logname,"a+");
		fseek(log,0,SEEK_END);
		fputs("\nPeerid didnot match the expected peer id, Connection terminated",log);
		fclose(log);

		exit(0);
		wrong_torrent=1;
		close(sockfd);
		return;

	}
	else
	{
		printf("\nHandshake recieved, verified.. Requesting file pieces....");

		log =fopen(logname,"a+");
		fseek(log,0,SEEK_END);
		fputs("\nHandshake successful, verified.. Requesting file pieces",log);
		fclose(log);


		bzero(buffer,1024);
		get_file_4m_seeder(sockfd,no_of_pcs,csize,bt_args,td,logname);
		printf("\nFile downloaded successfully");

		log =fopen(logname,"a+");
		fseek(log,0,SEEK_END);
		fputs("\nFile download successful. Closing log file",log);
		fclose(log);
		//compute_hash();
		close(sockfd);

	}


}


int get_file_4m_seeder(int sockfd,int no_of_pcs,int csize,bt_args_t bt_args,struct tor_data td,char *logname)
{
	//Declare variables
	FILE *log;
	char tempo[1024];
	long int i,j,actual_offset,ii;
	int n;
	FILE *fp;
	FILE *fp2;
	char c[100];
	char state[1024];
	char full_state[1024];
	char zero_state[1024];
	int jn;
	//Compute the name of SaveState file - to store the restart states
	strcpy(c,"SaveState_");

	if(strlen(bt_args.save_file)<1)
		strcat(c,"Default");
	else
		strcat(c,bt_args.save_file);

	if(bt_args.verbose)
	{
		printf("\nSaving the restart information of torrent file to %s",c);
	}

	log =fopen(logname,"a+");
	fseek(log,0,SEEK_END);
	sprintf(tempo,"\nSaving the restart information of torrent file to %s",c);
	fputs(tempo,log);
	fclose(log);
	//Load the state information into arrays
	fp2=fopen(c,"r");
	if(fp2==NULL)
	{
		fp2=fopen(c,"a+");
		for(jn=0;jn<no_of_pcs;jn++)
		{
			fputc('0',fp2);
			state[jn]='0';
			full_state[jn]='1';
			zero_state[jn]='0';
		}
		state[jn]='\0';
		full_state[jn]='\0';
		zero_state[jn]='\0';

	}
	else
	{
		for(jn=0;jn<no_of_pcs;jn++)
		{
			state[jn]=fgetc(fp2);
			full_state[jn]='1';
			zero_state[jn]='0';
		}
		state[jn]='\0';
		full_state[jn]='\0';
		zero_state[jn]='\0';

	}
	fclose(fp2);

	if(bt_args.verbose)
	{
		printf("\nThe current state information is %s",state);
	}

	log =fopen(logname,"a+");
	fseek(log,0,SEEK_END);
	sprintf(tempo,"\nThe current state information is %s",state);
	fputs(tempo,log);
	fclose(log);
	//Check if an available copy of the file is already present
	if(strlen(bt_args.save_file)<1)
	{
		fp=fopen("Default","r");
		if(fp==NULL)
		{

			fp=fopen("Default","w");

		}
		else
		{
			fclose(fp);
			fp=fopen("Default","r+");
		}
	}
	else
	{
		fp=fopen(bt_args.save_file,"r");
		if(fp==NULL)
		{

			fp=fopen(bt_args.save_file,"w");

		}
		else
		{
			fclose(fp);
			printf("\n Reopening the file in append mode");

			fp=fopen(bt_args.save_file,"r+");
			fseek(fp,0,SEEK_SET);
		}
	}
	bt_msg_t msg2seeder;
	bt_msg_t msg4mseeder;
	int bytes_left,last_round;

	long int k=0;
	int random0;

	//Compare if the file has already been dowloaded
	if(strcmp(state,full_state)==0)
	{
		printf("\nFile already present");

		log =fopen(logname,"a+");
		fseek(log,0,SEEK_END);
		fputs("\nFile already present",log);
		fclose(log);

		return 28;
	}
	if(strcmp(state,zero_state)!=0)
	{

		printf("\nPrevious copy of file present, Restarting the downloading.. \n");

		log =fopen(logname,"a+");
		fseek(log,0,SEEK_END);
		fputs("\nPrevious copy of file present, Restarting the downloading.. \n",log);
		fclose(log);
	}
	int count;
	for(count=0;count<no_of_pcs-1;count++)
	{

		if(strcmp(state,full_state)==0)
		{
			printf("\nNow has full info");
			break;
		}

		//Compute a random piece to ask the seeder
		int kkr_flag =0;
		while(1)
		{
			if(strncmp(state,full_state,no_of_pcs-1)==0)
			{
				kkr_flag=1;
				break;
			}
			random0=rand()%(no_of_pcs-1);

			if(state[random0]=='0')
				break;
		}
		if(bt_args.verbose)
		{
			printf("\nRadom piece selected is %d",random0);
		}
		log =fopen(logname,"a+");
		fseek(log,0,SEEK_END);
		sprintf(tempo,"\nRadom piece selected is %d",random0);
		fputs(tempo,log);
		fclose(log);

		i=random0;

		//i =count;
		if(kkr_flag==1)
			break;
		for(j=0;j<(td.piece_len/csize);j++)
		{
			msg2seeder.bt_type=6;
			msg2seeder.payload.request.index=i;
			msg2seeder.payload.request.begin=csize*j;

			msg2seeder.payload.request.length=csize;
			k++;
			//Send request for the random piece
			n = send( sockfd,&msg2seeder,sizeof(msg2seeder),0);
			//Recieve the piece from the seeder
			n = recv(sockfd,&msg4mseeder,sizeof(msg4mseeder),0);

			//Check if it is a piece from the seeder
			if(msg4mseeder.bt_type==7)
			{
				actual_offset= msg2seeder.payload.request.index*td.piece_len+msg2seeder.payload.request.begin;
				fseek(fp,actual_offset,SEEK_SET);

				for(ii=0;ii<msg2seeder.payload.request.length;ii++)
				{
					fputc(msg4mseeder.payload.piece.piece[ii],fp);

				}
			}


		}
		state[i]='1';

		int jnn;
		fp2=fopen(c,"w");
		for(jnn=0;jnn<no_of_pcs;jnn++)
		{
			fputc(state[jnn],fp2);
		}
		fclose(fp2);
		//Compute the percentage progress
		int rrr;
		int rrr_count=0;
		for(rrr=0;rrr<no_of_pcs;rrr++)
		{
			if(state[rrr]=='1')
				rrr_count++;
		}
		float p;
		p =(float)rrr_count/no_of_pcs*100.0;
		if(bt_args.verbose)
		{
			printf("\nCompleted download of piece %ld",i);


			printf("\n%.2f percentage of file downloaded",p);


		}
		log =fopen(logname,"a+");
		fseek(log,0,SEEK_END);
		sprintf(tempo,"\nCompleted download of piece %ld",i);
		fputs(tempo,log);
		fclose(log);

		log =fopen(logname,"a+");
		fseek(log,0,SEEK_END);
		sprintf(tempo,"\n%.2f percentage of file downloaded",p);
		fputs(tempo,log);
		fclose(log);

	}
	//Request the last piece of the file
	i=no_of_pcs-1;
	bytes_left=td.lenght-(i*td.piece_len);

	if(bytes_left%csize==0)
		last_round=bytes_left/csize;
	else
		last_round=bytes_left/csize+1;

	for(j=0;j<last_round;j++)
	{
		if(j!=(last_round-1))
		{
			msg2seeder.bt_type=6;
			msg2seeder.payload.request.index=i;
			msg2seeder.payload.request.begin=csize*j;

			msg2seeder.payload.request.length=csize;
			k++;
			n = send( sockfd,&msg2seeder,sizeof(msg2seeder),0);

			n = recv(sockfd,&msg4mseeder,sizeof(msg4mseeder),0);

			actual_offset= msg2seeder.payload.request.index*td.piece_len+msg2seeder.payload.request.begin;
			fseek(fp,actual_offset,SEEK_SET);

			for(ii=0;ii<msg2seeder.payload.request.length;ii++)
			{
				fputc(msg4mseeder.payload.piece.piece[ii],fp);

			}


		}
		else
		{
			msg2seeder.bt_type=6;
			msg2seeder.payload.request.index=i;
			msg2seeder.payload.request.begin=csize*j;
			if(bytes_left%csize!=0)
				msg2seeder.payload.request.length=bytes_left%csize;
			else
				msg2seeder.payload.request.length=1023;

			k++;
			n = send( sockfd,&msg2seeder,sizeof(msg2seeder),0);

			n = recv(sockfd,&msg4mseeder,sizeof(msg4mseeder),0);

			actual_offset= msg2seeder.payload.request.index*td.piece_len+msg2seeder.payload.request.begin;
			fseek(fp,actual_offset,SEEK_SET);

			for(ii=0;ii<msg2seeder.payload.request.length;ii++)
			{
				fputc(msg4mseeder.payload.piece.piece[ii],fp);

			}
			if(msg2seeder.payload.request.length==1023)
				fputc(msg4mseeder.payload.piece.piece[ii],fp);

		}
	}
	state[i]='1';
	if(bt_args.verbose)
	{
		printf("\nCompleted download of piece %ld",i);
		printf("\n%d percnetage of file downloaded",(no_of_pcs/no_of_pcs)*100);
	}

	for(i=0;i<no_of_pcs;i++)
	{
		msg2seeder.bt_type=4;
		msg2seeder.payload.have=i;
		n = send( sockfd,&msg2seeder,sizeof(msg2seeder),0);
	}

	log =fopen(logname,"a+");
	fseek(log,0,SEEK_END);
	sprintf(tempo,"\nCompleted download of piece %ld",i);
	fputs(tempo,log);
	sprintf(tempo,"\n%d percnetage of file downloaded",(no_of_pcs/no_of_pcs)*100);
	fputs(tempo,log);

	fclose(log);
	fclose(fp);
	fp2=fopen(c,"w");

	//Update the state information
	for(jn=0;jn<no_of_pcs;jn++)
	{
		fputc(state[jn],fp2);
	}
	fclose(fp2);

	return 46;

}


void my_dump(be_node *node,char *str)
{
	size_t i;
	//Check the type of node
	switch (node->type) {
	case BE_STR:
		//If a string is encoded in the torrent file, check if it is pieces
		if(str!=NULL)
		{if(strcmp(str,"pieces")==0)
		{

			strcpy(td.pieces,node->val.s);

		}
		//If a string is encoded in the torrent file, check if it is name
		if(strcmp(str,"name")==0)
		{
			strcpy(td.name,node->val.s);

		}

		}

		break;

	case BE_INT:
		//Similarly check for lenght, piecelengh in the dicitonary
		if(str!=NULL)
		{
			if(strcmp(str,"length")==0)
			{
				td.lenght=node->val.i;
			}
			if(strcmp(str,"piece length")==0)
			{
				td.piece_len=node->val.i;
			}
		}
		break;

	case BE_LIST:

		for (i = 0; node->val.l[i]; ++i)
			my_dump(node->val.l[i],NULL);


		break;

	case BE_DICT:
		//Check for the dictionary values
		for (i = 0; node->val.d[i].val; ++i) {

			if(strcmp(node->val.d[i].key,"length")==0)
			{
				my_dump(node->val.d[i].val,"length");
			}
			else if(strcmp(node->val.d[i].key,"name")==0)
			{
				my_dump(node->val.d[i].val,"name");
			}
			else if(strcmp(node->val.d[i].key,"piece length")==0)
			{
				my_dump(node->val.d[i].val,"piece length");
			}
			else if(strcmp(node->val.d[i].key,"pieces")==0)
			{
				my_dump(node->val.d[i].val,"pieces");
			}

			else
				my_dump(node->val.d[i].val,NULL);
		}

		break;
	}
}


void compute_hash(bt_args_t bt_args,struct tor_data td,int no_of_pcs)

{

	FILE *fp;
	char hash[262144];
	char total[1024];
	//char *h;
	//char c[20];
	unsigned char id[20];
	if(strlen(bt_args.save_file)<1)
		fp=fopen("Default","r");
	else
		fp=fopen(bt_args.save_file,"r");
	if(fp==NULL)
	{
		printf("\nDownloaded file does not exist in this folder");
		return;
	}


	long int i;

	//Printing the lenght of file as a verification
	fseek(fp,0,SEEK_END);
	long int len;
	len =ftell(fp);

	//Set the file pointer to the original position
	fseek(fp,0,SEEK_SET);

	if(no_of_pcs==1)
	{

		for(i=0;i<len;i++)
			hash[i]=fgetc(fp);

		SHA1( (unsigned char *)hash, len,  id); 

		if(strcmp(id,td.pieces)==0)
			printf("\nHash verified for the downloaded file");

	}
	else
	{
		int count;
		//Read the first 262144 bytes
		for(count=0;count<no_of_pcs-1;count++)
		{
			for(i=0;i<262144;i++)
				hash[i]=fgetc(fp);

			SHA1( (unsigned char *)hash, 262144,  id); 

			strcat(total,id);
			bzero(hash,262144);
			bzero(id,20);
		}

		if(strcmp(total,td.pieces)==0)
			printf("\nHash verified for the downloaded file");
	}




}
