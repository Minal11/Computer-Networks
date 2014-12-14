/***
 *Authors:
 *Minal Kondawar (mkondawa)
 *Saketh Babu Palla (spalla)
 *
 *
 ***/

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

#include "bt_lib.h"
#include "bt_setup.h"
#include "bencode.h"

#define HANDSHAKE_SIZE 72
#define BITFIELD 1024

FILE *lf; //log file pointer
void setBitfield(bt_msg_t *msg,bt_args_t *bt_args)
{
	int i;
	
	msg->length=1;
	msg->bt_type=BT_BITFILED;
	printf("%d",bt_args->bt_info->num_pieces);
	msg->payload.bitfiled.size=bt_args->bt_info->num_pieces;
	//msg->payload.bitfiled.bitfield=(char*)malloc(bt_args->bt_info->num_pieces*sizeof(char));
	memset(msg->payload.bitfiled.bitfield,0,msg->payload.bitfiled.size);
	for(i=0;i<bt_args->bt_info->num_pieces;i++)
		msg->payload.bitfiled.bitfield[i]='1';
	msg->payload.bitfiled.bitfield[i]='\0';
	
	//exit(1);
}


void start_seeder(bt_args_t *bt_args)
{

	if(bt_args->lmode)
	{
		lf=fopen(bt_args->log_file,"a");

	}

	int sockfd, leecherfd;
	struct sockaddr_in seedSockAddr, leecherSockAddr;
	int len=0;
	char buff[1024], sendbuff[1024];
	int size;
	int no_of_bytes, counter,quotient,rem;
	long total;
	char pname[20];
	char rbytes[8];
	char hash[20];
	char pid[20];

	char pname1[20];
	char rbytes1[8];
	char hash1[20];
	char pid1[20];
	int i, j=0, totalSent=0;
	bt_msg_t msg, rmsg, smsg, hmsg;
	bt_handshake hshake,seedershake;
	FILE *fp;
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Server socket creation error:");
		exit(1);
	}	
	if((bind(sockfd,(struct sockaddr *)&(bt_args->peers[0]->sockaddr), sizeof(bt_args->peers[0]->sockaddr)))<0) //peer[1] is assumed to be a leecher
	{
         perror("Server bind error:");
         exit(1);
    }

	
    if((listen(sockfd,MAX_CONNECTIONS))<0)
    {
         perror("Server listen:");
         exit(1);
    }

	if(bt_args->verbose)
	{
		printf("Seeder listening on port no: %d\n",bt_args->peers[0]->port);		
	}

	if(bt_args->lmode)
	{
		fprintf(lf,"\n SEEDER_SOCKET:Seeder listening on port no : %d\n",bt_args->peers[0]->port);
		fflush(lf);
	}
	while(1)
	{
	
		len = sizeof(leecherSockAddr);
	
		if((leecherfd=accept(sockfd,(struct sockaddr *)&leecherSockAddr, (socklen_t*)&len))<0)
	    {
	        perror(" Server Accept:");
	         exit(1);
		}
		if(bt_args->lmode)
		{
			fprintf(lf,"\nSEEDER_SOCKET: Accepted leecher connection request\n");
			fflush(lf);
		}
		if(bt_args->verbose)
		{
			printf("Seeder has accepted the connection request from the leecher\n");		
		}
		//printf("Accepted");
		//Receiving handshake from the leecher
		if(bt_args->lmode)
		{
			fprintf(lf,"\nSEEDER: Receiving handshake from the leecher\n");
			fflush(lf);
		}
		if(bt_args->verbose)
		{
			printf("\nReceiving the handshake from the Leecher\n");
		}
		memset(buff,0,sizeof(buff));
		recv(leecherfd,buff,sizeof(hshake),0);
		for(i=0;i<20;i++)
			pname[i]=buff[i];
		for(i=0;i<8;i++)
			rbytes[i]=buff[i+20];
		for(i=0;i<20;i++)
			hash[i]=buff[i+28];
		for(i=0;i<20;i++)
			pid[i]=buff[i+48];
		rbytes[8]='\0';
		pname[20]='\0';
		hash[20]='\0';
		pid[20]='\0';
		memcpy(&hshake,buff,sizeof(hshake));
		
		
		initHandshake(&seedershake,bt_args->bt_info->name,bt_args->peers[0]->id);
//		printf("\nseeder ahndshke : %s", seedershake.peer_id);

		for(i=0;i<20;i++)
			pname1[i]=seedershake.protocol_name[i];
		for(i=0;i<8;i++)
			rbytes1[i]=seedershake.protocol_name[i+20];
		for(i=0;i<20;i++)
			hash1[i]=seedershake.protocol_name[i+28];
		for(i=0;i<20;i++)
			pid1[i]=seedershake.protocol_name[i+48];
		rbytes1[8]='\0';
		pname1[20]='\0';
		hash1[20]='\0';
		pid1[20]='\0';
		
		//compare
		if((strcmp(pname,pname1)==0) && (strcmp(rbytes,rbytes1)==0) && (strcmp(hash,hash1)==0) && (strcmp(pid,pid1)==0))
		{
			
			if(bt_args->verbose)
			{
				printf("\nHandshake hashes successfully matched\n");
			}
			if(bt_args->lmode)
			{
				fprintf(lf, "SEEDER_HANDSHAKE: Hashes suucessfully matched!!Sending it back to the Leecher\n");
				fflush(lf);
			}
			send(leecherfd, buff, sizeof(hshake),0);
		}
		
		//printf("\n protocol name at seeder ------->%s\t %s\t %s\t%s",pname1, rbytes1,hash1,pid1);
		
		//printf("%d",bt_args->bt_info->num_pieces);
		setBitfield(&msg,bt_args);	
		if(bt_args->lmode)
		{
			fprintf(lf, "SEEDER: Sending the bitfield to the leecher\n");
			fflush(lf);
		}
		if(bt_args->verbose)
		{
			printf("\n Sending the bitfield now\n");
		}
	//printf("\nmsg payload%s", msg.payload.bitfiled.bitfield);
		send(leecherfd,&(msg),sizeof(msg),0);
		
	//recieved interest msg
		size=sizeof(msg.bt_type)+sizeof(msg.length);
		memset(buff,0,sizeof(buff));
		memset(&rmsg,0,sizeof(rmsg));
		recv(leecherfd,buff,size,0);
		memcpy(&rmsg,buff,size);
		if(bt_args->lmode)
		{
			fprintf(lf, "SEEDER: Received Interested message from the Leecher\n");
			fflush(lf);
		}
//		printf("\n Interested msg was recieved:%d \t %d",rmsg.length, rmsg.bt_type);
		//size=0;
	//	size=sizeof(msg.bt_type)+sizeof(msg.length);
		memset(buff,0,sizeof(buff));
		memset(&msg,0,sizeof(msg));
		//will recieve the packets
		//memset(sendbuff,0,sizeof(sendbuff));
	
		fp=fopen(bt_args->bt_info->name,"rb");
		if(bt_args->lmode)
		{
			fprintf(lf, "SEEDER: Sending the requested piece to the leecher\n");
			fflush(lf);
		}
		while(recv(leecherfd,buff,sizeof(msg),0))
		{
			memcpy(&msg,buff,sizeof(msg));
			smsg.payload.piece.index=msg.payload.request.index;
			smsg.payload.piece.begin=msg.payload.request.begin;
			smsg.payload.piece.length=msg.payload.request.length;
		
			fread(smsg.payload.piece.piece,1,msg.payload.request.length,fp);
			send(leecherfd,&smsg,sizeof(smsg),0);
            if(j!=0)
	        	totalSent += msg.payload.request.length;
			//printf("%d",msg.payload.request.length);
			//exit(1);
            j++;
			//fprintf(lf,"hey i m in loop");
			if(bt_args->verbose){
				
	            if(j/30)    
					printf("\nsent %dB of %dB", totalSent, bt_args->bt_info->length);
			}		
			memset(buff,0,sizeof(buff));
			memset(&msg,0,sizeof(msg));
			memset(&smsg,0,sizeof(smsg));
            
		}
		if(bt_args->lmode)
		{
			fprintf(lf, "SEEDER: sent %dB of %dB\n", bt_args->bt_info->length);
			fflush(lf);
		}
		printf("\nSent %dB of %dB", bt_args->bt_info->length);

	} 	
	if(lf){

		fclose(lf);
		lf=NULL;
	}
}
void start_leecher(bt_args_t *bt_args)
{
	int sockfd;
	bt_handshake hshake;
	struct sockaddr_in leecherSockAddr;
	int len=0;	
	char buff[1024];
	bt_msg_t rmsg, smsg, msg, msg1;
	int no_of_packets, no_of_blocks, no_of_bytes;
	int pindex, bindex, quotient, rem,begin, counter, left_amount;
	long total;
	char output_filename[FILE_NAME_MAX];
	char destination[FILE_NAME_MAX];
	FILE *fp;
	int i,j=0;
	int getIndex;
	int d=0;

	if(bt_args->lmode)
	{
		lf = fopen(bt_args->log_file, "a");

	}
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Client Socket creation failed!");
		exit(1);
    }
	leecherSockAddr=bt_args->peers[1]->sockaddr;
	if((connect(sockfd, (struct sockaddr *)&leecherSockAddr, sizeof(leecherSockAddr))) < 0)
	{
			perror("connect connection failed!");
			exit(1);
    }
//	printf("Connected");
	if(bt_args->lmode)
	{
		fprintf(lf, "LEECHER_SOCKET: Established a connection with the seeder\n");
		fflush(lf);
	}
	//initiate handshake
	initHandshake(&hshake,bt_args->bt_info->name,bt_args->peers[1]->id);
	
	if(bt_args->lmode)
	{
		fprintf(lf, "LEECHER_HANDHSHAKE: Initiating the handshake - Sending the handshake structure to the seeder\n");
		fflush(lf);
	}
	if(bt_args->verbose)
	{
		printf("Leecher initializing the Handshake process\n");
		
	}
	send(sockfd,&hshake,sizeof(hshake),0);


	//send()
	//revc
	//compare
	recv(sockfd,buff,sizeof(hshake),0);
	
	
	if(memcmp(hshake.protocol_name,buff,20)==0)
	{
		//printf("Handshake complte");
		if(bt_args->lmode)
		{
			fprintf(lf, "LEECHER_HANDSHAKE: Received Handshake structure back from the seeder after the successful comparison of the hashes\n");
			fflush(lf);
		}
		if(bt_args->verbose)
		{
			printf("Handshake complete\n");
		}
	}
	else
	{
		//printf("not complter");
		if(bt_args->verbose)
		{
			printf("Handshake structure mismatched!!! Exiting\n");
		}
		if(bt_args->lmode)
		{
			fprintf(lf, "LEECHER_HANDSHAKE: Received Handshake structure mismatched!!! Exiting\n");
			fflush(lf);
		}
		//fclose(lf);
//		exit(1);

	}
	
	//bitfield recieved
	memset(buff,0,sizeof(buff));
	recv(sockfd,buff,sizeof(rmsg),0);
	if(bt_args->lmode)
	{
		fprintf(lf, "LEECHER: Received Bitfield from the seeder\n");
		fflush(lf);
	}
	memcpy(&rmsg,buff,sizeof(rmsg));
//	printf("\nleecher recieved%s \t %d \t %d",rmsg.payload.bitfiled.bitfield, rmsg.bt_type, rmsg.length);

	//send interest message
	createInterest(&smsg);
	printf("\n Interested msg was sent:%d \t %d",smsg.length, smsg.bt_type);
	send(sockfd,&(smsg),sizeof(smsg),0);
	if(bt_args->lmode)
	{
		fprintf(lf, "LEECHER: Sent the interested message to the seeder\n");
		fflush(lf);
	}		
	//sending request on block level
	if(bt_args->lmode)
	{
		fprintf(lf, "LEECHER: Now requesting for the pieces in the block level\n");
		fflush(lf);
	}
	//open the file to read
	strcpy(output_filename, bt_args->bt_info->name);
	strcat(output_filename, "_leeched"); //output file will be in the format: <input_file>_leeched
	if(bt_args->smode)	//if save option is enabled
	{
		strcpy(destination, bt_args->save_file);
		strcat(destination, output_filename);
	}
	else
	{
		strcpy(destination, output_filename);
	}
	fp = fopen(destination, "wb");
/*	
	if(strcmp(bt_args->bt_info->name,"moby_dick.txt")==0)
		fp=fopen("new.txt","wb");
	else
		fp=fopen("new.mp3","wb");
*/
	i=5;
	no_of_packets=bt_args->bt_info->num_pieces;
	char array[30] = {0};
	for(pindex=no_of_packets;pindex>0;pindex--)
	{
		j=0;
		//randomize the packets
		//store the piece
		while(1){
	        srand(time(NULL));
                getIndex = rand()%1000;
		getIndex %= no_of_packets;

	

		if(array[getIndex]==1)
			continue;
		else{
		    array[getIndex]=1;
		    break;
			}
		}
			printf("\n getindex:%d",getIndex);
		if(getIndex==(no_of_packets-1))//last packet
		{
			if(bt_args->bt_info->length<bt_args->bt_info->piece_length)
				total=bt_args->bt_info->length;
			else
			{
				total=bt_args->bt_info->length-((no_of_packets-1)*bt_args->bt_info->piece_length);
			}			
			quotient = total/1024;
			rem = total%1024;
			no_of_blocks= (rem == 0)?quotient:(quotient+1);
		}		
		else
		{
			
			total=bt_args->bt_info->piece_length;
			quotient = total/1024;
			rem = total%1024;
			no_of_blocks= (rem == 0)?quotient:(quotient+1);

		}	
		no_of_bytes=1024;
		//printf("no of blockes%d",no_of_blocks);
		counter=total;
		for(bindex=0;bindex<=no_of_blocks;bindex++)
		{
					
				//create a request
				//printf("\nbindex = %d\n", bindex);
				no_of_bytes=(counter<1024)?counter:1024;
				begin=(bt_args->bt_info->piece_length)*(getIndex-1)+1024*bindex;
	//			printf("\n brgin :%d", begin);
			
		//		printf("\npindex = %d, counter = %d, no_of_bytes = %d, begin = %d\n", pindex, counter, no_of_bytes, begin);
				createRequest(&msg,pindex,begin,no_of_bytes);
			//	printf("\n msg length:%d",msg.length);
		//	printf("\n msg type:%d",msg.bt_type);
	//		printf("\n msg index:%d",msg.payload.request.index);
		//	printf("\n msg begin:%d",msg.payload.request.begin);
	//	printf("\n msg length:%d",msg.payload.request.length);
				send(sockfd,(const void *)&(msg),sizeof(msg),0);
				memset(buff,0,sizeof(buff));
				recv(sockfd,buff,sizeof(msg),0);

				memcpy(&msg1,buff,sizeof(msg1));
			//printf("\n peice index:%d",msg1.payload.piece.index);
		//	printf("\n peice begin:%d",msg1.payload.piece.begin);
			//printf("\n peice length:%d",msg1.payload.piece.length);
				if(j>0)
				{	
				
					fwrite(msg1.payload.piece.piece,1,msg1.payload.piece.length,fp);
				}
				else
				{
					j=1;
				}
			//	printf("\n i wrote it");
				memset(msg1.payload.piece.piece,0,1024);
				memset(&msg,0,sizeof(msg));
				memset(&msg1,0,sizeof(msg1));
				memset(buff,0,sizeof(buff));
				left_amount = counter;
				counter=counter-1024;

		}
	d=d+total;	
	
	if(bt_args->lmode)
	{
		fprintf(lf, "LEECHER:Successfully downloaded %dB of %dB", d, bt_args->bt_info->length);
	}
	printf("\nSuccessfully downloaded %dB of %dB", d, bt_args->bt_info->length);
		
//	fclose(fp);


	}
if(fp)
	fclose(fp);
if(lf)
	fclose(lf);
}


int main (int argc, char * argv[]){

	bt_args_t bt_args;
  int i;

  parse_args(&bt_args, argc, argv);


  if(bt_args.lmode)
  {
	lf = fopen(bt_args.log_file, "w");
  }
  if(bt_args.verbose){
    printf("Args:\n");
    printf("verbose: %d\n",bt_args.verbose);
    printf("save_file: %s\n",bt_args.save_file);
    printf("log_file: %s\n",bt_args.log_file);
    printf("torrent_file: %s\n", bt_args.torrent_file);

    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args.peers[i] != NULL)
        print_peer(bt_args.peers[i]);
    }

    
  }

	if(bt_args.lmode)
	{
		fprintf(lf, "TORRENT_FILE: Reading and parsing the torrent file\n");
		fflush(lf);
	}
  //read and parse the torrent file here
	struct keyValue *curr;
	curr=parseTorrentFile(bt_args.torrent_file);	
	bt_info_t bt_info;
	parse_bt_info(&bt_info,curr);
	

  if(bt_args.verbose){
    // print out the torrent file arguments here
		printf("-----------------------------------");
		printf("\nParsed info value from torrent file");
		printf("\n------------------------------------");
		printf("\nannounce=%s",bt_info.url);
		printf("\nname=%s",bt_info.name);
		printf("\nlength=%d",bt_info.length);
		printf("\npiece_length=%d",bt_info.piece_length);
		printf("\npiece hashes=%s",bt_info.complete_hash);
  }

	if(bt_args.lmode)
	{
		fprintf(lf, "TORRENT_FILE: Finished parsing the torrent file\n");
		fflush(lf);
	}
  //main client loop
  printf("Starting Main Loop\n");
	if(bt_args.b==1)
	{
		bt_args.bt_info=&bt_info;
		printf("%d",bt_args.bt_info->num_pieces);
	
		start_seeder(&bt_args);
	}
	else
	{
		bt_args.bt_info=&bt_info;
		start_leecher(&bt_args);
	}

  return 0;
}




