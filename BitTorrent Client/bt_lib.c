#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> //hashing pieces

#include "bt_lib.h"
#include "bt_setup.h"
#include "bencode.h"


void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;
  
  //format print
  len = snprintf(data,256,"%s%u",ip,port);

  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id); 

  return;
}


/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port){
    
  struct hostent * hostinfo;
  //set the host id and port for referece
  int i;
  //peer->id=(char *)malloc(20*sizeof(char));
  //strcpy(peer->id,"12345");
 // printf("\n%s",peer->id);
    memcpy(peer->id, id, ID_SIZE);
printf("\npeerrr id = %s\n", peer->id);
 // strcpy(peer->id, id);
 peer->port = port;
//  memcpy(&(peer->port), &port, sizeof(port));
printf("\npeerrr port = %d\n", peer->port);
  //get the host by name
  if((hostinfo = gethostbyname(ip)) ==  NULL){
    perror("gethostbyname failure, no such host?");
    herror("gethostbyname");
    exit(1);
  }
  
  //zero out the sock address
  bzero(&(peer->sockaddr), sizeof(peer->sockaddr));
      
  //set the family to AF_INET, i.e., Iternet Addressing
  peer->sockaddr.sin_family = AF_INET;
    
  //copy the address to the right place
  bcopy((char *) (hostinfo->h_addr), 
        (char *) &(peer->sockaddr.sin_addr.s_addr),
        hostinfo->h_length);
    
  //encode the port
 // memcpy(peer->sockaddr.sin_port, &htons(port), sizeof(htons(port)));
 peer->sockaddr.sin_port = htons(port);
 //printf("\n\nIn bt_lib.c --- init_peer --- peer's ip =  and port = %s\n\n", peer->sockaddr.sin_port);
//  peer->sockaddr.sin_port = ntohs(port);
  
  return 0;

}

int init_seeder(peer_t *peer, char * id, char * ip, unsigned short port){
    
  struct hostent * hostinfo;
  //set the host id and port for referece
  int i;
  //peer->id=(char *)malloc(20*sizeof(char));
  //strcpy(peer->id,"12345");
 // printf("\n%s",peer->id);
 //   memcpy(peer->id, id, ID_SIZE);
 // strcpy(peer->id, id);
  peer->port = port;
    
  //get the host by name
  if((hostinfo = gethostbyname(ip)) ==  NULL){
    perror("gethostbyname failure, no such host?");
    herror("gethostbyname");
    exit(1);
  }
  
  //zero out the sock address
//  bzero(&(peer->sockaddr), sizeof(peer->sockaddr));
  memset(&(peer->sockaddr), 0, sizeof(peer->sockaddr));
  //set the family to AF_INET, i.e., Iternet Addressing
  peer->sockaddr.sin_family = PF_INET;
    
  //copy the address to the right place
//  peer->sockaddr.sin_addr.s_addr = inet_addr((char *)(hostinfo->h_addr));  //sin_addr = ip addr
  peer->sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  /*bcopy(inet_addr((char *) (hostinfo->h_addr)), 
        (char *) &(peer->sockaddr.sin_addr.s_addr),
        hostinfo->h_length);
    */
  //encode the port
  peer->sockaddr.sin_port = ntohs(port);
  
  return 0;

}
/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer){
  int i;

  if(peer){
    printf("peer: %s:%u ",
           inet_ntoa(peer->sockaddr.sin_addr),
           peer->port);
    printf("id: ");
    for(i=0;i<ID_SIZE;i++){
      printf("%02x",peer->id[i]);
    }
    printf("\n");
  }
}

/**
*Storing parse value of torrent 
*file in bt_info structure
**/
int parse_bt_info(bt_info_t * bt_info,struct keyValue *curr)
{
	int len1=HASH_LENGTH;
	int psize,mod,m,no;
	int i,j,k;
	char **ph;
	char *t=(char*)malloc(len1*sizeof(char*)+1);
	
	do
	{
		if(strcmp(curr->key,"announce")==0)
		{
		//	printf("\n%s",curr->key);
		//	printf("\t%s",curr->val->val_str->str);
			strcpy(bt_info->url,curr->val->val_str->str); //it copies \0
			
		}
	
			
		//printf("%s",curr->key);
		if(strcmp(curr->key,"info")==0)
		{

			if(strcmp(curr->val->val_dict->key,"length")==0)
			{
			//	printf("\n%s",curr->val->val_dict->key);
			//	printf("\t%d",atoi(curr->val->val_dict->val->val_int->int_value));
				bt_info->length=atoi(curr->val->val_dict->val->val_int->int_value);
				//printf("\n%d",bt_info->length);
			
			}
			if(strcmp(curr->val->val_dict->next->key,"name")==0)
			{
				//printf("\n%s",curr->val->val_dict->next->key);
			//	printf("\t%s",curr->val->val_dict->next->val->val_str->str);
				strcpy(bt_info->name,curr->val->val_dict->next->val->val_str->str);
			
			}
			if(strcmp(curr->val->val_dict->next->next->key,"piece length")==0)
			{
				//printf("\n%s",curr->val->val_dict->next->next->key);
			//	printf("\t%d",atoi(curr->val->val_dict->next->next->val->val_int->int_value));
				bt_info->piece_length=atoi(curr->val->val_dict->next->next->val->val_int->int_value);
			}
			
		//	printf("\n%s",curr->val->val_dict->next->next->next->key);
		
			no=curr->val->val_dict->next->next->next->val->num_value;
			//psize=no/len1;
			bt_info->num_pieces=bt_info->length/bt_info->piece_length;
			mod=bt_info->length%bt_info->piece_length;;
			if(mod>0)
			{
				bt_info->num_pieces=bt_info->num_pieces+1;
				//psize=psize+1;
			}
			bt_info->complete_hash=(char *)malloc(no*sizeof(char));
			//printf("\n whats the  value--------------->>>>%0s<<------\n",curr->val->val_dict->next->next->next->val->val_str->str);

			for(k=0;k<no;k++)
				bt_info->complete_hash[k]=curr->val->val_dict->next->next->next->val->val_str->str[k];
			bt_info->complete_hash[no]='\0';
			//for(k=0;k<no;k++)			
				//printf("%c",bt_info->complete_hash[k]);
			bt_info->piece_hashes=(unsigned char**)malloc(no*sizeof(char *)+bt_info->num_pieces);
			j=0;
			m=0;
			psize=bt_info->num_pieces;
			while(psize)
			{
				memset(t,0,5);	
 		
				for(i=0,m=j;i<20,m<j+len1;m++,i++)
					t[i]=curr->val->val_dict->next->next->next->val->val_str->str[m];
				t[i]='\0';
				
//				bt_info->piece_hashes[bt_info->num_pieces]=(char *)malloc(len1*sizeof(char*)+1);
bt_info->piece_hashes[bt_info->num_pieces-psize]=(char *)malloc(len1*sizeof(char*)+1);
				//strcpy(bt_info->piece_hashes[bt_info->num_pieces],t);
				strcpy(bt_info->piece_hashes[bt_info->num_pieces-psize],t);
				//bt_info->piece_hashes[bt_info->num_pieces-psize][len1+1]='\0';
				//printf("\n\npeice_hash%d\t%s",abs(psize-6)+1,bt_info->piece_hashes[bt_info->num_pieces]);
	//			printf("\n\npeice_hash%d\t%s",abs(psize-6)+1,bt_info->piece_hashes[bt_info->num_pieces-psize]);				
		//		for(i=0;i<20;i++)
//					printf("%02x",bt_info->piece_hashes[bt_info->num_pieces-psize][i]);					
				j=j+len1;
				psize--;
			}
			break;
		}
		else
		{
			
			curr=curr->next;
		}
	}while(curr!=NULL);

return 1;
}

//claculating hash-sha1

unsigned char *calculate_sha1(char *info)
{
	unsigned char *digest=malloc(sizeof(char)*20);//one for for no memory leak
	memset(digest,0,20);
    SHA1((unsigned char *)info, 20, digest);
	//digest[21]='\0';
	return digest; 
}
unsigned char *calculate_sha1_buff(char *info, int len)
{
	unsigned char *digest=malloc(sizeof(char)*20);//one for for no memory leak
	memset(digest,0,20);
    SHA1((unsigned char *)info, len, digest);
	//digest[21]='\0';
	return digest; 
}

//handshad=king

void initHandshake(bt_handshake *hshake,char *info, char id[])
{
	int j;
	unsigned char infoHash[20];
	
	//hshake->protocol_name=(char*)malloc(20*sizeof(char));
	strcpy(hshake->protocol_name,"19BitTorrentProtocol");
	strcpy(hshake->reserved_bytes,"00000000");
	
	SHA1(info,strlen(info),hshake->hash);
	
	memcpy(hshake->peer_id,id,20);
	
	
}	

void createInterest(bt_msg_t *smsg)
{
	
	smsg->length=1;
	smsg->bt_type=BT_INTERSTED;
	
}
	
void createRequest(bt_msg_t *msg,int index,int begin,int data)
{
	msg->length=1;
	msg->bt_type=BT_REQUEST;
	
	msg->payload.request.index=index;
	msg->payload.request.begin=begin;
	msg->payload.request.length=data;
	
}
