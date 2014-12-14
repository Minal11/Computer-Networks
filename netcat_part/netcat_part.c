/*******************************************************************************/
/*Project1: netcat_part-
Team: Minal Kondawar (mkondawa@indiana.edu) and Saketh Babu Palla (spalla@indiana.edu)
********************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/hmac.h> // need to add -lssl to compile

#define BUF_LEN 1024

/** Warning: This is a very weak supplied shared key...as a result it is not
 * really something you'd ever want to use again :)
 */
static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

/**
 * Structure to hold all relevant state
 **/
typedef struct nc_args{
	struct sockaddr_in destaddr, sourceaddr; //destination/server address
	unsigned short port; //destination/listen port
	unsigned short listen; //listen flag
	int n_bytes; //number of bytes to send
	int offset; //file offset
	int verbose; //verbose output info
	int message_mode; // retrieve input to send via command line
	char * message; // if message_mode is activated, this will store the message
	char * filename; //input/output file
}nc_args_t;


/**
 * usage(FILE * file) -> void
 *
 * Write the usage info for netcat_part to the give file pointer.
 */
void usage(FILE * file){
	fprintf(file,
		"netcat_part [OPTIONS]  dest_ip [file] \n"
	        "\t -h           \t\t Print this help screen\n"
         	"\t -v           \t\t Verbose output\n"
	 	"\t -m \"MSG\"   \t\t Send the message specified on the command line. \n"
	 	"                \t\t Warning: if you specify this option, you do not specify a file. \n"
         	"\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
         	"\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
         	"\t -o offset    \t\t Offset into file to start sending\n"
         	"\t -l           \t\t Listen on port instead of connecting and write output to file\n"
         	"                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n"
         	);
}

/**
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function use getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return results
 **/

void parse_args(nc_args_t * nc_args, int argc, char * argv[]){
	int ch;
	struct hostent * hostinfo;
  //set defaults
	nc_args->n_bytes = 0;
	nc_args->offset = 0;
	nc_args->listen = 0;
	nc_args->port = 6767;
	nc_args->verbose = 0;
	nc_args->message_mode = 0;

	while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1) 
	{
		switch (ch) {
			case 'h': //help
	      			usage(stdout);
	      			exit(0);
	      			break;
	    		case 'l': //listen
	      			nc_args->listen = 1; //it is used to indicate that the server is listening!!!
	      			break;
	    		case 'p': //port
	      			nc_args->port = atoi(optarg);
	      			break;
	    		case 'o'://offset
	      			nc_args->offset = atoi(optarg);
				break;
	    		case 'n'://bytes
				nc_args->n_bytes = atoi(optarg);
	      			break;
	    		case 'v':
	      			nc_args->verbose = 1;
	      			break;
	    		case 'm':
	      			nc_args->message_mode = 1;
				if(strlen(optarg)==0)			//check for empty message
				{
					printf("\n Empty message: Please enter some message");
					exit(1);
				}	      			
				nc_args->message = malloc(strlen(optarg)+1);
				strncpy(nc_args->message, optarg, strlen(optarg)+1);
	      			break;
	    		default:
	      			fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
	      			usage(stdout);
	      			exit(1);
		}
	}
 
	argc -= optind;
	argv += optind;
 
	if (argc < 2 && nc_args->message_mode == 0)
	{
		fprintf(stderr, "ERROR: Require ip and file\n");
		usage(stderr);
		exit(1);
	}
	else if (argc != 1 && nc_args->message_mode == 1)
	{
		fprintf(stderr, "ERROR: Require ip send/recv from when in message mode\n");
    		usage(stderr);
    		exit(1);
  	}
 
  	if(!(hostinfo = gethostbyname(argv[0])))
	{
    		fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
    		usage(stderr);
    		exit(1);
  	}

  	nc_args->destaddr.sin_family = hostinfo->h_addrtype;
  	bcopy((char *) hostinfo->h_addr,(char *) &(nc_args->destaddr.sin_addr.s_addr),hostinfo->h_length);
     	nc_args->destaddr.sin_port = htons(nc_args->port);
   
  /* Save file name if not in message mode */
  	if (nc_args->message_mode == 0) {
    		nc_args->filename = malloc(strlen(argv[1])+1);
    		strncpy(nc_args->filename,argv[1],strlen(argv[1])+1);
  	}
  return;
}


int main(int argc, char * argv[])
{

	nc_args_t nc_args;
  	int sockfd, clientfd; 
  	char input[BUF_LEN];//Input buffer for holding actual data content at client side.
  	char serverinput[BUF_LEN]; //buffer for holding the ultimate data to be written into the output file
  	char receivedinput[BUF_LEN]; //buffer at the server side to receive the data sent from client side
  	char receivedinput_dup[BUF_LEN]; //duplicate buffer for holding the copy of received_input while tokenizing it

  	unsigned int len;	
  	FILE *outputptr;	//for outfile file
  	FILE *readptr;		//for input file

  	char *token;
	char ch;		
  	char clientch;

  	unsigned int memory_reserved_for_data, data_length;
  	unsigned char *chash;
  	unsigned int chashlen;
  
  	int filesize;

  	char cdigest[41]; //length of the sha1 digest * 2 + 1 ('\0')
  	char sdigest[41]; //length of the sha1 digest * 2 + 1 ('\0')
  	char clientdigest[41]; //server side buffer to hold the digest received from the client

   	char data_to_be_sent[BUF_LEN];
   	int packet_count, pindex; //pindex = packet index
   	int end_ind;
  	unsigned char *shash;
  	unsigned int shashlen;

  	int count = 0;
  	int i,j,k;
  	int off;
  	unsigned int c_ind = 0, s_ind = 0; //indices for traversing client side and server side buffer.
  	int received_msg_size;
  	int bytes_sent;
  	int bytes_read = 0;


  	//initializes the arguments struct for your use
 	 parse_args(&nc_args, argc, argv);


 	//Server Side
	if(nc_args.listen == 1) 
	{
    		if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
    		{
   			perror("Socket:");
			exit(1);
    		}
		else
		{
			if(nc_args.verbose != 0)	//verbose mode
				printf("\nCreated socket successfully............");
		}
		
		len=sizeof(struct sockaddr_in);
      		if((bind(sockfd,(struct sockaddr *)&nc_args.destaddr,len))==-1)
      		{
 	     		perror("Bind:");
			exit(1);
      		}
		else
		{
			if(nc_args.verbose != 0)	//verbose mode
				printf("\nAssigned IP and Port to socket successfully............");
		}
      		if((listen(sockfd,1))==-1) 
      		{
 	     		perror("listen:");
             		exit(1);
      		}
		else
		{
			if(nc_args.verbose != 0)	//verbose mode
				printf("\nListening state: Waiting for connection............");
		}	
      		while(1)
      		{
	    		if((clientfd=accept(sockfd,(struct sockaddr *)&nc_args.sourceaddr,&len))==-1)
            		{
	            		perror("Accept:");
                    		exit(0);
            		} 
			else
			{
				if(nc_args.verbose != 0)	//verbose mode
					printf("\nAccepting user connection............");
			} 
          
	   		outputptr = fopen(nc_args.filename, "w+"); //output file
	   		pindex = 0;
	   		while(received_msg_size = recv(clientfd, receivedinput, BUF_LEN, 0)) //Received data from client is stored in receivedinput buffer
	   		{	   
	
		  		memset(serverinput, 0, BUF_LEN);
		  		 
		  		memset(clientdigest, 0, 41); //Initializing the client digest value with zeroes
				if(nc_args.verbose != 0)						  		
					printf("\n%d bytes data received.......", received_msg_size);
		  
		  		strcpy(receivedinput_dup, receivedinput); //Duplicate buffer holding a copy of received data
		  		receivedinput_dup[strlen(receivedinput_dup)] = '\0';
		  		  			  
		  		token = strtok(receivedinput_dup, "|"); //extracts the actual message data
		  		strcpy(serverinput, token); //copying the actual message data to serverinput buffer
		  		serverinput[strlen(serverinput)] = '\0';
		  		  		
		  		token = strtok(NULL, "|"); 	      //extracts the digest embedded in the client's packet
		  		strcpy(clientdigest, token); //storing the received digest in clientdigest buffer which is to be compared by the server's digest
		  		
		  		clientdigest[strlen(clientdigest)] = '\0';
		  		shash = HMAC(EVP_sha1(), key, strlen(key), (unsigned char *)serverinput, strlen(serverinput),  NULL, NULL);	
	 
		  		for(i = 0; i < 20; i++)
		  		{
	         			sprintf(&sdigest[i*2], "%02x", (unsigned int)shash[i]); 
		  		} 
		   		
		  		if(strcmp(clientdigest, sdigest) == 0)		//comparing the digest 
				{ 

		  			s_ind=0;
					do	   	 		//writing to output file
		  			{		
						ch = serverinput[s_ind];
						fputc(ch, outputptr);
						s_ind++;
					}while(s_ind<=strlen(serverinput));
	   
				}
		   		else
		   		{
					printf("\nOperation Failed: Due to Bad Digest");
					close(clientfd);
					fclose(outputptr);
					exit(1);
		   		}

	     		}
			printf("\nSuccessfully data written in the file..:)");
	     
					
	     		close(clientfd);
			fclose(outputptr);

	   		if((received_msg_size = recv(clientfd, receivedinput, BUF_LEN, 0)) <0)
  	     		{
				exit(1);
             		}

			
		}//end of while
	}//end of listen mode
	
	//Client side
	else  	
	{
		if((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		{
			perror("Client Socket creation failed!");
			exit(1);
		}
		else
		{
			if(nc_args.verbose != 0)	//verbose mode
				printf("\nCreated socket successfully............");
		}

	
		memory_reserved_for_data = BUF_LEN - 44;	//40-digest 1-'\0' "|" -2 bytes 1-\0
	
		if(nc_args.message_mode == 1) //message mode
		{	 
			off = nc_args.offset;
			if(off>=strlen(nc_args.message) || off<0) //If offset exceeds the message length (or) less than 0
			{
				printf("\n offset value should be range between 0 and message length");
				exit(1);
			}
			if(nc_args.n_bytes<0) //If number of bytes is less than 0
			{
				printf("\n No of bytes cannot be negative");
				exit(1);
			}
			
			if((connect(sockfd, (struct sockaddr *) &nc_args.destaddr, sizeof(nc_args.destaddr))) < 0)
			{
				perror("socket connection failed!");
				exit(1);
			}
			else
			{
				if(nc_args.verbose != 0)	//verbose mode
					printf("\nMade TCP Connection to Server............");
			}
			if(nc_args.n_bytes == 0||nc_args.n_bytes>strlen(nc_args.message)) //If the number of bytes is equal to 0 (or) greater than the length of messsage
		 	{
				nc_args.n_bytes = strlen(nc_args.message) - nc_args.offset;
		 	}
		 	packet_count= (nc_args.n_bytes/memory_reserved_for_data) + 1;
		 	if(nc_args.verbose != 0)	
				printf("\n\nTotal number of packets sent: %d", packet_count);
		 	for(pindex = 0; pindex < packet_count; pindex++)
		 	{
				c_ind = 0;
				memset(input, 0, BUF_LEN);
				if(pindex == packet_count - 1) //Last packet
				{
					while(off < (nc_args.n_bytes+nc_args.offset) && c_ind <= memory_reserved_for_data)
					{
						input[c_ind++] = nc_args.message[off++];
					}
				}
				else //All but last packets
				{
					while(c_ind <= memory_reserved_for_data) //Store the data in the input buffer occupying just the memory reserved for the actual data
					{
						input[c_ind++] = nc_args.message[off++];
					}

				}
				input[c_ind]= '\0';
				chash = HMAC(EVP_sha1(), key, strlen(key), (unsigned char *)input, c_ind, NULL, NULL);
				for(i = 0; i < 20; i++)
                        	{
                          		sprintf(&cdigest[i*2], "%02x", (unsigned int)chash[i]);
                        	}

				//Storing the actual data and digest coupled with the delimiter(|) in the final data_to_be_sent buffer
				strcpy(data_to_be_sent, input);
				strcat(data_to_be_sent, "|");
				strcat(data_to_be_sent, cdigest);
			
				data_length = c_ind + sizeof("|") + 40 + 1;
				
				data_to_be_sent[data_length] = '\0';

				//sending the final data_to_be_sent buffer to the server
				bytes_sent = send(sockfd, data_to_be_sent, data_length, 0);
				if(nc_args.verbose != 0)		
					printf("\nTotal number of bytes_sent =  %d\n", bytes_sent);
				if(bytes_sent != data_length)
				{
					perror("client send() failed:");
					exit(1);
				}
		 	}
		 	printf("\nData Sent Successfully!!!!!!!!!");

		}//end of message mode
		else //file mode
		{	
			readptr = fopen(nc_args.filename, "r");
			if(readptr==NULL)
			{
				printf("\nFile does not exist");
				printf("\n Please create the file before using it");
				exit(1);
			} 

			//seeking the file pointer to the end to determine its size
			fseek(readptr, 0, SEEK_END);
			filesize = ftell(readptr);

			if(filesize<=0)
			{
				printf("\n Empty file: Please add some content in it");
				exit(1);
			}
			if(nc_args.offset>filesize || nc_args.offset<0) //If the offset exceeds the file size or is less than 0
			{
				printf("\n Offset should be in range of 0-file size");
				exit(1);
			}
			if(nc_args.n_bytes<0) //If the number of bytes is negative
			{
				printf("\n No of bytes cannot be negative");
				exit(1);
			}
			
			//connect statemnt
			if((connect(sockfd, (struct sockaddr *) &nc_args.destaddr, sizeof(nc_args.destaddr))) < 0)
			{
				perror("socket connection failed!");
				exit(1);
			}
			else
			{
				if(nc_args.verbose != 0)	//verbose mode
					printf("\nMade TCP Connection to Server............");
			}

			
			//seeking the file pointer to the given offset value from the beginning
			fseek(readptr, nc_args.offset, SEEK_SET); 
		
			//If the number of bytes is 0 (or) exceeds the file size
			if(nc_args.n_bytes == 0 || nc_args.n_bytes>filesize)
			{
		  		nc_args.n_bytes = filesize - nc_args.offset;
		  	}

			
			//seeking the file pointer to n_bytes position from the current position(offset) to determine the end of the required content (when -o and -n options are enabled)
			fseek(readptr, nc_args.n_bytes, SEEK_CUR);
			end_ind = ftell(readptr); 

			fseek(readptr, nc_args.offset, SEEK_SET); //seeking the pointer back to offset position
			packet_count = (nc_args.n_bytes / memory_reserved_for_data) + 1;//Total number of packets for the current file size
			if(nc_args.verbose != 0)
				printf("\n\n Total no of packets sent:%d", packet_count);
			bytes_read = nc_args.offset; //incrementing the counter from the offset value
			for(pindex = 0; pindex < packet_count; pindex++)
			{//Iterating through each packet
				c_ind = 0; 
				memset(input, 0, BUF_LEN);
				clientch = fgetc(readptr);
				if(pindex == packet_count - 1) //Last packet
				{	
										
					while(bytes_read < end_ind)
					{
						input[c_ind++] = clientch;
						clientch = fgetc(readptr);
						bytes_read++;
					}
					
				}
				else //all but last packet
				{
					while(c_ind <= memory_reserved_for_data) //writing the data into input buffer occupying just memory_reserved_for_data bytes 
					{
						input[c_ind++] = clientch;
						clientch = fgetc(readptr);
					}
				}

				input[c_ind] = '\0'; //Now, c_ind holds the length of 'input' array
				chash = HMAC(EVP_sha1(), key, strlen(key), (unsigned char *)input, c_ind, NULL, NULL);
				for(i = 0; i < 20; i++)
		        	{
		          		sprintf(&cdigest[i*2], "%02x", (unsigned int)chash[i]);
		        	}

				//storing the actual data and digest coupled using a delimiter(|) in the final data_to_be_sent buffer
				strcpy(data_to_be_sent, input);
				strcat(data_to_be_sent, "|");
				strcat(data_to_be_sent, cdigest);
				data_length = c_ind + sizeof("|") + 40 + 1;
				data_to_be_sent[data_length] = '\0';

				//sending the final data_to_be_sent buffer to the server
				bytes_sent = send(sockfd, data_to_be_sent, data_length, 0);
				if(bytes_sent != data_length)
				{
					perror("send() failed:");
					exit(1);
				}
				if(nc_args.verbose != 0)		
					printf("\nPacket %d: Total number of bytes sent = %d\n",pindex+1, bytes_sent);
				bytes_read += c_ind;
			} //End of packets' iteration loop	
			printf("Data sent successfully :)\n");
			fclose(readptr);
		}//end of else (file mode)

 
		close(sockfd);
		exit(0);
	
	}	
  return 0;
}





