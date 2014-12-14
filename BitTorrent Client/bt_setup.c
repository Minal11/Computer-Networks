#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include "bt_setup.h"
#include "bt_lib.h"


/**
 * usage(FILE * file) -> void
 *
 * print the usage of this program to the file stream file
 *
 **/
int j;
void usage(FILE * file){
  if(file == NULL){
    file = stdout;
  }

  fprintf(file,
          "bt-client [OPTIONS] file.torrent\n"
          "  -h            \t Print this help screen\n"
          "  -b ip         \t Bind to this ip for incoming connections, ports\n"
          "                \t are selected automatically\n"
          "  -s save_file  \t Save the torrent in directory save_dir (dflt: .)\n"
          "  -l log_file   \t Save logs to log_filw (dflt: bt-client.log)\n"
          "  -p ip:port    \t Instead of contacing the tracker for a peer list,\n"
          "                \t use this peer instead, ip:port (ip or hostname)\n"
          "                \t (include multiple -p for more than 1 peer)\n"
          "  -I id         \t Set the node identifier to id (dflt: random)\n"
          "  -v            \t verbose, print additional verbose info\n");
}

/**
 * __parse_peer(peer_t * peer, char peer_st) -> void
 *
 * parse a peer string, peer_st and store the parsed result in peer
 *
 * ERRORS: Will exit on various errors
 **/

void __parse_peer(peer_t * peer, char * peer_st){
  char * parse_str;
  char * word;
  unsigned short port;
  char * ip;
  unsigned char id[20];
  unsigned char idHash[20];
  char sep[] = ":";
  int i;

  
  //need to copy becaus strtok mangels things
  parse_str = malloc(strlen(peer_st)+1);
  strncpy(parse_str, peer_st, strlen(peer_st)+1);

  //only can have 2 tokens max, but may have less
  for(word = strtok(parse_str, sep), i=0; 
      (word && i < 3); 
      word = strtok(NULL,sep), i++){

    printf("%d:%s\n",i,word);
    switch(i){
    case 0://id
      ip = word;
      break;
    case 1://ip
      port = atoi(word);
    default:
      break;
    }

  }

  if(i < 2){
    fprintf(stderr,"ERROR: Parsing Peer: Not enough values in '%s'\n",peer_st);
    usage(stderr);
    exit(1);
  }

  if(word){
    fprintf(stderr, "ERROR: Parsing Peer: Too many values in '%s'\n",peer_st);
    usage(stderr);
    exit(1);
  }


  //calculate the id, value placed in id
  calc_id(ip, port, id);
 /* calc_id(ip,port,idHash);
  for(j = 0; j < 20; j++)
  {
      sprintf(&id[j], "%x", idHash[j]);
  }
  */
  id[20] = '\0';
  
//  strncpy(peer->id, id, sizeof(id));
  
 
 // peer->id[20]='\0';
 // printf("\nLeecher's id in __parse_peers  = %s or %s \nand formmated value= ", id, peer->id);
/*  for(j = 0; j < 20; j++)
  {
   printf("%x", peer->id[j]);
  } 
*/
  //build the object we need
  init_peer(peer, id, ip, port);
  
  //free extra memory
  free(parse_str);

  return;
}

/**
 * pars_args(bt_args_t * bt_args, int argc, char * argv[]) -> void
 *
 * parse the command line arguments to bt_client using getopt and
 * store the result in bt_args.
 *
 * ERRORS: Will exit on various errors
 *
 **/
void parse_args(bt_args_t * bt_args, int argc,  char * argv[]){
  int ch; //ch for each flag
  int n_peers = 0;
  int i;
  unsigned char seederId[20];
  char *seedIpDeflt = "localhost";
  bt_args->seedIp = (char *)malloc(strlen(seedIpDeflt)*sizeof(char));

//Storing the default value in seeder's address field
  strcpy(bt_args->seedIp, seedIpDeflt);
  /* set the default args */
  bt_args->verbose=0; //no verbosity
  
  //null save_file, log_file and torrent_file
  memset(bt_args->save_file,0x00,FILE_NAME_MAX);
  memset(bt_args->torrent_file,0x00,FILE_NAME_MAX);
  memset(bt_args->log_file,0x00,FILE_NAME_MAX);
  
  //null out file pointers
  bt_args->f_save = NULL;

  //null bt_info pointer, should be set once torrent file is read
  bt_args->bt_info = NULL;

  //default lag file
  strncpy(bt_args->log_file,"bt-client.log",FILE_NAME_MAX);
  
  for(i=0;i<MAX_CONNECTIONS;i++){
    bt_args->peers[i] = NULL; //initially NULL
  }

  bt_args->id = 0;
  
  while ((ch = getopt(argc, argv, "hp:s:l:vI:b:")) != -1) {
    switch (ch) {
    case 'h': //help
      usage(stdout);
      exit(0);
      break;
    case 'b':
		bt_args->b=1;
		bt_args->peers[0] = malloc(sizeof(peer_t));

      //parse peers
      __parse_peer(bt_args->peers[0], optarg);
/*//      bt_args.bindingAddress = (char *)malloc(sizeof(optarg));
//     strncpy(bt_args.bindingAddress, optarg, sizeof(optarg));
      bt_args->mode = 0; //seeder mode
      strncpy(bt_args->seedIp, optarg, sizeof(optarg));
//      bt_args->seeder = malloc(sizeof(peer_t));
//      __parse_peer(bt_args->seeder, optarg);
      calc_id(optarg, SEEDER_PORT, seederId);
      strncpy(bt_args->seederId, seederId, sizeof(seederId));
      printf("\nseeder's id = ");
      for(j = 0; j < 20; j++)
      {
	printf("%x", seederId[j]);
      }
     // calc_id(optarg, 6790, seederId);
//      init_seeder(bt_args->seeder, seederId, optarg, 6768); //optarg = ip addressi, port = 6768
    //  init_peer(bt_args->seeder, seederId,  optarg, 6767); //optarg = ip addressi, port = 6767
     */ break;
    case 'v': //verbose
      bt_args->verbose = 1;
      break;
    case 's': //save file
      strncpy(bt_args->save_file,optarg,FILE_NAME_MAX);
	  bt_args->smode = 1;
      break;
    case 'l': //log file
		bt_args->lmode=1;
      strncpy(bt_args->log_file,optarg,FILE_NAME_MAX);
      break;
    case 'p': //peer
      n_peers++;
      bt_args->peerCount = n_peers;
      bt_args->mode=1;//Leecher mode
      //check if we are going to overflow
      if(n_peers > MAX_CONNECTIONS){
        fprintf(stderr,"ERROR: Can only support %d initial peers",MAX_CONNECTIONS);
        usage(stderr);
        exit(1);
      }

      bt_args->peers[n_peers] = malloc(sizeof(peer_t));

      //parse peers
      __parse_peer(bt_args->peers[n_peers], optarg);
      break;
    case 'I':
      bt_args->id = atoi(optarg);
      break;
    default:
      fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
      usage(stdout);
      exit(1);
    }
  }


  argc -= optind;
  argv += optind;

  if(argc == 0){
    fprintf(stderr,"ERROR: Require torrent file\n");
    usage(stderr);
    exit(1);
  }

  //copy torrent file over
  strncpy(bt_args->torrent_file,argv[0],FILE_NAME_MAX);

  return ;
}

