#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>


#include "bencode.h"




struct value * createKeyValue(char ch, FILE *fp, struct value *temp);


struct keyValue * parseTorrentFile(char *torrentFile)
{

	FILE *fp;//file pointer to read torrent file
	char ch; //variable to read character from file
	char buffer[1000],buff[10];
        int i,j,k;
        int num_int;
	char c;
	int len;
	//struct value *keyValue=(struct keyValue *)malloc(sizeof(struct keyValue));
	struct keyValue *start,*last;
	start=NULL;
	char **ph;
	
	int len1=20;
	int psize;
	int mod;
	int m;
	char *t=(char*)malloc(len1*sizeof(char*)+1);
	int no;
	//strt=NULL;
	fp=fopen(torrentFile,"r");
	if(fp==NULL)
	{
		printf("\n File does not exists");
		exit(1);
	}
	//read the file and parse it
	ch=fgetc(fp);
	//assumption torrent file starts with d->e
	while(ch!=EOF)
	{
		ch=fgetc(fp);
		//printf("\n in main:ch:%c",ch);
		if(isdigit(ch))
		{
			 c=ch;
                      	 i=0;
                         while(c!=':')
                         {
                         	buff[i]=c;
                                c=fgetc(fp);
                                i++;
                         }
                         buff[i]='\0';
                         sscanf(buff,"%d",&num_int);
                  //       printf("\n in main:Num_int:%d",num_int);
			 fread(buffer,1,num_int,fp);
                         buffer[num_int]='\0';
			 	
			// printf("\n%s",buffer);
                         
                         struct keyValue *newKey=(struct keyValue *)malloc(sizeof(struct keyValue));
                         last=start;
			 memcpy(newKey->key,buffer,num_int+1);
  			 newKey->num_value=num_int;
                         struct value *temp=(struct value *)malloc(sizeof(struct value));
                         temp=createKeyValue(ch,fp,temp);
			 
                         newKey->val=temp;
		//	 printf("\n =========>%s",newKey->val->val_str);
                         newKey->next=NULL;
                         
                         if(start==NULL)
			 {
			       start=newKey;
			 }
                         else
			 {
				while(last->next!=NULL)
					last=last->next;
				last->next=newKey;
		         }

		}
		else if(ch=='e')
		{
		//	printf("\n read complete file");
			break;
		}
		else
		{
		//	printf("\n Something went wrong");
			exit(1);
		}
	}
/*	printf("\n-------------------------------------------------");
	struct keyValue *curr,*curr2;
	//curr2=strt;
	curr=start;
	do
	{
		if(strcmp(curr->key,"announce")==0)
		{
			printf("\n%s",curr->key);
			printf("\t%s",curr->val->val_str->str);
			
		}
	
			
		//printf("%s",curr->key);
		if(strcmp(curr->key,"info")==0)
		{

			if(strcmp(curr->val->val_dict->key,"length")==0)
			{
				printf("\n%s",curr->val->val_dict->key);
				printf("\t%d",atoi(curr->val->val_dict->val->val_int->int_value));
			
			}
			if(strcmp(curr->val->val_dict->next->key,"name")==0)
			{
				printf("\n%s",curr->val->val_dict->next->key);
				printf("\t%s",curr->val->val_dict->next->val->val_str->str);
			
			}
			if(strcmp(curr->val->val_dict->next->next->key,"piece length")==0)
			{
				printf("\n%s",curr->val->val_dict->next->next->key);
				printf("\t%d",atoi(curr->val->val_dict->next->next->val->val_int->int_value));
			
			}
			
			printf("\n%s",curr->val->val_dict->next->next->next->key);
		//	curr2=curr->val->val_dict;
			//for(i=0;i<120;i++)
			//printf("------------------------");
			//printf("\n length of buffer:%d", curr->val->val_dict->next->next->next->val->num_value);
			no=curr->val->val_dict->next->next->next->val->num_value;
			psize=no/len1;
			mod=no%len1;
			if(mod>0)
				psize=psize+1;
	
			ph=(char**)malloc(120*sizeof(char *)+psize);
			j=0;
			m=0;
			while(psize)
			{
				memset(t,0,5);	
 		
				for(i=0,m=j;i<20,m<j+len1;m++,i++)
					t[i]=curr->val->val_dict->next->next->next->val->val_str->str[m];
				t[i]='\0';
				
				ph[psize]=(char *)malloc(len1*sizeof(char*)+1);
				strcpy(ph[psize],t);
				printf("\n\npeice_hash%d\t%s",abs(psize-6)+1,ph[psize]);
				j=j+len1;
				psize--;
			}
			




		
			break;
		}
		else
		{
			
			curr=curr->next;
		}
	}while(curr!=NULL);*/
	return start;
}



struct value * createKeyValue(char ch, FILE *fp,struct value *temp)
{

        char buffer[1000],buff[10];
        int i,j,k;
        int num_int;//for forming the number
        int x;
	char c;

	while(ch!=EOF)
	{
		
		//assuming file always start with dictionary
		ch=fgetc(fp);
	//	printf("\n in function:ch:%c",ch);

		switch(ch)
		{
			case 'd':
				printf("\n");
				struct keyValue *start1,*last1;
				start1=last1=NULL;				
			//	struct value *node_dict=(struct value*)malloc(sizeof(struct value));
				temp->op='d';
				temp->val_str=NULL;
				temp->val_int=NULL;
				temp->val_list=NULL;
				ch=fgetc(fp);
				while(ch!='e')
				{
					c=ch;
					
                      	 		i=0;
                         		while(c!=':')
                         		{
                         			buff[i]=c;
                                		c=fgetc(fp);
                                		i++;
                         		}
                         		buff[i]='\0';
                         		sscanf(buff,"%d",&num_int);
					temp->num_value=num_int;
                      //   		printf("\n in d mode:Num_int:%d",num_int);
			 		fread(buffer,1,num_int,fp);
                         		buffer[num_int]='\0';
			// 		printf("\n%s",buffer);
					struct keyValue *linkedlist_node=(struct keyValue *)malloc(sizeof(struct keyValue));
					last1=start1;
					memcpy(linkedlist_node->key,buffer,num_int+1);
					struct value *temp1=(struct value *)malloc(sizeof(struct value));
                         		temp1=createKeyValue(ch,fp,temp1);
					
                         		linkedlist_node->val=temp1;
                         		linkedlist_node->next=NULL;
                         
                         		if(start1==NULL)
			 		{
			       			start1=linkedlist_node;
			 		}
                         		else
			 		{
						while(last1->next!=NULL)
							last1=last1->next;
						last1->next=linkedlist_node;
		         		}

					ch=fgetc(fp);							
				}
				
				temp->val_dict=start1;
			//	strt=start1;
				return temp;				
				break;
			case 'l':
				
				break;
			case ':':
			//	printf("\n some error: in colon mode");
				break;
			case 'i':
			//	printf("\nin i mode");
			//	struct value *node_int=(struct value *)malloc(sizeof(struct value));
                                temp->op='i';
                                temp->val_str=NULL;
                                temp->val_list=NULL;
				temp->val_dict=NULL;
                                struct integer_literal *temp_int=(struct integer_literal *)malloc(sizeof(struct integer_literal));

				c=ch;
                		i=0;
                		c=fgetc(fp);
                		while(c!='e')
                		{
                        		buffer[i]=c;
                        		i++;
                        		c=fgetc(fp);
                		}
			//	printf("\n value of c in i mode:%c",c);
				temp->num_value=i;
                		buffer[i]='\0';
			//	printf("\n %s",buffer);	
                		memcpy(temp_int->int_value,buffer,i+1);
                		temp->val_int=temp_int;
				//strt=NULL;
				return temp;
                		

				break;
			case 'e':
			//	printf("e");
				break;
			default:
			//	printf("in defualt");
			//	struct value *node=(struct value *)malloc(sizeof(struct value));
				temp->op='s';
				temp->val_int=NULL;
				temp->val_list=NULL;
				temp->val_dict=NULL;
				struct string_literal *temp_struct=(struct string_literal *)malloc(sizeof(struct string_literal));

				if(isdigit(ch))
				{
					 c=ch;
                			 i=0;
                			while(c!=':')
                			{
                        			buff[i]=c;

                        			c=fgetc(fp);
                        			i++;
                			}
			                buff[i]='\0';
					sscanf(buff,"%d",&num_int);
			//                printf("\n Num_int:%d",num_int);
					
					temp->num_value=num_int;
					fread(buffer,1,num_int,fp);
					buffer[num_int]='\0';
			//		printf("\n %s",buffer);
					memcpy(temp_struct->str,buffer,num_int+1);
					temp->val_str=temp_struct;
					//for(x=0;x<=num_int-1;x++)
					///{
					//	printf("\t%d=%c",x,temp->val_str->str[x]);
			//		printf("Value 0------>:%c",temp->val_str->str[num_int-1]);
					//}
					//printf("................:%s",
				//	strt=NULL;
					return temp;

				}

					
	
				
				else
				{
	//				printf("\n Some error in file");
					exit(1);
				}
				break;
			
		}	
		
	}


}

