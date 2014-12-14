#ifndef _BENCODE_H
#define _BENCODE_H

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>

#include "bencode.h"

//struct value * createKeyValue(char ch, FILE *fp,struct value *temp,struct keyValue*);
//integer i3748475e
struct integer_literal
{
	
	char int_value[1000];
};
//string 4:spam 
struct string_literal
{
	
	char str[1000];
};
//list l--->e can contain integer and string
struct list_literal
{
	char list_op;
	struct integer_literal *list_int;
	struct string_literal *list_str;
	struct list_literal *list_list;
};
//dict d--->e can contain list integer and string and itself


struct value
{
	char op;
	int num_value;
	struct integer_literal *val_int;
        struct string_literal *val_str;
        struct list_literal *val_list;
        struct keyValue *val_dict;
};
 struct keyValue
{
	char key[1000];
	int num_value;
	struct value *val;
	struct keyValue *next;
};

struct keyValue * parseTorrentFile(char *torrentFile);

#endif
