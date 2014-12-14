CC = gcc

OPTS1 = lssl

OPTS2 = o

all: clean compile

clean:
	rm -f *.o *.out *~

compile: bt_client.c bt_lib.c bt_setup.c bencode.c
	$(CC) -$(OPTS1) bt_client.c bt_lib.c bt_setup.c bencode.c -$(OPTS2) bt_client
