CC = gcc

OPTS1 = lssl

OPTS2 = o

all: clean compile

clean:
	rm -f *.o *.out *~

compile: netcat_part.c
	$(CC) -$(OPTS1) netcat_part.c -$(OPTS2) netcat_part
		

