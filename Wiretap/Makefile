CC = g++

OPTS1 = lpcap

OPTS2 = o

all: clean compile

clean:
	rm -f *.o *.out *~

compile: wiretap.cpp
	$(CC) -$(OPTS1) wiretap.cpp  -$(OPTS2) wiretap

