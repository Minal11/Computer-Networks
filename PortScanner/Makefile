CC = g++

OPTS1 = o

OPTS2 = lpcap

OPTS3 = lpthread

all: clean compile

clean:
	rm -f *.o *.out *~

compile: portScanner.cpp
	$(CC) -$(OPTS2) -$(OPTS3) portScanner.cpp -$(OPTS1) portScanner
