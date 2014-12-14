Project 1: Socket Programming-netcat_part
---------------------------------------------
Name: Minal Ganesh Kondawar
uname: mkondawa

Name: Saketh Babu Palla
uname: spalla
----------------------------------------------

We have implemented client side and server side functionality in a single file (called netcat_part.c). Hence, based on the options provided at the command line, it behaves as either server or client. The basic workflow of our code is as follows: 

netcat_part as a server:

It just keeps listening for the incoming connection requests(on either default port or the one specified at the command line) from the clients and once the connection is established, it starts recieving data from the client and extracts the actual message part of it and digest and stores them in serverinput buffer and clientdigest buffer respectively before actually storing in the file specified at the command line. After calculating the digest(sdigest) for the extracted message, it compares both the digests and only if matched, it stores it in the output file and closes the connection. (And it can handle only upto 1 client. For a new client, it should be restared.)

netcat_part as a Client:

Based on the specified mode(message mode or file mode) and the offset and number of bytes values, it sends the approriate content to the server along ­with the calculated digest (cdigest)(seperated by a delimiter)via data_to_be_sent buffer. The memory distribution of this buffer is memeory_reserved_for_data(for holding the actual message data without digest) + 40 (size of the calculated digest value) + 4(size of delimiters and null termination characters). Also, maximum size of each packet is 1024 bytes (BUF_LEN). We are sending hash value on per-packet basis.

And we are not sending hash length value to the server, because, in our code, both uses the same hashing algorithm for which hashlength is fixed. 

Tasks Accomplished:

We were able to perform all the tasks mentioned in the instruction file. Also, we have implemented extreme cases like 'empty file', 'empty message', 'no file', 'offset and number of bytes exceeding file size' and ‘negative value of offset and number of bytes’.

To compile:
Run the makefile using make command

To execute as a server:
./netcat [-p <port number>] -l <Destination address> <outputfile>

To execute as a client: (Different permutations of the following)
./netcat [-v] [-p <port number>][-o <offset>] [-n <n_bytes>] [-m <message>] <Destination address> [file name]



For example: 
Server:
./netcat_part  -l localhost output.txt

Client:
./netcat_part localhost alphabet.txt

Interpreting the output:
After running valid command line commands as shown above, the contents from the client side gets transferred to file at the server. So, after the completion of execution, the output file at the server should contain the data(without digest) based on the offset and n_bytes values.

If verbose option is selected, our code walks through the entire process in a verbose manner on the command line. It displays the number of bytes sent/received on per–packet basis (which includes actual data size, hash size, delimiter and the null terminator).

Submitted Files: 
The files we submitted are 
netcat_part.c source code
Readme File
MakeFile: It cleans the directory and compiles the source code.
Individual write-ups




