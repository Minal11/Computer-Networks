Project 2: Bittorrent Client

Name: Minal Kondawar
uname: mkondawa

Name:Saketh Babu Palla
uname:spalla

Task Accomplished
1 Seeder and 1 Leeched
Build a client that can implement the standard client protocol such a single seeder can transfer a file to a single leecher
1. Parsed the torrent files 
2. Implemented Handshake protocol
3. Reading and writing peice blocks from files using randomization
Files
bt_client.c : Main code file which perform all the activities for Bit Torrent Protocol
bt_lib.c : Contains all the helper functions to implement BitTorrent Client
bt_setup.c: Parses the all argument and store in bt_args structure
bencode.c: Parses torrent file
*.log:  (mylog1.log for the seeder and mylog.log for the leecher)Holds the Logging information
Compile:
gcc -g -lssl bt_client.c bt_lib.c bt_setup.c bencode.c–o bt_client
Execute
Seeder
./bt_client –v –b localhost:2334 moby_dick.txt.torrent –l mylog1.log
Leecher
./bt_client –v –p localhost:2334 moby_dick.txt.torrent –l mylog.log
Output
Displays the progress of downloading and uploading.


