---------------------------
Krupa Tadepalli | krtadepa
Sreeja Ketineni | vketinen
---------------------------
-----------------------
BitClient Programming : 
-----------------------

Includes details on the following file :


bt_client.c
--------------

Descrption:
------------

The objective of this assignment is to utilize the BitTorrent protocol and develop a peer-to-peer file sharing system. For this project, we use the guidelines given in lab3.doc and implement the protocol.

Tasks:
------

1. To implement bt_client.c as a seeder, leecher. 
2. Start the seeder.
3. Start the leecher in another system, download based on the torrent

Additonal Tasks:
1. Multiple clients can download from the seeder simultaneously.

Compilation & Execution : 
--------------------------

1. Log into the burrow system
2. Open terminal, navigate to the respective directory.
3. Type : make (this will compile the program and create bt_client object file)
4. For uniqueness sake and avoid connection issues with others the port 4646 has been choosen to host the seeder on the host machine.

   4.1. As a seeder:
        1. Login into any of the CS machine,for example silo.
		2. Navigate to the folder where bt_client object file is present
		3. $./bt_client moby_dick.txt.torrent        
       
     The above steps initialize the seeder and wait for incoming connections to be served. If the seeder has the torrent file leecher is 
     requesting then start transferring the contents of the file.
    
   4.2 As a leecher
        1. Login into the machine,for example dacite.
		2. Navigate to the folder where torrent file, bt_client object files are present
		3. $./bt_client -p silo:4646 -s dwnload_moby.txt moby_dick.txt.torrent      
	
	This will start communication with the seeder and start downloading the file. After the file is downloaded to the local machine, SHA1 is computed, verified with the SHA1 information present in the torrent file.
	
	Another leecher can be simultaneously started in some other system, executing the commands similarly. The seeder has capability to server multiple requests simultaneously. 

    	
	
   Interpretation of Result:
	-------------------------
        1. The seeder has only one functionality, i.e. to accept connections from the incoming peers and send the data requested.
        2. In the current project the leecher will only be able to download file from the seeder and store it in its local space.
		3. The project also implements restarts, i.e. if a client closes its connection unexpectedly; the state information is stored. When 
		   the client is restarted, this information is used to start downloading the file from the last left piece.
		
		
