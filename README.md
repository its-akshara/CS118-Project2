# CS118 Project 2

## Makefile

This provides a couple make targets for things.
By default (all target), it makes the `server` and `client` executables.

It provides a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Provided Files

`server.cpp` and `client.cpp` are the entry points for the server and client part of the project.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Wireshark dissector

For debugging purposes, you can use the wireshark dissector from `tcp.lua`. The dissector requires
at least version 1.12.6 of Wireshark with LUA support enabled.

To enable the dissector for Wireshark session, use `-X` command line option, specifying the full
path to the `tcp.lua` script:

    wireshark -X lua_script:./confundo.lua

To dissect tcpdump-recorded file, you can use `-r <pcapfile>` option. For example:

    wireshark -X lua_script:./confundo.lua -r confundo.pcap

## Names of Contributers with Contributions
### Arpi Beshlikyan, 404239449
Arpi mainly worked on the client. She implemented the polling, designed the architecture of the client and worked with Melissa to implement congestion control.

### Melissa Cox, 704800126
Melissa mainly worked on the client. She also worked on the client's 3-way handshake, FIN, timers. She worked with Arpi to implement congestion control.

### Akshara Sundararajan, 404731846
Akshara implemented the entirety of the server and helped out with the client's 3 way handshake, FIN, timers. The basis of our code was from her project 1 code.

## Design of Server

We use an object called Header, and created functions to convert the byte array version of the header to an struct Header and vice versa.

We have 2 unordered_maps that store the values of the most recently sent ACK for an in order packet and the next expected sequence number from the client. The key is the connection ID.

The workflow is as follows:
- parseArguments() parses passed in arguments into an Arguments object, does correctness checking.
- Set up UDP connection by calling socket(), setReuse().
  - Needed to create server address and bind socket
  - The worker() functions sets up the environment (setupEnvironment()), then call listenForPackets() which accepts all incoming packets. Finally it closes the socket.
  - listenForPackets(): Contains main logic of the server. Divided into the following parts:
    - Receive data over UDP socket
      - Parse the header into a Header object.
        - Check for validity of packet (does it need to be dropped, is it in order)
        - If its not in order send the most recent ACK for the most recent in order packet received
	  - printPacketDetails() displays required information on output.
	    - Find out what kind of packet it is, create response accordingly
	        - If it is forming a new connection, create a SYN-ACK response, create new file and update checker for number of active connections
		    - Check if it is an ACK/has no flags, create ACK response, write payload to file if it contains a payload
		        - If it is a FIN, creacte FIN-ACK response
			  - Send response to the client and print packet details that are being sent.

## Design of Client

We use an object called Header, and created functions to convert the byte array version of the header to an struct Header and vice versa.

The workflow is as follows:
- parseArguments() parses passed in arguments into an Arguments object, does correctness checking.
- Set up the UDP connections, create server/client address, setup the connection.
- communicate(): Contains all the logic related talking to the server, from the 3-way TCP handshake to the FIN
    - printPacketDetails() displays required information on output.
    - Send the SYN until you receive a SYN ACK
    - Send the ACK to complete the 3 way handshake
    - Setup a loop for as long as the server has communicated with the client in the past 10 seconds
        - Use a map to keep track of expected ACKs mapped to the payload to be sent to the client
        - Call updateWindow() to update ssthresh and cwnd each time an ACK is received.
        - Send the packets with the payload from the file as long as the total number of bytes in the payloads across packets < CWND
        - We have a vector keeping track of UNACK'ed packets
    - Once the file is read and we receive the ACK for it, start the FIN using a timer of 2 seconds.

## Problems we ran into
Figuring out wrap around for the server was difficult. Making sure the server can account for all types of missing packets was also hard.

We had major issues implementing the client. We had issues with congestion control. Also, there were inconsistencies with the golden server/client that made it hard to predict correct behaviour.

## Additional libraries used

We used the following C/C++ headers in addition:
iostream
fstream
unordered_map
iomanip
cstdint
iostream
thread
chrono
csignal
climits

## Acknowledgements/Resources used
https://en.wikipedia.org/wiki/Go-Back-N_ARQ
https://www.geeksforgeeks.org/chrono-in-c/
Piazza saved us, thank you TAs