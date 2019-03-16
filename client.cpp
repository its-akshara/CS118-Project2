#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <list>
#include <iterator>

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>
#include <chrono>
#include <string>
#include <climits>

using namespace std;

const int NUMBER_OF_ARGS = 3;
const int DATA_SIZE = 512;
const int HEADER_SIZE = 12;
const int PACKET_SIZE = HEADER_SIZE + DATA_SIZE;

const int NUM_MASK1 = 0xff000000;
const int NUM_MASK2 = 0x00ff0000;
const int NUM_MASK3 = 0x0000ff00;
const int NUM_MASK4 = 0x000000ff;
const int NUM_RIGHT_OFFSET1=24;
const int NUM_RIGHT_OFFSET2=16;
const int NUM_RIGHT_OFFSET3=8;
const long CONN_MASK =0xffff0000;
const int CONN_RIGHT_OFFSET = 16;
const int ACK_MASK = 4;
const int ACK_OFFSET = 2;
const int SYN_MASK = 2;
const int SYN_OFFSET = 1;
const int FIN_MASK = 1;
const int FLAG_POS = 11;

struct Header
{
  uint32_t sequenceNumber;
  uint32_t acknowledgementNumber;
  uint16_t connectionID;
  bool ACKflag;
  bool SYNflag;
  bool FINflag;
};

int32_t getFlags(bool ACKflag, bool SYNflag, bool FINflag)
{
  return ((ACKflag<<ACK_OFFSET))|((SYNflag<<SYN_OFFSET))|(FINflag);
}

// returns a 96 bit(12 byte) array representing the TCP header
void convertHeaderToByteArray(Header h, char header[HEADER_SIZE])
{
  memset(&header[0], 0, HEADER_SIZE);
  uint32_t seqNetwork = htonl(h.sequenceNumber);
  uint32_t ackNetwork = (htonl(h.acknowledgementNumber));
  //an int representing the third 'row' of the header
  uint16_t connNetwork = htons(h.connectionID);
  uint16_t ASFNetwork = htons(getFlags(h.ACKflag,h.SYNflag,h.FINflag));
  memcpy(header, (char *)&seqNetwork, sizeof(uint32_t));
  memcpy(header+4, (char *)&ackNetwork, sizeof(uint32_t));
  memcpy(header+8, (char *)&connNetwork, sizeof(uint16_t));
  memcpy(header+10, (char *)&ASFNetwork, sizeof(uint16_t));
}

uint32_t getValueFromBytes(char *h, int index)
{
  return ntohl(((h[index])<<NUM_RIGHT_OFFSET1)|((h[index+1])<<NUM_RIGHT_OFFSET2)|((h[index+2])<<NUM_RIGHT_OFFSET3)|(h[index+3]));
}

Header convertByteArrayToHeader(char *h)
{
  Header res;
  res.ACKflag = h[FLAG_POS]&ACK_MASK;
  res.SYNflag = h[FLAG_POS]&SYN_MASK;
  res.FINflag = h[FLAG_POS]&FIN_MASK;

  memcpy(&res.sequenceNumber, (uint32_t *)h, sizeof(uint32_t));
  memcpy(&res.acknowledgementNumber, (uint32_t *)&h[4], sizeof(uint32_t));
  memcpy(&res.connectionID, (uint16_t *)&h[8], sizeof(uint16_t));

  res.acknowledgementNumber = ntohl(res.acknowledgementNumber);
  res.connectionID = ntohs(res.connectionID);
  res.sequenceNumber = ntohl(res.sequenceNumber);

  return res;
}

struct Arguments
{
  int port;
  string host;
  string filename;
};

enum msgType{RECV,SEND,DROP};

void printUsage()
{
  cerr<< "USAGE: ./client <HOSTNAME-OR-IP> <PORT> <FILENAME>\n";
}

void printError(string message)
{
  cerr<<"ERROR: ";
  cerr<< message <<endl;
}

void exitOnError(int sockfd)
{
  close(sockfd);
  exit(1);
}

Header createFIN(Header ack)
{
  Header FIN;
  FIN.acknowledgementNumber = 0;
  FIN.connectionID = ack.connectionID;
  FIN.ACKflag = 0;
  FIN.SYNflag = 0;
  FIN.FINflag = 1;
  FIN.sequenceNumber = ack.acknowledgementNumber;

  return FIN;
}

sockaddr_in createServerAddr(const int port, const string IP)
{
  sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);     // short, network byte order
  serverAddr.sin_addr.s_addr = inet_addr(IP.c_str());
  memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));
  return serverAddr;
}

sockaddr_in createClientAddr(const int sockfd)
{
  struct sockaddr_in clientAddr;
  socklen_t clientAddrLen = sizeof(clientAddr);
  if (getsockname(sockfd, (struct sockaddr *)&clientAddr, &clientAddrLen) == -1)
    {
      printError("getsockname() failed.");
      exitOnError(sockfd);
    }
  return clientAddr;
}

void connectionSetup(const struct sockaddr_in clientAddr)
{
  char ipstr[INET_ADDRSTRLEN] = {'\0'};
  inet_ntop(clientAddr.sin_family, &clientAddr.sin_addr, ipstr, sizeof(ipstr));
}

void printPacketDetails(Header packet_header, msgType type, uint32_t cwnd, uint32_t ssthresh, bool dup=false)
{

  if(type==DROP)
    cout<<"DROP ";
  else if(type==RECV)
    cout<<"RECV ";
  else
    cout<<"SEND ";

  cout<<packet_header.sequenceNumber<<" "<<packet_header.acknowledgementNumber<<" "<<packet_header.connectionID<<" "<<cwnd<<" "<<ssthresh;

  if(packet_header.ACKflag)
    cout<<" "<<"ACK";
  if(packet_header.SYNflag)
    cout<<" "<<"SYN";
  if(packet_header.FINflag)
    cout<<" "<<"FIN";
  if(type==SEND && dup)
    cout<<" DUP";

  cout<<endl;
}

Header createFinalACK(Header ack)
{
  Header h;
  h.ACKflag = 1;
  h.acknowledgementNumber = ack.sequenceNumber+1;
  h.sequenceNumber = ack.acknowledgementNumber;
  h.FINflag = 0;
  h.SYNflag = 0;
  h.connectionID = ack.connectionID;
  return h;
}

void updateWindow(uint32_t &cwnd, uint32_t &ssthresh){
  if (cwnd < ssthresh)
  {
    cwnd += 512;
  }
  else  /*  cwnd >= ssthresh  */
  {
    cwnd += (512*512)/cwnd;
  }
  //cout << "\ncwnd: "<<cwnd<<" | ssthresh: " <<ssthresh<<endl;
}

void communicate(const int sockfd, const string filename, struct sockaddr_in serverAddr)
{
  //------------ SYN Handshaking ------------//

  uint16_t connexID = 0;
  uint32_t cwnd = 512;
  uint32_t ssthresh = 10000;

  Header clientSYN;
  clientSYN.sequenceNumber = 12345;
  clientSYN.acknowledgementNumber = 0;
  clientSYN.connectionID = connexID;
  clientSYN.ACKflag = 0;
  clientSYN.SYNflag = 1;
  clientSYN.FINflag = 0;

  char c_SYN[HEADER_SIZE] = {0}; //holds SYN to send to server
  convertHeaderToByteArray(clientSYN, c_SYN);

  int rec_res = 0;
  char c_SYNACK[HEADER_SIZE] = {0}; // holds SYN ACK received from server
  Header serverSYNACK;

  socklen_t serverAddrLen = sizeof(serverAddr);

  //Polling stuff
  bool receivedSYNACK = false;
  struct pollfd fds;
  int timeout_msecs = 500;
  bool isSYN_DUP = false;

  fds.fd = sockfd;
  fds.events = POLLIN;

  while (!receivedSYNACK)
  {
    //--- Send SYN ---//
    if (sendto(sockfd, c_SYN, HEADER_SIZE, 0, (const sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
      printError("Unable to send SYN header to server");
      exitOnError(sockfd);
    }
    printPacketDetails(clientSYN, SEND, cwnd, ssthresh);

    //--- Wait for SYN ACK ---//
    poll(&fds, 1, timeout_msecs);
    if (fds.revents != 0)         // An event on sockfd has occurred.
    {
      rec_res = recvfrom(sockfd, c_SYNACK, HEADER_SIZE, 0, (struct sockaddr *)&serverAddr,&serverAddrLen);
      if (rec_res == -1)
      {
        printError("Error in receiving SYN ACK from server");
        exitOnError(sockfd);
      }
      if(rec_res > 0)
      {
          serverSYNACK = convertByteArrayToHeader(c_SYNACK);
          if (serverSYNACK.ACKflag && serverSYNACK.SYNflag && !serverSYNACK.FINflag)
          {
              receivedSYNACK = true;
              connexID = serverSYNACK.connectionID;
              printPacketDetails(serverSYNACK, RECV, cwnd, ssthresh);
              break;
          }
      }
    }
    //-----------------------//

    isSYN_DUP = true;
  }

  //--- Send ACK for SYN ACK ---//
  Header clientSYNACK_ACK;
  clientSYNACK_ACK.sequenceNumber = serverSYNACK.acknowledgementNumber;
  clientSYNACK_ACK.acknowledgementNumber = serverSYNACK.sequenceNumber+1;
  clientSYNACK_ACK.connectionID = connexID;
  clientSYNACK_ACK.ACKflag = 1;
  clientSYNACK_ACK.SYNflag = 0;
  clientSYNACK_ACK.FINflag = 0;

  char c_SYNACK_ACK[HEADER_SIZE] = {0}; //holds SYN to send to server
  convertHeaderToByteArray(clientSYNACK_ACK, c_SYNACK_ACK);

  if (sendto(sockfd, c_SYNACK_ACK, HEADER_SIZE, 0, (const sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
  {
    printError("Unable to send ACK for SYN ACK to server");
    exitOnError(sockfd);
  }

  printPacketDetails(clientSYNACK_ACK, SEND, cwnd, ssthresh);
  //-----------------------------------------// End of SYN Handshaking

  // send/receive data to/from connection
  fstream fin;
  fin.open(filename, ios::in);
  char buf[PACKET_SIZE] = {0};

  char c_serverACK[HEADER_SIZE] = {0};
  Header serverACK;

  char c_clientPayloadHeader[HEADER_SIZE] = {0};
  Header clientPayloadHeader;

  uint32_t seqNum = 12345; //TODO
  uint32_t ackNum = 0; //TODO

  //--------- Polling for payloads ---------//
  struct pollfd fds_socket;
  timeout_msecs = 500;

  fds_socket.fd = sockfd; //waiting for ACKS
  fds_socket.events = POLLIN;

  //receiving
  Header ack = serverSYNACK;
  char ackArray[HEADER_SIZE];
  auto start = chrono::system_clock::now();
  auto end = chrono::system_clock::now();
  while ((chrono::duration_cast<chrono::seconds>(end - start).count() < 10)) //TODO
  {
    end = chrono::system_clock::now();
    if (seqNum > 102400) //Max sequenceNumber, reset
      seqNum = seqNum % (102401);
    if (ackNum > 102400) //Max acknowledgementNumber, reset
      ackNum = ackNum % (102401);

    fin.read(buf, DATA_SIZE);

    //sending
    char msgHeader[HEADER_SIZE];
    char msgSend[HEADER_SIZE+fin.gcount()];

    Header payloadHeader;
    payloadHeader.sequenceNumber = ack.acknowledgementNumber;
    payloadHeader.acknowledgementNumber = 0;
    payloadHeader.connectionID = connexID;
    payloadHeader.ACKflag = 0;
    payloadHeader.SYNflag = 0;
    payloadHeader.FINflag = 0;

    //Check size of payload
    //if 0, break
    if(fin.gcount() == 0){
      break;
    }
    //if not, create a reponse packet
    convertHeaderToByteArray(payloadHeader, msgHeader);
    //appending header and payload to packet to send
    memcpy(msgSend,msgHeader,HEADER_SIZE);
    memcpy(msgSend+12,buf,fin.gcount());
    //send response packet
    if (sendto(sockfd, msgSend, HEADER_SIZE+fin.gcount(), 0, (const sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
      printError("Unable to send data to server");
      exitOnError(sockfd);
    }
    printPacketDetails(payloadHeader, SEND, cwnd, ssthresh);

    //receive the ack for the response packet
    poll(&fds, 1, timeout_msecs);
    if (fds.revents != 0)         // An event on sockfd has occurred.
    {
      rec_res = recvfrom(sockfd, ackArray, HEADER_SIZE, 0, (struct sockaddr *)&serverAddr,&serverAddrLen);
      if (rec_res == -1)
      {
        printError("Error in receiving SYN ACK from server");
        exitOnError(sockfd);
      }
      if(rec_res > 0)
      {
        start = chrono::system_clock::now();
        ack = convertByteArrayToHeader(ackArray);
        printPacketDetails(ack, RECV, cwnd, ssthresh);
        updateWindow(cwnd, ssthresh);
      }
    }



  } //end of while
  if (chrono::duration_cast<chrono::seconds>(end - start).count() >= 10)
  {
    printError("No response from server.");
    exitOnError(sockfd);
  }

  fin.close();

    Header fin_packet = createFIN(ack);
    char finArray[DATA_SIZE];

    convertHeaderToByteArray(fin_packet,finArray);

    if (sendto(sockfd, finArray, HEADER_SIZE, 0, (const sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
      printError("Unable to send FIN to server");
      exitOnError(sockfd);
    }

    printPacketDetails(fin_packet, SEND, cwnd, ssthresh);
     start = chrono::system_clock::now();
     end = chrono::system_clock::now();
    while((chrono::duration_cast<chrono::seconds>(end - start).count() < 2))
    {
      end = chrono::system_clock::now();
      poll(&fds, 1, timeout_msecs);
      if (fds.revents != 0)         // An event on sockfd has occurred.
      {
        rec_res = recvfrom(sockfd, ackArray, HEADER_SIZE, 0, (struct sockaddr *)&serverAddr,&serverAddrLen);
        if (rec_res == -1)
        {
          printError("Error in receiving FIN ACK from server");
          exitOnError(sockfd);
        }
        if(rec_res > 0)
        {
          ack = convertByteArrayToHeader(ackArray);
          if(!ack.FINflag)
          {
            printPacketDetails(ack, DROP, cwnd, ssthresh);
          }
          else
          {
            printPacketDetails(ack, RECV, cwnd, ssthresh);
            Header finalACK = createFinalACK(ack);
            convertHeaderToByteArray(finalACK,finArray);
            if (sendto(sockfd, finArray, HEADER_SIZE, 0, (const sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
            {
              printError("Unable to send FIN to server");
              exitOnError(sockfd);
            }
            printPacketDetails(finalACK, SEND, cwnd, ssthresh);
          }
      }
    }}


  //---------------------------------------//


}

long parsePort(char **argv)
{
  long temp_port = strtol(argv[2],nullptr,10);
  if(temp_port == 0 || temp_port==LONG_MAX || temp_port==LONG_MIN || (temp_port<1024)|| temp_port>65535)
    {
      printError("Port number needs to be a valid integer greater than 1023.");
      exit(1);
    }
  return temp_port;
}

string parseHost(char **argv)
{
  struct addrinfo hints, *info;
  hints.ai_family = AF_INET;

  if(getaddrinfo(argv[1], NULL,&hints,&info))
    {
      printError("Host name is invalid.");
      printUsage();
      exit(1);
    }
  char addrbuf[INET_ADDRSTRLEN + 1];
  const char *addr = inet_ntop(info->ai_family, &(((struct sockaddr_in *)info->ai_addr)->sin_addr),addrbuf,sizeof(addrbuf));

  return (string)addr;
}

Arguments parseArguments(int argc, char**argv)
{
  if(argc!=(NUMBER_OF_ARGS+1))
    {
      printError("Incorrect number of arguments");
      printUsage();
      exit(1);
    }
  Arguments args;

  // host
  args.host = parseHost(argv);

  // port
  args.port = parsePort(argv);
  // filename
  args.filename = (string) argv[3];

  return args;
}

void setupEnvironment(const int sockfd)
{
  int flags = fcntl(sockfd, F_GETFL, 0);
  if(flags<0)
    {
      printError("fcntl() failed 1.");
      exit(1);
    }
  if(fcntl(sockfd,F_SETFL,O_NONBLOCK|flags)<0)
    {
      printError("fcntl() failed.");
      exit(1);
    }
}

int
main(int argc, char **argv)
{
  Arguments args = parseArguments(argc, argv);
  // create a socket using UDP IP
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  setupEnvironment(sockfd);

  struct sockaddr_in serverAddr = createServerAddr(args.port, args.host);
  struct sockaddr_in clientAddr = createClientAddr(sockfd);

  connectionSetup(clientAddr);
  communicate(sockfd, args.filename, serverAddr);
  close(sockfd);
  return 0;
}
