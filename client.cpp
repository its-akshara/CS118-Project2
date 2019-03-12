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

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>
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

enum msgType{RECV,SEND,DROP};

// // pass by reference
// void updateArrayIndexToNumberBitwise(char header[HEADER_SIZE+1], int index, uint32_t number)
// {
//   uint32_t network_byte_order = htonl(number);
//   header[index] = (NUM_MASK4)&(network_byte_order>>NUM_RIGHT_OFFSET1);
//   header[index+1] = NUM_MASK4&(network_byte_order>>NUM_RIGHT_OFFSET2);
//   header[index+2] = NUM_MASK4&(network_byte_order>>NUM_RIGHT_OFFSET3);
//   header[index+3] = (NUM_MASK4&network_clibyte_order);
// }

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
  // updateArrayIndexToNumberBitwise(header,0,h.sequenceNumber);
  // updateArrayIndexToNumberBitwise(header,4,h.acknowledgementNumber);
  //an int representing the third 'row' of the header
  uint16_t connNetwork = htons(h.connectionID);
  // header[8] = (NUM_MASK4)&(connNetwork>>NUM_RIGHT_OFFSET3);
  // header[9] = (NUM_MASK4)&(connNetwork);
  uint16_t ASFNetwork = htons(getFlags(h.ACKflag,h.SYNflag,h.FINflag));
  memcpy(header, (char *)&seqNetwork, sizeof(uint32_t));
  memcpy(header+4, (char *)&ackNetwork, sizeof(uint32_t));
  memcpy(header+8, (char *)&connNetwork, sizeof(uint16_t));
  memcpy(header+10, (char *)&ASFNetwork, sizeof(uint16_t));


}

uint32_t getValueFromBytes(char *h, int index)
{
  return (((h[index])<<NUM_RIGHT_OFFSET1)|((h[index+1])<<NUM_RIGHT_OFFSET2)|((h[index+2])<<NUM_RIGHT_OFFSET3)|(h[index+3]));
}

Header convertByteArrayToHeader(char *h)
{
  Header res;
  res.ACKflag = h[FLAG_POS]&ACK_MASK;
  res.SYNflag = h[FLAG_POS]&SYN_MASK;
  res.FINflag = h[FLAG_POS]&FIN_MASK;

  res.sequenceNumber = getValueFromBytes(h,0);
  res.acknowledgementNumber = getValueFromBytes(h,4);
  res.connectionID = (getValueFromBytes(h,8)>>16)&~CONN_MASK;
  return res;
}

struct Arguments
{
  int port;
  string host;
  string filename;
};

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

void printPacketDetails(Header packet_header, msgType type, bool dup=false)
{
  if(type==DROP)
    cout<<"DROP ";
  else if(type==RECV)
    cout<<"RECV ";
  else
    cout<<"SEND ";

  cout<<packet_header.sequenceNumber<<" "<<packet_header.acknowledgementNumber<<" "<<packet_header.connectionID;

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

void communicate(const int sockfd, const string filename, struct sockaddr_in serverAddr)
{
  // send/receive data to/from connection
  fstream fin;
  fin.open(filename, ios::in);
  char buf[PACKET_SIZE] = {0};

  fd_set writefds;

  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  do {
    fin.read(buf, DATA_SIZE);

    FD_CLR(sockfd,&writefds);
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);


    int sel_res = select(sockfd+1,NULL,&writefds,NULL,&timeout);

    if(sel_res == -1)
      {
	      printError("select() failed.");
	      exitOnError(sockfd);
      }
    // else if(sel_res==0)
    //   {
	  //     printError("Timeout! Client has not been able to send data to the server in more than 15 seconds.");
    //   	exitOnError(sockfd);
    //   }
    else
      {
        Header temp;
        temp.sequenceNumber = 12345;
        temp.acknowledgementNumber = 0;
        temp.connectionID = 0;
        temp.ACKflag = 0;
        temp.SYNflag = 1;
        temp.FINflag = 0;

        //do 3 way handshake

        char buf_send[HEADER_SIZE+fin.gcount()];
        memset(&buf_send[0], 0, HEADER_SIZE+fin.gcount());
        char header[HEADER_SIZE];
        convertHeaderToByteArray(temp,header);
        memcpy(buf_send,header,HEADER_SIZE);
        memcpy(buf_send+12,buf, fin.gcount());

        printf("%s\n",buf_send);
        cout<<"HEADER:";
        for(int i =0; i<12;i++)
        {
          cout<<(int32_t)buf_send[i]<<" ";
        }
        cout<<endl;

        if (sendto(sockfd, buf_send, fin.gcount() + HEADER_SIZE, 0, (const sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
          {
            printError("Unable to send data to server");
            exitOnError(sockfd);
          }
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
      }


  } while (!fin.eof());
  fin.close();

  //fin stuff

    // read/write data from/into the connection
    bool isEnd = false;
    bool dup = false;

    while (!isEnd)
      {
        memset(buf, '\0', sizeof(buf));
        socklen_t serverAddrSize = sizeof(serverAddr);

        int rec_res = recvfrom(sockfd, buf, HEADER_SIZE, 0, (struct sockaddr *)&serverAddr, &serverAddrSize);

        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        if (rec_res == -1 && errno!=EWOULDBLOCK)
          {
  	        printError("Error in receiving data");
            exitOnError(sockfd);
          }
        else if(!rec_res)
          {
  	        break;
          }
        if(rec_res > 0)
        {
          char header[HEADER_SIZE];
          memcpy(header, buf, HEADER_SIZE);
          Header packet_header = convertByteArrayToHeader(header);
          Header response;
          char responsePacket[HEADER_SIZE];
          cout <<endl;
          cout << "Header contents received: \n";
          cout<< "SEQ:"<<packet_header.sequenceNumber <<" ACK:"<<packet_header.acknowledgementNumber<<endl;
          cout <<"CONN ID:"<<packet_header.connectionID<<endl;
          cout << "SYN:"<<packet_header.SYNflag <<" ACK:"<<packet_header.ACKflag << " FIN:"<<packet_header.FINflag<<endl;

          cout <<endl;

        //send UDP pkt with FIN flag//////////////////////////////////////////////////
        //temporary placeholder header struct with FIN data
        Header findata;
        findata.sequenceNumber = packet_header.sequenceNumber;
        findata.acknowledgementNumber = packet_header.acknowledgementNumber;
        findata.connectionID = packet_header.connectionID; //test value
        findata.ACKflag = 0;
        findata.SYNflag = 0;
        findata.FINflag = 1;
        //char array of fin header
        char finheader[HEADER_SIZE];
        convertHeaderToByteArray(findata,finheader);
        //send the fin header to server
        socklen_t serverAddrSize = sizeof(serverAddr);
        if (sendto(sockfd, finheader, fin.gcount() + HEADER_SIZE, 0, (const sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
          {
            printError("Unable to send data to server");
            exitOnError(sockfd);
          }
          cout << "\n...FIN SENT TO SERVER...\n";

          //Expect pkt with FIN ACK flag////////////////////////////////////////////////////
          if (!packet_header.SYNflag&&packet_header.FINflag&&packet_header.ACKflag) //check for fin-ack flag
          {
            cout << "\nreceived FIN ACK\n";
            cout << "\n wait 2 secs for pkt with fin\n";
            cout << "\n close connection \n";
            return;
            //wait 2 secs for pkt with FIN flag (FIN-WAIT)////////////////////////////////
            //Respond to each incoming FIN with an ACK pkt////////////////////////////////
          }
        }
      }
      cout<< "What was received:"<<buf<<endl;
      Header packet_header = convertByteArrayToHeader(buf);
      //print out header
      cout <<endl;
      cout << "Header contents received: \n";
      cout<< "SEQ:"<<packet_header.sequenceNumber <<" ACK:"<<packet_header.acknowledgementNumber<<endl;
      cout <<"CONN ID:"<<packet_header.connectionID<<endl;
      cout << "SYN:"<<packet_header.SYNflag <<" ACK:"<<packet_header.ACKflag << " FIN:"<<packet_header.FINflag<<endl;

      cout <<endl;
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
