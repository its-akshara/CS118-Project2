#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
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

// pass by reference
void updateArrayIndexToNumberBitwise(char header[HEADER_SIZE+1], int index, uint32_t number)
{
  uint32_t network_byte_order = htonl(number);
  header[index] = ((NUM_MASK1&network_byte_order)>>NUM_RIGHT_OFFSET1);
  header[index+1] = ((NUM_MASK2&network_byte_order)>>NUM_RIGHT_OFFSET2);
  header[index+2] = ((NUM_MASK3&network_byte_order)>>NUM_RIGHT_OFFSET3);
  header[index+3] = (NUM_MASK4&network_byte_order);
}

int32_t getConnIDAndFlags(uint16_t connectionID,bool ACKflag, bool SYNflag, bool FINflag)
{
  return ((connectionID<<CONN_RIGHT_OFFSET)&CONN_MASK)|((ACKflag<<ACK_OFFSET)&ACK_MASK)|((SYNflag<<SYN_OFFSET)&SYN_MASK)|(FINflag&
  FIN_MASK);
}

// returns a 96 bit(12 byte) array representing the TCP header
void convertHeaderToByteArray(Header h, char header[HEADER_SIZE])
{
  memset(&header[0], 0, HEADER_SIZE);
  updateArrayIndexToNumberBitwise(header,0,h.sequenceNumber);
  updateArrayIndexToNumberBitwise(header,4,h.acknowledgementNumber);
  //an int representing the third 'row' of the header
  int32_t connIDASF = getConnIDAndFlags(h.connectionID,h.ACKflag,h.SYNflag,h.FINflag);
  updateArrayIndexToNumberBitwise(header,8,connIDASF);
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
        temp.sequenceNumber = 123;
        temp.acknowledgementNumber = 8;
        temp.connectionID = 0;
        temp.ACKflag = 0;
        temp.SYNflag = 1;
        temp.FINflag = 0;
        char buf_send[HEADER_SIZE+fin.gcount()];
        char header[HEADER_SIZE];
        convertHeaderToByteArray(temp,header);
        cout << header<<endl<<endl;
        strcpy(buf_send,header);
        strcat(buf_send,buf);

        cout<< "Sending: ";
        printf("%s\n",buf_send);
        cout<<"HEADER:";
        for(int i =0; i<12;i++)
        {
          cout<<(int32_t)header[i]<<" ";

        }
        cout<<endl;

        if (sendto(sockfd, buf, fin.gcount() + HEADER_SIZE, 0, (const sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
          {
            printError("Unable to send data to server");
            exitOnError(sockfd);
          }
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
      }

  } while (!fin.eof());
  fin.close();
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
