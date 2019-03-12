#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <iomanip>
#include <cstdint>
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <climits>

using namespace std;

const int NUMBER_OF_ARGS = 2;
const int MAX_CLIENT_NUMBER = 12;
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

int client_number = 1;
unordered_map<int,int> connToCumACK;

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

  //res.sequenceNumber = getValueFromBytes(h,0);
  //res.acknowledgementNumber = getValueFromBytes(h,4);
  //res.connectionID = (getValueFromBytes(h,8)>>16)&~CONN_MASK;
  return res;
}

struct Arguments
{
  int port;
  string fileDir;
};

void printUsage()
{
  cerr<< "USAGE: ./server <PORT> <FILE-DIR>\n";
}

void printInt_32(uint32_t x)
{
    cout << setfill('0') << setw(8) << hex << x << '\n';
}

void printInt_16(uint16_t x)
{
    cout << setfill('0') << setw(4) << hex << x << '\n';
}

void printError(string message)
{
  cerr<<"ERROR: ";
  cerr<< message <<endl;
}

void sigHandler(int n)
{
  if(n == SIGTERM || n == SIGQUIT)
    {
      exit(0);
    }
  else
    {
      printError("Signal "+to_string(n)+" received.");
      exit(1);
    }
}


long parsePort(char **argv)
{
  long temp_port = strtol(argv[1],nullptr,10);
  if(temp_port == 0 || temp_port==LONG_MAX || temp_port==LONG_MIN || (temp_port<1024) || temp_port>65535)
    {
      printError("Port number needs to be a valid integer greater than 1023.");
      exit(1);
    }
  return temp_port;
}

void exitOnError(int sockfd)
{
  close(sockfd);
  exit(1);
}

void createDirIfNotExists(string path)
{
  struct stat s;
    
  if(!(stat(path.c_str(), &s) == 0 &&S_ISDIR(s.st_mode)))
    {
      if(mkdir(path.c_str(), 0777)<0)
        {
	        printError("Unable to create directory.");
	        exit(1);
        }
        
    }
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
    
  // port
  args.port = parsePort(argv);
    
  // directory
  createDirIfNotExists(string(argv[2]));
  args.fileDir = (string) argv[2];
    
  return args;
}

void setReuse(const int sockfd)
{
  // allow others to reuse the address
  int yes = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    printError("setsockopt() failed.");
    exitOnError(sockfd);
  }
}

bool hasNoFlags(Header packet_header)
{
  return !packet_header.FINflag&&!packet_header.ACKflag&&!packet_header.SYNflag;
}


struct sockaddr_in createServerAddr(const int sockfd, const int port)
{
  // bind address to socket
  struct sockaddr_in addr;
  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);     // short, network byte order
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  return addr;
}

void bindSocket(const int sockfd, const sockaddr_in addr)
{
  if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) <0)
    {
      printError("bind() failed.");
      exitOnError(sockfd);
    }
}

string getFileName(string fileDir, int num)
{
  return fileDir +"/" + to_string(num) + ".file";
}

// creates the SYNACK for the 3-way handshake
Header createSYNACK(Header clientSyn)
{
  Header serverSynAck;
  serverSynAck.ACKflag = 1;
  serverSynAck.connectionID = client_number;
  serverSynAck.SYNflag = 1;
  serverSynAck.FINflag = 0;
  serverSynAck.sequenceNumber = 4321;
  serverSynAck.acknowledgementNumber = clientSyn.sequenceNumber+1;
  return serverSynAck;
}

Header createACKHandshake(Header client, uint32_t payloadSize)
{
  Header serverACK;
  serverACK.SYNflag = 0;
  serverACK.FINflag = 0;
  serverACK.ACKflag = 1;

  serverACK.connectionID = client.connectionID;
  serverACK.acknowledgementNumber = client.sequenceNumber;

  if(hasNoFlags(client))
  {
    serverACK.sequenceNumber = connToCumACK[client.connectionID];
  }
  else
  {
    serverACK.sequenceNumber = client.acknowledgementNumber;
    connToCumACK[client.connectionID] = client.acknowledgementNumber;
  }
    

  if(payloadSize>0)
  {
    serverACK.acknowledgementNumber+=payloadSize;
  }
  else if(client.SYNflag)
  {
    serverACK.acknowledgementNumber++;
  }

  return serverACK;
}

bool beginNewConnection(Header packet)
{
  return packet.SYNflag&&!packet.ACKflag&&!packet.FINflag&&(packet.connectionID==0);
}

bool receivedACK(Header packet)
{
  return packet.ACKflag&&!packet.FINflag&&!packet.SYNflag;
}

void createNewFile(int num, string fileDir)
{
  fstream fout;
  fout.open(getFileName(fileDir,num), ios::out);
  fout.close();
}

void writePayloadToFile(int num, string fileDir, char * payload, int size)
{
  fstream fout;
  fout.open(getFileName(fileDir,num), ios::app);
  fout.write(payload, size);
  fout.close();
}

enum msgType{RECV,SEND,DROP};

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

bool receivedFIN(Header packet_header)
{
  return !packet_header.SYNflag&&packet_header.FINflag&&!packet_header.ACKflag;
}

Header createFINACK(Header packet_header)
{
  Header serverFINACK;
  serverFINACK.ACKflag = 1;
  serverFINACK.SYNflag = 0;
  serverFINACK.FINflag = 1;

  serverFINACK.sequenceNumber = connToCumACK[packet_header.connectionID];

  serverFINACK.connectionID = packet_header.connectionID;
  serverFINACK.acknowledgementNumber = packet_header.sequenceNumber+1;
  return serverFINACK; 
}

void listenForPackets(int clientSockfd, string fileDir)
{
  // read/write data from/into the connection
  bool isEnd = false;
  bool dup = false;
  char buf[PACKET_SIZE] = {0};
    
  // fd_set readfds;
    
  struct timeval timeout;
  timeout.tv_sec = 15;
  timeout.tv_usec = 0;
    
  while (!isEnd)
    {
      memset(buf, '\0', sizeof(buf));
      struct sockaddr_in clientAddr;
      socklen_t clientAddrSize = sizeof(clientAddr);
      
      int rec_res = recvfrom(clientSockfd, buf, PACKET_SIZE, 0, (struct sockaddr *)&clientAddr,&clientAddrSize);

      timeout.tv_sec = 10;
      timeout.tv_usec = 0;
      if (rec_res == -1 && errno!=EWOULDBLOCK)
        {
	        printError("Error in receiving data");
          exitOnError(clientSockfd);
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
        
        // print details
        printPacketDetails(packet_header,RECV);

        // if SYN then start 3 way handshake -> create new connection state
        if (beginNewConnection(packet_header))
        {
          response = createSYNACK(packet_header);
          createNewFile(client_number,fileDir);
          client_number++;
        }
        else if(receivedACK(packet_header)||hasNoFlags(packet_header))
        {
          response = createACKHandshake(packet_header, rec_res-HEADER_SIZE);
          // write to file
          writePayloadToFile(packet_header.connectionID,fileDir,buf+HEADER_SIZE, rec_res-HEADER_SIZE);
        }
        else if(receivedFIN(packet_header))
        {
          response = createFINACK(packet_header);
        }

        convertHeaderToByteArray(response,responsePacket);

        if(!receivedACK(packet_header))
        {
          if (sendto(clientSockfd, responsePacket, HEADER_SIZE, 0, (const sockaddr *)&clientAddr, clientAddrSize) == -1)
          {
            printError("Unable to send data to server");
            exitOnError(clientSockfd);
          }
          printPacketDetails(response,SEND,dup);
        }
      }
      
    }
}

void setupEnvironment(const int sockfd)
{
  int flags = fcntl(sockfd, F_GETFL, 0);
  if(flags<0)
    {
      printError("fcntl() failed");
      exit(1);
    }
  if(fcntl(sockfd,F_SETFL,flags|O_NONBLOCK)<0)
    {
      printError("fcntl() failed.");
      exit(1);
    }
}

void worker(int clientSockfd, int n, string fileDir)
{
  setupEnvironment(clientSockfd);
  // set up handshake
  listenForPackets(clientSockfd, fileDir);
  // end handshake
  close(clientSockfd);
}

int main(int argc, char **argv)
{
  Arguments args = parseArguments(argc, argv);
    
  signal(SIGTERM, sigHandler);
  signal(SIGQUIT, sigHandler);

  // create a socket using UDP IP
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if(sockfd < 0)
  {
    printError("fcntl() failed");
    exit(1);
  }

  setReuse(sockfd);
  setupEnvironment(sockfd);
    
  struct sockaddr_in addr = createServerAddr(sockfd, args.port);
    
  bindSocket(sockfd, addr);
    
  // set socket to listen status
  while (true)
    {
      worker(sockfd,client_number,args.fileDir);      
    }
  close(sockfd);
    
  return 0;
}

