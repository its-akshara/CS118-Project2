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
void updateArrayIndexToNumberBitwise(unsigned char header[HEADER_SIZE+1], int index, uint32_t number)
{
  uint32_t network_byte_order = (number);
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
void convertHeaderToByteArray(Header h, unsigned char header[HEADER_SIZE])
{
  memset(&header[0], 0, HEADER_SIZE);
  updateArrayIndexToNumberBitwise(header,0,h.sequenceNumber);
  updateArrayIndexToNumberBitwise(header,4,h.acknowledgementNumber);
  //an int representing the third 'row' of the header
  int32_t connIDASF = getConnIDAndFlags(h.connectionID,h.ACKflag,h.SYNflag,h.FINflag);
  updateArrayIndexToNumberBitwise(header,8,connIDASF);
}

uint32_t getValueFromBytes(unsigned char *h, int index)
{
  return (((h[index])<<NUM_RIGHT_OFFSET1)|((h[index+1])<<NUM_RIGHT_OFFSET2)|((h[index+2])<<NUM_RIGHT_OFFSET3)|(h[index+3]));
}

Header convertByteArrayToHeader(unsigned char *h)
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

void listenForPackets(int clientSockfd, string fileDir)
{
  // read/write data from/into the connection
  bool isEnd = false;
  char buf[PACKET_SIZE] = {0};
  fstream fout;
  int num = 0;
    
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
          fout.close();
          exitOnError(clientSockfd);
        }
      else if(!rec_res)
        {
	        break;
        }
      if(rec_res > 0)
      {
        cout<< "What was received:"<<buf<<endl;
        cout<<"Return value:"<<rec_res<<endl;
        unsigned char header[HEADER_SIZE];
        memcpy(header, buf, HEADER_SIZE);
        Header packet_header = convertByteArrayToHeader(header);
        for(int i = 0; i<12; i++)
        {
          cout<<(uint32_t)header[i]<<" ";
        }
        // print details
        // if SYN then start 3 way handshake -> create new connection state
        
        // send SYN ACK

        // if ACK

        // if FIN update connection state

        cout <<endl;
        cout << "Header contents: \n";
        cout<< "SEQ NO:"<<packet_header.sequenceNumber <<" ACK NO:"<<packet_header.acknowledgementNumber<<endl;
        cout <<"CONNECTION ID:"<<packet_header.connectionID<<endl;
        cout << "SYN:"<<packet_header.SYNflag <<" ACK:"<<packet_header.ACKflag << " FIN:"<<packet_header.FINflag<<endl;
        fout.open(getFileName(fileDir,num), ios::out);
        fout.write(buf+HEADER_SIZE, rec_res-HEADER_SIZE);//-HEADER_SIZE);+HEADER_SIZE
      }
      
    }
  fout.close();
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
  int client_number  = 1;
  Arguments args = parseArguments(argc, argv);
    
  signal(SIGTERM, sigHandler);
  signal(SIGQUIT, sigHandler);

   Header test;
   test.connectionID = 3;
   test.acknowledgementNumber = 777;
   test.sequenceNumber = 99;
   test.SYNflag = 1;
   test.ACKflag = 1;
   test.FINflag = 1;

  unsigned char blah[HEADER_SIZE];
  convertHeaderToByteArray(test,blah);
  cout << "test header:"<<endl;
  for(int i = 0; i<12; i++)
  {
    cout<<(uint32_t)blah[i]<<" ";
  }
  cout <<endl;

  Header back  = convertByteArrayToHeader(blah);

  cout<< "Convert back"<<endl;
  cout <<back.sequenceNumber<<" "<<back.acknowledgementNumber<<" "<<back.connectionID<<" "<<endl;

  
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

