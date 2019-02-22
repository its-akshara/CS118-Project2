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
#include <climits>

using namespace std;

const int NUMBER_OF_ARGS = 3;
const int PACKET_SIZE = 1024;

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

void serverConnect(const int sockfd, const struct sockaddr_in &serverAddr)
{
  // connect to the server
  struct timeval timeout;
  timeout.tv_sec = 15;
  timeout.tv_usec = 0;
    
  if (connect(sockfd,(struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1 && errno!=EINPROGRESS)
    {
      printError("connect() failed.");
      close(sockfd);
      exit(1);
    }
  fd_set writefds;
  FD_ZERO(&writefds);
  FD_SET(sockfd, &writefds);
    
  int res = select(sockfd + 1, NULL, &writefds, NULL, &timeout);
    
  if(res == -1)
    {
      printError("select() failed.");
      exitOnError(sockfd);
    }
  else if(res==0)
    {
      printError("Timeout! Client has not been able to connect to the server in more than 15 seconds.");
      exitOnError(sockfd);
    }
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;
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

void communicate(const int sockfd, const string filename)
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
    fin.read(buf, PACKET_SIZE);
        
    FD_CLR(sockfd,&writefds);
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);
        
        
    int sel_res = select(sockfd+1,NULL,&writefds,NULL,&timeout);
        
    if(sel_res == -1)
      {
	printError("select() failed.");
	exitOnError(sockfd);
      }
    else if(sel_res==0)
      {
	printError("Timeout! Client has not been able to send data to the server in more than 15 seconds.");
	exitOnError(sockfd);
      }
    else
      {
	if (send(sockfd, buf, fin.gcount(), MSG_NOSIGNAL) == -1)
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
    
  // create a socket using TCP IP
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
  setupEnvironment(sockfd);

  struct sockaddr_in serverAddr = createServerAddr(args.port, args.host);

  serverConnect(sockfd, serverAddr);

  struct sockaddr_in clientAddr = createClientAddr(sockfd);
  
  connectionSetup(clientAddr);
    
  communicate(sockfd, args.filename);

  close(sockfd);

  return 0;
}
