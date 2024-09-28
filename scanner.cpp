#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>
#include <string>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>

void scan_udp_ports(const char* ip, int port_low, int port_high){

  // Setting up socket structure
  int sock;
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);

  // Message to send with UDP
  char message[] = "UDP port scan";

  // Monitoring file descriptor
  fd_set fds;

  // Setup for time delay
  struct timeval timeout;

  // Loop through the ports in between min and max
  for (int port = port_low; port <= port_high; port ++){
    // Response from port
    int respone;
    char buffer[1024];

    // Create UDP sockets and check for failure
    if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
      perror("Could not create socket");
      continue;
    }

    // Set the socket to non-blocking mode
    fcntl(sock, F_SETFL, O_NONBLOCK);

    // Declare port for socket
    addr.sin_port = htons(port); 

    // Send the UDP datagram
    int send_result = sendto(sock, message, sizeof(message), 0, (struct sockaddr*)&addr, sizeof(addr));

    // Check if the message was sent 
    if (send_result >= 0){
      // Receive the Response
      FD_ZERO(&fds);
      FD_SET(sock, &fds);
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      respone = select(sock + 1, &fds, nullptr, nullptr, &timeout);

      if (respone > 0) {
        // Port sends response and looks to be open
        std::cout << "Port " << port << " is open!\n";
        int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, nullptr, nullptr);
        if (len >= 0) {
          buffer[len] = '\0';
          close(sock);
          std::cout << "\nResponse from port: " << buffer << "\n\n";
        }
      } else {
        // Port sends no response within timeout
        std::cout << "Port " << port << " is closed!\n";
      }
      
    } else {
      perror("Error sending to port");
    }

    //Close socket
    close(sock);
  }
}

int main(int argc, char* argv[]){
  // Make sure that the correct amount arguments is supplied
  if (argc != 4){
    perror("This program only accepts 3 arguments, an IP address, port low and port high");
    exit(0);
  }

  // Reading ports from input
  char* ip = argv[1];
  int port_low = std::stoi(argv[2]);
  int port_high = std::stoi(argv[3]);

  scan_udp_ports(ip, port_low, port_high);

  return 0;
}
