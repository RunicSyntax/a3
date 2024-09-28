#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <iostream>
#include <unistd.h>
#include <string>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
#include <iomanip>

class Socket {
  public:
    const char* ip;
    int socket_type;

  int send_n_recv(int port, char message[], size_t message_size, char *recv_buffer[], size_t buffer_size) {
    
  }
}

struct pseudo_header {
    u_int32_t source_address;  // Source IP address
    u_int32_t destination_address;  // Destination IP address
    u_int8_t placeholder;  // Placeholder byte (set to 0)
    u_int8_t protocol;  // Protocol (set to 17 for UDP)
    u_int16_t udp_length;  // Length of the UDP header and payload
};

unsigned short calculate_checksum(unsigned short *buff, int nwords) {
    unsigned long checksum;
    for (checksum = 0; nwords > 0; nwords--) {
        checksum += *buff++;
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    return (unsigned short)(~checksum);
}

void solve_port(const char* ip, int port, int challenge_num, char message[], size_t message_size){
   // Setting up socket structure
  int sock;
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip);  

  // Monitor file descriptor
  fd_set fds;

  // Setup for time delay
  struct timeval timeout;

  // Prepare for response from port
  int response;
  int second_response;
  char buffer[1024];
  char second_buffer[1024];

  // Create UDP sockets and check for failure
  if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
    perror("Could not create socket");
    return;
  }

  // Set the socket to non-blocking mode
  fcntl(sock, F_SETFL, O_NONBLOCK);

  // Declare port for socket
  addr.sin_port = htons(port); 

  // Send the UDP datagram
  int send_result = sendto(sock, message, message_size, 0, (struct sockaddr*)&addr, sizeof(addr));

  // Check if the message was sent 
  if (send_result >= 0){
    // Receive the Response
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    response = select(sock + 1, &fds, nullptr, nullptr, &timeout);

    if (response > 0) {
      // Read response from port

      int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, nullptr, nullptr);
      if (len >= 0) {
        buffer[len] = '\0';

        // Print out response from port 
        std::cout << "\nResponse from port: " << buffer << "\n\n";

        if (challenge_num == 2){

          const unsigned char *last_six = (unsigned char *)(buffer + len - 6);

          // UDP checksum
          uint16_t expected_checksum = (last_six[0] << 8) | last_six[1];

          // Source IP 
          uint32_t source_ip = 0;
          std::memcpy(&source_ip, last_six + 2, 4);

          char package[30];
          memset(package, 0, sizeof(package));
          
          // Designate data length
          uint16_t data_len = 2;

          // Make the IP header
          struct iphdr* iph = (struct iphdr*) package;

          // Fill in IP header information
          iph->ihl = 5;
          iph->version = 4;
          iph->tos = 0;
          iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
          iph->id = htons(5500);
          iph->frag_off = 0;
          iph->ttl = 64;
          iph->protocol = IPPROTO_UDP;
          iph->check = 0;
          iph->saddr = htonl(source_ip);
          iph->daddr = htonl(inet_addr(ip));


          iph->check = calculate_checksum((unsigned short *)package, sizeof(struct iphdr) / 2);

          // Make the UDP header
          struct udphdr *udph = (struct udphdr *) (package + sizeof(struct iphdr));

          // Fill in UDP header information
          udph->source = htons(5500);
          udph->dest = htons(port);
          udph->len = htons(sizeof(struct udphdr) + data_len);
          udph->check = 0;

          // Define data pointer for checksum modification
          uint16_t *data = (uint16_t *)(package + sizeof(struct iphdr) + sizeof(struct udphdr));
          *data = 0;

          // Pseudo-header for checksum calculation
          struct pseudo_header psh;
          psh.source_address = htonl(source_ip);
          psh.destination_address = htonl(inet_addr(ip));
          psh.placeholder = 0;
          psh.protocol = IPPROTO_UDP;
          psh.udp_length = htons(sizeof(struct udphdr) + data_len);

          // Buffer for pseudo-header + UDP packet
          u_char pseudo_packet[30];
          memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
          memcpy(pseudo_packet + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + data_len);

          uint16_t checksum = calculate_checksum((unsigned short*)pseudo_packet, sizeof(pseudo_packet));
          for (uint16_t i = 0; i < 65535; i++) {
            udph->check = 0;
            *data = i;
            memcpy(pseudo_packet + sizeof(struct pseudo_header) + sizeof(struct udphdr), data, sizeof(data_len));
            checksum = calculate_checksum((unsigned short*)pseudo_packet, sizeof(pseudo_packet));
            if(checksum = expected_checksum){
              break;
            }
          }

          std::cout << "Calculated checksum: " << std::hex << checksum << std::endl;
          udph->check = htons(checksum);

          int package_size = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;

          int send = sendto(sock, package, package_size, 0, (struct sockaddr*)&addr, sizeof(addr));

          FD_ZERO(&fds);
          FD_SET(sock, &fds);
          timeout.tv_sec = 1;
          timeout.tv_usec = 0;
          second_response = select(sock + 1, &fds, nullptr, nullptr, &timeout);

          int length = recvfrom(sock, second_buffer, sizeof(second_buffer) - 1, 0, nullptr, nullptr);
          if (length >= 0) {
              second_buffer[length] = '\0';  // Null-terminate the received message
              std::cout << "Response to custom reply: " << second_buffer << std::endl;
          } else {
              perror("Failed to receive response to custom reply");
          }
        }
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


int main (int argc, char *argv[]) {
  if (argc != 6) {
    perror("This program only accepts 5 arguments, an IP address and 4 ports");
    exit(0);
  }

  // Reading IP from input
  char* ip = argv[1];

  // Reading and converting ports from input
  int port1 = std::stoi(argv[2]);
  int port2 = std::stoi(argv[3]);
  int port3 = std::stoi(argv[4]);
  int port4 = std::stoi(argv[5]);

  // Define messages for ports

  // Solving port 1
  char message1[5]; 

  uint8_t group_number = 69;
  message1[0] = static_cast<char>(group_number);

  uint32_t group_secret = 0x9be8fbaa;
  uint32_t byte_challenge = 0xbef9a458;

  uint32_t payload1 = group_secret ^ byte_challenge;
  uint32_t signature = htonl(payload1);

  std::memcpy(&message1[1], &signature, sizeof(signature));

  // Attempt to solve the port
  //solve_port(ip, port1, 1, message1, sizeof(message1));

  // Solving port 2
  char message2[4];

  std::memcpy(&message2[0], &signature, sizeof(signature));

  // Attempt to solve the port
  solve_port(ip, port2, 2, message2, sizeof(message2));

  char message3[] = "";
  char message4[] = "";

  // Attempt to solve each port
  //solve_port(ip, port3, 3, message3, sizeof(message3));
  //solve_port(ip, port4, 4, message4, sizeof(message4));

  return 0;
}
