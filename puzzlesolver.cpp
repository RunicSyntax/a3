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
    return 0;
  }
};

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


        if (challenge_num == 2) {
            const unsigned char *last_six = (unsigned char *)(buffer + len - 6);

            // Extract expected checksum from the response
            uint16_t expected_checksum = (last_six[0] << 8) | last_six[1];

            // Extract source IP from the response
            uint32_t source_ip;
            std::memcpy(&source_ip, last_six + 2, 4);

            char package[sizeof(struct iphdr) + sizeof(struct udphdr)];
            memset(package, 0, sizeof(package));

            // Create IP header
            struct iphdr* iph = (struct iphdr*) package;
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
            iph->id = htons(5500);
            iph->frag_off = 0;
            iph->ttl = 64;
            iph->protocol = IPPROTO_UDP;
            iph->check = 0;
            iph->saddr = source_ip;  // Source IP is already in network byte order
            iph->daddr = inet_addr(ip);  // Destination IP in network byte order

            // Calculate IP header checksum
            iph->check = calculate_checksum((unsigned short *)iph, sizeof(struct iphdr) / 2);

            // Create UDP header
            struct udphdr *udph = (struct udphdr *) (package + sizeof(struct iphdr));
            udph->dest = htons(port);
            udph->len = htons(sizeof(struct udphdr));
            udph->check = 0;

            // Set up the pseudo-header
            struct pseudo_header psh;
            psh.source_address = source_ip;
            psh.destination_address = inet_addr(ip);
            psh.placeholder = 0;
            psh.protocol = IPPROTO_UDP;
            psh.udp_length = htons(sizeof(struct udphdr));

            // Prepare buffer for checksum calculation
            int pseudo_packet_size = sizeof(struct pseudo_header) + sizeof(struct udphdr);
            char pseudo_packet[pseudo_packet_size];
            memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
            memcpy(pseudo_packet + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));

            // Adjust the source port to match the expected checksum
            uint16_t source_port;
            bool checksum_matched = false;
            for (source_port = 10000; source_port < 65535; source_port++) {
                udph->source = htons(source_port);

                // Recalculate UDP checksum
                memcpy(pseudo_packet + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));
                uint16_t calculated_checksum = calculate_checksum((unsigned short *)pseudo_packet, pseudo_packet_size / 2);

                if (calculated_checksum == expected_checksum) {
                    udph->check = htons(calculated_checksum);
                    checksum_matched = true;
                    break;
                }
            }

            if (!checksum_matched) {
                std::cerr << "Failed to find a source port that matches the expected checksum." << std::endl;
                close(sock);
                return;
            }

            // Send the packet
            struct sockaddr_in dest_addr = addr;  // Copy destination address
            dest_addr.sin_port = udph->dest;      // Ensure destination port is set

            int package_size = sizeof(struct iphdr) + sizeof(struct udphdr);
            int send_result = sendto(sock, package, package_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
            if (send_result < 0) {
                perror("Error sending custom reply");
            }

            // Wait for a response
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            second_response = select(sock + 1, &fds, nullptr, nullptr, &timeout);

            if (second_response > 0) {
                int length = recvfrom(sock, second_buffer, sizeof(second_buffer) - 1, 0, nullptr, nullptr);
                if (length >= 0) {
                    second_buffer[length] = '\0';  // Null-terminate the received message
                    std::cout << "Response to custom reply: " << second_buffer << std::endl;
                } else {
                    perror("Failed to receive response to custom reply");
                }
            } else {
                std::cout << "No response received to custom reply." << std::endl;
            }
        }


        /*
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
          //uint16_t data_len = 2;

          // Make the IP header
          struct iphdr* iph = (struct iphdr*) package;

          int source_port = 12345;

          // Fill in IP header information
          iph->ihl = 5;
          iph->version = 4;
          iph->tos = 0;
          iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
          iph->id = htons(5500);
          iph->frag_off = 0;
          iph->ttl = 64;
          iph->protocol = IPPROTO_UDP;
          iph->check = 0;
          iph->saddr = htonl(source_ip);
          iph->daddr = htonl(inet_addr(ip));


          iph->check = calculate_checksum((unsigned short *)&iph, sizeof(struct iphdr) / 2);

          // Make the UDP header
          struct udphdr *udph = (struct udphdr *) (package + sizeof(struct iphdr));

          // Fill in UDP header information
          udph->source = htons(source_port);
          udph->dest = htons(port);
          udph->len = htons(sizeof(struct udphdr));
          udph->check = 0;

          // Define data pointer for checksum modification
          //uint16_t *data = (uint16_t *)(package + sizeof(struct iphdr) + sizeof(struct udphdr));
          //k*data = 0;

          // Pseudo-header for checksum calculation
          struct pseudo_header psh;
          psh.source_address = htonl(source_ip);
          psh.destination_address = htonl(inet_addr(ip));
          psh.placeholder = 0;
          psh.protocol = IPPROTO_UDP;
          psh.udp_length = htons(sizeof(struct udphdr));

          // Buffer for pseudo-header + UDP packet
          u_char pseudo_packet[30];
          memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
          memcpy(pseudo_packet + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));
          
          unsigned short initial_udp_checksum = calculate_checksum(&psh, &udph, nullptr, 0);

          short checksum_difference = expected_checksum - initial_udp_checksum;

          source_port += checksum_difference / 2;
          udph->source = htons(source_port);
          
          udph->check = htons(expected_checksum);

          int package_size = sizeof(struct iphdr) + sizeof(struct udphdr);

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
        }*/
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
