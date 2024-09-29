#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <errno.h>
#include <vector>
#include <sstream>
#include <string>
#include <ifaddrs.h>
#include <fcntl.h>

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t destination_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};


// Checksum function for IP header
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

// Function to calculate UDP checksum
unsigned short udp_checksum(struct iphdr *iph, unsigned short *udp_pkt, int udp_len) {
    char buf[65536];
    memset(buf, 0, 65536);

    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.destination_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(udp_len);

    memcpy(buf, &psh, sizeof(struct pseudo_header));
    memcpy(buf + sizeof(struct pseudo_header), udp_pkt, udp_len);

    return checksum((unsigned short*)buf, sizeof(struct pseudo_header) + udp_len);
}

class Socket {
  public:
    const char* ip;
    int socket_type;
    int sock;

    // Constructor to initialize the socket
    Socket(const char* ip_address, int type) : ip(ip_address), socket_type(type), sock(-1) {
        // Create the socket based on the socket type (UDP, TCP, etc.)
        sock = socket(AF_INET, socket_type, 0);
        if (sock < 0) {
            perror("Could not create socket");
        }
    }


    int send_n_recv(int port, char message[], size_t message_size, char *recv_buffer, size_t buffer_size) {
        if (sock < 0) {
            std::cerr << "Socket not initialized" << std::endl;
            return -1;
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(ip);  

        // Monitor file descriptor
        fd_set fds;

        // Setup for time delay
        struct timeval timeout;

        // Declare port for socket
        addr.sin_port = htons(port); 

        // Set the socket to non-blocking mode
        fcntl(sock, F_SETFL, O_NONBLOCK);

        // Send the UDP datagram or TCP message
        int send_result = sendto(sock, message, message_size, 0, (struct sockaddr*)&addr, sizeof(addr));

        // Check if the message was sent 
        if (send_result >= 0) {

            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;

            int response = select(sock + 1, &fds, nullptr, nullptr, &timeout);

            if (response > 0) {
                int len = recvfrom(sock, recv_buffer, buffer_size - 1, 0, nullptr, nullptr);
                if (len >= 0) {
                    recv_buffer[len] = '\0';
                    std::cout << "\nResponse from port: " << recv_buffer << "\n\n";     
                    return len;
                } else {
                    std::cerr << "Failed to receive reply" << std::endl;
                }
            } else {
                std::cerr << "No response received within the timeout period" << std::endl;
            }
        } else {
            perror("Error sending to port");
        }
      return 0;
    }
};

std::string get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    char addr[INET_ADDRSTRLEN];
    std::string local_ip = "";

    if (getifaddrs(&ifaddr) == -1) {
        perror("Error getting local IP address");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        // Check for IPv4
        if (ifa->ifa_addr->sa_family == AF_INET) {
            void *tmp_addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, tmp_addr, addr, INET_ADDRSTRLEN);
            // Exclude loopback address
            if (strcmp(addr, "127.0.0.1") != 0) {
                local_ip = addr;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);

    if (local_ip == "") {
        std::cerr << "Could not determine local IP address." << std::endl;
        exit(EXIT_FAILURE);
    }

    return local_ip;
}

unsigned short calculate_checksum(unsigned short *buff, int nwords) {
    unsigned long checksum;
    for (checksum = 0; nwords > 0; nwords--) {
        checksum += *buff++;
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    return (unsigned short)(~checksum);
}

struct iphdr* create_ipv4_header(char* package_buffer, uint32_t source_ip, uint32_t dest_ip, uint8_t protocol, uint16_t frag_off) {
    // Create the ip header into the buffer
    struct iphdr* iph = (struct iphdr*) package_buffer;

    iph->ihl = 5;
    iph->version = 4;                                                       // IPv4
    iph->tos = 0; 
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
    iph->id = htons(5500);
    iph->frag_off = htons(frag_off);
    iph->ttl = 64;
    iph->protocol = protocol;                                               // Protocol f.x IPPROTO_UDP or IPPROTO_TCP
    iph->check = 0;
    iph->saddr = source_ip;                                                 // Source IP address
    iph->daddr = dest_ip;                                                   // Destination IP address

    iph->check = calculate_checksum((unsigned short*) iph, sizeof(struct iphdr) / 2);

    return iph;
}

void solve_secret(const char* ip, int port, char message[], size_t message_size){
  // Create the UDP socket
  Socket udpSocket = Socket(ip, SOCK_DGRAM);

  // Create a reply buffer
  char reply_buffer[512];

  // Send the message using the socket
  int result = udpSocket.send_n_recv(port,                   // Port being sent to 
                                     message,                // Message being sent to the port
                                     message_size,           // Size of the message
                                     reply_buffer,           // The buffer which receives the reply from the port
                                     sizeof(reply_buffer));  // Size of the buffer
}


void solve_checksum(const char* ip, int port, char message[], size_t message_size){
  // Convert dest IP to uint32_t
  uint32_t dest_ip = inet_addr(ip);

  // Create UDP socket
  Socket udpSocket = Socket(ip, SOCK_DGRAM);

  // Create a reply buffer
  char reply_buffer[512];

  // Send the message using the socket
  int result = udpSocket.send_n_recv(port,                   // Port being sent to 
                                     message,                // Message being sent to the port
                                     message_size,           // Size of the message
                                     reply_buffer,           // The buffer which receives the reply from the port
                                     sizeof(reply_buffer));  // Size of the buffer 

  // Get the last six characters from the buffer
  const unsigned char *last_six = (unsigned char *)(reply_buffer + result - 6);
  
  // Extract expected checksum from the response
  uint16_t expected_checksum = (last_six[0] << 8) | last_six[1];
  expected_checksum = ntohs(expected_checksum);

  // Extract source IP from the response
  uint32_t source_ip;
  std::memcpy(&source_ip, last_six + 2, 4);

  // Initialize package buffer
  char package[sizeof(struct iphdr) + sizeof(struct udphdr)];
  memset(package, 0, sizeof(package));

  // Create IP header
  struct iphdr* iph = create_ipv4_header(package, source_ip, dest_ip, IPPROTO_UDP, 0);

  // Declare sample source_port
  uint16_t source_port;

  // Create UDP header
  struct udphdr *udph = (struct udphdr *) (package + sizeof(struct iphdr));
  udph->source = htons(source_port);
  udph->dest = htons(port);
  udph->len = htons(sizeof(struct udphdr));
  udph->check = 0;

  // Set up the pseudo-header
  struct pseudo_header psh;
  psh.source_address = iph->saddr;
  psh.destination_address = iph->daddr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_UDP;
  psh.udp_length = udph->len;

  // Prepare buffer for checksum calculation
  int pseudo_packet_size = sizeof(struct pseudo_header) + sizeof(struct udphdr);
  char pseudo_packet[pseudo_packet_size];
  memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
  memcpy(pseudo_packet + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));

  // Adjust the source port to match the expected checksum
  bool checksum_matched = false;
  for (source_port = 0; source_port < 65535; source_port++) {
    udph->source = htons(source_port);

    // Recalculate UDP checksum
    memcpy(pseudo_packet + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));
    uint16_t calculated_checksum = calculate_checksum((unsigned short *)pseudo_packet, pseudo_packet_size / 2);

    if (calculated_checksum == expected_checksum) {
        udph->check = calculated_checksum;
        checksum_matched = true;
        break;
    }
  }

  if (!checksum_matched) {
      std::cerr << "Failed to find a source port that matches the expected checksum." << std::endl;
      close(udpSocket.sock);
      return;
  }

  // Create a second reply buffer
  char second_reply_buffer[512];

  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = dest_ip;

  int package_size = sizeof(struct iphdr) + sizeof(struct udphdr);
  int send_result = sendto(udpSocket.sock, package, package_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
  if (send_result < 0) {
      perror("Error sending custom reply");
  }

  int second_result = udpSocket.send_n_recv(port,                   // Port being sent to 
                                     package,                       // Message being sent to the port
                                     package_size,                  // Size of the message
                                     second_reply_buffer,           // The buffer which receives the reply from the port
                                     sizeof(second_reply_buffer));  // Size of the buffer 
}

void solve_evil(const char *target_ip, int evil_port, uint32_t net_signature, const char *source_ip) {

    // Create raw socket for sending
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0) {
        perror("Error creating raw socket");
    }

    int one = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
    }

    // Packet buffer
    char datagram[4096];

    // Zero out the packet buffer
    memset(datagram, 0, 4096);

    // IP header pointer
    struct iphdr *iph = (struct iphdr *)datagram;

    // UDP header pointer
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));

    // Data pointer
    char *data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    int data_len;

    // Prepare the data payload for the evil port
    memcpy(data, &net_signature, sizeof(net_signature));
    data_len = sizeof(net_signature);

    // Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    iph->id = htons(54321);
    iph->frag_off = htons(0x8000); // Set the evil bit (most significant bit of fragment offset)
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = inet_addr(target_ip);

    // IP checksum
    iph->check = checksum((unsigned short *)datagram, iph->ihl * 4);

    // UDP Header
    udph->source = htons(12345);
    udph->dest = htons(evil_port);
    udph->len = htons(sizeof(struct udphdr) + data_len);
    udph->check = 0; // Will calculate later

    // Calculate UDP checksum
    udph->check = calculate_checksum((unsigned short*)udph, sizeof(struct udphdr) + data_len);

    // Destination address
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = udph->dest;
    sin.sin_addr.s_addr = iph->daddr;

    // Send the packet to the evil port
    if(sendto(sockfd, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("Error sending packet to evil port");
    }

    std::cout << "Sent evil packet to " << target_ip << ":" << evil_port << std::endl;

    // Close raw socket
    close(sockfd);

    // Receive response from the evil port
    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(recv_sock < 0) {
        perror("Error creating receive socket");
    }

    struct sockaddr_in recv_addr;
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = udph->source;
    recv_addr.sin_addr.s_addr = iph->saddr;

    if(bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("Error binding receive socket");
    }

    // Set timeout for receiving
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // Receive response
    char recv_buffer[1024];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);

    int recv_len = recvfrom(recv_sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&sender_addr, &sender_len);
    if(recv_len > 0) {
        recv_buffer[recv_len] = '\0';
        std::cout << "Received response from evil port: " << recv_buffer << std::endl;
    } else {
        perror("No response received from evil port");
    }

    close(recv_sock);
}


void solve_knock(const char* ip, int port, char message[], size_t message_size, char knock[], size_t knock_size) {
    // Create UDP socket
    Socket udpSocket(ip, SOCK_DGRAM);

    // Create a reply buffer
    char reply_buffer[512];

    // Send the initial message to the oracle
    int result = udpSocket.send_n_recv(port,
                                       message,
                                       message_size,
                                       reply_buffer,
                                       sizeof(reply_buffer));

    if (result <= 0) {
        std::cerr << "Failed to receive port sequence from the oracle." << std::endl;
        return;
    }

    // Null-terminate the received message
    reply_buffer[result] = '\0';

    // Parse the port sequence from the oracle's response
    std::vector<int> port_sequence;
    std::istringstream iss(reply_buffer);
    std::string port_str;
    while (std::getline(iss, port_str, ',')) {
        try {
            int knock_port = std::stoi(port_str);
            port_sequence.push_back(knock_port);
        } catch (const std::exception& e) {
            std::cerr << "Invalid port number received: " << port_str << std::endl;
            return;
        }
    }

    if (port_sequence.empty()) {
        std::cerr << "No ports to knock on." << std::endl;
        return;
    }

    // Iterate over the port sequence
    for (size_t i = 0; i < port_sequence.size(); i++) {
        int knock_port = port_sequence[i];

        // Send the knock message
        char recv_buffer[512];

        int send_result = udpSocket.send_n_recv(knock_port,
                                                knock,
                                                knock_size,
                                                recv_buffer,
                                                sizeof(recv_buffer));

    char secret_buffer[512];

    int result = udpSocket.send_n_recv(port,
                                       message,
                                       message_size,
                                       secret_buffer,
                                       sizeof(secret_buffer));
    }
}

void solve_bonus(const char *target_ip) {
    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0) {
        perror("Error creating raw socket");
    }

    // Target address structure
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = 0;
    if(inet_pton(AF_INET, target_ip, &dest_addr.sin_addr) != 1) {
        perror("Invalid IP address");
        close(sockfd);
    }

    // Buffer for the packet
    char packet[1024];
    memset(packet, 0, sizeof(packet));

    // ICMP header
    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(1);

    // ICMP data (payload)
    const char *payload = "$group_69$";
    int payload_size = strlen(payload);
    memcpy(packet + sizeof(struct icmphdr), payload, payload_size);

    int packet_size = sizeof(struct icmphdr) + payload_size;

    // Calculate ICMP checksum
    icmp->checksum = 0;
    icmp->checksum = calculate_checksum((unsigned short *)packet, packet_size);

    // Send the packet
    if(sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("Error sending packet");
        close(sockfd);
    }

    std::cout << "ICMP Echo Request sent to " << target_ip << " with payload '" << payload << "'" << std::endl;

    // Receive response
    char recv_buffer[1024];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);

    // Set timeout for receiving
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int bytes_received = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);
    if(bytes_received > 0) {
        std::cout << "Received ICMP reply from " << inet_ntoa(recv_addr.sin_addr) << std::endl;
    } else {
        perror("No ICMP reply received");
    }

    close(sockfd);
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

  /////////////////////////////////////
  //        Solving Secret Port      //
  /////////////////////////////////////

  // Create a 5 byte buffer
  char secret_payload[5]; 

  uint8_t group_number = 69;
  secret_payload[0] = static_cast<char>(group_number);

  // Group secret gotten from previous reply
  uint32_t group_secret = 0x9be8fbaa;
  uint32_t byte_challenge = 0xbef9a458;

  uint32_t signature = group_secret ^ byte_challenge;

  // Change the Big Endian
  uint32_t signature_n = htonl(signature); 
  std::memcpy(&secret_payload[1], &signature_n, sizeof(signature_n));

  // Attempt to solve secret port
  solve_secret(ip, port1, secret_payload, sizeof(secret_payload));


  /////////////////////////////////////
  //        Solving Checksum         //
  /////////////////////////////////////

  char message2[4];

  std::memcpy(&message2[0], &signature_n, sizeof(signature_n));

  solve_checksum(ip, port2, message2, sizeof(message2));

  /////////////////////////////////////
  //        Solving Evil Port        //
  /////////////////////////////////////

  // Get local IP address
  std::string local_ip = get_local_ip();
  const char *source_ip = local_ip.c_str();

  solve_evil(ip, port3, signature_n, source_ip);

  /////////////////////////////////////
  //        Solving Knock Port       //
  /////////////////////////////////////

  // Prepare the initial message to send to port4
  std::string initial_knock_message = "4025,4094"; // Replace with your hidden ports

  // Convert the message to a character array
  char knock_buffer[initial_knock_message.size() + 1];
  std::strcpy(knock_buffer, initial_knock_message.c_str());

  // Define the secret phrase
  std::string secret_phrase = "Omae wa mou shindeiru";
  char knock[50];

  // Prepare the knock message containing signature_n and secret_phrase
  std::memcpy(knock, &signature_n, sizeof(signature_n));
  std::memcpy(knock + sizeof(signature_n), secret_phrase.c_str(), secret_phrase.size());
  size_t knock_size = sizeof(signature_n) + secret_phrase.size();

  // Attempt to solve the knock port
  solve_knock(ip, port4, knock_buffer, strlen(knock_buffer), knock, knock_size);

  /////////////////////////////////////
  //        Solving Bonus Port       //
  /////////////////////////////////////

  // Attempt to solve bonus
  solve_bonus(ip);  

  return 0;
}
