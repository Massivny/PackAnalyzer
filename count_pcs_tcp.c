#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

void packet_handler( u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    
    const u_char* ip_header;
    // Finding start of IP header (+ 14 bytes - const Ethernet header length)
    ip_header = packet + 14;
    // Protocol is always the 10th byte of the IP header
    u_char protocol = *(ip_header + 9);
    if (protocol == IPPROTO_TCP)
    {
        (*(int*)args)++;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s *enter path to .pcap file*\n", argv[0]);
        return -1;
    }

    char* file                    = argv[1];    //Path to .pcap file
    char filter_exp[100]          = {};         //Optional filter expression 
    char errbuf[PCAP_ERRBUF_SIZE] = {};         //Error buffer 
    int count_pcs_tcp             = 0;          //Number of transisted packets
    pcap_t* handler               = NULL;       //Dev identificator
    struct bpf_program fp         = {};         //Struct to store compiled version of filter
    bpf_u_int32 netp              = 0;          //Network mask

    for (int i = 2; i < argc; i++)
    {
        strcat(filter_exp, argv[i]);
        strcat(filter_exp, " ");
    }

    handler = pcap_open_offline(file, errbuf);
    if (!handler)
    {
        fprintf(stderr, "Error handling pcap file %s: %s\n", file, errbuf);
        return -1;
    }

    if (pcap_compile(handler, &fp, filter_exp, 0, netp) == -1)
    {
        fprintf(stderr, "Error calling pcap_compile!\n");
        return -1;
    }

    if (pcap_setfilter(handler, &fp) == -1)
    {
        fprintf(stderr, "Error calling pcap_setFilter!\n");
        return -1;
    }
    
    if (pcap_loop(handler, 0, packet_handler, (u_char*)&count_pcs_tcp) < 0)
    {
        fprintf(stderr, "Error reading packets from pcap file!\n");
        return -1;
    }

    pcap_close(handler);

    printf("Number of TCP packets: %d\n", count_pcs_tcp);

    return 0;
}
