#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#define CAPWAP_CTRL_PORT 5246
#define CAPWAP_DATA_PORT 5247
#define SHA1_DIGEST_LEN 20
#define AES_BLOCK_SIZE 16


typedef unsigned char  uchar8;
typedef unsigned short ushort16;
typedef unsigned int   uint32;
typedef struct{
    uchar8   dst_mac[6];
    uchar8   src_mac[6];
    ushort16 type;
} eth_hdr_t;

typedef struct {
    uint32 flags;
} vlan_hdr_t;

typedef struct{
    uchar8   dsap;
    uchar8   ssap;
    uchar8   ui;
    uchar8   oui[3];
    ushort16 type;
} llc_hdr_t;

typedef struct{
    uchar8   length:4;
    uchar8   version:4;
    uchar8   tos;
    ushort16 tot_len;
    ushort16 id;
    ushort16 frag_off;
    uchar8   ttl;
    uchar8   proto;
    ushort16 checksum;
    uint32   src_addr;
    uint32   dst_addr;
} ip_hdr_t;

typedef struct{
    ushort16 src_port;
    ushort16 dst_port;
    ushort16 length;
    ushort16 checksum;
} udp_hdr_t;

typedef struct {
    unsigned char rec_type;
    unsigned char version[2];
    unsigned char epoch[2];
    unsigned char seq[6];
    unsigned char len[2];
    unsigned char ciphertext[];
} dtls_record_t;

unsigned char WriteMacSecret[SHA1_DIGEST_LEN];

unsigned char WriteKey[AES_BLOCK_SIZE];

void hex_dump (const unsigned char *pkt, unsigned pkt_len)
{
    int i, j;

    for (i=0; i<((pkt_len+15)/16); i++) {
        printf("%04x: ", i);
        // HEX
        for (j=0; j<16; j++) {
            if (i*16+j < pkt_len)
                printf("%02x ", pkt[i*16+j]);
            else
                printf("   ");
            if (j == 7) printf("- ");
        }
        // ASCII
        for (j=0; j<16; j++) {
            if (i*16+j < pkt_len)
                if ((pkt[i*16+j] >= 32) && (pkt[i*16+j] <= 126))
                    printf("%c", pkt[i*16+j]);
                else
                    printf(".");
            else
                printf("  ");
            if (j == 7) printf(" ");
        }
        printf("\n");
    };
}

unsigned char atoh(unsigned char c){
    switch(c) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'A': return 10;
    case 'B': return 11;
    case 'C': return 12;
    case 'D': return 13;
    case 'E': return 14;
    case 'F': return 15;
    default:
        printf("Error parsing %c", c);
        return 0;
    }
    return 0;
}

int read_key_file(const char *filename)
{
    FILE *fd;
    char buffer[2048];
    unsigned char mac_key[SHA1_DIGEST_LEN];
    unsigned char enc_key[AES_BLOCK_SIZE];
    unsigned char *ptr;
    int i;

    fd = fopen(filename, "r");

    // Read the MAC key
    if (fgets(buffer, 2048, fd) == 0) {
        printf("MAC Key Read failed\n");
        return 0;
    }
    for (i=0; i<SHA1_DIGEST_LEN; i++){
        WriteMacSecret[i] = (atoh(buffer[i*2])*16) + atoh(buffer[i*2+1]);
    }

    // Read the Encrypt key
    if (fgets(buffer, AES_BLOCK_SIZE*2+1, fd) == 0) {
        printf("MAC Key Read failed\n");
        return 0;
    }

    for (i=0; i<AES_BLOCK_SIZE; i++){
        WriteKey[i] = (atoh(buffer[i*2])*16) + atoh(buffer[i*2+1]);
    }

    for (i=0; i<SHA1_DIGEST_LEN; i++) {
        printf("%02x ", WriteMacSecret[i]);
    }
    printf("\n");

    for (i=0; i<AES_BLOCK_SIZE; i++) {
        printf("%02x ", WriteKey[i]);
    }
    printf("\n");


    return 1;
}

int verify_packet(const unsigned char *buffer, unsigned buffer_len)
{

    EVP_CIPHER_CTX ctx;
    HMAC_CTX md;

    dtls_record_t *record;
    unsigned char *ciphertext;
    unsigned ciphertext_len;

    unsigned char *iv;
    int out1_len, out2_len;
    unsigned char cleartext_buf[2048];
    unsigned cleartext_len;

    unsigned char computed_mac[20];
    unsigned int computed_mac_len;

    unsigned char pad_len = 0;
    size_t cleartext_len_for_mac;

    unsigned char length_field_for_mac[2];

    bzero(cleartext_buf, 2048);

    record = (dtls_record_t *)(buffer+4);

    printf("Record:\n");
    hex_dump((unsigned char *)record, buffer_len - 4);

    ciphertext_len = ((record->len[0] << 8) | record->len[1]) - 16;
    iv = record->ciphertext;
    ciphertext = iv + 16;

    if (ciphertext_len % 16) {
        printf("Invalid ciphertext len %d!\n", ciphertext_len);
        return -10;
    }
    
//    printf("Ciphertext:\n");
//    hex_dump(ciphertext, ciphertext_len);

    // Try decrypt the packet

    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL,
                      WriteKey, iv, AES_DECRYPT);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // No auto-pad

    if (EVP_CipherUpdate(&ctx, cleartext_buf, &out1_len,
                         ciphertext, ciphertext_len)){
        if (EVP_CipherFinal_ex(&ctx, cleartext_buf+out1_len, &out2_len)) {
            cleartext_len = out1_len + out2_len;
            printf("Cleartext (%d):\n", cleartext_len);
            hex_dump(cleartext_buf, cleartext_len);
        } else {
            printf("Decrypt failure!\n");
            return 1;            
        }
    } else {
        printf("Decrypt failure!\n");
        return 1;
    }
        
    EVP_CIPHER_CTX_cleanup(&ctx);

    pad_len = *(cleartext_buf + (cleartext_len - 1));

    cleartext_len_for_mac = cleartext_len - pad_len - 1 - SHA1_DIGEST_LEN;

    // MAC CHECK

    length_field_for_mac[0] = cleartext_len_for_mac >> 8;
    length_field_for_mac[1] = cleartext_len_for_mac & 0xFF;

    HMAC_CTX_init(&md);
    HMAC_Init_ex(&md, WriteMacSecret, SHA1_DIGEST_LEN, EVP_sha1(), NULL);

    HMAC_Update(&md, &(record->epoch[0]), 2 );
    HMAC_Update(&md, &(record->seq[0]), 6 );
    HMAC_Update(&md, &(record->rec_type), 1 );
    HMAC_Update(&md, &(record->version[0]), 2);
    HMAC_Update(&md, &(length_field_for_mac[0]), 2);
    HMAC_Update(&md, cleartext_buf, cleartext_len_for_mac);

    HMAC_Final(&md, computed_mac, &computed_mac_len);

    if (memcmp( cleartext_buf + (cleartext_len - pad_len - 1 - SHA1_DIGEST_LEN),
                computed_mac,
                SHA1_DIGEST_LEN) == 0 ) {
        hex_dump(cleartext_buf + (cleartext_len - pad_len - 1 - SHA1_DIGEST_LEN), SHA1_DIGEST_LEN);
        hex_dump(computed_mac, SHA1_DIGEST_LEN);
        printf("MAC OK!\n");
    } else {
        printf("MAC failure\n");
        hex_dump(computed_mac, SHA1_DIGEST_LEN);
        return 2;
    }

    return 0;
};

int main(int argc, char *argv[])
{
    char           errbuf[PCAP_ERRBUF_SIZE];
    pcap_t        *in_pkts;
    int            res;

    struct pcap_pkthdr *pkt_hdr;
    const uchar8             *pkt_data;
    uint32              pkt_count = 0;

    OpenSSL_add_all_algorithms();

    if (argc != 3) {
        printf("Syntax: %s <key_file> <cap_file>\n", argv[0]);
        return -1;
    }

    if (read_key_file(argv[1]) == 0) {
        printf("Failed to read key file %s\n", argv[1]);
        return -1;
    }

    bzero(errbuf, PCAP_ERRBUF_SIZE);
    in_pkts = pcap_open_offline(argv[2], errbuf);
    if (in_pkts == NULL) {
        printf("Error opening capture file %s\n", argv[2]);
        printf("%s", errbuf);
        return -1;
    }

    while ((res = pcap_next_ex(in_pkts, &pkt_hdr, &pkt_data)) > 0) {

        uint32      off            = 0;
        const uchar8 *buf = pkt_data;

        eth_hdr_t *eth_hdr = (eth_hdr_t *)NULL;
        vlan_hdr_t *vlan_hdr = (vlan_hdr_t *)NULL;
        ip_hdr_t  *ip_hdr = (ip_hdr_t *)NULL;
        udp_hdr_t *udp_hdr = (udp_hdr_t *)NULL;

        pkt_count++;

        eth_hdr = (eth_hdr_t *)(buf+off);
        off += sizeof(eth_hdr_t);

        if (eth_hdr->type == ntohs(0x8100)) {
            vlan_hdr = (vlan_hdr_t *)(buf+off);
            off += sizeof(vlan_hdr_t);
        }

        ip_hdr = (ip_hdr_t *)(buf+off);
        off += sizeof(ip_hdr_t);

        udp_hdr = (udp_hdr_t *)(buf+off);
        off += sizeof(udp_hdr_t);

        printf("Packet %u: ", pkt_count);

        /*
        if ((ntohs(udp_hdr->dst_port) != CAPWAP_CTRL_PORT) &&
            ntohs(udp_hdr->dst_port) != CAPWAP_DATA_PORT) {
            // Next packet
            printf("Skipped! %u\n", ntohs(udp_hdr->dst_port));
            continue;
        }
        */

        if (verify_packet(buf+off, 
                          pkt_hdr->caplen - sizeof(eth_hdr_t) 
                          - ((vlan_hdr)?sizeof(vlan_hdr_t):0)
                          - sizeof(ip_hdr_t) - sizeof(udp_hdr_t)) == 0 )
            printf("Packet %d verified\n---------------------\n\n",
                    pkt_count);
    }

    return 0;
}

