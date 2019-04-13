#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <arpheader.h>



#define PACKETSIZE sizeof(struct allpacket)

void input(char* argv[],pcap_t *handle,int sw,const u_char *packet)
{
    /*
   //IP check
  int i=0;
  for(i=2;i<4;i++)
  {
      printf("aa %s\n",argv[i]);
  }*/

   // Mac Adderss -------------------------------
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, "eth0");
  ioctl(fd, SIOCGIFHWADDR, &s);

  printf("My Mac Address : ");
  for (int x = 0; x < 6; ++x)
  printf("%02x ", (u_char) s.ifr_addr.sa_data[x]);
  printf("\n");

  //--------------------------------------------
  //ethernet
  struct ether_header * ethhdr = (struct ether_header *) packet;
  u_char pkt[PACKETSIZE];
  struct allpacket *s_packet = (struct allpacket *)pkt;
  //struct allpacket *s_packet = malloc(sizeof(struct allpacket));
  //struct allpacket *r_packet = (struct allpacket *) (packet);
  // dmac search--------------------------------------
  switch(sw)
  {
  case 1:
      printf("dmac :");
     for(int i=0;i<=5;i++)
     {
        s_packet->e_dmac[i] = 0xFF;
        printf("%02x ",s_packet->e_dmac[i]);
     }
     printf("\n");
     break;
  case 2:
      printf("dmac :");
      for(int i=0;i<=5;i++)
      {
          s_packet->e_dmac[i] = ethhdr->ether_dhost[i];
          printf("%02x ",s_packet->e_smac[i]);
      }
      printf("\n");
      break;
  }

      //smac --------------------------------------------
  printf("smac :");
    for(int i=0; i<=5;i++)
    {
        s_packet->e_smac[i] = (u_char)s.ifr_addr.sa_data[i];
        printf("%02x ",s_packet->e_smac[i]);
    }
    printf("\n");

      //  ARP 0x0806
      s_packet->type = ntohs(0x0806);
      printf("type : %04x\n",s_packet->type);
      //ARP-----------------------------
      // HardWare type : ethernet 1
      s_packet->hd_type = ntohs(0x0001);
      printf("hd_type %04x\n",s_packet->hd_type);

      // Protocol type : IPv4 0x0800
      s_packet->protocol_type = ntohs(0x0800);
      printf("protocol_type %04x\n",s_packet->protocol_type);

      // Hardware size 6 , Protocol size 4
      s_packet->hd_size = 0x06;
      s_packet->protocol_size = 0x04;

      printf("hd_size %02x\n",s_packet->hd_size);
      printf("protocol_size %02x\n",s_packet->protocol_size);

      // OPcode 1 = request ,2 = reply
      switch (sw) {
      case 1:
          s_packet->opcode = ntohs(0x0002);
          printf("opcode %04x\n",s_packet->opcode);

          break;
      case 2:
          s_packet->opcode = ntohs(0x0001);
          printf("opcode %04x\n",s_packet->opcode);
          break;
      }

      // Sender Mac
      printf("sender mac : ");
      for(int i=0; i<=5;i++)
      {
           s_packet->a_s_mac[i] = s_packet->e_smac[i] ;
           printf(" %02x ", s_packet->a_s_mac[i]);
      }
      printf("\n");
      // Sender IP

      s_packet->a_s_protocol[0] = inet_addr(argv[2])&0x000000FF;
      s_packet->a_s_protocol[1] = (inet_addr(argv[2])&0x0000FF00)>>8;
      s_packet->a_s_protocol[2] = (inet_addr(argv[2])&0x00FF0000)>>16;
      s_packet->a_s_protocol[3] = (inet_addr(argv[2])&0xFF000000)>>24;

        printf("sender IP %d",inet_addr(argv[2])&0x000000FF);
        printf(" %d",(inet_addr(argv[2])&0x0000FF00)>>8);
        printf(" %d",(inet_addr(argv[2])&0x00FF0000)>>16);
        printf(" %d ",(inet_addr(argv[2])&0xFF000000)>>24);
        printf("\n");
      // Target Mac
      switch (sw) {
        case 1:
          printf("Target Mac : ");
          for(int i=0;i<=5;i++)
          {
              s_packet->a_t_mac[i] = 0x00;
              printf("%02x ",s_packet->a_t_mac[i]);
          }
          printf("\n");
          break;
      case 2:
          printf("taget mac\n");
          for(int i=0;i<=5;i++)
          {
              s_packet->a_t_mac[i] = ethhdr->ether_shost[i];
          }
          printf("\n");
          break;

      }

     // Target IP
     s_packet->a_t_protocol[0] = inet_addr(argv[3])&0x000000FF;
     s_packet->a_t_protocol[1] = (inet_addr(argv[3])&0x0000FF00)>>8;
     s_packet->a_t_protocol[2] = (inet_addr(argv[3])&0x00FF0000)>>16;
     s_packet->a_t_protocol[3] = (inet_addr(argv[3])&0xFF000000)>>24;

     printf("\nTarget IP %d",inet_addr(argv[3])&0x000000FF);
     printf(" %d",(inet_addr(argv[3])&0x0000FF00)>>8);
     printf(" %d",(inet_addr(argv[3])&0x00FF0000)>>16);
     printf(" %d \n",(inet_addr(argv[3])&0xFF000000)>>24);
     /*
     printf("%02x \n",packet[38]);
     printf("%02x \n",packet[39]);
     printf("%02x \n",packet[40]);
     printf("%02x \n",packet[41]);
      */

        int res = pcap_sendpacket(handle,pkt,sizeof(pkt));

        if(res == -1)
             printf(" error\n");
}

int main(int argc, char* argv[]) {

      if (argc != 4) {
         printf("error\n");
         return -1;
       }

      char* dev = argv[1];
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
      if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
      }

       input(argv,handle,1,0);


        struct pcap_pkthdr* header;
        const u_char* packet;
        pcap_next_ex(handle, &header, &packet);


        struct allpacket * new_packet = (struct allpacket *) packet;
        if(ntohs(new_packet->type) == ETHERTYPE_ARP
                && ntohs(new_packet->opcode) == ARPOP_RREQUEST )
            input(argv,handle,2,packet);

      pcap_close(handle);
      return 0;
    }

