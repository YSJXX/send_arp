#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>



void input(char* argv[],pcap_t *handle,int sw,const u_char *packet)
{
    struct ether_header * ethhdr = (struct ether_header *) (packet);
    struct arphdr * arphd = (struct arphdr *) (packet + 14);

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


  u_char s_packet[50];
  // dmac search--------------------------------------
  switch(sw)
  {
  case 1:
     for(int i=0;i<=5;i++)
     {
         s_packet[i] = 0xFF;
     }break;
  case 2:
      printf("dmac\n");
      for(int i=0;i<=5;i++)
      {
          s_packet[i] = ethhdr->ether_shost[i];
          printf("%02x ",s_packet[i]);
      }
      printf("\n");
      break;
  }

  // smac --------------------------------------------
  s_packet[6] = (u_char)s.ifr_addr.sa_data[0];
  s_packet[7] = (u_char)s.ifr_addr.sa_data[1];
  s_packet[8] = (u_char)s.ifr_addr.sa_data[2];
  s_packet[9] = (u_char)s.ifr_addr.sa_data[3];
  s_packet[10] = (u_char)s.ifr_addr.sa_data[4];
  s_packet[11] = (u_char)s.ifr_addr.sa_data[5];
  //  ARP 0x0806
  s_packet[12] = 0x08;
  s_packet[13] = 0x06;
  // HardWare type : ethernet 1
  s_packet[14] = 0x00;
  s_packet[15] = 0x01;
  // Protocol type : IPv4 0x0800
  s_packet[16] = 0x08;
  s_packet[17] = 0x00;
  // Hardware size 6 , Protocol size 4
  s_packet[18] = 0x06;
  s_packet[19] = 0x04;
  // OPcode 1 = request ,2 = reply
  s_packet[20] = 0x00;
  s_packet[21] = 0x01;
  // Sender Mac
  s_packet[22] = s_packet[6];
  s_packet[23] = s_packet[7];
  s_packet[24] = s_packet[8];
  s_packet[25] = s_packet[9];
  s_packet[26] = s_packet[10];
  s_packet[27] = s_packet[11];
  // Sender IP
  s_packet[28] = inet_addr(argv[2])&0x000000FF;
  s_packet[29] = (inet_addr(argv[2])&0x0000FF00)>>8;
  s_packet[30] = (inet_addr(argv[2])&0x00FF0000)>>16;
  s_packet[31] = (inet_addr(argv[2])&0xFF000000)>>24;
  /*
 printf("%02x \n",packet[28]);
 printf("%02x \n",packet[29]);
 printf("%02x \n",packet[30]);
 printf("%02x \n",packet[31]);
  */
  // Target Mac
  switch (sw) {
    case 1:
      for(int i=0;i<=5;i++)
      {
          s_packet[32+i] = 0x00;
          //printf("%02x ",packet[32+i]);
      }break;
  case 2:
      printf("taget mac\n");
      for(int i=0;i<=5;i++)
      {
          s_packet[32+i] = ethhdr->ether_shost[i];
          printf("%02x ",s_packet[32+i]);
      }
      printf("\n");
      break;

  }

 // Target IP
 s_packet[38] = inet_addr(argv[3])&0x000000FF;
 s_packet[39] = (inet_addr(argv[3])&0x0000FF00)>>8;
 s_packet[40] = (inet_addr(argv[3])&0x00FF0000)>>16;
 s_packet[41] = (inet_addr(argv[3])&0xFF000000)>>24;
 /*
 printf("%02x \n",packet[38]);
 printf("%02x \n",packet[39]);
 printf("%02x \n",packet[40]);
 printf("%02x \n",packet[41]);
  */


 int res = pcap_sendpacket(handle,s_packet,50);
     if(res == -1)
         printf("error\n");
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


        struct ether_header * ethhdr = (struct ether_header *) (packet);
        struct arphdr * arphd = (struct arphdr *) (packet + 14);

        if(ntohs(ethhdr->ether_type) == ETHERTYPE_ARP&& ntohs(arphd->ar_op) == ARPOP_REPLY )
            input(argv,handle,2,packet);

      pcap_close(handle);
      return 0;
    }

