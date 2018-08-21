#include <pcap.h>
#include <stdio.h>


void usage() {

  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

char* GetMAC(u_char *packet, int type)
{
  //TYPE -> 1=src, 2=dst

  int offset=0, i;

  if(type != 1)
    offset += 6;

  static char mac[20];

  for(i=0; i<5; i++)

    sprintf(mac+(i*3), "%02x:", packet[offset+i]);
    sprintf(mac+(i*3), "%02x", packet[offset+i]);

  return mac;
}


char* GetIP(u_char *packet, int type)
{
  int offset=26;

  if(type != 1)
    offset += 4;

  static char ip[20];

  sprintf(ip, "%d.%d.%d.%d", packet[offset],packet[offset+1],packet[offset+2],packet[offset+3]);
  return ip;
}


char* GetPort(u_char *packet, int type)
{

  int offset=34;

  if(type != 1)
    offset += 2
;
  static char port[6];

  sprintf(port, "%d", packet[offset]*0x100 + packet[offset+1]);

  return port;
}

char* GetData(u_char *packet)
{

  int offset=0x36;

  while(sizeof(packet) - offset > 0 && offset - 0x36 < 16)
  {

    printf("%02x ", packet[offset++]);

  }

  printf("\n");
}


int main(int argc, char* argv[]) {

  if (argc != 2) {

    usage();

    return -1;
  }

  char* dev = argv[1];

  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) {

    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);

    return -1;
  }

  int count=0;

  while (true) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("packet number is %d\n", ++count);
    printf("%u bytes captured\n", header->caplen);

    printf("source MAC address:%s\t", GetMAC((u_char*)packet, 1));
    printf("destination MAC address:%s\n", GetMAC((u_char*)packet, 2));

    if(packet[12] != 0x08 || packet[13] != 0x00){ 
      printf("It is not an IPv4 packet\n");
      continue;
    }

    printf("source IP:%s\t", GetIP((u_char*)packet, 1));
    printf("destination IP:%s\n", GetIP((u_char*)packet, 2));

    if(packet[23] != 0x06){
      printf("There is no packet !\n");
      continue;
    }

    printf("source port:%s\t", GetPort((u_char*)packet, 1));
    printf("destination port:%s\n", GetPort((u_char*)packet, 2));
    printf("data:");
    GetData((u_char*)packet);
  }

  pcap_close(handle);
  return 0;
}
