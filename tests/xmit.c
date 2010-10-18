// Testing C program: will inject packet to ethernet interface. Btw: it's really simple, more than I imagined ;)

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>


static int get_iface_index(int fd, const char *device)
{
    struct ifreq ifr;
 
    memset(&ifr, 0, sizeof(ifr));
    strncpy (ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
 
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
    {
        return (-1);
    }
 
    return ifr.ifr_ifindex;
}

int main(int argc, char** argv) {
  int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  char device[] = "eth1";
  char packet[] = "ahoj lamo";
  unsigned int size = sizeof(packet);
  int c = 0;

  if (fd == -1) {
      if (errno == EPERM) {
          printf("%s(): UID/EUID 0 or capability CAP_NET_RAW required", __func__);
       } else {
          printf("socket: %s", strerror(errno));
       }
      return 1;
  }

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof (sa));
  sa.sll_family    = AF_PACKET;
  sa.sll_ifindex   = get_iface_index(fd, device);
  if (sa.sll_ifindex == -1) return 2;
  sa.sll_protocol  = htons(ETH_P_ALL);

  c = sendto(fd, packet, size, 0, (struct sockaddr *)&sa, sizeof (sa));
  if (c != size) {
    printf("libnet_write_link(): only %d bytes written (%s)\n", c, strerror(errno));
  }
  else {
    printf("Written %d bytes\n", c);
  }

  return 0;
}

