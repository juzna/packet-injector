/*
 *  OS dependent APIs for Linux
 *
 *  Copyright (C) 2006, 2007, 2008 Thomas d'Otreppe
 *  Copyright (C) 2004, 2005 Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/utsname.h>

#include "radiotap/radiotap-parser.h"
        /* radiotap-parser defines types like u8 that
         * ieee80211_radiotap.h needs
         *
         * we use our local copy of ieee80211_radiotap.h
         *
         * - since we can't support extensions we don't understand
         * - since linux does not include it in userspace headers
         */
#include "radiotap/ieee80211_radiotap.h"
#include "osdep.h"
#include "pcap.h"
#include "crctable_osdep.h"
#include "common.h"
#include "byteorder.h"

#define uchar unsigned char

/*
 * XXX need to have a different read/write/open function for each Linux driver.
 */

struct priv_linux {
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_main;
    int fd_debug;
    int fd_rtc;

    FILE *f_cap_in;

    struct pcap_file_header pfh_in;

    int sysfs_inject;
    char *wl;
    char *main_if;
    unsigned char pl_mac[6];
    int inject_wlanng;
};

#ifndef NULL_MAC
#define NULL_MAC        "\x00\x00\x00\x00\x00\x00"
#endif

unsigned long calc_crc_osdep( unsigned char * buf, int len)
{
    unsigned long crc = 0xFFFFFFFF;

    for( ; len > 0; len--, buf++ )
        crc = crc_tbl_osdep[(crc ^ *buf) & 0xFF] ^ ( crc >> 8 );

    return( ~crc );
}

/* CRC checksum verification routine */

int check_crc_buf_osdep( unsigned char *buf, int len )
{
    unsigned long crc;

    if (len<0)
    	return 0;

    crc = calc_crc_osdep(buf, len);
    buf+=len;
    return( ( ( crc       ) & 0xFF ) == buf[0] &&
            ( ( crc >>  8 ) & 0xFF ) == buf[1] &&
            ( ( crc >> 16 ) & 0xFF ) == buf[2] &&
            ( ( crc >> 24 ) & 0xFF ) == buf[3] );
}


static int linux_get_channel(struct wif *wi) { return 0; }
static int linux_get_freq(struct wif *wi) { return 0; }
static int linux_set_rate(struct wif *wi, int rate) { return 0; }
static int linux_get_rate(struct wif *wi) { return 0; }

static int linux_set_mtu(struct wif *wi, int mtu)
{
    struct priv_linux *dev = wi_priv(wi);
    struct ifreq ifr;

    memset( &ifr, 0, sizeof( struct ifreq ) );

    if(dev->main_if)
        strncpy( ifr.ifr_name, dev->main_if, sizeof( ifr.ifr_name ) - 1 );
    else
        strncpy( ifr.ifr_name, wi_get_ifname(wi), sizeof( ifr.ifr_name ) - 1 );

    ifr.ifr_mtu = mtu;
    if( ioctl( dev->fd_in, SIOCSIFMTU, &ifr ) < 0 )
    {
        return( -1 );
    }

    return 0;
}

static int linux_get_mtu(struct wif *wi)
{
    struct priv_linux *dev = wi_priv(wi);
    struct ifreq ifr;

    memset( &ifr, 0, sizeof( struct ifreq ) );

    if(dev->main_if)
        strncpy( ifr.ifr_name, dev->main_if, sizeof( ifr.ifr_name ) - 1 );
    else
        strncpy( ifr.ifr_name, wi_get_ifname(wi), sizeof( ifr.ifr_name ) - 1 );

    if( ioctl( dev->fd_in, SIOCGIFMTU, &ifr ) < 0 )
    {
        return( -1 );
    }

    return ifr.ifr_mtu;
}

static int linux_read(struct wif *wi, unsigned char *buf, int count, struct rx_info *ri)
{
    struct priv_linux *dev = wi_priv(wi);
    int caplen = 0;

    if( ( caplen = read( dev->fd_in, buf, count ) ) < 0 )
    {
        if( errno == EAGAIN )
            return( 0 );

        perror( "read failed" );
        return( -1 );
    }
//    printf("Captured %d bytes of %d\n", caplen, count);
    write(dev->fd_debug, buf, caplen); // Debug write

    return caplen;
}

static int linux_write(struct wif *wi, unsigned char *buf, int count,
                        struct tx_info *ti)
{
    struct priv_linux *dev = wi_priv(wi);
    unsigned char maddr[6];
    int ret, usedrtap=0;
    
    ret = write( dev->fd_out, buf, count );

    if( ret < 0 )
    {
        if( errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS || errno == ENOMEM )
        {
            usleep( 10000 );
            return( 0 );
        }

        perror( "write failed" );
        return( -1 );
    }

    if( ret < 0 )
    {
        if( errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS || errno == ENOMEM )
        {
            usleep( 10000 );
            return( 0 );
        }

        perror( "write failed" );
        return( -1 );
    }

    return( ret );
}

static int linux_set_channel(struct wif *wi, int channel) { return 0; }
static int linux_set_freq(struct wif *wi, int freq) { return 0; }
int linux_get_monitor(struct wif *wi) { return 0; }
int set_monitor( struct priv_linux *dev, char *iface, int fd ) { return 0; }


static int openraw(struct priv_linux *dev, char *iface, int fd, int *arptype,
		   uchar *mac)
{
    struct ifreq ifr;
    struct ifreq ifr2;
    struct iwreq wrq;
    struct iwreq wrq2;
    struct packet_mreq mr;
    struct sockaddr_ll sll;
    struct sockaddr_ll sll2;

    /* find the interface index */

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, iface, sizeof( ifr.ifr_name ) - 1 );

    if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFINDEX) failed" );
        return( 1 );
    }

    memset( &sll, 0, sizeof( sll ) );
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons( ETH_P_ALL );

    /* lookup the hardware type */
    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    /* lookup iw mode */
    //memset( &wrq, 0, sizeof( struct iwreq ) );
//    strncpy( wrq.ifr_name, iface, IFNAMSIZ );

    /* Is interface st to up, broadcast & running ? */
#if 0 
   if((ifr.ifr_flags | IFF_UP | IFF_BROADCAST | IFF_RUNNING) != ifr.ifr_flags)
    {
        /* Bring interface up*/
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

        if( ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 )
        {
            perror( "ioctl(SIOCSIFFLAGS) failed" );
            return( 1 );
        }
    }
#endif

    /* bind the raw socket to the interface */

    if( bind( fd, (struct sockaddr *) &sll,
              sizeof( sll ) ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "bind(ETH_P_ALL) failed" );
        return( 1 );
    }

    /* lookup the hardware type */

    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    memcpy( mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);

    *arptype = ifr.ifr_hwaddr.sa_family;


    /* enable promiscuous mode */
/*
    memset( &mr, 0, sizeof( mr ) );
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;
    if( setsockopt( fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mr, sizeof( mr ) ) < 0 )
    {
        perror( "setsockopt(PACKET_MR_PROMISC) failed" );
        return( 1 );
    }
*/
    return( 0 );
}

/*
 * Open the interface and set mode monitor
 * Return 1 on failure and 0 on success
 */
static int do_linux_open(struct wif *wi, char *iface)
{
    int kver, unused;
    struct utsname checklinuxversion;
    struct priv_linux *dev = wi_priv(wi);
    char *iwpriv;
    char strbuf[512];
    FILE *f;
    char athXraw[] = "athXraw";
    pid_t pid;
    int n;
    DIR *net_ifaces;
    struct dirent *this_iface;
    FILE *acpi;
    char r_file[128], buf[128];
    struct ifreq ifr;
    char * unused_str;

    if((dev->fd_debug = fopen("/tmp/debug", "w")) < 0) {
        fprintf(stderr, "Unable to open debug dump\n");
	return 1;
    }

    /* open raw socks */
/*    if( ( dev->fd_in = socket( PF_PACKET, SOCK_RAW,
                              htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }

    if( ( dev->fd_main = socket( PF_PACKET, SOCK_RAW,
                              htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }
*/
    if( ( dev->fd_out = socket( PF_PACKET, SOCK_RAW,
                               htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        goto close_in;
    }


    if (openraw(dev, iface, dev->fd_out, &dev->arptype_out, dev->pl_mac) != 0) {
        goto close_out;
    }

    dev->fd_in = dev->fd_out;
    //dev->arptype_in = dev->arptype_out;

    return 0;
close_out:
    close(dev->fd_out);
close_in:
    close(dev->fd_in);
    return 1;
}

static void do_free(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);

        if(pl->wl)
            free(pl->wl);

	if(pl->main_if)
            free(pl->main_if);

	free(pl);
	free(wi);
}

static void linux_close(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);

	if (pl->fd_in)
		close(pl->fd_in);
	if (pl->fd_out)
		close(pl->fd_out);

if(pl->fd_debug) close(pl->fd_debug);

	do_free(wi);
}

static int linux_fd(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);

	return pl->fd_in;
}

static int linux_get_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_linux *pl = wi_priv(wi);
	struct ifreq ifr;
	int fd;

	fd = wi_fd(wi);
	/* find the interface index */

	memset( &ifr, 0, sizeof( ifr ) );
	strncpy( ifr.ifr_name, wi_get_ifname(wi), sizeof( ifr.ifr_name ) - 1 );

	if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
	{
		printf("Interface %s: \n", wi_get_ifname(wi));
		perror( "ioctl(SIOCGIFINDEX) failed" );
		return( 1 );
	}

	if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
	{
		printf("Interface %s: \n", wi_get_ifname(wi));
		perror( "ioctl(SIOCGIFHWADDR) failed" );
		return( 1 );
	}

	memcpy( pl->pl_mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);

	/* XXX */
	memcpy(mac, pl->pl_mac, 6);
	return 0;
}

static int linux_set_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_linux *pl = wi_priv(wi);
	struct ifreq ifr;
	int fd, ret;

	fd = wi_fd(wi);
	/* find the interface index */

	memset( &ifr, 0, sizeof( ifr ) );
	strncpy( ifr.ifr_name, wi_get_ifname(wi), sizeof( ifr.ifr_name ) - 1 );

	if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
	{
		printf("Interface %s: \n", wi_get_ifname(wi));
		perror( "ioctl(SIOCGIFHWADDR) failed" );
		return( 1 );
	}

//         if down
        ifr.ifr_flags &= ~(IFF_UP | IFF_BROADCAST | IFF_RUNNING);

        if( ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 )
        {
            perror( "ioctl(SIOCSIFFLAGS) failed" );
            return( 1 );
        }

// 	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
// 	ifr.ifr_hwaddr.sa_len = 6;
	memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
	memcpy(pl->pl_mac, mac, 6);

        //set mac
        ret = ioctl(fd, SIOCSIFHWADDR, ifr);

        //if up
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

        if( ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 )
        {
            perror( "ioctl(SIOCSIFFLAGS) failed" );
            return( 1 );
        }

        return ret;
}

static struct wif *linux_open(char *iface)
{
	struct wif *wi;
	struct priv_linux *pl;

	wi = wi_alloc(sizeof(*pl));
	if (!wi)
		return NULL;
        wi->wi_read             = linux_read;
        wi->wi_write            = linux_write;
        wi->wi_set_channel      = linux_set_channel;
        wi->wi_get_channel      = linux_get_channel;
        wi->wi_set_freq		= linux_set_freq;
        wi->wi_get_freq		= linux_get_freq;
        wi->wi_close            = linux_close;
	wi->wi_fd		= linux_fd;
	wi->wi_get_mac		= linux_get_mac;
	wi->wi_set_mac		= linux_set_mac;
        wi->wi_get_monitor      = linux_get_monitor;
	wi->wi_get_rate		= linux_get_rate;
	wi->wi_set_rate		= linux_set_rate;
	wi->wi_get_mtu		= linux_get_mtu;
	wi->wi_set_mtu		= linux_set_mtu;


	if (do_linux_open(wi, iface)) {
		do_free(wi);
		return NULL;
	}

	return wi;
}

struct wif *wi_open_osdep(char *iface)
{
        return linux_open(iface);
}

int get_battery_state(void)
{
    char buf[128];
    int batteryTime = 0;
    FILE *apm;
    int flag;
    char units[32];
    int ret;
    static int linux_apm = 1;
    static int linux_acpi = 1;

    if (linux_apm == 1)
    {
        if ((apm = fopen("/proc/apm", "r")) != NULL ) {
            if ( fgets(buf, 128,apm) != NULL ) {
                int charging, ac;
                fclose(apm);

                ret = sscanf(buf, "%*s %*d.%*d %*x %x %x %x %*d%% %d %s\n", &ac,
                                                        &charging, &flag, &batteryTime, units);

                                if(!ret) return 0;

                if ((flag & 0x80) == 0 && charging != 0xFF && ac != 1 && batteryTime != -1) {
                    if (!strncmp(units, "min", 32))
                        batteryTime *= 60;
                }
                else return 0;
                linux_acpi = 0;
                return batteryTime;
            }
        }
        linux_apm = 0;
    }
    if (linux_acpi && !linux_apm)
    {
        DIR *batteries, *ac_adapters;
        struct dirent *this_battery, *this_adapter;
        FILE *acpi, *info;
        char battery_state[128];
        char battery_info[128];
        int rate = 1, remain = 0, current = 0;
        static int total_remain = 0, total_cap = 0;
        int batno = 0;
        static int info_timer = 0;
        int batt_full_capacity[3];
        linux_apm=0;
        linux_acpi=1;
        ac_adapters = opendir("/proc/acpi/ac_adapter");
        if ( ac_adapters == NULL )
            return 0;

        while (ac_adapters != NULL && ((this_adapter = readdir(ac_adapters)) != NULL)) {
            if (this_adapter->d_name[0] == '.')
                continue;
            /* safe overloaded use of battery_state path var */
            snprintf(battery_state, sizeof(battery_state),
                "/proc/acpi/ac_adapter/%s/state", this_adapter->d_name);
            if ((acpi = fopen(battery_state, "r")) == NULL)
                continue;
            if (acpi != NULL) {
                while(fgets(buf, 128, acpi)) {
                    if (strstr(buf, "on-line") != NULL) {
                        fclose(acpi);
                        if (ac_adapters != NULL)
                            closedir(ac_adapters);
                        return 0;
                    }
                }
                fclose(acpi);
            }
        }
        if (ac_adapters != NULL)
            closedir(ac_adapters);

        batteries = opendir("/proc/acpi/battery");

        if (batteries == NULL) {
            closedir(batteries);
            return 0;
        }

        while (batteries != NULL && ((this_battery = readdir(batteries)) != NULL)) {
            if (this_battery->d_name[0] == '.')
                continue;

            snprintf(battery_info, sizeof(battery_info), "/proc/acpi/battery/%s/info", this_battery->d_name);
            info = fopen(battery_info, "r");
            batt_full_capacity[batno] = 0;
            if ( info != NULL ) {
                while (fgets(buf, sizeof(buf), info) != NULL)
                    if (sscanf(buf, "last full capacity:      %d mWh", &batt_full_capacity[batno]) == 1)
                        continue;
                fclose(info);
            }


            snprintf(battery_state, sizeof(battery_state),
                "/proc/acpi/battery/%s/state", this_battery->d_name);
            if ((acpi = fopen(battery_state, "r")) == NULL)
                continue;
            while (fgets(buf, 128, acpi)) {
                if (strncmp(buf, "present:", 8 ) == 0) {
                                /* No information for this battery */
                    if (strstr(buf, "no" ))
                        continue;
                }
                else if (strncmp(buf, "charging state:", 15) == 0) {
                                /* the space makes it different than discharging */
                    if (strstr(buf, " charging" )) {
                        fclose( acpi );
                        return 0;
                    }
                }
                else if (strncmp(buf, "present rate:", 13) == 0)
                    rate = atoi(buf + 25);
                else if (strncmp(buf, "remaining capacity:", 19) == 0) {
                    remain = atoi(buf + 25);
                    total_remain += remain;
                }
                else if (strncmp(buf, "present voltage:", 17) == 0)
                    current = atoi(buf + 25);
            }
            total_cap += batt_full_capacity[batno];
            fclose(acpi);
            batteryTime += (int) (( ((float)remain) /rate ) * 3600);
            batno++;
        }
        info_timer++;

        if (batteries != NULL)
            closedir(batteries);
    }
    return batteryTime;
}
