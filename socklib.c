// Socket functions library

//system includes
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>

#include <linux/netdevice.h>
#include <linux/netlink.h>

//includes from prism2 driver set
//#include <wlan/wlan_compat.h>
//#include <wlan/p80211netdev.h>
#define ETH_P_80211_RAW 0x1900
init_raw_sock(int *fd_sock, char *device) {
	struct ifreq ifr;
	struct sockaddr_ll saddr;
	
	if(device == NULL || fd_sock == NULL)
		return 1;
	
	if((*fd_sock = socket(PF_PACKET, SOCK_RAW, ETH_P_80211_RAW)) < 0) {
		*fd_sock = (int)NULL;
		return 1;
	}
	
	bzero((char *)&ifr, sizeof(ifr));
	strncpy((char *)&(ifr.ifr_name), device,strlen(device)+1);
     	ioctl(*fd_sock, SIOCGIFINDEX , (char *)&ifr);
#ifdef DEBUG
// printf("DEBUG:(init_sock): interface number = %d\n",ifr.ifr_ifindex);
#endif 
	bzero((char *)&saddr, sizeof(saddr));
	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_80211_RAW);
	saddr.sll_ifindex = ifr.ifr_ifindex;

	if(bind(*fd_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0 ) {
		printf("init_sock: Could not bind socket to interface\n");
		return 1;
	}	
	return 0;
}

init_spy_sock(int *fd_sock,char *device) {
	
	struct ifreq ifr;
	struct sockaddr_ll saddr;

	static struct sockaddr_nl nl_sk_addr;
	
	int myset = 10;
	
	if(device == NULL || fd_sock == NULL)
		return 1;
	
	if((*fd_sock = socket(PF_PACKET, SOCK_RAW, ETH_P_ALL)) < 0) {
		*fd_sock = (int)NULL;
		return 1;
	}
	
	bzero((char *)&ifr, sizeof(ifr));
	strncpy((char *)&(ifr.ifr_name), device,strlen(device)+1);
     	ioctl(*fd_sock, SIOCGIFINDEX , (char *)&ifr);
#ifdef DEBUG
	printf("DEBUG:(init_sock): interface number = %d\n",ifr.ifr_ifindex);
#endif 
	
	bzero((char *)&saddr, sizeof(saddr));
	saddr.sll_family = PF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = ifr.ifr_ifindex;

	if(bind(*fd_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0 ) {
		printf("init_sock: Could not bind socket to interface\n");
		return 1;
	}
/*	
	if (setsockopt (*fd_sock, SOL_SOCKET,SO_REUSEADDR, &myset, sizeof(myset)) < 0) {
               printf("init_sniff_socket: Could not set socket options\n");
               return 1;
        }
*/	
}

int read_packet(int fd_sock, char *buf, int buf_len) {
	fd_set fds;
	struct timeval tv;
	int result;
	
	FD_ZERO(&fds);
	FD_SET(fd_sock, &fds);

	tv.tv_sec=1;
	tv.tv_usec=0;
	result = select( fd_sock+1, &fds, NULL, NULL, &tv);
	if(result < 0 ) {
#ifdef DEBUG
		printf("read_packet: select failed\n");
#endif
	}
	if(result == 0) {
#ifdef DEBUG
		printf("read_packet: select timed out\n");
#endif
	}

	if(FD_ISSET(fd_sock,&fds)) {
		result = recv(fd_sock, buf, buf_len,0);
		if(result < 0 ) {
#ifdef DEBUG
			printf("read_packet: recv failed\n");
			return -1;
#endif
		}
		else return result;
	}
	return 0;

}

shut_sock(int fd_sock) {
	return 0;
}

