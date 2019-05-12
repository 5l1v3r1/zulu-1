/* Main 'zulu' handler file

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

// system includes
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>

//local includes
#include "socklib.h"
#include "zulu.h"
#include "p80211.h"

#define TYPE_UNKNOWN 	0x00
#define TYPE_FRG_BEACON 0x01
#define TYPE_FRG_DISASS 0x02
#define TYPE_BW_HOG	    0x03
#define TYPE_WLAN_SPY	0x04
#define TYPE_FRG_ASS	0x05
#define TYPE_FRG_DATA_TODS    0x06 
#define TYPE_FRG_PSPOLL    0x07 
#define TYPE_FRG_PROBE_REQ 0x08
#define TYPE_FRG_AUTH 0x09
#define TYPE_FRG_AUTH_SHARED 10
#define TYPE_ASS_RESP 11
#define TYPE_FRG_ATIM 12
#define TYPE_FRG_ARBIT_IE_PROBE_REQ 14 // Hacked to send probe responses.
#define TYPE_FRG_DEAUTH	15
#define TYPE_FRG_RTS 16
#define TYPE_FRG_CTS 17
#define TYPE_VER_DISTRIB 18

#define DEFAULT_PACK_SIZE 	64
#define DEFAULT_BEACON_INT 	100
#define DEFAULT_DELAY		100
#define STR_MAC_LEN 		2*6 
#define MAX_DEVICE_LEN		32
//#define DEFAULT_CHANNEL		1
#define DEFAULT_CHANNEL		165
#define DEFAULT_SRC_MAC		"\x00\x01\x02\x03\x04\x05"
#define DEFAULT_DES_MAC		"\xff\xff\xff\xff\xff\xff"
#define DEFAULT_NO_FRAMES_TO_SEND 1

#define MAX_FILE_LGTH 128
// local forward declarations
void usage(int argc, char *argv[]);
int str_to_mac(unsigned char *,unsigned char *);
void abort();
void stop();
/* image credits http://sherlocco.com/engines/lordofrings/Bblocks/Zulu%20.aspx */
// socket is global, so that stop signal can close it down
int fd_sock;
unsigned int delay;

static int min(int a,int b) {
  return (a<b? a : b);
}

int main(int argc, char *argv[]) {
  unsigned char src_mac[] = DEFAULT_SRC_MAC; 
  unsigned char dest_mac[] = DEFAULT_DES_MAC;
  unsigned char channel;
  char ssid[WLAN_SSID_MAXLEN] = "zulu";
  unsigned int pack_size,beac_int;	
  char device[MAX_DEVICE_LEN] = "wlan0";
  char distri_file[MAX_FILE_LGTH];
  char error_message[WLAN_SSID_MAXLEN] = "";
	
  int type, countFramesToSend;
  short reason_code;
  char c;
  unsigned char flags;

  FILE *f_distri;
  int data_distri = 0;
  int mgmt_distri = 0;
  int ctrl_distri = 0;
  char temp_count [5];
  char type_distri [10];
  int read_count = 0;
  __u16 duration = 0;
  __u16 sequence = 0;
  __u8 fragment = 0;
  __u8 data_type = 0;
  __u16 assoc_id = 0;
  int in_ch = 6; //default channel is 6
  beac_int = DEFAULT_BEACON_INT;
  reason_code = WLAN_RSN_DISAS_INAC;
  type = TYPE_UNKNOWN;
  pack_size = DEFAULT_PACK_SIZE;
  delay = DEFAULT_DELAY;
  channel = DEFAULT_CHANNEL;
  countFramesToSend =  DEFAULT_NO_FRAMES_TO_SEND;
  flags=0; //default value: where all the flags are set to 0

  bzero(distri_file, MAX_FILE_LGTH);
  bzero(temp_count, 5);
  bzero(type_distri, 10);
  
  while(1) 	{
        static struct option long_options[] =
        {
               {"to_ap",     no_argument,       0, 'a'},
	       {"from_ap",     no_argument,       0, 'b'},
	       {"adhoc",     no_argument,       0, 'c'},
	       {"bridge",    no_argument,       0, 'e'},
	       {"cf_ack",    no_argument,       0, 'g'},
	       {"cf_poll",    no_argument,       0, 'h'},
	       {"null_data",    no_argument,       0, 'j'},
               {"ssid",         required_argument, 0, 'k'},
               {"duration",  required_argument, 0, 'z'},
	       {"delay", required_argument, 0, 'q'},
               {"sequence",  required_argument, 0, 'y'},
               {"file",    required_argument, 0, 'x'},
               {"fragment", required_argument, 0, 'l'},
               {"channel", required_argument, 0, 'u'},
               {0, 0, 0, 0}
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;
     
        c = getopt_long (argc, argv, "wrmopi:t:s:f:n:d:",
                         long_options, &option_index);
     
        /* Detect the end of the options. */
        if (c == -1)
          break;

	switch(c) {
	case 'z':
	  if(long_options[option_index].name == "duration") {
	    duration = atoi(optarg);
	    printf("duration set to %i\n",duration);
	  }
	  break;
	case 'y':
	  sequence = atoi(optarg);
	  flags = flags | 0x08; //retry bit
	  break;
        case 'k':
          //printf("setting ssid to %s\n",optarg);
          memcpy(ssid,optarg,min(WLAN_SSID_MAXLEN,strlen(optarg)));
	  ssid[min(WLAN_SSID_MAXLEN,strlen(optarg))]= '\0';
          break;
	case 'g':
	  data_type = data_type | 0x10;//cf-ack
	  break;
	case 'h':
	  data_type = data_type | 0x20;//cf-poll
	  break;
	case 'j':
	  data_type = data_type | 0x40;//null data
	  break;
	case 'a':
	  flags = flags & 0xfc; //clear the last two bits
	  flags = flags | 0x01; //to_ap
	  break;
	case 'b':
	  flags = flags & 0xfc; //clear the last two bits
	  flags = flags | 0x02; //from_ap
	  break;
	case 'c':
	  flags = flags & 0xfc; //clear the last two bits adhoc
	  break;
        case 'u':
          in_ch = atoi(optarg);
	  break;
	case 'e':
	  flags = flags & 0xfc; //clear the last two bits
	  flags = flags | 0x03; //bridge
	  break;
	case 'p':
	  flags = flags | 0x10; //pwr mang bit
	  break;
	case 'f':
          flags = flags | 0x04; //frag bit
	  break;
        case 'l':
          fragment = atoi(optarg);
	  break;
	case 'q':
	  delay=atoi(optarg);
	  break;
	case 'i':
	  strcpy(device,optarg);
	  break;
	case 't':
	  type=atoi(optarg);
	  break;
	case 'x':
	   strcpy(distri_file, optarg);
	   break;
	case 'r':
          //flags |= WLAN_RETRY;
	  flags = flags | 0x08; //Retry bit
	  break;
	case 'w':
	  flags = flags | 0x40; //Wep bit
	  break;
	case 'm':
	  flags = flags | 0x20; //More bit
	  break;
	case 'o':
	  flags = flags | 0x80; //Order bit
	  break;
        case 'n' :
	  countFramesToSend = atoi(optarg);
	  break;
	case 's':
	  if(str_to_mac(src_mac,optarg)) {
		printf("source MAC entry invalid\n");
		return 1;
	  }
	  break;
	case 'd':
	  if(str_to_mac(dest_mac,optarg)) {
		printf("destination MAC entry invalid\n");
		return 1;
	  }
	  break;
	default:
	  usage(argc,argv);	
	}
  }
  if(type == TYPE_UNKNOWN)
	usage(argc,argv);
#ifdef DEBUG
  printf("Program parameters:\n"\
		 "type: %d\n"\
		 "src mac: %x:%x:%x:%x:%x:%x\n"\
		 "dest mac: %x:%x:%x:%x:%x:%x\n"\
		 "device: %s\n"\
		 "channel: %d\n"\
		 "delay: %u micro sec\n"\
		 ,type,
		 src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5],
		 dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5],
		 device,
		 channel,
		 delay);
#endif	
  if(optind < argc) {
	switch(type) {
	case TYPE_FRG_BEACON:
	  memcpy(ssid,argv[optind],min(WLAN_SSID_MAXLEN,strlen(argv[optind])));
	  ssid[min(WLAN_SSID_MAXLEN,strlen(argv[optind]))]= '\0';
	  printf("optind: %d\t argc: %d\n",optind, argc);
	  if(optind+1 < argc)
		beac_int=atoi(argv[optind+1]);
	  if(optind+2 < argc)
		channel = atoi(argv[optind+2]);
	  break;
	case TYPE_FRG_DISASS:
	  if(optind < argc) {
		reason_code=atoi(argv[optind]);
	  }
	  break;
	case TYPE_FRG_DEAUTH:
	  if(optind < argc) {
		reason_code=atoi(argv[optind]);
	  }
	  break;
	case TYPE_BW_HOG:
	  if(optind < argc) {
		pack_size=atoi(argv[optind]);
	  }	
	  break;
	case TYPE_FRG_ASS:
	  break;
	case TYPE_FRG_DATA_TODS:
	  break;
	case TYPE_FRG_RTS:

	   break;
	case TYPE_FRG_CTS:

	   break;
	case TYPE_FRG_PSPOLL:
	  if(optind  < argc) {
		assoc_id = atoi(argv[optind]);
		printf("assoc_id = %x\n", assoc_id);
	  }
	  break;
	case TYPE_FRG_PROBE_REQ:
	  break;
	case TYPE_FRG_AUTH:
	  
	  break;
	case TYPE_FRG_AUTH_SHARED:

	  break;
	case TYPE_ASS_RESP:
	  break;
	case TYPE_FRG_ARBIT_IE_PROBE_REQ: // Hack for probe response
	  if(optind < argc)
		beac_int=atoi(argv[optind+1]);
	  if(optind+1 < argc)
		channel = atoi(argv[optind+2]);
	  break;
	default:
	  abort();		
	}
  }

  signal(SIGINT, stop);
#ifdef DEBUG
  printf("Using device = %s\n",device);
#endif	
  if(iwconfig_set_ssid(device,error_message,"zulu") < 0) {
    printf("main: could not set essid%s\n",error_message);
    return 1;
  }
  if(iwconfig_set_channel(device,error_message,in_ch) < 0) {
    printf("main: could not set channel %s\n",error_message);
    return 1;
  }
  if(type != TYPE_WLAN_SPY) 	{
	if(init_raw_sock(&fd_sock, device)) {
	  printf("main: could not create socket\n");
	  return 1;
	}
  }
  else { 
	if(init_spy_sock(&fd_sock, device)) {
	  printf("main: could not create socket\n");
	  return 1;
	}
  }	
  switch(type) {
  case TYPE_FRG_BEACON:
     /* Forge beacons*/
     printf("Sending %d beacons", countFramesToSend);
     if(forge_beacon(fd_sock,src_mac, ssid, beac_int,channel,countFramesToSend,duration, flags, fragment, sequence)) {
	//printf("main: forge_beacon failed\n");
	return 1;
     }
     break;

  case TYPE_FRG_DISASS:
	/* forge disassociations */
    if(forge_disassoc(fd_sock,src_mac,dest_mac,reason_code,countFramesToSend, duration, flags, sequence, fragment)) {
	  //printf("main: forge_disassoc failed\n");
	  return 1;
	}
	break;

  case TYPE_FRG_DEAUTH:
	/* forge deauths */
    if(forge_deauth(fd_sock,src_mac,dest_mac,reason_code,countFramesToSend,duration,flags, fragment, sequence)) {
	  //printf("main: forge_deauth failed\n");
	  return 1;
	}
	break;
  case TYPE_BW_HOG:
	/* just send garbage data on the air */
    if(bw_hog(fd_sock,src_mac,pack_size,countFramesToSend)) {
	  //printf("main: bw_hog failed\n");
	  return 1;
	}
	break;
  case TYPE_WLAN_SPY:
	if(wlan_spy(fd_sock)) {
	  //printf("main: wlan_spy failed\n");
	}
	break;	
  case TYPE_FRG_ASS:
    if(forge_ap_flood_associate(fd_sock,src_mac,dest_mac,ssid,countFramesToSend,duration,flags, fragment, sequence)) {
	  //printf("main: forge_ap_flood_associate failed\n");
	}
	break;
  case TYPE_FRG_DATA_TODS:
    if(forge_Data(fd_sock,src_mac,dest_mac,1,countFramesToSend,flags,duration,fragment,sequence,data_type)) {
	  //printf("main: forge_Data to DS failed\n");
	}
	break;
  case TYPE_FRG_RTS:
    if(forge_control_rts(fd_sock,src_mac,dest_mac,countFramesToSend,duration,flags)) {
	//printf("main: forge_Data to DS failed\n");
     }
     break;
  case TYPE_FRG_CTS:
    if(forge_control_cts(fd_sock,dest_mac,countFramesToSend,duration,flags)) {
	//printf("main: forge_Data to DS failed\n");
     }
     break;
  case TYPE_VER_DISTRIB:
     f_distri=fopen(distri_file, "r");
     if (f_distri == NULL) {
	printf("Cannot open the distribution file\n");
	exit(1);
     }

     read_count = fscanf(f_distri,"%s %s", type_distri, temp_count);
     if (read_count !=2) {
	printf("Error in distribution file\n");
	exit(1);
     }
     data_distri = atoi(temp_count);
     
     read_count = fscanf(f_distri,"%s %s", type_distri, temp_count);
     if (read_count !=2) {
	printf("Error in distribution file\n");
	exit(1);
     }
     mgmt_distri = atoi(temp_count);
     
     read_count = fscanf(f_distri,"%s %s", type_distri, temp_count);
     if (read_count !=2) {
	printf("Error in distribution file\n");
	exit(1);
     }
     ctrl_distri = atoi(temp_count);
     if(forge_ver_distrib(fd_sock,src_mac,dest_mac,data_distri, mgmt_distri, ctrl_distri)) {
	//printf("main: Verification of Distribution failed\n");
     }
     break;
 case TYPE_FRG_PSPOLL:
	/* Hack */
   if(forge_pspoll(fd_sock,countFramesToSend,src_mac,dest_mac,assoc_id,flags)) {
	 //printf("main: forge_pspoll failed\n");
   }
   break;
 case TYPE_FRG_ATIM:
   if(forge_atim(fd_sock,countFramesToSend,src_mac,dest_mac,duration,flags,fragment,sequence)) {
     //printf("main: forge_atim failed\n");
   }
 case TYPE_FRG_PROBE_REQ:
   if(forge_ProbeRequest(fd_sock,src_mac,ssid,countFramesToSend,0, duration,flags, fragment,sequence)) {
	 //printf("main: forge_Data from DSfailed\n");
   }
   break;
  case TYPE_FRG_AUTH:
    if(forge_Authentication(fd_sock, src_mac, dest_mac, 0,countFramesToSend,duration, flags, fragment, sequence)) {
	  // printf("main: frg Authentication failed\n");
	}
   break;
  case TYPE_FRG_AUTH_SHARED:
    if(forge_Authentication(fd_sock, src_mac, dest_mac, 1, countFramesToSend,duration, flags, fragment, sequence)) {
	  //printf("main: frg Authentication failed\n");
	}
	break;
  case TYPE_ASS_RESP:
    if(forge_associate_resp(fd_sock, src_mac, dest_mac,countFramesToSend,duration,flags,fragment,sequence)) {
	  //printf("main: frg Association response failed\n");
	}
	break;
  case TYPE_FRG_ARBIT_IE_PROBE_REQ:

	// Probe response hack
    if(forge_proberesponse(fd_sock,src_mac, ssid, beac_int,channel,countFramesToSend,duration,flags,fragment,sequence)) {
	  //printf("main: forge_beacon failed\n");
	  return 1;
	}
	break;
  default:
	abort();	
  }				
		
	
  if(shut_sock(fd_sock)) {
	printf("main: could not shut down socket\n");
	return 1;
  }
		

  return 0;	
		
}

void usage(int argc, char *argv[]) {
  printf("\n\n%s: Which 802.11 n/w do u want to bring down today ?\n\n",argv[0]);
  printf("802.11 Data/Mgmt Frame Generator\n");
  printf("Usage: %s -t <frame type> -i <interface> [options]\n");
  printf("\nOptional arguments:\n\t-s <source MAC> \n\t-d <destination MAC>\n\t-n <number of frames to send>\n\t-w : set WEP bit\n\t-r : set retry bit\n\t-p : set power mangement bit\n\t-o : set order bit\n\t-m : set more data bit\n\t-f : sets the fragment bit\n\t--sequence <frame sequence number>\n\t--duration <duration>\n\t--delay = <delay between consecutive frames>\n\t--ssid <ssid string>\n\t--to_ap\n\t--from_ap\n\t--adhoc\n\t--bridge\n\t--cf_ack\n\t--cf_poll\n\t--null_data\n\t--channel <channel #>\n\nFrame Types:\n"\
	 "\ttype 1 Beacon:  <beacon interval> and <channel> as parameters\n"\
	 "\ttype 2 Dissociation: <reason code>\n"\
	 "\ttype 3 Junk Packet: <packet size>\n"\
	 "\ttype 4 Sniff:takes no inputs.. sniff n/w in this mode\n"\
	 "\ttype 5 Association req:\n"
	 "\ttype 6 Data: --cf_ack --cf_poll --null_data are used to set the data type\n"\
	 "\ttype 7 Power-Save Poll: <Association ID>\n"\
	 "\ttype 8 Probe Request: forge a probe request\n"\
	 "\ttype 9 Open Authentication frame: \n"\
	 "\ttype 10 Shared Authentication frame: \n"\
	 "\ttype 11 Asssociation Response frame:  \n"\
	 "\ttype 12 ATIM: \n"\
	 "\ttype 14 Probe response: <beacon interval>\n"\
	 "\ttype 15 Deauth: <reason code>\n"\
	 "\ttype 16 Control RTS:  \n"\
         "\ttype 17 Control CTS:  \n" \
	 "\ttype 18 Verify Distrib: --file Distribution_file \n");
  
  exit(1);	
}

void stop() {
  printf("Shutting up...\n");
  fflush(stdout);
  shut_sock(fd_sock);
  exit(EXIT_SUCCESS);
}

void abort() {
  printf("Error occured. Terminating...adios !\n");
  exit(1);
}

int str_to_mac(unsigned char *mac, unsigned char *str) {
  unsigned short int dig1,dig2;
	
  if(strlen(str) != STR_MAC_LEN)
	return 1;
	
  while (*str && *(str+1)) {
	dig1= *str;
	dig2= *(str+1); 
	
	if(!(isxdigit(dig1) || isxdigit(dig2)))
	  return 1;
	dig1 = ctoi(dig1) * 16 + ctoi(dig2);
	memcpy(mac,&dig1,1);
	mac++;
	str+=2;
		
  }
  return 0;	
}

int ctoi(int c) {
  if(!isxdigit(c))
	return -1;
  c -= '0';
  if(c <= 9)
	return c;
  c= c - ( 'A' - '0') + 10;
  if(c <= 15)
	return c;
  c= c - ( 'a' - 'A') ;
  return c;
	
}

