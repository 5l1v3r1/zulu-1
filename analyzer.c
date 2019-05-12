// Packet analyzer
//
#include <stdio.h>
#include <asm/types.h>
#include <string.h>
// local includes
#include "p80211.h"
#include "wlaninfo.h"
#include "llist.h"
#include "macros.h"
#include "config.h"

int handle_mgmt(unsigned char *packet, unsigned int pack_len, p80211_hdr_t * p_phdr);
int handle_data(unsigned char *packet, unsigned int pack_len, p80211_hdr_t * p_phdr);

int handle_mgmt_beacon(unsigned char *packet, unsigned int pack_len, p80211_hdr_t *p_phdr);

int analyze_packet(unsigned char *packet, unsigned int pack_len) {
	static p80211_hdr_t phdr, *p_phdr;
	
	// we assume that the FCS at the end of the packet is also passed on to us and hence we reduce the packet length field here itself accordingly.
	pack_len -= WLAN_FCS_LEN;
	
	p_phdr = &phdr;

	memset(p_phdr, 0, sizeof(p80211_hdr_t));
	
	if(pack_len >= sizeof(p_phdr->hdr1))
		memcpy(&(p_phdr->hdr1), packet, sizeof(p_phdr->hdr1));
	else
		return 1;

	
	switch(GET_FTYPE(p_phdr)) {
		case WLAN_FTYPE_MGMT:
#ifdef MOREDEBUG			
			printf("Found mgmt pkt!\n");
#endif
			if(handle_mgmt(packet,pack_len,p_phdr)) {
#ifdef MOREDEBUG
				printf("Bad management packet on the air!\n");
#endif				
				return 1;
			}
				
			break;
		case WLAN_FTYPE_CTRL:
#ifdef MOREDEBUG
			printf("Found ctrl pkt!\n");
#endif
			break;
		case WLAN_FTYPE_DATA:
#ifdef MOREDEBUG
			printf("Found data pkt!\n");
#endif
			if(handle_data(packet,pack_len,p_phdr)) {
#ifdef MOREDEBUG
				printf("Bad data packet on the air!\n");
#endif
				return 1;
			}
			break;
		default:
			break;	
				
	}	
}

int handle_mgmt(unsigned char *packet, unsigned int pack_len, p80211_hdr_t * p_phdr){

  // management frames always contain 3 addresses, hence copy all the remaining header information
  unsigned n_prem_len;
  
  my_client_info_t mci,*p_mci;
  
  n_prem_len = pack_len;	
  
  if(n_prem_len >= WLAN_3ADDR_HDR_LEN )
	memcpy(p_phdr,packet,WLAN_3ADDR_HDR_LEN);
  else
	return 1;
  
  packet += WLAN_3ADDR_HDR_LEN;
  n_prem_len -= (WLAN_3ADDR_HDR_LEN);
  
  switch(GET_FSUBTYPE(p_phdr)) {
  case WLAN_MGMT_BEACON:
#ifdef MOREDEBUG
	printf("I see a beacon !\n");
#endif
	if(handle_mgmt_beacon(packet,n_prem_len,p_phdr)) {
#ifdef DEBUG
	  printf("Bad beacon on the air, ");
	  DISPLAY_MAC(p_phdr->hdr2.mac2);
	  printf(" is playing dirty !! \n");
#endif
	  return 1;
	}
	break;
  case WLAN_MGMT_AS_REQ:
	memset(&mci,0,sizeof(my_client_info_t));
	p_mci = &mci;
	memcpy(&p_mci->mac[0],&p_phdr->hdr2.mac2[0],WLAN_ADDR_LEN);
	memcpy(&p_mci->dest_mac[0],&p_phdr->hdr2.mac1[0],WLAN_ADDR_LEN);
	p_mci->state = CLI_ST_ASSOING;
	update_client_list(p_mci);
	break;
  case WLAN_MGMT_REAS_REQ:
	memset(&mci,0,sizeof(my_client_info_t));
	p_mci = &mci;
	memcpy(&p_mci->mac[0],&p_phdr->hdr2.mac2[0],WLAN_ADDR_LEN);
	memcpy(&p_mci->dest_mac[0],&p_phdr->hdr2.mac1[0],WLAN_ADDR_LEN);
	p_mci->state = CLI_ST_REASING;
	update_client_list(p_mci);
	break;
  case WLAN_MGMT_PROB_REQ:
	memset(&mci,0,sizeof(my_client_info_t));
	p_mci = &mci;
	memcpy(&p_mci->mac[0],&p_phdr->hdr2.mac2[0],WLAN_ADDR_LEN);
	memcpy(&p_mci->dest_mac[0],&p_phdr->hdr2.mac1[0],WLAN_ADDR_LEN);
	p_mci->state = CLI_ST_PROBING;
	update_client_list(p_mci);
	break;
  default:
	break;	
  }
  return 0;
}

int handle_mgmt_beacon(unsigned char *p_raw_binf, unsigned int n_prem_len, p80211_hdr_t * p_phdr) {

	my_beacon_info_t mbi, *p_mbi;
	info_element *p_ie_new;
	unsigned n_skip,n_stdskip,n_lenoff;
	__u16	temp;
	
	// beacon includes the fixed fields: timestamp, beacon interval, capability information
	// IE's are SSID, supp rates, 1 or more PHY sets, optional CF, IBSS, TIM sets and  reserved sets if any	....
	// we are only interested in timestamp, beacon, interval, capability, SSID and supported rates.

	// do this so that we can write any macros if any considering that we pass a pointer as parameter instead of the actual struct.

	n_stdskip = sizeof(p_ie_new->id) + sizeof(p_ie_new->length);
	n_lenoff = sizeof(p_ie_new->id);
	
	memset(&mbi,0, sizeof(my_beacon_info_t));
	p_mbi = &mbi;
	
	memcpy(&p_mbi->mac[0],&p_phdr->hdr2.mac2[0],WLAN_ADDR_LEN);
	if(n_prem_len >= WLAN_BEACON_FIXED_PARAM_LEN) {
		memcpy(&p_mbi->beacon_interval,&p_raw_binf[WLAN_BEACON_BI_OFFSET],sizeof(p_mbi->beacon_interval));
		memcpy(&temp,&p_raw_binf[WLAN_BEACON_CAP_OFFSET],sizeof(temp));
		p_mbi->wep_status = temp & WLAN_BEACON_CAP_WEP_MASK;
	}
	else 
		return 1;

	p_raw_binf += WLAN_BEACON_FIXED_PARAM_LEN;
	n_prem_len -= WLAN_BEACON_FIXED_PARAM_LEN; 


/* This code gets all beacon information which we are not really interested right now, so what we will do is to gather only the information that we want from the beacon which includes the mac address of AP, beacon interval, channel, ssid and wep status, this information is stored in the data struct called my_beacon_info_t */				
	while(n_prem_len >0 ) {
		switch(p_raw_binf[0]) {
			case WLAN_IE_SSID:
#ifdef MOREDEBUG				
				printf("Found SSID IE!\n");
#endif

/*
// we dont need to make it so complicated to handle raw information and put it in a linked list and all...				
				p_ie_new = malloc(sizeof(info_element));
				p_ie_new->id = p_raw_binf[0];
				p_ie_new->length = p_raw_binf[sizeof(p_ie_new->id)];
				p_ie_new->data = malloc(p_ie_new->length);
				if(p_ie_new->data == NULL) {
					printf("handle_mgmt_beacon: malloc for IE data failed!\n");
					return 1;
				}
				memcpy(p_ie_new->data, &p_raw_binf[sizeof(p_ie_new->id) +sizeof(p_ie_new->length)],p_ie_new->length);
				
				if(add_list_item(&(p_binf->p_ie_list),p_ie_new,sizeof(info_element)))
						return 1;
				p_raw_binf += sizeof(p_ie_new->id) +sizeof(p_ie_new->length) + p_ie_new->length;
				n_prem_len -= sizeof(p_ie_new->id) +sizeof(p_ie_new->length) + p_ie_new->length;
				
				break;
*/
				n_skip = n_stdskip + p_raw_binf[n_lenoff];
				if(n_prem_len >= n_skip ) {
					memcpy(&(p_mbi->ssid[0]),&p_raw_binf[n_stdskip],min(WLAN_SSID_MAXLEN,p_raw_binf[n_lenoff]));
					n_skip = n_stdskip + p_raw_binf[n_lenoff] ;
	                                p_raw_binf += n_skip;
			                n_prem_len -= n_skip;
				}
				else 
					return 1;
				break;
				
			case WLAN_IE_DSSET:

				n_skip = n_stdskip +  p_raw_binf[n_lenoff];
				if(n_prem_len >= n_skip) {
					memcpy(&p_mbi->channel,&p_raw_binf[n_stdskip],min(sizeof(p_mbi->channel),p_raw_binf[n_lenoff]));
					p_raw_binf += n_skip; 
					n_prem_len -= n_skip;			
				}	
				else
					return 1;
				break;		
			default:
				n_skip = n_stdskip +  p_raw_binf[n_lenoff] ;
				if(n_prem_len >= n_skip) {
					p_raw_binf += n_skip; 
					n_prem_len -= n_skip;	
				}	
				else 
					return 1;		
				break;
				
		}
	}	

	update_ap_list(p_mbi);
	return 0;
}

int handle_data(unsigned char *packet, unsigned int pack_len, p80211_hdr_t * p_phdr) {
	
	unsigned n_prem_len;
	my_client_info_t mci, *p_mci;
	
	n_prem_len = pack_len;	
	
	if(n_prem_len >= WLAN_3ADDR_HDR_LEN )
		memcpy(p_phdr,packet,WLAN_3ADDR_HDR_LEN);
	else
		return 1;

	packet += WLAN_3ADDR_HDR_LEN;
	n_prem_len -= (WLAN_3ADDR_HDR_LEN);

	memset(&mci,0,sizeof(my_client_info_t));
	p_mci = &mci;
	memcpy(&p_mci->mac[0],&p_phdr->hdr2.mac2[0],WLAN_ADDR_LEN);
	memcpy(&p_mci->dest_mac[0],&p_phdr->hdr2.mac1[0],WLAN_ADDR_LEN);
	p_mci->state = CLI_ST_XMITING;

	if(GET_FTODS(p_phdr))
		update_client_list(p_mci);
}
