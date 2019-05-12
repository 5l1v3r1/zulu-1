// wlan information store, and access

// system includes
#include <asm/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// local includes
#include "p80211.h"
#include "wlaninfo.h"
#include "macros.h"

// Global varaibles
static ap_list  apl[AP_TABLE_SIZE];
static __u8	apl_tag[AP_TABLE_SIZE];

static cl_list  cll[CL_TABLE_SIZE];
static __u8	cll_tag[CL_TABLE_SIZE];

static char client_states[][16] = { "Probing", "Associating", "Re-ass", "Xmitting" };

// local forward declarations
static unsigned int mac_hash_fn(__u8 mac[]);

int update_ap_list(my_beacon_info_t *p_mbi) {
	unsigned int mac_hash;
	ap_list *new_node,*node,*last;
	__u8 found;
	
	mac_hash = mac_hash_fn(p_mbi->mac);
#ifdef MOREDEBUG
	printf("AP HASH = %u\n",mac_hash);
#endif	
// FIXME	
// make life easier and faster by using memcmp
// take care since the string fields like SSID might cause trouble if
// the data is not initialized to 0 or something common for all structs passed to this
	node = &apl[mac_hash];
	last = node;
	found = 0;

	if(apl_tag[mac_hash])  {
		do {
			if(memcmp(&node->mbi.mac[0],&p_mbi->mac[0],WLAN_ADDR_LEN)==0) {
				found = 1;
				break;
			}
			last = node;
			node = (ap_list *)(node->ll.next);
		}while(node);
	
		if(found) {
			if(memcmp(&node->mbi,p_mbi,sizeof(my_beacon_info_t))!=0){
				memcpy(&node->mbi,p_mbi,sizeof(my_beacon_info_t));

#ifdef DEBUG
				printf("Updated AP list: mac ");
				DISPLAY_MAC(p_mbi->mac);
				printf("\n");	
#endif
			}
#ifdef MOREDEBUG
			else
				printf("No change in AP properties!\n");
#endif			
		}
		else {
#ifdef DEBUG
			printf("allocating new ap entry\n");
#endif
			new_node = (ap_list *)malloc(sizeof(ap_list));
			if(new_node == NULL)
				return 1;
			memcpy(&new_node->mbi,p_mbi,sizeof(new_node->mbi));
			add_list_item((gen_llist **)&last,(gen_llist *)new_node,sizeof(ap_list));

#ifdef DEBUG
			printf("New AP added to list on same hash: mac ");
			DISPLAY_MAC(p_mbi->mac);
			printf("\n");	
				
#endif
		}
	}
	else {
		apl_tag[mac_hash] = 1;
		init_list(node);
		memcpy(&node->mbi,p_mbi, sizeof(my_beacon_info_t));
		
#ifdef DEBUG
		printf("adding first new ap entry\n");
#endif 
#ifdef DEBUG
		printf("New AP added to list: mac ");
		DISPLAY_MAC(p_mbi->mac);
		printf("\n");		
#endif
	}
}

int init_ap_list() {
	free_ap_list();
	memset(&apl,0, sizeof(ap_list) * AP_TABLE_SIZE);
	memset(&apl_tag,0, sizeof(__u8) * AP_TABLE_SIZE);
}

int free_ap_list() {
	register int i;
	for(i=0; i < AP_TABLE_SIZE; i++) {
		if(apl_tag[i]) 
			free_list((gen_llist *)&apl[i]);
	}	
}

// client list functions
int update_client_list (my_client_info_t *p_mci) {
	unsigned int mac_hash;
	cl_list *new_node,*node,*last;
	__u8 found;
	
	mac_hash = mac_hash_fn(p_mci->mac);
#ifdef MOREDEBUG
	printf("CLIENT MAC HASH = %u\n",mac_hash);
#endif	
// FIXME	
// make life easier and faster by using memcmp
// the data is not initialized to 0 or something common for all structs passed to this
	node = &cll[mac_hash];
	last = node;
	found = 0;

	if(cll_tag[mac_hash])  {
		do {
			if(memcmp(&node->mci.mac[0],&p_mci->mac[0],WLAN_ADDR_LEN)==0) {
				found = 1;
				break;
			}
			last = node;
			node = (cl_list *)(node->ll.next);
		}while(node);
	
		if(found) {
			if(memcmp(&node->mci,p_mci,sizeof(my_client_info_t))!=0){
				memcpy(&node->mci,p_mci,sizeof(my_client_info_t));

#ifdef DEBUG
				printf("Updated Client list: mac ");
				DISPLAY_MAC(p_mci->mac);
				printf("\n");	
				printf("New state %x\n",p_mci->state);
#endif
			}
#ifdef MOREDEBUG
			else
				printf("No change in client properties!\n");
#endif			
		}
		else {
#ifdef DEBUG
			printf("allocating new client entry\n");
#endif
			new_node = (cl_list *)malloc(sizeof(cl_list));
			if(new_node == NULL)
				return 1;
			memcpy(&new_node->mci,p_mci,sizeof(new_node->mci));
			add_list_item((gen_llist **)&last,(gen_llist *)new_node,sizeof(cl_list));

#ifdef DEBUG
			printf("New client added to list on same hash: mac ");
			DISPLAY_MAC(p_mci->mac);
			printf("\n");		
#endif
		}
	}
	else {
		cll_tag[mac_hash] = 1;
		init_list(node);
		memcpy(&node->mci,p_mci, sizeof(my_client_info_t));
		
#ifdef DEBUG
		printf("adding first new client entry\n");
#endif 
#ifdef DEBUG
		printf("New client added to list: mac ");
		DISPLAY_MAC(p_mci->mac);
		printf("\n");			
#endif
	}
	
}

int init_client_list() {
	free_client_list();
	memset(&cll,0, sizeof(cl_list) * CL_TABLE_SIZE);
	memset(&cll_tag,0, sizeof(__u8) * CL_TABLE_SIZE);
}

int free_client_list() {
	register int i;
	for(i=0; i < CL_TABLE_SIZE; i++) {
		if(cll_tag[i]) 
			free_list((gen_llist *)&cll[i]);
	}	
}

// the mac hashing function
static unsigned int mac_hash_fn(__u8 mac[]) {
	__u8 temp;
	register int i;
	
	temp = 0;
	for(i= WLAN_ADDR_LEN/2; i < WLAN_ADDR_LEN; i++) {
		temp += (__u8) mac[i];
		
	}
	return (temp % AP_TABLE_SIZE);
}

// display wlan stats
void display_wlan_stats() {
	register int i;
	ap_list *p_apl;
	cl_list *p_cll;

	
	printf("----AP STATS---\n");
	for(i=0;i < AP_TABLE_SIZE;i++) {
		if(apl_tag[i]) {
			p_apl = &apl[i];
			do {
				printf("MAC:");
				DISPLAY_MAC(p_apl->mbi.mac);
				printf(" BI: %u",p_apl->mbi.beacon_interval);
				printf(" CH: %u",p_apl->mbi.channel);
				printf(" SSID: %s",p_apl->mbi.ssid);
				printf(" WEP: %s",p_apl->mbi.wep_status?"yes":"no");
				printf("\n");
				p_apl = p_apl->ll.next;
			}while(p_apl);
			
		}	
	}
	printf("----END AP STATS---\n");
	printf("\n\n");

	printf("----CLIENT STATS---\n");
	for(i=0;i < CL_TABLE_SIZE;i++) {
		if(cll_tag[i]) {
			p_cll = &cll[i];
			do {
				printf("MAC:");
				DISPLAY_MAC(p_cll->mci.mac);
				printf(" State: %s",client_states[p_cll->mci.state]);
				printf("->MAC:");
				DISPLAY_MAC(p_cll->mci.dest_mac);
				printf("\n");
				p_cll = p_cll->ll.next;
			}while(p_cll);
		}
	}
	printf("----END CLIENT STATS---\n");
	alarm(10);
}

