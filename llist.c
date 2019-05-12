// doubly linked list opeations

//system includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//local includes
#include "llist.h"

int add_list_item(gen_llist **phead,gen_llist *new_node,unsigned int size) {
	gen_llist *temp;
	gen_llist *head;

	head = *phead;
	
	if(head) {	
		if(head->next) {
			temp = head->next;
			head->next = new_node;
			new_node->prev = head;
			new_node->next = temp;	
			temp->prev = new_node;	
		
		}
		else {
			new_node->next = head->next;
			head->next = new_node;
			new_node->prev = head;
		}
	}
	else {
		*phead = (gen_llist *)malloc(size);
		head = *phead;
		if(head == NULL) {
			printf("add_list_item: malloc of new head node failed!\n");
			return 1;
		}
		memcpy(head,new_node,size);
		head->next = head->prev = NULL;
		
	}
	return 0;
}	

int init_list(gen_llist *head) {
	head->next = head->prev = NULL;
}

// gotcha 
// refer to the gotcha in llist.h as well...
// not a clean way to handle list handling for any kind of structs
// the condition being that the struct contains space allocated for 2 pointers of size 32 bit to prev and next;
//
__u32 *get_next(gen_llist *from) {
	return (from->next);
}

int register_call_back(gen_llist *node,int (*free_call_back)()) {
	node->free_call_back  = free_call_back;
}

int free_list(gen_llist *head) {
	gen_llist *node;
	while(head) {
		if(head->free_call_back)
			head->free_call_back();
		node = head;
		head = (gen_llist *)head->next;
		free(head);
	}
}
