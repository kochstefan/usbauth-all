%define api.prefix usbauth_yy

%{
#include "generic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern char* usbauth_yytext;
#define CONFIG_FILE "/home/stefan/usbauth.config"

extern struct auth *gen_auths;
extern unsigned gen_length;

struct data *d;
bool cnt = false;
char *paramStr;
char *opStr;
char *valStr;
uint8_t *counter = NULL;
struct data **currd = NULL;
unsigned currd_offs = 0;

void cpyy(char **dest) {
	int len = strlen(usbauth_yytext);
	*dest = (char*) calloc(len+1, sizeof(char));
	strncpy(*dest, usbauth_yytext, len);
	(*dest)[len] = 0;
}

void process(uint8_t *counter, void **arr, bool data) {
	unsigned size;
	
	if(data)
		size = sizeof(struct data);
	else
		size = sizeof(struct auth);
	
	if(!*arr)
		*arr = (void*) malloc((*counter+1) * size);
	else {
		*arr = (void*) realloc(*arr, (*counter+1) * size);
	}
	uint8_t *ptr = (uint8_t*) *arr + *counter * size;
	memset(ptr, 0, size);
	
	if(data) {
		d = (struct data*) ptr;
		(*counter)++;
	}
}

/*auth_keyword -> "allow", "deny"
condition -> "condition"
case -> "case"
all -> "all"
param -> SysFS-Attr
op -> "==", "!=", "<=", ">=", "<", ">"
val -> SysFS-Val */
%}
%token allow deny condition all case_ val param op op_eq op_neq op_le op_ge op_lt op_gt nl eof par_busnum par_devpath par_idVendor par_idProduct par_bDeviceClass par_bDeviceSubClass par_bConfigurationValue par_bInterfaceNumber par_bInterfaceClass par_bInterfaceSubClass par_count
%%
S: FILE { printf("file ok\n"); return 0;}
FILE: LINE | FILE LINE
NLA: nl | NLA nl
LINE: { process(&gen_length, (void**)&gen_auths, false); gen_auths[gen_length].valid = true; } RULE NLA { gen_length++; printf("line ok\n");}
RULE: GENERIC|AUTH|COND
OPERATOR: op_eq|op_neq|op_le|op_ge|op_lt|op_gt
PARAM: par_busnum|par_devpath|par_idVendor|par_idProduct|par_bDeviceClass|par_bDeviceSubClass|par_bConfigurationValue|par_bInterfaceNumber|par_bInterfaceClass|par_bInterfaceSubClass|par_count
DATA: param {cpyy(&paramStr);} op {cpyy(&opStr);} val {cpyy(&valStr); process(counter, (void**)currd, true); usbauth_config_convert_str_to_data(d, paramStr, opStr, valStr);}
DATAm: DATA | DATAm DATA
GENERIC: auth_keyword all
AUTH: auth_keyword { counter = &(gen_auths[gen_length].attr_len); currd = &(gen_auths[gen_length].attr_array);} DATAm
COND: condition { gen_auths[gen_length].cond = true; counter = &(gen_auths[gen_length].cond_len); currd = &(gen_auths[gen_length].cond_array);} DATAm case_ { counter = &(gen_auths[gen_length].attr_len); currd = &(gen_auths[gen_length].attr_array);} DATAm
auth_keyword: allow {gen_auths[gen_length].allowed = true;} | deny {gen_auths[gen_length].allowed = false;}
%%

int yyerror(char*msg) {
	printf("error %s", msg);
	return 0;
}


