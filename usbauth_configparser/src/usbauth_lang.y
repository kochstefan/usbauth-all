%define api.prefix usbauth_yy

%{
#include "generic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern char* usbauth_yytext;
#define CONFIG_FILE "/home/stefan/usbauth.config"

extern struct Auth *gen_auths;
extern unsigned gen_length;

struct Data **data_array = NULL;
uint8_t *data_array_length = NULL;
struct Data *data_ptr = NULL;

bool cnt = false;
char *paramStr = NULL;
char *opStr = NULL;
char *valStr = NULL;



void allocate_copy_yytext(char **dest) {
	int len = strlen(usbauth_yytext);
	*dest = (char*) calloc(len+1, sizeof(char));
	strncpy(*dest, usbauth_yytext, len);
	(*dest)[len] = 0;
}

void process(unsigned *counter, void **arr, bool data) {
	unsigned size;
	
	if(data)
		size = sizeof(struct Data);
	else
		size = sizeof(struct Auth);
	
	if(!*arr)
		*arr = (void*) malloc((*counter+1) * size);
	else {
		*arr = (void*) realloc(*arr, (*counter+1) * size);
	}
	uint8_t *ptr = (uint8_t*) *arr + *counter * size;
	memset(ptr, 0, size);
	
	if(data) {
		data_ptr = (struct Data*) ptr;
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
%token allow deny condition all case_ val param op op_eq op_neq op_le op_ge op_lt op_gt nl eof par_busnum par_devpath par_idVendor par_idProduct par_bDeviceClass par_bDeviceSubClass par_bConfigurationValue par_bInterfaceNumber par_bInterfaceClass par_bInterfaceSubClass par_count comment comment2
%%
S: FILE { printf("file ok\n"); return 0;}
FILE: LINE | FILE LINE
NLA: nl | NLA nl
LINE: { process(&gen_length, (void**)&gen_auths, false); gen_auths[gen_length].valid = true; } RULE NLA { gen_length++; printf("line ok\n");}
RULE: COMMENT | GENERICC | AUTHC | CONDC
OPERATOR: op_eq|op_neq|op_le|op_ge|op_lt|op_gt
PARAM: par_busnum|par_devpath|par_idVendor|par_idProduct|par_bDeviceClass|par_bDeviceSubClass|par_bConfigurationValue|par_bInterfaceNumber|par_bInterfaceClass|par_bInterfaceSubClass|par_count
DATA: param {allocate_copy_yytext(&paramStr);} op {allocate_copy_yytext(&opStr);} val {allocate_copy_yytext(&valStr); process(data_array_length, (void**)data_array, true); usbauth_config_convert_str_to_data(data_ptr, paramStr, opStr, valStr);}
DATAm: DATA | DATAm DATA
GENERICC: GENERIC COMMENTADD
GENERIC: auth_keyword all
AUTHC: AUTH COMMENTADD
AUTH: auth_keyword { data_array_length = &(gen_auths[gen_length].attr_len); data_array = &(gen_auths[gen_length].attr_array);} DATAm
CONDC: COND COMMENTADD
COND: condition { gen_auths[gen_length].type = COND; data_array_length = &(gen_auths[gen_length].cond_len); data_array = &(gen_auths[gen_length].cond_array);} DATAm case_ { data_array_length = &(gen_auths[gen_length].attr_len); data_array = &(gen_auths[gen_length].attr_array);} DATAm
COMMENT: comment { allocate_copy_yytext(&(gen_auths[gen_length].comment)); printf("c%s\n", (gen_auths[gen_length].comment));}
EMPTY: 
COMMENTADD: EMPTY|COMMENT
auth_keyword: allow {gen_auths[gen_length].type = ALLOW;} | deny {gen_auths[gen_length].type = DENY;}
%%

int yyerror(char*msg) {
	printf("error %s", msg);
	return 0;
}


