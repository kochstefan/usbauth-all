%define api.prefix usbauth_yy

%{

#include "generic.h"
#include "usbauth_configparser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int yylex();
int yyerror(const char*msg);
void allocate_copy_yytext(char **dest);

extern char* usbauth_yytext;

extern struct Auth *gen_auths;
extern uint8_t gen_length;

static struct Data **data_array = NULL;
static unsigned *data_array_length = NULL;
static struct Data *data_ptr = NULL;

static char *paramStr = NULL;
static char *opStr = NULL;
static char *valStr = NULL;
static bool anychild = false;
static int tmpType = INVALID;

int yyerror (const char*msg) {
	printf("error %s", msg);
	return 0;
}

void allocate_copy_yytext(char **dest) {
	int len = strlen(usbauth_yytext);
	*dest = (char*) calloc(len+1, sizeof(char));
	strncpy(*dest, usbauth_yytext, len);
	(*dest)[len] = 0;
}

void process(uint8_t *counter, void **arr, bool data) {
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

%}

%token allow deny condition all case_ anyChild name op nl eof comment 

%%
S: FILE { printf("file ok\n"); return 0;}
FILE: LINE | FILE LINE
NLA: nl | NLA nl
LINE: { process(&gen_length, (void**)&gen_auths, false); } RULE NLA { gen_auths[gen_length].type = tmpType; gen_length++; tmpType = INVALID; printf("line ok\n");}
RULE: COMMENT | GENERICC | AUTHC | CONDC
ANYCHILDADD: EMPTY {anychild = false;} | anyChild {anychild = true;}
DATA: ANYCHILDADD name {allocate_copy_yytext(&paramStr);} op {allocate_copy_yytext(&opStr);} name {allocate_copy_yytext(&valStr); process(data_array_length, (void**)data_array, true); usbauth_convert_str_to_data(data_ptr, paramStr, opStr, valStr); data_ptr->anyChild = anychild;}
DATAm: DATA | DATAm DATA
GENERICC: GENERIC COMMENTADD
GENERIC: auth_keyword all
AUTHC: AUTH COMMENTADD
AUTH: auth_keyword { data_array_length = &(gen_auths[gen_length].attr_len); data_array = &(gen_auths[gen_length].attr_array);} DATAm
CONDC: COND COMMENTADD
COND: condition { tmpType = COND; data_array_length = &(gen_auths[gen_length].cond_len); data_array = &(gen_auths[gen_length].cond_array);} DATAm case_ { data_array_length = &(gen_auths[gen_length].attr_len); data_array = &(gen_auths[gen_length].attr_array);} DATAm
COMMENT: comment { tmpType = COMMENT; allocate_copy_yytext((char**)&(gen_auths[gen_length].comment)); printf("c%s\n", (gen_auths[gen_length].comment));}
EMPTY: 
COMMENTADD: EMPTY|COMMENT
auth_keyword: allow {tmpType = ALLOW;} | deny {tmpType = DENY;}
%%
