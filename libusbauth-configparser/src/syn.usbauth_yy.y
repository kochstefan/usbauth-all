/*
 * Copyright (c) 2015 SUSE LLC. All Rights Reserved.
 * Author: Stefan Koch <skoch@suse.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2.1 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, contact SUSE LLC.
 *
 * To contact SUSE about this file by physical or electronic mail,
 * you may find current contact information at www.suse.com
 */

%define api.prefix {usbauth_yy}

%{

#include "generic.h"
#include "usbauth-configparser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int yylex();
int yyerror(const char*msg);
void allocate_copy_yytext(char **dest);

extern char* usbauth_yytext;

extern struct Auth *gen_auths;
extern unsigned gen_length;

static struct Data **data_array = NULL;
static unsigned *data_array_length = NULL;
static struct Data *data_ptr = NULL;

static char *paramStr = NULL;
static char *opStr = NULL;
static char *valStr = NULL;
static bool anychild = false;
static int tmpType = INVALID;

int yyerror (const char*msg) {
	printf("error %s\n", msg);
	return 0;
}

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

%}

%token t_allow t_deny t_condition t_all t_case t_anyChild t_name t_op t_val t_nl t_eof t_comment 

%%
S: FILE { return 0; }
FILE: LINE | FILE LINE
NLA: t_nl | NLA t_nl
LINE: { process(&gen_length, (void**)&gen_auths, false); } RULE NLA { gen_auths[gen_length].type = tmpType; gen_length++; tmpType = INVALID; }
RULE: COMMENT {tmpType = COMMENT; } | GENERIC | AUTH | COND
COMMENT: t_comment { allocate_copy_yytext((char**)&(gen_auths[gen_length].comment)); }
COMMENT_add: EMPTY | COMMENT
GENERIC: AUTH_KEYWORD t_all COMMENT_add
AUTH: AUTH_KEYWORD { data_array_length = &(gen_auths[gen_length].attr_len); data_array = &(gen_auths[gen_length].attr_array); } DATA_mult COMMENT_add
AUTH_KEYWORD: t_allow {tmpType = ALLOW; } | t_deny {tmpType = DENY; }
COND: t_condition { tmpType = COND; data_array_length = &(gen_auths[gen_length].cond_len); data_array = &(gen_auths[gen_length].cond_array); } DATA_mult t_case { data_array_length = &(gen_auths[gen_length].attr_len); data_array = &(gen_auths[gen_length].attr_array); } DATA_mult COMMENT_add
DATA: ANYCHILD_add t_name {allocate_copy_yytext(&paramStr); } t_op {allocate_copy_yytext(&opStr); } t_val {allocate_copy_yytext(&valStr); process(data_array_length, (void**)data_array, true); usbauth_convert_str_to_data(data_ptr, paramStr, opStr, valStr); data_ptr->anyChild = anychild; }
DATA_mult: DATA | DATA_mult DATA
ANYCHILD_add: EMPTY {anychild = false; } | t_anyChild {anychild = true; }
EMPTY: 
%%
