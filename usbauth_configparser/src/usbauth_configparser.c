/*
 ============================================================================
 Name        : usbauth_configparser.c
 Author      : Stefan Koch
 Version     : alpha
 Copyright   : 2015 SUSE Linux GmbH
 Description : USB authentication for udev
 ============================================================================
 */

#include "generic.h"
#include "usbauth_configparser.h"
#include "usbauth_lang.tab.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CONFIG_FILE "/home/stefan/usbauth.config"

unsigned gen_length;
struct Auth *gen_auths;

extern FILE *usbauth_yyin;

const char* parameter_strings[] = {"INVALID", "busnum", "devpath", "idVendor", "idProduct", "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol", "bConfigurationValue", "bInterfaceNumber", "bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol", "count"};
const char* operator_strings[] = {"==", "!=", "<=", ">=", "<", ">"};

int str_to_enum(const char *string, const char** string_array, int array_len) {
	enum Parameter ret = INVALID;

	int i;
	for (i = 0; i < array_len; i++) {
		if (strcmp(string, string_array[i]) == 0) {
			ret = i;
			break;
		}
	}

	return ret;
}

const char* enum_to_str(int param, const char** string_array, int array_len) {
	const char* ret = string_array[0];

	if (param < array_len)
		ret = string_array[param];

	return ret;
}

enum Parameter str_to_param(const char *string) {
	return str_to_enum(string, parameter_strings, sizeof(parameter_strings));
}

const char* param_to_str(enum Parameter param) {
	return enum_to_str(param, parameter_strings, sizeof(parameter_strings));
}

enum Operator str_to_op(const char *string) {
	return str_to_enum(string, operator_strings, sizeof(operator_strings));
}

const char* op_to_str(enum Operator param) {
	return enum_to_str(param, operator_strings, sizeof(operator_strings));
}

bool usbauth_config_convert_str_to_data(struct Data *d, char *paramStr, char* opStr, char *valStr) {
	bool ret = true;

	if(!d || !paramStr || !valStr)
		return false;

	d->param = str_to_param(paramStr);
	if (d->param == INVALID)
		ret = false;

	d->op = str_to_op(opStr);

	sscanf(valStr, "%x", &d->val);

	return ret;
}

char* auth_to_str(struct Auth *auth) {
	char v[16];
	char *str = calloc(512, sizeof(char));

	strcpy(str, "");
	strcpy(v, "");

	if (auth->type == COND)
		strcat(str, "condition");
	else if (auth->type == ALLOW)
		strcat(str, "allow");
	else if (auth->type == DENY)
		strcat(str, "deny");

	if (auth->type != COMMENT)
		strcat(str, " ");

	struct Data* cond_array = auth->cond_array;
	if (auth->type == COND) {
		int k;
		for (k = 0; k < auth->cond_len; k++) {
			strcat(str, parameter_strings[cond_array[k].param]);
			strcat(str, operator_strings[cond_array[k].op]);
			sprintf(v, "%x", cond_array[k].val);
			strcat(str, v);
			strcat(str, " ");
		}

		strcat(str, "case ");
	}
	struct Data* attr_array = auth->attr_array;
	int j;
	for (j = 0; j < auth->attr_len; j++) {
		strcat(str, parameter_strings[attr_array[j].param]);
		strcat(str, operator_strings[attr_array[j].op]);
		sprintf(v, "%x", attr_array[j].val);
		strcat(str, v);
		strcat(str, " ");
	}

	if(auth->comment)
		strcat(str, auth->comment);

	return str;
}

void allocate_and_copy(struct Auth** auth_arr, struct Auth* auths, unsigned length) {
	struct Auth *arr;

	arr = 0;
	if (length)
		arr = calloc(length, sizeof(struct Auth));
	if (arr)
		memcpy(arr, auths, length*sizeof(struct Auth));

	arr->attr_array = NULL;
	if (arr->attr_len)
		arr->attr_array = calloc(arr->attr_len, sizeof(struct Data));
	if (arr->attr_array)
		memcpy(arr->attr_array, auths->attr_array, arr->attr_len*sizeof(struct Data));

	arr->cond_array = NULL;
	if (arr->cond_len)
		arr->cond_array = calloc(arr->cond_len, sizeof(struct Data));
	if (arr->cond_array)
		memcpy(arr->cond_array, auths->cond_array, arr->cond_len*sizeof(struct Data));

	*auth_arr = arr;
}

int usbauth_config_free() {
	int ret = -1;

	if(gen_auths) {
		usbauth_config_free_auths(gen_auths, gen_length);
		gen_auths = NULL;
		gen_length = 0;
		ret = 0;
	}

	return ret;
}

int usbauth_config_read() {
	usbauth_yyin = fopen(CONFIG_FILE, "r");

	if(!usbauth_yyin)
		return -1;

	usbauth_config_free();

	int ret = usbauth_yyparse();

	fclose(usbauth_yyin);

	return ret;
}

int usbauth_config_write() {
	FILE* fout = fopen(CONFIG_FILE "1", "w");

	if(!fout)
		return -1;

	int i = 0;
	for (i = 0; i < gen_length; i++)
		fprintf(fout, "%s\n", auth_to_str(&gen_auths[i]));
	fclose(fout);

	return 0;
}

void usbauth_config_free_auths(struct Auth* auths, unsigned length) {
	unsigned i;
	for (i = 0; i < length; i++) {
		free(auths[i].attr_array);
	}
	free(auths);
}

void usbauth_config_get_auths(struct Auth** auths, unsigned *length) {
	allocate_and_copy(auths, gen_auths, gen_length);
	*length = gen_length;
}

void usbauth_config_set_auths(struct Auth* auths, unsigned length) {
	usbauth_config_free_auths(gen_auths, gen_length);
	allocate_and_copy(&gen_auths, auths, length);
	gen_length = length;
}

