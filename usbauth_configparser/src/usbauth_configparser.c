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

const char* parameters[] = {"INVALID", "busnum", "devpath", "idVendor", "idProduct", "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol", "bConfigurationValue", "bInterfaceNumber", "bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol", "count"};
const char* operators[] = {"==", "!=", "<=", ">=", "<", ">"};

bool usbauth_config_convert_str_to_data(struct Data *d, char *paramStr, char* opStr, char *valStr) {
	bool ret = true;

	if(!d || !paramStr || !valStr)
		return false;

	if (strcmp(paramStr, "busnum") == 0) {
		d->param = busnum;
	} else if (strcmp(paramStr, "devpath") == 0) {
		d->param = devpath;
	} else if (strcmp(paramStr, "idVendor") == 0) {
		d->param = idVendor;
	} else if (strcmp(paramStr, "idProduct") == 0) {
		d->param = idProduct;
	} else if (strcmp(paramStr, "bDeviceClass") == 0) {
		d->param = bDeviceClass;
	} else if (strcmp(paramStr, "bDeviceSubClass") == 0) {
		d->param = bDeviceSubClass;
	} else if (strcmp(paramStr, "bConfigurationValue") == 0) {
		d->param = bConfigurationValue;
	} else if (strcmp(paramStr, "bInterfaceNumber") == 0) {
		d->param = bInterfaceNumber;
	} else if (strcmp(paramStr, "bInterfaceClass") == 0) {
		d->param = bInterfaceClass;
	} else if (strcmp(paramStr, "bInterfaceSubClass") == 0) {
		d->param = bInterfaceSubClass;
	} else if (strcmp(paramStr, "count") == 0) {
		d->param = count;
	} else {
		d->param = INVALID;
		ret = false;
	}

	if (strcmp(opStr, "==") == 0) {
		d->op = eq;
	} else if (strcmp(opStr, "!=") == 0) {
		d->op = neq;
	} else if (strcmp(opStr, "<=") == 0) {
		d->op = lt;
	} else if (strcmp(opStr, ">=") == 0) {
		d->op = gt;
	} else if (strcmp(opStr, "<") == 0) {
		d->op = l;
	} else if (strcmp(opStr, ">") == 0) {
		d->op = g;
	}

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
	else if (auth->type == COMMENT)
		strcat(str, "#");

	if (auth->type != COMMENT)
		strcat(str, " ");

	struct Data* cond_array = auth->cond_array;
	if (auth->type == COND) {
		int k;
		for (k = 0; k < auth->cond_len; k++) {
			strcat(str, parameters[cond_array[k].param]);
			strcat(str, operators[cond_array[k].op]);
			sprintf(v, "%x", cond_array[k].val);
			strcat(str, v);
			strcat(str, " ");
		}

		strcat(str, "case ");
	}
	struct Data* attr_array = auth->attr_array;
	int j;
	for (j = 0; j < auth->attr_len; j++) {
		strcat(str, parameters[attr_array[j].param]);
		strcat(str, operators[attr_array[j].op]);
		sprintf(v, "%x", attr_array[j].val);
		strcat(str, v);
		strcat(str, " ");
	}

	if(auth->comment) {
		strcat(str, "#");
		strcat(str, auth->comment);
	}

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

