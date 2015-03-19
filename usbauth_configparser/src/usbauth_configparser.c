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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CONFIG_FILE "/home/stefan/usbauth.config"

extern uint8_t ruleCnt;
struct auth *au;

extern FILE *usbauth_yyin;

const char* parameters[] = {"INVALID", "busnum", "devpath", "idVendor", "idProduct", "bDeviceClass", "bDeviceSubClass", "bConfigurationValue", "bInterfaceNumber", "bInterfaceClass", "bInterfaceSubClass", "count"};
const char* operators[] = {"==", "!=", "<=", ">=", "<", ">"};

bool usbauth_config_param_val_str_to_data(struct data *d, char *paramStr, char* opStr, char *valStr) {
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

char* auth_to_str(struct auth *auth) {
	char v[16];
	char *str = calloc(512, sizeof(char));

	strcpy(str, "");
	strcpy(v, "");

	if (auth->cond)
		strcat(str, "condition");
	else if (auth->allowed)
		strcat(str, "allow");
	else
		strcat(str, "deny");

	strcat(str, " ");
	struct data* cond_array = auth->cond_array;
	if (auth->cond) {
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
	struct data* attr_array = auth->attr_array;
	int j;
	for (j = 0; j < auth->attr_len; j++) {
		strcat(str, parameters[attr_array[j].param]);
		strcat(str, operators[attr_array[j].op]);
		sprintf(v, "%x", attr_array[j].val);
		strcat(str, v);
		strcat(str, " ");
	}

	return str;
}

void allocate_and_copy(struct auth** auth_arr, struct auth* auths, unsigned length) {
	struct auth *arr;

	arr = 0;
	if (length)
		arr = calloc(length, sizeof(struct auth));
	if (arr)
		memcpy(arr, auths, length*sizeof(struct auth));

	arr->attr_array = NULL;
	if (arr->attr_len)
		arr->attr_array = calloc(arr->attr_len, sizeof(struct data));
	if (arr->attr_array)
		memcpy(arr->attr_array, auths->attr_array, arr->attr_len*sizeof(struct data));

	arr->cond_array = NULL;
	if (arr->cond_len)
		arr->cond_array = calloc(arr->cond_len, sizeof(struct data));
	if (arr->cond_array)
		memcpy(arr->cond_array, auths->cond_array, arr->cond_len*sizeof(struct data));

	*auth_arr = arr;
}

int usbauth_config_read() {
	usbauth_yyin = fopen(CONFIG_FILE, "r");
	int ret = usbauth_yyparse();
	fclose(usbauth_yyin);
	return ret;
}

int usbauth_config_write() {
	FILE* fout = fopen(CONFIG_FILE "1", "w");
	int i = 0;
	for (i = 0; i < ruleCnt; i++)
		fprintf(fout, "%s\n", auth_to_str(&au[i]));
	fclose(fout);
}

void usbauth_config_get_auths(struct auth** auths, unsigned *length) {
	allocate_and_copy(auths, au, ruleCnt);
	*length = ruleCnt;
}

void usbauth_config_set_auths(struct auth* auths, unsigned length) {
	allocate_and_copy(&au, auths, length);
	ruleCnt = length;
}

