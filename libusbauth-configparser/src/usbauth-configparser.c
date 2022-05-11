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

/*
 * Description : Library for USB Firewall including flex/bison parser
 */

#include "generic.h"
#include "usbauth-configparser.h"
#include "syn.usbauth_yy.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libudev.h>

#define CONFIG_FILE "/etc/usbauth.conf"

unsigned gen_length;
struct Auth *gen_auths;

extern FILE *usbauth_yyin;

const char* parameter_strings[] = {"INVALID", "busnum", "devpath", "idVendor", "idProduct", "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol", "bConfigurationValue", "bNumInterfaces", "bInterfaceNumber", "bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol", "bNumEndpoints", "bcdDevice", "speed", "devnum", "serial", "manufacturer", "product", "connectType", "intfcount", "devcount", "PARAM_NUM_ITEMS"};
const char* operator_strings[] = {"==", "!=", "<=", ">=", "<", ">", "OP_NUM_ITEMS"};

// mapping table for value types of parameters (maps with parameter_strings array)
enum Valuetype value_map[] = {
	INVALID, DEC,    DEC,     HEX,      HEX,       HEX,          HEX,             HEX,             DEC,                 DEC,            HEX,              HEX,             HEX,                HEX,                HEX,           HEX,       STRING, DEC,   STRING, STRING,       STRING,  STRING,      HEX,       HEX,      PARAM_NUM_ITEMS
};

const char* usbauth_get_param_valStr(enum Parameter param, struct udev_device *udevdev) {
	struct udev_device *parent = NULL;
	const char* paramStr = usbauth_param_to_str(param);
	const char* valStr = NULL;

	// connectType is in a subdir
	if(connectType == param)
		paramStr = "port/connect_type";

	if(udevdev)
		valStr = udev_device_get_sysattr_value(udevdev, paramStr);

	if(!valStr) {
		parent = udev_device_get_parent(udevdev);
		valStr = udev_device_get_sysattr_value(parent, paramStr);
	}

	return valStr;
}

int usbauth_get_param_val(enum Parameter param, struct udev_device *udevdev) {
	int val = -1;
	const char* valStr = usbauth_get_param_valStr(param, udevdev);
	char* end = NULL;

	if(valStr)
		val = strtol(valStr, &end, 16);

	if(end && *end != 0)
		val = -1;

	return val;
}

int usbauth_str_to_enum(const char *string, const char** string_array, unsigned array_len) {
	enum Parameter ret = INVALID;

	unsigned i;
	for (i = 0; i < array_len; i++) {
		if (strcmp(string, string_array[i]) == 0) {
			ret = i;
			break;
		}
	}

	return ret;
}

const char* usbauth_enum_to_str(int val, const char** string_array, unsigned array_len) {
	const char* ret = string_array[0];

	if (val < array_len)
		ret = string_array[val];

	return ret;
}

enum Parameter usbauth_str_to_param(const char *string) {
	return usbauth_str_to_enum(string, parameter_strings, sizeof(parameter_strings)/sizeof(const char*));
}

const char* usbauth_param_to_str(enum Parameter param) {
	return usbauth_enum_to_str(param, parameter_strings, sizeof(parameter_strings)/sizeof(const char*));
}

enum Operator usbauth_str_to_op(const char *string) {
	return usbauth_str_to_enum(string, operator_strings, sizeof(operator_strings)/sizeof(const char*));
}

const char* usbauth_op_to_str(enum Operator op) {
	return usbauth_enum_to_str(op, operator_strings, sizeof(operator_strings)/sizeof(const char*));
}

bool usbauth_convert_str_to_data(struct Data *d, const char *paramStr, const char* opStr, const char *valStr) {
	bool ret = true;

	if(!d || !paramStr || !valStr)
		return false;

	d->param = usbauth_str_to_param(paramStr);
	if (d->param == INVALID)
		ret = false;

	d->op = usbauth_str_to_op(opStr);

	d->val = valStr;

	return ret;
}

const char* usbauth_auth_to_str(const struct Auth *auth) {
	const unsigned str_len = 512;
	char *str = calloc(str_len + 1, sizeof(char));
	char *v = calloc(str_len + 1, sizeof(char));

	strcpy(str, "");
	strcpy(v, "");

	if (auth->type == COND)
		strncat(str, "condition", usbauth_sub_length(str_len, strlen(str)));
	else if (auth->type == ALLOW)
		strncat(str, "allow", usbauth_sub_length(str_len, strlen(str)));
	else if (auth->type == DENY)
		strncat(str, "deny", usbauth_sub_length(str_len, strlen(str)));

	struct Data* cond_array = auth->cond_array;
	if (auth->type == COND) {
		int k;
		for (k = 0; k < auth->cond_len; k++) {
			strncat(str, " ", usbauth_sub_length(str_len, strlen(str)));
			strncat(str, parameter_strings[cond_array[k].param], usbauth_sub_length(str_len, strlen(str)));
			strncat(str, operator_strings[cond_array[k].op], usbauth_sub_length(str_len, strlen(str)));
			snprintf(v, str_len, "%s", cond_array[k].val);
			strncat(str, v, usbauth_sub_length(str_len, strlen(str)));
		}

		strncat(str, " case", usbauth_sub_length(str_len, strlen(str)));
	}

	struct Data* attr_array = auth->attr_array;
	int j;
	for (j = 0; j < auth->attr_len; j++) {
		strncat(str, " ", usbauth_sub_length(str_len, strlen(str)));
		strncat(str, attr_array[j].anyChild ? "anyChild " : "", usbauth_sub_length(str_len, strlen(str)));
		strncat(str, parameter_strings[attr_array[j].param], usbauth_sub_length(str_len, strlen(str)));
		strncat(str, operator_strings[attr_array[j].op], usbauth_sub_length(str_len, strlen(str)));
		snprintf(v, str_len, "%s", attr_array[j].val);
		strncat(str, v, usbauth_sub_length(str_len, strlen(str)));
	}

	if ((auth->type == ALLOW || auth->type == DENY) && auth->attr_len == 0)
		strncat(str, " all", usbauth_sub_length(str_len, strlen(str)));

	if(auth->comment) {
		if(auth->type != COMMENT)
			strncat(str, " ", usbauth_sub_length(str_len, strlen(str)));
		strncat(str, "#", usbauth_sub_length(str_len, strlen(str)));
		strncat(str, auth->comment, usbauth_sub_length(str_len, strlen(str)));
	}

	return str;
}

unsigned usbauth_sub_length(unsigned base, unsigned val) {
	if (base > val)
		return base - val;
	else
		return 0;
}

void usbauth_allocate_and_copy(struct Auth** destination, const struct Auth* source, unsigned length) {
	struct Auth *arr = NULL;

	if (length)
		arr = calloc(length, sizeof(struct Auth));

	if (arr) {
		memcpy(arr, source, length * sizeof(struct Auth));

		arr->attr_array = NULL;
		if (arr->attr_len)
			arr->attr_array = calloc(arr->attr_len, sizeof(struct Data));
		if (arr->attr_array)
			memcpy(arr->attr_array, source->attr_array, arr->attr_len * sizeof(struct Data));

		arr->cond_array = NULL;
		if (arr->cond_len)
			arr->cond_array = calloc(arr->cond_len, sizeof(struct Data));
		if (arr->cond_array)
			memcpy(arr->cond_array, source->cond_array, arr->cond_len * sizeof(struct Data));
	}

	*destination = arr;
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
	FILE* fout = fopen(CONFIG_FILE, "w");

	if(!fout)
		return -1;

	int i = 0;
	for (i = 0; i < gen_length; i++) {
		const char *str = usbauth_auth_to_str(&gen_auths[i]);
		fprintf(fout, "%s\n", str);
		free((char*)str);
		str = NULL;
	}
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
	usbauth_allocate_and_copy(auths, gen_auths, gen_length);
	*length = gen_length;
}

void usbauth_config_set_auths(struct Auth* auths, unsigned length) {
	usbauth_config_free_auths(gen_auths, gen_length);
	usbauth_allocate_and_copy(&gen_auths, auths, length);
	gen_length = length;
}

