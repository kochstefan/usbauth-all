/*
 * generic.h
 *
 *  Created on: 22.01.2015
 *      Author: stefan
 */

#ifndef GENERIC_H_
#define GENERIC_H_


#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

enum parameters {
	INVALID, busnum, devpath, idVendor, idProduct, bDeviceClass, bDeviceSubClass, bConfigurationValue, bInterfaceNumber, bInterfaceClass, bInterfaceSubClass, count
};

enum operator { eq, neq, lt, gt, l, g };

struct data {
	int param;
	enum operator op;
	unsigned val;
};

struct auth {
	bool valid;
	bool allowed;
	bool cond;
	uint8_t count;
	uint8_t attr_len;
	struct data *attr_array;
	uint8_t cond_len;
	struct data *cond_array;
};

struct match_ret {
	bool match_attrs:1;
	bool match_cond:1;
};

#endif /* GENERIC_H_ */
