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

enum Parameter {
	INVALID, busnum, devpath, idVendor, idProduct, bDeviceClass, bDeviceSubClass, bDeviceProtocol, bConfigurationValue, bInterfaceNumber, bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol, intfcount, devcount
};

enum Operator { eq, neq, lt, gt, l, g };

struct Data {
	bool anyChild;
	int param;
	enum Operator op;
	unsigned val;
};

enum Type { COMMENT, DENY, ALLOW, COND };

struct Auth {
	bool valid;
	enum Type type;
	const char *comment;
	uint8_t intfcount;
	uint8_t devcount;
	uint8_t attr_len;
	struct Data *attr_array;
	uint8_t cond_len;
	struct Data *cond_array;
};

struct match_ret {
	bool match_attrs:1;
	bool match_conds:1;
};

struct auth_ret {
	bool match;
	bool allowed;
};

#endif /* GENERIC_H_ */
