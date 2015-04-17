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
	INVALID, busnum, devpath, idVendor, idProduct, bDeviceClass, bDeviceSubClass, bDeviceProtocol, bConfigurationValue, bInterfaceNumber, bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol, devnum, serial, intfcount, devcount
};

enum Operator { eq, neq, lt, gt, l, g };

// structure for parameters, example bInterfaceNumber==01
struct Data {
	bool anyChild; // if true parse parameter for the devices interfaces, too. example match bInterfaceProtocol==1 for all devices interfaces (the parameter is only at intf 0, so it would returned at intf 1 as well)
	int param;
	enum Operator op;
	const char* val;
};

enum Type { COMMENT, DENY, ALLOW, COND };

// structure for an rule or condition
struct Auth {
	bool valid;
	enum Type type;
	const char *comment;
	uint8_t intfcount; // counts how much interfaces affected by rule/cond
	uint8_t devcount; // counts how much devices affected by rule/cond
	uint8_t attr_len;
	struct Data *attr_array; // used for rules and the case section of conditions
	uint8_t cond_len;
	struct Data *cond_array; // used for conditions
};

// used as return structure to check if attr or conds matched
struct match_ret {
	bool match_attrs:1;
	bool match_conds:1;
};

// used as return structure to check if rule/cond matches and the device should allowed or denied
struct auth_ret {
	bool match;
	bool allowed;
};

#endif /* GENERIC_H_ */
