/*
 * usbauth_configparser.h
 *
 *  Created on: 27.02.2015
 *      Author: stefan
 */

#ifndef USBAUTH_CONFIGPARSER_H_
#define USBAUTH_CONFIGPARSER_H_

#include "generic.h"

bool usbauth_config_convert_str_to_data(struct data *d, char *paramStr, char* opStr, char *valStr);

char* auth_to_str(struct auth *auth);

int usbauth_config_free();

int usbauth_config_read();

int usbauth_config_write();

void usbauth_config_free_auths(struct auth* auths, unsigned length);

void usbauth_config_get_auths(struct auth** auths, unsigned *length);

void usbauth_config_set_auths(struct auth* auths, unsigned length);

#endif /* USBAUTH_CONFIGPARSER_H_ */
