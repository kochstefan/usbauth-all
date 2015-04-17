/*
 * usbauth_configparser.h
 *
 *  Created on: 27.02.2015
 *      Author: stefan
 */

#ifndef USBAUTH_CONFIGPARSER_H_
#define USBAUTH_CONFIGPARSER_H_

#include "generic.h"

/**
 * convert string to enum
 *
 * string: string to convert
 *
 * Return: converted enum value
 */
int str_to_enum(const char *string, const char** string_array, unsigned array_len);

/**
 * convert enum to string
 *
 * string: enum value to convert
 *
 * Return: converted string
 */
const char* enum_to_str(int val, const char** string_array, unsigned array_len);

/**
 * convert param string to param enum
 *
 * string: param string
 *
 * Return: parameter as enum
 */
enum Parameter str_to_param(const char *string);

/**
 * convert param enum to param string
 *
 * param: parameter as enum
 *
 * Return: param string
 */
const char* param_to_str(enum Parameter param);

/**
 * convert operator string to operator enum
 *
 * string: operator string
 *
 * Return: operator as enum
 */
enum Operator str_to_op(const char *string);

/**
 * convert operator enum to operator string
 *
 * op: operator as enum
 *
 * Return: operator string
 */
const char* op_to_str(enum Operator op);

/**
 * convert parameter, operator and value string to Data structure
 */
bool convert_str_to_data(struct Data *d, char *paramStr, char* opStr, char *valStr);

/**
 * make from on auth rule a string
 * used by usbauth_config_write
 */
char* auth_to_str(struct Auth *auth);

/**
 * copy auth rules from source to destination. Destination will allocated first.
 *
 * @destination: pointer to save allocated pointer in it (out)
 * @source: pointer to source auth rules (in)
 * @array_length: auth rules length (in)
 *
 * Return: true if there is at least one rule from type ALLOW or DENY
 */
void allocate_and_copy(struct Auth** destination, struct Auth* source, unsigned length);

/**
 * free allocated memory of auth structures
 */
int usbauth_config_free();

/**
 * parse the config file with flex/bison parser
 */
int usbauth_config_read();

/**
 * write the auth structures to config file
 */
int usbauth_config_write();

/**
 * free memory from rules
 *
 * @auths: pointer of pointer to save rules array pointer in it (out)
 * @length: pointer of unsigned value to save array length in it (out)
 *
 */
void usbauth_config_free_auths(struct Auth* auths, unsigned length);

/**
 * get parsed rules
 *
 * note: call usbauth_config_read() before to parse config file
 *
 * @auths: pointer of pointer to save rules array pointer in it (out)
 * @length: pointer of unsigned value to save array length in it (out)
 *
 */
void usbauth_config_get_auths(struct Auth** auths, unsigned *length);

/**
 * set new rules
 *
 * used for set edited rules by YaST
 *
 * @auths: pointer of pointer to save rules array pointer in it (out)
 * @length: pointer of unsigned value to save array length in it (out)
 *
 */
void usbauth_config_set_auths(struct Auth* auths, unsigned length);

#endif /* USBAUTH_CONFIGPARSER_H_ */
