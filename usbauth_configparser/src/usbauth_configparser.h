/*
 ============================================================================
 Name        : usbauth_configparser.h
 Author      : Stefan Koch <skoch@suse.de>
 Version     : 1.0
 Copyright   : 2015 SUSE Linux GmbH
 Description : library for USB Firewall including flex/bison parser
 ============================================================================
 */

#ifndef USBAUTH_CONFIGPARSER_H_
#define USBAUTH_CONFIGPARSER_H_

#include <usbauth/generic.h>

struct udev_device;
typedef struct DBusError DBusError;

/**
 * check dbus errors
 *
 * @error: dbus error structure
 *
 * Return: true if no error, false if error
 */
bool usbauth_dbus_no_error_check(DBusError *error);

/**
 * get a sysfs usb device parameter as string
 *
 * @param: parameter as enum
 * @udevdev: device structure
 *
 * Return: string, NULL at error (example: not available)
 */
const char* usbauth_get_param_valStr(enum Parameter param, struct udev_device *udevdev);

/**
 * get a sysfs usb device parameter as value
 *
 * @param: parameter as enum
 * @udevdev: device structure
 *
 * Return: converted value, -1 at error (example: not convertable, not available)
 */
int usbauth_get_param_val(enum Parameter param, struct udev_device *udevdev);

/**
 * convert string to enum
 *
 * @string: string to convert
 * @string_array: array with string values
 * @array_len: length of array
 *
 * Return: converted enum value
 */
int usbauth_str_to_enum(const char *string, const char** string_array, unsigned array_len);

/**
 * convert enum to string
 *
 * @val: enum value to convert
 * @string_array: array with string values
 * @array_len: length of array
 *
 * Return: converted string
 */
const char* usbauth_enum_to_str(int val, const char** string_array, unsigned array_len);

/**
 * convert param string to param enum
 *
 * @string: param string
 *
 * Return: parameter as enum
 */
enum Parameter usbauth_str_to_param(const char *string);

/**
 * convert param enum to param string
 *
 * @param: parameter as enum
 *
 * Return: param string
 */
const char* usbauth_param_to_str(enum Parameter param);

/**
 * convert operator string to operator enum
 *
 * @string: operator string
 *
 * Return: operator as enum
 */
enum Operator usbauth_str_to_op(const char *string);

/**
 * convert operator enum to operator string
 *
 * @op: operator as enum
 *
 * Return: operator string
 */
const char* usbauth_op_to_str(enum Operator op);

/**
 * convert parameter, operator and value string to Data structure
 *
 * @d: pointer to Data entry (output param)
 * @paramStr: parameter as string
 * @opStr: operator as string
 * @valStr: value as string
 *
 * Return: true at success, otherwise false
 */
bool usbauth_convert_str_to_data(struct Data *d, const char *paramStr, const char* opStr, const char *valStr);

/**
 * make from an auth rule a string
 * used by usbauth_config_write
 *
 * @auth: auth rule
 *
 * Return: string representation of a rule, caller must free pointer self
 */
const char* usbauth_auth_to_str(const struct Auth *auth);

/**
 * copy auth rules from source to destination. Destination will allocated first.
 *
 * @destination: pointer to save allocated pointer in it (out)
 * @source: pointer to source auth rules (in)
 * @array_length: auth rules length (in)
 *
 * Return: true if there is at least one rule from type ALLOW or DENY
 */
void usbauth_allocate_and_copy(struct Auth** destination, const struct Auth* source, unsigned length);

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
 * note: to save rules usbauth_config_write() must called after this
 *
 * example: used to set edited rules by YaST
 *
 * @auths: pointer of pointer to save rules array pointer in it (out)
 * @length: pointer of unsigned value to save array length in it (out)
 *
 */
void usbauth_config_set_auths(struct Auth* auths, unsigned length);

#endif /* USBAUTH_CONFIGPARSER_H_ */
