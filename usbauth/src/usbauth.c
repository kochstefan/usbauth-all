/*
 * Copyright (c) 2015 SUSE LLC. All Rights Reserved.
 * Author: Stefan Koch <skoch@suse.de>
 *
 * Copyright (c) 2017 Stefan Koch <stefan.koch10@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General
 * Public License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact SUSE LLC.
 *
 * To contact SUSE about this file by physical or electronic mail,
 * you may find current contact information at www.suse.com
 */

/*
 * Description : USB firewall against BadUSB attacks
 */

#include "usbauth.h"

#include <usbauth/usbauth-configparser.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/file.h>

static FILE *logfile = NULL;

static struct udev *udev = NULL;
DBusConnection *bus = NULL;
struct udev_device *plug_usb_device = NULL;
static bool *iscounted = NULL;
static bool debuglog = false;

bool match_valsStr(const char *lval, enum Operator op, const char *rval) {
	bool ret = false;
	int cmp = strcmp(lval, rval);

	if (op == eq && cmp == 0)
		ret = true;
	else if (op == neq && cmp != 0)
		ret = true;
	else if (op == le && cmp <= 0)
		ret = true;
	else if (op == ge && cmp >= 0)
		ret = true;
	else if (op == l && cmp < 0)
		ret = true;
	else if (op == g && cmp > 0)
		ret = true;

	if (debuglog)
		syslog(LOG_DEBUG, "match_valsStr:%i (%s %s %s)\n", ret, lval, usbauth_op_to_str(op), rval);

	return ret;
}

bool match_valsInt(int lval, enum Operator op, int rval) {
	bool ret = false;

	if (op == eq && lval == rval)
		ret = true;
	else if (op == neq && lval != rval)
		ret = true;
	else if (op == le && lval <= rval)
		ret = true;
	else if (op == ge && lval >= rval)
		ret = true;
	else if (op == l && lval < rval)
		ret = true;
	else if (op == g && lval > rval)
		ret = true;

	return ret;
}

bool match_vals_devpath(const char *lvalStr, enum Operator op, const char *rvalStr, enum Valuetype valtype) {
	bool ret = false;
	int comp = 0;

	int lvalLen = strlen(lvalStr);
	int rvalLen = strlen(rvalStr);
	char *lval = calloc(lvalLen, sizeof(char));
	char *rval = calloc(rvalLen, sizeof(char));

		if(lval && rval) {
		char *lStr = NULL;
		char *rStr = NULL;
		char *lvalAllocPtr = lval;
		char *rvalAllocPtr = rval;
		strcpy(lval, lvalStr);
		strcpy(rval, rvalStr);

		// compare devnum like a software version number using sub version (e. g. major, minor, patch version)
		while ((lStr = strsep(&lval, ".")) && (rStr = strsep(&rval, ".")))
		{
			if (match_vals(lStr, g, rStr, valtype)) {
				comp = 1;
				break;
			} else if (match_vals(lStr, l, rStr, valtype)) {
				comp = -1;
				break;
			}
		}

		// compare result -1, 0, 1 with given operator
		ret = match_valsInt(comp, op, 0);

		free(lvalAllocPtr);
		free(rvalAllocPtr);
	}

	return ret;
}

bool match_vals_devpath_autotype(const char *lvalStr, enum Operator op, const char *rvalStr) {
	return match_vals_devpath(lvalStr, op, rvalStr, UNKNOWN);
}

bool match_vals(const char *lvalStr, enum Operator op, const char *rvalStr, enum Valuetype valtype) {
	enum Valuetype type = UNKNOWN;
	bool ret = false;
	bool useDevpathMatching = false;
	char* lend = NULL;
	char* rend = NULL;
	char* tmpStr = NULL;
	int base = 16;
	int lval = -1;
	int rval = -1;
	int rvalLen = strlen(rvalStr);

	if (valtype != UNKNOWN)
		type = valtype;
	else if (rvalLen >= 2 && rvalStr[0] == '"' && rvalStr[rvalLen-1] == '"') { // right value type is STRING
		type = STRING;
		rvalLen -= 2;

		tmpStr = calloc(rvalLen + 1, sizeof(char));
		strncpy(tmpStr, rvalStr + 1, rvalLen);
		tmpStr[rvalLen] = '\0';
		rvalStr = tmpStr;
	} else if (rvalLen >= 2 && rvalStr[0] == '\\') { // right value type is HEX, DEC or UNKNOWN
		if (rvalStr[1] == 'x') {
			type = HEX;
			base = 16;
		} else if (rvalStr[1] == 'd') {
			type = DEC;
			base = 10;
		}

		if (type != UNKNOWN) { // right value type is HEX or DEC
			rvalLen -= 2;
			tmpStr = calloc(rvalLen + 1, sizeof(char));
			strncpy(tmpStr, rvalStr + 2, rvalLen);
			tmpStr[rvalLen] = '\0';
			rvalStr = tmpStr;
		}
	}

	if (type != STRING) {
		if (strchr(rvalStr, '.')) // right value type contains '.'
			useDevpathMatching = true;
		else { // right value type is HEX, DEC or UNKNOWN
			lval = strtol(lvalStr, &lend, base);
			rval = strtol(rvalStr, &rend, base);

			if (lend && *lend != 0)
				lval = -1;

			if (rend && *rend != 0)
				rval = -1;
		}
	}

	if (useDevpathMatching)
		ret = match_vals_devpath(lvalStr, op, rvalStr, type);
	else if (lval != -1 && rval != -1)
		ret = match_valsInt(lval, op, rval);
	else if (type == STRING || type == UNKNOWN)
		ret = match_valsStr(lvalStr, op, rvalStr);

	if (debuglog)
		syslog(LOG_DEBUG, "match_vals:%i (%s %s %s), (%i %s %i)\n", ret, lvalStr, usbauth_op_to_str(op), rvalStr, lval, usbauth_op_to_str(op), rval);

	if (tmpStr)
		free(tmpStr);

	return ret;
}

bool match_vals_autotype(const char *lvalStr, enum Operator op, const char *rvalStr) {
	return match_vals(lvalStr, op, rvalStr, UNKNOWN);
}

bool match_vals_interface(struct Auth *rule, struct Data *d, struct udev_device *interface) {
	bool ret = false;
	const char* lvalStr = NULL;
	const char* rvalStr = d->val;
	const char* type = udev_device_get_devtype(interface);
	char cntStr[16];
	strcpy(cntStr, "");

	if (!type || !rvalStr || strcmp(type, "usb_interface") != 0)
		return false;

	if (intfcount == d->param) { // intfcount parameter is not in sysfs
		char* rend = NULL;
		int rval = strtol(rvalStr, &rend, 16);
		if (rend && *rend != 0)
			ret = false;
		else
			ret = match_valsInt(rule->intfcount + 1, d->op, rval);
	} else if (devcount == d->param) { // devcount parameter is not in sysfs
		char* rend = NULL;
		int rval = strtol(rvalStr, &rend, 16);
		if (rend && *rend != 0)
			ret = false;
		else
			ret = match_valsInt(rule->devcount + 1, d->op, rval);
	} else {
		lvalStr = usbauth_get_param_valStr(d->param, interface); // get parameter from sysfs
		if (lvalStr)
			ret = match_vals_autotype(lvalStr, d->op, rvalStr);
	}

	return ret;
}

bool match_vals_device(struct Auth *rule, struct Data *d, struct udev_device *device) {
	bool matches = false;
	const char *path = udev_device_get_syspath(device);
	const char *type = udev_device_get_devtype(device);
	struct udev_list_entry *devices = NULL, *entry = NULL;
	struct udev_enumerate *enumerate = NULL;
	int dev_class = 0;

	if (!path || !type || strcmp(type, "usb_device") != 0)
		return false;

	enumerate = udev_enumerate_new(udev);

	if (!enumerate)
		return false;

	udev_enumerate_add_match_parent(enumerate, device);
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	if (!devices)
		return false;

	// get the current class from sysfs, because unmatched interfaces should be unchanged
	dev_class = usbauth_get_param_val(bDeviceClass, device);

	// iterate over the childs (usb_interface's) of the udevdev (usb_device)
	udev_list_entry_foreach(entry, devices)
	{
		const char *path = NULL;
		struct udev_device *interface = NULL;
		const char *type = NULL;

		if (entry)
			path = udev_list_entry_get_name(entry);

		if (path)
			interface = udev_device_new_from_syspath(udev, path);

		if (interface)
			type = udev_device_get_devtype(interface);

		if (type && strcmp(type, "usb_interface") == 0) {
			int intf_class = usbauth_get_param_val(bInterfaceClass, interface);
			if (dev_class == 9 && intf_class != 9) // dev class is HUB and intf class is not HUB
				continue; // skip device childs from hubs, use only hub's interfaces

			matches |= match_vals_interface(rule, d, interface);
		}

		if (interface)
			udev_device_unref(interface);
	}

	udev_enumerate_unref(enumerate);

	if (debuglog)
		syslog(LOG_DEBUG, "match_vals_device:%i\n", matches);

	return matches;
}

bool no_error_check_dbus(DBusError *error) {
	bool ret = true;

	if (dbus_error_is_set(error)) {
		ret = false;

		if (debuglog)
			syslog(LOG_DEBUG, "dbus_error: %s\n", error->message);

		dbus_error_free(error);
	}

	return ret;
}

void send_dbus(struct udev_device *udevdev, int32_t authorize, int32_t devn) {
	DBusMessage *msg = NULL;
	DBusError error;
	bool dbusret = false;
	const char *path = udev_device_get_syspath(udevdev);

	if (!bus)
		return;

	dbus_error_init(&error);
	dbus_bus_request_name(bus, "org.opensuse.usbauth", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);

	if (!no_error_check_dbus(&error))
		return;

	msg = dbus_message_new_signal("/usbauth/signal/Object", "org.opensuse.usbauth.Message", "usbauth");

	if (!msg || !path)
		return;

	dbusret = dbus_message_append_args(msg, DBUS_TYPE_INT32, &authorize, DBUS_TYPE_INT32, &devn, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);

	if (dbusret)
		dbusret = dbus_connection_send(bus, msg, NULL);

	if (dbusret)
		dbus_connection_flush(bus);

	dbus_message_unref(msg);

	syslog(LOG_NOTICE, "send dbus message (path=%s)\n", path);
}

void probe_interface(struct udev_device *interface) {
	const char *type = udev_device_get_devtype(interface);
	if (type && strcmp(type, "usb_interface") == 0) {
		const char *name = udev_device_get_sysname(interface);
		FILE *probe = fopen("/sys/bus/usb/drivers_probe", "w");

		if (!name || !probe)
			return;

		fprintf(probe, "%s", name);
		fclose(probe);
	}
}

void probe_device(struct udev_device *udevdev) {
	const char *path = udev_device_get_syspath(udevdev);
	const char *type = udev_device_get_devtype(udevdev);
	struct udev_list_entry *devices = NULL, *entry = NULL;
	struct udev_enumerate *enumerate = NULL;

	if (!path || !type || strcmp(type, "usb_device") != 0)
		return;

	enumerate = udev_enumerate_new(udev);

	if (!enumerate)
		return;

	udev_enumerate_add_match_parent(enumerate, udevdev);
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	if (!devices)
		return;

	// iterate over the childs (usb_interface's) of the udevdev (usb_device)
	udev_list_entry_foreach(entry, devices)
	{
		const char *intfpath = NULL;
		struct udev_device *interface = NULL;

		if (entry)
			intfpath = udev_list_entry_get_name(entry);

		if (intfpath)
			interface = udev_device_new_from_syspath(udev, intfpath);

		if (interface)
			type = udev_device_get_devtype(interface);

		// probe interface
		probe_interface(interface);

		if (interface)
			udev_device_unref(interface);
	}
	udev_enumerate_unref(enumerate);
}

void authorize_interface(struct udev_device *interface, bool authorize, bool dbus) {
	const char *path = udev_device_get_syspath(interface);
	const char *type = udev_device_get_devtype(interface);
	int32_t devn = usbauth_get_param_val(devnum, interface);
	struct udev_device *parent = udev_device_get_parent(interface);
	char valueStr[16];

	if (!path || !type || !parent || strcmp(type, "usb_interface") != 0)
		return;

	strcpy(valueStr, "");
	snprintf(valueStr, 16, "%" SCNu8, authorize);

	udev_device_set_sysattr_value(interface, "authorized", valueStr);

	syslog(LOG_NOTICE, "%s interface %s/authorized\n", authorize ? "allow" : "deny", path);

	// probe all device's childs to avoid side-effects with drivers that need multiple interfaces
	probe_device(parent);

	if (dbus)
		send_dbus(interface, authorize, devn);
}

bool isRule(struct Auth *array, unsigned array_length) {
	bool ret = false;

	int i = 0;
	for (i = 0; i < array_length; i++) {
		if (array[i].type == ALLOW || array[i].type == DENY)
			ret = true;
	}

	return ret;
}

bool match_data(struct Auth *rule, struct Data *d, struct udev_device *interface) {
	bool ret = false;
	struct udev_device *parent = udev_device_get_parent(interface);

	if (d->anyChild) {
		ret = match_vals_device(rule, d, parent);
	} else {
		ret = match_vals_interface(rule, d, interface);
	}

	if (debuglog)
		syslog(LOG_DEBUG, "match_data:%i\n", ret);

	return ret;
}

struct match_ret match_auth_interface(struct Auth *rule, struct udev_device *interface) {
	int i;
	struct match_ret ret;
	bool match = false;
	ret.match_attrs = true;
	ret.match_conds = true;
	ret.match_attrs_nocnts = true;

	if (!rule || !interface || rule->type == COMMENT) {
		ret.match_attrs = false;
		ret.match_conds = false;
		ret.match_attrs_nocnts = false;
		return ret;
	}

	// iterate over the data structures (case parameters) from the auth structure
	// to check if the auth rule matches the cases
	for (i = 0; i < rule->attr_len; i++) {
		struct Data *d = &rule->attr_array[i];

		if (!d || !d->val) {
			ret.match_attrs = false;
			ret.match_conds = false;
			ret.match_attrs_nocnts = false;
			return ret;
		}

		match = match_data(rule, d, interface);
		ret.match_attrs &= match;

		if (d->param != devcount && d->param != intfcount)
			ret.match_attrs_nocnts &= match;
	}

	// iterate over the data structures (condition parameters) from the auth structure
	// to check if the auth rule matches the conditions
	for (i = 0; i < rule->cond_len && ret.match_attrs; i++) {
		struct Data *d = &rule->cond_array[i];

		if (!d || !d->val) {
			ret.match_attrs = false;
			ret.match_conds = false;
			ret.match_attrs_nocnts = false;
			return ret;
		}

		ret.match_conds &= match_data(rule, d, interface);
	}

	return ret;
}

struct auth_ret match_auths_interface(struct Auth *rule_array, size_t array_len, struct udev_device *usb_interface) {
	int i;
	struct auth_ret ret;
	ret.match = false;
	ret.allowed = false;

	// iterate over the rules without conditions from the auth array
	// for each rule that (case) attributes matches with the given interface
	for (i = 0; i < array_len; i++) {
		struct match_ret r1 = match_auth_interface(&rule_array[i], usb_interface);
		bool ruleApplicable = r1.match_attrs_nocnts; // true if interface is affected by rule
		if (rule_array[i].type != COND && ruleApplicable) {
			int j = 0;

			// iterate only over the conditions from the auth array
			// to check whether the auth rule matches the conditions
			for (j = 0; j < array_len; j++) {
				// conditions affecting only ALLOW rules
				if (rule_array[j].type == COND && rule_array[i].type == ALLOW) {
					struct match_ret r = match_auth_interface(&rule_array[j], usb_interface);
					// if the condition belongs to the interface (match_attrs is true, that are the case parameters)
					// AND the condition is fulfilled (match_conds is true, that are the condition parameters)
					if (r.match_attrs && r.match_conds) {
						rule_array[j].intfcount++; // count affects r.match_conds

						if (iscounted)
							iscounted[j] = true; // the devcount will incremented later to avoid side effects
					} else if (r.match_attrs && !r.match_conds) // only if the condition belongs to the interface (cases, match_attrs) and the condition is not fulfilled (conds, match_conds)
						ruleApplicable = false; // condition conflicts with affected rule then ignore the rule
				}
			}

			if (ruleApplicable) { // if current/iterated interface matched rule and was not disabled by conflicting condition
				rule_array[i].intfcount++; // describes how much interfaces are affected by the rule

				if (iscounted)
					iscounted[i] = true; // the devcount will incremented later to avoid side effects

				if (r1.match_attrs) {
					ret.match |= true; // if interface is affected by at least one rule do allow or deny it, otherwise skip allow/deny action
					ret.allowed = rule_array[i].type == ALLOW ? true : false; // allow or deny usb_interface, last rule is deciding
				}
			}
		}
	}

	if (debuglog)
		syslog(LOG_DEBUG, "match_auths_interface:%i:%i\n", ret.match, ret.allowed);

	return ret;
}

void match_auths_device_interfaces(struct Auth *rule_array, size_t array_len, struct udev_device *usb_device) {
	const char *type = udev_device_get_devtype(usb_device);
	const char *path = udev_device_get_syspath(usb_device);
	struct udev_list_entry *devices = NULL, *entry = NULL;
	struct udev_enumerate *enumerate = NULL;
	unsigned dev_class = 0;
	const char *plugpath = NULL;

	if (plug_usb_device)
		plugpath = udev_device_get_syspath(plug_usb_device);

	if (!path || !type)
		return;

	if (plugpath && strcmp(path, plugpath) == 0)
		return;

	if (strcmp(type, "usb_device") != 0)
		return;

	enumerate = udev_enumerate_new(udev);

	if (!enumerate)
		return;

	udev_enumerate_add_match_parent(enumerate, usb_device);
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	if (!devices)
		return;

	dev_class = usbauth_get_param_val(bDeviceClass, usb_device);

	if (!iscounted)
		iscounted = calloc(array_len, sizeof(bool));

	// iterate over the childs (usb_interface's) of the udevdev (usb_device)
	udev_list_entry_foreach(entry, devices)
	{
		const char *path = NULL;
		struct udev_device *interface = NULL;
		const char *type = NULL;

		if (entry)
			path = udev_list_entry_get_name(entry);

		if (path)
			interface = udev_device_new_from_syspath(udev, path);

		if (interface)
			type = udev_device_get_devtype(interface);

		if (type && strcmp(type, "usb_interface") == 0) {
			unsigned intf_class = usbauth_get_param_val(bInterfaceClass, interface);
			struct auth_ret r;

			if (dev_class == 9 && intf_class != 9) // dev class is HUB and intf class is not HUB
				continue; // skip device childs from hubs, use only hub's interfaces

			r = match_auths_interface(rule_array, array_len, interface);

			// do only if one rule has matched, so if there would no generic rule and no specific rule do nothing
			// now it's the correct device (if plug is set it's only initialization)
			// do not authorize interfaces and do not send dbus messages multiple times
			if (r.match && !plug_usb_device)
				authorize_interface(interface, r.allowed, true);
		}

		if (interface)
			udev_device_unref(interface);
	}

	// if multiple interfaces are counted by an rule count only once for device
	if (iscounted) {
		unsigned i;
		for (i=0; i<array_len; i++) {
			if (iscounted[i])
				rule_array[i].devcount++;
		}
		free(iscounted);
		iscounted = NULL;
	}

	udev_enumerate_unref(enumerate);

	if (debuglog)
		syslog(LOG_DEBUG, "match_auths_device_interfaces plug=%s path=%s\n", plug_usb_device ? "true" : "false", path);
}

void perform_rules_devices(struct Auth *rule_array, size_t array_len, bool add) {
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *entry;

	enumerate = udev_enumerate_new(udev);

	if (!enumerate)
		return;

	udev_enumerate_add_match_subsystem(enumerate, "usb");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	if (!devices)
		return;

	syslog(LOG_NOTICE, "perform rules for devices (add=%s)\n", add ? "true" : "false");

	// iterate over all USB devices
	udev_list_entry_foreach(entry, devices)
	{
		const char *path = NULL;
		struct udev_device *udevdev = NULL;
		const char *type = NULL;

		if (entry)
			path = udev_list_entry_get_name(entry);

		if (path)
			udevdev = udev_device_new_from_syspath(udev, path);

		if (udevdev)
			type = udev_device_get_devtype(udevdev);

		if (type && strcmp(type, "usb_device") == 0) // filter out interfaces, to avoid multiple iterations
			match_auths_device_interfaces(rule_array, array_len, udevdev);

		if (udevdev)
			udev_device_unref(udevdev);
	}

	udev_enumerate_unref(enumerate);
}

void perform_udev_env(struct Auth *auths, size_t length, bool add) {
	const char *type = NULL;
	struct udev_device *intf = NULL;

	intf = udev_device_new_from_environment(udev);

	if (intf)
		type = udev_device_get_devtype(intf);

	if (type && strcmp(type, "usb_interface") == 0) { // use only usb_device's
		if (add)
			plug_usb_device = udev_device_get_parent(intf); // set parent of interface (device)

		syslog(LOG_NOTICE, "called by udev with given usb_interface\n");

		if (add) { // only in udev-add mode
			struct auth_ret r;
			perform_rules_devices(auths, length, false); // plug device will excluded
			plug_usb_device = NULL; // to work with excluded device
			//match_auths_device_interfaces(auths, length, intf); // check plugged (excluded before) device's interfaces now

			r = match_auths_interface(auths, length, intf);

			// do only if one rule has matched, so if there would no generic rule and no specific rule do nothing
			if (r.match)
				authorize_interface(intf, r.allowed, true);
		}
	}
}

void perform_notifier(const char* actionStr, const char* devnumStr, const char* path) {
	struct udev_device *interface = udev_device_new_from_syspath(udev, path);
	char* end = NULL;
	int devn_argv = strtol(devnumStr, &end, 16);
	int devn_sysfs = -1;
	const char *type = NULL;

	syslog(LOG_NOTICE, "called by notifier\n");

	if (interface) {
		devn_sysfs = usbauth_get_param_val(devnum, interface);
		type = udev_device_get_devtype(interface);
	}

	// at conversion error do nothing
	if (end && *end != 0)
		type = NULL;

	// devnr from parameter list must be the same as from sysfs to ensure the correct device
	if (type && strcmp(type, "usb_interface") == 0 && devn_sysfs == devn_argv) {
		bool allw = strcmp(actionStr, "allow") == 0 ? true : false;

		authorize_interface(interface, allw, false);
		udev_device_unref(interface);
	}
}

int main(int argc, char **argv) {
	unsigned length = 0;
	struct Auth *auths = NULL;
	DBusError error;

	dbus_error_init(&error);
	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	udev = udev_new();

	if (!udev) { // udev is needed
		syslog(LOG_ERR, "udev error\n");
		return EXIT_FAILURE;
	}

	// connect to syslog
	openlog("usbauth", LOG_PERROR | LOG_PID, LOG_LOCAL0);

	// use stderr if logfile cannot accessed
	if (!logfile)
		logfile = stderr;

	// at dbus error disable it
	if (!no_error_check_dbus(&error) && bus) {
		dbus_connection_unref(bus);
		bus = NULL;
	}

	if (usbauth_config_read())
		 syslog(LOG_ERR, "error at parsing usbauth configuration file\n");

	usbauth_config_get_auths(&auths, &length);

	if (!iscounted)
		iscounted = calloc(length, sizeof(bool));

	if (!isRule(auths, length)) {
		syslog(LOG_ERR, "Config file not found or empty.\n");
	} else if (argc <= 1) {
		syslog(LOG_ERR, "more than one argument is needed to call usbauth\n");
	} else if (argc <= 2) {
		if (strcmp(argv[1], "udev-add") == 0) { // called by udev
			perform_udev_env(auths, length, true);
		} else if (strcmp(argv[1], "init") == 0) { // called manually with init parameter
			perform_rules_devices(auths, length, true);
		}
	} else if (argc > 2 && (strcmp(argv[1], "allow") == 0 || strcmp(argv[1], "deny") == 0)) { // called by notifier
		perform_notifier(argv[1], argv[2], argv[3]);
	} else {
		syslog(LOG_ERR, "wrong syntax to call usbauth\n");
	}

	if (bus) {
		dbus_connection_unref(bus);
		bus = NULL;
	}

	udev_unref(udev);
	udev = NULL;
	usbauth_config_free_auths(auths, length);

	// disconnect from syslog
	closelog();

	return EXIT_SUCCESS;
}
