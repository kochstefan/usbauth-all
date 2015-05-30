/*
 * Copyright (c) 2015 SUSE LLC. All Rights Reserved.
 * Author: Stefan Koch <skoch@suse.de>
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

#include <usbauth/usbauth_configparser.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>

#define LOG_FILE "/var/log/usbauth.log"
#define LOG2_FILE "/var/log/usbauth.log2"
#define LOG3_FILE "/var/log/usbauth.log3"
#define LOCK_FILE "/var/run/usbauth.pid"

struct kernels {
	uint8_t busnum;
	uint8_t devpath;
	uint8_t confignum;
	uint8_t intfnum;
};

struct ser {
	bool allowed;
	uint8_t cl;
	uint16_t vId;
	uint16_t pId;
	uint8_t busnum;
	uint8_t devpath;
};

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
	else if (op == lt && cmp <= 0)
		ret = true;
	else if (op == gt && cmp >= 0)
		ret = true;
	else if (op == l && cmp < 0)
		ret = true;
	else if (op == g && cmp > 0)
		ret = true;

	if (debuglog)
		fprintf(logfile, "match_valsStr:%i (%s %s %s)\n", ret, lval, usbauth_op_to_str(op), rval);

	return ret;
}

bool match_valsInt(int lval, enum Operator op, int rval) {
	bool ret = false;

	if (op == eq && lval == rval)
		ret = true;
	else if (op == neq && lval != rval)
		ret = true;
	else if (op == lt && lval <= rval)
		ret = true;
	else if (op == gt && lval >= rval)
		ret = true;
	else if (op == l && lval < rval)
		ret = true;
	else if (op == g && lval > rval)
		ret = true;

	return ret;
}

bool match_vals(const char *lvalStr, enum Operator op, const char *rvalStr) {
	bool ret = false;
	char* lend = NULL;
	char* rend = NULL;
	int lval = strtol(lvalStr, &lend, 16);
	int rval = strtol(rvalStr, &rend, 16);

	if(lend && *lend != 0)
		lval = -1;

	if(rend && *rend != 0)
		rval = -1;

	if(lval != -1 && rval != -1)
		ret = match_valsInt(lval, op, rval);
	else
		ret = match_valsStr(lvalStr, op, rvalStr);

	if (debuglog)
		fprintf(logfile, "match_vals:%i (%s %s %s), (%i %s %i)\n", ret, lvalStr, usbauth_op_to_str(op), rvalStr, lval, usbauth_op_to_str(op), rval);

	return ret;
}

bool match_vals_interface(struct Auth *rule, struct Data *d, struct udev_device *interface) {
	bool ret = false;
	const char* lvalStr = NULL;
	const char* rvalStr = d->val;
	const char *type = udev_device_get_devtype(interface);
	char cntStr[16];
	strcpy(cntStr, "");

	if (!type || strcmp(type, "usb_interface") != 0)
		return false;

	if(intfcount == d->param) { // intfcount parameter is not in sysfs
		char* rend = NULL;
		int rval = strtol(rvalStr, &rend, 16);
		if (rend && *rend != 0)
			ret = false;
		else
			ret = match_valsInt(rule->intfcount + 1, d->op, rval);
	} else if(devcount == d->param) { // devcount parameter is not in sysfs
		char* rend = NULL;
		int rval = strtol(rvalStr, &rend, 16);
		if (rend && *rend != 0)
			ret = false;
		else
			ret = match_valsInt(rule->devcount + 1, d->op, rval);
	} else {
		lvalStr = usbauth_get_param_valStr(d->param, interface); // get parameter from sysfs
		ret = match_vals(lvalStr, d->op, rvalStr);
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

	if(!enumerate)
		return false;

	udev_enumerate_add_match_parent(enumerate, device);
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	if(!devices)
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
			if(dev_class == 9 && intf_class != 9) // dev class is HUB and intf class is not HUB
				continue; // skip device childs from hubs, use only hub's interfaces

			matches |= match_vals_interface(rule, d, interface);
		}

		if (interface)
			udev_device_unref(interface);
	}

	udev_enumerate_unref(enumerate);

	if (debuglog)
		fprintf(logfile, "match_vals_device:%i\n", matches);

	return matches;
}

bool device_processed(struct udev_device* dev) {
	bool ret = 0;
	const char *maskChStr = udev_device_get_sysattr_value(dev, "interface_authorization_mask_changed");
	if (maskChStr)
		ret = strtoul(maskChStr, NULL, 16) == 1 ? true : false;

	return ret;
}

bool no_error_check_dbus(DBusError *error) {
	bool ret = true;

	if(dbus_error_is_set(error)) {
		ret = false;
		fprintf(logfile, "dbus_error %s\n", error->message);
		dbus_error_free(error);
	}

	return ret;
}

void send_dbus(struct udev_device *udevdev, int32_t authorize, int32_t devn) {
	DBusMessage *msg = NULL;
	DBusError error;
	const char *path = udev_device_get_syspath(udevdev);

	dbus_error_init(&error);
	dbus_bus_request_name(bus, "org.opensuse.usbauth", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);

	no_error_check_dbus(&error);

	msg = dbus_message_new_signal("/usbauth/signal/Object", "org.opensuse.usbauth.Message", "usbauth");

	if(!msg || !path)
		return;

	dbus_message_append_args(msg, DBUS_TYPE_INT32, &authorize, DBUS_TYPE_INT32, &devn, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);
	dbus_connection_send(bus, msg, NULL);
	dbus_connection_flush(bus);
	dbus_message_unref(msg);

	fprintf(logfile, "send_dbus %s\n", path);
}

void authorize_mask(struct udev_device *udevdev, uint32_t mask, bool dbus) {
	const char *path = udev_device_get_syspath(udevdev);
	const char *type = udev_device_get_devtype(udevdev);
	char maskStr[16];

	if (!path || !type || strcmp(type, "usb_device") != 0)
		return;

	strcpy(maskStr, "");
	snprintf(maskStr, 16, "%" SCNx32, mask);

	udev_device_set_sysattr_value(udevdev, "interface_authorization_mask", maskStr);

	fprintf(logfile, "authorize_mask %x %s/interface_authorization_mask\n", mask, path);

	if (dbus) {
		struct udev_list_entry *devices = NULL, *entry = NULL;
		struct udev_enumerate *enumerate = NULL;
		unsigned dev_class = 0;

		enumerate = udev_enumerate_new(udev);

		if(!enumerate)
			return;

		udev_enumerate_add_match_parent(enumerate, udevdev);
		udev_enumerate_scan_devices(enumerate);
		devices = udev_enumerate_get_list_entry(enumerate);

		if(!devices)
			return;

		// get the current mask from sysfs, because unmatched interfaces should be unchanged
		dev_class = usbauth_get_param_val(bDeviceClass, udevdev);

		// iterate over the childs (usb_interface's) of the udevdev (usb_device)
		udev_list_entry_foreach(entry, devices)
		{
			const char *intfpath = NULL;
			struct udev_device *interface = NULL;
			const char *type = NULL;

			if (entry)
				intfpath = udev_list_entry_get_name(entry);

			if (intfpath)
				interface = udev_device_new_from_syspath(udev, intfpath);

			if (interface)
				type = udev_device_get_devtype(interface);

			if (type && strcmp(type, "usb_interface") == 0) {
				unsigned intf_class = usbauth_get_param_val(bInterfaceClass, interface);
				int nr = usbauth_get_param_val(bInterfaceNumber, interface);
				int32_t devn = usbauth_get_param_val(devnum, udevdev);

				if(dev_class == 9 && intf_class != 9) // dev class is HUB and intf class is not HUB
					continue; // skip device childs from hubs, use only hub's interfaces

				send_dbus(interface, mask & (1 << nr) ? true : false, devn);
			}

			if (interface)
				udev_device_unref(interface);
		}
		udev_enumerate_unref(enumerate);
	}
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

	if(d->anyChild) {
		ret = match_vals_device(rule, d, parent);
	} else {
		ret = match_vals_interface(rule, d, interface);
	}

	if (debuglog)
		fprintf(logfile, "match_data:%i\n", ret);

	return ret;
}

struct match_ret match_auth_interface(struct Auth *rule, struct udev_device *interface) {
	int i;
	struct match_ret ret;
	bool match = false;
	ret.match_attrs = true;
	ret.match_conds = true;
	ret.match_attrs_nocnts = true;

	if(!rule || !interface || rule->type == COMMENT) {
		ret.match_attrs = false;
		ret.match_conds = false;
		ret.match_attrs_nocnts = false;
		return ret;
	}

	// iterate over the data structures (case parameters) from the auth structure
	// to check if the auth rule matches the cases
	for (i = 0; i < rule->attr_len; i++) {
		struct Data *d = &rule->attr_array[i];

		if(!d || !d->val) {
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

		if(!d || !d->val) {
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

						iscounted[j] = true; // the devcount will incremented later to avoid side effects
					} else if (r.match_attrs && !r.match_conds) // only if the condition belongs to the interface (cases, match_attrs) and the condition is not fulfilled (conds, match_conds)
						ruleApplicable = false; // condition conflicts with affected rule then ignore the rule
				}
			}

			if (ruleApplicable) { // if current/iterated interface matched rule and was not disabled by conflicting condition
				rule_array[i].intfcount++; // describes how much interfaces are affected by the rule

				iscounted[i] = true;  // the devcount will incremented later to avoid side effects

				if (r1.match_attrs) {
					ret.match |= true; // if interface is affected by at least one rule do allow or deny it, otherwise skip allow/deny action
					ret.allowed = rule_array[i].type == ALLOW ? true : false; // allow or deny usb_interface, last rule is deciding
				}
			}
		}
	}

	if (debuglog)
		fprintf(logfile, "match_auths_interface:%i:%i\n", ret.match, ret.allowed);

	return ret;
}

void match_auths_device_interfaces(struct Auth *rule_array, size_t array_len, struct udev_device *usb_device) {
	const char *type = udev_device_get_devtype(usb_device);
	const char *path = udev_device_get_syspath(usb_device);
	struct udev_list_entry *devices = NULL, *entry = NULL;
	struct udev_enumerate *enumerate = NULL;
	unsigned dev_class = 0;
	uint32_t mask = 0;
	const char *plugpath = NULL;
	const char *maskStr = NULL;

	if(plug_usb_device)
		plugpath = udev_device_get_syspath(plug_usb_device);

	if(!path || !type)
		return;

	if (plugpath && strcmp(path, plugpath) == 0)
		return;

	if (strcmp(type, "usb_device") != 0)
		return;

	enumerate = udev_enumerate_new(udev);

	if(!enumerate)
		return;

	udev_enumerate_add_match_parent(enumerate, usb_device);
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	if(!devices)
		return;

	// get the current mask from sysfs, because unmatched interfaces should be unchanged
	dev_class = usbauth_get_param_val(bDeviceClass, usb_device);
	maskStr = udev_device_get_sysattr_value(usb_device, "interface_authorization_mask");
	if (maskStr)
		mask = strtoul(maskStr, NULL, 16);

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

			if(dev_class == 9 && intf_class != 9) // dev class is HUB and intf class is not HUB
				continue; // skip device childs from hubs, use only hub's interfaces

			struct auth_ret r = match_auths_interface(rule_array, array_len, interface);
			uint8_t nr = usbauth_get_param_val(bInterfaceNumber, interface);

			// do only if one rule has matched, so if there would no generic rule and no specific rule do nothing
			if (r.match) {
				if (r.allowed)
					mask |= (1 << nr);
				else if (!r.allowed)
					mask &= ~(1 << nr);
			}
		}

		if (interface)
			udev_device_unref(interface);
	}

	// if multiple interfaces are counted by an rule count only once for device
	if (iscounted) {
		unsigned i;
		for (i=0; i<array_len; i++) {
			if(iscounted[i])
				rule_array[i].devcount++;
		}
		free(iscounted);
		iscounted = NULL;
	}

	udev_enumerate_unref(enumerate);

	// now it's the correct device (if plug is set it's only initialization)
	// do not authorize interfaces and do not send dbus messages multiple times
	if (!plug_usb_device) {
		authorize_mask(usb_device, mask, true);
	}

	if (debuglog)
		fprintf(logfile, "match_auths_device_interfaces mask=%x plug=%i path=%s\n", mask, plug_usb_device ? true : false, path);
}

void perform_rules_devices(struct Auth *rule_array, size_t array_len, bool add) {
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *entry;

	enumerate = udev_enumerate_new(udev);

	if(!enumerate)
		return;

	udev_enumerate_add_match_subsystem(enumerate, "usb");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	if(!devices)
		return;

	if (add)
		fprintf(logfile, "perform_rules_devices\n");

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

	plug_usb_device = udev_device_new_from_environment(udev);

	if (plug_usb_device)
		type = udev_device_get_devtype(plug_usb_device);

	if (type && strcmp(type, "usb_interface") == 0) { // use only usb_device's
		struct udev_device *plg = NULL;
		if(add)
		plug_usb_device = udev_device_get_parent(plug_usb_device); // set parent of interface (device)

		if(device_processed(plug_usb_device))
			return;

		fprintf(logfile, "perform_udev_env\n");

		plg = plug_usb_device; // save local pointer
		if (add) { // only in udev-add mode
			perform_rules_devices(auths, length, false); // plug device will excluded
			plug_usb_device = NULL; // to work with excluded device
			match_auths_device_interfaces(auths, length, plg); // check plugged (excluded before) device's interfaces now
		}
	}
}

void perform_notifier(const char* actionStr, const char* devnumStr, const char* path) {
	struct udev_device *interface = udev_device_new_from_syspath(udev, path);
	char* end = NULL;
	int devn_argv = strtol(devnumStr, &end, 16);
	int devn_sysfs = -1;
	const char *type = NULL;

	fprintf(logfile, "perform_notifier\n");

	if(interface) {
		devn_sysfs = usbauth_get_param_val(devnum, interface);
		type = udev_device_get_devtype(interface);
	}

	// at conversion error do nothing
	if (end && *end != 0)
		type = NULL;

	// devnr from parameter list must be the same as from sysfs to ensure the correct device
	if(type && strcmp(type, "usb_interface") == 0 && devn_sysfs == devn_argv) {
		struct udev_device *parent = udev_device_get_parent(interface);
		int iNr = usbauth_get_param_val(bInterfaceNumber, interface);
		bool allw = strcmp(actionStr, "allow") == 0 ? true : false;
		const char* maskStr = udev_device_get_sysattr_value(parent, "interface_authorization_mask");
		int val = -1;

		if(maskStr)
			val = strtol(maskStr, NULL, 16);

		if (parent && iNr >= 0) {
			uint32_t mask = 0;
			if(val >= 0)
				mask = val;

			if (allw)
				mask |= (1 << iNr);
			else
				mask &= ~(1 << iNr);

			authorize_mask(parent, mask, false);
		}
		udev_device_unref(interface);
	}
}

int main(int argc, char **argv) {
	unsigned length = 0;
	struct Auth *auths = NULL;
	int pid_file = 0;
	DBusError error;
	dbus_error_init(&error);
	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	no_error_check_dbus(&error);

	// create pid file to avoid multiple usbauth processes
	pid_file = open(LOCK_FILE, O_CREAT | O_RDWR);

	// wait that a possible lock is away
	while(flock(pid_file, LOCK_EX | LOCK_NB))
		usleep(100000);

	udev = udev_new();
	if(!udev)
		return EXIT_FAILURE;

	logfile = fopen(LOG_FILE, "a");

	if(!logfile)
		logfile = stderr;

	usbauth_config_read();

	usbauth_config_get_auths(&auths, &length);

	if(!isRule(auths, length)) {
		fprintf(logfile, "Config file not found or empty.\n");
	} else if(argc <= 1) {
		printf("read manpage how to call usbauth\n");
	} else if(argc <= 2) {
		if(strcmp(argv[1], "udev-add") == 0) { // called by udev
			perform_udev_env(auths, length, true);
		} else if(strcmp(argv[1], "init") == 0) { // called manually with init parameter
			perform_rules_devices(auths, length, true);
		}
	} else if (argc > 2 && (strcmp(argv[1], "allow") == 0 || strcmp(argv[1], "deny") == 0)) { // called by notifier
		perform_notifier(argv[1], argv[2], argv[3]);
	}

	dbus_connection_unref(bus);
	bus=NULL;

	udev_unref(udev);
	udev = NULL;
	usbauth_config_free_auths(auths, length);
	return EXIT_SUCCESS;
}
