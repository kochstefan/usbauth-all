/*
 ============================================================================
 Name        : usbauth.c
 Author      : Stefan Koch
 Version     : alpha
 Copyright   : 2015 SUSE Linux GmbH
 Description : USB authentication for udev
 ============================================================================
 */

#include "usbauth.h"
#include "../../usbauth_configparser/src/usbauth_configparser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_FILE "/home/stefan/usbauth.config"
#define LOG_FILE "/home/stefan/logusbauth"
#define SYSFS_USB "/sys/bus/usb/devices"

#define NOTIFY_DIR "/home/stefan/notify/"

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

int get_param_val(int param, struct udev_device *udevdev) {
	unsigned val = 0;
	struct udev_device *parent = udev_device_get_parent(udevdev);

	if(!udevdev) {
		return val;
	}

	switch(param) {
	case busnum:
		val = strtoul(udev_device_get_sysattr_value(parent, "busnum"), NULL, 16);
		break;
	case devpath:
		val = strtoul(udev_device_get_sysattr_value(parent, "devpath"), NULL, 16);
		break;
	case idVendor:
		val = strtoul(udev_device_get_sysattr_value(parent, "idVendor"), NULL, 16);
		break;
	case idProduct:
		val = strtoul(udev_device_get_sysattr_value(parent, "idProduct"), NULL, 16);
		break;
	case bDeviceClass:
		val = strtoul(udev_device_get_sysattr_value(parent, "bDeviceClass"), NULL, 16);
		break;
	case bDeviceSubClass:
		val = strtoul(udev_device_get_sysattr_value(parent, "bDeviceSubClass"), NULL, 16);
		break;
	case bDeviceProtocol:
		val = strtoul(udev_device_get_sysattr_value(parent, "bDeviceProtocol"), NULL, 16);
		break;
	case bConfigurationValue:
		val = strtoul(udev_device_get_sysattr_value(parent, "bConfigurationValue"), NULL, 0);
		break;
	case bInterfaceNumber:
		val = strtoul(udev_device_get_sysattr_value(udevdev, "bInterfaceNumber"), NULL, 16);
		break;
	case bInterfaceClass:
		val = strtoul(udev_device_get_sysattr_value(udevdev, "bInterfaceClass"), NULL, 16);
		break;
	case bInterfaceSubClass:
		val = strtoul(udev_device_get_sysattr_value(udevdev, "bInterfaceSubClass"), NULL, 16);
		break;
	case bInterfaceProtocol:
		val = strtoul(udev_device_get_sysattr_value(udevdev, "bInterfaceProtocol"), NULL, 16);
		break;
	default:
		break;
	}

	return val;
}

void serialize_dbus_error_check(DBusError *error) {
	if(dbus_error_is_set(error)) {
		printf("error %s", error->message);
		dbus_error_free(error);
	}
}

void serialize_dbus(struct udev_device *udevdev, bool authorize) {
	const char *path = udev_device_get_syspath(udevdev);
	DBusError error;
	dbus_error_init(&error);
	DBusConnection *bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	serialize_dbus_error_check(&error);

	//dbus_bus_request_name(bus, "test.signal.source", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);

	serialize_dbus_error_check(&error);

	DBusMessage *msg = dbus_message_new_signal("/test/signal/Object", "test.signal.Type", "Test");
	if(!msg)
		printf("NULL");

	dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &authorize, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);
	fprintf(logfile, "dbus%s\n", path);
	dbus_connection_send(bus, msg, NULL);
	dbus_connection_flush(bus);
	dbus_message_unref(msg);
	msg=NULL;
	dbus_connection_unref(bus);
	bus=NULL;
}

void authorize_interface_libudev(struct udev_device *udevdev, bool authorize, bool dbus) {
	const char* path = udev_device_get_devpath(udevdev);
	unsigned cl = strtoul(udev_device_get_sysattr_value(udevdev, "bInterfaceClass"), NULL, 16);
	fprintf(logfile, "USB Interface with class %02x\n", cl);
	unsigned value = authorize ? 1 : 0;
	char v[16];
	strcpy(v, "");
	sprintf(v, "%x", value);
	fprintf(logfile, "/sys%s/interface_authorized %u\n", path, value);
	if (dbus)
		serialize_dbus(udevdev, authorize);
	udev_device_set_sysattr_value(udevdev, "interface_authorized", v);
}

void authorize_device_libudev(struct udev_device *udevdev, bool authorize, bool dbus) {
	const char* path = udev_device_get_devpath(udevdev);
	unsigned cl = strtoul(udev_device_get_sysattr_value(udevdev, "bDeviceClass"), NULL, 16);
	unsigned val = strtoul(udev_device_get_sysattr_value(udevdev, "bNumInterfaces"), NULL, 16);
	fprintf(logfile, "USB Interface with class %02x\n", cl);
	unsigned value = authorize ? val : 0;
	char v[16];
	strcpy(v, "");
	sprintf(v, "%x", value);
	fprintf(logfile, "/sys%s/interface_authorization_mask %u\n", path, value);
	if (dbus)
		serialize_dbus(udevdev, authorize);
	udev_device_set_sysattr_value(udevdev, "interface_authorization_mask", v);
}

struct match_ret match_auth_interface(struct auth *a, struct udev_device *udevdev) {
	struct match_ret ret;
	ret.match_attrs = true;
	ret.match_cond = true;

	if(!a || !udevdev || !a->valid) {
		ret.match_attrs = false;
		ret.match_cond = false;
		return ret;
	}

	int i;
	for (i = 0; i < a->attr_len; i++) {
		struct data *d = &a->attr_array[i];
		unsigned val = 0;

		val = get_param_val(d->param, udevdev);

		if(count == d->param) // count parameter is not in udev device
			val = a->count;

		if (d->op == eq && !(val == d->val))
			ret.match_attrs = false;
		else if (d->op == neq && !(val != d->val))
			ret.match_attrs = false;
		else if (d->op == lt && !(val <= d->val))
			ret.match_attrs = false;
		else if (d->op == gt && !(val >= d->val))
			ret.match_attrs = false;
		else if (d->op == l && !(val < d->val))
			ret.match_attrs = false;
		else if (d->op == g && !(val > d->val))
			ret.match_attrs = false;
	}

	for (i = 0; i < a->cond_len && ret.match_attrs; i++) {
		struct data *d = &a->cond_array[i];
		unsigned val = 0;

		if(count == d->param) // count parameter is not in udev device
			val = a->count;

		if (d->op == eq && !(val == d->val))
			ret.match_cond = false;
		else if (d->op == neq && !(val != d->val))
			ret.match_cond = false;
		else if (d->op == lt && !(val <= d->val))
			ret.match_cond = false;
		else if (d->op == gt && !(val >= d->val))
			ret.match_cond = false;
		else if (d->op == l && !(val < d->val))
			ret.match_cond = false;
		else if (d->op == g && !(val > d->val))
			ret.match_cond = false;
	}

	return ret;
}

struct auth_ret match_auths_interface(struct auth *a, size_t len, struct udev_device *udevdev) {
	struct auth_ret ret;
	ret.match = false;
	ret.allowed = false;
	int i;
	for (i = 0; i < len; i++) {
		if (!a[i].cond && match_auth_interface(&a[i], udevdev).match_attrs) {

			bool ruleMatched = true;
			int j = 0;
			for (j = 0; j < len; j++) {
				struct match_ret r;
				if (a[j].cond) {
					r = match_auth_interface(&a[j], udevdev);
					if (r.match_attrs && r.match_cond && a[i].allowed) {// count only if allowed for conditions
						a[j].count++;
						unsigned u = a[j].count;
						fprintf(logfile, "cc %i  %u\n", j, u);
					}
					else if (r.match_attrs && !r.match_cond) // only if interface matched properties and condition complies
						ruleMatched = false;
				}
			}

			if (ruleMatched) { // if current/iterated rule matched
				a[i].count++;

				unsigned u = a[i].count;
				fprintf(logfile, "dd %i  %u\n", i, u);

				ret.match |= true;
				ret.allowed = a[i].allowed;
			}
		}
	}
	return ret;
}

void match_auths_device_interfaces(struct auth *a, size_t len, struct udev_device *udevdev, bool emulate) {
	const char *type = udev_device_get_devtype(udevdev);
	const char *path = udev_device_get_syspath(udevdev);

	if(!path || !type)
		return;

	if (strcmp(type, "usb_device") != 0)
		return;

	fprintf(logfile, "DEV %s %s\n", path, type);

	struct udev_list_entry *devices, *entry;
	struct udev_enumerate *enumerate = udev_enumerate_new(udev);

	udev_enumerate_add_match_parent(enumerate, udevdev);
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	unsigned val = strtoul(udev_device_get_sysattr_value(udevdev, "bDeviceClass"), NULL, 16);

	bool genMatch = false;
	bool genAllowed = true;
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

		if (type && strcmp(type, "usb_interface") == 0) {
			unsigned ival = strtoul(udev_device_get_sysattr_value(udevdev, "bInterfaceClass"), NULL, 16);
			if(val == 9 && ival !=9)
				continue; // skip other childs from hub that not belong to itself

			fprintf(logfile, "path %s %s\n", path, type);
			struct auth_ret r = match_auths_interface(a, len, udevdev);

			if(val == 0) {
				if (!emulate && r.match) // if one rule has matched
					authorize_interface_libudev(udevdev, r.allowed, true);
			} else {
				genMatch |= r.match;
				genAllowed &= r.allowed;
			}
		}

		if (udevdev)
			udev_device_unref(udevdev);
	}

	udev_enumerate_unref(enumerate);

	if (!emulate && val != 0 && genMatch)  // if one rule has matched
		authorize_device_libudev(udevdev, genAllowed, true);
}

void perform_rules_devices(struct auth *a, size_t len, bool emulate) {
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *entry;

	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "usb");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

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

		if (type && strcmp(type, "usb_device") == 0) // filter out interfaces
			match_auths_device_interfaces(a, len, udevdev, emulate);

		if (udevdev)
			udev_device_unref(udevdev);
	}

	udev_enumerate_unref(enumerate);
}

bool perform_rules_environment(struct auth *a, size_t len) {
	struct udev_device *udevdev = udev_device_new_from_environment(udev);

	if(!udevdev)
		return false;

	const char *path = udev_device_get_devpath(udevdev);
	const char *type = udev_device_get_devtype(udevdev);

	if(!path || !type)
		return false;

	if (strcmp(type, "usb_device") == 0) {
		fprintf(logfile, "path %s %s\n", path, type);
		const char* cl = udev_device_get_sysattr_value(udevdev, "bDeviceClass");
		if(cl)
			strtoul(cl, NULL, 16);
		fprintf(logfile, "class %s\n", cl);
		match_auths_device_interfaces(a, len, udevdev, false);
	}

	udev_device_unref(udevdev);

	return true;
}

int main(int argc, char **argv) {
	udev = udev_new();
	logfile = fopen(LOG_FILE, "w");

	usbauth_config_read();
	unsigned length;
	struct auth *auths;
	usbauth_config_get_auths(&auths, &length);

	if (argc <= 1) { // called by udev
		perform_rules_devices(auths, length, true);
		perform_rules_environment(auths, length);
	} else if(strcmp(argv[1], "init") == 0) { // called manually with init parameter
		perform_rules_devices(auths, length, false);
	} else if (argc > 2 && (strcmp(argv[1], "allow") == 0 || strcmp(argv[1], "deny") == 0)) { // called by notifier
		struct udev_device *udevdev = udev_device_new_from_syspath(udev, argv[2]);
		if(udevdev) {
			bool allw = strcmp(argv[1], "allow") == 0 ? true : false;
			authorize_interface_libudev(udevdev, allw, false);
			udev_device_unref(udevdev);
		}
	}

	udev_unref(udev);
	usbauth_config_free_auths(auths, length);

	return 0;
}
