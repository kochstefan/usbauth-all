/*
 ============================================================================
 Name        : usbauth.c
 Author      : Stefan Koch
 Version     : alpha
 Copyright   : 2015 SUSE Linux GmbH
 Description : USB authentication for udev
 ============================================================================
 */

#include "generic.h"
#include "../../usbauth_configparser/src/usbauth_configparser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libudev.h>
#include <dbus/dbus.h>

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

int get_val_libudev(int param, struct udev_device *udevdev) {
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

void serialize(struct udev_device *udevdev) {
	struct ser dev;
	FILE *notify_file = fopen(NOTIFY_DIR "1", "wb");

	dev.allowed = false;
	dev.cl = get_val_libudev(bInterfaceClass, udevdev);
	dev.vId = get_val_libudev(idVendor, udevdev);
	dev.pId = get_val_libudev(idProduct, udevdev);
	dev.busnum = get_val_libudev(busnum, udevdev);
	dev.devpath = get_val_libudev(devpath, udevdev);

	int i= fwrite(&dev, sizeof(dev), 1, notify_file);
	printf("%i", i);
}

void chkerr(DBusError *error) {
	if(dbus_error_is_set(error)) {
		printf("error %s", error->message);
		dbus_error_free(error);
	}
}

void serialize_dbus(struct udev_device *udevdev) {
	const char *path = udev_device_get_syspath(udevdev);

	DBusError error;
	dbus_error_init(&error);
	DBusConnection *bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	chkerr(&error);

	//dbus_bus_request_name(bus, "test.signal.source", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);

	chkerr(&error);

	DBusMessage *msg = dbus_message_new_signal("/test/signal/Object", "test.signal.Type", "Test");
	if(!msg)
		printf("NULL");

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);
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
	if (dbus && authorize)
		serialize_dbus(udevdev);
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
	if (dbus && authorize)
		serialize_dbus(udevdev);
	udev_device_set_sysattr_value(udevdev, "interface_authorization_mask", v);
}

struct match_ret auth_match_interface_libudev(struct auth *a, struct udev_device *udevdev) {
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

		val = get_val_libudev(d->param, udevdev);

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

bool parse_udev_environment_vars(struct auth *a, size_t len) {
	struct udev *udev;
	struct udev_device *udevdev;

	udev = udev_new();
	udevdev = udev_device_new_from_environment(udev);
	const char *path = udev_device_get_devpath(udevdev);
	const char *type = udev_device_get_devtype(udevdev);

	if(!path || !type)
		return false;

	if (strcmp(type, "usb_interface") == 0) {
		fprintf(logfile, "path %s %s\n", path, type);
		const char* cl = udev_device_get_sysattr_value(udevdev, "bInterfaceClass");
		fprintf(logfile, "class %s\n", cl);
		struct udev_device *par = udev_device_get_parent(udevdev);
		device_interfaces_match_auth_udev(par, a, len);
	}

	return true;
}

struct auth_ret intffunct(struct udev_device *udevdev, struct auth *a, size_t len) {
	struct auth_ret ret;
	ret.match = false;
	ret.allowed = false;
	int i;
	for (i = 0; i < len; i++) {
		if (!a[i].cond && auth_match_interface_libudev(&a[i], udevdev).match_attrs) {

			bool ruleMatched = true;
			int j = 0;
			for (j = 0; j < len; j++) {
				struct match_ret r;
				if (a[j].cond) {
					r = auth_match_interface_libudev(&a[j], udevdev);
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

void allowhub(struct auth *a, size_t len) {
	int i = 0;
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *entry;

	udev = udev_new();

	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "usb");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	udev_list_entry_foreach(entry, devices)
	{
		const char *path = udev_list_entry_get_name(entry);
		struct udev_device *udevdev = udev_device_new_from_syspath(udev, path);
		const char *type = udev_device_get_devtype(udevdev);
		if (type && strcmp(type, "usb_device") == 0) {// filter out interfaces
			unsigned val = strtoul(udev_device_get_sysattr_value(udevdev, "bDeviceClass"), NULL, 16);
			authorize_device_libudev(udevdev, true, true);
		}
	}
}

void device_interfaces_match_auth_udev(struct udev_device *udevdev, struct auth *a, size_t len, bool emulate) {
	const char *type = udev_device_get_devtype(udevdev);
	const char *path = udev_device_get_syspath(udevdev);

	if(!path || !type)
		return;

	if (strcmp(type, "usb_device") != 0)
		return;

	fprintf(logfile, "DEV %s %s\n", path, type);
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *entry;

	udev = udev_new();

	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_parent(enumerate, udevdev);
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	unsigned val = strtoul(udev_device_get_sysattr_value(udevdev, "bDeviceClass"), NULL, 16);

	if(val == 9) // skip HUBs
		return;

	bool genMatch = true;
	bool genAllowed = true;
	udev_list_entry_foreach(entry, devices)
	{
		const char *path = udev_list_entry_get_name(entry);
		struct udev_device *udevdev = udev_device_new_from_syspath(udev, path);
		const char *type = udev_device_get_devtype(udevdev);

		if (type && strcmp(type, "usb_interface") == 0) {
			fprintf(logfile, "path %s %s\n", path, type);
			struct auth_ret r = intffunct(udevdev, a, len);

			if(val == 0) {
				if (!emulate && r.match) // if one rule has matched
					authorize_interface_libudev(udevdev, r.allowed, true);
			} else {
				genMatch &= r.match;
				genAllowed &= r.allowed;
			}
		}
	}
	if (!emulate && val != 0 && genMatch)  // if one rule has matched
		authorize_device_libudev(udevdev, genAllowed, true);
}

void devices_enumerate_libudev(struct auth *a, size_t len, bool emulate) {
	int i = 0;
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *entry;

	udev = udev_new();

	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "usb");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	udev_list_entry_foreach(entry, devices)
	{
		i++;
		fprintf(logfile, "%i\n", i);
		const char *path = udev_list_entry_get_name(entry);
		struct udev_device *udevdev = udev_device_new_from_syspath(udev, path);
		const char *type = udev_device_get_devtype(udevdev);
		if (type && strcmp(type, "usb_device") == 0) // filter out interfaces
			device_interfaces_match_auth_udev(udevdev, a, len, emulate);
	}
}

bool chk_args(const char *p1, const char *p2) {
	if(!p1 || !p2)
		return false;

	struct udev_device *udevdev = udev_device_new_from_syspath(udev, p2);

	if(!udevdev) {
		return false;
	}

	bool allw = strcmp(p1, "allow") == 0 ? true : false;
	authorize_interface_libudev(udevdev, allw, false);

	return true;
}

int main(int argc, char **argv) {
	udev = udev_new();
	logfile = fopen(LOG_FILE, "w");
	FILE *config = fopen(CONFIG_FILE, "r");

	usbauth_config_read();
	unsigned length;
	struct auth *auths;
	usbauth_config_get_auths(&auths, &length);

	if (argc <= 1) {
		devices_enumerate_libudev(auths, length, true);
		parse_udev_environment_vars(auths, length);
	} else if (strcmp(argv[1], "allow") == 0 || strcmp(argv[1], "deny") == 0) {
		chk_args(argv[1], argv[2]);
		printf("exit");
		return 0;
	} else if(strcmp(argv[1], "init") == 0) {
		allowhub(auths, length);
		devices_enumerate_libudev(auths, length, false);
	}

	unsigned i;
	for (i = 0; i < length; i++) {
		free(auths[i].attr_array);
	}
	free(auths);

	return 0;
}
