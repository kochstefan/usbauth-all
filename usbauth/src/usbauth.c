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
#include <libusb-1.0/libusb.h>
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
	case idVendor:
		val = strtoul(udev_device_get_sysattr_value(parent, "idVendor"), NULL, 16);
		break;
	case idProduct:
		val = strtoul(udev_device_get_sysattr_value(parent, "idProduct"), NULL, 16);
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
	DBusConnection *bus = dbus_bus_get(DBUS_BUS_SESSION, &error);

	chkerr(&error);

	dbus_bus_request_name(bus, "test.signal.source", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);

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
	fprintf(logfile, "/sys%s/interface_authorized %u\n", path, authorize);
	if (dbus && authorize)
		serialize_dbus(udevdev);
	//udev_device_set_sysattr_value(udevdev, "interface_authorized", authorize);
}

void authorize_interface_libusb(struct libusb_device *dev, const struct libusb_interface_descriptor *intf, bool authorize) {
	struct libusb_config_descriptor *conf;
	libusb_get_active_config_descriptor(dev, &conf);

	uint8_t busNr = libusb_get_bus_number(dev);
	uint8_t portNr = libusb_get_port_number(dev);
	uint8_t confNr = conf->bConfigurationValue;
	uint8_t intfNr = intf->bInterfaceNumber;
	char d[16];
	sprintf(d, "%" SCNu8 "-%" SCNu8 ":%" SCNu8 ".%" SCNu8, busNr, portNr, confNr, intfNr);
	fprintf(logfile, "%s, USB Interface with class %02x\n", d, intf->bInterfaceClass);
	fprintf(logfile, "%s/%s/interface_authorized %u\n", SYSFS_USB, d, authorize);
}

unsigned file_get_line_count(FILE *file) {
	unsigned counter = 0;
	char *line = NULL;
	size_t len = 0;
	while(getline(&line, &len, file) > 0) {
		free(line);
		line = NULL;
		len = 0;
		counter++;
	}

	rewind(file);

	return counter;
}

int str_parse_param_val(const char* str, char **param, char **op, char **val) {
	int ret = 0;
	int slen = strlen(str);
	int len = 0;
	const char *send = str + slen;
	char *p1 = NULL;
	char *tmp1;

	char* ops[] = { "==", "!=", "<=", ">=", "<", ">" };

	int i = 0;
	for (i = 0; i < sizeof(ops) / sizeof(char*); i++) {
		tmp1 = strstr(str, ops[i]);
		if ((tmp1 && tmp1 < p1) || !p1) {
			p1 = tmp1;
			len = strlen(ops[i]);
			if (op) {
				*op = (char*) calloc(len, sizeof(char));
				strncpy(*op, ops[i], len);
				(*op)[len] = 0;
			}
		}
	}

	if (p1) {
		const char *ll = str;
		char *lr = p1, *rl = p1 + 1;

		while (rl < send && *ll == ' ')
			ll++;

		while (lr > str && *--lr == ' ')
			;
		while (rl < send && *++rl == ' ')
			;

		char *rr = rl;

		while (rr < send && (*rr != ' ' && *rr != '\n' && *rr != '\r'))
			rr++;

		rr--;

		len = lr - ll + 1;
		if (param) {
			*param = (char*) calloc(len + 1, sizeof(char));
			strncpy(*param, ll, len);
			(*param)[len] = 0;
		}

		len = rr - rl + 1;
		if (val) {
			*val = (char*) calloc(len + 1, sizeof(char));
			strncpy(*val, rl, len);
			(*val)[len] = 0;
		}

		ret = rr - str + 1;
	}

	return ret;
}

unsigned str_get_param_count(const char* str) {
	unsigned counter = 0;
	int sn = 0;
	int iter = 0;
	while ((sn = str_parse_param_val(str + iter, NULL, NULL, NULL)) > 0) {
		counter++;
		iter += sn;
	}

	return counter;
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

		if(count == d->param)
			val = a->count+1;

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

		if(count == d->param)
			val = a->count+1;

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

bool auth_match_interface_libusb(struct auth *a, struct libusb_device *dev, const struct libusb_interface_descriptor *intf) {
	bool ret = true;

	if(!a || !dev || !intf || !a->valid)
		return false;

	struct libusb_device_descriptor desc;
	struct libusb_config_descriptor *conf;
	libusb_get_device_descriptor(dev, &desc);
	libusb_get_active_config_descriptor(dev, &conf);

	int i;
	for (i = 0; i < a->attr_len; i++) {
		struct data *d = &a->attr_array[i];
		unsigned val = 0;

		switch(d->param) {
		case idVendor:
			val = desc.idVendor;
			break;
		case idProduct:
			val = desc.idProduct;
			break;
		case bConfigurationValue:
			val = conf->bConfigurationValue;
			break;
		case bInterfaceNumber:
			val = intf->bInterfaceNumber;
			break;
		case bInterfaceClass:
			val = intf->bInterfaceClass;
			break;
		default:
			break;
		}

		if (val != d->val)
			ret = false;
	}

	return ret;
}

bool parse_udev_environment_vars() {
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
	}

	return true;
}

void interfaces_enumerate_libudev(struct auth *a, size_t len) {
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *entry;
	struct udev_device *udevdev;

	udev = udev_new();

	udevdev = udev_device_new_from_environment(udev);

	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "usb");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	udev_list_entry_foreach(entry, devices)
	{
		const char *path;
		const char *type;

		path = udev_list_entry_get_name(entry);
		udevdev = udev_device_new_from_syspath(udev, path);
		type = udev_device_get_devtype(udevdev);

		if (strcmp(type, "usb_interface") == 0) {
			fprintf(logfile, "path %s %s\n", path, type);

			bool match = false;
			bool allowed = false;
			int i;
			for (i = 0; i < len; i++) {
				if (!a[i].cond && auth_match_interface_libudev(&a[i], udevdev).match_attrs) {

					bool ruleMatched = true;
					int j = 0;
					for (j = 0; j < len; j++) {
						struct match_ret r;
						if (a[j].cond) {
							r = auth_match_interface_libudev(&a[j], udevdev);
							if (r.match_attrs && r.match_cond && a[i].allowed) // count only if allowed for conditions
								a[j].count++;
							else if (r.match_attrs && !r.match_cond) // only if interface matched properties and condition complies
								ruleMatched = false;
						}
					}

					if (ruleMatched) { // if current/iterated rule matched
						a[i].count++;
						match |= true;
						allowed = a[i].allowed;
					}
				}
			}
			if (match) // if one rule has matched
				authorize_interface_libudev(udevdev, allowed, true);
		}

	}
}

void interfaces_enumerate_libusb(struct auth *a, size_t len) {
	struct libusb_device **devs;
	struct libusb_device *dev;

	libusb_init(NULL);
	libusb_get_device_list(NULL, &devs);

	int i = 0;
	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		struct libusb_config_descriptor *conf;
		libusb_get_device_descriptor(dev, &desc);
		libusb_get_active_config_descriptor(dev, &conf);
		fprintf(logfile, "USB Device %04x:%04x with class %02x\n", desc.idVendor, desc.idProduct, desc.bDeviceClass);
		int i;
		for (i = 0; i < conf->bNumInterfaces; i++) {
			const struct libusb_interface_descriptor *intf = conf->interface[i].altsetting;
			bool match = false;
			bool allowed = false;
			int j;
			for (j = 0; j < len; j++) {
				if (auth_match_interface_libusb(&a[j], dev, intf)) {
					match |= true;
					allowed = a[j].allowed;
				}
			}
			if (match)
				authorize_interface_libusb(dev, intf, allowed);
		}
		libusb_free_config_descriptor(conf);
	}

	libusb_free_device_list(devs, 1);
	libusb_exit(NULL);
}

bool substr_parse_params(const char *substr, uint8_t *arr_len, struct data **arr) {
	bool valid = true;
	int cnt = 0;
	int length = 0;

	bool param = false;
	char *paramStr = NULL;
	char *opStr = NULL;
	char *valStr = NULL;

	if(!substr || !arr_len || !arr)
		return false;

	*arr_len = str_get_param_count(substr);
	if (*arr_len)
		*arr = (struct data*) calloc(*arr_len, sizeof(struct data));

	while ((length = str_parse_param_val(substr, &paramStr, &opStr, &valStr))
			> 0) {
		param = true;
		valid &= usbauth_config_param_val_str_to_data(&(*arr)[cnt], paramStr, opStr, valStr);
		free(paramStr);
		free(opStr);
		free(valStr);
		cnt++;
		substr += length;
	}

	if (!param)
		valid = false;

	return valid;
}

bool rule_parse_params(const char *str, struct auth* a) {
	bool valid = false;

	char *denyStr = "deny";
	char *allowStr = "allow";
	char *condStr = "condition";
	char *allStr = "all";
	char *caseStr = "case";
	bool cond = false;
	bool all = false;
	char *substr = NULL;

	char *attr_str = NULL;
	char *cond_str = NULL;

	if(!str || !a)
		return false;

	if ((substr = strstr(str, denyStr)) != 0) {
		substr += strlen(denyStr);
		attr_str = substr;
		a->allowed = false;
	} else if ((substr = strstr(str, allowStr)) != 0) {
		substr += strlen(allowStr);
		attr_str = substr;
		a->allowed = true;
	} else if ((substr = strstr(str, condStr)) != 0) {
		substr += strlen(condStr);
		a->cond = true;
		a->allowed = false;

		char *substr2 = strstr(substr, caseStr);
		int attr_str_len = substr2 - substr - 1;
		substr2 += strlen(caseStr);
		int cond_str_len = strlen(substr2);

		cond_str = (char*) calloc(attr_str_len + 1, sizeof(char));
		attr_str = (char*) calloc(cond_str_len + 1, sizeof(char));
		strncpy(cond_str, substr, attr_str_len);
		cond_str[attr_str_len] = 0;
		strncpy(attr_str, substr2, cond_str_len);
		attr_str[cond_str_len] = 0;
		cond = true;
	}

	if (substr && (substr = strstr(substr, allStr)) != 0) {
		substr += strlen(allStr);
		attr_str = substr;
		all = true;
	}

	if (all)
		valid = true;

	a->valid = substr_parse_params(attr_str, &a->attr_len, &a->attr_array);
	if (cond)
		substr_parse_params(cond_str, &a->cond_len, &a->cond_array);

	return valid;
}

bool chk_args(const char *p1, const char *p2) {
	if(!p1 || !p2)
		return false;

	struct udev_device *udevdev = udev_device_new_from_syspath(udev, p1);

	if(!udevdev) {
		printf("hallo");
		return false;
	}

	bool allw = strcmp(p2, "allow") == 0 ? true : false;
	authorize_interface_libudev(udevdev, allw, false);

	return true;
}

int main(int argc, char **argv) {
	udev = udev_new();
	logfile = fopen(LOG_FILE, "w");
	FILE *config = fopen(CONFIG_FILE, "r");

	if(argc > 2) {
		chk_args(argv[1], argv[2]);
		printf("exit");
		return 0;
	}

	char *str = NULL;
	size_t line_len = 0;

	size_t line_cnt = file_get_line_count(config);
	struct auth *a = NULL;
	if (line_cnt)
		a = (struct auth*) calloc(line_cnt, sizeof(struct auth));

	int i;
	for (i = 0; i < line_cnt; i++) {
		getline(&str, &line_len, config);
		rule_parse_params(str, &a[i]);
	}

	interfaces_enumerate_libudev(a, line_cnt);
//	interfaces_enumerate_libusb(a, line_cnt);

	parse_udev_environment_vars();

	for (i = 0; i < line_cnt; i++) {
		free(a[i].attr_array);
	}
	free(a);

	usbauth_config_read();
	unsigned length;
	struct auth *auths;
	usbauth_config_get_auths(&auths, &length);
	interfaces_enumerate_libudev(auths, length);


	return 0;
}
