/*
 ============================================================================
 Name        : usbauth_notifier.c
 Author      : Stefan Koch
 Version     : alpha
 Copyright   : 2015 SUSE Linux GmbH
 Description : Notifier for USB authentication with udev
 ============================================================================
 */

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnotify/notify.h>
#include <string.h>
#include <libudev.h>
#include <dbus/dbus.h>
#include <pthread.h>
#include "../../usbauth_configparser/src/generic.h"

static GMainLoop *loop = NULL;
static struct udev *udev = NULL;
static DBusConnection *bus = NULL;

struct Dev {
	struct udev_device *dev;
	int32_t devn;
};

const char* parameter_strings[] = {"INVALID", "busnum", "devpath", "idVendor", "idProduct", "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol", "bConfigurationValue", "bInterfaceNumber", "bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol", "devnum", "serial", "intfcount", "devcount"};
const char* operator_strings[] = {"==", "!=", "<=", ">=", "<", ">"};

const char* enum_to_str(int val, const char** string_array, int array_len) {
	const char* ret = string_array[0];

	if (val < array_len)
		ret = string_array[val];

	return ret;
}

const char* param_to_str(enum Parameter param) {
	return enum_to_str(param, parameter_strings, sizeof(parameter_strings));
}

unsigned get_param_val(enum Parameter param, struct udev_device *udevdev) {
	unsigned val = 0;
	struct udev_device *parent = NULL;
	const char* paramStr = param_to_str(param);
	const char* valStr = NULL;

	if(udevdev)
		valStr = udev_device_get_sysattr_value(udevdev, paramStr);

	if(!valStr) {
		parent = udev_device_get_parent(udevdev);
		valStr = udev_device_get_sysattr_value(parent, paramStr);
	}

	if(valStr)
		val = strtoul(valStr, NULL, 16);

	return val;
}

void serialize_dbus_error_check(DBusError *error) {
	if(dbus_error_is_set(error)) {
		printf("error %s", error->message);
		dbus_error_free(error);
	}
}

void dbus_init() {
	DBusError error;

	dbus_error_init(&error);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	serialize_dbus_error_check(&error);

	dbus_bus_request_name(bus, "test.signal.target", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);
	serialize_dbus_error_check(&error);

	dbus_bus_add_match(bus, "type='signal',interface='test.signal.Type'", &error);
	serialize_dbus_error_check(&error);
}

void dbus_deinit() {
	dbus_connection_unref(bus);
	bus=NULL;
}

struct udev_device *deserialize_dbus(bool *authorize, int32_t *devn) {
	struct udev_device *ret = NULL;
	const char *path = NULL;
	DBusError error;
	DBusMessage *msg = NULL;
	dbus_error_init(&error);
	dbus_connection_flush(bus);

	while (true) {
		dbus_connection_read_write(bus, 1);
		msg = dbus_connection_pop_message(bus);
		if (msg) {
			if (dbus_message_is_signal(msg, "test.signal.Type", "Test")) {
				dbus_message_get_args(msg, &error, DBUS_TYPE_BOOLEAN, authorize, DBUS_TYPE_INT32, devn, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);
				serialize_dbus_error_check(&error);
				ret = udev_device_new_from_syspath(udev, path);
				dbus_message_unref(msg);
				msg = NULL;
				printf("test\n");
				break;
			}
			else
				printf("else\n");
		}
		sleep(1);
	}

	return ret;
}

char *classArray[] = { "PER_INTERFACE", "AUDIO", "COMM", "HID", "", "PHYSICAL", "STILL_IMAGE", "PRINTER", "MASS_STORAGE", "HUB" };

const char* getClassString(unsigned cl, unsigned subcl, unsigned iprot, bool returnIcon) {
	const char *ret = "";
	const char *str = "";
	const char *icon = "";

	switch(cl) {
	case 0:
		str = "PER_INTERFACE";
		icon = "dialog-information";
		break;
	case 1:
		str = "AUDIO";
		icon = "audio-card";
		break;
	case 2:
		str = "COMM";
		icon = "modem";
		break;
	case 3:
		str = "HID";
		icon = "input-keyboard";
		if (subcl == 1 && iprot == 1) {
			str = "KEYBOARD";
			icon = "input-keyboard";
		}
		else if (subcl == 1 && iprot == 2) {
			str = "MOUSE";
			icon = "input-mouse";
		}
		break;
	case 5:
		str = "PHYSICAL";
		icon = "dialog-information";
		break;
	case 6:
		str = "STILL_IMAGE";
		icon = "camera-photo";
		break;
	case 7:
		str = "PRINTER";
		icon = "printer";
		break;
	case 8:
		str = "MASS_STORAGE";
		icon = "drive-removable-media-usb";
		break;
	case 9:
		str = "HUB";
		icon = "dialog-information";
		break;
	default:
		str = "UNKNOWN";
		icon = "dialog-information";
		break;
	}

	if(returnIcon)
		ret = icon;
	else
		ret = str;

	return ret;
}

void action_callback(NotifyNotification *callback, char* action, gpointer user_data) {
	char cmd[256];
	const char *authstr = strcmp(action, "act_allow") ? "deny" : "allow";
	struct Dev *dev = (struct Dev*) user_data;
	struct udev_device *udevdev = dev->dev;
	int devn = dev->devn;

	printf("usbauth notifyid %u action %s\n", 1, authstr);

	snprintf(cmd, sizeof(cmd), "pkexec usbauth %s %x %s", authstr, devn, udev_device_get_syspath(udevdev));
	printf("%s\n", cmd);
	system(cmd);
	g_object_unref(G_OBJECT(callback));
}

void create_notification(struct udev_device* udevdev, int32_t devn, bool authorize) {
	char titleMsg[32];
	char detailedMsg[128];

	if(!udevdev)
		return NULL;

	const char *type = udev_device_get_devtype(udevdev);

	if(!type)
		return NULL;

	unsigned cl = 255;
	unsigned subcl = 255;
	unsigned iprot = 0;
	uint16_t vId = 0;
	uint16_t pId = 0;
	uint16_t busn = 0;
	uint16_t devp = 0;
	char *titleStr = "";

	if (strcmp(type, "usb_interface") == 0) {
		cl = get_param_val(bInterfaceClass, udevdev);
		subcl = get_param_val(bInterfaceSubClass, udevdev);
		iprot = get_param_val(bInterfaceProtocol, udevdev);
		vId = get_param_val(idVendor, udevdev);
		pId = get_param_val(idProduct, udevdev);
		busn = get_param_val(busnum, udevdev);
		devp = get_param_val(devpath, udevdev);
		titleStr = "New %s interface";
	} else if (strcmp(type, "usb_device") == 0) {
		cl = get_param_val(bDeviceClass, udevdev);
		subcl = get_param_val(bDeviceSubClass, udevdev);
		iprot = get_param_val(bDeviceProtocol, udevdev);
		vId = get_param_val(idVendor, udevdev);
		pId = get_param_val(idProduct, udevdev);
		busn = get_param_val(busnum, udevdev);
		devp = get_param_val(devpath, udevdev);
		titleStr = "New %s device";
	}

	snprintf(titleMsg, sizeof(titleMsg), titleStr, getClassString(cl, subcl, iprot, false));
	snprintf(detailedMsg, sizeof(detailedMsg), "Default rule: %s\nID %" SCNx16 ":%" SCNx16 "\nbusnum %" SCNu8 ", devpath %" SCNu8, authorize ? "ALLOW" : "DENY", vId, pId, busn, devp);

	struct Dev *dev = calloc(1, sizeof(struct Dev));
	dev->dev = udevdev;
	dev->devn = devn;
	NotifyNotification *notification = notify_notification_new(titleMsg, detailedMsg, getClassString(cl, subcl, iprot, true));
	notify_notification_add_action(notification, "act_allow", "allow", (NotifyActionCallback) action_callback, dev, NULL);
	notify_notification_add_action(notification, "act_deny", "deny", (NotifyActionCallback) action_callback, dev, NULL);
	notify_notification_show(notification, NULL);
}

void *thread_loop(void *arg) {
	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	return NULL;
}

int main(int argc, char **argv) {
	udev = udev_new();
	dbus_init();
	notify_init("usbauth");

	pthread_t thread;
	int res = pthread_create(&thread, NULL, thread_loop, NULL);

	while(1) {
		printf("hallo");
		bool authorize = false;
		int32_t devn = -1;
		struct udev_device *udevdev = deserialize_dbus(&authorize, &devn);

		if (udevdev) {
			create_notification(udevdev, devn, authorize);
		}

		sleep(1);
	}

	g_main_loop_quit(loop);
	pthread_join(&thread, NULL);

	notify_uninit();

	dbus_deinit();

	udev_unref(udev);
	udev = NULL;

	return EXIT_SUCCESS;
}
