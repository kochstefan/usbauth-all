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

#define NOTIFY_DIR "/home/stefan/notify/"
struct ser {
	bool allowed;
	uint8_t cl;
	uint16_t vId;
	uint16_t pId;
	uint8_t busnum;
	uint8_t devpath;
};
enum parameters {
	INVALID, busnum, devpath, idVendor, idProduct, bDeviceClass, bDeviceSubClass, bConfigurationValue, bInterfaceNumber, bInterfaceClass, bInterfaceSubClass, count
};

static GMainLoop *loop;

static struct udev *udev = NULL;
static struct udev_device *udevdev = NULL;
static DBusConnection *bus = NULL;

void deserialize(struct ser *dev) {
	FILE *notify_file = fopen(NOTIFY_DIR "1", "rb");

	int i= fread(dev, sizeof(dev), 1, notify_file);
	printf("%i", i);
}

void chkerr(DBusError *error) {
	if(dbus_error_is_set(error)) {
		printf("error %s", error->message);
		dbus_error_free(error);
	}
}

void dbus_init() {
	DBusError error;

	dbus_error_init(&error);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	chkerr(&error);

	dbus_bus_request_name(bus, "test.signal.target", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);
	chkerr(&error);

	dbus_bus_add_match(bus, "type='signal',interface='test.signal.Type'", &error);
	chkerr(&error);
}

void dbus_deinit() {
	dbus_connection_unref(bus);
	bus=NULL;
}

struct udev_device *deserialize_dbus() {
	struct udev_device *ret;
	const char *path = NULL;
	DBusError error;
	DBusMessage *msg = NULL;
	dbus_error_init(&error);
	dbus_connection_flush(bus);

	while (true) {
		dbus_connection_read_write(bus, 0);
		msg = dbus_connection_pop_message(bus);
		if (msg) {
			if (dbus_message_is_signal(msg, "test.signal.Type", "Test")) {
				dbus_message_get_args(msg, &error, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);
				chkerr(&error);
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

const char* getClassString(unsigned cl, bool returnIcon) {
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

void actioncb(NotifyNotification *callback, char* action, gpointer user_data) {
	char cmd[256];
	const char *authstr = strcmp(action, "act_allow") ? "deny" : "allow";

	printf("usbauth notifyid %u action %s\n", 1, authstr);

	snprintf(cmd, sizeof(cmd), "pkexec usbauth %s %s", authstr, udev_device_get_syspath(udevdev));
	printf(cmd);
	system(cmd);

	g_main_loop_quit(loop);
}

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
	case bDeviceClass:
		val = strtoul(udev_device_get_sysattr_value(udevdev, "bDeviceClass"), NULL, 16);
		break;
	default:
		break;
	}

	return val;
}

int main(void) {
	char titleMsg[32];
	char detailedMsg[128];
	udev = udev_new();
	dbus_init();

	while(1) {
		udevdev = deserialize_dbus();
		const char *type = udev_device_get_devtype(udevdev);

		unsigned cl = 255;
		if (strcmp(type, "usb_interface") == 0) {
			cl = get_val_libudev(bInterfaceClass, udevdev);
		} else if (strcmp(type, "usb_device") == 0) {
			cl = get_val_libudev(bDeviceClass, udevdev);
		}

		uint16_t vId = get_val_libudev(idVendor, udevdev);
		uint16_t pId = get_val_libudev(idProduct, udevdev);
		uint16_t busn = get_val_libudev(busnum, udevdev);
		uint16_t devp = get_val_libudev(devpath, udevdev);
		bool allowed = false;

		snprintf(titleMsg, sizeof(titleMsg), "New %s device", getClassString(cl, false));
		snprintf(detailedMsg, sizeof(detailedMsg), "Default rule: %s\nID %" SCNx16 ":%" SCNx16 "\nbusnum %" SCNu8 ", devpath %" SCNu8, allowed ? "ALLOW" : "DENY", vId, pId, busn, devp);

		loop = g_main_loop_new(NULL, FALSE);
		notify_init("usbauth");
		NotifyNotification *notification = notify_notification_new(titleMsg, detailedMsg, getClassString(cl, true));
		notify_notification_add_action(notification, "act_allow", "allow", (NotifyActionCallback) actioncb, NULL, NULL);
		notify_notification_add_action(notification, "act_deny", "deny", (NotifyActionCallback) actioncb, NULL, NULL);
		notify_notification_show(notification, NULL);
		g_main_loop_run(loop);
		g_object_unref(G_OBJECT(notification));
		notify_uninit();

		sleep(1);
	}

	dbus_deinit();

	return EXIT_SUCCESS;
}
