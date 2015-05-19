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
 * Description : Notifier for USB Firewall to use with desktop environments
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libudev.h>
#include <dbus/dbus.h>
#include <pthread.h>
#include <signal.h>
#include <usbauth/generic.h>
#include <usbauth/usbauth_configparser.h>

#include "usbauth_notifier.h"

#define NPRIV_PATH "/usr/bin/usbauth_npriv"

static bool work = true;
static struct udev *udev = NULL;
static DBusConnection *bus = NULL;
static GMainLoop *loop = NULL;

char *classArray[] = { "PER_INTERFACE", "AUDIO", "COMM", "HID", "", "PHYSICAL", "STILL_IMAGE", "PRINTER", "MASS_STORAGE", "HUB" };

const char* get_info_string(unsigned cl, unsigned subcl, unsigned iprot, bool returnIcon) {
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

bool init_dbus() {
	bool ret = true;
	DBusError error;

	dbus_error_init(&error);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	ret &= no_error_check_dbus(&error);

	dbus_bus_request_name(bus, "org.opensuse.usbauth.notifier", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);
	ret &= no_error_check_dbus(&error);

	dbus_bus_add_match(bus, "type='signal',interface='org.opensuse.usbauth.Message'", &error);
	ret &= no_error_check_dbus(&error);

	return ret;
}

void deinit_dbus() {
	dbus_connection_unref(bus);
	bus=NULL;
}

bool no_error_check_dbus(DBusError *error) {
	bool ret = true;

	if(dbus_error_is_set(error)) {
		ret = false;
		printf("error %s", error->message);
		dbus_error_free(error);
	}

	return ret;
}

struct Dev* receive_dbus(bool *authorize) {
	struct Dev *ret = NULL;
	struct udev_device *udevdev = NULL;
	int32_t authorize_int = 0;
	int32_t devn_int = 0;
	const char *path = NULL;
	DBusError error;
	DBusMessage *msg = NULL;
	dbus_error_init(&error);
	dbus_connection_flush(bus);
	ret = calloc(1, sizeof(struct Dev));

	while (work) { // receive dbus message
		dbus_connection_read_write(bus, 1);
		msg = dbus_connection_pop_message(bus);
		if (msg) { // get interface udev_device from message path and devnum
			if (dbus_message_is_signal(msg, "org.opensuse.usbauth.Message", "usbauth")) {
				dbus_message_get_args(msg, &error, DBUS_TYPE_INT32, &authorize_int, DBUS_TYPE_INT32, &devn_int, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);
				no_error_check_dbus(&error);
				udevdev = udev_device_new_from_syspath(udev, path);
				dbus_message_unref(msg);
				msg = NULL;
				printf("test\n");
				break;
			}
			else
				printf("else\n");
		}
		usleep(100000);
	}

	if (ret) {
		*authorize = authorize_int;
		ret->udevdev = udevdev;
		ret->devnum = devn_int;
	}

	return ret;
}

void notification_action_callback(NotifyNotification *callback, char* action, gpointer user_data) {
	char cmd[256];
	const char *authstr = strcmp(action, "act_allow") ? "deny" : "allow";
	struct Dev *dev = (struct Dev*) user_data;
	struct udev_device *udevdev = dev->udevdev;
	int devn = -1;

	if(!dev)
		return;

	if(!udevdev) {
		free(dev);
		return;
	}

	devn = dev->devnum;

	printf("usbauth notifyid %u action %s\n", 1, authstr);

	snprintf(cmd, sizeof(cmd), "%s %s %x %s", NPRIV_PATH, authstr, devn, udev_device_get_syspath(udevdev));
	printf("%s\n", cmd);
	system(cmd);
	udev_device_unref(udevdev);
	free(dev);
	g_object_unref(G_OBJECT(callback));
}

void notification_create(const struct Dev* dev, bool authorize) {
	struct udev_device *udevdev = dev->udevdev;
	int32_t devn = dev->devnum;
	char titleMsg[32];
	char detailedMsg[128];
	unsigned cl = 255;
	unsigned subcl = 255;
	unsigned iprot = 0;
	unsigned vId = 0;
	unsigned pId = 0;
	unsigned busn = 0;
	unsigned devp = 0;
	unsigned conf = 0;
	unsigned intf = 0;
	const char *titleStr = "";
	struct Dev *dev_heap = NULL;
	NotifyNotification *notification = NULL;
	const char *type = udev_device_get_devtype(udevdev);
	dev_heap = calloc(1, sizeof(struct Dev));

	if(!type || !dev_heap)
		return;

	if (strcmp(type, "usb_interface") == 0) { // values from interface
		cl = usbauth_get_param_val(bInterfaceClass, udevdev);
		subcl = usbauth_get_param_val(bInterfaceSubClass, udevdev);
		iprot = usbauth_get_param_val(bInterfaceProtocol, udevdev);
		titleStr = "New %s interface";
	}

	// values from interfaces parent
	vId = usbauth_get_param_val(idVendor, udevdev);
	pId = usbauth_get_param_val(idProduct, udevdev);
	busn = usbauth_get_param_val(busnum, udevdev);
	devp = usbauth_get_param_val(devpath, udevdev);
	conf = usbauth_get_param_val(bConfigurationValue, udevdev);
	intf = usbauth_get_param_val(bInterfaceNumber, udevdev);

	snprintf(titleMsg, sizeof(titleMsg), titleStr, get_info_string(cl, subcl, iprot, false));
	snprintf(detailedMsg, sizeof(detailedMsg), "Default rule: %s\nID %x:%x\nbusnum %u, devpath %u\nconfig %u, intf %u", authorize ? "ALLOW" : "DENY", vId, pId, busn, devp, conf, intf);

	// pointer of dev heap gets back at callback so stack would be then out of context
	dev_heap->udevdev = udevdev;
	dev_heap->devnum = devn;
	notification = notify_notification_new(titleMsg, detailedMsg, get_info_string(cl, subcl, iprot, true));
	notify_notification_add_action(notification, "act_allow", "allow", (NotifyActionCallback) notification_action_callback, dev_heap, NULL);
	notify_notification_add_action(notification, "act_deny", "deny", (NotifyActionCallback) notification_action_callback, dev_heap, NULL);
	notify_notification_show(notification, NULL);
}

void* notification_thread_loop(void *arg) {
	loop = g_main_loop_new(NULL, FALSE);
	if (loop)
		g_main_loop_run(loop);

	g_thread_exit(NULL);
	return NULL;
}

void signal_handler(int sig) {
	work = false;
}

int main(int argc, char **argv) {
	GThread *thread = NULL;

	// set signal handler for SIGINT and SIGTERM, the handler sets work to false
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	udev = udev_new();

	if(!udev)
		return EXIT_FAILURE;

	if(!init_dbus())
		return EXIT_FAILURE;

	if(!notify_init("usbauth"))
		return EXIT_FAILURE;

	thread = g_thread_new("thread", notification_thread_loop, NULL); // thread for g_main_loop

	// work until SIGING or SIGTERM
	while(work) {
		bool authorize = false;
		struct Dev *dev = receive_dbus(&authorize); // receive dbus message from USB firewall

		if (dev) {
			notification_create(dev, authorize); // create notification according interface device from dbus message
			free(dev);
		}
	}

	g_main_loop_quit(loop); // exit g_main_loop
	g_thread_join(thread); // exit g_main_loop thread

	notify_uninit();

	deinit_dbus();

	udev_unref(udev);
	udev = NULL;

	return EXIT_SUCCESS;
}
