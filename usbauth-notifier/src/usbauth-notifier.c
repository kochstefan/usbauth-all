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
#include <libintl.h>
#include <locale.h>
#include <syslog.h>
#include <sys/wait.h>
#include <grp.h>

#include <usbauth/generic.h>
#include <usbauth/usbauth-configparser.h>

#include "usbauth-notifier.h"

#define NPRIV_PATH BINDIR "/usbauth-npriv"

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
		str = gettext("Per Interface");
		icon = "dialog-information";
		break;
	case 1:
		str = gettext("Audio");
		icon = "audio-card";
		break;
	case 2:
		str = gettext("Communication");
		icon = "modem";
		break;
	case 3:
		str = gettext("HID");
		icon = "input-keyboard";
		if (subcl == 1 && iprot == 1) {
			str = gettext("Keyboard");
			icon = "input-keyboard";
		}
		else if (subcl == 1 && iprot == 2) {
			str = gettext("Mouse");
			icon = "input-mouse";
		}
		break;
	case 5:
		str = gettext("Physical");
		icon = "dialog-information";
		break;
	case 6:
		str = gettext("Image");
		icon = "camera-photo";
		break;
	case 7:
		str = gettext("Printer");
		icon = "printer";
		break;
	case 8:
		str = gettext("Mass Storage");
		icon = "drive-removable-media-usb";
		break;
	case 9:
		str = gettext("Hub");
		icon = "dialog-information";
		break;
	case 0x0a:
		str = gettext("CDC data");
		icon = "modem";
		break;
	case 0x0b:
		str = gettext("Smart Card");
		icon = "secure-card";
		break;
	case 0x0d:
		str = gettext("Content Security");
		icon = "dialog-information";
		break;
	case 0x0e:
		str = gettext("Video");
		icon = "camera-video";
		break;
	case 0x0f:
		str = gettext("Personal Healthcare");
		icon = "dialog-information";
		break;
	case 0x10:
		str = gettext("AV");
		icon = "camera-video";
		break;
	case 0x11:
		str = gettext("Billboard");
		icon = "dialog-information";
		break;
	case 0xdc:
		str = gettext("Diagnostic Device");
		icon = "dialog-information";
		break;
	case 0xe0:
		str = gettext("Wireless Controller");
		icon = "network-wireless";
		break;
	case 0xef:
		str = gettext("Miscellaneous");
		icon = "dialog-information";
		break;
	case 0xfe:
		str = gettext("Application Specific");
		icon = "dialog-information";
		break;
	case 0xff:
		str = gettext("Vendor Specific");
		icon = "dialog-information";
		break;
	default:
		str = gettext("Unknown");
		icon = "dialog-information";
		break;
	}

	if (returnIcon)
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

	if (dbus_error_is_set(error)) {
		ret = false;
		syslog(LOG_ERR, "dbus_error: %s\n", error->message);
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

	while (work) { // receive dbus message
		dbus_connection_read_write(bus, 1);
		msg = dbus_connection_pop_message(bus);
		if (msg) { // get interface udev_device from message path and devnum
			if (dbus_message_is_signal(msg, "org.opensuse.usbauth.Message", "usbauth")) {
				dbus_message_get_args(msg, &error, DBUS_TYPE_INT32, &authorize_int, DBUS_TYPE_INT32, &devn_int, DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);
				if (no_error_check_dbus(&error)) {
					syslog(LOG_NOTICE, "successful received dbus message\n");
					udevdev = udev_device_new_from_syspath(udev, path);
					if (udevdev)
						ret = calloc(1, sizeof(struct Dev));

					if (ret) {
						*authorize = authorize_int;
						ret->udevdev = udevdev;
						ret->devnum = devn_int;
					}
				}
				dbus_message_unref(msg);
				msg = NULL;
				break;
			}
		}
		usleep(100000);
	}

	return ret;
}

void notification_action_callback(NotifyNotification *callback, char* action, gpointer user_data) {
	const char *authstr = strcmp(action, "act_allow") ? "deny" : "allow";
	struct Dev *dev = (struct Dev*) user_data;
	struct udev_device *udevdev = dev->udevdev;
	const char *syspath = NULL;
	int devn = -1;
	char sdevn[32];

	if (!dev)
		return;

	if (!udevdev) {
		free(dev);
		return;
	}

	devn = dev->devnum;
	syspath = udev_device_get_syspath(udevdev);
	snprintf(sdevn, sizeof(sdevn), "%x", devn);

	// /usr/bin/usbauth-npriv allow/deny DEVNUM PATH
	syslog(LOG_NOTICE, "execute %s %s %s %s\n", NPRIV_PATH, authstr, sdevn, syspath);
	if (fork())
		wait(NULL);
	else
		execl(NPRIV_PATH, NPRIV_PATH, authstr, sdevn, syspath, NULL);

	udev_device_unref(udevdev);
	free(dev);
	g_object_unref(G_OBJECT(callback));
}

void notification_create(const struct Dev* dev, bool authorize) {
	struct udev_device *udevdev = dev->udevdev;
	int32_t devn = dev->devnum;
	char titleMsg[48];
	char detailedMsg[128];
	unsigned cl = 255;
	unsigned subcl = 255;
	unsigned iprot = 0;
	unsigned vId = 0;
	unsigned pId = 0;
	const char *busn = 0;
	const char *devp = 0;
	const char *conf = 0;
	const char *intf = 0;
	const char *titleStr = "";
	struct Dev *dev_heap = NULL;
	NotifyNotification *notification = NULL;
	const char *type = udev_device_get_devtype(udevdev);

	dev_heap = calloc(1, sizeof(struct Dev));

	if (!type || !dev_heap) {
		syslog(LOG_ERR, "error at creating notification\n");
		return;
	}

	if (strcmp(type, "usb_interface") == 0) { // values from interface
		cl = usbauth_get_param_val(bInterfaceClass, udevdev);
		subcl = usbauth_get_param_val(bInterfaceSubClass, udevdev);
		iprot = usbauth_get_param_val(bInterfaceProtocol, udevdev);
		titleStr = gettext("New USB interface");
	}

	// values from interfaces parent
	vId = usbauth_get_param_val(idVendor, udevdev);
	pId = usbauth_get_param_val(idProduct, udevdev);
	busn = usbauth_get_param_valStr(busnum, udevdev);
	devp = usbauth_get_param_valStr(devpath, udevdev);
	conf = usbauth_get_param_valStr(bConfigurationValue, udevdev);
	intf = usbauth_get_param_valStr(bInterfaceNumber, udevdev);

	snprintf(titleMsg, sizeof(titleMsg), "%s (%s-%s:%s.%s)", titleStr, busn, devp, conf, intf);
	snprintf(detailedMsg, sizeof(detailedMsg), "<b>%s:</b> %s\n<b>%s:</b> %s\n<b>%s:</b> %04x:%04x\n<b>%s:</b> %s-%s:%s.%s", gettext("Default"), authorize ? gettext("Allow") : gettext("Deny"), gettext("Type"), get_info_string(cl, subcl, iprot, false), "ID", vId, pId, gettext("Name"), busn, devp, conf, intf);

	// pointer of dev heap gets back at callback so stack would be then out of context
	dev_heap->udevdev = udevdev;
	dev_heap->devnum = devn;
	notification = notify_notification_new(titleMsg, detailedMsg, get_info_string(cl, subcl, iprot, true));
	notify_notification_add_action(notification, "act_allow", gettext("Allow"), (NotifyActionCallback) notification_action_callback, dev_heap, NULL);
	notify_notification_add_action(notification, "act_deny", gettext("Deny"), (NotifyActionCallback) notification_action_callback, dev_heap, NULL);
	notify_notification_show(notification, NULL);

	syslog(LOG_INFO, "show notification for syspath %s\n", udev_device_get_syspath(udevdev));
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
	struct group *gr = NULL;
	GThread *thread = NULL;

	// set signal handler for SIGINT and SIGTERM, the handler sets work to false
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// connect to syslog
	openlog("usbauth-notifier", LOG_PERROR | LOG_PID, LOG_USER);

	// set GID to usbauth
	gr = getgrnam("usbauth");

	if (!gr || !gr->gr_gid) {
		syslog(LOG_ERR, "getgrnam error");
		return EXIT_FAILURE;
	}

	if (setgid(gr->gr_gid)) {
		syslog(LOG_ERR, "setgid error");
		return EXIT_FAILURE;
	}

	setlocale(LC_ALL, "");
	textdomain("usbauth-notifier");

	udev = udev_new();

	if (!udev) {
		syslog(LOG_ERR, "udev error\n");
		return EXIT_FAILURE;
	}

	if (!init_dbus()) {
		syslog(LOG_ERR, "dbus init error\n");
		return EXIT_FAILURE;
	}

	if (!notify_init("usbauth")) {
		syslog(LOG_ERR, "notify init error\n");
		return EXIT_FAILURE;
	}

	thread = g_thread_new("thread", notification_thread_loop, NULL); // thread for g_main_loop

	syslog(LOG_NOTICE, "usbauth-notifier started\n");

	// work until SIGINT or SIGTERM
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

	syslog(LOG_NOTICE, "usbauth-notifier stopped\n");

	// disconnect from syslog
	closelog();

	return EXIT_SUCCESS;
}
