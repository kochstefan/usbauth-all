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
 * Description : notifier for USB Firewall to use with desktop environments
 */

#ifndef USBAUTH_NOTIFIER_H_
#define USBAUTH_NOTIFIER_H_

#include <stdint.h>
#include <stdbool.h>
#include <libudev.h>
#include <libnotify/notify.h>

struct Dev {
	struct udev_device *udevdev;
	int32_t devnum;
};

/**
 * get string representation of device class or icon name string
 *
 * @cl: interface class number
 * @subcl: interface sub class number
 * @iprot: interface protocol (for differ keyboard and mouse)
 * @returnIcon: false that device class string should returned, true if icon name string should returned
 *
 * Return: device class string (returnIcon == false) or icon name string (returnIcon == true)
 */
const char* get_info_string(unsigned cl, unsigned subcl, unsigned iprot, bool returnIcon);

/**
 * initialize dbus related things
 */
bool init_dbus();

/**
 * deinitialize dbus related things
 */
void deinit_dbus();

/**
 * check dbus errors
 *
 * @error: dbus error structure
 *
 * Return: true if no error, false if error
 */
bool no_error_check_dbus(DBusError *error);

/**
 * receive dbus message from USB firewall
 * will called when user clicked on allow or deny in notify pop up
 *
 * @authorize (output param): true if interface was authorized by the USB firewall, false if interface was not authorized by the USB firewall
 *
 * Return: Dev structure with udev_device from type "usb_interface" and devnum from sysfs tree
 */
struct Dev* receive_dbus(bool *authorize);

/**
 * callback handler from after action from notification
 * will called when user clicked on allow or deny in notify pop up
 *
 * @callback: pointer to notify structure
 * @action: to differ from allow and deny actions
 * @user_data: pointer that is given to the notification message, and is returned back on callback; used to relate the interface from notification (struct Dev*)
 */
void notification_action_callback(NotifyNotification *callback, char* action, gpointer user_data);

/**
 * create a notification that will showed as pop up
 * will called when user clicked on allow or deny in notify pop up
 *
 * @dev: Dev structure with udev_device from type "usb_interface" and devnum from sysfs tree
 * @authorize: true if interface was authorized by the USB firewall, false if interface was not authorized by the USB firewall
 */
void notification_create(const struct Dev* intf, bool authorize);

/**
 * Thread for g_main_loop needed for action_callback handler
 */
void* notification_thread_loop(void *arg);

/**
 * signal handler that catches SIGINT and SIGTERM to exit program
 *
 * @int: signal type
 */
void signal_handler(int sig);

#endif /* USBAUTH_NOTIFIER_H_ */
