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

#ifndef USBAUTH_H_
#define USBAUTH_H_

#include <usbauth/generic.h>

#include <libudev.h>
#include <dbus/dbus.h>


/**
 * checks string constraint
 *
 * lval op rval
 * examlpe: "01g" == "01g" : return true
 *
 * @lvalStr: left value
 * @op: operator
 * @rvalStr: right value
 * @parent: if not NULL parent will matched, too
 *
 * return: true if constraint is matched
 */
bool match_valsStr(const char *lval, enum Operator op, const char *rval);

/**
 * checks integer constraint
 *
 * lval op rval
 * examlpe: 01 <= 02 : return true
 *
 * @lval: left value
 * @op: operator
 * @rval: right value
 * @parent: if not NULL parent will matched, too
 *
 * return: true if constraint is matched
 */
bool match_valsInt(int lval, enum Operator op, int rval);

/**
 * checks constraint
 * tries first to convert strings to integer, if failed a string compare is processed
 *
 * lval op rval
 * examlpe: 01 <= 02 : return true
 *
 * @lvalStr: left value
 * @op: operator
 * @rvalStr: right value
 * @parent: if not NULL parent will matched, too
 *
 * return: true if constraint is matched
 */
bool match_vals(const char *lvalStr, enum Operator op, const char *rvalStr);

/**
 * checks if constraint from rule and data matches for an interface
 *
 * @rule: rule to check including left value (lval)
 * @d: data structure with param and right value (rval)
 * @interface: udev_device from type "usb_interface"
 *
 * return: true if constraint is matched
 */
bool match_vals_interface(struct Auth *rule, struct Data *d, struct udev_device *interface);

/**
 * checks if constraint from rule and data matches for at minimum one device's interface
 *
 * @rule: rule to check including left value (lval)
 * @d: data structure with param and right value (rval)
 * @device: udev_device from type "usb_device"
 *
 * return: true if constraint is matched for minimum one device's interface
 */
bool match_vals_device(struct Auth *rule, struct Data *d, struct udev_device *device);

/* check if a device is already processed
 *
 * @dev: udev device
 *
 * Returns: true if device's mask was changed (so processed), otherwise false
 */
bool device_processed(struct udev_device* dev);

/**
 * check dbus errors
 *
 * @error: dbus error structure
 *
 * Return: true if error, false if no error
 */
bool error_check_dbus(DBusError *error);

/**
 * send dbus message to notifier service for interface
 *
 * @udevdev: udev_device with type "usb_interface"
 * @authorize: true for allow, false for deny
 *
 */
void send_dbus(struct udev_device *udevdev, int32_t authorize, int32_t devnum);

/**
 * allow or deny a device per bitmask
 *
 * the bitmask is used for marking interfaces
 * example: 1 for interface 1
 * 3 for interface 1 and 2
 *
 * @udevdev: udev_device with type "usb_device"
 * @mask: bitmask
 * @dbus: if true, notifications should be enabled
 *
 */
void authorize_mask(struct udev_device *udevdev, uint32_t mask, bool dbus);

/**
 * checks if there is at least one rule from type ALLOW or DENY
 *
 * example: false if there are only comments
 *
 * @array: auth rules
 * @array_length: auth rules length
 *
 * Return: true if there is at least one rule from type ALLOW or DENY
 */
bool isRule(struct Auth *array, unsigned array_length);

/**
 * checks if an auth rule matches an USB interface
 * @rule: auth rule
 * @interface: udev_device with type "usb_interface"
 *
 * Return: match_attrs is true if the interface matches all (case) attributes
 * match_cond is true if the interface matches all condition attributes or has no such condition attributes
 */
struct match_ret match_auth_interface(struct Auth *a, struct udev_device *udevdev);

/**
 * checks if an USB interface matches to all auth rules
 * if matches the interface will be allowed for use
 *
 * note: a condition that matches with the interface must apply,
 * otherwise the interface will denied
 *
 * @array: auth rules
 * @array_length: auth rules length
 * @interface: udev_device with type "usb_interface"
 *
 * Return: match is true if the interface matches with all rules
 * allowed: true if the interface should be allowed, otherwise false
 */
struct auth_ret match_auths_interface(struct Auth *array, size_t array_length, struct udev_device *udevdev);

/**
 * checks if at minimum one auth rule matches to an USB device
 * and allows or denies the device then
 *
 * note: all interfaces of the USB devices are checked
 * if one interface doesn't match with any rule it will skipped
 *
 * @array: auth rules
 * @array_length: auth rules length
 * @usb_device: udev_device with type "usb_device"
 */
void match_auths_device_interfaces(struct Auth *array, size_t array_length, struct udev_device *usb_device);

/**
 * perform rules on all USB devices
 *
 * @rule_array: auth rules
 * @array_length: auth rules length
 * @add: true if udev-add mode, false if udev-remove mode
 */
void perform_rules_devices(struct Auth *array, size_t array_length, bool add);

/**
 * perform rules on udev environment
 *
 * @rule_array: auth rules
 * @array_length: auth rules length
 * @add: true if udev-add mode, false if udev-remove mode
 */
void perform_udev_env(struct Auth *auths, size_t length, bool add);

/**
 * perform notifier command
 *
 * @action: allow or deny
 * @devnum: devnum of interface
 * @path: path to interface
 *
 */
void perform_notifier(const char* action, const char* devnum, const char* path);

#endif /* USBAUTH_H_ */
