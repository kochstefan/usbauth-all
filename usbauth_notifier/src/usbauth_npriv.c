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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USBAUTH_PATH "/usr/sbin/usbauth"
#define NOTIFIER_PATH "/usr/bin/usbauth_notifier"

/*
 * This programm will installed with SUID bit setted
 * The usbauth_notifier will call it to call usbauth firewall
 * with superuser rights
 *
 * Example call:
 * usbauth_npriv allow/deny DEVNUM PATH
 *
 * This program calls then:
 * /usr/sbin/usbauth allow/deny DEVNUM PATH
 *
 * but only if the caller is
 * /usr/bin/usbauth_notifier
 *
 */
int main(int argc, char **argv) {
	char str_proc[128];
	char str_path[128];
	unsigned len_str_path;

	unsigned ppid = getppid();
	snprintf(str_proc, 128, "/proc/%u/exe", ppid);

	len_str_path = readlink(str_proc, str_path, 128);
	str_path[len_str_path] = 0;

	// three args are used
	// the caller must be the notifier
	if(argc >= 4  && strncmp(NOTIFIER_PATH, str_path, strlen(NOTIFIER_PATH)) == 0) {
		char str3[512];
		// /usr/sbin/usbauth allow/deny DEVNUM PATH
		snprintf(str3, 512, "%s %s %s %s", USBAUTH_PATH, argv[1], argv[2], argv[3]);
		setuid(0);
		system(str3);
	}

	return EXIT_SUCCESS;
}
