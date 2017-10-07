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
#define NOTIFIER_PATH "/usr/bin/usbauth-notifier"
#define BUFSIZE 128
#define CALLBUFSIZE 512

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
	char str_proc[BUFSIZE] = {0};
	char str_path[BUFSIZE] = {0};
	size_t len_str_path = 0;
	pid_t ppid = 0;

	ppid = getppid();
	snprintf(str_proc, BUFSIZE, "/proc/%d/exe", (int) ppid);

	len_str_path = readlink(str_proc, str_path, BUFSIZE-1);
	if (len_str_path < 0 || len_str_path >= BUFSIZE)
		len_str_path = 0;

	str_path[len_str_path] = 0;

	// three params must be given and the caller must be the notifier
	if(argc >= 4  && strncmp(NOTIFIER_PATH, str_path, BUFSIZE) == 0) {
		char str_call[CALLBUFSIZE] = {0};
		// /usr/sbin/usbauth allow/deny DEVNUM PATH
		snprintf(str_call, CALLBUFSIZE, "%s %s %s %s", USBAUTH_PATH, argv[1], argv[2], argv[3]);
		setuid(0);
		system(str_call);
	}

	return EXIT_SUCCESS;
}
