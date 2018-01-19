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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/wait.h>

#define USBAUTH_PATH "/usr/sbin/usbauth"
#define NOTIFIER_PATH "/usr/lib/usbauth-notifier/usbauth-notifier"
#define BUFSIZE 128

/*
 * This program will installed with SUID bit setted
 * The usbauth_notifier will call it to call usbauth firewall
 * with superuser rights
 *
 * Example call:
 * usbauth-npriv allow/deny DEVNUM PATH
 *
 * This program calls then:
 * /usr/sbin/usbauth allow/deny DEVNUM PATH
 *
 * but only if the caller is
 * /usr/lib/usbauth-notifier/usbauth-notifier
 *
 */
int main(int argc, char **argv) {
	int ret = EXIT_FAILURE;
	char str_proc[BUFSIZE] = {0};
	char str_path[BUFSIZE] = {0};
	size_t len_str_path = 0;
	pid_t ppid = 0;

	// connect to syslog
	openlog("usbauth-npriv", LOG_PERROR | LOG_PID, LOG_LOCAL0);

	ppid = getppid();
	snprintf(str_proc, BUFSIZE, "/proc/%d/exe", (int) ppid);

	len_str_path = readlink(str_proc, str_path, BUFSIZE-1);
	if (len_str_path < 0 || len_str_path >= BUFSIZE)
		len_str_path = 0;

	str_path[len_str_path] = 0;

	// three params must be given and the caller must be the notifier
	if (argc >= 4  && strncmp(NOTIFIER_PATH, str_path, BUFSIZE) == 0) {
		ret = setuid(0);

		if (!ret)
			ret = clearenv();

		if (!ret) {
			// /usr/sbin/usbauth allow/deny DEVNUM PATH
			syslog(LOG_NOTICE, "execute %s %s %s %s\n", USBAUTH_PATH, argv[1], argv[2], argv[3]);
			if (fork())
				wait(NULL);
			else
				execl(USBAUTH_PATH, USBAUTH_PATH, argv[1], argv[2], argv[3], NULL);
		} else {
			syslog(LOG_ERR, "setuid failed\n");
		}
	} else {
		syslog(LOG_ERR, "call of usbauth-npriv from ppid=%d with unauthorized installation path=%s\n", ppid, str_path);
	}

	// disconnect from syslog
	closelog();

	return ret;
}
