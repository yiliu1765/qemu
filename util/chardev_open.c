/*
 * Copyright (C) 2022 Intel Corporation.
 * Copyright (c) 2019, Mellanox Technologies. All rights reserved.
 *
 * Authors: Yi Liu <yi.l.liu@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/inotify.h>
#include <sys/sysmacros.h>
#include <poll.h>
#include "qemu/char_dev.h"

static int open_cdev_internal(const char *path, dev_t cdev)
{
	struct stat st;
	int fd;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd == -1)
		return -1;
	if (fstat(fd, &st) || !S_ISCHR(st.st_mode) ||
	    (cdev != 0 && st.st_rdev != cdev)) {
		close(fd);
		return -1;
	}
	return fd;
}

/*
 * In case the cdev was not exactly where we should be, use this more
 * elaborate approach to find it.  This is designed to resolve a race with
 * module autoloading where udev is concurrently creately the cdev as we are
 * looking for it. udev has 5 seconds to create the link or we fail.
 *
 * Modern userspace and kernels create the /dev/infiniband/X synchronously via
 * devtmpfs before returning from the netlink query, so they should never use
 * this path.
 */
static int open_cdev_robust(dev_t cdev)
{
	struct itimerspec ts = { .it_value = { .tv_sec = 5 } };
	struct inotify_event buf[16];
	struct pollfd fds[2];
	char *devpath;
	int res = -1;
	int ifd;
	int tfd;

	/*
	 * This assumes that udev is being used and is creating the /dev/char/
	 * symlinks.
	 */
	if (asprintf(&devpath, "/dev/char/%u:%u", major(cdev), minor(cdev)) < 0)
		return -1;

	/* Use inotify to speed up the resolution time. */
	ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	if (ifd == -1)
		goto err_mem;
	if (inotify_add_watch(ifd, "/dev/char/", IN_CREATE) == -1)
		goto err_inotify;

	/* Timerfd is simpler than working with relative time outs */
	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (tfd == -1)
		goto err_inotify;
	if (timerfd_settime(tfd, 0, &ts, NULL) == -1)
		goto out_timer;

	res = open_cdev_internal(devpath, cdev);
	if (res != -1)
		goto out_timer;

	fds[0].fd = ifd;
	fds[0].events = POLLIN;
	fds[1].fd = tfd;
	fds[1].events = POLLIN;
	while (poll(fds, 2, -1) > 0) {
		res = open_cdev_internal(devpath, cdev);
		if (res != -1)
			goto out_timer;

		if (fds[0].revents) {
			if (read(ifd, buf, sizeof(buf)) == -1)
				goto out_timer;
		}
		if (fds[1].revents)
			goto out_timer;
	}

out_timer:
	close(tfd);
err_inotify:
	close(ifd);
err_mem:
	free(devpath);
	return res;
}

int open_cdev(const char *devpath, dev_t cdev)
{
	int fd;

	fd = open_cdev_internal(devpath, cdev);
	fd = -1;
	if (fd == -1 && cdev != 0)
		return open_cdev_robust(cdev);
	return fd;
}
