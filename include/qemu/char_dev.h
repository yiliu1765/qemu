/*
 * QEMU Chardev Helper
 *
 * Copyright 2016 - 2018 Red Hat, Inc.
 *
 * Authors:
 *   Fam Zheng <famz@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_CHARDEV_HELPERS_H
#define QEMU_CHARDEV_HELPERS_H

int open_cdev(const char *devpath, dev_t cdev);
#endif
