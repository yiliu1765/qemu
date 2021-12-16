/*
 * QEMU abstraction of IOMMU
 *
 * Copyright (C) 2021 Intel Corporation.
 *
 * Authors: Liu Yi L <yi.l.liu@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_IOMMU_H
#define HW_IOMMU_H

#include "qemu/queue.h"
#include "qemu/thread.h"
#include "qom/object.h"
#include <linux/iommufd.h>

int iommufd_open(void);
void iommufd_close(int fd);
int iommufd_alloc_ioasd(int fd, uint32_t *ioasid);
void iommufd_free_ioasd(int fd, uint32_t ioasid);
#endif// HW_IOMMU_H
