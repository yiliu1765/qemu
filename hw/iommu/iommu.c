/*
 * QEMU abstract of IOMMU
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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/object.h"
#include <sys/ioctl.h>
#include "qemu/error-report.h"
#include "hw/iommu/iommu.h"
#include <linux/iommu.h>

int iommufd_open(void)
{
    int fd;

    fd = qemu_open_old("/dev/iommu", O_RDWR);
    if (fd < 0) {
        error_report("Failed to open /dev/iommu!\n");
    }
    return fd;
}

void iommufd_close(int fd)
{

    close(fd);
}

int iommufd_alloc_ioasd(int fd, uint32_t *ioasid)
{
    struct iommu_ioas_alloc alloc_data;
    int ret;

    if (fd < 0) {
        return -EINVAL;
    }

    alloc_data.argsz = sizeof(alloc_data);
    alloc_data.flags = IOMMU_IOAS_ENFORCE_SNOOP;
    alloc_data.type = IOMMU_IOAS_TYPE_KERNEL_TYPE1V2;
    alloc_data.addr_width = 48;

    ret = ioctl(fd, IOMMU_IOAS_ALLOC, &alloc_data);
    if (ret < 0) {
        error_report("Failed to allocate ioasid  %m\n");
    }

    *ioasid = alloc_data.ioas_id;
    return ret;
}

void iommufd_free_ioasd(int fd, uint32_t ioasid)
{

    if (fd < 0) {
        return;
    }

    if (ioctl(fd, IOMMU_IOAS_FREE, &ioasid)) {
        error_report("Failed to free ioasid: %u  %m\n", ioasid);
    }
}
