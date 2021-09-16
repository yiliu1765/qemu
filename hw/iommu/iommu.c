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

int iommufd_alloc_ioasd(int fd)
{
    struct iommu_ioasid_alloc alloc_data;
    int ioasid;

    if (fd < 0) {
        return -EINVAL;
    }

    alloc_data.argsz = sizeof(alloc_data);
    alloc_data.flags = IOMMU_IOASID_ATTR_ENFORCE_SNOOP;
    alloc_data.type = IOMMU_IOASID_TYPE_KERNEL;
    alloc_data.addr_width = 48;

    ioasid = ioctl(fd, IOMMU_IOASID_ALLOC, &alloc_data);
    if (ioasid < 0) {
        error_report("Failed to allocate ioasid  %m\n");
    }

    return ioasid;
}

void iommufd_free_ioasd(int fd, int ioasid)
{

    if (fd < 0 || ioasid < 0) {
        return;
    }

    if (ioctl(fd, IOMMU_IOASID_FREE, &ioasid)) {
        error_report("Failed to free ioasid: %d  %m\n", ioasid);
    }
}
