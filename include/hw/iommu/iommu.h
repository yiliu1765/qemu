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

#include "exec/memory.h"
#include "qemu/queue.h"
#include "qemu/thread.h"
#include "qom/object.h"
#include "exec/hwaddr.h"
#include "exec/cpu-common.h"
#include <linux/iommufd.h>

typedef struct IOMMUDevice IOMMUDevice;
typedef struct IOMMUGuestIOMMU IOMMUGuestIOMMU;
typedef struct IOMMURamDiscardListener IOMMURamDiscardListener;
typedef struct IOMMUHostDMAWindow IOMMUHostDMAWindow;
typedef struct IOMMUContainer IOMMUContainer;
typedef struct IOMMUAddressSpace IOMMUAddressSpace;

typedef struct IOMMUDeviceOps {
    int (*bind_iommufd)(struct IOMMUDevice *idev, int iommufd);
    int (*attach_ioas)(struct IOMMUDevice *idev, int iommufd, uint32_t ioas_id);
    void (*detach_ioas)(struct IOMMUDevice *idev, int iommufd, uint32_t ioas_id);
    void (*dev_reset)(struct IOMMUDevice *idev);
} IOMMUDeviceOps;

struct IOMMUDevice {
    IOMMUContainer *container;
    const IOMMUDeviceOps *ops;
    QLIST_ENTRY(IOMMUDevice) container_next;
    QLIST_ENTRY(IOMMUDevice) next;
    bool ram_block_discard_allowed;
};

struct IOMMUGuestIOMMU {
    IOMMUContainer *container;
    IOMMUMemoryRegion *iommu;
    hwaddr iommu_offset;
    IOMMUNotifier n;
    QLIST_ENTRY(IOMMUGuestIOMMU) giommu_next;
};

struct IOMMURamDiscardListener {
    IOMMUContainer *container;
    MemoryRegion *mr;
    hwaddr offset_within_address_space;
    hwaddr size;
    uint64_t granularity;
    RamDiscardListener listener;
    QLIST_ENTRY(IOMMURamDiscardListener) next;
};

struct IOMMUHostDMAWindow {
    hwaddr min_iova;
    hwaddr max_iova;
    uint64_t iova_pgsizes;
    QLIST_ENTRY(IOMMUHostDMAWindow) hostwin_next;
};

struct IOMMUContainer {
    IOMMUAddressSpace *space;
    int iommufd;
    uint32_t ioas_id;
    MemoryListener listener;
    MemoryListener prereg_listener;
    unsigned iommu_type;
    Error *error;
    bool initialized;
    bool dirty_pages_supported;
    uint64_t dirty_pgsizes;
    uint64_t max_dirty_bitmap_size;
    unsigned long pgsizes;
    unsigned int dma_max_mappings;
    QLIST_HEAD(, IOMMUGuestIOMMU) giommu_list;
    QLIST_HEAD(, IOMMUHostDMAWindow) hostwin_list;
    QLIST_HEAD(, IOMMUDevice) device_list;
    QLIST_HEAD(, IOMMURamDiscardListener) vrdl_list;
    QLIST_ENTRY(IOMMUContainer) next;
};

struct IOMMUAddressSpace {
    AddressSpace *as;
    QLIST_HEAD(, IOMMUContainer) containers;
    QLIST_ENTRY(IOMMUAddressSpace) list;
};

typedef QLIST_HEAD(IOMMUDeviceList, IOMMUDevice) IOMMUDeviceList;
extern IOMMUDeviceList iommu_device_list;

int iommu_register_device(IOMMUDevice *idev, AddressSpace *as,
                          const IOMMUDeviceOps *ops, Error **errp);
void iommu_unregister_device(IOMMUDevice *idev);

int iommu_device_attach_container(IOMMUDevice *idev,
                                  IOMMUContainer *container, Error **errp);

int iommu_ram_block_discard_disable(IOMMUContainer *container, bool state);

inline IOMMUContainer *iommu_device_container(IOMMUDevice *idev)
{
    return idev->container;
}

inline bool iommu_check_container(IOMMUContainer *container,
                                  AddressSpace *as)
{
    return (container->space->as == as);
}

int iommufd_get(void);
void iommufd_put(int fd);
int iommufd_alloc_ioas(int fd, uint32_t *ioas);
void iommufd_free_ioas(int fd, uint32_t ioas);
int iommufd_unmap_dma(int iommufd, uint32_t ioas, hwaddr iova, ram_addr_t size);
int iommufd_map_dma(int iommufd, uint32_t ioas, hwaddr iova, ram_addr_t size, void *vaddr, bool readonly);
#endif// HW_IOMMU_H
