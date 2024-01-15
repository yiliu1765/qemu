/*
 * iommufd container backend
 *
 * Copyright (C) 2023 Intel Corporation.
 * Copyright Red Hat, Inc. 2023
 *
 * Authors: Yi Liu <yi.l.liu@intel.com>
 *          Eric Auger <eric.auger@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "sysemu/iommufd.h"
#include "qapi/error.h"
#include "qapi/qmp/qerror.h"
#include "qemu/module.h"
#include "qom/object_interfaces.h"
#include "qemu/error-report.h"
#include "monitor/monitor.h"
#include "trace.h"
#include <sys/ioctl.h>

static void iommufd_backend_init(Object *obj)
{
    IOMMUFDBackend *be = IOMMUFD_BACKEND(obj);

    be->fd = -1;
    be->users = 0;
    be->owned = true;
}

static void iommufd_backend_finalize(Object *obj)
{
    IOMMUFDBackend *be = IOMMUFD_BACKEND(obj);

    if (be->owned) {
        close(be->fd);
        be->fd = -1;
    }
}

static void iommufd_backend_set_fd(Object *obj, const char *str, Error **errp)
{
    IOMMUFDBackend *be = IOMMUFD_BACKEND(obj);
    int fd = -1;

    fd = monitor_fd_param(monitor_cur(), str, errp);
    if (fd == -1) {
        error_prepend(errp, "Could not parse remote object fd %s:", str);
        return;
    }
    be->fd = fd;
    be->owned = false;
    trace_iommu_backend_set_fd(be->fd);
}

static bool iommufd_backend_can_be_deleted(UserCreatable *uc)
{
    IOMMUFDBackend *be = IOMMUFD_BACKEND(uc);

    return !be->users;
}

static void iommufd_backend_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(oc);

    ucc->can_be_deleted = iommufd_backend_can_be_deleted;

    object_class_property_add_str(oc, "fd", NULL, iommufd_backend_set_fd);
}

int iommufd_backend_connect(IOMMUFDBackend *be, Error **errp)
{
    int fd, ret = 0;

    if (be->owned && !be->users) {
        fd = qemu_open_old("/dev/iommu", O_RDWR);
        if (fd < 0) {
            error_setg_errno(errp, errno, "/dev/iommu opening failed");
            ret = fd;
            goto out;
        }
        be->fd = fd;
    }
    be->users++;
out:
    trace_iommufd_backend_connect(be->fd, be->owned,
                                  be->users, ret);
    return ret;
}

void iommufd_backend_disconnect(IOMMUFDBackend *be)
{
    if (!be->users) {
        goto out;
    }
    be->users--;
    if (!be->users && be->owned) {
        close(be->fd);
        be->fd = -1;
    }
out:
    trace_iommufd_backend_disconnect(be->fd, be->users);
}

int iommufd_backend_alloc_ioas(IOMMUFDBackend *be, uint32_t *ioas_id,
                               Error **errp)
{
    int ret, fd = be->fd;
    struct iommu_ioas_alloc alloc_data  = {
        .size = sizeof(alloc_data),
        .flags = 0,
    };

    ret = ioctl(fd, IOMMU_IOAS_ALLOC, &alloc_data);
    if (ret) {
        error_setg_errno(errp, errno, "Failed to allocate ioas");
        return ret;
    }

    *ioas_id = alloc_data.out_ioas_id;
    trace_iommufd_backend_alloc_ioas(fd, *ioas_id, ret);

    return ret;
}

void iommufd_backend_free_id(IOMMUFDBackend *be, uint32_t id)
{
    int ret, fd = be->fd;
    struct iommu_destroy des = {
        .size = sizeof(des),
        .id = id,
    };

    ret = ioctl(fd, IOMMU_DESTROY, &des);
    trace_iommufd_backend_free_id(fd, id, ret);
    if (ret) {
        error_report("Failed to free id: %u %m", id);
    }
}

int iommufd_backend_map_dma(IOMMUFDBackend *be, uint32_t ioas_id, hwaddr iova,
                            ram_addr_t size, void *vaddr, bool readonly)
{
    int ret, fd = be->fd;
    struct iommu_ioas_map map = {
        .size = sizeof(map),
        .flags = IOMMU_IOAS_MAP_READABLE |
                 IOMMU_IOAS_MAP_FIXED_IOVA,
        .ioas_id = ioas_id,
        .__reserved = 0,
        .user_va = (uintptr_t)vaddr,
        .iova = iova,
        .length = size,
    };

    if (!readonly) {
        map.flags |= IOMMU_IOAS_MAP_WRITEABLE;
    }

    ret = ioctl(fd, IOMMU_IOAS_MAP, &map);
    trace_iommufd_backend_map_dma(fd, ioas_id, iova, size,
                                  vaddr, readonly, ret);
    if (ret) {
        ret = -errno;

        /* TODO: Not support mapping hardware PCI BAR region for now. */
        if (errno == EFAULT) {
            warn_report("IOMMU_IOAS_MAP failed: %m, PCI BAR?");
        } else {
            error_report("IOMMU_IOAS_MAP failed: %m");
        }
    }
    return ret;
}

int iommufd_backend_unmap_dma(IOMMUFDBackend *be, uint32_t ioas_id,
                              hwaddr iova, ram_addr_t size)
{
    int ret, fd = be->fd;
    struct iommu_ioas_unmap unmap = {
        .size = sizeof(unmap),
        .ioas_id = ioas_id,
        .iova = iova,
        .length = size,
    };

    ret = ioctl(fd, IOMMU_IOAS_UNMAP, &unmap);
    /*
     * IOMMUFD takes mapping as some kind of object, unmapping
     * nonexistent mapping is treated as deleting a nonexistent
     * object and return ENOENT. This is different from legacy
     * backend which allows it. vIOMMU may trigger a lot of
     * redundant unmapping, to avoid flush the log, treat them
     * as succeess for IOMMUFD just like legacy backend.
     */
    if (ret && errno == ENOENT) {
        trace_iommufd_backend_unmap_dma_non_exist(fd, ioas_id, iova, size, ret);
        ret = 0;
    } else {
        trace_iommufd_backend_unmap_dma(fd, ioas_id, iova, size, ret);
    }

    if (ret) {
        ret = -errno;
        error_report("IOMMU_IOAS_UNMAP failed: %m");
    }
    return ret;
}

int iommufd_backend_alloc_hwpt(IOMMUFDBackend *be, uint32_t dev_id,
                               uint32_t pt_id, uint32_t flags,
                               uint32_t data_type, uint32_t data_len,
                               void *data_ptr, uint32_t *out_hwpt)
{
    int ret, fd = be->fd;
    struct iommu_hwpt_alloc alloc_hwpt = {
        .size = sizeof(struct iommu_hwpt_alloc),
        .flags = flags,
        .dev_id = dev_id,
        .pt_id = pt_id,
        .data_type = data_type,
        .data_len = data_len,
        .data_uptr = (uintptr_t)data_ptr,
    };

    ret = ioctl(fd, IOMMU_HWPT_ALLOC, &alloc_hwpt);
    if (ret) {
        ret = -errno;
        error_report("IOMMU_HWPT_ALLOC failed: %m");
    } else {
        *out_hwpt = alloc_hwpt.out_hwpt_id;
    }

    trace_iommufd_backend_alloc_hwpt(fd, dev_id, pt_id, flags, data_type,
                                     data_len, (uint64_t)data_ptr,
                                     alloc_hwpt.out_hwpt_id, ret);
    return ret;
}

int iommufd_backend_invalidate_cache(IOMMUFDBackend *be, uint32_t hwpt_id,
                                     uint32_t data_type, uint32_t entry_len,
                                     uint32_t *entry_num, void *data_ptr)
{
    int ret, fd = be->fd;
    struct iommu_hwpt_invalidate cache = {
        .size = sizeof(cache),
        .hwpt_id = hwpt_id,
        .data_type = data_type,
        .entry_len = entry_len,
        .entry_num = *entry_num,
        .data_uptr = (uintptr_t)data_ptr,
    };

    ret = ioctl(fd, IOMMU_HWPT_INVALIDATE, &cache);

    trace_iommufd_backend_invalidate_cache(fd, hwpt_id, data_type, entry_len,
                                           *entry_num, cache.entry_num,
                                           (uintptr_t)data_ptr, ret);
    if (ret) {
        *entry_num = cache.entry_num;
        error_report("IOMMU_HWPT_INVALIDATE failed: %s", strerror(errno));
        ret = -errno;
    } else {
        g_assert(*entry_num == cache.entry_num);
    }

    return ret;
}

static const TypeInfo iommufd_backend_info = {
    .name = TYPE_IOMMUFD_BACKEND,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(IOMMUFDBackend),
    .instance_init = iommufd_backend_init,
    .instance_finalize = iommufd_backend_finalize,
    .class_size = sizeof(IOMMUFDBackendClass),
    .class_init = iommufd_backend_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void register_types(void)
{
    type_register_static(&iommufd_backend_info);
}

type_init(register_types);

void iommufd_device_init(IOMMUFDDevice *idev, IOMMUFDBackend *iommufd,
                         int devid, uint32_t ioas_id, void *opaque,
                         IOMMUFDDeviceOps *ops)
{
    host_iommu_base_device_init(&idev->base, HID_IOMMUFD,
                                sizeof(IOMMUFDDevice));
    idev->iommufd = iommufd;
    idev->devid = devid;
    idev->ioas_id = ioas_id;
    idev->opaque = opaque;
    idev->ops = ops;
}

int iommufd_device_get_info(IOMMUFDDevice *idev,
                            enum iommu_hw_info_type *type,
                            uint32_t len, void *data, Error **errp)
{
    struct iommu_hw_info info = {
        .size = sizeof(info),
        .dev_id = idev->devid,
        .data_len = len,
        .data_uptr = (uintptr_t)data,
    };
    int ret;

    ret = ioctl(idev->iommufd->fd, IOMMU_GET_HW_INFO, &info);
    if (ret) {
        error_setg_errno(errp, errno, "Failed to get hardware info");
    } else {
        *type = info.out_data_type;
    }

    return ret;
}

int iommufd_device_attach_hwpt(IOMMUFDDevice *idev, uint32_t hwpt_id)
{
    g_assert(idev->ops->attach_hwpt);
    return idev->ops->attach_hwpt(idev, hwpt_id);
}

int iommufd_device_detach_hwpt(IOMMUFDDevice *idev)
{
    g_assert(idev->ops->detach_hwpt);
    return idev->ops->detach_hwpt(idev);
}
