/*
 * generic functions used by VFIO devices
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Alex Williamson <alex.williamson@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on qemu-kvm device-assignment:
 *  Adapted for KVM by Qumranet.
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 *  Copyright (C) 2008, IBM, Muli Ben-Yehuda (muli@il.ibm.com)
 */

#include "qemu/osdep.h"
#include <sys/ioctl.h>
#ifdef CONFIG_KVM
#include <linux/kvm.h>
#endif
#include <linux/vfio.h>

#include "hw/vfio/vfio-common.h"
#include "hw/vfio/vfio.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "exec/ram_addr.h"
#include "hw/hw.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/range.h"
#include "sysemu/kvm.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "trace.h"
#include "qapi/error.h"
#include "migration/migration.h"
#include "hw/iommu/iommu.h"

static int vfio_get_devicefd(const char *sysfs_path, Error **errp)
{
    int vfio_id = -1, ret = 0;
    char *path, *tmp;
    DIR *dir;
    struct dirent *dent;
    struct stat st;
    gchar *contents;
    gsize length;
    int major, minor;
    dev_t vfio_devt;

    path = g_strdup_printf("%s/vfio-device", sysfs_path);
    printf("path: %s, \n", path);
    if (stat(path, &st) < 0) {
        error_setg_errno(errp, errno, "no such host device");
        error_prepend(errp, VFIO_MSG_PREFIX, path);
        return -ENOTTY;
    }

    dir = opendir(path);
    if (!dir) {
        ret = -ENOTTY;
        goto out;
    }

    while ((dent = readdir(dir))) {
        char *end_name;

        if (!strncmp(dent->d_name, "vfio", 4)) {
            vfio_id = strtol(dent->d_name + 4, &end_name, 10);
            break;
        }
    }

    printf("vfio_id: %d\n", vfio_id);
    if (vfio_id == -1) {
        ret = -ENOTTY;
        goto out;
    }

    /* check if the major:minor matches */
    tmp = g_strdup_printf("%s/%s/dev", path, dent->d_name);
    if (!g_file_get_contents(tmp, &contents, &length, NULL)) {
        error_report("failed to load \"%s\"", tmp);
        exit(1);
    }
    printf("tmp: %s, content: %s, len: %ld\n", tmp, contents, length);
    if (sscanf(contents, "%d:%d", &major, &minor) != 2) {
        error_report("failed to load \"%s\"", tmp);
        exit(1);
    }
    printf("%d, %d\n", major, minor);
    g_free(contents);
    g_free(tmp);

    tmp = g_strdup_printf("/dev/vfio/devices/vfio%d", vfio_id);
    if (stat(tmp, &st) < 0) {
        error_setg_errno(errp, errno, "no such vfio device");
        error_prepend(errp, VFIO_MSG_PREFIX, tmp);
        ret = -ENOTTY;
        goto out;
    }
    vfio_devt = makedev(major, minor);
    printf("vfio_devt: %lu, %lu\n", vfio_devt, st.st_rdev);
    if (st.st_rdev != vfio_devt) {
        ret = -EINVAL;
    } else {
        ret = qemu_open_old(tmp, O_RDWR);
    }
    g_free(tmp);

out:
    g_free(path);
    return ret;
}

static int vfio_device_bind_iommufd(VFIODevice *vbasedev, int iommufd)
{
    struct vfio_device_bind_iommufd bind;
    int ret;

    bind.argsz = sizeof(bind);
    bind.flags = 0;
    bind.iommufd = iommufd;
    bind.dev_cookie = (uint64_t)vbasedev;

    ret = ioctl(vbasedev->fd, VFIO_DEVICE_BIND_IOMMUFD, &bind);
    if (ret) {
        printf("error bind failed, rt: %d\n", ret);
    } else {
        vbasedev->devid = bind.out_devid;
        printf("bind succ for devicefd: %d, devid: %u\n", vbasedev->fd, bind.out_devid);
    }

    return ret;
}

static int vfio_device_attach_ioas(VFIODevice *vbasedev, int iommufd, uint32_t ioas_id)
{
    struct vfio_device_attach_ioas attach_data;
    int ret;

    attach_data.argsz = sizeof(attach_data);
    attach_data.flags = 0;
    attach_data.iommufd = iommufd;
    attach_data.ioas_id = ioas_id;

    printf("attach ioas: %u - 1\n", ioas_id);
    ret = ioctl(vbasedev->fd, VFIO_DEVICE_ATTACH_IOAS, &attach_data);
    printf("attach ioas: %u - 2, ret: %d, hwpt_id: %u\n", ioas_id, ret, attach_data.out_hwpt_id);
    if (ret) {
        printf("error attach ioas failed, rt: %d\n", ret);
    }
    return ret;
}

static void vfio_device_detach_ioas(VFIODevice *vbasedev, int iommufd, uint32_t ioas_id)
{
    struct vfio_device_detach_ioas detach_data;
    int ret;

    detach_data.argsz = sizeof(detach_data);
    detach_data.flags = 0;
    detach_data.iommufd = iommufd;
    detach_data.ioas_id = ioas_id;

    printf("detach ioas: %d - 1\n", ioas_id);
    ret = ioctl(vbasedev->fd, VFIO_DEVICE_DETACH_IOAS, &detach_data);
    printf("detach ioas: %d - 2, ret: %d\n", ioas_id, ret);
}

static int vfio_iommu_dev_bind_iommufd(IOMMUDevice *idev, int iommufd)
{
    VFIODevice *vbasedev = container_of(idev, VFIODevice, idev);
    return vfio_device_bind_iommufd(vbasedev, iommufd);
}

static int vfio_iommu_dev_attach_ioas(IOMMUDevice *idev, int iommufd, uint32_t ioas_id)
{
    VFIODevice *vbasedev = container_of(idev, VFIODevice, idev);
    return vfio_device_attach_ioas(vbasedev, iommufd, ioas_id);
}

static void vfio_iommu_dev_detach_ioas(IOMMUDevice *idev, int iommufd, uint32_t ioas_id)
{
    VFIODevice *vbasedev = container_of(idev, VFIODevice, idev);
    vfio_device_detach_ioas(vbasedev, iommufd, ioas_id);
}

static void vfio_iommu_dev_reset(IOMMUDevice *idev)
{
    VFIODevice *vbasedev = container_of(idev, VFIODevice, idev);

    if (vbasedev->dev->realized) {
         vbasedev->ops->vfio_compute_needs_reset(vbasedev);
    }
    if (vbasedev->dev->realized && vbasedev->needs_reset) {
        vbasedev->ops->vfio_hot_reset_multi(vbasedev);
    }
}

const IOMMUDeviceOps vfio_iommu_dev_ops = {
    .bind_iommufd = vfio_iommu_dev_bind_iommufd,
    .attach_ioas = vfio_iommu_dev_attach_ioas,
    .detach_ioas = vfio_iommu_dev_detach_ioas,
    .dev_reset = vfio_iommu_dev_reset,
};

static bool vfio_group_find_device(VFIOGroup *group, VFIODevice *vbasedev)
{
    VFIODevice *vbasedev_iter;

    QLIST_FOREACH(vbasedev_iter, &group->device_list, next) {
        if (strcmp(vbasedev_iter->name, vbasedev->name) == 0) {
            return true;
        }
    }

    return false;
}

#if 0
static IOMMUContainer *vfio_group_get_container(VFIOGroup *group)
{
    VFIODevice *vbasedev;

    if (QLIST_EMPTY(&group->device_list)) {
        return NULL;
    }

    vbasedev = QLIST_FIRST(&group->device_list);

    return iommu_device_container(&vbasedev->idev);
}
#endif

static VFIOGroup * vfio_device_get_group(VFIODevice *vbasedev,
                                         int groupid, AddressSpace *as,
                                         Error **errp)
{
    VFIOGroup *group;

    QLIST_FOREACH(group, &vfio_group_list, next) {
        if (group->groupid == groupid) {
            IOMMUContainer *container = group->iommu_container;

            /* Found it.  Now is it already in the right context? */
            if (iommu_check_container(container, as)) {
                if (!iommu_device_attach_container(&vbasedev->idev, container, errp)) {
                    return group;
                } else {
                    error_setg(errp, "failed to attach device in group %d to its alias address spaces",
                               group->groupid);
                    return NULL;
                }
            } else {
                error_setg(errp, "group %d used in multiple address spaces",
                           group->groupid);
                return NULL;
            }
        }
    }

    group = g_malloc0(sizeof(*group));

    group->groupid = groupid;
    QLIST_INIT(&group->device_list);

    if (iommu_register_device(&vbasedev->idev, as, &vfio_iommu_dev_ops, errp)) {
        error_prepend(errp, "failed to setup container for group %d: ",
                      groupid);
        goto free_group_exit;
    }

    if (QLIST_EMPTY(&vfio_group_list)) {
        qemu_register_reset(vfio_reset_handler, NULL);
    }

    group->iommu_container = iommu_device_container(&vbasedev->idev);

    QLIST_INSERT_HEAD(&vfio_group_list, group, next);

    return group;

free_group_exit:
    g_free(group);

    return NULL;
}

static void __vfio_put_group(VFIOGroup *group)
{
    if (!group || !QLIST_EMPTY(&group->device_list)) {
        return;
    }

    if (!group->ram_block_discard_allowed) {
        iommu_ram_block_discard_disable(group->iommu_container, false);
    }
//    vfio_kvm_device_del_group(group);
//    vfio_disconnect_container(group);
    QLIST_REMOVE(group, next);
    g_free(group);

    if (QLIST_EMPTY(&vfio_group_list)) {
        qemu_unregister_reset(vfio_reset_handler, NULL);
    }
}

static void vfio_device_put_group(VFIODevice *vbasedev, VFIOGroup *group)
{
    iommu_unregister_device(&vbasedev->idev);
    __vfio_put_group(group);
}

int test_iommufd(void);

int vfio_device_get(VFIODevice *vbasedev, int groupid, AddressSpace *as, Error **errp)
{
    struct vfio_device_info dev_info = { .argsz = sizeof(dev_info) };
    VFIOGroup *group;
    int ret, fd;

    printf("################### Test START #################\n");
    test_iommufd();
    printf("################### Test END #################\n\n");

    fd = vfio_get_devicefd(vbasedev->sysfsdev, errp);
    if (fd < 0) {
        printf("%s no direct device open\n", __func__);
        return -1;
    }

    vbasedev->fd = fd;

    group = vfio_device_get_group(vbasedev, groupid, as, errp);
    if (!group) {
        error_prepend(errp, "error connect as");
        vbasedev->fd = 0;
        close(fd);
        return -1;
    }

    if (vfio_group_find_device(group, vbasedev)) {
        error_setg_errno(errp, errno, "error already attached device");
        vfio_device_put_group(vbasedev, group);
        vbasedev->fd = 0;
        close(fd);
        return -1;
    }

    ret = ioctl(fd, VFIO_DEVICE_GET_INFO, &dev_info);
    if (ret) {
        error_setg_errno(errp, errno, "error getting device info");
        vfio_device_put_group(vbasedev, group);
        vbasedev->fd = 0;
        close(fd);
        return ret;
    }

    /*
     * Set discarding of RAM as not broken for this group if the driver knows
     * the device operates compatibly with discarding.  Setting must be
     * consistent per group, but since compatibility is really only possible
     * with mdev currently, we expect singleton groups.
     */
    if (vbasedev->ram_block_discard_allowed !=
        group->ram_block_discard_allowed) {
        if (!QLIST_EMPTY(&group->device_list)) {
            error_setg(errp, "Inconsistent setting of support for discarding "
                       "RAM (e.g., balloon) within group");
            vfio_device_put_group(vbasedev, group);
            vbasedev->fd = 0;
            close(fd);
            return -1;
        }

        if (!group->ram_block_discard_allowed) {
            group->ram_block_discard_allowed = true;
            iommu_ram_block_discard_disable(group->iommu_container, false);
        }
    }

    vbasedev->group = group;
    QLIST_INSERT_HEAD(&group->device_list, vbasedev, next);

    vbasedev->num_irqs = dev_info.num_irqs;
    vbasedev->num_regions = dev_info.num_regions;
    vbasedev->flags = dev_info.flags;

//    trace_vfio_get_device(name, dev_info.flags, dev_info.num_regions,
//                          dev_info.num_irqs);

    vbasedev->reset_works = !!(dev_info.flags & VFIO_DEVICE_FLAGS_RESET);
    return 0;
}

void vfio_device_put_base(VFIODevice *vbasedev)
{
    VFIOGroup *group = vbasedev->group;

    if (!group) {
        return;
    }

    vbasedev->group = NULL;
    QLIST_REMOVE(vbasedev, next);
    vfio_device_put_group(vbasedev, group);
    close(vbasedev->fd);
    vbasedev->fd = 0;
}

#include "test.c"
