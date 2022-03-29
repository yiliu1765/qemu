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
#include "hw/hw.h"
#include "qemu/error-report.h"
#include "qemu/range.h"
#include "sysemu/kvm.h"
#include "sysemu/reset.h"
#include "trace.h"
#include "qapi/error.h"
#include "migration/migration.h"

#ifdef CONFIG_KVM
/*
 * We have a single VFIO pseudo device per KVM VM.  Once created it lives
 * for the life of the VM.  Closing the file descriptor only drops our
 * reference to it and the device's reference to kvm.  Therefore once
 * initialized, this file descriptor is only released on QEMU exit and
 * we'll re-use it should another vfio device be attached before then.
 */
static int vfio_kvm_device_fd = -1;
#endif

VFIOGroupList vfio_group_list =
    QLIST_HEAD_INITIALIZER(vfio_group_list);

/*
 * Device state interfaces
 */

bool vfio_mig_active(void)
{
    VFIOGroup *group;
    VFIODevice *vbasedev;

    if (QLIST_EMPTY(&vfio_group_list)) {
        return false;
    }

    QLIST_FOREACH(group, &vfio_group_list, next) {
        QLIST_FOREACH(vbasedev, &group->device_list, next) {
            if (vbasedev->migration_blocker) {
                return false;
            }
        }
    }
    return true;
}

bool vfio_devices_all_dirty_tracking(VFIOContainer *container)
{
    VFIOGroup *group;
    VFIODevice *vbasedev;
    MigrationState *ms = migrate_get_current();

    if (!migration_is_setup_or_active(ms->state)) {
        return false;
    }

    QLIST_FOREACH(group, &container->group_list, container_next) {
        QLIST_FOREACH(vbasedev, &group->device_list, next) {
            VFIOMigration *migration = vbasedev->migration;

            if (!migration) {
                return false;
            }

            if ((vbasedev->pre_copy_dirty_page_tracking == ON_OFF_AUTO_OFF)
                && (migration->device_state & VFIO_DEVICE_STATE_RUNNING)) {
                return false;
            }
        }
    }
    return true;
}

bool vfio_devices_all_running_and_saving(VFIOContainer *container)
{
    VFIOGroup *group;
    VFIODevice *vbasedev;
    MigrationState *ms = migrate_get_current();

    if (!migration_is_setup_or_active(ms->state)) {
        return false;
    }

    QLIST_FOREACH(group, &container->group_list, container_next) {
        QLIST_FOREACH(vbasedev, &group->device_list, next) {
            VFIOMigration *migration = vbasedev->migration;

            if (!migration) {
                return false;
            }

            if ((migration->device_state & VFIO_DEVICE_STATE_SAVING) &&
                (migration->device_state & VFIO_DEVICE_STATE_RUNNING)) {
                continue;
            } else {
                return false;
            }
        }
    }
    return true;
}

void vfio_reset_handler(void *opaque)
{
    VFIOGroup *group;
    VFIODevice *vbasedev;

    QLIST_FOREACH(group, &vfio_group_list, next) {
        QLIST_FOREACH(vbasedev, &group->device_list, next) {
            if (vbasedev->dev->realized) {
                vbasedev->ops->vfio_compute_needs_reset(vbasedev);
            }
        }
    }

    QLIST_FOREACH(group, &vfio_group_list, next) {
        QLIST_FOREACH(vbasedev, &group->device_list, next) {
            if (vbasedev->dev->realized && vbasedev->needs_reset) {
                vbasedev->ops->vfio_hot_reset_multi(vbasedev);
            }
        }
    }
}

void vfio_spapr_group_attach(VFIOContainer *container, int32_t tablefd)
{
#ifdef CONFIG_KVM
    VFIOGroup *group;
    struct kvm_vfio_spapr_tce param = { .tablefd = tablefd, };
    struct kvm_device_attr attr = {
                .group = KVM_DEV_VFIO_GROUP,
                .attr = KVM_DEV_VFIO_GROUP_SET_SPAPR_TCE,
                .addr = (uint64_t)(unsigned long)&param,
            };

    QLIST_FOREACH(group, &container->group_list, container_next) {
        param.groupfd = group->fd;
        if (ioctl(vfio_kvm_device_fd, KVM_SET_DEVICE_ATTR, &attr)) {
            error_report("vfio: failed to setup fd %d "
                         "for a group with fd %d: %s",
                         param.tablefd, param.groupfd,
                         strerror(errno));
            return;
        }
        trace_vfio_spapr_group_attach(param.groupfd, param.tablefd);
    }
#endif
}

static void vfio_kvm_device_add_group(VFIOGroup *group)
{
#ifdef CONFIG_KVM
    struct kvm_device_attr attr = {
        .group = KVM_DEV_VFIO_GROUP,
        .attr = KVM_DEV_VFIO_GROUP_ADD,
        .addr = (uint64_t)(unsigned long)&group->fd,
    };

    if (!kvm_enabled()) {
        return;
    }

    if (vfio_kvm_device_fd < 0) {
        struct kvm_create_device cd = {
            .type = KVM_DEV_TYPE_VFIO,
        };

        if (kvm_vm_ioctl(kvm_state, KVM_CREATE_DEVICE, &cd)) {
            error_report("Failed to create KVM VFIO device: %m");
            return;
        }

        vfio_kvm_device_fd = cd.fd;
    }

    if (ioctl(vfio_kvm_device_fd, KVM_SET_DEVICE_ATTR, &attr)) {
        error_report("Failed to add group %d to KVM VFIO device: %m",
                     group->groupid);
    }
#endif
}

static void vfio_kvm_device_del_group(VFIOGroup *group)
{
#ifdef CONFIG_KVM
    struct kvm_device_attr attr = {
        .group = KVM_DEV_VFIO_GROUP,
        .attr = KVM_DEV_VFIO_GROUP_DEL,
        .addr = (uint64_t)(unsigned long)&group->fd,
    };

    if (vfio_kvm_device_fd < 0) {
        return;
    }

    if (ioctl(vfio_kvm_device_fd, KVM_SET_DEVICE_ATTR, &attr)) {
        error_report("Failed to remove group %d from KVM VFIO device: %m",
                     group->groupid);
    }
#endif
}

/*
 * vfio_get_iommu_type - selects the richest iommu_type (v2 first)
 */
static int vfio_get_iommu_type(VFIOContainer *container,
                               Error **errp)
{
    int iommu_types[] = { VFIO_TYPE1v2_IOMMU, VFIO_TYPE1_IOMMU,
                          VFIO_SPAPR_TCE_v2_IOMMU, VFIO_SPAPR_TCE_IOMMU };
    int i;

    for (i = 0; i < ARRAY_SIZE(iommu_types); i++) {
        if (ioctl(container->fd, VFIO_CHECK_EXTENSION, iommu_types[i])) {
            return iommu_types[i];
        }
    }
    error_setg(errp, "No available IOMMU models");
    return -EINVAL;
}

static int vfio_init_container(VFIOContainer *container, int group_fd,
                               Error **errp)
{
    int iommu_type, ret;

    iommu_type = vfio_get_iommu_type(container, errp);
    if (iommu_type < 0) {
        return iommu_type;
    }

    ret = ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container->fd);
    if (ret) {
        error_setg_errno(errp, errno, "Failed to set group container");
        return -errno;
    }

    while (ioctl(container->fd, VFIO_SET_IOMMU, iommu_type)) {
        if (iommu_type == VFIO_SPAPR_TCE_v2_IOMMU) {
            /*
             * On sPAPR, despite the IOMMU subdriver always advertises v1 and
             * v2, the running platform may not support v2 and there is no
             * way to guess it until an IOMMU group gets added to the container.
             * So in case it fails with v2, try v1 as a fallback.
             */
            iommu_type = VFIO_SPAPR_TCE_IOMMU;
            continue;
        }
        error_setg_errno(errp, errno, "Failed to set iommu for container");
        return -errno;
    }

    container->iommu_type = iommu_type;
    return 0;
}

static int vfio_get_iommu_info(VFIOContainer *container,
                               struct vfio_iommu_type1_info **info)
{

    size_t argsz = sizeof(struct vfio_iommu_type1_info);

    *info = g_new0(struct vfio_iommu_type1_info, 1);
again:
    (*info)->argsz = argsz;

    if (ioctl(container->fd, VFIO_IOMMU_GET_INFO, *info)) {
        g_free(*info);
        *info = NULL;
        return -errno;
    }

    if (((*info)->argsz > argsz)) {
        argsz = (*info)->argsz;
        *info = g_realloc(*info, argsz);
        goto again;
    }

    return 0;
}

static struct vfio_info_cap_header *
vfio_get_iommu_info_cap(struct vfio_iommu_type1_info *info, uint16_t id)
{
    struct vfio_info_cap_header *hdr;
    void *ptr = info;

    if (!(info->flags & VFIO_IOMMU_INFO_CAPS)) {
        return NULL;
    }

    for (hdr = ptr + info->cap_offset; hdr != ptr; hdr = ptr + hdr->next) {
        if (hdr->id == id) {
            return hdr;
        }
    }

    return NULL;
}

static void vfio_get_iommu_info_migration(VFIOContainer *container,
                                         struct vfio_iommu_type1_info *info)
{
    struct vfio_info_cap_header *hdr;
    struct vfio_iommu_type1_info_cap_migration *cap_mig;

    hdr = vfio_get_iommu_info_cap(info, VFIO_IOMMU_TYPE1_INFO_CAP_MIGRATION);
    if (!hdr) {
        return;
    }

    cap_mig = container_of(hdr, struct vfio_iommu_type1_info_cap_migration,
                            header);

    /*
     * cpu_physical_memory_set_dirty_lebitmap() supports pages in bitmap of
     * qemu_real_host_page_size to mark those dirty.
     */
    if (cap_mig->pgsize_bitmap & qemu_real_host_page_size) {
        container->dirty_pages_supported = true;
        container->max_dirty_bitmap_size = cap_mig->max_dirty_bitmap_size;
        container->dirty_pgsizes = cap_mig->pgsize_bitmap;
    }
}

static int vfio_ram_block_discard_disable(VFIOContainer *container, bool state)
{
    switch (container->iommu_type) {
    case VFIO_TYPE1v2_IOMMU:
    case VFIO_TYPE1_IOMMU:
        /*
         * We support coordinated discarding of RAM via the RamDiscardManager.
         */
        return ram_block_uncoordinated_discard_disable(state);
    default:
        /*
         * VFIO_SPAPR_TCE_IOMMU most probably works just fine with
         * RamDiscardManager, however, it is completely untested.
         *
         * VFIO_SPAPR_TCE_v2_IOMMU with "DMA memory preregistering" does
         * completely the opposite of managing mapping/pinning dynamically as
         * required by RamDiscardManager. We would have to special-case sections
         * with a RamDiscardManager.
         */
        return ram_block_discard_disable(state);
    }
}

static int vfio_connect_container(VFIOGroup *group, AddressSpace *as,
                                  Error **errp)
{
    VFIOContainer *container;
    int ret, fd;
    VFIOAddressSpace *space;

    space = vfio_get_address_space(as);

    /*
     * VFIO is currently incompatible with discarding of RAM insofar as the
     * madvise to purge (zap) the page from QEMU's address space does not
     * interact with the memory API and therefore leaves stale virtual to
     * physical mappings in the IOMMU if the page was previously pinned.  We
     * therefore set discarding broken for each group added to a container,
     * whether the container is used individually or shared.  This provides
     * us with options to allow devices within a group to opt-in and allow
     * discarding, so long as it is done consistently for a group (for instance
     * if the device is an mdev device where it is known that the host vendor
     * driver will never pin pages outside of the working set of the guest
     * driver, which would thus not be discarding candidates).
     *
     * The first opportunity to induce pinning occurs here where we attempt to
     * attach the group to existing containers within the AddressSpace.  If any
     * pages are already zapped from the virtual address space, such as from
     * previous discards, new pinning will cause valid mappings to be
     * re-established.  Likewise, when the overall MemoryListener for a new
     * container is registered, a replay of mappings within the AddressSpace
     * will occur, re-establishing any previously zapped pages as well.
     *
     * Especially virtio-balloon is currently only prevented from discarding
     * new memory, it will not yet set ram_block_discard_set_required() and
     * therefore, neither stops us here or deals with the sudden memory
     * consumption of inflated memory.
     *
     * We do support discarding of memory coordinated via the RamDiscardManager
     * with some IOMMU types. vfio_ram_block_discard_disable() handles the
     * details once we know which type of IOMMU we are using.
     */

    QLIST_FOREACH(container, &space->containers, next) {
        if (!ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd)) {
            ret = vfio_ram_block_discard_disable(container, true);
            if (ret) {
                error_setg_errno(errp, -ret,
                                 "Cannot set discarding of RAM broken");
                if (ioctl(group->fd, VFIO_GROUP_UNSET_CONTAINER,
                          &container->fd)) {
                    error_report("vfio: error disconnecting group %d from"
                                 " container", group->groupid);
                }
                return ret;
            }
            group->container = container;
            QLIST_INSERT_HEAD(&container->group_list, group, container_next);
            vfio_kvm_device_add_group(group);
            return 0;
        }
    }

    fd = qemu_open_old("/dev/vfio/vfio", O_RDWR);
    if (fd < 0) {
        error_setg_errno(errp, errno, "failed to open /dev/vfio/vfio");
        ret = -errno;
        goto put_space_exit;
    }

    ret = ioctl(fd, VFIO_GET_API_VERSION);
    if (ret != VFIO_API_VERSION) {
        error_setg(errp, "supported vfio version: %d, "
                   "reported version: %d", VFIO_API_VERSION, ret);
        ret = -EINVAL;
        goto close_fd_exit;
    }

    container = g_malloc0(sizeof(*container));
    container->space = space;
    container->fd = fd;
    container->error = NULL;
    container->dirty_pages_supported = false;
    container->dma_max_mappings = 0;
    QLIST_INIT(&container->giommu_list);
    QLIST_INIT(&container->hostwin_list);
    QLIST_INIT(&container->vrdl_list);

    ret = vfio_init_container(container, group->fd, errp);
    if (ret) {
        goto free_container_exit;
    }

    ret = vfio_ram_block_discard_disable(container, true);
    if (ret) {
        error_setg_errno(errp, -ret, "Cannot set discarding of RAM broken");
        goto free_container_exit;
    }

    switch (container->iommu_type) {
    case VFIO_TYPE1v2_IOMMU:
    case VFIO_TYPE1_IOMMU:
    {
        struct vfio_iommu_type1_info *info;

        /*
         * FIXME: This assumes that a Type1 IOMMU can map any 64-bit
         * IOVA whatsoever.  That's not actually true, but the current
         * kernel interface doesn't tell us what it can map, and the
         * existing Type1 IOMMUs generally support any IOVA we're
         * going to actually try in practice.
         */
        ret = vfio_get_iommu_info(container, &info);

        if (ret || !(info->flags & VFIO_IOMMU_INFO_PGSIZES)) {
            /* Assume 4k IOVA page size */
            info->iova_pgsizes = 4096;
        }
        vfio_host_win_add(container, 0, (hwaddr)-1, info->iova_pgsizes);
        container->pgsizes = info->iova_pgsizes;

        /* The default in the kernel ("dma_entry_limit") is 65535. */
        container->dma_max_mappings = 65535;
        if (!ret) {
            vfio_get_info_dma_avail(info, &container->dma_max_mappings);
            vfio_get_iommu_info_migration(container, info);
        }
        g_free(info);
        break;
    }
    case VFIO_SPAPR_TCE_v2_IOMMU:
    case VFIO_SPAPR_TCE_IOMMU:
    {
        struct vfio_iommu_spapr_tce_info info;
        bool v2 = container->iommu_type == VFIO_SPAPR_TCE_v2_IOMMU;

        /*
         * The host kernel code implementing VFIO_IOMMU_DISABLE is called
         * when container fd is closed so we do not call it explicitly
         * in this file.
         */
        if (!v2) {
            ret = ioctl(fd, VFIO_IOMMU_ENABLE);
            if (ret) {
                error_setg_errno(errp, errno, "failed to enable container");
                ret = -errno;
                goto enable_discards_exit;
            }
        } else {
            container->prereg_listener = vfio_prereg_listener;

            memory_listener_register(&container->prereg_listener,
                                     &address_space_memory);
            if (container->error) {
                memory_listener_unregister(&container->prereg_listener);
                ret = -1;
                error_propagate_prepend(errp, container->error,
                    "RAM memory listener initialization failed: ");
                goto enable_discards_exit;
            }
        }

        info.argsz = sizeof(info);
        ret = ioctl(fd, VFIO_IOMMU_SPAPR_TCE_GET_INFO, &info);
        if (ret) {
            error_setg_errno(errp, errno,
                             "VFIO_IOMMU_SPAPR_TCE_GET_INFO failed");
            ret = -errno;
            if (v2) {
                memory_listener_unregister(&container->prereg_listener);
            }
            goto enable_discards_exit;
        }

        if (v2) {
            container->pgsizes = info.ddw.pgsizes;
            /*
             * There is a default window in just created container.
             * To make region_add/del simpler, we better remove this
             * window now and let those iommu_listener callbacks
             * create/remove them when needed.
             */
            ret = vfio_spapr_remove_window(container, info.dma32_window_start);
            if (ret) {
                error_setg_errno(errp, -ret,
                                 "failed to remove existing window");
                goto enable_discards_exit;
            }
        } else {
            /* The default table uses 4K pages */
            container->pgsizes = 0x1000;
            vfio_host_win_add(container, info.dma32_window_start,
                              info.dma32_window_start +
                              info.dma32_window_size - 1,
                              0x1000);
        }
    }
    }

    vfio_kvm_device_add_group(group);

    QLIST_INIT(&container->group_list);
    QLIST_INSERT_HEAD(&space->containers, container, next);

    group->container = container;
    QLIST_INSERT_HEAD(&container->group_list, group, container_next);

    container->listener = vfio_memory_listener;

    memory_listener_register(&container->listener, container->space->as);

    if (container->error) {
        ret = -1;
        error_propagate_prepend(errp, container->error,
            "memory listener initialization failed: ");
        goto listener_release_exit;
    }

    container->initialized = true;

    return 0;
listener_release_exit:
    QLIST_REMOVE(group, container_next);
    QLIST_REMOVE(container, next);
    vfio_kvm_device_del_group(group);
    vfio_listener_release(container);

enable_discards_exit:
    vfio_ram_block_discard_disable(container, false);

free_container_exit:
    g_free(container);

close_fd_exit:
    close(fd);

put_space_exit:
    vfio_put_address_space(space);

    return ret;
}

static void vfio_disconnect_container(VFIOGroup *group)
{
    VFIOContainer *container = group->container;

    QLIST_REMOVE(group, container_next);
    group->container = NULL;

    /*
     * Explicitly release the listener first before unset container,
     * since unset may destroy the backend container if it's the last
     * group.
     */
    if (QLIST_EMPTY(&container->group_list)) {
        vfio_listener_release(container);
    }

    if (ioctl(group->fd, VFIO_GROUP_UNSET_CONTAINER, &container->fd)) {
        error_report("vfio: error disconnecting group %d from container",
                     group->groupid);
    }

    if (QLIST_EMPTY(&container->group_list)) {
        VFIOAddressSpace *space = container->space;
        VFIOGuestIOMMU *giommu, *tmp;
        VFIOHostDMAWindow *hostwin, *next;

        QLIST_REMOVE(container, next);

        QLIST_FOREACH_SAFE(giommu, &container->giommu_list, giommu_next, tmp) {
            memory_region_unregister_iommu_notifier(
                    MEMORY_REGION(giommu->iommu), &giommu->n);
            QLIST_REMOVE(giommu, giommu_next);
            g_free(giommu);
        }

        QLIST_FOREACH_SAFE(hostwin, &container->hostwin_list, hostwin_next,
                           next) {
            QLIST_REMOVE(hostwin, hostwin_next);
            g_free(hostwin);
        }

        trace_vfio_disconnect_container(container->fd);
        close(container->fd);
        g_free(container);

        vfio_put_address_space(space);
    }
}

VFIOGroup *vfio_get_group(int groupid, AddressSpace *as, Error **errp)
{
    VFIOGroup *group;
    char path[32];
    struct vfio_group_status status = { .argsz = sizeof(status) };

    QLIST_FOREACH(group, &vfio_group_list, next) {
        if (group->groupid == groupid) {
            /* Found it.  Now is it already in the right context? */
            if (group->container->space->as == as) {
                return group;
            } else {
                error_setg(errp, "group %d used in multiple address spaces",
                           group->groupid);
                return NULL;
            }
        }
    }

    group = g_malloc0(sizeof(*group));

    snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
    group->fd = qemu_open_old(path, O_RDWR);
    if (group->fd < 0) {
        error_setg_errno(errp, errno, "failed to open %s", path);
        goto free_group_exit;
    }

    if (ioctl(group->fd, VFIO_GROUP_GET_STATUS, &status)) {
        error_setg_errno(errp, errno, "failed to get group %d status", groupid);
        goto close_fd_exit;
    }

    if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        error_setg(errp, "group %d is not viable", groupid);
        error_append_hint(errp,
                          "Please ensure all devices within the iommu_group "
                          "are bound to their vfio bus driver.\n");
        goto close_fd_exit;
    }

    group->groupid = groupid;
    QLIST_INIT(&group->device_list);

    if (vfio_connect_container(group, as, errp)) {
        error_prepend(errp, "failed to setup container for group %d: ",
                      groupid);
        goto close_fd_exit;
    }

    if (QLIST_EMPTY(&vfio_group_list)) {
        qemu_register_reset(vfio_reset_handler, NULL);
    }

    QLIST_INSERT_HEAD(&vfio_group_list, group, next);

    return group;

close_fd_exit:
    close(group->fd);

free_group_exit:
    g_free(group);

    return NULL;
}

void vfio_put_group(VFIOGroup *group)
{
    if (!group || !QLIST_EMPTY(&group->device_list)) {
        return;
    }

    if (!group->ram_block_discard_allowed) {
        vfio_ram_block_discard_disable(group->container, false);
    }
    vfio_kvm_device_del_group(group);
    vfio_disconnect_container(group);
    QLIST_REMOVE(group, next);
    trace_vfio_put_group(group->fd);
    close(group->fd);
    g_free(group);

    if (QLIST_EMPTY(&vfio_group_list)) {
        qemu_unregister_reset(vfio_reset_handler, NULL);
    }
}

int vfio_group_get_device(VFIOGroup *group, const char *name,
                          VFIODevice *vbasedev, Error **errp)
{
    struct vfio_device_info dev_info = { .argsz = sizeof(dev_info) };
    int ret, fd;

    fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, name);
    if (fd < 0) {
        error_setg_errno(errp, errno, "error getting device from group %d",
                         group->groupid);
        error_append_hint(errp,
                      "Verify all devices in group %d are bound to vfio-<bus> "
                      "or pci-stub and not already in use\n", group->groupid);
        return fd;
    }

    ret = ioctl(fd, VFIO_DEVICE_GET_INFO, &dev_info);
    if (ret) {
        error_setg_errno(errp, errno, "error getting device info");
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
            close(fd);
            return -1;
        }

        if (!group->ram_block_discard_allowed) {
            group->ram_block_discard_allowed = true;
            vfio_ram_block_discard_disable(group->container, false);
        }
    }

    vbasedev->fd = fd;
    vbasedev->group = group;
    QLIST_INSERT_HEAD(&group->device_list, vbasedev, next);

    vbasedev->num_irqs = dev_info.num_irqs;
    vbasedev->num_regions = dev_info.num_regions;
    vbasedev->flags = dev_info.flags;

    trace_vfio_group_get_device(name, dev_info.flags, dev_info.num_regions,
                                dev_info.num_irqs);

    vbasedev->reset_works = !!(dev_info.flags & VFIO_DEVICE_FLAGS_RESET);
    return 0;
}

void vfio_put_base_device(VFIODevice *vbasedev)
{
    if (!vbasedev->group) {
        return;
    }
    QLIST_REMOVE(vbasedev, next);
    vbasedev->group = NULL;
    trace_vfio_put_base_device(vbasedev->fd);
    close(vbasedev->fd);
}

/* FIXME: should below code be in common.c? */
/*
 * Interfaces for IBM EEH (Enhanced Error Handling)
 */
static bool vfio_eeh_container_ok(VFIOContainer *container)
{
    /*
     * As of 2016-03-04 (linux-4.5) the host kernel EEH/VFIO
     * implementation is broken if there are multiple groups in a
     * container.  The hardware works in units of Partitionable
     * Endpoints (== IOMMU groups) and the EEH operations naively
     * iterate across all groups in the container, without any logic
     * to make sure the groups have their state synchronized.  For
     * certain operations (ENABLE) that might be ok, until an error
     * occurs, but for others (GET_STATE) it's clearly broken.
     */

    /*
     * XXX Once fixed kernels exist, test for them here
     */

    if (QLIST_EMPTY(&container->group_list)) {
        return false;
    }

    if (QLIST_NEXT(QLIST_FIRST(&container->group_list), container_next)) {
        return false;
    }

    return true;
}

static int vfio_eeh_container_op(VFIOContainer *container, uint32_t op)
{
    struct vfio_eeh_pe_op pe_op = {
        .argsz = sizeof(pe_op),
        .op = op,
    };
    int ret;

    if (!vfio_eeh_container_ok(container)) {
        error_report("vfio/eeh: EEH_PE_OP 0x%x: "
                     "kernel requires a container with exactly one group", op);
        return -EPERM;
    }

    ret = ioctl(container->fd, VFIO_EEH_PE_OP, &pe_op);
    if (ret < 0) {
        error_report("vfio/eeh: EEH_PE_OP 0x%x failed: %m", op);
        return -errno;
    }

    return ret;
}

static VFIOContainer *vfio_eeh_as_container(AddressSpace *as)
{
    VFIOAddressSpace *space = vfio_get_address_space(as);
    VFIOContainer *container = NULL;

    if (QLIST_EMPTY(&space->containers)) {
        /* No containers to act on */
        goto out;
    }

    container = QLIST_FIRST(&space->containers);

    if (QLIST_NEXT(container, next)) {
        /* We don't yet have logic to synchronize EEH state across
         * multiple containers */
        container = NULL;
        goto out;
    }

out:
    vfio_put_address_space(space);
    return container;
}

bool vfio_eeh_as_ok(AddressSpace *as)
{
    VFIOContainer *container = vfio_eeh_as_container(as);

    return (container != NULL) && vfio_eeh_container_ok(container);
}

int vfio_eeh_as_op(AddressSpace *as, uint32_t op)
{
    VFIOContainer *container = vfio_eeh_as_container(as);

    if (!container) {
        return -ENODEV;
    }
    return vfio_eeh_container_op(container, op);
}
