/*
 * VFIO CONTAINER BASE OBJECT
 *
 * Copyright (C) 2022 Intel Corporation.
 *
 * Authors: Yi Liu <yi.l.liu@intel.com>
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
#include "qapi/visitor.h"
#include "hw/vfio/vfio-common.h"

int vfio_container_dma_map(VFIOContainer *cobj,
                           hwaddr iova, ram_addr_t size,
                           void *vaddr, bool readonly)
{
    VFIOContainerClass *vccs;

    if (!cobj) {
        return -EINVAL;
    }

    vccs = VFIO_CONTAINER_GET_CLASS(cobj);
    if (!vccs) {
        return -EINVAL;
    }

    if (!vccs->dma_map) {
        return -EINVAL;
    }

    return vccs->dma_map(cobj, iova, size, vaddr, readonly);
}

int vfio_container_dma_unmap(VFIOContainer *cobj,
                             hwaddr iova, ram_addr_t size,
                             IOMMUTLBEntry *iotlb)
{
    VFIOContainerClass *vccs;

    if (!cobj) {
        return -EINVAL;
    }

    vccs = VFIO_CONTAINER_GET_CLASS(cobj);
    if (!vccs) {
        return -EINVAL;
    }

    if (!vccs->dma_unmap) {
        return -EINVAL;
    }

    return vccs->dma_unmap(cobj, iova, size, iotlb);
}

void vfio_container_set_dirty_page_tracking(VFIOContainer *cobj, bool start)
{
    VFIOContainerClass *vccs;

    if (!cobj) {
        return;
    }

    vccs = VFIO_CONTAINER_GET_CLASS(cobj);
    if (!vccs) {
        return;
    }

    if (!vccs->set_dirty_page_tracking) {
        return;
    }

    vccs->set_dirty_page_tracking(cobj, start);
}

int vfio_container_get_dirty_bitmap(VFIOContainer *cobj, uint64_t iova,
                                    uint64_t size, ram_addr_t ram_addr)
{
    VFIOContainerClass *vccs;

    if (!cobj) {
        return -EINVAL;
    }

    vccs = VFIO_CONTAINER_GET_CLASS(cobj);
    if (!vccs) {
        return -EINVAL;
    }

    if (!vccs->get_dirty_bitmap) {
        return -EINVAL;
    }

    return vccs->get_dirty_bitmap(cobj, iova, size, ram_addr);
}

bool vfio_container_is_spapr(VFIOContainer *cobj)
{
    VFIOContainerClass *vccs;

    if (!cobj) {
        return false;
    }

    vccs = VFIO_CONTAINER_GET_CLASS(cobj);
    if (!vccs) {
        return false;
    }

    if (!vccs->is_spapr) {
        return false;
    }

    return vccs->is_spapr(cobj);
}

void vfio_container_register_listener(VFIOContainer *cobj, const MemoryListener listener)
{
    cobj->listener = listener;

    memory_listener_register(&cobj->listener, cobj->space->as);
}

void vfio_container_release_listener(VFIOContainer *cobj)
{
    memory_listener_unregister(&cobj->listener);
}

void vfio_container_init(void *_cobj, size_t instance_size,
                         const char *mrtypename,
                         VFIOAddressSpace *space)
{
    VFIOContainer *cobj;

    object_initialize(_cobj, instance_size, mrtypename);
    cobj = VFIO_CONTAINER(_cobj);

    cobj->space = space;
    cobj->error = NULL;
    cobj->dirty_pages_supported = false;
    cobj->dma_max_mappings = 0;
    QLIST_INIT(&cobj->giommu_list);
    QLIST_INIT(&cobj->hostwin_list);
    QLIST_INIT(&cobj->vrdl_list);
}

void vfio_container_destroy(VFIOContainer *cobj)
{

}

static void vfio_container_finalize_fn(Object *obj)
{
    VFIOContainer *cobj = VFIO_CONTAINER(obj);

    printf("%s cobj: %p\n", __func__, cobj);
}

static const TypeInfo host_iommu_context_info = {
    .parent             = TYPE_OBJECT,
    .name               = TYPE_VFIO_CONTAINER,
    .class_size         = sizeof(VFIOContainerClass),
    .instance_size      = sizeof(VFIOContainer),
    .instance_finalize  = vfio_container_finalize_fn,
    .abstract           = true,
};

static void vfio_container_register_types(void)
{
    type_register_static(&host_iommu_context_info);
}

type_init(vfio_container_register_types)
