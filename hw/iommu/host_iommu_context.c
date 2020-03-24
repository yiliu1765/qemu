/*
 * QEMU abstract of Host IOMMU
 *
 * Copyright (C) 2020 Intel Corporation.
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
#include "qapi/visitor.h"
#include "hw/iommu/host_iommu_context.h"

int host_iommu_ctx_pasid_alloc(HostIOMMUContext *iommu_ctx, uint32_t min,
                               uint32_t max, uint32_t *pasid)
{
    HostIOMMUContextClass *hicxc;

    if (!iommu_ctx) {
        return -EINVAL;
    }

    hicxc = HOST_IOMMU_CONTEXT_GET_CLASS(iommu_ctx);

    if (!hicxc) {
        return -EINVAL;
    }

    if (!(iommu_ctx->flags & HOST_IOMMU_PASID_REQUEST) ||
        !hicxc->pasid_alloc) {
        return -EINVAL;
    }

    return hicxc->pasid_alloc(iommu_ctx, min, max, pasid);
}

int host_iommu_ctx_pasid_free(HostIOMMUContext *iommu_ctx, uint32_t pasid)
{
    HostIOMMUContextClass *hicxc;

    if (!iommu_ctx) {
        return -EINVAL;
    }

    hicxc = HOST_IOMMU_CONTEXT_GET_CLASS(iommu_ctx);
    if (!hicxc) {
        return -EINVAL;
    }

    if (!(iommu_ctx->flags & HOST_IOMMU_PASID_REQUEST) ||
        !hicxc->pasid_free) {
        return -EINVAL;
    }

    return hicxc->pasid_free(iommu_ctx, pasid);
}

void host_iommu_ctx_init(void *_iommu_ctx, size_t instance_size,
                         const char *mrtypename,
                         uint64_t flags)
{
    HostIOMMUContext *iommu_ctx;

    object_initialize(_iommu_ctx, instance_size, mrtypename);
    iommu_ctx = HOST_IOMMU_CONTEXT(_iommu_ctx);
    iommu_ctx->flags = flags;
    iommu_ctx->initialized = true;
}

static const TypeInfo host_iommu_context_info = {
    .parent             = TYPE_OBJECT,
    .name               = TYPE_HOST_IOMMU_CONTEXT,
    .class_size         = sizeof(HostIOMMUContextClass),
    .instance_size      = sizeof(HostIOMMUContext),
    .abstract           = true,
};

static void host_iommu_ctx_register_types(void)
{
    type_register_static(&host_iommu_context_info);
}

type_init(host_iommu_ctx_register_types)