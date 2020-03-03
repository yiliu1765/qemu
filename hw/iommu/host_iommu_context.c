/*
 * QEMU abstract of Host IOMMU
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
#include "qapi/visitor.h"
#include "hw/iommu/host_iommu_context.h"
#include <sys/ioctl.h>
#include "qemu/error-report.h"

int host_iommu_ctx_bind_stage1_pgtbl(HostIOMMUContext *iommu_ctx,
                                     struct iommu_gpasid_bind_data *bind)
{
    if (!iommu_ctx ||
        !(iommu_ctx->info->features & IOMMU_SVA_FEAT_BIND_PGTBL)) {
        return -EINVAL;
    }

    if (ioctl(iommu_ctx->fd, IOMMU_USVA_BIND_PGTBL, bind)) {
        error_report("%s: pasid (%llu) bind failed: %m",
                      __func__, bind->hpasid);
        return -errno;
    } else {
        return 0;
    }
}

int host_iommu_ctx_unbind_stage1_pgtbl(HostIOMMUContext *iommu_ctx,
                                 struct iommu_gpasid_bind_data *unbind)
{
    if (!iommu_ctx ||
        !(iommu_ctx->info->features & IOMMU_SVA_FEAT_BIND_PGTBL)) {
        return -EINVAL;
    }

    if (ioctl(iommu_ctx->fd, IOMMU_USVA_UNBIND_PGTBL, unbind)) {
        error_report("%s: pasid (%llu) unbind failed: %m",
                      __func__, unbind->hpasid);
        return -errno;
    } else {
        return 0;
    }
}

int host_iommu_ctx_flush_stage1_cache(HostIOMMUContext *iommu_ctx,
                                 struct iommu_cache_invalidate_info *cache)
{
    if (!iommu_ctx ||
        !(iommu_ctx->info->features & IOMMU_SVA_FEAT_CACHE_INVLD)) {
        return -EINVAL;
    }

    if (ioctl(iommu_ctx->fd, IOMMU_USVA_FLUSH_CACHE, cache)) {
        error_report("%s: cache flush failed: %m", __func__);
        return -errno;
    } else {
        return 0;
    }
}

void host_iommu_ctx_init(void *_iommu_ctx, size_t instance_size,
                         const char *mrtypename, int fd,
                         struct iommu_sva_info *info)
{
    HostIOMMUContext *iommu_ctx;

    object_initialize(_iommu_ctx, instance_size, mrtypename);
    iommu_ctx = HOST_IOMMU_CONTEXT(_iommu_ctx);
    iommu_ctx->info = g_malloc0(info->argsz);
    memcpy(iommu_ctx->info, info, info->argsz);
    iommu_ctx->fd = fd;
    iommu_ctx->initialized = true;
}

static void host_iommu_ctx_finalize_fn(Object *obj)
{
    HostIOMMUContext *iommu_ctx = HOST_IOMMU_CONTEXT(obj);

    g_free(iommu_ctx->info);
}

static const TypeInfo host_iommu_context_info = {
    .parent             = TYPE_OBJECT,
    .name               = TYPE_HOST_IOMMU_CONTEXT,
    .class_size         = sizeof(HostIOMMUContextClass),
    .instance_size      = sizeof(HostIOMMUContext),
    .instance_finalize  = host_iommu_ctx_finalize_fn,
    .abstract           = false,
};

static void host_iommu_ctx_register_types(void)
{
    type_register_static(&host_iommu_context_info);
}

type_init(host_iommu_ctx_register_types)
