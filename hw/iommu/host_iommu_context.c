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
#include "hw/iommu/host_iommu_context.h"

int host_iommu_ctx_pasid_alloc(HostIOMMUContext *host_icx, uint32_t min,
                               uint32_t max, uint32_t *pasid)
{
    if (host_icx && (host_icx->flags & HOST_IOMMU_PASID_REQUEST) &&
        host_icx->ops && host_icx->ops->pasid_alloc) {
        return host_icx->ops->pasid_alloc(host_icx, min, max, pasid);
    }
    return -ENOENT;
}

int host_iommu_ctx_pasid_free(HostIOMMUContext *host_icx, uint32_t pasid)
{
    if (host_icx && (host_icx->flags & HOST_IOMMU_PASID_REQUEST) &&
        host_icx->ops && host_icx->ops->pasid_free) {
        return host_icx->ops->pasid_free(host_icx, pasid);
    }
    return -ENOENT;
}

void host_iommu_ctx_init(HostIOMMUContext *host_icx,
                         uint64_t flags, HostIOMMUOps *ops)
{
    host_icx->flags = flags;
    host_icx->ops = ops;
}

void host_iommu_ctx_destroy(HostIOMMUContext *host_icx)
{
    host_icx->flags = 0x0;
    host_icx->ops = NULL;
}
