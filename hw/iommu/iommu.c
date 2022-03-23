/*
 * QEMU abstract of IOMMU
 *
 * Copyright (C) 2022 Intel Corporation.
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
#ifdef CONFIG_KVM
#include <linux/kvm.h>
#endif
#include <sys/ioctl.h>
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
#include "qemu/error-report.h"
#include "hw/iommu/iommu.h"
#include <linux/vfio.h>

IOMMUDeviceList iommu_device_list =
    QLIST_HEAD_INITIALIZER(iommu_device_list);
static QLIST_HEAD(, IOMMUAddressSpace) iommu_address_spaces =
    QLIST_HEAD_INITIALIZER(iommu_address_spaces);

int iommufd_users = 0;
int iommufd = -1;

/*
 * DMA - Mapping and unmapping for the "type1" IOMMU interface used on x86
 */
static int vfio_dma_unmap(IOMMUContainer *container,
                          hwaddr iova, ram_addr_t size,
                          IOMMUTLBEntry *iotlb)
{
    return iommufd_unmap_dma(container->iommufd,
                             container->ioas_id, iova, size);
}

static int vfio_dma_map(IOMMUContainer *container, hwaddr iova,
                        ram_addr_t size, void *vaddr, bool readonly)
{
    return iommufd_map_dma(container->iommufd, container->ioas_id,
                           iova, size, vaddr, readonly);
}

static void vfio_host_win_add(IOMMUContainer *container,
                              hwaddr min_iova, hwaddr max_iova,
                              uint64_t iova_pgsizes)
{
    IOMMUHostDMAWindow *hostwin;

    QLIST_FOREACH(hostwin, &container->hostwin_list, hostwin_next) {
        if (ranges_overlap(hostwin->min_iova,
                           hostwin->max_iova - hostwin->min_iova + 1,
                           min_iova,
                           max_iova - min_iova + 1)) {
            hw_error("%s: Overlapped IOMMU are not enabled", __func__);
        }
    }

    hostwin = g_malloc0(sizeof(*hostwin));

    hostwin->min_iova = min_iova;
    hostwin->max_iova = max_iova;
    hostwin->iova_pgsizes = iova_pgsizes;
    QLIST_INSERT_HEAD(&container->hostwin_list, hostwin, hostwin_next);
}

static bool vfio_listener_skipped_section(MemoryRegionSection *section)
{
    return (!memory_region_is_ram(section->mr) &&
            !memory_region_is_iommu(section->mr)) ||
           /*
            * Sizing an enabled 64-bit BAR can cause spurious mappings to
            * addresses in the upper part of the 64-bit address space.  These
            * are never accessed by the CPU and beyond the address width of
            * some IOMMU hardware.  TODO: IOMMU should tell us the IOMMU width.
            */
           section->offset_within_address_space & (1ULL << 63);
}

/* Called with rcu_read_lock held.  */
static bool vfio_get_xlat_addr(IOMMUTLBEntry *iotlb, void **vaddr,
                               ram_addr_t *ram_addr, bool *read_only)
{
    MemoryRegion *mr;
    hwaddr xlat;
    hwaddr len = iotlb->addr_mask + 1;
    bool writable = iotlb->perm & IOMMU_WO;

    /*
     * The IOMMU TLB entry we have just covers translation through
     * this IOMMU to its immediate target.  We need to translate
     * it the rest of the way through to memory.
     */
    mr = address_space_translate(&address_space_memory,
                                 iotlb->translated_addr,
                                 &xlat, &len, writable,
                                 MEMTXATTRS_UNSPECIFIED);
    if (!memory_region_is_ram(mr)) {
        error_report("iommu map to non memory area %"HWADDR_PRIx"",
                     xlat);
        return false;
    } else if (memory_region_has_ram_discard_manager(mr)) {
        RamDiscardManager *rdm = memory_region_get_ram_discard_manager(mr);
        MemoryRegionSection tmp = {
            .mr = mr,
            .offset_within_region = xlat,
            .size = int128_make64(len),
        };

        /*
         * Malicious VMs can map memory into the IOMMU, which is expected
         * to remain discarded. vfio will pin all pages, populating memory.
         * Disallow that. vmstate priorities make sure any RamDiscardManager
         * were already restored before IOMMUs are restored.
         */
        if (!ram_discard_manager_is_populated(rdm, &tmp)) {
            error_report("iommu map to discarded memory (e.g., unplugged via"
                         " virtio-mem): %"HWADDR_PRIx"",
                         iotlb->translated_addr);
            return false;
        }

        /*
         * Malicious VMs might trigger discarding of IOMMU-mapped memory. The
         * pages will remain pinned inside vfio until unmapped, resulting in a
         * higher memory consumption than expected. If memory would get
         * populated again later, there would be an inconsistency between pages
         * pinned by vfio and pages seen by QEMU. This is the case until
         * unmapped from the IOMMU (e.g., during device reset).
         *
         * With malicious guests, we really only care about pinning more memory
         * than expected. RLIMIT_MEMLOCK set for the user/process can never be
         * exceeded and can be used to mitigate this problem.
         */
        warn_report_once("Using vfio with vIOMMUs and coordinated discarding of"
                         " RAM (e.g., virtio-mem) works, however, malicious"
                         " guests can trigger pinning of more memory than"
                         " intended via an IOMMU. It's possible to mitigate "
                         " by setting/adjusting RLIMIT_MEMLOCK.");
    }

    /*
     * Translation truncates length to the IOMMU page size,
     * check that it did not truncate too much.
     */
    if (len & iotlb->addr_mask) {
        error_report("iommu has granularity incompatible with target AS");
        return false;
    }

    if (vaddr) {
        *vaddr = memory_region_get_ram_ptr(mr) + xlat;
    }

    if (ram_addr) {
        *ram_addr = memory_region_get_ram_addr(mr) + xlat;
    }

    if (read_only) {
        *read_only = !writable || mr->readonly;
    }

    return true;
}

static void vfio_iommu_map_notify(IOMMUNotifier *n, IOMMUTLBEntry *iotlb)
{
    IOMMUGuestIOMMU *giommu = container_of(n, IOMMUGuestIOMMU, n);
    IOMMUContainer *container = giommu->container;
    hwaddr iova = iotlb->iova + giommu->iommu_offset;
    void *vaddr;
    int ret;

//    trace_vfio_iommu_map_notify(iotlb->perm == IOMMU_NONE ? "UNMAP" : "MAP",
//                                iova, iova + iotlb->addr_mask);

    if (iotlb->target_as != &address_space_memory) {
        error_report("Wrong target AS \"%s\", only system memory is allowed",
                     iotlb->target_as->name ? iotlb->target_as->name : "none");
        return;
    }

    rcu_read_lock();

    if ((iotlb->perm & IOMMU_RW) != IOMMU_NONE) {
        bool read_only;

        if (!vfio_get_xlat_addr(iotlb, &vaddr, NULL, &read_only)) {
            goto out;
        }
        /*
         * vaddr is only valid until rcu_read_unlock(). But after
         * vfio_dma_map has set up the mapping the pages will be
         * pinned by the kernel. This makes sure that the RAM backend
         * of vaddr will always be there, even if the memory object is
         * destroyed and its backing memory munmap-ed.
         */
        ret = vfio_dma_map(container, iova,
                           iotlb->addr_mask + 1, vaddr,
                           read_only);
        if (ret) {
            error_report("vfio_dma_map(%p, 0x%"HWADDR_PRIx", "
                         "0x%"HWADDR_PRIx", %p) = %d (%m)",
                         container, iova,
                         iotlb->addr_mask + 1, vaddr, ret);
        }
    } else {
        ret = vfio_dma_unmap(container, iova, iotlb->addr_mask + 1, iotlb);
        if (ret) {
            error_report("vfio_dma_unmap(%p, 0x%"HWADDR_PRIx", "
                         "0x%"HWADDR_PRIx") = %d (%m)",
                         container, iova,
                         iotlb->addr_mask + 1, ret);
        }
    }
out:
    rcu_read_unlock();
}

static void vfio_ram_discard_notify_discard(RamDiscardListener *rdl,
                                            MemoryRegionSection *section)
{
    IOMMURamDiscardListener *vrdl = container_of(rdl, IOMMURamDiscardListener,
                                                listener);
    const hwaddr size = int128_get64(section->size);
    const hwaddr iova = section->offset_within_address_space;
    int ret;

    /* Unmap with a single call. */
    ret = vfio_dma_unmap(vrdl->container, iova, size , NULL);
    if (ret) {
        error_report("%s: vfio_dma_unmap() failed: %s", __func__,
                     strerror(-ret));
    }
}

static int vfio_ram_discard_notify_populate(RamDiscardListener *rdl,
                                            MemoryRegionSection *section)
{
    IOMMURamDiscardListener *vrdl = container_of(rdl, IOMMURamDiscardListener,
                                                listener);
    const hwaddr end = section->offset_within_region +
                       int128_get64(section->size);
    hwaddr start, next, iova;
    void *vaddr;
    int ret;

    /*
     * Map in (aligned within memory region) minimum granularity, so we can
     * unmap in minimum granularity later.
     */
    for (start = section->offset_within_region; start < end; start = next) {
        next = ROUND_UP(start + 1, vrdl->granularity);
        next = MIN(next, end);

        iova = start - section->offset_within_region +
               section->offset_within_address_space;
        vaddr = memory_region_get_ram_ptr(section->mr) + start;

        ret = vfio_dma_map(vrdl->container, iova, next - start,
                           vaddr, section->readonly);
        if (ret) {
            /* Rollback */
            vfio_ram_discard_notify_discard(rdl, section);
            return ret;
        }
    }
    return 0;
}

static void vfio_register_ram_discard_listener(IOMMUContainer *container,
                                               MemoryRegionSection *section)
{
    RamDiscardManager *rdm = memory_region_get_ram_discard_manager(section->mr);
    IOMMURamDiscardListener *vrdl;

    /* Ignore some corner cases not relevant in practice. */
    g_assert(QEMU_IS_ALIGNED(section->offset_within_region, TARGET_PAGE_SIZE));
    g_assert(QEMU_IS_ALIGNED(section->offset_within_address_space,
                             TARGET_PAGE_SIZE));
    g_assert(QEMU_IS_ALIGNED(int128_get64(section->size), TARGET_PAGE_SIZE));

    vrdl = g_new0(IOMMURamDiscardListener, 1);
    vrdl->container = container;
    vrdl->mr = section->mr;
    vrdl->offset_within_address_space = section->offset_within_address_space;
    vrdl->size = int128_get64(section->size);
    vrdl->granularity = ram_discard_manager_get_min_granularity(rdm,
                                                                section->mr);

    g_assert(vrdl->granularity && is_power_of_2(vrdl->granularity));
    g_assert(container->pgsizes &&
             vrdl->granularity >= 1ULL << ctz64(container->pgsizes));

    ram_discard_listener_init(&vrdl->listener,
                              vfio_ram_discard_notify_populate,
                              vfio_ram_discard_notify_discard, true);
    ram_discard_manager_register_listener(rdm, &vrdl->listener, section);
    QLIST_INSERT_HEAD(&container->vrdl_list, vrdl, next);

    /*
     * Sanity-check if we have a theoretically problematic setup where we could
     * exceed the maximum number of possible DMA mappings over time. We assume
     * that each mapped section in the same address space as a RamDiscardManager
     * section consumes exactly one DMA mapping, with the exception of
     * RamDiscardManager sections; i.e., we don't expect to have gIOMMU sections
     * in the same address space as RamDiscardManager sections.
     *
     * We assume that each section in the address space consumes one memslot.
     * We take the number of KVM memory slots as a best guess for the maximum
     * number of sections in the address space we could have over time,
     * also consuming DMA mappings.
     */
    if (container->dma_max_mappings) {
        unsigned int vrdl_count = 0, vrdl_mappings = 0, max_memslots = 512;

#ifdef CONFIG_KVM
        if (kvm_enabled()) {
            max_memslots = kvm_get_max_memslots();
        }
#endif

        QLIST_FOREACH(vrdl, &container->vrdl_list, next) {
            hwaddr start, end;

            start = QEMU_ALIGN_DOWN(vrdl->offset_within_address_space,
                                    vrdl->granularity);
            end = ROUND_UP(vrdl->offset_within_address_space + vrdl->size,
                           vrdl->granularity);
            vrdl_mappings += (end - start) / vrdl->granularity;
            vrdl_count++;
        }

        if (vrdl_mappings + max_memslots - vrdl_count >
            container->dma_max_mappings) {
            warn_report("%s: possibly running out of DMA mappings. E.g., try"
                        " increasing the 'block-size' of virtio-mem devies."
                        " Maximum possible DMA mappings: %d, Maximum possible"
                        " memslots: %d", __func__, container->dma_max_mappings,
                        max_memslots);
        }
    }
}

static void vfio_unregister_ram_discard_listener(IOMMUContainer *container,
                                                 MemoryRegionSection *section)
{
    RamDiscardManager *rdm = memory_region_get_ram_discard_manager(section->mr);
    IOMMURamDiscardListener *vrdl = NULL;

    QLIST_FOREACH(vrdl, &container->vrdl_list, next) {
        if (vrdl->mr == section->mr &&
            vrdl->offset_within_address_space ==
            section->offset_within_address_space) {
            break;
        }
    }

    if (!vrdl) {
        hw_error("vfio: Trying to unregister missing RAM discard listener");
    }

    ram_discard_manager_unregister_listener(rdm, &vrdl->listener);
    QLIST_REMOVE(vrdl, next);
    g_free(vrdl);
}

static void vfio_listener_region_add(MemoryListener *listener,
                                     MemoryRegionSection *section)
{
    IOMMUContainer *container = container_of(listener, IOMMUContainer, listener);
    hwaddr iova, end;
    Int128 llend, llsize;
    void *vaddr;
    int ret;
    IOMMUHostDMAWindow *hostwin;
    bool hostwin_found;
    Error *err = NULL;

    if (vfio_listener_skipped_section(section)) {
//        trace_vfio_listener_region_add_skip(
//                section->offset_within_address_space,
//                section->offset_within_address_space +
//                int128_get64(int128_sub(section->size, int128_one())));
        return;
    }

    if (unlikely((section->offset_within_address_space &
                  ~qemu_real_host_page_mask) !=
                 (section->offset_within_region & ~qemu_real_host_page_mask))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    iova = REAL_HOST_PAGE_ALIGN(section->offset_within_address_space);
    llend = int128_make64(section->offset_within_address_space);
    llend = int128_add(llend, section->size);
    llend = int128_and(llend, int128_exts64(qemu_real_host_page_mask));

    if (int128_ge(int128_make64(iova), llend)) {
        return;
    }
    end = int128_get64(int128_sub(llend, int128_one()));

    hostwin_found = false;
    QLIST_FOREACH(hostwin, &container->hostwin_list, hostwin_next) {
        if (hostwin->min_iova <= iova && end <= hostwin->max_iova) {
            hostwin_found = true;
            break;
        }
    }

    if (!hostwin_found) {
        error_setg(&err, "Container %p can't map guest IOVA region"
                   " 0x%"HWADDR_PRIx"..0x%"HWADDR_PRIx, container, iova, end);
        goto fail;
    }

    memory_region_ref(section->mr);

    if (memory_region_is_iommu(section->mr)) {
        IOMMUGuestIOMMU *giommu;
        IOMMUMemoryRegion *iommu_mr = IOMMU_MEMORY_REGION(section->mr);
        int iommu_idx;

//        trace_vfio_listener_region_add_iommu(iova, end);
        /*
         * FIXME: For IOMMU iommu types which have KVM acceleration to
         * avoid bouncing all map/unmaps through qemu this way, this
         * would be the right place to wire that up (tell the KVM
         * device emulation the IOMMU iommu handles to use).
         */
        giommu = g_malloc0(sizeof(*giommu));
        giommu->iommu = iommu_mr;
        giommu->iommu_offset = section->offset_within_address_space -
                               section->offset_within_region;
        giommu->container = container;
        llend = int128_add(int128_make64(section->offset_within_region),
                           section->size);
        llend = int128_sub(llend, int128_one());
        iommu_idx = memory_region_iommu_attrs_to_index(iommu_mr,
                                                       MEMTXATTRS_UNSPECIFIED);
        iommu_notifier_init(&giommu->n, vfio_iommu_map_notify,
                            IOMMU_NOTIFIER_IOTLB_EVENTS,
                            section->offset_within_region,
                            int128_get64(llend),
                            iommu_idx);

        ret = memory_region_iommu_set_page_size_mask(giommu->iommu,
                                                     container->pgsizes,
                                                     &err);
        if (ret) {
            g_free(giommu);
            goto fail;
        }

        ret = memory_region_register_iommu_notifier(section->mr, &giommu->n,
                                                    &err);
        if (ret) {
            g_free(giommu);
            goto fail;
        }
        QLIST_INSERT_HEAD(&container->giommu_list, giommu, giommu_next);
        memory_region_iommu_replay(giommu->iommu, &giommu->n);

        return;
    }

    /* Here we assume that memory_region_is_ram(section->mr)==true */

    /*
     * For RAM memory regions with a RamDiscardManager, we only want to map the
     * actually populated parts - and update the mapping whenever we're notified
     * about changes.
     */
    if (memory_region_has_ram_discard_manager(section->mr)) {
        vfio_register_ram_discard_listener(container, section);
        return;
    }

    vaddr = memory_region_get_ram_ptr(section->mr) +
            section->offset_within_region +
            (iova - section->offset_within_address_space);

//    trace_vfio_listener_region_add_ram(iova, end, vaddr);

    llsize = int128_sub(llend, int128_make64(iova));

    if (memory_region_is_ram_device(section->mr)) {
        hwaddr pgmask = (1ULL << ctz64(hostwin->iova_pgsizes)) - 1;

        if ((iova & pgmask) || (int128_get64(llsize) & pgmask)) {
//            trace_vfio_listener_region_add_no_dma_map(
//                memory_region_name(section->mr),
//                section->offset_within_address_space,
//                int128_getlo(section->size),
//                pgmask + 1);
            return;
        }
    }

    ret = vfio_dma_map(container, iova, int128_get64(llsize),
                       vaddr, section->readonly);
    if (ret) {
        error_setg(&err, "vfio_dma_map(%p, 0x%"HWADDR_PRIx", "
                   "0x%"HWADDR_PRIx", %p) = %d (%m)",
                   container, iova, int128_get64(llsize), vaddr, ret);
        if (memory_region_is_ram_device(section->mr)) {
            /* Allow unexpected mappings not to be fatal for RAM devices */
            error_report_err(err);
            return;
        }
        goto fail;
    }

    return;

fail:
    if (memory_region_is_ram_device(section->mr)) {
        error_report("failed to vfio_dma_map. pci p2p may not work");
        return;
    }
    /*
     * On the initfn path, store the first error in the container so we
     * can gracefully fail.  Runtime, there's not much we can do other
     * than throw a hardware error.
     */
    if (!container->initialized) {
        if (!container->error) {
            error_propagate_prepend(&container->error, err,
                                    "Region %s: ",
                                    memory_region_name(section->mr));
        } else {
            error_free(err);
        }
    } else {
        error_report_err(err);
        hw_error("vfio: DMA mapping failed, unable to continue");
    }
}

static void vfio_listener_region_del(MemoryListener *listener,
                                     MemoryRegionSection *section)
{
    IOMMUContainer *container = container_of(listener, IOMMUContainer, listener);
    hwaddr iova, end;
    Int128 llend, llsize;
    int ret;
    bool try_unmap = true;

    if (vfio_listener_skipped_section(section)) {
//        trace_vfio_listener_region_del_skip(
//                section->offset_within_address_space,
//                section->offset_within_address_space +
//                int128_get64(int128_sub(section->size, int128_one())));
        return;
    }

    if (unlikely((section->offset_within_address_space &
                  ~qemu_real_host_page_mask) !=
                 (section->offset_within_region & ~qemu_real_host_page_mask))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    if (memory_region_is_iommu(section->mr)) {
        IOMMUGuestIOMMU *giommu;

        QLIST_FOREACH(giommu, &container->giommu_list, giommu_next) {
            if (MEMORY_REGION(giommu->iommu) == section->mr &&
                giommu->n.start == section->offset_within_region) {
                memory_region_unregister_iommu_notifier(section->mr,
                                                        &giommu->n);
                QLIST_REMOVE(giommu, giommu_next);
                g_free(giommu);
                break;
            }
        }

        /*
         * FIXME: We assume the one big unmap below is adequate to
         * remove any individual page mappings in the IOMMU which
         * might have been copied into IOMMU. This works for a page table
         * based IOMMU where a big unmap flattens a large range of IO-PTEs.
         * That may not be true for all IOMMU types.
         */
    }

    iova = REAL_HOST_PAGE_ALIGN(section->offset_within_address_space);
    llend = int128_make64(section->offset_within_address_space);
    llend = int128_add(llend, section->size);
    llend = int128_and(llend, int128_exts64(qemu_real_host_page_mask));

    if (int128_ge(int128_make64(iova), llend)) {
        return;
    }
    end = int128_get64(int128_sub(llend, int128_one()));

    llsize = int128_sub(llend, int128_make64(iova));

//    trace_vfio_listener_region_del(iova, end);

    if (memory_region_is_ram_device(section->mr)) {
        hwaddr pgmask;
        IOMMUHostDMAWindow *hostwin;
        bool hostwin_found = false;

        QLIST_FOREACH(hostwin, &container->hostwin_list, hostwin_next) {
            if (hostwin->min_iova <= iova && end <= hostwin->max_iova) {
                hostwin_found = true;
                break;
            }
        }
        assert(hostwin_found); /* or region_add() would have failed */

        pgmask = (1ULL << ctz64(hostwin->iova_pgsizes)) - 1;
        try_unmap = !((iova & pgmask) || (int128_get64(llsize) & pgmask));
    } else if (memory_region_has_ram_discard_manager(section->mr)) {
        vfio_unregister_ram_discard_listener(container, section);
        /* Unregistering will trigger an unmap. */
        try_unmap = false;
    }

    if (try_unmap) {
        if (int128_eq(llsize, int128_2_64())) {
            /* The unmap ioctl doesn't accept a full 64-bit span. */
            llsize = int128_rshift(llsize, 1);
            ret = vfio_dma_unmap(container, iova, int128_get64(llsize), NULL);
            if (ret) {
                error_report("vfio_dma_unmap(%p, 0x%"HWADDR_PRIx", "
                             "0x%"HWADDR_PRIx") = %d (%m)",
                             container, iova, int128_get64(llsize), ret);
            }
            iova += int128_get64(llsize);
        }
        ret = vfio_dma_unmap(container, iova, int128_get64(llsize), NULL);
        if (ret) {
            error_report("vfio_dma_unmap(%p, 0x%"HWADDR_PRIx", "
                         "0x%"HWADDR_PRIx") = %d (%m)",
                         container, iova, int128_get64(llsize), ret);
        }
    }

    memory_region_unref(section->mr);
}

static const MemoryListener vfio_memory_listener = {
    .region_add = vfio_listener_region_add,
    .region_del = vfio_listener_region_del,
};

static void vfio_listener_release(IOMMUContainer *container)
{
    memory_listener_unregister(&container->listener);
    if (container->iommu_type == VFIO_SPAPR_TCE_v2_IOMMU) {
        memory_listener_unregister(&container->prereg_listener);
    }
}

int iommu_ram_block_discard_disable(IOMMUContainer *container, bool state)
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
         * IOMMU_SPAPR_TCE_IOMMU most probably works just fine with
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

static IOMMUAddressSpace *iommu_get_address_space(AddressSpace *as)
{
    IOMMUAddressSpace *space;

    QLIST_FOREACH(space, &iommu_address_spaces, list) {
        if (space->as == as) {
            return space;
        }
    }

    /* No suitable IOMMUAddressSpace, create a new one */
    space = g_malloc0(sizeof(*space));
    space->as = as;
    QLIST_INIT(&space->containers);

    QLIST_INSERT_HEAD(&iommu_address_spaces, space, list);

    return space;
}

static void iommu_put_address_space(IOMMUAddressSpace *space)
{
    if (QLIST_EMPTY(&space->containers)) {
        QLIST_REMOVE(space, list);
        g_free(space);
    }
}

static int iommu_get_ioas(int *fd, uint32_t *ioas_id)
{
    *fd = iommufd_get();
    if (*fd < 0) {
        return -ENODEV;
    }

    return iommufd_alloc_ioas(*fd, ioas_id);
}

static void iommu_put_ioas(int fd, uint32_t ioas_id)
{
    iommufd_free_ioas(fd, ioas_id);
    iommufd_put(fd);
}

static void iommu_device_detach_ioas(IOMMUDevice *idev, int fd, uint32_t ioas_id)
{
    idev->ops->detach_ioas(idev, fd, ioas_id);
}

static int iommu_device_connect_ioas(IOMMUDevice *idev, int fd,
                                     uint32_t ioas_id, Error **errp)
{
    int ret;

    ret = idev->ops->bind_iommufd(idev, fd);
    if (ret) {
        error_setg_errno(errp, errno, "error bind iommufd");
        return ret;
    }

    ret = idev->ops->attach_ioas(idev, fd, ioas_id);
    if (ret) {
        error_setg_errno(errp, errno, "error attach ioas");
    }

    return ret;
}

int iommu_device_attach_container(IOMMUDevice *idev,
                                  IOMMUContainer *container, Error **errp)
{
    return iommu_device_connect_ioas(idev, container->iommufd,
                                     container->ioas_id, errp);
}

static int iommu_device_connect_container(IOMMUDevice *idev,
                                          AddressSpace *as, Error **errp)
{
    IOMMUContainer *container;
    int ret, fd;
    uint32_t ioas_id, iova_pgsizes;
    IOMMUAddressSpace *space;

    space = iommu_get_address_space(as);

    /*
     * IOMMU is currently incompatible with discarding of RAM insofar as the
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
     * with some IOMMU types. iommu_ram_block_discard_disable() handles the
     * details once we know which type of IOMMU we are using.
     */

    QLIST_FOREACH(container, &space->containers, next) {
        if (!iommu_device_attach_container(idev, container, errp)) {
            ret = iommu_ram_block_discard_disable(container, true);
            if (ret) {
                iommu_device_detach_ioas(idev, container->iommufd, container->ioas_id);
                error_setg_errno(errp, -ret,
                                 "Cannot set discarding of RAM broken");
                goto put_space_exit;
            }
            idev->container = container;
            QLIST_INSERT_HEAD(&container->device_list, idev, container_next);
//          vfio_kvm_device_add_group(group);
            return 0;
        }
    }

    // Equal to open(/dev/vfio/vfio);
    ret = iommu_get_ioas(&fd, &ioas_id);
    if (ret) {
        error_setg_errno(errp, errno, "error alloc ioas");
        goto put_space_exit;
    }

    ret = iommu_device_connect_ioas(idev, fd, ioas_id, errp);
    if (ret) {
        goto put_ioas_exit;
    }

    container = g_malloc0(sizeof(*container));
    container->space = space;
    container->iommufd = fd;
    container->ioas_id = ioas_id;
    container->error = NULL;
    container->dirty_pages_supported = false;
    container->dma_max_mappings = 0;
    QLIST_INIT(&container->giommu_list);
    QLIST_INIT(&container->hostwin_list);
    QLIST_INIT(&container->vrdl_list);
    container->iommu_type = VFIO_TYPE1v2_IOMMU;

    ret = iommu_ram_block_discard_disable(container, true);
    if (ret) {
        error_setg_errno(errp, -ret, "Cannot set discarding of RAM broken");
        goto free_container_exit;
    }

    /* Assume 4k IOVA page size */
    iova_pgsizes = 4096;
    vfio_host_win_add(container, 0, (hwaddr)-1, iova_pgsizes);
    container->pgsizes = iova_pgsizes;

    /* The default in the kernel ("dma_entry_limit") is 65535. */
    container->dma_max_mappings = 65535;

//    vfio_kvm_device_add_group(group);

    QLIST_INIT(&container->device_list);
    QLIST_INSERT_HEAD(&space->containers, container, next);

    idev->container = container;
    QLIST_INSERT_HEAD(&container->device_list, idev, container_next);

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
    QLIST_REMOVE(idev, container_next);
    QLIST_REMOVE(container, next);
//    vfio_kvm_device_del_group(group);
    vfio_listener_release(container);

    iommu_ram_block_discard_disable(container, false);

free_container_exit:
    g_free(container);
    iommu_device_detach_ioas(idev, fd, ioas_id);

put_ioas_exit:
    iommu_put_ioas(fd, ioas_id);
put_space_exit:
    iommu_put_address_space(space);

    return ret;
}

static void iommu_device_disconnect_container(IOMMUDevice *idev)
{
    IOMMUContainer *container = idev->container;

    QLIST_REMOVE(idev, container_next);
    idev->container = NULL;

    iommu_device_detach_ioas(idev, container->iommufd, container->ioas_id);

    /*
     * Explicitly release the listener first before unset container,
     * since unset may destroy the backend container if it's the last
     * group.
     */
    if (QLIST_EMPTY(&container->device_list)) {
        vfio_listener_release(container);
    }

    if (QLIST_EMPTY(&container->device_list)) {
        IOMMUAddressSpace *space = container->space;
        IOMMUGuestIOMMU *giommu, *tmp;

        QLIST_REMOVE(container, next);

        QLIST_FOREACH_SAFE(giommu, &container->giommu_list, giommu_next, tmp) {
            memory_region_unregister_iommu_notifier(
                    MEMORY_REGION(giommu->iommu), &giommu->n);
            QLIST_REMOVE(giommu, giommu_next);
            g_free(giommu);
        }

//        trace_vfio_disconnect_container(container->fd);
        iommu_put_ioas(container->iommufd, container->ioas_id);
        g_free(container);

        iommu_put_address_space(space);
    }
}

#if 0
static void iommu_reset_handler(void *opaque)
{
    IOMMUDevice *idev;

    QLIST_FOREACH(idev, &iommu_device_list, next) {
        idev->ops->dev_reset(idev);
    }
}
#endif

int iommu_register_device(IOMMUDevice *idev, AddressSpace *as,
                          const IOMMUDeviceOps *ops, Error **errp)
{
    IOMMUDevice *device;
    int ret;

    QLIST_FOREACH(device, &iommu_device_list, next) {
        if (device == idev) {
            /* Found it.  Now is it already in the right context? */
            if (device->container->space->as == as) {
                return 0;
            } else {
                error_setg(errp, "device %p used in multiple address spaces",
                           idev);
                return -EBUSY;
            }
        }
    }

    idev->ops = ops;
    ret = iommu_device_connect_container(idev, as, errp);
    if (ret) {
        error_prepend(errp, "failed to setup container for device %p: ",
                      idev);
        idev->ops = NULL;
        return ret;
    }

//    if (QLIST_EMPTY(&iommu_device_list)) {
//        qemu_register_reset(iommu_reset_handler, NULL);
//    }

    QLIST_INSERT_HEAD(&iommu_device_list, idev, next);

    return 0;
}

void iommu_unregister_device(IOMMUDevice *idev)
{
    iommu_device_disconnect_container(idev);

    idev->ops = NULL;
//    if (QLIST_EMPTY(&iommu_device_list)) {
//        qemu_unregister_reset(iommu_reset_handler, NULL);
//    }
}

int iommufd_get(void)
{
    if (iommufd == -1) {
        iommufd = qemu_open_old("/dev/iommu", O_RDWR);
        if (iommufd < 0) {
            error_report("Failed to open /dev/iommu!\n");
        } else {
            iommufd_users = 1;
        }
        printf("open iommufd: %d\n", iommufd);
    } else {
        iommufd_users++;
    }
    return iommufd;
}

void iommufd_put(int fd)
{
    if (--iommufd_users) {
        return;
    }
    iommufd = -1;
    printf("close iommufd: %d\n", fd);
    close(fd);
}

int iommufd_alloc_ioas(int fd, uint32_t *ioas)
{
    struct iommu_ioas_alloc alloc_data;
    int ret;

    if (fd < 0) {
        return -EINVAL;
    }

    alloc_data.size = sizeof(alloc_data);
    alloc_data.flags = 0;

    ret = ioctl(fd, IOMMU_IOAS_ALLOC, &alloc_data);
    if (ret) {
        error_report("Failed to allocate ioas  %m\n");
    }

    *ioas = alloc_data.out_ioas_id;

    return ret;
}

void iommufd_free_ioas(int fd, uint32_t ioas)
{
    struct iommu_destroy des;

    if (fd < 0) {
        return;
    }

    des.size = sizeof(des);
    des.id = ioas;

    if (ioctl(fd, IOMMU_DESTROY, &des)) {
        error_report("Failed to free ioas: %u  %m\n", ioas);
    }
}

int iommufd_unmap_dma(int iommufd, uint32_t ioas, hwaddr iova, ram_addr_t size)
{
    struct iommu_ioas_unmap unmap;
    int ret;

    memset(&unmap, 0x0, sizeof(unmap));
    unmap.size = sizeof(unmap);
    unmap.ioas_id = ioas;
    unmap.iova = iova;
    unmap.length = size;

    ret = ioctl(iommufd, IOMMU_IOAS_UNMAP, &unmap);
    if (ret) {
        error_report("IOMMU_IOAS_UNMAP failed: %s", strerror(errno));
    }
    return ret;
}

int iommufd_map_dma(int iommufd, uint32_t ioas, hwaddr iova, ram_addr_t size, void *vaddr, bool readonly)
{
    struct iommu_ioas_map map;
    int ret;

    memset(&map, 0x0, sizeof(map));
    map.size = sizeof(map);
    map.flags = IOMMU_IOAS_MAP_READABLE |
                IOMMU_IOAS_MAP_FIXED_IOVA;
    map.ioas_id = ioas;
    map.user_va = (int64_t)vaddr;
    map.iova = iova;
    map.length = size;
    if (!readonly) {
        map.flags |= IOMMU_IOAS_MAP_WRITEABLE;
    }

    ret = ioctl(iommufd, IOMMU_IOAS_MAP, &map);
    if (ret) {
        error_report("IOMMU_IOAS_MAP failed: %s", strerror(errno));
    }
    return ret;
}
