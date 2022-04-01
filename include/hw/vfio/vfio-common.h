/*
 * common header for vfio based device assignment support
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

#ifndef HW_VFIO_VFIO_COMMON_H
#define HW_VFIO_VFIO_COMMON_H

#include "exec/memory.h"
#include "qemu/queue.h"
#include "qemu/notify.h"
#include "ui/console.h"
#include "hw/display/ramfb.h"
#ifdef CONFIG_LINUX
#include <linux/vfio.h>
#endif
#include "sysemu/sysemu.h"
#include "qom/object.h"
//#include "hw/vfio/vfio-iommu-backend.h"

#define VFIO_MSG_PREFIX "vfio %s: "

extern const MemoryListener vfio_memory_listener;

enum {
    VFIO_DEVICE_TYPE_PCI = 0,
    VFIO_DEVICE_TYPE_PLATFORM = 1,
    VFIO_DEVICE_TYPE_CCW = 2,
    VFIO_DEVICE_TYPE_AP = 3,
};

typedef struct VFIOMmap {
    MemoryRegion mem;
    void *mmap;
    off_t offset;
    size_t size;
} VFIOMmap;

typedef struct VFIORegion {
    struct VFIODevice *vbasedev;
    off_t fd_offset; /* offset of region within device fd */
    MemoryRegion *mem; /* slow, read/write access */
    size_t size;
    uint32_t flags; /* VFIO region flags (rd/wr/mmap) */
    uint32_t nr_mmaps;
    VFIOMmap *mmaps;
    uint8_t nr; /* cache the region number for debug */
} VFIORegion;

typedef struct VFIOMigration {
    struct VFIODevice *vbasedev;
    VMChangeStateEntry *vm_state;
    VFIORegion region;
    uint32_t device_state;
    int vm_running;
    Notifier migration_state;
    uint64_t pending_bytes;
} VFIOMigration;

typedef struct VFIOContainer VFIOContainer;

typedef struct VFIOAddressSpace {
    AddressSpace *as;
    QLIST_HEAD(, VFIOContainer) containers;
    QLIST_ENTRY(VFIOAddressSpace) list;
} VFIOAddressSpace;

struct VFIOGroup;

typedef struct VFIOGuestIOMMU {
    VFIOContainer *container;
    IOMMUMemoryRegion *iommu;
    hwaddr iommu_offset;
    IOMMUNotifier n;
    QLIST_ENTRY(VFIOGuestIOMMU) giommu_next;
} VFIOGuestIOMMU;

typedef struct VFIORamDiscardListener {
    VFIOContainer *container;
    MemoryRegion *mr;
    hwaddr offset_within_address_space;
    hwaddr size;
    uint64_t granularity;
    RamDiscardListener listener;
    QLIST_ENTRY(VFIORamDiscardListener) next;
} VFIORamDiscardListener;

typedef struct VFIOHostDMAWindow {
    hwaddr min_iova;
    hwaddr max_iova;
    uint64_t iova_pgsizes;
    QLIST_ENTRY(VFIOHostDMAWindow) hostwin_next;
} VFIOHostDMAWindow;

typedef struct VFIODeviceOps VFIODeviceOps;

typedef struct VFIODevice {
    QLIST_ENTRY(VFIODevice) next;
    struct VFIOGroup *group;
    char *sysfsdev;
    char *name;
    DeviceState *dev;
    int fd;
    int type;
    bool reset_works;
    bool needs_reset;
    bool no_mmap;
    bool ram_block_discard_allowed;
    bool enable_migration;
    VFIODeviceOps *ops;
    const struct VFIOIOMMUOps *iommu_ops;
    unsigned int num_irqs;
    unsigned int num_regions;
    unsigned int flags;
    VFIOMigration *migration;
    Error *migration_blocker;
    OnOffAuto pre_copy_dirty_page_tracking;
} VFIODevice;

struct VFIODeviceOps {
    void (*vfio_compute_needs_reset)(VFIODevice *vdev);
    int (*vfio_hot_reset_multi)(VFIODevice *vdev);
    void (*vfio_eoi)(VFIODevice *vdev);
    Object *(*vfio_get_object)(VFIODevice *vdev);
    void (*vfio_save_config)(VFIODevice *vdev, QEMUFile *f);
    int (*vfio_load_config)(VFIODevice *vdev, QEMUFile *f);
};

typedef int (*vfio_iommu_dma_map)(VFIOContainer *cobj,
                                  hwaddr iova, ram_addr_t size,
                                  void *vaddr, bool readonly);
typedef int (*vfio_iommu_dma_unmap)(VFIOContainer *cobj,
                                    hwaddr iova, ram_addr_t size,
                                    IOMMUTLBEntry *iotlb);
typedef int (*vfio_iommu_attach_device)(VFIODevice *vbasedev,
                                        AddressSpace *as, Error **errp);
typedef int (*vfio_iommu_detach_device)(VFIODevice *vbasedev,
                                        AddressSpace *as, Error **errp);
typedef void (*vfio_iommu_put_device)(VFIODevice *vbasedev);

typedef enum VFIOIOMMUBackendType {
    VFIO_IOMMU_BACKEND_TYPE_LEGACY = 0,
    VFIO_IOMMU_BACKEND_TYPE_IOMMUFD = 1,
} VFIOIOMMUBackendType;

typedef struct VFIOIOMMUOps {
    VFIOIOMMUBackendType backend_type;
    vfio_iommu_dma_map vfio_iommu_dma_map;
    vfio_iommu_dma_unmap vfio_iommu_dma_unmap;
    vfio_iommu_attach_device  vfio_iommu_attach_device;
    vfio_iommu_detach_device  vfio_iommu_detach_device;
    vfio_iommu_put_device  vfio_iommu_put_device;
} VFIOIOMMUOps;

extern const VFIOIOMMUOps legacy_ops;
extern const VFIOIOMMUOps iommufd_ops;

struct VFIOLegacyContainer;

typedef struct VFIOGroup {
    int fd;
    int groupid;
    struct VFIOLegacyContainer *container;
    QLIST_HEAD(, VFIODevice) device_list;
    QLIST_ENTRY(VFIOGroup) next;
    QLIST_ENTRY(VFIOGroup) container_next;
    bool ram_block_discard_allowed;
} VFIOGroup;

typedef struct VFIODMABuf {
    QemuDmaBuf buf;
    uint32_t pos_x, pos_y, pos_updates;
    uint32_t hot_x, hot_y, hot_updates;
    int dmabuf_id;
    QTAILQ_ENTRY(VFIODMABuf) next;
} VFIODMABuf;

typedef struct VFIODisplay {
    QemuConsole *con;
    RAMFBState *ramfb;
    struct vfio_region_info *edid_info;
    struct vfio_region_gfx_edid *edid_regs;
    uint8_t *edid_blob;
    QEMUTimer *edid_link_timer;
    struct {
        VFIORegion buffer;
        DisplaySurface *surface;
    } region;
    struct {
        QTAILQ_HEAD(, VFIODMABuf) bufs;
        VFIODMABuf *primary;
        VFIODMABuf *cursor;
    } dmabuf;
} VFIODisplay;

void vfio_host_win_add(VFIOContainer *cobj,
                       hwaddr min_iova, hwaddr max_iova,
                       uint64_t iova_pgsizes);
int vfio_host_win_del(VFIOContainer *cobj, hwaddr min_iova,
                      hwaddr max_iova);
void vfio_container_register_listener(VFIOContainer *cobj, const MemoryListener listener);
void vfio_container_release_listener(VFIOContainer *cobj);
VFIOAddressSpace *vfio_get_address_space(AddressSpace *as);
void vfio_put_address_space(VFIOAddressSpace *space);
void vfio_spapr_group_attach(VFIOContainer *cobj, int tablefd);
bool vfio_devices_all_running_and_saving(VFIOContainer *cobj);
bool vfio_devices_all_dirty_tracking(VFIOContainer *cobj);

void vfio_put_base_device(VFIODevice *vbasedev);
void vfio_disable_irqindex(VFIODevice *vbasedev, int index);
void vfio_unmask_single_irqindex(VFIODevice *vbasedev, int index);
void vfio_mask_single_irqindex(VFIODevice *vbasedev, int index);
int vfio_set_irq_signaling(VFIODevice *vbasedev, int index, int subindex,
                           int action, int fd, Error **errp);
void vfio_region_write(void *opaque, hwaddr addr,
                           uint64_t data, unsigned size);
uint64_t vfio_region_read(void *opaque,
                          hwaddr addr, unsigned size);
int vfio_region_setup(Object *obj, VFIODevice *vbasedev, VFIORegion *region,
                      int index, const char *name);
int vfio_region_mmap(VFIORegion *region);
void vfio_region_mmaps_set_enabled(VFIORegion *region, bool enabled);
void vfio_region_unmap(VFIORegion *region);
void vfio_region_exit(VFIORegion *region);
void vfio_region_finalize(VFIORegion *region);
void vfio_reset_handler(void *opaque);

extern const MemoryRegionOps vfio_region_ops;
typedef QLIST_HEAD(VFIOGroupList, VFIOGroup) VFIOGroupList;
extern VFIOGroupList vfio_group_list;

bool vfio_mig_active(void);
int64_t vfio_mig_bytes_transferred(void);

#ifdef CONFIG_LINUX
int vfio_get_region_info(VFIODevice *vbasedev, int index,
                         struct vfio_region_info **info);
int vfio_get_dev_region_info(VFIODevice *vbasedev, uint32_t type,
                             uint32_t subtype, struct vfio_region_info **info);
bool vfio_has_region_cap(VFIODevice *vbasedev, int region, uint16_t cap_type);
struct vfio_info_cap_header *
vfio_get_region_info_cap(struct vfio_region_info *info, uint16_t id);
bool vfio_get_info_dma_avail(struct vfio_iommu_type1_info *info,
                             unsigned int *avail);
struct vfio_info_cap_header *
vfio_get_device_info_cap(struct vfio_device_info *info, uint16_t id);
#endif
extern const MemoryListener vfio_prereg_listener;

int vfio_spapr_create_window(VFIOContainer *cobj,
                             MemoryRegionSection *section,
                             hwaddr *pgsize);
int vfio_spapr_remove_window(VFIOContainer *cobj,
                             hwaddr offset_within_address_space);

int vfio_migration_probe(VFIODevice *vbasedev, Error **errp);
void vfio_migration_finalize(VFIODevice *vbasedev);

#define TYPE_VFIO_CONTAINER "qemu:vfio-container-obj"
#define VFIO_CONTAINER(obj) \
        OBJECT_CHECK(VFIOContainer, (obj), TYPE_VFIO_CONTAINER)
#define VFIO_CONTAINER_CLASS(klass) \
        OBJECT_CLASS_CHECK(VFIOContainerClass, (klass), \
                         TYPE_VFIO_CONTAINER)
#define VFIO_CONTAINER_GET_CLASS(obj) \
        OBJECT_GET_CLASS(VFIOContainerClass, (obj), \
                         TYPE_VFIO_CONTAINER)

typedef struct VFIOContainerClass {
    /* private */
    ObjectClass parent_class;

    int (*dma_map)(VFIOContainer *cobj,
                              hwaddr iova, ram_addr_t size,
                              void *vaddr, bool readonly);
    int (*dma_unmap)(VFIOContainer *cobj,
                                hwaddr iova, ram_addr_t size,
                                IOMMUTLBEntry *iotlb);
    void (*set_dirty_page_tracking)(VFIOContainer *cobj, bool start);
    int (*get_dirty_bitmap)(VFIOContainer *cobj, uint64_t iova,
                                 uint64_t size, ram_addr_t ram_addr);
    bool (*is_spapr)(VFIOContainer *cobj);
} VFIOContainerClass;

/*
 * This is an abstraction of host IOMMU with dual-stage capability
 */
struct VFIOContainer {
    Object parent_obj;

    VFIOAddressSpace *space;
    MemoryListener listener;
    Error *error;
    bool initialized;
    bool dirty_pages_supported;
    uint64_t dirty_pgsizes;
    uint64_t max_dirty_bitmap_size;
    unsigned long pgsizes;
    unsigned int dma_max_mappings;
    QLIST_HEAD(, VFIOGuestIOMMU) giommu_list;
    QLIST_HEAD(, VFIOHostDMAWindow) hostwin_list;
    QLIST_HEAD(, VFIORamDiscardListener) vrdl_list;
    QLIST_ENTRY(VFIOContainer) next;
};

typedef struct VFIOLegacyContainer {
    VFIOContainer obj;
    int fd; /* /dev/vfio/vfio, empowered by the attached groups */
    MemoryListener prereg_listener;
    unsigned iommu_type;
    QLIST_HEAD(, VFIOGroup) group_list;
} VFIOLegacyContainer;

int vfio_container_dma_map(VFIOContainer *cobj,
                           hwaddr iova, ram_addr_t size,
                           void *vaddr, bool readonly);
int vfio_container_dma_unmap(VFIOContainer *cobj,
                             hwaddr iova, ram_addr_t size,
                             IOMMUTLBEntry *iotlb);
void vfio_container_set_dirty_page_tracking(VFIOContainer *cobj, bool start);
int vfio_container_get_dirty_bitmap(VFIOContainer *cobj, uint64_t iova,
                                    uint64_t size, ram_addr_t ram_addr);
bool vfio_container_is_spapr(VFIOContainer *cobj);
void vfio_container_init(void *_container, size_t instance_size,
                         const char *mrtypename,
                         VFIOAddressSpace *space);
void vfio_container_destroy(VFIOContainer *cobj);
#endif /* HW_VFIO_VFIO_COMMON_H */
