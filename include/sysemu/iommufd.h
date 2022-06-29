#ifndef SYSEMU_IOMMUFD_H
#define SYSEMU_IOMMUFD_H

#include "qom/object.h"
#include "qemu/thread.h"
#include "exec/hwaddr.h"
#include "exec/ram_addr.h"
#include <linux/iommufd.h>

#define TYPE_IOMMUFD_BACKEND "iommufd"
OBJECT_DECLARE_TYPE(IOMMUFDBackend, IOMMUFDBackendClass,
                    IOMMUFD_BACKEND)
#define IOMMUFD_BACKEND(obj) \
    OBJECT_CHECK(IOMMUFDBackend, (obj), TYPE_IOMMUFD_BACKEND)
#define IOMMUFD_BACKEND_GET_CLASS(obj) \
    OBJECT_GET_CLASS(IOMMUFDBackendClass, (obj), TYPE_IOMMUFD_BACKEND)
#define IOMMUFD_BACKEND_CLASS(klass) \
    OBJECT_CLASS_CHECK(IOMMUFDBackendClass, (klass), TYPE_IOMMUFD_BACKEND)
struct IOMMUFDBackendClass {
    ObjectClass parent_class;
};

struct IOMMUFDBackend {
    Object parent;

    /*< protected >*/
    int fd;            /* /dev/iommu file descriptor */
    bool owned;        /* is the /dev/iommu opened internally */
    QemuMutex lock;
    uint32_t users;

    /*< public >*/
};

int iommufd_backend_connect(IOMMUFDBackend *be, Error **errp);
void iommufd_backend_disconnect(IOMMUFDBackend *be);

int iommufd_backend_get_ioas(IOMMUFDBackend *be, uint32_t *ioas_id);
void iommufd_backend_put_ioas(IOMMUFDBackend *be, uint32_t ioas_id);
void iommufd_backend_free_id(int fd, uint32_t id);
int iommufd_backend_unmap_dma(IOMMUFDBackend *be, uint32_t ioas,
                              hwaddr iova, ram_addr_t size);
int iommufd_backend_map_dma(IOMMUFDBackend *be, uint32_t ioas, hwaddr iova,
                            ram_addr_t size, void *vaddr, bool readonly);
int iommufd_backend_copy_dma(IOMMUFDBackend *be, uint32_t src_ioas,
                             uint32_t dst_ioas, hwaddr iova,
                             ram_addr_t size, bool readonly);

int iommufd_backend_alloc_s1_hwpt(int iommufd, uint32_t dev_id,
                          hwaddr s1_ptr, uint32_t s2_hwpt,
                          int fd, union iommu_stage1_config *s1_config,
                          uint32_t *out_s1_hwpt, int *out_fault_fd);
int iommufd_backend_alloc_s2_hwpt(int iommufd, uint32_t dev_id,
                                  uint32_t ioas, uint32_t *out_s2_hwpt);
int iommufd_backend_invalidate_cache(int iommufd, uint32_t hwpt_id,
                             struct iommu_cache_invalidate_info *info);
int iommufd_backend_page_response(int iommufd, uint32_t hwpt_id,
                          uint32_t dev_id, struct iommu_page_response *resp);
int iommufd_backend_alloc_pasid(int iommufd, uint32_t min, uint32_t max,
                        bool identical, uint32_t *pasid);
int iommufd_backend_free_pasid(int iommufd, uint32_t pasid);
#endif
