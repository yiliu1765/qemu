#ifndef SYSEMU_IOMMUFD_H
#define SYSEMU_IOMMUFD_H

#include "qom/object.h"
#include "exec/hwaddr.h"
#include "exec/cpu-common.h"
#include <linux/iommufd.h>
#include "sysemu/host_iommu_device.h"

#define TYPE_IOMMUFD_BACKEND "iommufd"
OBJECT_DECLARE_TYPE(IOMMUFDBackend, IOMMUFDBackendClass, IOMMUFD_BACKEND)

struct IOMMUFDBackendClass {
    ObjectClass parent_class;
};

struct IOMMUFDBackend {
    Object parent;

    /*< protected >*/
    int fd;            /* /dev/iommu file descriptor */
    bool owned;        /* is the /dev/iommu opened internally */
    uint32_t users;

    /*< public >*/
};

int iommufd_backend_connect(IOMMUFDBackend *be, Error **errp);
void iommufd_backend_disconnect(IOMMUFDBackend *be);

int iommufd_backend_alloc_ioas(IOMMUFDBackend *be, uint32_t *ioas_id,
                               Error **errp);
void iommufd_backend_free_id(IOMMUFDBackend *be, uint32_t id);
int iommufd_backend_map_dma(IOMMUFDBackend *be, uint32_t ioas_id, hwaddr iova,
                            ram_addr_t size, void *vaddr, bool readonly);
int iommufd_backend_unmap_dma(IOMMUFDBackend *be, uint32_t ioas_id,
                              hwaddr iova, ram_addr_t size);
int iommufd_backend_alloc_hwpt(IOMMUFDBackend *be, uint32_t dev_id,
                               uint32_t pt_id, uint32_t flags,
                               uint32_t data_type, uint32_t data_len,
                               void *data_ptr, uint32_t *out_hwpt);
int iommufd_backend_invalidate_cache(IOMMUFDBackend *be, uint32_t hwpt_id,
                                     uint32_t data_type, uint32_t entry_len,
                                     uint32_t *entry_num, void *data_ptr);


typedef struct IOMMUFDDeviceOps IOMMUFDDeviceOps;

/* Abstraction of host IOMMUFD device */
typedef struct IOMMUFDDevice {
    /* private: */
    HostIOMMUDevice base;
    void *opaque;

    /* public: */
    IOMMUFDBackend *iommufd;
    uint32_t devid;
    IOMMUFDDeviceOps *ops;
    uint32_t ioas_id;
    uint32_t errata;
} IOMMUFDDevice;

struct IOMMUFDDeviceOps {
    int (*attach_hwpt)(IOMMUFDDevice *idev, uint32_t hwpt_id);
    int (*detach_hwpt)(IOMMUFDDevice *idev);
};

void iommufd_device_init(IOMMUFDDevice *idev, IOMMUFDBackend *iommufd,
                         int devid, uint32_t ioas_id, void *opaque,
                         IOMMUFDDeviceOps *ops);
int iommufd_device_get_info(IOMMUFDDevice *idev,
                            enum iommu_hw_info_type *type,
                            uint32_t len, void *data, Error **errp);
int iommufd_device_attach_hwpt(IOMMUFDDevice *idev, uint32_t hwpt_id);
int iommufd_device_detach_hwpt(IOMMUFDDevice *idev);
#endif
