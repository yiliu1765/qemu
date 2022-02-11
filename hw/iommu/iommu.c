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
#include <sys/ioctl.h>
#include "qemu/error-report.h"
#include "hw/iommu/iommu.h"

int iommufd_users = 0;
int iommufd = -1;

int iommufd_get(void)
{
    if (iommufd == -1) {
        iommufd = qemu_open_old("/dev/iommu", O_RDWR);
        if (iommufd < 0) {
            error_report("Failed to open /dev/iommu!\n");
        } else {
            iommufd_users = 1;
        }
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
    close(fd);
}

int iommufd_alloc_ioas(int fd, uint32_t *ioas)
{
    struct iommu_ioas_pagetable_alloc alloc_data;
    int ret;

    if (fd < 0) {
        return -EINVAL;
    }

    alloc_data.size = sizeof(alloc_data);
    alloc_data.flags = 0;

    ret = ioctl(fd, IOMMU_IOAS_PAGETABLE_ALLOC, &alloc_data);
    if (ret < 0) {
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
    struct iommu_ioas_pagetable_unmap unmap;
    int ret;

    memset(&unmap, 0x0, sizeof(unmap));
    unmap.size = sizeof(unmap);
    unmap.ioas_id = ioas;
    unmap.iova = iova;
    unmap.length = size;

    ret = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
    if (ret) {
        error_report("IOMMU_IOAS_PAGETABLE_UNMAP failed: %s", strerror(errno));
    }
    return ret;
}

int iommufd_map_dma(int iommufd, uint32_t ioas, hwaddr iova, ram_addr_t size, void *vaddr, bool readonly)
{
    struct iommu_ioas_pagetable_map map;
    int ret;

    memset(&map, 0x0, sizeof(map));
    map.size = sizeof(map);
    map.flags = IOMMU_IOAS_PAGETABLE_MAP_READABLE |
                IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA;
    map.ioas_id = ioas;
    map.user_va = (int64_t)vaddr;
    map.iova = iova;
    map.length = size;
    if (!readonly) {
        map.flags |= IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE;
    }

    ret = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_MAP, &map);
    if (ret) {
        error_report("IOMMU_IOAS_PAGETABLE_MAP failed: %s", strerror(errno));
    }
    return ret;
}

#if 0
static int iommufd_device_get_info(int iommufd, int devicefd,
                                   uint32_t ioas,
                                   struct iommu_ioas_pagetable_iova_ranges **info)
{
    size_t argsz = sizeof(struct iommu_ioas_pagetable_iova_ranges);

    *info = g_new0(struct iommu_ioas_pagetable_iova_ranges, 1);
again:
    (*info)->size = argsz;
    (*info)->ioas_id = ioas;

    printf("%s ioas: %u\n", __func__, ioas);
    if (ioctl(iommufd, IOMMU_IOAS_PAGETABLE_IOVA_RANGES, *info)) {
        printf("error to get info %m\n");
        g_free(*info);
        *info = NULL;
        return -errno;
    }

    if (((*info)->size > argsz)) {
        argsz = (*info)->size;
        *info = g_realloc(*info, argsz);
        memset(*info, 0x0, argsz);
        goto again;
    }

    return 0;
}

static void get_device_iova_ranges(struct iommu_ioas_pagetable_iova_ranges *info)
{
    int i;

    for (i = 0; i < info->out_num_iovas; i++) {
        printf("out_valid_iovas[%d].start: 0x%llx, last: 0x%llx\n", i, info->out_valid_iovas[i].start, info->out_valid_iovas[i].last);
    }
}

static int check_device_iommu_info(int iommufd, int devicefd, uint32_t ioas)
{
    struct iommu_ioas_pagetable_iova_ranges *info;

    if (!iommufd_device_get_info(iommufd, devicefd, ioas, &info)) {
        get_device_iova_ranges(info);
	g_free(info);
	return 0;
    }
    return -EINVAL;
}

	printf("mapped, allocated iova: %llx\n", (unsigned long long) map.iova);

	printf("map with fixed iova: %llx\n", (unsigned long long) map.iova);
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_MAP, &map);
	if (rt) {
		printf("map failed %m\n");
		goto out;
	}
	printf("unmap\n");
	unmap.iova = map.iova;
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
	if (rt) {
		printf("unmap failed %m\n");
		goto out;
	}

out:
	munmap((void *)map.user_va, map.length);
	return rt;
}

static int test_dma_copy(int iommufd, uint32_t ioas1, uint32_t ioas2)
{
	struct iommu_ioas_pagetable_map map;
	struct iommu_ioas_pagetable_unmap unmap;
	struct iommu_ioas_pagetable_copy copy;
	int rt;

	/* Prepare MAP  on ioas1 */
	memset(&map, 0x0, sizeof(map));
	map.size = sizeof(map);
	map.flags = IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE |
		    IOMMU_IOAS_PAGETABLE_MAP_READABLE;
	map.ioas_id = ioas1;

	/* Allocate some space and setup a DMA mapping */
	map.user_va = (__u64)(uintptr_t)mmap(0, 1024 * 1024, PROT_READ | PROT_WRITE,
					     MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	printf("map.user_va: %llx\n", (unsigned long long)map.user_va);
	map.length = 1024 * 1024;

	printf("map on ioas: %u\n", ioas1);
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_MAP, &map);
	if (rt) {
		printf("map failed %m\n");
		goto out_free;
	}
	printf("mapped, allocated iova: %llx\n", (unsigned long long) map.iova);

	/* copy to ioas2 without fixed iova */
	memset(&copy, 0x0, sizeof(copy));
	copy.size = sizeof(copy);
	copy.dst_ioas_id = ioas2;
	copy.src_ioas_id = ioas1;
	copy.length = map.length;
	copy.src_iova = map.iova;
	copy.flags = IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE |
		     IOMMU_IOAS_PAGETABLE_MAP_READABLE;

	printf("copy to ioas2 w/o fixed iova\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_COPY, &copy);
	if (rt) {
		printf("copy failed %m\n");
		goto out_unmap_ioas1;
	}

	memset(&unmap, 0x0, sizeof(unmap));
	unmap.size = sizeof(unmap);
	unmap.ioas_id = copy.dst_ioas_id;
	unmap.iova = copy.dst_iova;
	unmap.length = copy.length;

	printf("unmap non-fixed iova on ioas2\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
	if (rt) {
		printf("unmap failed %m\n");
		goto out_unmap_ioas1;
	}

	/* copy to ioas2 with fixed iova */
	copy.dst_iova = copy.dst_iova + 0x400000;
	copy.flags |= IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA;

	printf("copy to ioas2 w/ fixed iova: %llx\n", (unsigned long long)copy.dst_iova);
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_COPY, &copy);
	if (rt) {
		printf("copy w/ fixed iova failed %m\n");
		goto out_unmap_ioas1;
	}

	memset(&unmap, 0x0, sizeof(unmap));
	unmap.size = sizeof(unmap);
	unmap.ioas_id = copy.dst_ioas_id;
	unmap.iova = copy.dst_iova;
	unmap.length = copy.length;

	printf("unmap fixed iova on ioas2\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
	if (rt) {
		printf("unmap failed %m\n");
	}

out_unmap_ioas1:
	memset(&unmap, 0x0, sizeof(unmap));
	unmap.size = sizeof(unmap);
	unmap.ioas_id = map.ioas_id;
	unmap.iova = map.iova;
	unmap.length = map.length;

	printf("unmap ioas1\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
	if (rt) {
		printf("unmap failed %m\n");
	}
out_free:
	munmap((void *)map.user_va, map.length);
	return rt;
}

static int device_test_preparation(int devicefd, int iommufd, uint64_t cookie, uint32_t ioas)
{
	int rt;

	rt = device_bind_iommufd(devicefd, iommufd, cookie);
	if (rt) {
		return rt;
	}

	rt = device_attach_ioas(devicefd, iommufd, ioas);
	if (rt) {
		return rt;
	}

	check_device_iommu_info(iommufd, devicefd, ioas);
	return 0;
}

#define IOMMUFD_TEST_DMA_COPY (1 << 0)
/*
 * @device_path2 and @cookie2 are used only when IOMMUFD_TEST_DMA_COPY is set
 * */
static int test_device_interface(int iommufd, char *device_path1, char *device_path2, uint64_t cookie1, uint64_t cookie2, uint32_t ioas, uint32_t flags)
{
	int rt, devicefd1, devicefd2;

	/* cookie expired */
	if (cookie1 == 0 || ((flags & IOMMUFD_TEST_DMA_COPY) && cookie2 == 0)) {
		return -EINVAL;
	}

	devicefd1 = qemu_open_old(device_path1, O_RDWR);
	if (devicefd1 < 0) {
		printf("error devicefd1: %d\n", devicefd1);
		return -EINVAL;
	}

	printf("Test %s, fd: %d, cookie: %llx\n", device_path1, devicefd1, (unsigned long long)cookie1);

	rt = device_test_preparation(devicefd1, iommufd, cookie1, ioas);
	if (rt) {
		close(devicefd1);
		return rt;
	}

	printf("============== Test normal dma with: %s\n", device_path1);
	rt = test_dma(iommufd, ioas);
	if (rt) {
		printf("dma test failed\n");
		goto out;
	}
	printf("test ends ==============\n");

	if (flags & IOMMUFD_TEST_DMA_COPY) {
		uint32_t ioas2;

		rt = iommufd_alloc_ioas(iommufd, &ioas2);
		if (rt < 0) {
			printf("failed to alloc ioas for dma copy, rt: %d\n", rt);
			goto out;
		}
		printf("%s allocate ioas: %d for dma copy\n", __func__, ioas2);

		devicefd2 = qemu_open_old(device_path2, O_RDWR);
		if (devicefd2 < 0) {
			printf("error open %s\n", device_path2);
			iommufd_free_ioas(iommufd, ioas2);
			rt = -EINVAL;
			goto out;
		}

		printf("use %s, fd: %d, cookie: %llx for dma copy test\n", device_path2, devicefd2, (unsigned long long)cookie2);

		rt = device_test_preparation(devicefd2, iommufd, cookie2, ioas2);
		if (rt) {
			printf("error prepare test for devicefd2: %d\n", devicefd2);
			close(devicefd2);
			iommufd_free_ioas(iommufd, ioas2);
			goto out;
		}

		printf("============== Test dma copy with: %s and %s\n", device_path1, device_path2);
		rt = test_dma_copy(iommufd, ioas, ioas2);
		if (rt) {
			printf("dma copy test failed\n");
		} else {
			printf("dma copy test succ\n");
		}
		printf("test ends ==============\n");

		device_detach_ioas(devicefd2, iommufd, ioas2);
		close(devicefd2);
		iommufd_free_ioas(iommufd, ioas2);
	}

out:
	device_detach_ioas(devicefd1, iommufd, ioas);
	printf("close devicefd1\n");
	close(devicefd1);
	return rt;
}

static void test_multi_device_group(int iommufd)
{
	uint32_t ioas;
        int rt, idx, j;
	int sdf[8];
	char *device_paths[8];
	struct vfio_device_detach_ioaspt detach_data;

	rt = iommufd_alloc_ioas(iommufd, &ioas);
	printf("%s ioas: %d\n", __func__, ioas);
	if (rt < 0) {
		printf("alloc ioas failed, rt: %d\n", rt);
		return;
	}

	for (idx = 0; idx < 8; idx++) {
		device_paths[idx] = g_strdup_printf("/dev/vfio/devices/vfio%d", idx + 2);
		printf("%s %s\n", __func__, device_paths[idx]);
		rt = test_device_interface(iommufd, device_paths[idx], (uint64_t)idx, IOMMUFD_TEST_DMA_COPY, ioas);
		if (rt < 0) {
			printf("error sdf[%d]: %d\n", idx, sdf[idx]);
			break;
		}
		sdf[idx] = rt;
	}

	for (j = 0; j < idx; j++) {
		int ret;

//		if (j == 3) {
//			continue;
//		}
		detach_data.argsz = sizeof(detach_data);
		detach_data.flags = 0;
		detach_data.iommufd = iommufd;
		detach_data.ioaspt_id = ioas;

		ret = ioctl(sdf[j], VFIO_DEVICE_DETACH_IOASPT, &detach_data);
		printf("detach ioas: %d, on %s ret: %d and then close devicefd\n", ioas, device_paths[j], ret);
		close(sdf[j]);
		g_free(device_paths[j]);
	}
	printf("try to free ioas: %d\n", ioas);
	iommufd_free_ioas(iommufd, ioas);
}

static uint64_t device_cookie_count = 1;
/*
 * Just a simple way to get device cookies, formal code should
 * mapp the cookie with VFIODevice.
 */
static uint64_t get_device_cookie(void)
{
    return (device_cookie_count == (~(1ULL) + 1)) ? 0 : device_cookie_count++;
}

int test_iommufd(void)
{
    int  iommufd, rt;
    uint32_t ioas;
    char *device_path;

    iommufd = iommufd_get();
    if (iommufd < 0) {
        printf("%s iommufd open error\n", __func__);
	return -ENODEV;
    }

    rt = iommufd_alloc_ioas(iommufd, &ioas);
    printf("%s ioas: %d\n", __func__, ioas);
    if (rt < 0) {
        printf("alloc ioas failed, rt: %d\n", rt);
	goto out_close_fd;
    }

    /* Test /dev/vfio/devices/vfio0 */
    device_path = g_strdup_printf("/dev/vfio/devices/vfio%d", 0);
    printf("Test %s\n", device_path);

    rt = test_device_interface(iommufd, device_path, NULL, get_device_cookie(),0, ioas, 0);
    if (rt < 0) {
        printf("Test failed %d\n", rt);
	goto out_free;
    }
    g_free(device_path);

    /* Test /dev/vfio/devices/vfio0 */
    device_path = g_strdup_printf("/dev/vfio/devices/vfio%d", 1);

    rt = test_device_interface(iommufd, device_path, NULL, get_device_cookie(),0, ioas, 0);
    if (rt < 0) {
        printf("Test failed %d\n", rt);
	goto out_free;
    }
    g_free(device_path);

    /* Test dma copy with */
    device_path = g_strdup_printf("/dev/vfio/devices/vfio%d", 0);
    if (1) {
        char *device_path2;

        device_path2 = g_strdup_printf("/dev/vfio/devices/vfio%d", 1);
        rt = test_device_interface(iommufd, device_path, device_path2, get_device_cookie(), get_device_cookie(), ioas, IOMMUFD_TEST_DMA_COPY);
        if (rt < 0) {
            printf("Test failed %d\n", rt);
            g_free(device_path2);
            goto out_free;
        }

    }

    //test_multi_device_group(iommufd);
out_free:
    g_free(device_path);
    iommufd_free_ioas(iommufd, ioas);
out_close_fd:
    iommufd_put(iommufd);

    return rt;
}

#endif
