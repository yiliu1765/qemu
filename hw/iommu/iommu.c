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

int iommufd_open(void)
{
    int fd;

    fd = qemu_open_old("/dev/iommu", O_RDWR);
    if (fd < 0) {
        error_report("Failed to open /dev/iommu!\n");
    }
    return fd;
}

void iommufd_close(int fd)
{

    close(fd);
}

int iommufd_alloc_ioasd(int fd, uint32_t *ioasid)
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
        error_report("Failed to allocate ioasid  %m\n");
    }

    *ioasid = alloc_data.out_ioas_id;

    return ret;
}

void iommufd_free_ioasd(int fd, uint32_t ioasid)
{
    struct iommu_destroy des;

    if (fd < 0) {
        return;
    }

    des.size = sizeof(des);
    des.id = ioasid;

    if (ioctl(fd, IOMMU_DESTROY, &des)) {
        error_report("Failed to free ioasid: %u  %m\n", ioasid);
    }
}
static int iommufd_device_get_info(int iommufd, int devicefd,
                                   uint32_t ioasid,
                                   struct iommu_ioas_pagetable_iova_ranges **info)
{
    size_t argsz = sizeof(struct iommu_ioas_pagetable_iova_ranges);

    *info = g_new0(struct iommu_ioas_pagetable_iova_ranges, 1);
again:
    (*info)->size = argsz;
    (*info)->ioas_id = ioasid;

    printf("%s ioasid: %u\n", __func__, ioasid);
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

static int check_device_iommu_info(int iommufd, int devicefd, uint32_t ioasid)
{
    struct iommu_ioas_pagetable_iova_ranges *info;

    if (!iommufd_device_get_info(iommufd, devicefd, ioasid, &info)) {
        get_device_iova_ranges(info);
	g_free(info);
	return 0;
    }
    return -EINVAL;
}

static int test_dma(int iommufd, uint32_t ioasid)
{
	struct iommu_ioas_pagetable_map map;
	struct iommu_ioas_pagetable_unmap unmap;
	int rt;

	/* Test MAP */
	memset(&map, 0x0, sizeof(map));
	map.size = sizeof(map);
	map.flags = IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE |
		    IOMMU_IOAS_PAGETABLE_MAP_READABLE;
	map.ioas_id = ioasid;

	/* Allocate some space and setup a DMA mapping */
	map.user_va = (__u64)(uintptr_t)mmap(0, 1024 * 1024, PROT_READ | PROT_WRITE,
					     MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	printf("map.user_va: %llx\n", (unsigned long long)map.user_va);
	map.length = 1024 * 1024;

	printf("map\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_MAP, &map);
	if (rt) {
		printf("map failed %m\n");
		goto out;
	}
	printf("mapped, allocated iova: %llx\n", (unsigned long long) map.iova);

	memset(&unmap, 0x0, sizeof(unmap));
	unmap.size = sizeof(unmap);
	unmap.ioas_id = ioasid;
	unmap.iova = map.iova;
	unmap.length = map.length;

	printf("unmap\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
	if (rt) {
		printf("unmap failed %m\n");
		goto out;
	}

	/* Test fixed IOVA */
	map.iova += 0x1000;
	map.flags |= IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA;
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

static int test_dma_copy(int iommufd, uint32_t ioasid1, uint32_t ioasid2)
{
	struct iommu_ioas_pagetable_map map;
	struct iommu_ioas_pagetable_unmap unmap;
	struct iommu_ioas_pagetable_copy copy;
	int rt;

	/* Prepare MAP  on ioasid1 */
	memset(&map, 0x0, sizeof(map));
	map.size = sizeof(map);
	map.flags = IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE |
		    IOMMU_IOAS_PAGETABLE_MAP_READABLE;
	map.ioas_id = ioasid1;

	/* Allocate some space and setup a DMA mapping */
	map.user_va = (__u64)(uintptr_t)mmap(0, 1024 * 1024, PROT_READ | PROT_WRITE,
					     MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	printf("map.user_va: %llx\n", (unsigned long long)map.user_va);
	map.length = 1024 * 1024;

	printf("map on ioasid: %u\n", ioasid1);
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_MAP, &map);
	if (rt) {
		printf("map failed %m\n");
		goto out_free;
	}
	printf("mapped, allocated iova: %llx\n", (unsigned long long) map.iova);

	/* copy to ioasid2 without fixed iova */
	memset(&copy, 0x0, sizeof(copy));
	copy.size = sizeof(copy);
	copy.dst_ioas_id = ioasid2;
	copy.src_ioas_id = ioasid1;
	copy.length = map.length;
	copy.src_iova = map.iova;
	copy.flags = IOMMU_IOAS_PAGETABLE_MAP_WRITEABLE |
		     IOMMU_IOAS_PAGETABLE_MAP_READABLE;

	printf("copy to ioasid2 w/o fixed iova\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_COPY, &copy);
	if (rt) {
		printf("copy failed %m\n");
		goto out_unmap_ioasid1;
	}

	memset(&unmap, 0x0, sizeof(unmap));
	unmap.size = sizeof(unmap);
	unmap.ioas_id = copy.dst_ioas_id;
	unmap.iova = copy.dst_iova;
	unmap.length = copy.length;

	printf("unmap non-fixed iova on ioasid2\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
	if (rt) {
		printf("unmap failed %m\n");
		goto out_unmap_ioasid1;
	}

	/* copy to ioasid2 with fixed iova */
	copy.dst_iova = copy.dst_iova + 0x400000;
	copy.flags |= IOMMU_IOAS_PAGETABLE_MAP_FIXED_IOVA;

	printf("copy to ioasid2 w/ fixed iova: %llx\n", (unsigned long long)copy.dst_iova);
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_COPY, &copy);
	if (rt) {
		printf("copy w/ fixed iova failed %m\n");
		goto out_unmap_ioasid1;
	}

	memset(&unmap, 0x0, sizeof(unmap));
	unmap.size = sizeof(unmap);
	unmap.ioas_id = copy.dst_ioas_id;
	unmap.iova = copy.dst_iova;
	unmap.length = copy.length;

	printf("unmap fixed iova on ioasid2\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
	if (rt) {
		printf("unmap failed %m\n");
	}

out_unmap_ioasid1:
	memset(&unmap, 0x0, sizeof(unmap));
	unmap.size = sizeof(unmap);
	unmap.ioas_id = map.ioas_id;
	unmap.iova = map.iova;
	unmap.length = map.length;

	printf("unmap ioasid1\n");
	rt = ioctl(iommufd, IOMMU_IOAS_PAGETABLE_UNMAP, &unmap);
	if (rt) {
		printf("unmap failed %m\n");
	}
out_free:
	munmap((void *)map.user_va, map.length);
	return rt;
}

static int device_bind_iommufd(int devicefd, int iommufd, uint64_t cookie)
{
	struct vfio_device_bind_iommufd bind;
	int rt;

	bind.argsz = sizeof(bind);
	bind.flags = 0;
	bind.iommufd = iommufd;
	bind.dev_cookie = cookie;

	rt = ioctl(devicefd, VFIO_DEVICE_BIND_IOMMUFD, &bind);
	if (rt) {
		printf("error bind failed, rt: %d\n", rt);
	} else {
		printf("bind succ for devicefd: %d, devid: %u\n", devicefd, bind.out_devid);
	}

	return rt;
}

static int device_attach_ioasid(int devicefd, int iommufd, uint32_t ioasid)
{
	struct vfio_device_attach_ioaspt attach_data;
	int rt;

	attach_data.argsz = sizeof(attach_data);
	attach_data.flags = 0;
	attach_data.iommufd = iommufd;
	attach_data.ioaspt_id = ioasid;

	printf("attach ioasid: %d - 1\n", ioasid);
	rt = ioctl(devicefd, VFIO_DEVICE_ATTACH_IOASPT, &attach_data);
	printf("attach ioasid: %d - 2, ret: %d, hwpt_id: %u\n", ioasid, rt, attach_data.out_hwpt_id);
	if (rt) {
		printf("error attach ioasid failed, rt: %d\n", rt);
	}
	return rt;
}

static void device_detach_ioasid(int devicefd, int iommufd, uint32_t ioasid)
{
	struct vfio_device_detach_ioaspt detach_data;
	int rt;

	detach_data.argsz = sizeof(detach_data);
	detach_data.flags = 0;
	detach_data.iommufd = iommufd;
	detach_data.ioaspt_id = ioasid;

	printf("detach ioasid: %d - 1\n", ioasid);
	rt = ioctl(devicefd, VFIO_DEVICE_DETACH_IOASPT, &detach_data);
	printf("detach ioasid: %d - 2, ret: %d\n", ioasid, rt);
}

static int device_test_preparation(int devicefd, int iommufd, uint64_t cookie, uint32_t ioasid)
{
	int rt;

	rt = device_bind_iommufd(devicefd, iommufd, cookie);
	if (rt) {
		return rt;
	}

	rt = device_attach_ioasid(devicefd, iommufd, ioasid);
	if (rt) {
		return rt;
	}

	check_device_iommu_info(iommufd, devicefd, ioasid);
	return 0;
}

#define IOMMUFD_TEST_DMA_COPY (1 << 0)
/*
 * @device_path2 and @cookie2 are used only when IOMMUFD_TEST_DMA_COPY is set
 * */
static int test_device_interface(int iommufd, char *device_path1, char *device_path2, uint64_t cookie1, uint64_t cookie2, uint32_t ioasid, uint32_t flags)
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

	rt = device_test_preparation(devicefd1, iommufd, cookie1, ioasid);
	if (rt) {
		close(devicefd1);
		return rt;
	}

	printf("============== Test normal dma with: %s\n", device_path1);
	rt = test_dma(iommufd, ioasid);
	if (rt) {
		printf("dma test failed\n");
		goto out;
	}
	printf("test ends ==============\n");

	if (flags & IOMMUFD_TEST_DMA_COPY) {
		uint32_t ioasid2;

		rt = iommufd_alloc_ioasd(iommufd, &ioasid2);
		if (rt < 0) {
			printf("failed to alloc ioasid for dma copy, rt: %d\n", rt);
			goto out;
		}
		printf("%s allocate ioasid: %d for dma copy\n", __func__, ioasid2);

		devicefd2 = qemu_open_old(device_path2, O_RDWR);
		if (devicefd2 < 0) {
			printf("error open %s\n", device_path2);
			iommufd_free_ioasd(iommufd, ioasid2);
			rt = -EINVAL;
			goto out;
		}

		printf("use %s, fd: %d, cookie: %llx for dma copy test\n", device_path2, devicefd2, (unsigned long long)cookie2);

		rt = device_test_preparation(devicefd2, iommufd, cookie2, ioasid2);
		if (rt) {
			printf("error prepare test for devicefd2: %d\n", devicefd2);
			close(devicefd2);
			iommufd_free_ioasd(iommufd, ioasid2);
			goto out;
		}

		printf("============== Test dma copy with: %s and %s\n", device_path1, device_path2);
		rt = test_dma_copy(iommufd, ioasid, ioasid2);
		if (rt) {
			printf("dma copy test failed\n");
		} else {
			printf("dma copy test succ\n");
		}
		printf("test ends ==============\n");

		device_detach_ioasid(devicefd2, iommufd, ioasid2);
		close(devicefd2);
		iommufd_free_ioasd(iommufd, ioasid2);
	}

out:
	device_detach_ioasid(devicefd1, iommufd, ioasid);
	printf("close devicefd1\n");
	close(devicefd1);
	return rt;
}
#if 0
static void test_multi_device_group(int iommufd)
{
	uint32_t ioasid;
        int rt, idx, j;
	int sdf[8];
	char *device_paths[8];
	struct vfio_device_detach_ioaspt detach_data;

	rt = iommufd_alloc_ioasd(iommufd, &ioasid);
	printf("%s ioasid: %d\n", __func__, ioasid);
	if (rt < 0) {
		printf("alloc ioasid failed, rt: %d\n", rt);
		return;
	}

	for (idx = 0; idx < 8; idx++) {
		device_paths[idx] = g_strdup_printf("/dev/vfio/devices/vfio%d", idx + 2);
		printf("%s %s\n", __func__, device_paths[idx]);
		rt = test_device_interface(iommufd, device_paths[idx], (uint64_t)idx, IOMMUFD_TEST_DMA_COPY, ioasid);
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
		detach_data.ioaspt_id = ioasid;

		ret = ioctl(sdf[j], VFIO_DEVICE_DETACH_IOASPT, &detach_data);
		printf("detach ioasid: %d, on %s ret: %d and then close devicefd\n", ioasid, device_paths[j], ret);
		close(sdf[j]);
		g_free(device_paths[j]);
	}
	printf("try to free ioasid: %d\n", ioasid);
	iommufd_free_ioasd(iommufd, ioasid);
}
#endif

static uint64_t device_cookie_count = 1;
/*
 * Just a simple way to get device cookies, formal code should
 * mapp the cookie with VFIODevice.
 */
static uint64_t get_device_cookie(void)
{
    return (device_cookie_count == (~(1ULL) + 1)) ? 0 : device_cookie_count++;
}

static int test_iommufd(void)
{
    int  iommufd, rt;
    uint32_t ioasid;
    char *device_path;

    iommufd = iommufd_open();
    if (iommufd < 0) {
        printf("%s iommufd open error\n", __func__);
	return -ENODEV;
    }

    rt = iommufd_alloc_ioasd(iommufd, &ioasid);
    printf("%s ioasid: %d\n", __func__, ioasid);
    if (rt < 0) {
        printf("alloc ioasid failed, rt: %d\n", rt);
	goto out_close_fd;
    }

    /* Test /dev/vfio/devices/vfio0 */
    device_path = g_strdup_printf("/dev/vfio/devices/vfio%d", 0);
    printf("Test %s\n", device_path);

    rt = test_device_interface(iommufd, device_path, NULL, get_device_cookie(),0, ioasid, 0);
    if (rt < 0) {
        printf("Test failed %d\n", rt);
	goto out_free;
    }
    g_free(device_path);

    /* Test /dev/vfio/devices/vfio0 */
    device_path = g_strdup_printf("/dev/vfio/devices/vfio%d", 1);

    rt = test_device_interface(iommufd, device_path, NULL, get_device_cookie(),0, ioasid, 0);
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
        rt = test_device_interface(iommufd, device_path, device_path2, get_device_cookie(), get_device_cookie(), ioasid, IOMMUFD_TEST_DMA_COPY);
        if (rt < 0) {
            printf("Test failed %d\n", rt);
            g_free(device_path2);
            goto out_free;
        }

    }

    //test_multi_device_group(iommufd);
out_free:
    g_free(device_path);
    iommufd_free_ioasd(iommufd, ioasid);
out_close_fd:
    iommufd_close(iommufd);

    return rt;
}

