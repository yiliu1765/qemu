/*
 * QEMU simulated pvpanic device.
 *
 * Copyright Fujitsu, Corp. 2013
 *
 * Authors:
 *     Wen Congyang <wency@cn.fujitsu.com>
 *     Hu Tao <hutao@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "system/runstate.h"

#include "hw/nvram/fw_cfg.h"
#include "hw/core/qdev-properties.h"
#include "hw/misc/pvpanic.h"
#include "qom/object.h"
#include "standard-headers/misc/pvpanic.h"

static void handle_event(int event)
{
    static bool logged;

    if (event & ~PVPANIC_EVENTS && !logged) {
        qemu_log_mask(LOG_GUEST_ERROR, "pvpanic: unknown event %#x.\n", event);
        logged = true;
    }

    if (event & PVPANIC_PANICKED) {
        GuestPanicInformation *panic_info;

        panic_info = g_new0(GuestPanicInformation, 1);
        panic_info->type = GUEST_PANIC_INFORMATION_TYPE_TDX;
        panic_info->u.tdx.error_code = (uint32_t) 0x123456;
        panic_info->u.tdx.message = (char *)"I'm a fake panic for TDX";
        panic_info->u.tdx.gpa = 0x654321;
        panic_info->u.tdx.has_gpa = true;

        qemu_system_guest_panicked(panic_info);
        return;
    }

    if (event & PVPANIC_CRASH_LOADED) {
        qemu_system_guest_crashloaded(NULL);
        return;
    }

    if (event & PVPANIC_SHUTDOWN) {
        qemu_system_guest_pvshutdown();
        return;
    }
}

/* return supported events on read */
static uint64_t pvpanic_read(void *opaque, hwaddr addr, unsigned size)
{
    PVPanicState *pvp = opaque;
    return pvp->events;
}

static void pvpanic_write(void *opaque, hwaddr addr, uint64_t val,
                                 unsigned size)
{
    handle_event(val);
}

static const MemoryRegionOps pvpanic_ops = {
    .endianness = DEVICE_LITTLE_ENDIAN,
    .read = pvpanic_read,
    .write = pvpanic_write,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

void pvpanic_setup_io(PVPanicState *s, DeviceState *dev, unsigned size)
{
    memory_region_init_io(&s->mr, OBJECT(dev), &pvpanic_ops, s, "pvpanic", size);
}
