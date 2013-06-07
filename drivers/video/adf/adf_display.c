/*
 * Copyright (C) 2013 Google, Inc.
 * adf_modeinfo_from_videomode modified from drm_display_mode_from_videomode in
 * drivers/gpu/drm/drm_modes.c
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/slab.h>
#include <video/adf.h>
#include <video/adf_display.h>

#include "adf.h"

/**
 * adf_display_entity_screen_size - handle the screen_size interface op
 * by querying a display core entity
 */
int adf_display_entity_screen_size(struct display_entity *display,
		u16 *width_mm, u16 *height_mm)
{
	unsigned int cdf_width, cdf_height;
	int ret;

	ret = display_entity_get_size(display, &cdf_width, &cdf_height);
	if (!ret) {
		*width_mm = cdf_width;
		*height_mm = cdf_height;
	}
	return ret;
}
EXPORT_SYMBOL(adf_display_entity_screen_size);

/**
 * adf_display_entity_notify_connected - notify ADF of a display core entity
 * being connected to an interface
 *
 * @intf: the interface
 * @display: the display
 *
 * adf_display_entity_notify_connected() wraps adf_hotplug_notify_connected()
 * but does not require a hardware modelist.  @display is queried to
 * automatically populate the modelist.
 *
 * Returns 0 on success or error code (<0) on failure.
 */
int adf_display_entity_notify_connected(struct adf_interface *intf,
		struct display_entity *display)
{
	const struct videomode *vmodes;
	struct drm_mode_modeinfo *dmodes = NULL;
	int ret;
	size_t i, n_modes;

	ret = display_entity_get_modes(display, &vmodes);
	if (ret < 0)
		return ret;

	n_modes = ret;
	if (n_modes) {
		dmodes = kzalloc(n_modes * sizeof(dmodes[0]), GFP_KERNEL);
		if (!dmodes)
			return -ENOMEM;
	}

	for (i = 0; i < n_modes; i++)
		adf_modeinfo_from_videomode(&vmodes[i], &dmodes[i]);

	ret = adf_hotplug_notify_connected(intf, dmodes, n_modes);
	kfree(dmodes);
	return ret;
}
EXPORT_SYMBOL(adf_display_entity_notify_connected);

/**
 * adf_modeinfo_from_videomode - copy a display core videomode into
 * an equivalent &struct drm_mode_modeinfo
 *
 * @vm: the input display core videomode
 * @dmode: the output DRM/ADF modeinfo
 */
void adf_modeinfo_from_videomode(const struct videomode *vm,
		struct drm_mode_modeinfo *dmode)
{
	memset(dmode, 0, sizeof(*dmode));

	dmode->hdisplay = vm->hactive;
	dmode->hsync_start = dmode->hdisplay + vm->hfront_porch;
	dmode->hsync_end = dmode->hsync_start + vm->hsync_len;
	dmode->htotal = dmode->hsync_end + vm->hback_porch;

	dmode->vdisplay = vm->vactive;
	dmode->vsync_start = dmode->vdisplay + vm->vfront_porch;
	dmode->vsync_end = dmode->vsync_start + vm->vsync_len;
	dmode->vtotal = dmode->vsync_end + vm->vback_porch;

	dmode->clock = vm->pixelclock / 1000;

	if (vm->flags & DISPLAY_FLAGS_HSYNC_HIGH)
		dmode->flags |= DRM_MODE_FLAG_PHSYNC;
	else if (vm->flags & DISPLAY_FLAGS_HSYNC_LOW)
		dmode->flags |= DRM_MODE_FLAG_NHSYNC;
	if (vm->flags & DISPLAY_FLAGS_VSYNC_HIGH)
		dmode->flags |= DRM_MODE_FLAG_PVSYNC;
	else if (vm->flags & DISPLAY_FLAGS_VSYNC_LOW)
		dmode->flags |= DRM_MODE_FLAG_NVSYNC;
	if (vm->flags & DISPLAY_FLAGS_INTERLACED)
		dmode->flags |= DRM_MODE_FLAG_INTERLACE;
	if (vm->flags & DISPLAY_FLAGS_DOUBLESCAN)
		dmode->flags |= DRM_MODE_FLAG_DBLSCAN;

	adf_modeinfo_set_name(dmode);
}
EXPORT_SYMBOL_GPL(adf_modeinfo_from_videomode);
