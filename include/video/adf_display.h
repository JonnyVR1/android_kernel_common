/*
 * Copyright (C) 2013 Google, Inc.
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

#ifndef _VIDEO_ADF_DISPLAY_H
#define _VIDEO_ADF_DISPLAY_H

#include <video/adf.h>
#include <video/display.h>
#include <video/videomode.h>

int adf_display_entity_screen_size(struct display_entity *display,
		u16 *width_mm, u16 *height_mm);

int adf_display_entity_notify_connected(struct adf_interface *intf,
		struct display_entity *display);

void adf_modeinfo_from_videomode(const struct videomode *vm,
		struct drm_mode_modeinfo *dmode);

#endif /* _VIDEO_ADF_DISPLAY_H */
