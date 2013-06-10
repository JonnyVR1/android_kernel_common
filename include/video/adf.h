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

#ifndef _VIDEO_ADF_H
#define _VIDEO_ADF_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include <drm/drm_fourcc.h>
#include <drm/drm_mode.h>

#ifdef __KERNEL__
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include "sync.h"
#endif

#define ADF_NAME_LEN 32
#define ADF_MAX_CUSTOM_DATA_SIZE PAGE_SIZE

enum adf_interface_type {
	ADF_INTF_DSI = 0,
	ADF_INTF_eDP = 1,
	ADF_INTF_DPI = 2,
	ADF_INTF_VGA = 3,
	ADF_INTF_DVI = 4,
	ADF_INTF_HDMI = 5,
	ADF_INTF_MEMORY = 6,
	ADF_INTF_TYPE_DEVICE_CUSTOM = 128,
	ADF_INTF_TYPE_MAX = (~(__u32)0),
};

enum adf_event_type {
	ADF_EVENT_VSYNC = 0,
	ADF_EVENT_HOTPLUG = 1,
	ADF_EVENT_DEVICE_CUSTOM = 128,
	ADF_EVENT_TYPE_MAX = 255,
};

/**
 * struct adf_set_event - start or stop subscribing to ADF events
 *
 * @type: the type of event to (un)subscribe
 * @enabled: subscribe or unsubscribe
 *
 * After subscribing to an event, userspace may poll() the ADF object's fd
 * to wait for events or read() to consume the event's data.
 *
 * ADF reserves event types 0 to %ADF_EVENT_DEVICE_CUSTOM-1 for its own events.
 * Devices may use event types %ADF_EVENT_DEVICE_CUSTOM to %ADF_EVENT_TYPE_MAX-1
 * for driver-private events.
 */
struct adf_set_event {
	__u8 type;
	__u8 enabled;
};

/**
 * struct adf_event - common header for ADF event data
 *
 * @type: event type
 * @length: total size of event data, header inclusive
 */
struct adf_event {
	__u8 type;
	__u32 length;
};

/**
 * struct adf_vsync_event - ADF vsync event
 *
 * @base: event header (see &struct adf_event)
 * @timestamp: time of vsync event, in nanoseconds
 */
struct adf_vsync_event {
	struct adf_event base;
	__u64 timestamp;
};

/**
 * struct adf_vsync_event - ADF display hotplug event
 *
 * @base: event header (see &struct adf_event)
 * @connected: whether a display is now connected to the interface
 */
struct adf_hotplug_event {
	struct adf_event base;
	__u8 connected;
};

#define ADF_MAX_PLANES 4
/**
 * struct adf_buffer_config - description of buffer displayed by adf_post_config
 *
 * @overlay_engine: id of the target overlay engine
 * @w: width of display region in pixels
 * @h: height of display region in pixels
 * @format: DRM-style fourcc, see drm_fourcc.h for standard formats
 * @fd: dma_buf fd for each plane
 * @offset: location of first pixel to scan out, in bytes
 * @pitch: stride (i.e. length of a scanline including padding) in bytes
 * @n_planes: number of planes in buffer
 * @acquire_fence: sync_fence fd which will clear when the buffer is
 *	ready for display, or <0 if the buffer is already ready
 */
struct adf_buffer_config {
	__u32 overlay_engine;

	__u16 w;
	__u16 h;
	__u32 format;

	__s64 fd[ADF_MAX_PLANES];
	__u32 offset[ADF_MAX_PLANES];
	__u32 pitch[ADF_MAX_PLANES];
	__u8 n_planes;

	__s64 acquire_fence;
};
#define ADF_MAX_BUFFERS (PAGE_SIZE / sizeof(struct adf_buffer_config))

/**
 * struct adf_post_config - request to flip to a new set of buffers
 *
 * @n_bufs: number of buffers displayed (input)
 * @bufs: description of buffers displayed (input)
 * @custom_data_size: size of driver-private data (input)
 * @custom_data: driver-private data (input)
 * @complete_fence: sync_fence fd which will clear when this
 *	configuration has left the screen (output)
 */
struct adf_post_config {
	size_t n_bufs;
	struct adf_buffer_config __user *bufs;

	size_t custom_data_size;
	void __user *custom_data;

	__s64 complete_fence;
};

/**
 * struct adf_simple_buffer_allocate - request to allocate a "simple" buffer
 *
 * @w: width of buffer in pixels (input)
 * @h: height of buffer in pixels (input)
 * @format: DRM-style fourcc (input)
 *
 * @fd: dma_buf fd (output)
 * @offset: location of first pixel, in bytes (output)
 * @pitch: length of a scanline including padding, in bytes (output)
 *
 * Simple buffers are analogous to DRM's "dumb" buffers.  They have a single
 * plane of linear RGB data which can be allocated and scanned out without
 * any driver-private ioctls or data.
 *
 * @format must be a standard RGB format defined in drm_fourcc.h.
 *
 * ADF clients must NOT assume that an interface can scan out a simple buffer
 * allocated by a different ADF interface, even if the two interfaces belong to
 * the same ADF device.
 */
struct adf_simple_buffer_alloc {
	__u16 w;
	__u16 h;
	__u32 format;

	__s64 fd;
	__u32 offset;
	__u32 pitch;
};

/**
 * struct adf_simple_post_config - request to flip to a single buffer without
 * driver-private data
 *
 * @buf: description of buffer displayed (input)
 * @complete_fence: sync_fence fd which will clear when this buffer has left the
 * screen (output)
 */
struct adf_simple_post_config {
	struct adf_buffer_config buf;
	__s64 complete_fence;
};

/**
 * struct adf_device_data - describes a display device
 *
 * @name: display device's name
 * @custom_data_size: size of driver-private data
 * @custom_data: driver-private data
 */
struct adf_device_data {
	char name[ADF_NAME_LEN];

	size_t custom_data_size;
	void __user *custom_data;
};

/**
 * struct adf_device_data - describes a display interface
 *
 * @name: display interface's name
 * @type: interface type (see enum @adf_interface_type)
 * @id: which interface of type @type;
 *	e.g. interface DSI.1 -> @type=@ADF_INTF_TYPE_DSI, @id=1
 * @dpms_state: DPMS state (one of @DRM_MODE_DPMS_* defined in drm_mode.h)
 * @hotplug_detect: whether a display is plugged in
 * @width_mm: screen width in millimeters, or 0 if unknown
 * @height_mm: screen height in millimeters, or 0 if unknown
 * @current_mode: current display mode
 * @n_available_modes: the number of hardware display modes
 * @available_modes: list of hardware display modes
 * @custom_data_size: size of driver-private data
 * @custom_data: driver-private data
 */
struct adf_interface_data {
	char name[ADF_NAME_LEN];

	__u32 type;
	__u32 id;
	/* e.g. type=ADF_INTF_TYPE_DSI, id=1 => DSI.1 */

	__u8 dpms_state;
	__u8 hotplug_detect;
	__u16 width_mm;
	__u16 height_mm;

	struct drm_mode_modeinfo current_mode;
	size_t n_available_modes;
	struct drm_mode_modeinfo __user *available_modes;

	size_t custom_data_size;
	void __user *custom_data;
};
#define ADF_MAX_MODES (PAGE_SIZE / sizeof(struct drm_mode_modeinfo))

/**
 * struct adf_overlay_engine_data - describes an overlay engine
 *
 * @name: overlay engine's name
 * @custom_data_size: size of driver-private data
 * @custom_data: driver-private data
 */
struct adf_overlay_engine_data {
	char name[ADF_NAME_LEN];

	size_t custom_data_size;
	void __user *custom_data;
};

#define ADF_SET_EVENT		_IOW('D', 0, struct adf_set_event)
#define ADF_BLANK		_IOW('D', 1, __u8)
#define ADF_POST_CONFIG		_IOW('D', 2, struct adf_post_config)
#define ADF_SET_MODE		_IOW('D', 3, struct drm_mode_modeinfo)
#define ADF_GET_DEVICE_DATA	_IOR('D', 4, struct adf_device_data)
#define ADF_GET_INTERFACE_DATA	_IOR('D', 5, struct adf_interface_data)
#define ADF_GET_OVERLAY_ENGINE_DATA \
				_IOR('D', 6, struct adf_overlay_engine_data)
#define ADF_SIMPLE_POST_CONFIG	_IOW('D', 7, struct adf_simple_post_config)
#define ADF_SIMPLE_BUFFER_ALLOC _IOW('D', 8, struct adf_simple_buffer_alloc)

#ifdef __KERNEL__
struct adf_obj;
struct adf_obj_ops;
struct adf_device;
struct adf_device_ops;
struct adf_interface;
struct adf_interface_ops;
struct adf_overlay_engine;
struct adf_overlay_engine_ops;

/**
 * struct adf_buffer - buffer displayed by adf_post
 *
 * @overlay_engine: target overlay engine
 * @w: width of display region in pixels
 * @h: height of display region in pixels
 * @format: DRM-style fourcc, see drm_fourcc.h for standard formats
 * @dma_bufs: dma_buf for each plane
 * @offset: location of first pixel to scan out, in bytes
 * @pitch: length of a scanline including padding, in bytes
 * @n_planes: number of planes in buffer
 * @acquire_fence: sync_fence which will clear when the buffer is
 *	ready for display
 *
 * &struct adf_buffer is the in-kernel counterpart to the userspace-facing
 * &struct adf_buffer_config.
 */
struct adf_buffer {
	struct adf_overlay_engine *overlay_engine;

	u16 w;
	u16 h;
	u32 format;

	struct dma_buf *dma_bufs[ADF_MAX_PLANES];
	u32 offset[ADF_MAX_PLANES];
	u32 pitch[ADF_MAX_PLANES];
	u8 n_planes;

	struct sync_fence *acquire_fence;
};

/**
 * struct adf_buffer_mapping - state for mapping a &struct adf_buffer into the
 * display device
 *
 * @attachments: dma-buf attachment for each plane
 * @sg_tables: SG tables for each plane
 */
struct adf_buffer_mapping {
	struct dma_buf_attachment *attachments[ADF_MAX_PLANES];
	struct sg_table *sg_tables[ADF_MAX_PLANES];
};

/**
 * struct adf_post - request to flip to a new set of buffers
 *
 * @n_bufs: number of buffers displayed
 * @bufs: buffers displayed
 * @mappings: in-device mapping state for each buffer
 * @custom_data_size: size of driver-private data
 * @custom_data: driver-private data
 *
 * &struct adf_post is the in-kernel counterpart to the userspace-facing
 * &struct adf_post_config.
 */
struct adf_post {
	size_t n_bufs;
	struct adf_buffer *bufs;
	struct adf_buffer_mapping *mappings;

	size_t custom_data_size;
	void *custom_data;
};

struct adf_pending_post {
	struct list_head head;
	struct adf_post config;
	void *state;
};

enum adf_obj_type {
	ADF_OBJ_OVERLAY_ENGINE = 0,
	ADF_OBJ_INTERFACE = 1,
	ADF_OBJ_DEVICE = 2,
};

/**
 * struct adf_obj_ops - common ADF object implementation ops
 *
 * @open: handle opening the object's device node
 * @release: handle releasing an open file
 * @ioctl: handle custom ioctls
 *
 * @supports_event: return whether the object supports generating events of type
 *	@type
 * @set_event: enable or disable events of type @type
 * @event_type_str: return a string representation of custom event @type
 *	(@type >= %ADF_EVENT_DEVICE_CUSTOM).
 *
 * @custom_data: copy up to %ADF_MAX_CUSTOM_DATA_SIZE bytes of driver-private
 *	data into @data (allocated by ADF) and return the number of copied bytes
 *	in @size.  Return 0 on success or an error code (<0) on failure.
 */
struct adf_obj_ops {
	/* optional */
	int (*open)(struct adf_obj *obj, struct inode *inode,
			struct file *file);
	/* optional */
	int (*release)(struct adf_obj *obj, struct inode *inode,
			struct file *file);
	/* optional */
	long (*ioctl)(struct adf_obj *obj, unsigned int cmd, unsigned long arg);

	/* optional */
	bool (*supports_event)(struct adf_obj *obj, enum adf_event_type type);
	/* required if supports_event is implemented */
	void (*set_event)(struct adf_obj *obj, enum adf_event_type type,
			bool enabled);
	/* optional */
	const char *(*event_type_str)(struct adf_obj *obj,
			enum adf_event_type type);

	/* optional */
	int (*custom_data)(struct adf_obj *obj, void *data, size_t *size);
};

struct adf_obj {
	enum adf_obj_type type;
	char name[ADF_NAME_LEN];
	struct adf_device *parent;

	const struct adf_obj_ops *ops;

	struct device dev;

	struct spinlock file_lock;
	struct list_head file_list;

	struct mutex event_lock;
	struct rb_root event_refcount;

	int id;
	int minor;
};

/**
 * struct adf_device_ops - display device implementation ops
 *
 * @owner: device's module
 * @base: common operations (see &struct adf_obj_ops)
 *
 * @validate_custom_format: validate the number and size of planes
 *	in buffers with a custom format (i.e., not one of the @DRM_FORMAT_*
 *	types defined in drm/drm_fourcc.h).  Return 0 if the buffer is valid or
 *	an error code (<0) otherwise.
 *
 * @validate: validate that the proposed configuration @cfg is legal.  The
 *	driver may optionally allocate and return some driver-private state in
 *	@driver_state, which will be passed to the corresponding post().  The
 *	driver may NOT commit any changes to hardware.  Return 0 if @cfg is
 *	valid or an error code (<0) otherwise.
 * @complete_fence: create a hardware-backed sync fence to be signaled when
 *	@cfg is removed from the screen.  If unimplemented, ADF automatically
 *	creates an sw_sync fence.  Return the sync fence on success or a
 *	PTR_ERR() on failure.
 * @post: flip @cfg onto the screen.  Wait for the display to begin scanning out
 *	@cfg before returning.
 * @advance_timeline: signal the sync fence for the last configuration to leave
 *	the display.  If unimplemented, ADF automatically advances an sw_sync
 *	timeline.
 * @state_free: free driver-private state allocated during validate()
 */
struct adf_device_ops {
	/* required */
	struct module *owner;
	const struct adf_obj_ops base;

	/* required if any of the device's overlay engines supports at least one
	   custom format */
	int (*validate_custom_format)(struct adf_device *dev,
			struct adf_buffer *buf);

	/* required */
	int (*validate)(struct adf_device *dev, struct adf_post *cfg,
			void **driver_state);
	/* optional */
	struct sync_fence *(*complete_fence)(struct adf_device *dev,
			struct adf_post *cfg, void *driver_state);
	/* required */
	void (*post)(struct adf_device *dev, struct adf_post *cfg,
			void *driver_state);
	/* required if complete_fence is implemented */
	void (*advance_timeline)(struct adf_device *dev,
			struct adf_post *cfg, void *driver_state);
	/* required if validate() allocates driver state */
	void (*state_free)(struct adf_device *dev, void *driver_state);
};

struct adf_device {
	struct adf_obj base;
	struct device *dev;

	const struct adf_device_ops *ops;

	struct mutex client_lock;

	struct idr interfaces;
	struct idr overlay_engines;

	struct list_head post_list;
	struct mutex post_lock;
	struct kthread_worker post_worker;
	struct task_struct *post_thread;
	struct kthread_work post_work;

	struct adf_pending_post *onscreen;

	struct sw_sync_timeline *timeline;
	int timeline_max;
};

/**
 * struct adf_interface_ops - display interface implementation ops
 *
 * @base: common operations (see &struct adf_obj_ops)
 *
 * @blank: change the display's DPMS state.  Return 0 on success or error
 *	code (<0) on failure.
 *
 * @alloc_simple_buffer: allocate a buffer with the specified @w, @h, and
 *	@format.  @format will be a standard RGB format (i.e.,
 *	adf_format_is_rgb(@format) == true).  Return 0 on success or error code
 *	(<0) on failure.  On success, return the buffer, offset, and pitch in
 *	@dma_buf, @offset, and @pitch respectively.
 * @describe_simple_post: provide driver-private data needed to post a single
 *	buffer @buf.  Copy up to ADF_MAX_CUSTOM_DATA_SIZE bytes into @data
 *	(allocated by ADF) and return the number of bytes in @size.  Return 0 on
 *	success or error code (<0) on failure.
 *
 * @modeset: change the interface's mode.  @mode is not necessarily part of the
 *	modelist passed to adf_hotplug_notify_connected(); the driver may
 *	accept or reject custom modes at its discretion.  Return 0 on success or
 *	error code (<0) if the mode could not be set.
 *
 * @screen_size: copy the screen dimensions in millimeters into @width_mm
 *	and @height_mm.  Return 0 on success or error code (<0) if the display
 *	dimensions are unknown.
 *
 * @type_str: return a string representation of custom @intf->type
 *	(@intf->type >= @ADF_INTF_TYPE_DEVICE_CUSTOM).
 */
struct adf_interface_ops {
	const struct adf_obj_ops base;

	/* optional */
	int (*blank)(struct adf_interface *intf, u8 state);

	/* optional */
	int (*alloc_simple_buffer)(struct adf_interface *intf,
			u16 w, u16 h, u32 format,
			struct dma_buf **dma_buf, u32 *offset, u32 *pitch);
	/* required if alloc_simple_buffer is implemented */
	int (*describe_simple_post)(struct adf_interface *intf,
			struct adf_buffer *fb, void *data, size_t *size);

	/* optional */
	int (*modeset)(struct adf_interface *intf,
			struct drm_mode_modeinfo *mode);

	/* optional */
	int (*screen_size)(struct adf_interface *intf, u16 *width_mm,
			u16 *height_mm);

	/* optional */
	const char *(*type_str)(struct adf_interface *intf);
};

struct adf_interface {
	struct adf_obj base;
	const struct adf_interface_ops *ops;

	struct drm_mode_modeinfo current_mode;

	enum adf_interface_type type;
	u32 idx;

	wait_queue_head_t vsync_wait;
	ktime_t vsync_timestamp;
	rwlock_t vsync_lock;

	u8 dpms_state;

	bool hotplug_detect;
	struct drm_mode_modeinfo *modelist;
	size_t n_modes;
	rwlock_t hotplug_modelist_lock;
};

/**
 * struct adf_interface_ops - overlay engine implementation ops
 *
 * @base: common operations (see &struct adf_obj_ops)
 *
 * @supported_formats: list of fourccs the overlay engine can scan out
 * @n_supported_formats: length of supported_formats
 */
struct adf_overlay_engine_ops {
	const struct adf_obj_ops base;

	/* required */
	const u32 *supported_formats;
	/* required */
	const size_t n_supported_formats;
};

struct adf_overlay_engine {
	struct adf_obj base;

	const struct adf_overlay_engine_ops *ops;
};

#define adf_obj_to_device(ptr) \
	container_of((ptr), struct adf_device, base)

#define adf_obj_to_interface(ptr) \
	container_of((ptr), struct adf_interface, base)

#define adf_obj_to_overlay_engine(ptr) \
	container_of((ptr), struct adf_overlay_engine, base)

int adf_device_init(struct adf_device *dev, struct device *parent,
		const struct adf_device_ops *ops, const char *fmt, ...);
void adf_device_destroy(struct adf_device *dev);
int adf_interface_init(struct adf_interface *intf, struct adf_device *dev,
		const struct adf_interface_ops *ops, const char *fmt, ...);
void adf_interface_destroy(struct adf_interface *intf);
int adf_overlay_engine_init(struct adf_overlay_engine *eng,
		struct adf_device *dev,
		const struct adf_overlay_engine_ops *ops, const char *fmt, ...);
void adf_overlay_engine_destroy(struct adf_overlay_engine *eng);

const char *adf_obj_type_str(enum adf_obj_type type);
const char *adf_interface_type_str(struct adf_interface *intf);
const char *adf_event_type_str(struct adf_obj *obj, enum adf_event_type type);
void adf_format_str(u32 format, char buf[5]);

int adf_event_get(struct adf_obj *obj, enum adf_event_type type);
int adf_event_put(struct adf_obj *obj, enum adf_event_type type);
int adf_event_notify(struct adf_obj *obj, struct adf_event *event);

static inline void adf_vsync_get(struct adf_interface *intf)
{
	adf_event_get(&intf->base, ADF_EVENT_VSYNC);
}

static inline void adf_vsync_put(struct adf_interface *intf)
{
	adf_event_put(&intf->base, ADF_EVENT_VSYNC);
}

int adf_vsync_wait(struct adf_interface *intf, long timeout);
void adf_vsync_notify(struct adf_interface *intf, ktime_t timestamp);

int adf_hotplug_notify_connected(struct adf_interface *intf,
		struct drm_mode_modeinfo *modelist, size_t n_modes);
void adf_hotplug_notify_disconnected(struct adf_interface *intf);

#endif /* __KERNEL__ */

#endif /* _VIDEO_ADF_H */
