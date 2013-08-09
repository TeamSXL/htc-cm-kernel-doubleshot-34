/* Copyright (c) 2002,2008-2011, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/debugfs.h>

#include "kgsl.h"
#include "kgsl_device.h"

#define KGSL_LOG_LEVEL_DEFAULT 3
#define KGSL_LOG_LEVEL_MAX     7

struct dentry *kgsl_debugfs_dir;

static inline int kgsl_log_set(unsigned int *log_val, void *data, u64 val)
{
	*log_val = min((unsigned int)val, (unsigned int)KGSL_LOG_LEVEL_MAX);
	return 0;
}

#define KGSL_DEBUGFS_LOG(__log)                         \
static int __log ## _set(void *data, u64 val)           \
{                                                       \
	struct kgsl_device *device = data;              \
	return kgsl_log_set(&device->__log, data, val); \
}                                                       \
static int __log ## _get(void *data, u64 *val)	        \
{                                                       \
	struct kgsl_device *device = data;              \
	*val = device->__log;                           \
	return 0;                                       \
}                                                       \
DEFINE_SIMPLE_ATTRIBUTE(__log ## _fops,                 \
__log ## _get, __log ## _set, "%llu\n");                \

KGSL_DEBUGFS_LOG(drv_log);
KGSL_DEBUGFS_LOG(cmd_log);
KGSL_DEBUGFS_LOG(ctxt_log);
KGSL_DEBUGFS_LOG(mem_log);
KGSL_DEBUGFS_LOG(pwr_log);

static int memfree_hist_print(struct seq_file *s, void *unused)
{
	void *base = kgsl_driver.memfree_hist.base_hist_rb;

	struct kgsl_memfree_hist_elem *wptr = kgsl_driver.memfree_hist.wptr;
	struct kgsl_memfree_hist_elem *p;
	char str[16];

	seq_printf(s, "%8s %8s %8s %11s\n",
			"pid", "gpuaddr", "size", "flags");

	mutex_lock(&kgsl_driver.memfree_hist_mutex);
	p = wptr;
	for (;;) {
		kgsl_get_memory_usage(str, sizeof(str), p->flags);
		/*
		 * if the ring buffer is not filled up yet
		 * all its empty elems have size==0
		 * just skip them ...
		*/
		if (p->size)
			seq_printf(s, "%8d %08x %8d %11s\n",
				p->pid, p->gpuaddr, p->size, str);
		p++;
		if ((void *)p >= base + kgsl_driver.memfree_hist.size)
			p = (struct kgsl_memfree_hist_elem *) base;

		if (p == kgsl_driver.memfree_hist.wptr)
			break;
	}
	mutex_unlock(&kgsl_driver.memfree_hist_mutex);
	return 0;
}

static int memfree_hist_open(struct inode *inode, struct file *file)
{
	return single_open(file, memfree_hist_print, inode->i_private);
}

static const struct file_operations memfree_hist_fops = {
	.open = memfree_hist_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

void kgsl_device_debugfs_init(struct kgsl_device *device)
{
	if (kgsl_debugfs_dir && !IS_ERR(kgsl_debugfs_dir))
		device->d_debugfs = debugfs_create_dir(device->name,
						       kgsl_debugfs_dir);

	if (!device->d_debugfs || IS_ERR(device->d_debugfs))
		return;

	device->cmd_log = KGSL_LOG_LEVEL_DEFAULT;
	device->ctxt_log = KGSL_LOG_LEVEL_DEFAULT;
	device->drv_log = KGSL_LOG_LEVEL_DEFAULT;
	device->mem_log = KGSL_LOG_LEVEL_DEFAULT;
	device->pwr_log = KGSL_LOG_LEVEL_DEFAULT;

	debugfs_create_file("log_level_cmd", 0644, device->d_debugfs, device,
			    &cmd_log_fops);
	debugfs_create_file("log_level_ctxt", 0644, device->d_debugfs, device,
			    &ctxt_log_fops);
	debugfs_create_file("log_level_drv", 0644, device->d_debugfs, device,
			    &drv_log_fops);
	debugfs_create_file("log_level_mem", 0644, device->d_debugfs, device,
				&mem_log_fops);
	debugfs_create_file("log_level_pwr", 0644, device->d_debugfs, device,
				&pwr_log_fops);
}

void kgsl_core_debugfs_init(void)
{
	kgsl_debugfs_dir = debugfs_create_dir("kgsl", 0);
}

void kgsl_core_debugfs_close(void)
{
	debugfs_remove_recursive(kgsl_debugfs_dir);
}
