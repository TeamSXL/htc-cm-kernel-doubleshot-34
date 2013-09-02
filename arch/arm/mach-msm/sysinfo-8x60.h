/*
 * Copyright (C) 2010 HTC, Inc.
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

#ifndef __ARCH_ARM_SYSINFO_8X60_H_
#define __ARCH_ARM_SYSINFO_8X60_H_

extern void sysinfo_proc_init(void);

extern int msm_dump_gpios(struct seq_file *m, int curr_len, char *gpio_buffer);
extern int pm8901_dump_mpp(struct seq_file *m, int curr_len, char *gpio_buffer);

#endif
