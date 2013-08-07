/* Copyright (c) 2012, The Linux Foundation. All rights reserved.
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
#ifndef __KGSL_IOMMU_H
#define __KGSL_IOMMU_H

#include <mach/iommu.h>

#define KGSL_IOMMU_CTX_OFFSET_V1	0
#define KGSL_IOMMU_CTX_OFFSET_V2	0x8000
#define KGSL_IOMMU_CTX_SHIFT		12

enum kgsl_iommu_reg_map {
	KGSL_IOMMU_GLOBAL_BASE = 0,
	KGSL_IOMMU_CTX_TTBR0,
	KGSL_IOMMU_CTX_TTBR1,
	KGSL_IOMMU_CTX_FSR,
	KGSL_IOMMU_CTX_TLBIALL,
	KGSL_IOMMU_CTX_RESUME,
	KGSL_IOMMU_REG_MAX
};

struct kgsl_iommu_register_list {
	unsigned int reg_offset;
	unsigned int reg_mask;
	unsigned int reg_shift;
};

/*
 * Max number of iommu units that the gpu core can have
 * On APQ8064, KGSL can control a maximum of 2 IOMMU units.
 */
#define KGSL_IOMMU_MAX_UNITS 2

/* Max number of iommu contexts per IOMMU unit */
#define KGSL_IOMMU_MAX_DEVS_PER_UNIT 2

/* Macros to read/write IOMMU registers */
#define KGSL_IOMMU_SET_CTX_REG(iommu, iommu_unit, ctx, REG, val)	\
		writel_relaxed(val,					\
		iommu_unit->reg_map.hostptr +				\
		iommu->iommu_reg_list[KGSL_IOMMU_CTX_##REG].reg_offset +\
		(ctx << KGSL_IOMMU_CTX_SHIFT) +				\
		iommu->ctx_offset)

#define KGSL_IOMMU_GET_CTX_REG(iommu, iommu_unit, ctx, REG)		\
		readl_relaxed(						\
		iommu_unit->reg_map.hostptr +				\
		iommu->iommu_reg_list[KGSL_IOMMU_CTX_##REG].reg_offset +\
		(ctx << KGSL_IOMMU_CTX_SHIFT) +				\
		iommu->ctx_offset)

/* Gets the lsb value of pagetable */
#define KGSL_IOMMMU_PT_LSB(iommu, pt_val) \
	(pt_val &							\
	~(iommu->iommu_reg_list[KGSL_IOMMU_CTX_TTBR0].reg_mask <<	\
	iommu->iommu_reg_list[KGSL_IOMMU_CTX_TTBR0].reg_shift))

/* offset at which a nop command is placed in setstate_memory */
#define KGSL_IOMMU_SETSTATE_NOP_OFFSET	1024

/*
 * struct kgsl_iommu_device - Structure holding data about iommu contexts
 * @dev: Device pointer to iommu context
 * @attached: Indicates whether this iommu context is presently attached to
 * a pagetable/domain or not
 * @pt_lsb: The LSB of IOMMU_TTBR0 register which is the pagetable
 * register
 * @ctx_id: This iommu units context id. It can be either 0 or 1
 * @clk_enabled: If set indicates that iommu clocks of this iommu context
 * are on, else the clocks are off
 * fault: Flag when set indicates that this iommu device has caused a page
 * fault
 */
struct kgsl_iommu_device {
	struct device *dev;
	bool attached;
	unsigned int pt_lsb;
	enum kgsl_iommu_context_id ctx_id;
	bool clk_enabled;
	struct kgsl_device *kgsldev;
};

struct kgsl_iommu_unit {
	struct kgsl_iommu_device dev[KGSL_IOMMU_MAX_DEVS_PER_UNIT];
	unsigned int dev_count;
	struct kgsl_memdesc reg_map;
};

struct kgsl_iommu {
	struct kgsl_iommu_unit iommu_units[KGSL_IOMMU_MAX_UNITS];
	unsigned int unit_count;
	unsigned int iommu_last_cmd_ts;
	bool clk_event_queued;
	struct kgsl_device *device;
};

struct kgsl_iommu_pt {
	struct iommu_domain *domain;
	struct kgsl_iommu *iommu;
};

#endif
