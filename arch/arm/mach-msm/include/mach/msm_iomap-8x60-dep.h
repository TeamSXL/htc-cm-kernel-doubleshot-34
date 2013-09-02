/*
 * Copyright (C) 2007 Google, Inc.
 * Copyright (c) 2008-2011, Code Aurora Forum. All rights reserved.
 * Author: Brian Swetland <swetland@google.com>
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
 *
 * The MSM peripherals are spread all over across 768MB of physical
 * space, which makes just having a simple IO_ADDRESS macro to slide
 * them into the right virtual location rough.  Instead, we will
 * provide a master phys->virt mapping for peripherals here.
 *
 */

#ifndef __ASM_ARCH_MSM_IOMAP_8X60_H
#define __ASM_ARCH_MSM_IOMAP_8X60_H

/* Physical base address and size of peripherals.
 * Ordered by the virtual base addresses they will be mapped at.
 *
 * MSM_VIC_BASE must be an value that can be loaded via a "mov"
 * instruction, otherwise entry-macro.S will not compile.
 *
 * If you add or remove entries here, you'll want to edit the
 * msm_io_desc array in arch/arm/mach-msm/io.c to reflect your
 * changes.
 *
 */

#define MSM_QGIC_DIST_BASE	IOMEM(0xFE000000)
#define MSM_QGIC_DIST_PHYS	0x02080000
#define MSM_QGIC_DIST_SIZE	SZ_4K

#define MSM_QGIC_CPU_BASE	IOMEM(0xFE001000)
#define MSM_QGIC_CPU_PHYS	0x02081000
#define MSM_QGIC_CPU_SIZE	SZ_4K

#define MSM_ACC_BASE		IOMEM(0xFE002000)
#define MSM_ACC_PHYS		0x02001000
#define MSM_ACC_SIZE		SZ_4K

#define MSM_GCC_BASE		IOMEM(0xFE003000)
#define MSM_GCC_PHYS		0x02082000
#define MSM_GCC_SIZE		SZ_4K

#define MSM_TLMM_BASE		IOMEM(0xFE004000)
#define MSM_TLMM_PHYS		0x00800000
#define MSM_TLMM_SIZE		SZ_16K

#define MSM_RPM_BASE		IOMEM(0xFE008000)
#define MSM_RPM_PHYS		0x00104000
#define MSM_RPM_SIZE		SZ_16K

#define MSM_CLK_CTL_BASE	IOMEM(0xFE010000)
#define MSM_CLK_CTL_PHYS	0x00900000
#define MSM_CLK_CTL_SIZE	SZ_16K

#define MSM_MMSS_CLK_CTL_BASE	IOMEM(0xFE014000)
#define MSM_MMSS_CLK_CTL_PHYS	0x04000000
#define MSM_MMSS_CLK_CTL_SIZE	SZ_4K

#define MSM_LPASS_CLK_CTL_BASE	IOMEM(0xFE015000)
#define MSM_LPASS_CLK_CTL_PHYS	0x28000000
#define MSM_LPASS_CLK_CTL_SIZE	SZ_4K

#define MSM_TMR_BASE		IOMEM(0xFE016000)
#define MSM_TMR_PHYS		0x02000000
#define MSM_TMR_SIZE		SZ_4K

#define MSM_TMR0_BASE		IOMEM(0xFE017000)
#define MSM_TMR0_PHYS		0x02040000
#define MSM_TMR0_SIZE		SZ_4K

#define MSM_SCPLL_BASE		IOMEM(0xFE018000)
#define MSM_SCPLL_PHYS		0x00903000
#define MSM_SCPLL_SIZE		SZ_1K

#define MSM_SHARED_RAM_BASE	IOMEM(0xFE200000)
#define MSM_SHARED_RAM_PHYS	0x40000000
#define MSM_SHARED_RAM_SIZE	SZ_1M

#define MSM_ACC0_BASE           IOMEM(0xFE300000)
#define MSM_ACC0_PHYS           0x02041000
#define MSM_ACC0_SIZE           SZ_4K

#define MSM_ACC1_BASE           IOMEM(0xFE301000)
#define MSM_ACC1_PHYS           0x02051000
#define MSM_ACC1_SIZE           SZ_4K

#define MSM_RPM_MPM_BASE        IOMEM(0xFE302000)
#define MSM_RPM_MPM_PHYS        0x00200000
#define MSM_RPM_MPM_SIZE        SZ_4K

#define MSM_SAW0_BASE		IOMEM(0xFE303000)
#define MSM_SAW0_PHYS		0x02042000
#define MSM_SAW0_SIZE		SZ_4K

#define MSM_SAW1_BASE		IOMEM(0xFE304000)
#define MSM_SAW1_PHYS		0x02052000
#define MSM_SAW1_SIZE		SZ_4K

#define MSM_IMEM_BASE		IOMEM(0xFE305000)
#define MSM_IMEM_PHYS		0x2A05F000
#define MSM_IMEM_SIZE		SZ_4K

/* TZ will write its jump addres when leaving TZ during resuming.
   While suspending, kernel writes MAGIC number to here.
   We can use it to check whether it has entered TZ or not. */
#define MSM_TZ_FOOTPRINT_JUMP_ADDRESS	(MSM_IMEM_BASE + 0x020) /* 4 bytes */

#define MSM_SIC_NON_SECURE_BASE	IOMEM(0xFE600000)
#define MSM_SIC_NON_SECURE_PHYS	0x12100000
#define MSM_SIC_NON_SECURE_SIZE	SZ_64K

#define MSM_QFPROM_BASE	IOMEM(0xFE700000)
#define MSM_QFPROM_PHYS	0x00700000
#define MSM_QFPROM_SIZE	SZ_4K

#define MSM_TCSR_BASE	IOMEM(0xFE701000)
#define MSM_TCSR_PHYS	0x16B00000
#define MSM_TCSR_SIZE	SZ_4K

#define MSM_EBI1_CH0_BASE	IOMEM(0xFE702000)
#define MSM_EBI1_CH0_PHYS	0x00a00000
#define MSM_EBI1_CH0_SIZE	0x00100000

#define MSM_HDMI_BASE		IOMEM(0xFE800000)
#define MSM_HDMI_PHYS		0x04A00000
#define MSM_HDMI_SIZE		SZ_4K

#ifdef CONFIG_MSM_DEBUG_UART
#define MSM_DEBUG_UART_BASE	0xFEC40000

#if CONFIG_MSM_DEBUG_UART == 11
	#define MSM_DEBUG_UART_PHYS 0x19B40000
#else
	#define MSM_DEBUG_UART_PHYS	0x19C40000
#endif

#define MSM_DEBUG_UART_SIZE	SZ_4K
#endif

#define MSM_HTC_RAM_CONSOLE_PHYS	0x40300000
#define MSM_HTC_RAM_CONSOLE_SIZE	(SZ_1M - SZ_128K) /* 128K for debug info */

#define MSM_HTC_DEBUG_INFO_BASE		IOMEM(0xFE802000)
#define MSM_HTC_DEBUG_INFO_PHYS		(MSM_HTC_RAM_CONSOLE_PHYS + MSM_HTC_RAM_CONSOLE_SIZE)
#define MSM_HTC_DEBUG_INFO_SIZE		SZ_128K

#define MSM_TZLOG_BASE                  MSM_HTC_DEBUG_INFO_BASE
#define MSM_TZLOG_PHYS			MSM_HTC_DEBUG_INFO_PHYS
#define MSM_TZLOG_SIZE			SZ_64K

#define MSM_WDT_PROC_INFO_BASE		(MSM_TZLOG_BASE + MSM_TZLOG_SIZE)
#define MSM_WDT_PROC_INFO_SIZE		SZ_4K

#define MSM_DO_IRQ_INFO_BASE		(MSM_WDT_PROC_INFO_BASE + MSM_WDT_PROC_INFO_SIZE)
#define MSM_DO_IRQ_INFO_SIZE		SZ_16

#define MSM_SPIN_LOCK_IRQSAVE_INFO_BASE		(MSM_DO_IRQ_INFO_BASE + MSM_DO_IRQ_INFO_SIZE)
#define MSM_SPIN_LOCK_IRQSAVE_INFO_SIZE		SZ_16

#define MSM_IRQ_COUNT_INFO_BASE		(MSM_SPIN_LOCK_IRQSAVE_INFO_BASE + MSM_SPIN_LOCK_IRQSAVE_INFO_SIZE)

#define MSM_TZ_DOG_BARK_REG_SAVE_BASE	(MSM_DO_IRQ_INFO_BASE + SZ_1K)
#define MSM_TZ_DOG_BARK_REG_SAVE_PHYS	(MSM_HTC_DEBUG_INFO_PHYS + MSM_TZLOG_SIZE + MSM_WDT_PROC_INFO_SIZE + SZ_1K)
#define MSM_TZ_DOG_BARK_REG_SAVE_SIZE	SZ_4K

/*Reserve 2 bytes for watchdog enable foot print*/
#define MSM_IRQ_COUNT_WATCHDOG_ENABLE_ADDR	MSM_IRQ_COUNT_INFO_BASE
/*Reserve 8 bytes for timestamp*/
#define MSM_IRQ_COUNT_TIMESTAMP_ADDR	(MSM_IRQ_COUNT_WATCHDOG_ENABLE_ADDR + 2)
/*Reserve 2 bytes for recoding which cpu pet watchdog */
#define MSM_IRQ_COUNT_WATCHDOG_PET_WORK_CPU_ADDR	(MSM_IRQ_COUNT_TIMESTAMP_ADDR + 8)
/*Reserve 8 bytes for timestamp*/
#define MSM_IRQ_COUNT_WATCHDOG_PET_TIMESTAMP_ADDR	(MSM_IRQ_COUNT_WATCHDOG_PET_WORK_CPU_ADDR + 2)
#define MSM_IRQ_COUNT_ADDR				(MSM_IRQ_COUNT_WATCHDOG_PET_TIMESTAMP_ADDR + 8)
#define MSM_IRQ_COUNT_INFO_SIZE		(SZ_1K - MSM_DO_IRQ_INFO_SIZE - MSM_SPIN_LOCK_IRQSAVE_INFO_SIZE)

#endif
