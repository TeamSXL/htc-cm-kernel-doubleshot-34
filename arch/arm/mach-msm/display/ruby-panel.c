/* Copyright (c) 2010-2011, Code Aurora Forum. All rights reserved.
 * Copyright (c) 2013 Sebastian Sobczyk <sebastiansobczyk@wp.pl>
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

#include "../../../../drivers/video/msm/msm_fb.h"
#include "../../../../drivers/video/msm/mipi_dsi.h"
#include "../../../../drivers/video/msm/mdp4.h"

#include <mach/gpio.h>
#include <mach/panel_id.h>
#include <mach/msm_bus_board.h>
#include <linux/mfd/pmic8058.h>
#include <linux/pwm.h>
#include <linux/pmic8058-pwm.h>
#include <mach/debug_display.h>

#include "../devices.h"
#include "../board-ruby.h"

#ifdef CONFIG_FB_MSM_TRIPLE_BUFFER
#define MSM_FB_PRIM_BUF_SIZE (960 * ALIGN(540, 32) * 4 * 3)
#else
#define MSM_FB_PRIM_BUF_SIZE (960 * ALIGN(540, 32) * 4 * 2)
#endif

#ifdef CONFIG_FB_MSM_HDMI_MSM_PANEL
#define MSM_FB_SIZE roundup(MSM_FB_PRIM_BUF_SIZE + 0x3F4800, 4096)
#else 
#define MSM_FB_SIZE roundup(MSM_FB_PRIM_BUF_SIZE, 4096)
#endif 
#define MSM_FB_BASE           0x40400000

#ifdef CONFIG_FB_MSM_OVERLAY0_WRITEBACK
#define MSM_FB_OVERLAY0_WRITEBACK_SIZE roundup((960 * ALIGN(540, 32) * 3 * 2), 4096)
#else
#define MSM_FB_OVERLAY0_WRITEBACK_SIZE (0)
#endif

#define PANEL_ID_PYD_SHARP	(0x21 | BL_MIPI | IF_MIPI | DEPTH_RGB888)
#define PANEL_ID_PYD_AUO_NT	(0x22 | BL_MIPI | IF_MIPI | DEPTH_RGB888)

#define HDMI_PANEL_NAME "hdmi_msm"

static int msm_fb_detect_panel(const char *name)
{
	if (!strncmp(name, HDMI_PANEL_NAME,
			strnlen(HDMI_PANEL_NAME,
				PANEL_NAME_MAX_LEN))) {
		return 0;
	}

	return -ENODEV;
}

static struct resource msm_fb_resources[] = {
	{
		.flags  = IORESOURCE_DMA,
	}
};

static struct msm_fb_platform_data msm_fb_pdata = {
	.detect_client = msm_fb_detect_panel,
};

static struct platform_device msm_fb_device = {
	.name   = "msm_fb",
	.id     = 0,
	.num_resources     = ARRAY_SIZE(msm_fb_resources),
	.resource          = msm_fb_resources,
	.dev.platform_data = &msm_fb_pdata,
};

void __init ruby_allocate_fb_region(void)
{
	unsigned long size;

	size = MSM_FB_SIZE;
	msm_fb_resources[0].start = MSM_FB_BASE;
	msm_fb_resources[0].end = msm_fb_resources[0].start + size - 1;
	pr_info("allocating %lu bytes at 0x%p (0x%lx physical) for fb\n",
		size, __va(MSM_FB_BASE), (unsigned long) MSM_FB_BASE);
}

#ifdef CONFIG_MSM_BUS_SCALING
static struct msm_bus_vectors mdp_init_vectors[] = {
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 0,
		.ib = 0,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};

static struct msm_bus_vectors mdp_sd_smi_vectors[] = {
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 147460000,
		.ib = 184325000,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};

static struct msm_bus_vectors mdp_sd_ebi_vectors[] = {
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 0,
		.ib = 0,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 168652800,
		.ib = 337305600,
	},
};

static struct msm_bus_vectors mdp_vga_vectors[] = {
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 37478400,
		.ib = 74956800,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 206131200,
		.ib = 412262400,
	},
};

static struct msm_bus_vectors mdp_720p_vectors[] = {
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 112435200,
		.ib = 224870400,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 281088000,
		.ib = 562176000,
	},
};

static struct msm_bus_vectors mdp_1080p_vectors[] = {
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 252979200,
		.ib = 505958400,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 421632000,
		.ib = 843264000,
	},
};

static struct msm_bus_paths mdp_bus_scale_usecases[] = {
	{
		ARRAY_SIZE(mdp_init_vectors),
		mdp_init_vectors,
	},
	{
		ARRAY_SIZE(mdp_sd_smi_vectors),
		mdp_sd_smi_vectors,
	},
	{
		ARRAY_SIZE(mdp_sd_ebi_vectors),
		mdp_sd_ebi_vectors,
	},
	{
		ARRAY_SIZE(mdp_vga_vectors),
		mdp_vga_vectors,
	},
	{
		ARRAY_SIZE(mdp_720p_vectors),
		mdp_720p_vectors,
	},
	{
		ARRAY_SIZE(mdp_1080p_vectors),
		mdp_1080p_vectors,
	},
};

static struct msm_bus_scale_pdata mdp_bus_scale_pdata = {
	mdp_bus_scale_usecases,
	ARRAY_SIZE(mdp_bus_scale_usecases),
	.name = "mdp",
};

static struct msm_bus_vectors dtv_bus_init_vectors[] = {
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 0,
		.ib = 0,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};

static struct msm_bus_vectors dtv_bus_def_vectors[] = {
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 566092800 *2,
		.ib = 707616000 *2,
	},
	{
		.src = MSM_BUS_MASTER_MDP_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 566092800 *2,
		.ib = 707616000 *2,
	},
};

static struct msm_bus_paths dtv_bus_scale_usecases[] = {
	{
		ARRAY_SIZE(dtv_bus_init_vectors),
		dtv_bus_init_vectors,
	},
	{
		ARRAY_SIZE(dtv_bus_def_vectors),
		dtv_bus_def_vectors,
	},
};

static struct msm_bus_scale_pdata dtv_bus_scale_pdata = {
	dtv_bus_scale_usecases,
	ARRAY_SIZE(dtv_bus_scale_usecases),
	.name = "dtv",
};

static struct lcdc_platform_data dtv_pdata = {
	.bus_scale_table = &dtv_bus_scale_pdata,
};
#endif

static struct mdp_reg ruby_color_enhancement[] = {
	{0x93400, 0x0222, 0x0},
	{0x93404, 0xFFE4, 0x0},
	{0x93408, 0xFFFD, 0x0},
	{0x9340C, 0xFFF1, 0x0},
	{0x93410, 0x0212, 0x0},
	{0x93414, 0xFFF9, 0x0},
	{0x93418, 0xFFF1, 0x0},
	{0x9341C, 0xFFE6, 0x0},
	{0x93420, 0x022D, 0x0},
	{0x93600, 0x0000, 0x0},
	{0x93604, 0x00FF, 0x0},
	{0x93608, 0x0000, 0x0},
	{0x9360C, 0x00FF, 0x0},
	{0x93610, 0x0000, 0x0},
	{0x93614, 0x00FF, 0x0},
	{0x93680, 0x0000, 0x0},
	{0x93684, 0x00FF, 0x0},
	{0x93688, 0x0000, 0x0},
	{0x9368C, 0x00FF, 0x0},
	{0x93690, 0x0000, 0x0},
	{0x93694, 0x00FF, 0x0},
	{0x90070, 0xCD298008, 0x0},
};

static struct mdp_reg ruy_auo_gamma[] = {
	{0x94800, 0x000000, 0x0},
	{0x94804, 0x010201, 0x0},
	{0x94808, 0x020202, 0x0},
	{0x9480C, 0x030304, 0x0},
	{0x94810, 0x040405, 0x0},
	{0x94814, 0x050506, 0x0},
	{0x94818, 0x060508, 0x0},
	{0x9481C, 0x070609, 0x0},
	{0x94820, 0x08070A, 0x0},
	{0x94824, 0x09080B, 0x0},
	{0x94828, 0x0A080C, 0x0},
	{0x9482C, 0x0B090E, 0x0},
	{0x94830, 0x0C0A0F, 0x0},
	{0x94834, 0x0D0B10, 0x0},
	{0x94838, 0x0E0B11, 0x0},
	{0x9483C, 0x0F0C12, 0x0},
	{0x94840, 0x100D13, 0x0},
	{0x94844, 0x110E14, 0x0},
	{0x94848, 0x120E15, 0x0},
	{0x9484C, 0x130F16, 0x0},
	{0x94850, 0x141016, 0x0},
	{0x94854, 0x151117, 0x0},
	{0x94858, 0x161118, 0x0},
	{0x9485C, 0x171219, 0x0},
	{0x94860, 0x18131A, 0x0},
	{0x94864, 0x19141A, 0x0},
	{0x94868, 0x1A151B, 0x0},
	{0x9486C, 0x1B151C, 0x0},
	{0x94870, 0x1C161D, 0x0},
	{0x94874, 0x1D171D, 0x0},
	{0x94878, 0x1E181E, 0x0},
	{0x9487C, 0x1F181F, 0x0},
	{0x94880, 0x201920, 0x0},
	{0x94884, 0x211A20, 0x0},
	{0x94888, 0x221B21, 0x0},
	{0x9488C, 0x231C22, 0x0},
	{0x94890, 0x241C22, 0x0},
	{0x94894, 0x251D23, 0x0},
	{0x94898, 0x261E23, 0x0},
	{0x9489C, 0x271F24, 0x0},
	{0x948A0, 0x282025, 0x0},
	{0x948A4, 0x292025, 0x0},
	{0x948A8, 0x2A2126, 0x0},
	{0x948AC, 0x2B2227, 0x0},
	{0x948B0, 0x2C2327, 0x0},
	{0x948B4, 0x2D2428, 0x0},
	{0x948B8, 0x2E2528, 0x0},
	{0x948BC, 0x2F2529, 0x0},
	{0x948C0, 0x30262A, 0x0},
	{0x948C4, 0x31272A, 0x0},
	{0x948C8, 0x32282B, 0x0},
	{0x948CC, 0x33292C, 0x0},
	{0x948D0, 0x34292C, 0x0},
	{0x948D4, 0x352A2D, 0x0},
	{0x948D8, 0x362B2D, 0x0},
	{0x948DC, 0x372C2E, 0x0},
	{0x948E0, 0x382D2F, 0x0},
	{0x948E4, 0x392E2F, 0x0},
	{0x948E8, 0x3A2E30, 0x0},
	{0x948EC, 0x3B2F30, 0x0},
	{0x948F0, 0x3C3030, 0x0},
	{0x948F4, 0x3D3131, 0x0},
	{0x948F8, 0x3E3231, 0x0},
	{0x948FC, 0x3F3332, 0x0},
	{0x94900, 0x403433, 0x0},
	{0x94904, 0x413434, 0x0},
	{0x94908, 0x423535, 0x0},
	{0x9490C, 0x433635, 0x0},
	{0x94910, 0x443735, 0x0},
	{0x94914, 0x453836, 0x0},
	{0x94918, 0x463937, 0x0},
	{0x9491C, 0x473938, 0x0},
	{0x94920, 0x483A39, 0x0},
	{0x94924, 0x493B3A, 0x0},
	{0x94928, 0x4A3C3B, 0x0},
	{0x9492C, 0x4B3D3C, 0x0},
	{0x94930, 0x4C3E3D, 0x0},
	{0x94934, 0x4C3E3E, 0x0},
	{0x94938, 0x4C3E3F, 0x0},
	{0x9493C, 0x4D3F40, 0x0},
	{0x94940, 0x4E4040, 0x0},
	{0x94944, 0x4F4041, 0x0},
	{0x94948, 0x504142, 0x0},
	{0x9494C, 0x514243, 0x0},
	{0x94950, 0x524344, 0x0},
	{0x94954, 0x534445, 0x0},
	{0x94958, 0x544546, 0x0},
	{0x9495C, 0x554546, 0x0},
	{0x94960, 0x564648, 0x0},
	{0x94964, 0x574748, 0x0},
	{0x94968, 0x584849, 0x0},
	{0x9496C, 0x5A4A4A, 0x0},
	{0x94970, 0x5C4B4A, 0x0},
	{0x94974, 0x5D4C4B, 0x0},
	{0x94978, 0x5E4D4C, 0x0},
	{0x9497C, 0x5F4E4D, 0x0},
	{0x94980, 0x604F4F, 0x0},
	{0x94984, 0x615050, 0x0},
	{0x94988, 0x625050, 0x0},
	{0x9498C, 0x635151, 0x0},
	{0x94990, 0x645252, 0x0},
	{0x94994, 0x655353, 0x0},
	{0x94998, 0x665454, 0x0},
	{0x9499C, 0x675556, 0x0},
	{0x949A0, 0x685657, 0x0},
	{0x949A4, 0x695758, 0x0},
	{0x949A8, 0x6A5759, 0x0},
	{0x949AC, 0x6B585A, 0x0},
	{0x949B0, 0x6C595B, 0x0},
	{0x949B4, 0x6D5A5D, 0x0},
	{0x949B8, 0x6E5B5E, 0x0},
	{0x949BC, 0x6F5C5F, 0x0},
	{0x949C0, 0x705D60, 0x0},
	{0x949C4, 0x715D61, 0x0},
	{0x949C8, 0x725E62, 0x0},
	{0x949CC, 0x735F63, 0x0},
	{0x949D0, 0x746064, 0x0},
	{0x949D4, 0x756166, 0x0},
	{0x949D8, 0x766267, 0x0},
	{0x949DC, 0x776368, 0x0},
	{0x949E0, 0x786469, 0x0},
	{0x949E4, 0x79646A, 0x0},
	{0x949E8, 0x7A656B, 0x0},
	{0x949EC, 0x7B666C, 0x0},
	{0x949F0, 0x7C676E, 0x0},
	{0x949F4, 0x7D686F, 0x0},
	{0x949F8, 0x7E6970, 0x0},
	{0x949FC, 0x7F6A71, 0x0},
	{0x94A00, 0x806B72, 0x0},
	{0x94A04, 0x816B74, 0x0},
	{0x94A08, 0x826C75, 0x0},
	{0x94A0C, 0x836D76, 0x0},
	{0x94A10, 0x846E77, 0x0},
	{0x94A14, 0x856F78, 0x0},
	{0x94A18, 0x867079, 0x0},
	{0x94A1C, 0x87717B, 0x0},
	{0x94A20, 0x88727C, 0x0},
	{0x94A24, 0x89737D, 0x0},
	{0x94A28, 0x8A737E, 0x0},
	{0x94A2C, 0x8B747F, 0x0},
	{0x94A30, 0x8C7581, 0x0},
	{0x94A34, 0x8D7682, 0x0},
	{0x94A38, 0x8E7783, 0x0},
	{0x94A3C, 0x8F7884, 0x0},
	{0x94A40, 0x907985, 0x0},
	{0x94A44, 0x917A87, 0x0},
	{0x94A48, 0x927B88, 0x0},
	{0x94A4C, 0x937B89, 0x0},
	{0x94A50, 0x947C8A, 0x0},
	{0x94A54, 0x957D8B, 0x0},
	{0x94A58, 0x967E8D, 0x0},
	{0x94A5C, 0x977F8E, 0x0},
	{0x94A60, 0x98808F, 0x0},
	{0x94A64, 0x998190, 0x0},
	{0x94A68, 0x9A8291, 0x0},
	{0x94A6C, 0x9B8393, 0x0},
	{0x94A70, 0x9C8494, 0x0},
	{0x94A74, 0x9D8595, 0x0},
	{0x94A78, 0x9E8696, 0x0},
	{0x94A7C, 0x9F8697, 0x0},
	{0x94A80, 0xA08798, 0x0},
	{0x94A84, 0xA18899, 0x0},
	{0x94A88, 0xA2899B, 0x0},
	{0x94A8C, 0xA38A9C, 0x0},
	{0x94A90, 0xA48B9D, 0x0},
	{0x94A94, 0xA58C9E, 0x0},
	{0x94A98, 0xA68D9F, 0x0},
	{0x94A9C, 0xA78EA0, 0x0},
	{0x94AA0, 0xA88FA1, 0x0},
	{0x94AA4, 0xA990A2, 0x0},
	{0x94AA8, 0xAA91A4, 0x0},
	{0x94AAC, 0xAB92A5, 0x0},
	{0x94AB0, 0xAC93A6, 0x0},
	{0x94AB4, 0xAD94A7, 0x0},
	{0x94AB8, 0xAE95A8, 0x0},
	{0x94ABC, 0xAF96A9, 0x0},
	{0x94AC0, 0xB097AA, 0x0},
	{0x94AC4, 0xB198AB, 0x0},
	{0x94AC8, 0xB299AC, 0x0},
	{0x94ACC, 0xB39AAD, 0x0},
	{0x94AD0, 0xB49BAE, 0x0},
	{0x94AD4, 0xB59CAF, 0x0},
	{0x94AD8, 0xB69DB0, 0x0},
	{0x94ADC, 0xB79EB1, 0x0},
	{0x94AE0, 0xB89FB2, 0x0},
	{0x94AE4, 0xB9A0B3, 0x0},
	{0x94AE8, 0xBAA1B4, 0x0},
	{0x94AEC, 0xBBA2B5, 0x0},
	{0x94AF0, 0xBCA3B6, 0x0},
	{0x94AF4, 0xBDA4B7, 0x0},
	{0x94AF8, 0xBEA5B8, 0x0},
	{0x94AFC, 0xBFA6B9, 0x0},
	{0x94B00, 0xC0A7BA, 0x0},
	{0x94B04, 0xC1A8BB, 0x0},
	{0x94B08, 0xC2A9BC, 0x0},
	{0x94B0C, 0xC3AABD, 0x0},
	{0x94B10, 0xC4ACBE, 0x0},
	{0x94B14, 0xC5ADBF, 0x0},
	{0x94B18, 0xC6AEC0, 0x0},
	{0x94B1C, 0xC7AFC1, 0x0},
	{0x94B20, 0xC8B0C2, 0x0},
	{0x94B24, 0xC9B1C3, 0x0},
	{0x94B28, 0xCAB2C4, 0x0},
	{0x94B2C, 0xCBB3C5, 0x0},
	{0x94B30, 0xCCB5C6, 0x0},
	{0x94B34, 0xCDB6C6, 0x0},
	{0x94B38, 0xCEB7C7, 0x0},
	{0x94B3C, 0xCFB8C8, 0x0},
	{0x94B40, 0xD0B9C9, 0x0},
	{0x94B44, 0xD1BBCA, 0x0},
	{0x94B48, 0xD2BCCB, 0x0},
	{0x94B4C, 0xD3BDCC, 0x0},
	{0x94B50, 0xD4BECD, 0x0},
	{0x94B54, 0xD5BFCE, 0x0},
	{0x94B58, 0xD6C1CF, 0x0},
	{0x94B5C, 0xD7C2D0, 0x0},
	{0x94B60, 0xD8C3D1, 0x0},
	{0x94B64, 0xD9C4D2, 0x0},
	{0x94B68, 0xDAC6D3, 0x0},
	{0x94B6C, 0xDBC7D3, 0x0},
	{0x94B70, 0xDCC8D4, 0x0},
	{0x94B74, 0xDDCAD5, 0x0},
	{0x94B78, 0xDECBD6, 0x0},
	{0x94B7C, 0xDFCCD7, 0x0},
	{0x94B80, 0xE0CED8, 0x0},
	{0x94B84, 0xE1CFD9, 0x0},
	{0x94B88, 0xE2D1DA, 0x0},
	{0x94B8C, 0xE3D2DB, 0x0},
	{0x94B90, 0xE4D3DC, 0x0},
	{0x94B94, 0xE5D5DD, 0x0},
	{0x94B98, 0xE6D6DE, 0x0},
	{0x94B9C, 0xE7D8DF, 0x0},
	{0x94BA0, 0xE8D9E0, 0x0},
	{0x94BA4, 0xE9DBE2, 0x0},
	{0x94BA8, 0xEADCE3, 0x0},
	{0x94BAC, 0xEBDEE4, 0x0},
	{0x94BB0, 0xECDFE5, 0x0},
	{0x94BB4, 0xEDE1E6, 0x0},
	{0x94BB8, 0xEEE2E7, 0x0},
	{0x94BBC, 0xEFE4E8, 0x0},
	{0x94BC0, 0xF0E5EA, 0x0},
	{0x94BC4, 0xF1E7EB, 0x0},
	{0x94BC8, 0xF2E9EC, 0x0},
	{0x94BCC, 0xF3EAED, 0x0},
	{0x94BD0, 0xF4ECEF, 0x0},
	{0x94BD4, 0xF5EDF0, 0x0},
	{0x94BD8, 0xF6EFF1, 0x0},
	{0x94BDC, 0xF7F1F3, 0x0},
	{0x94BE0, 0xF8F3F4, 0x0},
	{0x94BE4, 0xF9F4F6, 0x0},
	{0x94BE8, 0xFAF6F7, 0x0},
	{0x94BEC, 0xFBF8F9, 0x0},
	{0x94BF0, 0xFCFAFA, 0x0},
	{0x94BF4, 0xFDFBFC, 0x0},
	{0x94BF8, 0xFEFDFD, 0x0},
	{0x94BFC, 0xFFFFFF, 0x0},
	{0x90070, 0x1F, 0x0},
};

int ruby_mdp_gamma(void)
{
	mdp_color_enhancement(ruby_color_enhancement, ARRAY_SIZE(ruby_color_enhancement));

	if (panel_type == PANEL_ID_PYD_AUO_NT)
		mdp_color_enhancement(ruy_auo_gamma, ARRAY_SIZE(ruy_auo_gamma));
	
	return 0;
}

static struct msm_panel_common_pdata mdp_pdata = {
	.gpio = 28,
	.mdp_max_clk = 200000000,
#ifdef CONFIG_MSM_BUS_SCALING
	.mdp_bus_scale_table = &mdp_bus_scale_pdata,
#endif
	.mdp_rev = MDP_REV_41,
#ifdef CONFIG_MSM_MULTIMEDIA_USE_ION
	.mem_hid = BIT(ION_CP_WB_HEAP_ID),
#else
	.mem_hid = MEMTYPE_EBI1,
#endif
	.mdp_gamma = ruby_mdp_gamma,
};

void __init ruby_mdp_writeback(void)
{
	mdp_pdata.ov0_wb_size = MSM_FB_OVERLAY0_WRITEBACK_SIZE;
}

static int first_init = 1;

static uint32_t lcd_on_gpio[] = {
	GPIO_CFG(RUBY_GPIO_LCM_ID0, 0, GPIO_CFG_INPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),
};

static uint32_t lcd_off_gpio[] = {
	GPIO_CFG(RUBY_GPIO_LCM_ID0, 0, GPIO_CFG_OUTPUT, GPIO_CFG_NO_PULL, GPIO_CFG_2MA),
};

static int mipi_dsi_panel_power(const int on)
{
	static bool dsi_power_on = false;
	struct regulator *rgl_l19;
	struct regulator *rgl_l20;
	int rc;

	if (!dsi_power_on) {
		rgl_l19 = regulator_get(NULL, "8058_l19");
		if (IS_ERR(rgl_l19)) {
			PR_DISP_ERR("%s: unable to get 8058_l19\n", __func__);
			goto fail;
		}

		rgl_l20 = regulator_get(NULL, "8058_l20");
		if (IS_ERR(rgl_l20)) {
			PR_DISP_ERR("%s: unable to get 8058_l20\n", __func__);
			goto fail;
		}

		ret = regulator_set_voltage(rgl_l19, 3000000, 3000000);
		if (ret) {
			PR_DISP_ERR("%s: error setting l19_2v85 voltage\n", __func__);
			goto fail;
		}

		ret = regulator_set_voltage(rgl_l20, 1800000, 1800000);
		if (ret) {
			PR_DISP_ERR("%s: error setting l20_1v8 voltage\n", __func__);
			goto fail;
		}

		rc = gpio_request(RUBY_GPIO_LCM_RST_N,
			"LCM_RST_N");
		if (rc) {
			printk(KERN_ERR "%s:LCM gpio %d request"
					"failed\n", __func__,
					RUBY_GPIO_LCM_RST_N);
			return -EINVAL;
		}

		dsi_power_on = true;
	}

	if (!rgl_l19 || IS_ERR(rgl_l19)) {
		PR_DISP_ERR("%s: l19_2v85 is not initialized\n", __func__);
		return;
	}

	if (!rgl_l20 || IS_ERR(rgl_l20)) {
		PR_DISP_ERR("%s: l20_1v8 is not initialized\n", __func__);
		return;
	}

	if (on) {
		gpio_tlmm_config(lcd_on_gpio[0], GPIO_CFG_ENABLE);

		if (regulator_enable(rgl_l19)) {
			PR_DISP_ERR("%s: Unable to enable the regulator:"
					" l19_2v85\n", __func__);
			return;
		}
		hr_msleep(5);

		if (regulator_enable(rgl_l20)) {
			PR_DISP_ERR("%s: Unable to enable the regulator:"
				" l20_1v8\n", __func__);
			return;
		}

		if (!first_init) {
			hr_msleep(10);
			gpio_set_value(RUBY_GPIO_LCM_RST_N, 1);
			hr_msleep(1);
			gpio_set_value(RUBY_GPIO_LCM_RST_N, 0);
			hr_msleep(1);
			gpio_set_value(RUBY_GPIO_LCM_RST_N, 1);
			hr_msleep(20);
		}
	} else {
		gpio_set_value(RUBY_GPIO_LCM_RST_N, 0);
		hr_msleep(5);
		if (regulator_disable(rgl_l20)) {
			PR_DISP_ERR("%s: Unable to enable the regulator:"
				" l20_1v8\n", __func__);
			return;
		}
		hr_msleep(5);
		if (regulator_disable(rgl_l19)) {
			PR_DISP_ERR("%s: Unable to enable the regulator:"
					" l19_2v85\n", __func__);
			return;
		}

		gpio_tlmm_config(lcd_off_gpio[0], GPIO_CFG_ENABLE);
		gpio_set_value(RUBY_GPIO_LCM_ID0, 0);
	}

	return 0;
}

static struct mipi_dsi_platform_data mipi_dsi_pdata = {
	.vsync_gpio = 28,
	.dsi_power_save = mipi_dsi_panel_power,
};

static struct dsi_buf panel_tx_buf;
static struct dsi_buf panel_rx_buf;

static char led_pwm1[] = {0x51, 0x0};
static char sw_reset[2] = {0x01, 0x00};
static char enter_sleep[2] = {0x10, 0x00};
static char exit_sleep[2] = {0x11, 0x00};
static char display_off[2] = {0x28, 0x00};
static char display_on[2] = {0x29, 0x00};
static char enable_te[2] = {0x35, 0x00};
static char test_reg[3] = {0x44, 0x02, 0xCF};
static char test_reg_ruy_auo[3] = {0x44, 0x01, 0x68};
static char test_reg_ruy_shp[3] = {0x44, 0x01, 0x68};
static char set_twolane[2] = {0xae, 0x03};
static char rgb_888[2] = {0x3A, 0x77};
static char novatek_e0[3] = {0xE0, 0x01, 0x03};
static char novatek_f4[2] = {0xf4, 0x55};
static char novatek_8c[16] = {
	0x8C, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x08, 0x00, 0x30, 0xC0, 0xB7, 0x37};
static char novatek_ff[2] = {0xff, 0x55 };
static char set_width[5] = {
	0x2A, 0x00, 0x00, 0x02, 0x1B};
static char set_height[5] = {
	0x2B, 0x00, 0x00, 0x03, 0xBF};
static char novatek_pwm_f3[2] = {0xF3, 0xAA };
static char novatek_pwm_00[2] = {0x00, 0x01 };
static char novatek_pwm_21[2] = {0x21, 0x20 };
static char novatek_pwm_22[2] = {0x22, 0x03 };
static char novatek_pwm_7d[2] = {0x7D, 0x01 };
static char novatek_pwm_7f[2] = {0x7F, 0xAA };
static char novatek_pwm_cp[2] = {0x09, 0x34 };
static char novatek_pwm_cp2[2] = {0xc9, 0x01 };
static char novatek_pwm_cp3[2] = {0xff, 0xaa };
static char max_pktsize[2] =  {MIPI_DSI_MRPS, 0x00};
static unsigned char bkl_enable_cmds[] = {0x53, 0x24};

static char ruy_shp_gamma1_d1[] = {
	0xD1, 0x00, 0x6D, 0x00,	0x76, 0x00, 0x88, 0x00,
	0x97, 0x00, 0xA5, 0x00,	0xBD, 0x00, 0xD0, 0x00,
	0xEE
};
static char ruy_shp_gamma1_d2[] = {
	0xD2, 0x01, 0x06, 0x01,	0x2B, 0x01, 0x46, 0x01,
	0x6B, 0x01, 0x83, 0x01,	0x84, 0x01, 0xA1, 0x01,
	0xC4
};
static char ruy_shp_gamma1_d3[] = {
	0xD3, 0x01, 0xD3, 0x01,	0xE4, 0x01, 0xF3, 0x02,
	0x0F, 0x02, 0x28, 0x02,	0x65, 0x02, 0x87, 0x02,
	0x95
};
static char ruy_shp_gamma1_d4[] = {
	0xD4, 0x02, 0x99, 0x02,	0x99
};
/* G+ */
static char ruy_shp_gamma1_d5[] = {
	0xD5, 0x00, 0xBE, 0x00,	0xC5, 0x00, 0xD2, 0x00,
	0xDD, 0x00, 0xE7, 0x00,	0xF9, 0x01, 0x09, 0x01,
	0x23
};
static char ruy_shp_gamma1_d6[] = {
	0xD6, 0x01, 0x35, 0x01,	0x4D, 0x01, 0x5F, 0x01,
	0x7A, 0x01, 0x93, 0x01,	0x93, 0x01, 0xA8, 0x01,
	0xC9
};
static char ruy_shp_gamma1_d7[] = {
	0xD7, 0x01, 0xD8, 0x01,	0xE8, 0x01, 0xF6, 0x02,
	0x11, 0x02, 0x29, 0x02,	0x49, 0x02, 0x71, 0x02,
	0x91
};
static char ruy_shp_gamma1_d8[] = {
	0xD8, 0x02, 0x99, 0x02,	0x99
};
/* B+ */
static char ruy_shp_gamma1_d9[] = {
	0xD9, 0x00, 0x84, 0x00,	0x93, 0x00, 0xAE, 0x00,
	0xC5, 0x00, 0xD6, 0x00,	0xF1, 0x01, 0x08, 0x01,
	0x29
};
static char ruy_shp_gamma1_dd[] = {
	0xDD, 0x01, 0x3D, 0x01,	0x5A, 0x01, 0x6D, 0x01,
	0x81, 0x01, 0x97, 0x01,	0x97, 0x01, 0xAC, 0x01,
	0xCD
};
static char ruy_shp_gamma1_de[] = {
	0xDE, 0x01, 0xDD, 0x01,	0xE7, 0x01, 0xF6, 0x02,
	0x0E, 0x02, 0x34, 0x02,	0x6A, 0x02, 0x75, 0x02,
	0x90
};
static char ruy_shp_gamma1_df[] = {
	0xDF, 0x02, 0x99, 0x02,	0x99
};
/* R- */
static char ruy_shp_gamma1_e0[] = {
	0xE0, 0x00, 0x8D, 0x00,	0x99, 0x00, 0xB0, 0x00,
	0xC5, 0x00, 0xD8, 0x00,	0xF9, 0x01, 0x14, 0x01,
	0x3E
};
static char ruy_shp_gamma1_e1[] = {
	0xE1, 0x01, 0x60, 0x01,	0x96, 0x01, 0xBF, 0x01,
	0xF8, 0x02, 0x20, 0x02,	0x22, 0x02, 0x57, 0x02,
	0x9C
};
static char ruy_shp_gamma1_e2[] = {
	0xE2, 0x02, 0xBE, 0x02,	0xE7, 0x03, 0x0C, 0x03,
	0x40, 0x03, 0x64, 0x03,	0xAB, 0x03, 0xD4, 0x03,
	0xE8
};
static char ruy_shp_gamma1_e3[] = {
	0xE3, 0x03, 0xED, 0x03,	0xEE
};
/* G- */
static char ruy_shp_gamma1_e4[] = {
	0xE4, 0x00, 0xFB, 0x01,	0x04, 0x01, 0x16, 0x01,
	0x26, 0x01, 0x34, 0x01,	0x4E, 0x01, 0x65, 0x01,
	0x8A
};
static char ruy_shp_gamma1_e5[] = {
	0xE5, 0x01, 0xA4, 0x01,	0xC9, 0x01, 0xE5, 0x02,
	0x11, 0x02, 0x3C, 0x02,	0x3D, 0x02, 0x63, 0x02,
	0xA9
};
static char ruy_shp_gamma1_e6[] = {
	0xE6, 0x02, 0xCB, 0x02,	0xF0, 0x03, 0x14, 0x03,
	0x44, 0x03, 0x64, 0x03,	0x8B, 0x03, 0xB9, 0x03,
	0xE2
};
static char ruy_shp_gamma1_e7[] = {
	0xE7, 0x03, 0xED, 0x03, 0xEE
};
/* B- */
static char ruy_shp_gamma1_e8[] = {
	0xE8, 0x00, 0xAB, 0x00,	0xC0, 0x00, 0xE5, 0x01,
	0x04, 0x01, 0x1C, 0x01,	0x43, 0x01, 0x62, 0x01,
	0x92
};
static char ruy_shp_gamma1_e9[] = {
	0xE9, 0x01, 0xB1, 0x01,	0xDD, 0x01, 0xFB, 0x02,
	0x1D, 0x02, 0x43, 0x02,	0x44, 0x02, 0x6C, 0x02,
	0xB0
};
static char ruy_shp_gamma1_ea[] = {
	0xEA, 0x02, 0xD5, 0x02,	0xED, 0x03, 0x12, 0x03,
	0x3F, 0x03, 0x73, 0x03,	0xB0, 0x03, 0xBD, 0x03,
	0xE0
};
static char ruy_shp_gamma1_eb[] = {
	0xEB, 0x03, 0xED, 0x03,	0xEE
};

/* Gamma for cut 2 */
/* R+ */
static char ruy_shp_gamma2_d1[] = {
	0xD1, 0x00, 0x6D, 0x00,	0x76, 0x00, 0x88, 0x00,
	0x97, 0x00, 0xA5, 0x00,	0xBD, 0x00, 0xD0, 0x00,
	0xEE
};
static char ruy_shp_gamma2_d2[] = {
	0xD2, 0x01, 0x06, 0x01,	0x2B, 0x01, 0x46, 0x01,
	0x6B, 0x01, 0x83, 0x01,	0x84, 0x01, 0xA1, 0x01,
	0xC4
};
static char ruy_shp_gamma2_d3[] = {
	0xD3, 0x01, 0xD3, 0x01,	0xE4, 0x01, 0xF3, 0x02,
	0x0F, 0x02, 0x28, 0x02,	0x65, 0x02, 0x87, 0x02,
	0x95
};
static char ruy_shp_gamma2_d4[] = {
	0xD4, 0x02, 0x99, 0x02,	0x99
};
/* G+ */
static char ruy_shp_gamma2_d5[] = {
	0xD5, 0x00, 0xBE, 0x00,	0xC5, 0x00, 0xD2, 0x00,
	0xDD, 0x00, 0xE7, 0x00,	0xF9, 0x01, 0x09, 0x01,
	0x23
};
static char ruy_shp_gamma2_d6[] = {
	0xD6, 0x01, 0x35, 0x01,	0x4D, 0x01, 0x5F, 0x01,
	0x7A, 0x01, 0x93, 0x01,	0x93, 0x01, 0xA8, 0x01,
	0xC9
};
static char ruy_shp_gamma2_d7[] = {
	0xD7, 0x01, 0xD8, 0x01,	0xE8, 0x01, 0xF6, 0x02,
	0x11, 0x02, 0x29, 0x02,	0x49, 0x02, 0x71, 0x02,
	0x91
};
static char ruy_shp_gamma2_d8[] = {
	0xD8, 0x02, 0x99, 0x02,	0x99
};
/* B+ */
static char ruy_shp_gamma2_d9[] = {
	0xD9, 0x00, 0x84, 0x00,	0x93, 0x00, 0xAE, 0x00,
	0xC5, 0x00, 0xD6, 0x00,	0xF1, 0x01, 0x08, 0x01,
	0x29
};
static char ruy_shp_gamma2_dd[] = {
	0xDD, 0x01, 0x3D, 0x01,	0x5A, 0x01, 0x6D, 0x01,
	0x81, 0x01, 0x97, 0x01,	0x97, 0x01, 0xAC, 0x01,
	0xCD
};
static char ruy_shp_gamma2_de[] = {
	0xDE, 0x01, 0xDD, 0x01,	0xE7, 0x01, 0xF6, 0x02,
	0x0E, 0x02, 0x34, 0x02,	0x6A, 0x02, 0x75, 0x02,
	0x90
};
static char ruy_shp_gamma2_df[] = {
	0xDF, 0x02, 0x99, 0x02,	0x99
};
/* R- */
static char ruy_shp_gamma2_e0[] = {
	0xE0, 0x00, 0x8D, 0x00,	0x99, 0x00, 0xB0, 0x00,
	0xC5, 0x00, 0xD8, 0x00,	0xF9, 0x01, 0x14, 0x01,
	0x3E
};
static char ruy_shp_gamma2_e1[] = {
	0xE1, 0x01, 0x60, 0x01,	0x96, 0x01, 0xBF, 0x01,
	0xF8, 0x02, 0x20, 0x02,	0x22, 0x02, 0x57, 0x02,
	0x9C
};
static char ruy_shp_gamma2_e2[] = {
	0xE2, 0x02, 0xBE, 0x02,	0xE7, 0x03, 0x0C, 0x03,
	0x40, 0x03, 0x64, 0x03,	0xAB, 0x03, 0xD4, 0x03,
	0xE8
};
static char ruy_shp_gamma2_e3[] = {
	0xE3, 0x03, 0xED, 0x03,	0xEE
};
/* G- */
static char ruy_shp_gamma2_e4[] = {
	0xE4, 0x00, 0xFB, 0x01,	0x04, 0x01, 0x16, 0x01,
	0x26, 0x01, 0x34, 0x01,	0x4E, 0x01, 0x65, 0x01,
	0x8A
};
static char ruy_shp_gamma2_e5[] = {
	0xE5, 0x01, 0xA4, 0x01,	0xC9, 0x01, 0xE5, 0x02,
	0x11, 0x02, 0x3C, 0x02,	0x3D, 0x02, 0x63, 0x02,
	0xA9
};
static char ruy_shp_gamma2_e6[] = {
	0xE6, 0x02, 0xCB, 0x02,	0xF0, 0x03, 0x14, 0x03,
	0x44, 0x03, 0x64, 0x03,	0x8B, 0x03, 0xB9, 0x03,
	0xE2
};
static char ruy_shp_gamma2_e7[] = {
	0xE7, 0x03, 0xED, 0x03, 0xEE
};
/* B- */
static char ruy_shp_gamma2_e8[] = {
	0xE8, 0x00, 0xAB, 0x00,	0xC0, 0x00, 0xE5, 0x01,
	0x04, 0x01, 0x1C, 0x01,	0x43, 0x01, 0x62, 0x01,
	0x92
};
static char ruy_shp_gamma2_e9[] = {
	0xE9, 0x01, 0xB1, 0x01,	0xDD, 0x01, 0xFB, 0x02,
	0x1D, 0x02, 0x43, 0x02,	0x44, 0x02, 0x6C, 0x02,
	0xB0
};
static char ruy_shp_gamma2_ea[] = {
	0xEA, 0x02, 0xD5, 0x02,	0xED, 0x03, 0x12, 0x03,
	0x3F, 0x03, 0x73, 0x03,	0xB0, 0x03, 0xBD, 0x03,
	0xE0
};
static char ruy_shp_gamma2_eb[] = {
	0xEB, 0x03, 0xED, 0x03,	0xEE
};

static struct dsi_cmd_desc ruy_shp_cmd_on_cmds[] = {
	/* added by our own */
	{ DTYPE_DCS_WRITE, 1, 0, 0, 10,
		sizeof(sw_reset), sw_reset },

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		5, (char[]){ 0xFF, 0xAA, 0x55, 0x25, 0x01 } },

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		17, (char[]){ 0xFA, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00,
					  0x00, 0x03, 0x20, 0x12,
					  0x20, 0xFF, 0xFF, 0xFF } },/* 90Hz -> 60Hz */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		5, (char[]){ 0xF3, 0x03, 0x03, 0x07, 0x14 } },/* vertical noise*/

	{ DTYPE_DCS_WRITE, 1, 0, 0, 120,
		sizeof(exit_sleep), exit_sleep },

	/* page 0 */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x08, 0x00 } },/* select page 0 */

	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		2, (char[]){ 0xB1, 0xFC } },/* display option */
	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		2, (char[]){ 0xB6, 0x07 } },/* output data hold time */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		3, (char[]){ 0xB7, 0x00, 0x00 } },/* EQ gate signal */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		5, (char[]){ 0xB8, 0x00, 0x07, 0x07, 0x07 } },/* EQ source driver */

	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		2, (char[]){ 0xBA, 0x02 } },/* vertical porch */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		4, (char[]){ 0xBB, 0x83, 0x03, 0x83 } },/* source driver (vertical noise) */

	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		2, (char[]){ 0xBC, 0x02 } },/* inversion driving */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		5, (char[]){ 0xBD, 0x01, 0x4B, 0x08, 0x26 } },/* timing control (normal mode) */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		12, (char[]){ 0xC7, 0x00, 0x0F, 0x0F, 0x06, 0x07, 0x09, 0x0A, 0x0A, 0x0A, 0xF0, 0xF0 } },/* timing control */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		ARRAY_SIZE(novatek_e0), novatek_e0 },/* PWM frequency = 13kHz */

	/* page 1 */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x08, 0x01 } },/* select page 1 */

	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){ 0xB0, 0x1F} },
	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){ 0xB1, 0x1F} },
	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){ 0xB3, 0x0D} },
	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){ 0xB4, 0x0F} },
	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){ 0xB6, 0x44} },
	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){ 0xB7, 0x24} },
	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){ 0xB9, 0x27} },
	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){ 0xBA, 0x24} },

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		4, (char[]){ 0xBC, 0x00, 0xC8, 0x00 } },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		4, (char[]){ 0xBD, 0x00, 0x78, 0x00 } },

	/* enter gamma table */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d1), ruy_shp_gamma1_d1 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d2), ruy_shp_gamma1_d2 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d3), ruy_shp_gamma1_d3 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d4), ruy_shp_gamma1_d4 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d5), ruy_shp_gamma1_d5 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d6), ruy_shp_gamma1_d6 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d7), ruy_shp_gamma1_d7 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d8), ruy_shp_gamma1_d8 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_d9), ruy_shp_gamma1_d9 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_dd), ruy_shp_gamma1_dd },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_de), ruy_shp_gamma1_de },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_df), ruy_shp_gamma1_df },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e0), ruy_shp_gamma1_e0 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e1), ruy_shp_gamma1_e1 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e2), ruy_shp_gamma1_e2 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e3), ruy_shp_gamma1_e3 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e4), ruy_shp_gamma1_e4 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e5), ruy_shp_gamma1_e5 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e6), ruy_shp_gamma1_e6 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e7), ruy_shp_gamma1_e7 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e8), ruy_shp_gamma1_e8 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_e9), ruy_shp_gamma1_e9 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_ea), ruy_shp_gamma1_ea },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma1_eb), ruy_shp_gamma1_eb },
	/* leave gamma table */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x00, 0x00 } },/* select page 0 */

	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(enable_te), enable_te },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(test_reg_ruy_shp), test_reg_ruy_shp },

	{ DTYPE_MAX_PKTSIZE, 1, 0, 0, 0,
		sizeof(max_pktsize), max_pktsize },

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_width), set_width },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_height), set_height },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(display_on), display_on },
};

static struct dsi_cmd_desc ruy_shp_c2_cmd_on_cmds[] = {
	/* added by our own */
	{ DTYPE_DCS_WRITE, 1, 0, 0, 10,
		sizeof(sw_reset), sw_reset },

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		5, (char[]){ 0xFF, 0xAA, 0x55, 0x25, 0x01 } },

	{ DTYPE_DCS_WRITE, 1, 0, 0, 120,
		sizeof(exit_sleep), exit_sleep },

	/* page 0 */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x08, 0x00 } },/* select page 0 */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		ARRAY_SIZE(novatek_e0), novatek_e0 },/* PWM frequency = 13kHz */

	/* page 1 */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x08, 0x01 } },/* select page 1 */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		4, (char[]){ 0xBC, 0x00, 0xC0, 0x00 } },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		4, (char[]){ 0xBD, 0x00, 0x70, 0x00 } },

	/* enter gamma table */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d1), ruy_shp_gamma2_d1 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d2), ruy_shp_gamma2_d2 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d3), ruy_shp_gamma2_d3 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d4), ruy_shp_gamma2_d4 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d5), ruy_shp_gamma2_d5 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d6), ruy_shp_gamma2_d6 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d7), ruy_shp_gamma2_d7 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d8), ruy_shp_gamma2_d8 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_d9), ruy_shp_gamma2_d9 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_dd), ruy_shp_gamma2_dd },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_de), ruy_shp_gamma2_de },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_df), ruy_shp_gamma2_df },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e0), ruy_shp_gamma2_e0 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e1), ruy_shp_gamma2_e1 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e2), ruy_shp_gamma2_e2 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e3), ruy_shp_gamma2_e3 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e4), ruy_shp_gamma2_e4 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e5), ruy_shp_gamma2_e5 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e6), ruy_shp_gamma2_e6 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e7), ruy_shp_gamma2_e7 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e8), ruy_shp_gamma2_e8 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_e9), ruy_shp_gamma2_e9 },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_ea), ruy_shp_gamma2_ea },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0, ARRAY_SIZE(ruy_shp_gamma2_eb), ruy_shp_gamma2_eb },
	/* leave gamma table */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x00, 0x00 } },/* select page 0 */

	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(enable_te), enable_te },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(test_reg_ruy_shp), test_reg_ruy_shp },

	{ DTYPE_MAX_PKTSIZE, 1, 0, 0, 0,
		sizeof(max_pktsize), max_pktsize },

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_width), set_width },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_height), set_height },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(display_on), display_on },
};

static struct dsi_cmd_desc ruy_shp_c2o_cmd_on_cmds[] = {
	/* added by our own */
	{ DTYPE_DCS_WRITE, 1, 0, 0, 10,
		sizeof(sw_reset), sw_reset },

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		5, (char[]){ 0xFF, 0xAA, 0x55, 0x25, 0x01 } },

	{ DTYPE_DCS_WRITE, 1, 0, 0, 120,
		sizeof(exit_sleep), exit_sleep },

	/* page 0 */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x08, 0x00 } },/* select page 0 */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		ARRAY_SIZE(novatek_e0), novatek_e0 },/* PWM frequency = 13kHz */

	/* page 1 */
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x08, 0x01 } },/* select page 1 */

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		6, (char[]){ 0xF0, 0x55, 0xAA, 0x52, 0x00, 0x00 } },/* select page 0 */

	{ DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(enable_te), enable_te },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(test_reg_ruy_shp), test_reg_ruy_shp },

	{ DTYPE_MAX_PKTSIZE, 1, 0, 0, 0,
		sizeof(max_pktsize), max_pktsize },

	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_width), set_width },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_height), set_height },
	{ DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(display_on), display_on },
};

static char pyd_sharp_gm[] = {
	0xf3, 0xaa,
	
	0x24, 0x00, 0x25, 0x04, 0x26, 0x11, 0x27, 0x1c, 0x28, 0x1a, 0x29, 0x2e,
	0x2a, 0x5e, 0x2b, 0x21, 0x2d, 0x1f, 0x2f, 0x27, 0x30, 0x60, 0x31, 0x15,
	0x32, 0x3e, 0x33, 0x5f, 0x34, 0x7c, 0x35, 0x86, 0x36, 0x87, 0x37, 0x08,

	0x38, 0x01, 0x39, 0x06, 0x3a, 0x14, 0x3b, 0x21, 0x3d, 0x1a, 0x3f, 0x2d,
	0x40, 0x5f, 0x41, 0x33, 0x42, 0x20, 0x43, 0x27, 0x44, 0x7b, 0x45, 0x15,
	0x46, 0x3e, 0x47, 0x5f, 0x48, 0xa7, 0x49, 0xb3, 0x4a, 0xb4, 0x4b, 0x35,

	0x4c, 0x2a, 0x4d, 0x2d, 0x4e, 0x36, 0x4f, 0x3e, 0x50, 0x18, 0x51, 0x2a,
	0x52, 0x5c, 0x53, 0x2c, 0x54, 0x1d, 0x55, 0x25, 0x56, 0x65, 0x57, 0x12,
	0x58, 0x3a, 0x59, 0x57, 0x5a, 0x93, 0x5b, 0xb2, 0x5c, 0xb6, 0x5d, 0x37,

	0x5e, 0x30, 0x5f, 0x34, 0x60, 0x3e, 0x61, 0x46, 0x62, 0x19, 0x63, 0x2b,
	0x64, 0x5c, 0x65, 0x3f, 0x66, 0x1f, 0x67, 0x26, 0x68, 0x80, 0x69, 0x13,
	0x6a, 0x3c, 0x6b, 0x57, 0x6c, 0xc0, 0x6d, 0xe2, 0x6e, 0xe7, 0x6f, 0x68,

	0x70, 0x00, 0x71, 0x0a, 0x72, 0x26, 0x73, 0x37, 0x74, 0x1e, 0x75, 0x32,
	0x76, 0x60, 0x77, 0x32, 0x78, 0x1f, 0x79, 0x26, 0x7a, 0x68, 0x7b, 0x14,
	0x7c, 0x39, 0x7d, 0x59, 0x7e, 0x85, 0x7f, 0x86, 0x80, 0x87, 0x81, 0x08,

	0x82, 0x01, 0x83, 0x0c, 0x84, 0x2b, 0x85, 0x3e, 0x86, 0x1f, 0x87, 0x33,
	0x88, 0x61, 0x89, 0x45, 0x8a, 0x1f, 0x8b, 0x26, 0x8c, 0x84, 0x8d, 0x14,
	0x8e, 0x3a, 0x8f, 0x59, 0x90, 0xb1, 0x91, 0xb3, 0x92, 0xb4, 0x93, 0x35,
	
	0xc9, 0x01,
	0xff, 0xaa,
};

static struct dsi_cmd_desc pyd_sharp_cmd_on_cmds[] = {
	{DTYPE_DCS_WRITE, 1, 0, 0, 10,
		sizeof(sw_reset), sw_reset},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 0},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 2},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 4},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 6},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 8},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 10},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 12},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 14},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 16},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 18},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 20},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 22},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 24},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 26},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 28},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 30},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 32},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 34},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 36},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 38},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 40},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 42},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 44},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 46},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 48},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 50},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 52},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 54},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 56},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 58},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 60},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 62},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 64},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 66},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 68},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 70},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 72},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 74},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 76},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 78},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 80},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 82},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 84},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 86},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 88},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 90},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 92},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 94},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 96},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 98},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 100},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 102},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 104},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 106},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 108},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 110},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 112},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 114},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 116},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 118},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 120},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 122},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 124},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 126},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 128},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 130},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 132},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 134},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 136},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 138},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 140},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 142},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 144},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 146},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 148},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 150},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 152},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 154},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 156},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 158},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 160},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 162},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 164},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 166},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 168},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 170},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 172},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 174},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 176},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 178},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 180},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 182},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 184},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 186},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 188},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 190},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 192},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 194},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 196},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 198},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 200},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 202},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 204},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 206},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 208},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 210},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 212},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 214},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 216},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 218},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_sharp_gm + 220},
	{DTYPE_DCS_WRITE, 1, 0, 0, 120,
		sizeof(exit_sleep), exit_sleep},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_f3), novatek_pwm_f3},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_00), novatek_pwm_00},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_21), novatek_pwm_21},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_22), novatek_pwm_22},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_7d), novatek_pwm_7d},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_7f), novatek_pwm_7f},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_f3), novatek_pwm_f3},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_cp), novatek_pwm_cp},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_cp2), novatek_pwm_cp2},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_cp3), novatek_pwm_cp3},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(enable_te), enable_te},
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(test_reg), test_reg},
	{DTYPE_MAX_PKTSIZE, 1, 0, 0, 0,
		sizeof(max_pktsize), max_pktsize},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_f4), novatek_f4},
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(novatek_8c), novatek_8c},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_ff), novatek_ff},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(set_twolane), set_twolane},
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_width), set_width},
	{DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_height), set_height},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(rgb_888), rgb_888},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(bkl_enable_cmds), bkl_enable_cmds},
};

static char pyd_auo_gm[] = {
	0xf3, 0xaa,

	0x24, 0X63, 0X25, 0X6B, 0X26, 0X78, 0X27, 0X7E, 0X28, 0X19, 0X29, 0X2E,
	0x2A, 0X61, 0X2B, 0X61, 0X2D, 0X1b, 0X2F, 0X22, 0X30, 0X84, 0X31, 0X1B,
	0x32, 0X4F, 0X33, 0X63, 0X34, 0X28, 0X35, 0XDF, 0X36, 0XC9, 0X37, 0X69,

	0x38, 0X63, 0X39, 0X6B, 0X3A, 0X78, 0X3B, 0X7E, 0X3D, 0X19, 0X3F, 0X2E,
	0x40, 0X61, 0X41, 0X61, 0X42, 0X1b, 0X43, 0X22, 0X44, 0X84, 0X45, 0X1B,
	0x46, 0X4F, 0X47, 0X63, 0X48, 0XC7, 0X49, 0XDF, 0X4A, 0XC9, 0X4B, 0X69,

	0x4C, 0X45, 0X4D, 0X54, 0X4E, 0X64, 0X4F, 0X75, 0X50, 0X18, 0X51, 0X2E,
	0x52, 0X62, 0X53, 0X61, 0X54, 0X1D, 0X55, 0X26, 0X56, 0X9D, 0X57, 0X10,
	0x58, 0X39, 0X59, 0X55, 0X5A, 0XC3, 0X5B, 0XD7, 0X5C, 0XFF, 0X5D, 0X6B,

	0x5E, 0X45, 0X5F, 0X54, 0X60, 0X64, 0X61, 0X75, 0X62, 0X18, 0X63, 0X2E,
	0x64, 0X62, 0X65, 0X61, 0X66, 0X1D, 0X67, 0X26, 0X68, 0X65, 0X69, 0X10,
	0x6A, 0X39, 0X6B, 0X55, 0X6C, 0XC3, 0X6D, 0XD7, 0X6E, 0XFF, 0X6F, 0X6B,

	0x70, 0X7D, 0X71, 0X82, 0X72, 0X89, 0X73, 0X97, 0X74, 0X19, 0X75, 0X2E,
	0x76, 0X61, 0X77, 0X6E, 0X78, 0X1A, 0X79, 0X1E, 0X7A, 0X8E, 0X7B, 0X0C,
	0x7C, 0X27, 0X7D, 0X58, 0X7E, 0XCF, 0X7F, 0XD9, 0X80, 0XFc, 0X81, 0X68,

	0x82, 0X7D, 0X83, 0X82, 0X84, 0X89, 0X85, 0X97, 0X86, 0X19, 0X87, 0X2E,
	0x88, 0X61, 0X89, 0X6E, 0X8A, 0X1A, 0X8B, 0X1E, 0X8C, 0X8E, 0X8D, 0X0C,
	0x8E, 0X27, 0X8F, 0X58, 0X90, 0XCF, 0X91, 0XD9, 0X92, 0XFc, 0X93, 0X68,
	
	0xC9, 0x01,
	0xff, 0xaa,
};

static struct dsi_cmd_desc pyd_auo_cmd_on_cmds[] = {
    {DTYPE_DCS_WRITE, 1, 0, 0, 10,
		sizeof(sw_reset), sw_reset},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){0xf3, 0xaa} },
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){0xA3, 0xFF} },
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){0xA4, 0xFF} },
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){0xA5, 0xFF} },
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){0xA6, 0x01} },
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, (char[]){0xFF, 0xAA} },
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 0},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 2},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 4},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 6},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 8},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 10},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 12},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 14},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 16},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 18},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 20},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 22},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 24},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 26},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 28},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 30},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 32},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 34},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 36},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 38},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 40},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 42},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 44},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 46},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 48},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 50},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 52},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 54},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 56},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 58},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 60},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 62},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 64},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 66},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 68},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 70},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 72},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 74},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 76},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 78},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 80},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 82},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 84},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 86},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 88},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 90},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 92},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 94},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 96},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 98},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 100},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 102},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 104},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 106},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 108},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 110},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 112},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 114},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 116},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 118},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 120},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 122},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 124},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 126},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 128},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 130},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 132},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 134},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 136},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 138},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 140},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 142},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 144},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 146},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 148},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 150},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 152},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 154},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 156},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 158},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 160},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 162},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 164},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 166},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 168},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 170},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 172},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 174},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 176},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 178},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 180},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 182},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 184},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 186},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 188},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 190},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 192},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 194},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 196},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 198},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 200},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 202},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 204},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 206},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 208},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 210},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 212},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 214},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 216},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 218},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0, 2, pyd_auo_gm + 220},
	{DTYPE_DCS_WRITE, 1, 0, 0, 120,
			sizeof(exit_sleep), exit_sleep},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_f3), novatek_pwm_f3},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_00), novatek_pwm_00},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_21), novatek_pwm_21},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_22), novatek_pwm_22},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_7d), novatek_pwm_7d},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_7f), novatek_pwm_7f},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_f3), novatek_pwm_f3},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_cp), novatek_pwm_cp},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_cp2), novatek_pwm_cp2},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(novatek_pwm_cp3), novatek_pwm_cp3},
    {DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(enable_te), enable_te},
    {DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(test_reg_ruy_auo), test_reg_ruy_auo},
    {DTYPE_MAX_PKTSIZE, 1, 0, 0, 0,
		sizeof(max_pktsize), max_pktsize},
    {DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_width), set_width},
    {DTYPE_DCS_LWRITE, 1, 0, 0, 0,
		sizeof(set_height), set_height},
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(bkl_enable_cmds), bkl_enable_cmds},
};

static struct dsi_cmd_desc novatek_display_off_cmds[] = {
		{DTYPE_DCS_WRITE, 1, 0, 0, 0,
			sizeof(display_off), display_off},
		{DTYPE_DCS_WRITE, 1, 0, 0, 110,
			sizeof(enter_sleep), enter_sleep}
};

static struct dsi_cmd_desc novatek_cmd_backlight_cmds[] = {
	{DTYPE_DCS_WRITE1, 1, 0, 0, 0,
		sizeof(led_pwm1), led_pwm1},
};

static struct dsi_cmd_desc novatek_display_on_cmds[] = {
	{DTYPE_DCS_WRITE, 1, 0, 0, 0,
		sizeof(display_on), display_on},
};

static struct dcs_cmd_req cmdreq;

static int ruby_lcd_on(struct platform_device *pdev)
{
	struct msm_fb_data_type *mfd;
	struct mipi_panel_info *mipi;

	mfd = platform_get_drvdata(pdev);
	if (!mfd)
		return -ENODEV;
	if (mfd->key != MFD_KEY)
		return -EINVAL;

	mipi = &mfd->panel_info.mipi;

	if (!first_init) {
		if (mipi->mode == DSI_CMD_MODE) {
			if (panel_type == PANEL_ID_RUY_SHARP_NT) {
				cmdreq.cmds = ruy_shp_cmd_on_cmds;
				cmdreq.cmds_cnt = ARRAY_SIZE(ruy_shp_cmd_on_cmds);
				cmdreq.flags = CMD_REQ_COMMIT;
				cmdreq.rlen = 0;
				cmdreq.cb = NULL;

				mipi_dsi_cmdlist_put(&cmdreq);
			}
			else if (panel_type == PANEL_ID_RUY_SHARP_NT_C2) {
				cmdreq.cmds = ruy_shp_c2_cmd_on_cmds;
				cmdreq.cmds_cnt = ARRAY_SIZE(ruy_shp_c2_cmd_on_cmds);
				cmdreq.flags = CMD_REQ_COMMIT;
				cmdreq.rlen = 0;
				cmdreq.cb = NULL;

				mipi_dsi_cmdlist_put(&cmdreq);
			}
			else if (panel_type == PANEL_ID_RUY_SHARP_NT_C2O) {
				cmdreq.cmds = ruy_shp_c2o_cmd_on_cmds;
				cmdreq.cmds_cnt = ARRAY_SIZE(ruy_shp_c2o_cmd_on_cmds);
				cmdreq.flags = CMD_REQ_COMMIT;
				cmdreq.rlen = 0;
				cmdreq.cb = NULL;

				mipi_dsi_cmdlist_put(&cmdreq);
			}
			else if (panel_type == PANEL_ID_PYD_SHARP) {
				cmdreq.cmds = pyd_sharp_cmd_on_cmds;
				cmdreq.cmds_cnt = ARRAY_SIZE(pyd_sharp_cmd_on_cmds);
				cmdreq.flags = CMD_REQ_COMMIT;
				cmdreq.rlen = 0;
				cmdreq.cb = NULL;

				mipi_dsi_cmdlist_put(&cmdreq);
			}
			else if (panel_type == PANEL_ID_PYD_AUO_NT) {
				cmdreq.cmds = pyd_auo_cmd_on_cmds;
				cmdreq.cmds_cnt = ARRAY_SIZE(pyd_auo_cmd_on_cmds);
				cmdreq.flags = CMD_REQ_COMMIT;
				cmdreq.rlen = 0;
				cmdreq.cb = NULL;

				mipi_dsi_cmdlist_put(&cmdreq);
			}
		}
	}
	first_init = 0;

	return 0;
}

static void ruby_display_on(struct msm_fb_data_type *mfd)
{
	cmdreq.cmds = novatek_display_on_cmds;
	cmdreq.cmds_cnt = ARRAY_SIZE(novatek_display_on_cmds);
	cmdreq.flags = CMD_REQ_COMMIT;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;

	mipi_dsi_cmdlist_put(&cmdreq);
}

static void ruby_display_off(struct msm_fb_data_type *mfd)
{
	cmdreq.cmds = novatek_display_off_cmds;
	cmdreq.cmds_cnt = ARRAY_SIZE(novatek_display_off_cmds);
	cmdreq.flags = CMD_REQ_COMMIT;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;

	mipi_dsi_cmdlist_put(&cmdreq);
}

static int ruby_lcd_off(struct platform_device *pdev)
{
	struct msm_fb_data_type *mfd;

	mfd = platform_get_drvdata(pdev);

	if (!mfd)
		return -ENODEV;
	if (mfd->key != MFD_KEY)
		return -EINVAL;

	return 0;
}

#define BRI_SETTING_MIN           30
#define BRI_SETTING_DEF           143
#define BRI_SETTING_MAX           255

#define PWM_MIN                   9       /* 3.5% of max pwm */
#define PWM_DEFAULT_AUO           83     /* 32.67% of max pwm */
#define PWM_DEFAULT_SHARP	  100	/* 39.2% of max pwm */
#define PWM_MAX                   255

#define PWM_DEFAULT	\
	(panel_type == PANEL_ID_PYD_AUO_NT ? PWM_DEFAULT_AUO:PWM_DEFAULT_SHARP)

static unsigned char ruby_shrink_pwm(int val)
{
	unsigned char shrink_br = BRI_SETTING_MAX;

	if (val <= 0) {
		shrink_br = 0;
	} else if (val > 0 && (val < BRI_SETTING_MIN)) {
			shrink_br = PWM_MIN;
	} else if ((val >= BRI_SETTING_MIN) && (val <= BRI_SETTING_DEF)) {
			shrink_br = (val - 30) * (PWM_DEFAULT - PWM_MIN) /
		(BRI_SETTING_DEF - BRI_SETTING_MIN) + PWM_MIN;
	} else if (val > BRI_SETTING_DEF && val <= BRI_SETTING_MAX) {
			shrink_br = (val - 143) * (PWM_MAX - PWM_DEFAULT) /
		(BRI_SETTING_MAX - BRI_SETTING_DEF) + PWM_DEFAULT;
	} else if (val > BRI_SETTING_MAX)
			shrink_br = PWM_MAX;

	PR_DISP_DEBUG("brightness orig=%d, transformed=%d\n", val, shrink_br);

	return shrink_br;
}

static void ruby_set_backlight(struct msm_fb_data_type *mfd)
{
	if (panel_type == PANEL_ID_NONE) {
		led_pwm1[1] = ruby_shrink_pwm((unsigned char)(mfd->bl_level));
	} else {
		led_pwm1[1] = (unsigned char)(mfd->bl_level);
	}

	cmdreq.cmds = novatek_cmd_backlight_cmds;
	cmdreq.cmds_cnt = ARRAY_SIZE(novatek_cmd_backlight_cmds);
	cmdreq.flags = CMD_REQ_COMMIT;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;

	mipi_dsi_cmdlist_put(&cmdreq);
}

static int __devinit ruby_lcd_probe(struct platform_device *pdev)
{
	msm_fb_add_device(pdev);

	return 0;
}

static struct platform_driver this_driver = {
	.probe  = ruby_lcd_probe,
	.driver = {
		.name   = "mipi_novatek",
	},
};

struct msm_fb_panel_data ruby_panel_data = {
	.on		= ruby_lcd_on,
	.off		= ruby_lcd_off,
	.set_backlight	= ruby_set_backlight,
	.display_on	= ruby_display_on,
	.display_off	= ruby_display_off,
};

static struct msm_panel_info pinfo;
static int ch_used[3] = {0, 0, 0};

static int mipi_ruby_device_register(const char* dev_name, struct msm_panel_info *pinfo,
					u32 channel, u32 panel)
{
	struct platform_device *pdev = NULL;
	int ret;

	if ((channel >= 3) || ch_used[channel])
		return -ENODEV;

	ch_used[channel] = TRUE;

	pdev = platform_device_alloc(dev_name, (panel << 8)|channel);
	if (!pdev)
		return -ENOMEM;

	ruby_panel_data.panel_info = *pinfo;

	ret = platform_device_add_data(pdev, &ruby_panel_data,
		sizeof(ruby_panel_data));
	if (ret) {
		PR_DISP_ERR("%s: platform_device_add_data failed!\n", __func__);
		goto err_device_put;
	}

	ret = platform_device_add(pdev);
	if (ret) {
		PR_DISP_ERR("%s: platform_device_register failed!\n", __func__);
		goto err_device_put;
	}
	return 0;

err_device_put:
	platform_device_put(pdev);
	return ret;
}

static struct mipi_dsi_phy_ctrl dsi_cmd_mode_phy_db = {
	{0x03, 0x01, 0x01, 0x00},
	{0x96, 0x1E, 0x1E, 0x00, 0x3C, 0x3C, 0x1E, 0x28, 0x0b, 0x13, 0x04},
	{0x7f, 0x00, 0x00, 0x00},
	{0xee, 0x02, 0x86, 0x00},
	{0x41, 0x9c, 0xb9, 0xd6, 0x00, 0x50, 0x48, 0x63, 0x01, 0x0f, 0x07,
	0x05, 0x14, 0x03, 0x03, 0x03, 0x54, 0x06, 0x10, 0x04, 0x03 },
};

static int __init mipi_cmd_novatek_blue_qhd_pt_init(void)
{
	int ret;

	pinfo.xres = 540;
	pinfo.yres = 960;
	pinfo.type = MIPI_CMD_PANEL;
	pinfo.pdest = DISPLAY_1;
	pinfo.wait_cycle = 0;
	pinfo.bpp = 24;
	pinfo.width = 53;
	pinfo.height = 95;
	pinfo.lcdc.h_back_porch = 64;
	pinfo.lcdc.h_front_porch = 96;
	pinfo.lcdc.h_pulse_width = 32;
	pinfo.lcdc.v_back_porch = 16;
	pinfo.lcdc.v_front_porch = 16;
	pinfo.lcdc.v_pulse_width = 4;
	pinfo.lcdc.border_clr = 0;
	pinfo.lcdc.underflow_clr = 0xff;
	pinfo.lcdc.hsync_skew = 0;
	pinfo.bl_max = 255;
	pinfo.bl_min = 1;
	pinfo.fb_num = 2;
	pinfo.clk_rate = 482000000;
	pinfo.lcd.vsync_enable = TRUE;
	pinfo.lcd.hw_vsync_mode = TRUE;
	pinfo.lcd.refx100 = 6096;
	pinfo.lcd.v_back_porch = 16;
	pinfo.lcd.v_front_porch = 16;
	pinfo.lcd.v_pulse_width = 4;
	pinfo.mipi.mode = DSI_CMD_MODE;
	pinfo.mipi.dst_format = DSI_CMD_DST_FORMAT_RGB888;
	pinfo.mipi.vc = 0;
	pinfo.mipi.rgb_swap = DSI_RGB_SWAP_BGR;
	pinfo.mipi.data_lane0 = TRUE;
	pinfo.mipi.data_lane1 = TRUE;
	pinfo.mipi.t_clk_post = 0x0a;
	pinfo.mipi.t_clk_pre = 0x1e;
	pinfo.mipi.stream = 0;
	pinfo.mipi.mdp_trigger = DSI_CMD_TRIGGER_SW;
	pinfo.mipi.dma_trigger = DSI_CMD_TRIGGER_SW;
	pinfo.mipi.te_sel = 1;
	pinfo.mipi.interleave_max = 1;
	pinfo.mipi.insert_dcs_cmd = TRUE;
	pinfo.mipi.wr_mem_continue = 0x3c;
	pinfo.mipi.wr_mem_start = 0x2c;
	pinfo.mipi.dsi_phy_db = &dsi_cmd_mode_phy_db;

	ret = mipi_ruby_device_register("mipi_novatek", &pinfo, MIPI_DSI_PRIM,
						MIPI_DSI_PANEL_QHD_PT);
	if (ret)
		PR_DISP_ERR("%s: failed to register device!\n", __func__);

	return ret;
}

void __init ruby_init_fb(void)
{
	platform_device_register(&msm_fb_device);
	
	if(panel_type != PANEL_ID_NONE) {
		msm_fb_register_device("mdp", &mdp_pdata);
		msm_fb_register_device("mipi_dsi", &mipi_dsi_pdata);
	}
	
	msm_fb_register_device("dtv", &dtv_pdata);
}

static int __init ruby_panel_init(void)
{
	mipi_dsi_buf_alloc(&panel_tx_buf, DSI_BUF_SIZE);
	mipi_dsi_buf_alloc(&panel_rx_buf, DSI_BUF_SIZE);


	if (panel_type == PANEL_ID_RUY_SHARP_NT) {
		PR_DISP_INFO("%s: panel ID = PANEL_ID_RUY_SHARP_NT\n", __func__);
		mipi_cmd_novatek_blue_qhd_pt_init();
	} 
	else if (panel_type == PANEL_ID_RUY_SHARP_NT_C2) {
		PR_DISP_INFO("%s: panel ID = PANEL_ID_RUY_SHARP_NT_C2\n", __func__);
		mipi_cmd_novatek_blue_qhd_pt_init();
	} 
	else if (panel_type == PANEL_ID_RUY_SHARP_NT_C2O) {
		PR_DISP_INFO("%s: panel ID = PANEL_ID_RUY_SHARP_NT_C2O\n", __func__);
		mipi_cmd_novatek_blue_qhd_pt_init();
	} 
	else if (panel_type == PANEL_ID_PYD_SHARP) {
		PR_DISP_INFO("%s: panel ID = PANEL_ID_PYD_SHARP\n", __func__);
		mipi_cmd_novatek_blue_qhd_pt_init();
	} 
	else if (panel_type == PANEL_ID_PYD_AUO_NT) {
		PR_DISP_INFO("%s: panel ID = PANEL_ID_PYD_AUO_NT\n", __func__);
		mipi_cmd_novatek_blue_qhd_pt_init();
	} 
	else {
		PR_DISP_ERR("%s: panel not supported!\n", __func__);
		return -ENODEV;
	}

	return platform_driver_register(&this_driver);
}

device_initcall_sync(ruby_panel_init);
