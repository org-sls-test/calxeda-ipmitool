/*
 * Copyright (c) 2003 Sun Microsystems, Inc.  All Rights Reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistribution of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistribution in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of Sun Microsystems, Inc. or the names of
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * 
 * This software is provided "AS IS," without a warranty of any kind.
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES,
 * INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED.
 * SUN MICROSYSTEMS, INC. ("SUN") AND ITS LICENSORS SHALL NOT BE LIABLE
 * FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING
 * OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.  IN NO EVENT WILL
 * SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST REVENUE, PROFIT OR DATA,
 * OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL, INCIDENTAL OR
 * PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF
 * LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
 * EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#ifndef IPMI_CXOEM_H
#define IPMI_CXOEM_H

#if HAVE_CONFIG_H
# include <config.h>
#endif
#include <ipmitool/ipmi.h>
#include <ipmitool/ipmi_sdr.h>

#define IPMI_NETFN_CXOEM		0x3e

/*
 * CX IPMI OEM command ids
 */
#define IPMI_CXOEM_FW_DOWNLOAD		0xE0
#define IPMI_CXOEM_FW_GET_STATUS	0xE1
#define IPMI_CXOEM_FW_SET_STATUS	0xE2
#define IPMI_CXOEM_FW_RAW			0xE3
#define IPMI_CXOEM_FABRIC_GET_PARAM 0xE4
#define IPMI_CXOEM_FABRIC_SET_PARAM 0xE5
#define IPMI_CXOEM_DATA_ACCESS      0xE6
#define IPMI_CXOEM_FABRIC_ACCESS    0xE7

/*
 * CX-defined constants
 */
#define CXOEM_FWDL_START      1
#define CXOEM_FWDL_STOP       2
#define CXOEM_FWUL_START      3
#define CXOEM_FWUL_STOP       4


static const int CXOEM_SUCCESS              = 0;
static const int CXOEM_ERROR                = -1;


/*
 * OEM FW rq/rs structs
 */

typedef struct img_info_s {
	unsigned char id;
	unsigned char type;
	uint32_t img_addr;
	uint32_t img_size;
	uint32_t flags;
}__attribute__((packed)) img_info_t;

struct cx_fw_info_rs {
	unsigned char ver;      /* param version */
	unsigned char count;	/* number of bytes */
	img_info_t img_info;
} __attribute__ ((packed));


/*
 * Prototypes
 */
int ipmi_cxoem_main(struct ipmi_intf *, int, char **);

#endif /*IPMI_CXOEM_H*/

