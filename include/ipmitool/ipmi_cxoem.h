/*
 * Copyright (c) 2011 Calxeda, Inc.  All Rights Reserved.
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
 * Neither the name of Calxeda, Inc. or the names of
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * This software is provided "AS IS," without a warranty of any kind.
 */

#ifndef IPMI_CXOEM_H
#define IPMI_CXOEM_H

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <ipmitool/ipmi.h>
#include <ipmitool/ipmi_sdr.h>

#define CX_VERSION				"-cx6"
#define IPMI_NETFN_OEM_SS		0x3e

/*
 * CX IPMI OEM command ids
 */
#define MSG_ELEMENT_TERMINATOR  0xff
#define MSG_PARAM_VAL_START_SCALAR  	0xf0
#define MSG_PARAM_VAL_START_STRING  	0xf1
#define MSG_PARAM_VAL_START_IPV4_ADDR  	0xf2
#define MSG_PARAM_VAL_START_MAC_ADDR  	0xf3
#define MSG_PARAM_VAL_START_BITMAP  	0xf4

#define IPMI_CMD_OEM_GET_DEVICE_INFO                0x01
#define IPMI_CMD_OEM_FEATURES_ENABLE                0xD0
#define IPMI_CMD_OEM_FW_DOWNLOAD                    0xE0
#define IPMI_CMD_OEM_FW_GET_STATUS                  0xE1
#define IPMI_CMD_OEM_FW_SET_STATUS                  0xE2
#define IPMI_CMD_OEM_FW_RAW                         0xE3
#define IPMI_CMD_OEM_FABRIC_GET                     0xE4
#define IPMI_CMD_OEM_FABRIC_SET                     0xE5
#define IPMI_CMD_OEM_FABRIC_CONFIG_GET				0xE6
#define IPMI_CMD_OEM_FABRIC_CONFIG_SET				0xE7
#define IPMI_CMD_OEM_FABRIC_UPDATE_CONFIG           0xE8
#define IPMI_CMD_OEM_FW_RESET                       0xE9
#define IPMI_CMD_OEM_DATA_ACCESS                    0xEA
#define IPMI_CMD_OEM_FABRIC_ADD						0xEB
#define IPMI_CMD_OEM_FABRIC_RM						0xEC
#define IPMI_CMD_OEM_TEST                           0xED
#define IPMI_CMD_OEM_FABRIC_INFO					0xEE
#define IPMI_CMD_OEM_FABRIC_SET_WATCH				0xEF
#define IPMI_CMD_OEM_FABRIC_CLEAR_WATCH				0xF0
#define IPMI_CMD_OEM_FABRIC_FACTORY_DEFAULT         0xF1
#define IPMI_CMD_OEM_FABRIC_CREATE					0xF2
#define IPMI_CMD_OEM_FABRIC_DELETE					0xF3
#define IPMI_CMD_OEM_FABRIC_TRACE					0xF4
#define IPMI_CMD_OEM_FRU_RESET			    0xF5
#define IPMI_CMD_OEM_PMIC_FW_WRITE			0xF6
#define IPMI_CMD_OEM_PMIC_GET_PARAM			0xF7

#define IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR        		0x01
#define IPMI_CMD_OEM_FABRIC_PARAMETER_NETMASK       		0x02
#define IPMI_CMD_OEM_FABRIC_PARAMETER_DEFGW         		0x03
#define IPMI_CMD_OEM_FABRIC_PARAMETER_IPSRC         		0x04
#define IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR       		0x05
#define IPMI_CMD_OEM_FABRIC_PARAMETER_IPINFO        		0x06
#define IPMI_CMD_OEM_FABRIC_PARAMETER_MTU           		0x07
#define IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_MODE   		0x08
#define IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDRS      		0x09
#define IPMI_CMD_OEM_FABRIC_PARAMETER_NODEID      			0x0A
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED    			0x0B
#define IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK    			0x0C
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LINKMAP    			0x0D
#define IPMI_CMD_OEM_FABRIC_PARAMETER_DEPTH_CHART  			0x0E
#define IPMI_CMD_OEM_FABRIC_PARAMETER_ROUTING_TABLE			0x0F
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_STATS			0x10
#define IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_STATS				0x11
#define IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_STATS			0x12
#define IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_CHANNEL_STATS		0x13
#define IPMI_CMD_OEM_FABRIC_PARAMETER_GLOBAL_WATCH			0x14
#define IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_WATCH				0x15
#define IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_CHANNEL_WATCH		0x16
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_WATCH			0x17
#define IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_WATCH			0x18
#define IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_SERVER			0x19
#define IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_PORT				0x1A
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_RESILIENCE		0x1B
#define IPMI_CMD_OEM_FABRIC_PARAMETER_NODENUM_OFFSET		0x1C
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED_POLICY		0x1D
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS			0x1E
#define IPMI_CMD_OEM_FABRIC_PARAMETER_CONFIGURATIONID		0x1F
#define IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITIONID			0x20
#define IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_NODES		0x21
#define IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_RANGE		0x22
#define IPMI_CMD_OEM_FABRIC_PARAMETER_PROFILEID				0x23
#define IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_BASE			0x24
#define IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_NUM			0x25
#define IPMI_CMD_OEM_FABRIC_PARAMETER_CUSTOMER_MACADDR		0x26
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS_FACTOR		0x27
#define IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_INFO			0x28
#define IPMI_CMD_OEM_FABRIC_PARAMETER_START					0x29
#define IPMI_CMD_OEM_FABRIC_PARAMETER_STOP					0x2a
#define IPMI_CMD_OEM_FABRIC_PARAMETER_STATUS				0x2b
#define IPMI_CMD_OEM_FABRIC_PARAMETER_DUMP					0x2c
#define IPMI_CMD_OEM_FABRIC_PARAMETER_LACP_STATUS			0x2d
#define IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_SPEED			0x2e

#define IPMI_CMD_OEM_FABRIC_SPECIFIER_NODE          0x40
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE     0x41
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP          0x42
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_PORT          0x43
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME      0x44
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK			0x45
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_OVERRIDE    	0x46
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC 	   		0x47
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_HOST 	   		0x48
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_FREQUENCY  	0x49
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_ACTUAL  		0x50
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_AVERAGING_FREQUENCY  	0x51
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION 0x52
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION 	0x53
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_PROFILE 		0x54
#define IPMI_CMD_OEM_FABRIC_SPECIFIER_SIZE	 		0x55

/*
 * CX-defined constants
 */
#define CXOEM_FW_DOWNLOAD       1
#define CXOEM_FW_STOP           2
#define CXOEM_FW_UPLOAD         3
#define CXOEM_FW_REGISTER_READ  4
#define CXOEM_FW_REGISTER_WRITE 5


static const int CXOEM_SUCCESS = 0;
static const int CXOEM_ERROR = -1;


/*
 * OEM FW rq/rs structs
 */

typedef struct img_info_s {
	unsigned char id;
	unsigned char type;
	uint32_t img_addr;
	uint32_t img_size;
	uint32_t in_use;
} __attribute__ ((packed)) img_info_t;

typedef struct simg_header_s {
	unsigned char magic[4];
	uint16_t hdrfmt;
	uint16_t priority;
	uint32_t imgoff;
	uint32_t imglen;
	uint32_t daddr;
	uint32_t flags;
	uint32_t crc32;
	unsigned char version[32];
} __attribute__ ((packed)) simg_header_t;

struct cx_fw_info_rs {
	unsigned char ver;	/* param version */
	unsigned char count;	/* number of bytes */
	img_info_t img_info;
} __attribute__ ((packed));


/*
 * OEM info rs structs
 */

typedef union cx_info_basic_u {
	/* Revision 1 */
	struct {
		uint32_t iana;
		uint8_t parameter_revision;
		uint8_t ecme_major_version;
		uint8_t ecme_minor_version;
		uint8_t ecme_revision;
		uint32_t ecme_build_number;
		uint32_t ecme_timestamp;
		char firmware_version[32];
	} __attribute__ ((packed)) rev1;

	/* Revision 2 -- replaced ECME version with a string */
	struct {
		uint32_t iana;
		uint8_t parameter_revision;
		char ecme_version[32];
		uint32_t ecme_timestamp;
		char firmware_version[32];
	} __attribute__ ((packed)) rev2;
} cx_info_basic_t;


/*
 * Prototypes
 */
int ipmi_cxoem_main(struct ipmi_intf *, int, char **);

#endif /*IPMI_CXOEM_H */
