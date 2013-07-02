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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>

#include <ipmitool/ipmi.h>
#include <ipmitool/ipmi_intf.h>
#include <ipmitool/helper.h>
#include <ipmitool/log.h>
#include <ipmitool/ipmi_sel.h>
#include <ipmitool/ipmi_sdr.h>
#include <ipmitool/ipmi_strings.h>
#include <ipmitool/ipmi_channel.h>
#include <ipmitool/ipmi_cxoem.h>
#include <ipmitool/ipmi_raw.h>

#include <ipmitool/intel_hex.h>


/*
 * cxoem data targets -- i.e. the kinds of data we can read and write
 */
#define CX_DATA_TARGET_MEM 1
#define CX_DATA_TARGET_CDB 2
#define CX_DATA_TARGET_UNKNOWN 0

/*
 * Maximum amount of data that can be read from or written to the configuration
 * data base
 */
#define MAX_RETURNABLE_CDB_LEN 64

/*
 * Kinds of access to cxoem data supported
 */
#define CX_DATA_ACCESS_READ 1
#define CX_DATA_ACCESS_WRITE 2
#define CX_DATA_ACCESS_UNKNOWN 0

/*
 * Supported cxoem data formatting hints
 */
#define CX_DATA_FMT_DEFAULT 0
#define CX_DATA_FMT_INT 1
#define CX_DATA_FMT_UINT 2
#define CX_DATA_FMT_XINT 3
#define CX_DATA_FMT_ASCII 4
#define CX_DATA_FMT_XSTR 5
#define CX_DATA_INT_TYPE 1
#define CX_DATA_BYTE_TYPE 2

/*
 * cxoem internal return codes
 */
#define CX_DATA_BAD_VALUE -1
#define CX_DATA_BAD_LENGTH -2
#define CX_DATA_OK 0

const struct valstr cx_ptypes[] = {
	{0x00, "DEL"},
	{0x01, "DEL1"},
	{0x02, "S2_ELF"},
	{0x03, "SOC_ELF"},
	{0x04, "A9_UEFI"},
	{0x05, "A9_UBOOT"},
	{0x06, "A9_EXEC"},
	{0x07, "A9_ELF"},
	{0x08, "SOCDATA"},
	{0x09, "DTB"},
	{0x0a, "CDB"},
	{0x0b, "UBOOTENV"},
	{0x0c, "SEL"},
	{0x0d, "BOOT_LOG"},
	{0x0e, "UEFI_ENV"},
	{0x0f, "DIAG_ELF"},
};

const struct valstr cx_tftp_status[] = {
	{0x00, "Invalid"},
	{0x01, "In progress"},
	{0x02, "Failed"},
	{0x03, "Complete"},
	{0x04, "Canceled"},
};

const struct valstr cx_fw_check_errors[] = {
	{0xFD, "CRC32 does not match"},
	{0xFC, "Missing SIMG magic string"},
	{0xF9, "Failed to read image"},
	{0xF6, "Image is invalid or not active"},
};

const char *tps_table[] = {
	"(Init)",
	"(Cold)",
	"(Warm)",
	"(Hot)",
	"(Critical)",
	"(Shutdown)",
};

static void ipmi_cxoem_usage(void)
{
	lprintf(LOG_NOTICE,
		"Usage: ipmitool cxoem <command> [option...]\n"
		"\n"
		"Commands: \n"
		"\n"
		"  fw fabric mac log data info feature pmic\n");
}

static void cx_fw_usage(void)
{
	lprintf(LOG_NOTICE,
		"\n"
		"Usage: ipmitool cxoem fw <command> [option...]\n"
		"\n"
		"Firmware Commands: \n"
		"\n"
		"  download       <filename> <partition> <type> tftp <ip[:port]>\n"
		"  upload         <partition> <filename> <type> tftp <ip[:port]>\n"
		"  register read  <partition> <filename> <type>\n"
		"  register write <partition> <filename> <type>\n"
		"  activate       <partition>\n"
		"  invalidate     <partition>\n"
		"  makenext       <partition>\n"
		"  flags          <partition> <flags> \n"
		"  status         <job id>      - returns status of the transfer by <job id>\n"
		"  check          <partition>   - force a crc check\n"
		"  cancel         <job id>\n"
		"  info\n"
		"  get            <filename> <offset> <size> tftp <ip[:port]>\n"
		"  put            <filename> <offset> <size> tftp <ip[:port]>\n"
		"  reset          Reset firmware to factory default\n"
		"  version        <version_str> - set the firmware version\n"
		"  fru_reset      Reset FRU to factory default\n"
		"\n");
}

static void cx_fabric_usage(void)
{
	lprintf(LOG_NOTICE,
		"\n"
		"Usage: ipmitool cxoem fabric <command> [option...]\n"
		"\n"
		"Fabric Commands: \n"
		"\n"
		"  set|get  <parameter> <value> [node <node_id>]\n"
		"     where parameter = node_id, ipaddr, netmask, defgw, ipsrc, macaddr, ntp_server, ntp_port, link_resilience\n"
		"  get uplink_speed\n"
		"  factory_default node <node_id>\n"
		"  update_config node <node_id>\n"
		"\n"
		"Ex: ipmitool cxoem fabric get ipaddr node 1\n"
		"\n"
		"\n"
		"Fabric Config commands affect all nodes in the fabric\n"
		"Usage: ipmitool cxoem fabric config <command> [option...]\n"
		"\n"
		"Fabric Config Commands: \n"
		"\n"
		"  set|get ipinfo tftp <tftp_server_addr> port <tftp_server_port> file <filename>\n"
		"  set|get ipsrc\n"
		"  set|get ntp_server <ntp_server_ipaddr>\n"
		"  set|get ntp_port <ntp_port>\n"
		"  set|get nodenum_offset <offset>\n"
		"  set|get macaddrs tftp <tftp_server_addr> port <tftp_server_port> file <filename>\n"
		"  set|get mtu <standard|jumbo>\n"
		"  set|get uplink <uplink_id> node <node_id> interface <interface_id>\n"
		"    where mode is:\n"
		"      0 - all interfaces go to Uplink0\n"
		"      1 - managment interfaces go to Uplink0, server interfaces go to Uplink1\n"
		"      2 - managment and eth0 interfaces go to Uplink0, eth1 interfaces go to Uplink1\n"
		"  set|get link_resilience <setting>\n"
		"    where setting is:\n"
		"      0 - Resilient: All redundant links are left enabled\n"
		"      1 - Link Minimal: All redundant links are disabled\n"
		"  factory_default\n"
		"  update_config\n"
		"\n"
		"Ex: ipmitool cxoem fabric config get ipinfo tftp 10.1.1.1 port 69 file ipinfo.out\n"
		"\n");
}

static void cx_feature_usage(void)
{
	lprintf(LOG_NOTICE,
		"\n"
		"Usage: ipmitool cxoem feature <status|enable|disable> <feature> \n"
		"\n"
		"Feature to Enable/Disable/Query are:\n"
		"  selaging : SEL Aging or Circular SEL buffer\n"
		"  hwwd     : Hardware Watchdog\n"
		"  tps      : Thermal Protection System (Status Only)\n"
		"  mansen   : Override for manual sensors monitoring\n"
		"\n"
		"Ex: ipmitool cxoem feature status selaging\n"
		"Ex: ipmitool cxoem feature enable hwwd\n" "\n");
}


int cx_fw_download(struct ipmi_intf *intf, char *filename, int partition,
		   int type, int ip1, int ip2, int ip3, int ip4, int port)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_DOWNLOAD;
	msg_data[0] = type;
	msg_data[1] = partition;
	msg_data[2] = CXOEM_FW_DOWNLOAD;
	msg_data[3] = 0;
	msg_data[4] = 0;
	msg_data[5] = 6;	// ipv4 addresses by default (for now)
	msg_data[6] = ip1;
	msg_data[7] = ip2;
	msg_data[8] = ip3;
	msg_data[9] = ip4;
	msg_data[10] = (port & 0xff);
	msg_data[11] = (port >> 8) & 0xff;
	msg_data[12] = strlen(filename) + 1;
	memcpy(&msg_data[13], filename, msg_data[12]);
	req.msg.data = msg_data;
	req.msg.data_len = msg_data[12] + 13;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error starting fw download");
		return -1;
	}

	if (rsp->ccode == 0) {
		uint16_t handle;
		handle = (unsigned int)rsp->data[0];
		handle |= (unsigned int)(rsp->data[1] << 8);
		printf("TFTP Handle ID:  %d\n", handle);
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}

int cx_fw_upload(struct ipmi_intf *intf, char *filename, int partition,
		 int type, int ip1, int ip2, int ip3, int ip4, int port)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_DOWNLOAD;
	msg_data[0] = type;
	msg_data[1] = partition;
	msg_data[2] = CXOEM_FW_UPLOAD;
	msg_data[3] = 0;
	msg_data[4] = 0;
	msg_data[5] = 6;	// ipv4 addresses by default (for now)
	msg_data[6] = ip1;
	msg_data[7] = ip2;
	msg_data[8] = ip3;
	msg_data[9] = ip4;
	msg_data[10] = (port & 0xff);
	msg_data[11] = (port >> 8) & 0xff;
	msg_data[12] = fmin(strlen(filename) + 1, 51);
	memcpy(&msg_data[13], filename, msg_data[12] - 1);
	req.msg.data = msg_data;
	req.msg.data_len = msg_data[12] + 13;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error starting fw upload");
		return -1;
	}
	if (rsp->ccode == 0) {
		uint16_t handle;
		handle = (unsigned int)rsp->data[0];
		handle |= (unsigned int)(rsp->data[1] << 8);
		printf("TFTP Handle ID:  %d\n", handle);
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}

int cx_fw_register_read(struct ipmi_intf *intf, char *filename, int partition,
			int type)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_DOWNLOAD;
	msg_data[0] = type;
	msg_data[1] = partition;
	msg_data[2] = CXOEM_FW_REGISTER_READ;
	msg_data[12] = fmin(strlen(filename) + 1, 51);
	memcpy(&msg_data[13], filename, msg_data[12] - 1);
	req.msg.data = msg_data;
	req.msg.data_len = msg_data[12] + 13;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error registering firmware read");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}
	if (rsp->data_len != 0) {
		lprintf(LOG_ERR, "Error: Invalid response size");
		return -1;
	}

	return CXOEM_SUCCESS;
}

int cx_fw_register_write(struct ipmi_intf *intf, char *filename, int partition,
			 int type)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_DOWNLOAD;
	msg_data[0] = type;
	msg_data[1] = partition;
	msg_data[2] = CXOEM_FW_REGISTER_WRITE;
	msg_data[12] = fmin(strlen(filename) + 1, 51);
	memcpy(&msg_data[13], filename, msg_data[12] - 1);
	req.msg.data = msg_data;
	req.msg.data_len = msg_data[12] + 13;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error registering firmware write");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}
	if (rsp->data_len != 0) {
		lprintf(LOG_ERR, "Error: Invalid response size");
		return -1;
	}

	return CXOEM_SUCCESS;
}

int cx_fw_raw(struct ipmi_intf *intf, char *filename, unsigned int address,
	      unsigned int size, int dir,
	      int ip1, int ip2, int ip3, int ip4, int port)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_RAW;
	msg_data[0] = dir;
	msg_data[1] = address & 0xff;
	msg_data[2] = (address >> 8) & 0xff;
	msg_data[3] = (address >> 16) & 0xff;
	msg_data[4] = (address >> 24) & 0xff;
	msg_data[5] = size & 0xff;
	msg_data[6] = (size >> 8) & 0xff;
	msg_data[7] = (size >> 16) & 0xff;
	msg_data[8] = (size >> 24) & 0xff;
	msg_data[9] = ip1;
	msg_data[10] = ip2;
	msg_data[11] = ip3;
	msg_data[12] = ip4;
	msg_data[13] = (port & 0xff);
	msg_data[14] = (port >> 8) & 0xff;
	msg_data[15] = strlen(filename) + 1;
	memcpy(&msg_data[16], filename, msg_data[15]);
	req.msg.data = msg_data;
	req.msg.data_len = msg_data[15] + 16;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error starting raw transfer");
		return -1;
	}

	if (rsp->ccode == 0) {
		uint16_t handle;
		handle = (unsigned int)rsp->data[0];
		handle |= (unsigned int)(rsp->data[1] << 8);

		printf("TFTP Handle ID:  %d\n", handle);
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}

int cx_fw_status(struct ipmi_intf *intf, uint16_t handle)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[16];
	int status = -1;

	memset(&req, 0, sizeof(req));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_GET_STATUS;
	msg_data[0] = 0;
	msg_data[1] = 1;	// param 1 = download status

	msg_data[2] = handle & 0x00ff;
	msg_data[3] = (handle >> 8) & 0x00ff;
	req.msg.data = msg_data;
	req.msg.data_len = 4;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error checking fw status");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	status = rsp->data[1];

	printf("Status : %s\n", val2str(status, cx_tftp_status));

	return rc;
}

int cx_fw_check(struct ipmi_intf *intf, int partition)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_GET_STATUS;
	msg_data[0] = 0;
	msg_data[1] = 4;	// param 4 = check image
	msg_data[2] = partition;
	req.msg.data = msg_data;
	req.msg.data_len = 3;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error during firmware check");
		return -1;
	}

	if (rsp->ccode == 0) {
		if (rsp->data[1] == 0) {
			unsigned int crc32;
			crc32 = (unsigned int)rsp->data[5];
			crc32 |= (unsigned int)(rsp->data[4] << 8);
			crc32 |= (unsigned int)(rsp->data[3] << 16);
			crc32 |= (unsigned int)(rsp->data[2] << 24);
			printf("CRC32             : %08x\n", crc32);
		} else {
			lprintf(LOG_ERR, "Error: %s",
				val2str(rsp->data[1], cx_fw_check_errors));
			return -1;
		}
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}

int cx_fw_info(struct ipmi_intf *intf, int partition)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];
	int i;
	struct cx_fw_info_rs *s;
	int count;
	img_info_t ii[20];
	simg_header_t header;

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_GET_STATUS;
	msg_data[0] = 0;
	msg_data[1] = 2;	// param 2 = info
	msg_data[2] = partition;
	req.msg.data = msg_data;
	req.msg.data_len = 2;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error getting firmware info");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	if (rsp->data_len < sizeof(struct cx_fw_info_rs))
		return -1;

	s = (struct cx_fw_info_rs *)&rsp->data[0];
	count = s->count / sizeof(img_info_t);
	memcpy(ii, &s->img_info, count * sizeof(img_info_t));

	printf("\n");
	for (i = 0; i < count; i++) {
		if (cx_fw_get_simg_header(intf, i, &header)) {
			return -1;
		}

		printf("%-18s : %02d\n", "Partition", ii[i].id);
		printf("%-18s : %02x (%s)\n", "Type", ii[i].type,
		       val2str(ii[i].type, cx_ptypes));
		printf("%-18s : %08x\n", "Offset", ii[i].img_addr);
		printf("%-18s : %08x\n", "Size", ii[i].img_size);
		printf("%-18s : %08x\n", "Priority", header.priority);
		printf("%-18s : %08x\n", "Daddr", header.daddr);
		printf("%-18s : %08x\n", "Flags", header.flags);
		if (header.hdrfmt >= 2)
			printf("%-18s : %s\n", "Version", header.version);
		else
			printf("%-18s : Unknown\n", "Version");
		if (ii[i].in_use <= 1)
			printf("%-18s : %u\n\n", "In Use", ii[i].in_use);
		else
			printf("%-18s : Unknown\n\n", "In Use");
	}

	return rc;
}


int
cx_fw_get_simg_header(struct ipmi_intf *intf, int partition,
		      simg_header_t * header)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_GET_STATUS;
	msg_data[0] = 0;
	msg_data[1] = 3;	// param 3 = get SIMG header
	msg_data[2] = partition;
	req.msg.data = msg_data;
	req.msg.data_len = 3;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error reading SIMG info");
		return -1;
	}

	if (rsp->ccode == 0) {
		memcpy(header, &rsp->data[1], sizeof(*header));
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}


int cx_fw_flags(struct ipmi_intf *intf, int partition, uint32_t flags)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[16];
	int i;

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_SET_STATUS;
	msg_data[0] = 0;	// resvd
	msg_data[1] = 1;	// param = 1 = "set flags"
	msg_data[2] = partition;
	msg_data[3] = (uint8_t) ((flags >> 24) & 0xff);
	msg_data[4] = (uint8_t) ((flags >> 16) & 0xff);
	msg_data[5] = (uint8_t) ((flags >> 8) & 0xff);
	msg_data[6] = (uint8_t) (flags & 0xff);
	req.msg.data = msg_data;
	req.msg.data_len = 7;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error setting firmware flags");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return 0;
}


int cx_fw_get_flags(struct ipmi_intf *intf, int partition, unsigned int *flags)
{
	int rc = CXOEM_SUCCESS;
	simg_header_t header;

	if (cx_fw_get_simg_header(intf, partition, &header)) {
		return -1;
	}

	*flags = header.flags;

	return rc;
}


int cx_fw_makenext(struct ipmi_intf *intf, int partition)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[4];
	int i;

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_SET_STATUS;
	msg_data[0] = 0;	// resvd
	msg_data[1] = 3;	// param = 3 = "make next"
	msg_data[2] = partition;
	req.msg.data = msg_data;
	req.msg.data_len = 3;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error setting firmware image to 'next'");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return 0;
}

int cx_fw_activate(struct ipmi_intf *intf, int partition)
{
	unsigned int flags;

	if (cx_fw_get_flags(intf, partition, &flags)) {
		return -1;
	}
	//printf("activate: read flags <%08x>\n", flags);
	flags &= (~0x02);	// bit 1 = SIMG_FLAG_ACTIVE
	printf("activate: write flags <%08x>\n", flags);

	cx_fw_flags(intf, partition, flags);

	return 0;
}


int cx_fw_invalidate(struct ipmi_intf *intf, int partition)
{
	unsigned int flags;

	if (cx_fw_get_flags(intf, partition, &flags)) {
		return -1;
	}
	//printf("invalidate: read flags <%08x>\n", flags);
	flags &= (~0x04);	// bit 2 = SIMG_FLAG_INVALID
	printf("invalidate: write flags <%08x>\n", flags);

	cx_fw_flags(intf, partition, flags);

	return 0;
}


int cx_fw_reset(struct ipmi_intf *intf)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;

	memset(&req, 0, sizeof(req));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_RESET;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR,
			"Error resetting firmware to factory default");
		return -1;
	}

	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return 0;
}


int cx_fw_version(struct ipmi_intf *intf, char *version)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[64];
	int i;

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FW_SET_STATUS;
	msg_data[0] = 0;	// resvd
	msg_data[1] = 4;	// param = 4 = "set version"
	strncpy(&msg_data[2], version, 32);
	req.msg.data = msg_data;
	req.msg.data_len = 34;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error setting firmware version");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return 0;
}


int cx_fw_fru_reset(struct ipmi_intf *intf)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;

	memset(&req, 0, sizeof(req));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_FRU_RESET;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR,
			"Error resetting FRU to factory default");
		return -1;
	}

	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Error: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return 0;
}


int cx_fw_main(struct ipmi_intf *intf, int argc, char **argv)
{
	char filename[65];
	int rv = 0;
	int partition, type;
	int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;
	int port = 0;

	errno = 0;

	if (argc < 1 || strncmp(argv[0], "help", 4) == 0) {
		cx_fw_usage();
		return 0;
	}

	if (strncmp(argv[0], "download", 8) == 0) {
		if ((argc > 3) && (argc < 7) && (strlen(argv[1]) > 0)) {
			/* There is a file name in the parameters */
			if (strlen(argv[1]) < 32) {
				strcpy((char *)filename, argv[1]);
				printf("File Name         : %s\n", filename);
			} else {
				lprintf(LOG_ERR,
					"File name must be smaller than 32 bytes\n");
			}

			partition = strtol(argv[2], (char **)NULL, 10);
			if (!errno) {
				printf("Partition         : %d\n", partition);
			} else {
				lprintf(LOG_ERR,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}

			if (isdigit(argv[3][0])) {
				type = strtol(argv[3], (char **)NULL, 10);
			} else {
				type = str2val(argv[3], cx_ptypes);
				if (type < 1 || type > 14)
					errno = -1;
			}
			if (!errno) {
				printf("Type              : %d\n", type);
			} else {
				lprintf(LOG_ERR,
					"<type> doesn't look like a valid value\n");
				return -1;
			}

			if (argc > 5 && strncmp(argv[4], "tftp", 4) == 0) {
				if (strchr(argv[5], ':')) {
					if (sscanf(argv[5], "%d.%d.%d.%d:%d",
						   &ip1, &ip2, &ip3, &ip4,
						   &port) != 5) {
						lprintf(LOG_ERR,
							"Invalid IP address: %s",
							argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d:%d\n", ip1,
					       ip2, ip3, ip4, port);
				} else {
					if (sscanf(argv[5], "%d.%d.%d.%d",
						   &ip1, &ip2, &ip3,
						   &ip4) != 4) {
						lprintf(LOG_ERR,
							"Invalid IP address: %s",
							argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d\n", ip1, ip2,
					       ip3, ip4);
				}
			} else {
				cx_fw_usage();
				return -1;
			}
			rv = cx_fw_download(intf, filename, partition, type,
					    ip1, ip2, ip3, ip4, port);
		} else {
			cx_fw_usage();
			return -1;
		}
	} else if (strncmp(argv[0], "upload", 8) == 0) {
		if ((argc > 3) && (argc < 7) && (strlen(argv[1]) > 0)) {
			/* There is a file name in the parameters */
			if (strlen(argv[2]) < 32) {
				strcpy((char *)filename, argv[2]);
				printf("File Name         : %s\n", filename);
			} else {
				lprintf(LOG_ERR,
					"File name must be smaller than 32 bytes\n");
			}

			partition = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Partition         : %d\n", partition);
			} else {
				lprintf(LOG_ERR,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}

			if (isdigit(argv[3][0])) {
				type = strtol(argv[3], (char **)NULL, 10);
			} else {
				type = str2val(argv[3], cx_ptypes);
				if (type < 1 || type > 14)
					errno = -1;
			}
			if (!errno) {
				printf("Type              : %d\n", type);
			} else {
				lprintf(LOG_ERR,
					"<type> doesn't look like a valid value\n");
				return -1;
			}

			if (argc > 5 && strncmp(argv[4], "tftp", 4) == 0) {
				if (strchr(argv[5], ':')) {
					if (sscanf(argv[5], "%d.%d.%d.%d:%d",
						   &ip1, &ip2, &ip3, &ip4,
						   &port) != 5) {
						lprintf(LOG_ERR,
							"Invalid IP address: %s",
							argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d:%d\n", ip1,
					       ip2, ip3, ip4, port);
				} else {
					if (sscanf(argv[5], "%d.%d.%d.%d",
						   &ip1, &ip2, &ip3,
						   &ip4) != 4) {
						lprintf(LOG_ERR,
							"Invalid IP address: %s",
							argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d\n", ip1, ip2,
					       ip3, ip4);
				}
			} else {
				cx_fw_usage();
				return -1;
			}
			rv = cx_fw_upload(intf, filename, partition, type,
					  ip1, ip2, ip3, ip4, port);
		} else {
			cx_fw_usage();
			return -1;
		}
	} else if (strncmp(argv[0], "register", 8) == 0) {
		if (argc == 5) {
			partition = strtol(argv[2], (char **)NULL, 10);
			if (!errno) {
				printf("Partition : %d\n", partition);
			} else {
				lprintf(LOG_ERR,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}

			if (strlen(argv[3]) < 32) {
				strcpy((char *)filename, argv[3]);
				printf("File Name : %s\n", filename);
			} else {
				lprintf(LOG_ERR,
					"File name must be smaller than 32 bytes\n");
			}

			if (isdigit(argv[4][0])) {
				type = strtol(argv[4], (char **)NULL, 10);
			} else {
				type = str2val(argv[4], cx_ptypes);
				if (type < 1 || type > 14)
					errno = -1;
			}
			if (!errno) {
				printf("Type      : %d\n", type);
			} else {
				lprintf(LOG_ERR,
					"<type> doesn't look like a valid value\n");
				return -1;
			}

			if (strncmp(argv[1], "read", 4) == 0) {
				rv = cx_fw_register_read(intf, filename,
							 partition, type);
			} else if(strncmp(argv[1], "write", 5) == 0) {
				rv = cx_fw_register_write(intf, filename,
							  partition, type);
			} else {
				cx_fw_usage();
				return -1;
			}
		} else {
			cx_fw_usage();
			return -1;
		}
	} else if (strncmp(argv[0], "put", 3) == 0) {
		unsigned int addr = 0;
		unsigned int size = 0;
		int dir = 0;	// 0 = download, 1 = upload
		if ((argc > 3) && (argc < 7) && (strlen(argv[1]) > 0)) {
			/* There is a file name in the parameters */
			if (strlen(argv[1]) < 32) {
				strcpy((char *)filename, argv[1]);
				printf("File Name         : %s\n", filename);
			} else {
				lprintf(LOG_ERR,
					"File name must be smaller than 32 bytes\n");
			}

			addr = strtoul(argv[2], (char **)NULL, 0);
			if (!errno) {
				printf("Address   : %08x\n", addr);
			} else {
				lprintf(LOG_ERR,
					"<address> doesn't look like a valid value\n");
				return -1;
			}

			size = strtoul(argv[3], (char **)NULL, 0);
			if (!errno) {
				printf("Size      : %08x\n", size);
			} else {
				lprintf(LOG_ERR,
					"<size> doesn't look like a valid value\n");
				return -1;
			}

			if (argc > 5 && strncmp(argv[4], "tftp", 4) == 0) {
				if (strchr(argv[5], ':')) {
					if (sscanf(argv[5], "%d.%d.%d.%d:%d",
						   &ip1, &ip2, &ip3, &ip4,
						   &port) != 5) {
						lprintf(LOG_ERR,
							"Invalid IP address: %s",
							argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d:%d\n", ip1,
					       ip2, ip3, ip4, port);
				} else {
					if (sscanf(argv[5], "%d.%d.%d.%d",
						   &ip1, &ip2, &ip3,
						   &ip4) != 4) {
						lprintf(LOG_ERR,
							"Invalid IP address: %s",
							argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d\n", ip1, ip2,
					       ip3, ip4);
				}
			} else {
				cx_fw_usage();
				return -1;
			}
			rv = cx_fw_raw(intf, filename, addr, size, dir,
				       ip1, ip2, ip3, ip4, port);
		} else {
			cx_fw_usage();
			return -1;
		}
	} else if (strncmp(argv[0], "get", 3) == 0) {
		unsigned int addr = 0;
		unsigned int size = 0;
		int dir = 1;	// 0 = download, 1 = upload
		if ((argc > 3) && (argc < 7) && (strlen(argv[1]) > 0)) {
			/* There is a file name in the parameters */
			if (strlen(argv[1]) < 32) {
				strcpy((char *)filename, argv[1]);
				printf("File Name         : %s\n", filename);
			} else {
				lprintf(LOG_ERR,
					"File name must be smaller than 32 bytes\n");
			}

			addr = strtoul(argv[2], (char **)NULL, 0);
			if (!errno) {
				printf("Address   : %08x\n", addr);
			} else {
				lprintf(LOG_ERR,
					"<address> doesn't look like a valid value\n");
				return -1;
			}

			size = strtoul(argv[3], (char **)NULL, 0);
			if (!errno) {
				printf("Size      : %08x\n", size);
			} else {
				lprintf(LOG_ERR,
					"<size> doesn't look like a valid value\n");
				return -1;
			}

			if (argc > 5 && strncmp(argv[4], "tftp", 4) == 0) {
				if (strchr(argv[5], ':')) {
					if (sscanf(argv[5], "%d.%d.%d.%d:%d",
						   &ip1, &ip2, &ip3, &ip4,
						   &port) != 5) {
						lprintf(LOG_ERR,
							"Invalid IP address: %s",
							argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d:%d\n", ip1,
					       ip2, ip3, ip4, port);
				} else {
					if (sscanf(argv[5], "%d.%d.%d.%d",
						   &ip1, &ip2, &ip3,
						   &ip4) != 4) {
						lprintf(LOG_ERR,
							"Invalid IP address: %s",
							argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d\n", ip1, ip2,
					       ip3, ip4);
				}
			} else {
				cx_fw_usage();
				return -1;
			}
			rv = cx_fw_raw(intf, filename, addr, size, dir,
				       ip1, ip2, ip3, ip4, port);
		} else {
			cx_fw_usage();
			return -1;
		}
	} else if (strncmp(argv[0], "status", 6) == 0) {
		uint16_t handle = 0;

		if (argc == 2) {
			handle = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Handle : %d\n", handle);
			} else {
				lprintf(LOG_ERR,
					"<handle> doesn't look like a valid value\n");
				return -1;
			}
		}
		rv = cx_fw_status(intf, handle);
	} else if (strncmp(argv[0], "info", 4) == 0) {
		int partition = -1;

		if (argc > 3) {
			partition = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Partition         : %d\n", partition);
			} else {
				lprintf(LOG_ERR,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}
		}
		rv = cx_fw_info(intf, partition);
	} else if (strncmp(argv[0], "makenext", 8) == 0) {
		if (argc == 2) {
			partition = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Partition         : %d\n", partition);
			} else {
				fprintf(stderr,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}
		} else {
			cx_fw_usage();
			return -1;
		}
		rv = cx_fw_makenext(intf, partition);
	} else if (strncmp(argv[0], "activate", 8) == 0) {
		int partition = -1;

		if (argc == 2) {
			partition = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Partition         : %d\n", partition);
			} else {
				lprintf(LOG_ERR,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}
		} else {
			cx_fw_usage();
			return -1;
		}
		rv = cx_fw_activate(intf, partition);
	} else if (strncmp(argv[0], "invalidate", 10) == 0) {
		int partition = -1;

		if (argc == 2) {
			partition = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Partition         : %d\n", partition);
			} else {
				lprintf(LOG_ERR,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}
		} else {
			cx_fw_usage();
			return -1;
		}
		rv = cx_fw_invalidate(intf, partition);
	} else if (strncmp(argv[0], "flags", 5) == 0) {
		int partition = -1;
		uint32_t flags = 0xffffffff;

		if (argc == 3) {
			partition = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Partition         : %d\n", partition);
			} else {
				lprintf(LOG_ERR,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}
			flags = strtoul(argv[2], (char **)NULL, 16);
			if (!errno) {
				printf("Flags             : %08x\n", flags);
			} else {
				lprintf(LOG_ERR,
					"<flags> doesn't look like a valid value\n");
				return -1;
			}
		} else {
			cx_fw_usage();
			return -1;
		}
		rv = cx_fw_flags(intf, partition, flags);
	} else if (strncmp(argv[0], "check", 5) == 0) {
		int partition = -1;

		if (argc == 2) {
			partition = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Partition         : %d\n", partition);
			} else {
				lprintf(LOG_ERR,
					"<partition> doesn't look like a valid value\n");
				return -1;
			}
		} else {
			cx_fw_usage();
			return -1;
		}
		rv = cx_fw_check(intf, partition);
	} else if (strncmp(argv[0], "reset", 5) == 0) {
		rv = cx_fw_reset(intf);
	} else if (strncmp(argv[0], "version", 7) == 0) {
		rv = cx_fw_version(intf, argv[1]);
	} else if (strncmp(argv[0], "fru_reset", 9) == 0) {
		rv = cx_fw_fru_reset(intf);
	} else {
		cx_fw_usage();
		return -1;
	}


	return rv;
}

typedef enum {
	Cx_Fabric_Arg_Invalid,
	Cx_Fabric_Arg_Command,
	Cx_Fabric_Arg_Parameter,
	Cx_Fabric_Arg_Specifier,
	Cx_Fabric_Arg_Value_Scalar,
	Cx_Fabric_Arg_Value_String,
	Cx_Fabric_Arg_Value_IPV4_Address,
	Cx_Fabric_Arg_Value_MAC_Address,
	Cx_Fabric_Arg_Value_Bitmap,
} cx_fabric_arg_type_t;

typedef struct {
	char *keyword;
	cx_fabric_arg_type_t arg_type;
	void *data;
} cx_fabric_arg_t;

#define MAX_PERMITTED_PARAMS 24
#define MAX_PERMITTED_SPECIFIERS 24
#define MAX_REQUIRED_SPECIFIERS 24

#define IPMI_CMD_OEM_PARAMETER_UNDEF 0
#define IPMI_CMD_OEM_SPECIFIER_UNDEF 0

typedef struct {
	char *keyword;
	uint8_t ipmi_cmd;
	uint8_t parameter_required;
	uint8_t parameter_value_expected;
	uint8_t permitted_params[MAX_PERMITTED_PARAMS];
	uint8_t permitted_specifiers[MAX_PERMITTED_SPECIFIERS];
	uint8_t required_specifiers[MAX_REQUIRED_SPECIFIERS];
} cx_fabric_cmd_t;

cx_fabric_cmd_t update_cmd = {
	"update_config",
	IPMI_CMD_OEM_FABRIC_UPDATE_CONFIG,
	0, 0,
	{0, 0, 0, 0, 0},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_NODE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION, 0, 0, 0},
	{0, 0, 0, 0, 0}
};

cx_fabric_cmd_t factory_default_node_cmd = {
	"factory_default",
	IPMI_CMD_OEM_FABRIC_FACTORY_DEFAULT,
	0, 0,
	{0, 0, 0, 0, 0},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION, 0, 0, 0},
	{0, 0, 0, 0, 0}
};

cx_fabric_cmd_t get_cmd = {
	"get",
	IPMI_CMD_OEM_FABRIC_GET,
	1, 0,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NETMASK,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_DEFGW,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPSRC,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NODEID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_RESILIENCE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_SERVER,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_PORT,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_CONFIGURATIONID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PROFILEID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_NODES,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_RANGE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_BASE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_NUM,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED_POLICY,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_CUSTOMER_MACADDR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS_FACTOR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_SPEED,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_INFO},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_NODE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_OVERRIDE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_ACTUAL,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PROFILE},
	{0, 0, 0, 0, 0}
};

cx_fabric_cmd_t set_cmd = {
	"set",
	IPMI_CMD_OEM_FABRIC_SET,
	1, 1,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NETMASK,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_DEFGW,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPSRC,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_RESILIENCE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_SERVER,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_PORT,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_CUSTOMER_MACADDR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_CONFIGURATIONID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITIONID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PROFILEID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_BASE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_NUM,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED_POLICY,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS_FACTOR},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_NODE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_OVERRIDE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PROFILE},
	{0, 0, 0, 0, 0}
};

cx_fabric_cmd_t add_cmd = {
	"add",
	IPMI_CMD_OEM_FABRIC_ADD,
	1, 1,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_CONFIGURATIONID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_NODES,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_RANGE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITIONID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PROFILEID},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_NODE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION, 0, 0},
	{0, 0, 0, 0, 0}
};

cx_fabric_cmd_t rm_cmd = {
	"rm",
	IPMI_CMD_OEM_FABRIC_RM,
	1, 1,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_CONFIGURATIONID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_RANGE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITIONID,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PROFILEID},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_NODE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION, 0},
	{0, 0, 0, 0, 0}
};

cx_fabric_cmd_t info_cmd = {
	"info",
	IPMI_CMD_OEM_FABRIC_INFO,
	1, 0,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_LINKMAP,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_DEPTH_CHART,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_ROUTING_TABLE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_STATS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_STATS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_CHANNEL_STATS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_STATS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_CONFIG},
	{ IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PORT,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME, 0, 0, 0, 0}
};

cx_fabric_cmd_t set_watch_cmd = {
	"set_watch",
	IPMI_CMD_OEM_FABRIC_SET_WATCH,
	1, 0,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_GLOBAL_WATCH,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_WATCH,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_CHANNEL_WATCH,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_WATCH,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_WATCH, 0},
	{ IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_HOST,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PORT,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_FREQUENCY,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_AVERAGING_FREQUENCY},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_HOST, 0, 0, 0, 0, 0}
};

cx_fabric_cmd_t clear_watch_cmd = {
	"clear_watch",
	IPMI_CMD_OEM_FABRIC_CLEAR_WATCH,
	1, 0,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_GLOBAL_WATCH,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_WATCH,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_CHANNEL_WATCH,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_WATCH,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_WATCH, 0},
	{ IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_HOST,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PORT, 0},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_HOST, 0, 0, 0, 0}
};

cx_fabric_cmd_t trace_cmd = {
	"trace",
	IPMI_CMD_OEM_FABRIC_TRACE,
	1, 0,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_START,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_STOP,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_STATUS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_DUMP, 0},
	{ IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_SIZE, 0},
	{0, 0, 0, 0, 0}
};

#define MAC_ADDRESS_SIZE    6
typedef uint8_t mac_address_t[MAC_ADDRESS_SIZE];

#define IPV4_ADDRESS_SIZE   4
typedef uint8_t ipv4_address_t[IPV4_ADDRESS_SIZE];

// match RSP_DATA_SIZE in oem_fabric.c
#define MAX_VAL_STRING 64
#define MAX_VAL_BITMAP 25
typedef union {
	uint8_t scalar[4];
	mac_address_t mac_addr;
	ipv4_address_t ipv4_addr;
	char string[MAX_VAL_STRING];
	uint8_t bitmap[MAX_VAL_BITMAP];
} cx_fabric_value_u;

typedef struct {
	cx_fabric_arg_type_t val_type;
	cx_fabric_value_u val;
	uint8_t val_len;
} cx_fabric_value_t;

typedef struct {
	char *keyword;
	uint8_t param;
	uint8_t required_specifiers[MAX_REQUIRED_SPECIFIERS];
	cx_fabric_arg_type_t val_type;
	int val_len;
	void (*printer) (void *data, int len);
} cx_fabric_param_t;

typedef struct {
	char *keyword;
	uint8_t spec;
	cx_fabric_arg_type_t val_type;
	int val_len;
	void (*printer) (void *data, int len);
} cx_fabric_spec_t;

void cx_fabric_string_printer(void *data, int len)
{
	int i;
	cx_fabric_value_t *val = (cx_fabric_value_t *) data;
	int value = 0;

	printf("%s\n", val->val.string);
	return;
}

void cx_fabric_bitmap_printer(void *data, int len)
{
	int i, in_range = 0, range_start = 0;
	int first = 1;
	cx_fabric_value_t *val = (cx_fabric_value_t *) data;

	for (i = 0; i < MAX_VAL_BITMAP * 8; i++) {
		if (val->val.bitmap[i/8] & (1 << (i%8))) {
			if (in_range) {
				continue;
			} else {
				if (first) {
					printf("%d", i);
					first = 0;
				} else {
					printf(",%d", i);
				}
				range_start = i;
				in_range = 1;
			}
		} else if (in_range) {
			if (range_start != (i-1)) {
				printf("-%d", i-1);
			}
			in_range = 0;
		}
	}

	if (in_range) {
		if (range_start != (i-1)) {
			printf("-%d", i-1);
		}
	} else if (first) {
		printf("No nodes in partition");
	}

	printf("\n");
	return;
}

void cx_fabric_scalar_printer(void *data, int len)
{
	int i;
	cx_fabric_value_t *val = (cx_fabric_value_t *) data;
	int value = 0;

	for (i = 0; i < len; i++) {
		value |= (val->val.scalar[i] << (8 * i));
	}
	printf("%d\n", value);
	return;
}

void cx_fabric_hex_printer(void *data, int len)
{
	int i;
	cx_fabric_value_t *val = (cx_fabric_value_t *) data;
	int value = 0;

	for (i = 0; i < len; i++) {
		value |= (val->val.scalar[i] << (8 * i));
	}
	printf("0x%0x\n", (unsigned int)value);
	return;
}

void cx_fabric_ipv4_printer(void *data, int len)
{
	cx_fabric_value_t *val = (cx_fabric_value_t *) data;
	printf("%d.%d.%d.%d\n", val->val.ipv4_addr[0],
	       val->val.ipv4_addr[1], val->val.ipv4_addr[2],
	       val->val.ipv4_addr[3]);
	return;
}

void cx_fabric_mac_printer(void *data, int len)
{
	cx_fabric_value_t *val = (cx_fabric_value_t *) data;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       val->val.mac_addr[0], val->val.mac_addr[1], val->val.mac_addr[2],
	       val->val.mac_addr[3], val->val.mac_addr[4],
	       val->val.mac_addr[5]);
	return;
}

cx_fabric_param_t ipaddr_param = {
	"ipaddr",
	IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_param_t ntp_server_param = {
	"ntp_server",
	IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_SERVER,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_param_t ntp_port_param = {
	"ntp_port",
	IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_PORT,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_param_t ipsrc_param = {
	"ipsrc",
	IPMI_CMD_OEM_FABRIC_PARAMETER_IPSRC,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t netmask_param = {
	"netmask",
	IPMI_CMD_OEM_FABRIC_PARAMETER_NETMASK,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_param_t defgw_param = {
	"defgw",
	IPMI_CMD_OEM_FABRIC_PARAMETER_DEFGW,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_param_t nodeid_param = {
	"nodeid",
	IPMI_CMD_OEM_FABRIC_PARAMETER_NODEID,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_param_t linkspeed_param = {
	"linkspeed",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_Scalar, 4,
	cx_fabric_string_printer
};

cx_fabric_param_t link_resilience_param = {
	"link_resilience",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_RESILIENCE,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t linkspeed_policy_param = {
	"ls_policy",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED_POLICY,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t link_users_factor_param = {
	"lu_factor",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS_FACTOR,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t uplink_speed_param = {
	"uplink_speed",
	IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_SPEED,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t uplink_info_param = {
	"uplink_info",
	IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_INFO,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_String, MAX_VAL_STRING,
	cx_fabric_string_printer
};

cx_fabric_param_t uplink_param = {
	"uplink",
	IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE,
	 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t cust_macaddr_param = {
	"customer_macaddr",
	IPMI_CMD_OEM_FABRIC_PARAMETER_CUSTOMER_MACADDR,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_MAC_Address, 6,
	cx_fabric_mac_printer
};

cx_fabric_param_t macaddr_param = {
	"macaddr",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_MAC_Address, 6,
	cx_fabric_mac_printer
};

cx_fabric_param_t linkmap_param = {
	"linkmap",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINKMAP,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t depth_chart_param = {
	"depth_chart",
	IPMI_CMD_OEM_FABRIC_PARAMETER_DEPTH_CHART,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t routing_table_param = {
	"routing_table",
	IPMI_CMD_OEM_FABRIC_PARAMETER_ROUTING_TABLE,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t link_users_param = {
	"link_users",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t partition_config_param = {
	"partition_config",
	IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_CONFIG,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t global_watch_param = {
	"global_watch",
	IPMI_CMD_OEM_FABRIC_PARAMETER_GLOBAL_WATCH,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t link_stats_param = {
	"link_stats",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_STATS,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t link_watch_param = {
	"link_watch_stats",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_WATCH,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t mac_stats_param = {
	"mac_stats",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_STATS,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t mac_watch_param = {
	"mac_watch",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_WATCH,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t mac_channel_stats_param = {
	"mac_channel_stats",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_CHANNEL_STATS,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t mac_channel_watch_param = {
	"mac_channel_watch",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MAC_CHANNEL_WATCH,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t uplink_stats_param = {
	"uplink_stats",
	IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_STATS,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t uplink_watch_param = {
	"uplink_watch",
	IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_WATCH,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t configurationid_param = {
	"configid",
	IPMI_CMD_OEM_FABRIC_PARAMETER_CONFIGURATIONID,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t partitionid_param = {
	"partid",
	IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITIONID,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t profileid_param = {
	"profileid",
	IPMI_CMD_OEM_FABRIC_PARAMETER_PROFILEID,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t partition_nodes_param = {
	"part_nodes",
	IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_NODES,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t partition_range_param = {
	"part_range",
	IPMI_CMD_OEM_FABRIC_PARAMETER_PARTITION_RANGE,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION, 0, 0, 0},
	Cx_Fabric_Arg_Value_Bitmap, MAX_VAL_BITMAP,
	cx_fabric_bitmap_printer
};

cx_fabric_param_t ipaddr_base_param = {
	"ipaddr_base",
	IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_BASE,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_param_t ipaddr_num_param = {
	"ipaddr_num",
	IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_NUM,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_param_t start_param = {
	"start",
	IPMI_CMD_OEM_FABRIC_PARAMETER_START,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t stop_param = {
	"stop",
	IPMI_CMD_OEM_FABRIC_PARAMETER_STOP,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t status_param = {
	"status",
	IPMI_CMD_OEM_FABRIC_PARAMETER_STATUS,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t status_string_param = {
	"status_string",
	IPMI_CMD_OEM_FABRIC_PARAMETER_STATUS_STRING,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_String, MAX_VAL_STRING,
	cx_fabric_string_printer
};

cx_fabric_param_t dump_param = {
	"dump",
	IPMI_CMD_OEM_FABRIC_PARAMETER_DUMP,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t node_spec = {
	"node",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_NODE,
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t interface_spec = {
	"interface",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t link_spec = {
	"link",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_LINK,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t override_spec = {
	"override",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_OVERRIDE,
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_spec_t actual_spec = {
	"actual",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_ACTUAL,
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_spec_t mac_spec = {
	"mac",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_MAC,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t tftp_spec = {
	"tftp",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP,
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_spec_t host_spec = {
	"host",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_HOST,
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_spec_t port_spec = {
	"port",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_PORT,
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t frequency_spec = {
	"frequency",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_FREQUENCY,
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t averaging_frequency_spec = {
	"averaging_frequency",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_AVERAGING_FREQUENCY,
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t file_spec = {
	"file",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME,
	Cx_Fabric_Arg_Value_String, 20,
	cx_fabric_string_printer
};

cx_fabric_spec_t configuration_spec = {
	"config",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIGURATION,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t partition_spec = {
	"part",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_PARTITION,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t profile_spec = {
	"profile",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_PROFILE,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t size_spec = {
	"size",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_SIZE,
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_arg_t cx_fabric_main_arg[] = {
	{"set_watch", Cx_Fabric_Arg_Command, (void *)&set_watch_cmd},
	{"clear_watch", Cx_Fabric_Arg_Command, (void *)&clear_watch_cmd},
	{"get", Cx_Fabric_Arg_Command, (void *)&get_cmd},
	{"set", Cx_Fabric_Arg_Command, (void *)&set_cmd},
	{"add", Cx_Fabric_Arg_Command, (void *)&add_cmd},
	{"rm", Cx_Fabric_Arg_Command, (void *)&rm_cmd},
	{"info", Cx_Fabric_Arg_Command, (void *)&info_cmd},
	{"update_config", Cx_Fabric_Arg_Command, (void *)&update_cmd},
	{"factory_default", Cx_Fabric_Arg_Command, (void *)&factory_default_node_cmd},
	{"trace", Cx_Fabric_Arg_Command, (void *)&trace_cmd},
	{"ipaddr_base", Cx_Fabric_Arg_Parameter, (void *)&ipaddr_base_param},
	{"ipaddr_num", Cx_Fabric_Arg_Parameter, (void *)&ipaddr_num_param},
	{"ipaddr", Cx_Fabric_Arg_Parameter, (void *)&ipaddr_param},
	{"ipsrc", Cx_Fabric_Arg_Parameter, (void *)&ipsrc_param},
	{"netmask", Cx_Fabric_Arg_Parameter, (void *)&netmask_param},
	{"ntp_server", Cx_Fabric_Arg_Parameter, (void *)&ntp_server_param},
	{"ntp_port", Cx_Fabric_Arg_Parameter, (void *)&ntp_port_param},
	{"defgw", Cx_Fabric_Arg_Parameter, (void *)&defgw_param},
	{"customer_macaddr", Cx_Fabric_Arg_Parameter, (void *)&cust_macaddr_param},
	{"macaddr", Cx_Fabric_Arg_Parameter, (void *)&macaddr_param},
	{"nodeid", Cx_Fabric_Arg_Parameter, (void *)&nodeid_param},
	{"linkspeed", Cx_Fabric_Arg_Parameter, (void *)&linkspeed_param},
	{"link_resilience", Cx_Fabric_Arg_Parameter, (void *)&link_resilience_param},
	{"ls_policy", Cx_Fabric_Arg_Parameter, (void *)&linkspeed_policy_param},
	{"lu_factor", Cx_Fabric_Arg_Parameter,
	 (void *)&link_users_factor_param},
	{"uplink_speed", Cx_Fabric_Arg_Parameter, (void *)&uplink_speed_param},
	{"uplink_info", Cx_Fabric_Arg_Parameter, (void *)&uplink_info_param},
	{"linkmap", Cx_Fabric_Arg_Parameter, (void *)&linkmap_param},
	{"depth_chart", Cx_Fabric_Arg_Parameter, (void *)&depth_chart_param},
	{"routing_table", Cx_Fabric_Arg_Parameter, (void *)&routing_table_param},
	{"link_users", Cx_Fabric_Arg_Parameter, (void *)&link_users_param},
	{"partition_config", Cx_Fabric_Arg_Parameter, (void *)&partition_config_param},
	{"global_watch", Cx_Fabric_Arg_Parameter, (void *)&global_watch_param},
	{"link_stats", Cx_Fabric_Arg_Parameter, (void *)&link_stats_param},
	{"link_watch", Cx_Fabric_Arg_Parameter, (void *)&link_watch_param},
	{"mac_channel_stats", Cx_Fabric_Arg_Parameter,
			(void *)&mac_channel_stats_param},
	{"mac_channel_watch", Cx_Fabric_Arg_Parameter,
			(void *)&mac_channel_watch_param},
	{"mac_stats", Cx_Fabric_Arg_Parameter, (void *)&mac_stats_param},
	{"mac_watch", Cx_Fabric_Arg_Parameter, (void *)&mac_watch_param},
	{"uplink_stats", Cx_Fabric_Arg_Parameter, (void *)&uplink_stats_param},
	{"uplink_watch", Cx_Fabric_Arg_Parameter, (void *)&uplink_watch_param},
	{"uplink", Cx_Fabric_Arg_Parameter, (void *)&uplink_param},
	{"configid", Cx_Fabric_Arg_Parameter, (void *)&configurationid_param},
	{"partid", Cx_Fabric_Arg_Parameter, (void *)&partitionid_param},
	{"profileid", Cx_Fabric_Arg_Parameter, (void *)&profileid_param},
	{"part_nodes", Cx_Fabric_Arg_Parameter, (void *)&partition_nodes_param},
	{"part_range", Cx_Fabric_Arg_Parameter, (void *)&partition_range_param},
	{"start", Cx_Fabric_Arg_Parameter, (void *)&start_param},
	{"stop", Cx_Fabric_Arg_Parameter, (void *)&stop_param},
	{"status", Cx_Fabric_Arg_Parameter, (void *)&status_param},
	{"status_string", Cx_Fabric_Arg_Parameter, (void *)&status_string_param},
	{"dump", Cx_Fabric_Arg_Parameter, (void *)&dump_param},
	{"node", Cx_Fabric_Arg_Specifier, (void *)&node_spec},
	{"interface", Cx_Fabric_Arg_Specifier, (void *)&interface_spec},
	{"link", Cx_Fabric_Arg_Specifier, (void *)&link_spec},
	{"override", Cx_Fabric_Arg_Specifier, (void *)&override_spec},
	{"actual", Cx_Fabric_Arg_Specifier, (void *)&actual_spec},
	{"mac", Cx_Fabric_Arg_Specifier, (void *)&mac_spec},
	{"tftp", Cx_Fabric_Arg_Specifier, (void *)&tftp_spec},
	{"host", Cx_Fabric_Arg_Specifier, (void *)&host_spec},
	{"port", Cx_Fabric_Arg_Specifier, (void *)&port_spec},
	{"size", Cx_Fabric_Arg_Specifier, (void *)&size_spec},
	{"frequency", Cx_Fabric_Arg_Specifier, (void *)&frequency_spec},
	{"averaging_frequency", Cx_Fabric_Arg_Specifier, (void *)&averaging_frequency_spec},
	{"file", Cx_Fabric_Arg_Specifier, (void *)&file_spec},
	{"config", Cx_Fabric_Arg_Specifier, (void *)&configuration_spec},
	{"part", Cx_Fabric_Arg_Specifier, (void *)&partition_spec},
	{"profile", Cx_Fabric_Arg_Specifier, (void *)&profile_spec},
	{NULL, Cx_Fabric_Arg_Invalid, (void *)NULL},
};

cx_fabric_cmd_t config_get_cmd = {
	"get",
	IPMI_CMD_OEM_FABRIC_CONFIG_GET,
	1, 0,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_IPINFO,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPSRC,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MTU,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_MODE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDRS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_SERVER,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_PORT,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_RESILIENCE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NODENUM_OFFSET,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_BASE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_NUM,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NETMASK,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_DEFGW,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED_POLICY,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS_FACTOR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_INFO,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LACP_STATUS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR_BASE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR_MASK,
	},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PORT,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_OVERRIDE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_ACTUAL,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	},
	{
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	}
};

cx_fabric_cmd_t config_set_cmd = {
	"set",
	IPMI_CMD_OEM_FABRIC_CONFIG_SET,
	1, 1,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_IPINFO,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPSRC,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MTU,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_MODE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDRS,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_SERVER,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_PORT,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_RESILIENCE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NODENUM_OFFSET,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_BASE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_IPADDR_NUM,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_NETMASK,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_DEFGW,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED_POLICY,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_USERS_FACTOR,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR_BASE,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR_MASK,
	},
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_PORT,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_OVERRIDE,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_INTERFACE,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	},
	{IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	 IPMI_CMD_OEM_SPECIFIER_UNDEF,
	}
};

cx_fabric_cmd_t update_config_cmd = {
	"update_config",
	IPMI_CMD_OEM_FABRIC_UPDATE_CONFIG,
	0, 0,
	{0, 0, 0, 0, 0},
	{0, 0, 0, 0, 0},
	{0, 0, 0, 0, 0}
};

cx_fabric_cmd_t factory_default_cmd = {
	"factory_default",
	IPMI_CMD_OEM_FABRIC_FACTORY_DEFAULT,
	0, 0,
	{0, 0, 0, 0, 0},
	{0, 0, 0, 0, 0},
	{0, 0, 0, 0, 0}
};

cx_fabric_cmd_t health_monitor_cmd = {
	"health_monitor",
	IPMI_CMD_OEM_FABRIC_HEALTH_MONITOR,
	1, 0,
	{IPMI_CMD_OEM_FABRIC_PARAMETER_START,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_STOP,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_STATUS_STRING,
	 IPMI_CMD_OEM_FABRIC_PARAMETER_DUMP, 0},
	{ IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIG_PING,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_ICMP_PING,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_RMCP_PING, 
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_ROUTE_CHECK,
	 IPMI_CMD_OEM_FABRIC_SPECIFIER_MCAM_CHECK, 0},
	{0, 0, 0, 0, 0}
};

cx_fabric_param_t ipinfo_config_param = {
	"ipinfo",
	IPMI_CMD_OEM_FABRIC_PARAMETER_IPINFO,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME, 0, 0, 0, 0},
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_param_t uplink_info_config_param = {
	"uplink_info",
	IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_INFO,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME, 0, 0, 0, 0},
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_param_t lacp_status_config_param = {
	"lacp_status",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LACP_STATUS,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 4,
	cx_fabric_hex_printer
};

cx_fabric_param_t ntp_server_config_param = {
	"ntp_server",
	IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_SERVER,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_param_t ntp_port_config_param = {
	"ntp_port",
	IPMI_CMD_OEM_FABRIC_PARAMETER_NTP_PORT,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_param_t nodenum_offset_config_param = {
	"nodenum_offset",
	IPMI_CMD_OEM_FABRIC_PARAMETER_NODENUM_OFFSET,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_param_t ipsrc_config_param = {
	"ipsrc",
	IPMI_CMD_OEM_FABRIC_PARAMETER_IPSRC,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t mtu_config_param = {
	"mtu",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MTU,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_param_t uplink_mode_config_param = {
	"uplink_mode",
	IPMI_CMD_OEM_FABRIC_PARAMETER_UPLINK_MODE,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t macaddrs_config_param = {
	"macaddrs",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDRS,
	{IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME, 0, 0, 0},
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_param_t linkspeed_config_param = {
	"linkspeed",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 4,
	cx_fabric_string_printer
};

cx_fabric_param_t link_resilience_config_param = {
	"link_resilience",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINK_RESILIENCE,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t linkspeed_policy_config_param = {
	"ls_policy",
	IPMI_CMD_OEM_FABRIC_PARAMETER_LINKSPEED_POLICY,
	{0, 0, 0, 0, 0},
	Cx_Fabric_Arg_Value_Scalar, 1,
	cx_fabric_scalar_printer
};

cx_fabric_param_t macaddr_base_param = {
	"macaddr_base",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR_BASE,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_MAC_Address, 6,
	cx_fabric_mac_printer
};

cx_fabric_param_t macaddr_mask_param = {
	"macaddr_mask",
	IPMI_CMD_OEM_FABRIC_PARAMETER_MACADDR_MASK,
	{0, 0, 0, 0, 0}
	,
	Cx_Fabric_Arg_Value_MAC_Address, 6,
	cx_fabric_mac_printer
};

cx_fabric_spec_t tftp_config_spec = {
	"tftp",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_TFTP,
	Cx_Fabric_Arg_Value_IPV4_Address, 4,
	cx_fabric_ipv4_printer
};

cx_fabric_spec_t port_config_spec = {
	"port",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_PORT,
	Cx_Fabric_Arg_Value_Scalar, 2,
	cx_fabric_scalar_printer
};

cx_fabric_spec_t file_config_spec = {
	"file",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_FILENAME,
	Cx_Fabric_Arg_Value_String, 20,
	cx_fabric_string_printer
};

cx_fabric_spec_t config_ping_spec = {
	"config_ping",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_CONFIG_PING,
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_spec_t icmp_ping_spec = {
	"icmp_ping",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_ICMP_PING,
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_spec_t rmcp_ping_spec = {
	"rmcp_ping",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_RMCP_PING,
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_spec_t route_check_spec = {
	"route_check",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_ROUTE_CHECK,
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_spec_t mcam_check_spec = {
	"route_check",
	IPMI_CMD_OEM_FABRIC_SPECIFIER_MCAM_CHECK,
	Cx_Fabric_Arg_Invalid, 0,
	NULL
};

cx_fabric_arg_t cx_fabric_config_arg[] = {
	{"get", Cx_Fabric_Arg_Command, (void *)&config_get_cmd},
	{"set", Cx_Fabric_Arg_Command, (void *)&config_set_cmd},
	{"update_config", Cx_Fabric_Arg_Command, (void *)&update_config_cmd},
	{"factory_default", Cx_Fabric_Arg_Command, (void *)&factory_default_cmd},
	{"health_monitor", Cx_Fabric_Arg_Command, (void *)&health_monitor_cmd},
	{"ipinfo", Cx_Fabric_Arg_Parameter, (void *)&ipinfo_config_param},
	{"uplink_info", Cx_Fabric_Arg_Parameter, (void *)&uplink_info_config_param},
	{"lacp_status", Cx_Fabric_Arg_Parameter, (void *)&lacp_status_config_param},
	{"ntp_server", Cx_Fabric_Arg_Parameter, (void *)&ntp_server_config_param},
	{"ntp_port", Cx_Fabric_Arg_Parameter, (void *)&ntp_port_config_param},
	{"nodenum_offset", Cx_Fabric_Arg_Parameter, (void *)&nodenum_offset_config_param},
	{"ipsrc", Cx_Fabric_Arg_Parameter, (void *)&ipsrc_config_param},
	{"mtu", Cx_Fabric_Arg_Parameter, (void *)&mtu_config_param},
	{"uplink_mode", Cx_Fabric_Arg_Parameter,
	 (void *)&uplink_mode_config_param},
	{"uplink", Cx_Fabric_Arg_Parameter, (void *)&uplink_param},
	{"macaddrs", Cx_Fabric_Arg_Parameter, (void *)&macaddrs_config_param},
	{"linkspeed", Cx_Fabric_Arg_Parameter, (void *)&linkspeed_config_param},
	{"link_resilience", Cx_Fabric_Arg_Parameter,
	 (void *)&link_resilience_config_param},
	{"ls_policy", Cx_Fabric_Arg_Parameter,
	 (void *)&linkspeed_policy_config_param},
	{"lu_factor", Cx_Fabric_Arg_Parameter,
	 (void *)&link_users_factor_param},
	{"ipaddr_base", Cx_Fabric_Arg_Parameter, (void *)&ipaddr_base_param},
	{"ipaddr_num", Cx_Fabric_Arg_Parameter, (void *)&ipaddr_num_param},
	{"netmask", Cx_Fabric_Arg_Parameter, (void *)&netmask_param},
	{"defgw", Cx_Fabric_Arg_Parameter, (void *)&defgw_param},
	{"macaddr_base", Cx_Fabric_Arg_Parameter, (void *)&macaddr_base_param},
	{"macaddr_mask", Cx_Fabric_Arg_Parameter, (void *)&macaddr_mask_param},
	{"start", Cx_Fabric_Arg_Parameter, (void *)&start_param},
	{"stop", Cx_Fabric_Arg_Parameter, (void *)&stop_param},
	{"status_string", Cx_Fabric_Arg_Parameter, (void *)&status_string_param},
	{"dump", Cx_Fabric_Arg_Parameter, (void *)&dump_param},
	{"tftp", Cx_Fabric_Arg_Specifier, (void *)&tftp_config_spec},
	{"port", Cx_Fabric_Arg_Specifier, (void *)&port_config_spec},
	{"file", Cx_Fabric_Arg_Specifier, (void *)&file_config_spec},
	{"override", Cx_Fabric_Arg_Specifier, (void *)&override_spec},
	{"interface", Cx_Fabric_Arg_Specifier, (void *)&interface_spec},
	{"config_ping", Cx_Fabric_Arg_Specifier, (void *)&config_ping_spec},
	{"icmp_ping", Cx_Fabric_Arg_Specifier, (void *)&icmp_ping_spec},
	{"rmcp_ping", Cx_Fabric_Arg_Specifier, (void *)&rmcp_ping_spec},
	{"route_check", Cx_Fabric_Arg_Specifier, (void *)&route_check_spec},
	{"mcam_check", Cx_Fabric_Arg_Specifier, (void *)&mcam_check_spec},
	{NULL, Cx_Fabric_Arg_Invalid, (void *)NULL},
};

cx_fabric_arg_type_t
cx_fabric_find_arg_type(cx_fabric_arg_t * arg_type_list, char *arg)
{
	int i, ip0, ip1, ip2, ip3;
	int mac0, mac1, mac2, mac3, mac4, mac5;
	int ls0, ls1;
	int val;
	int ret;

	errno = 0;

	// First see if it is a standard type (Command, Parameter, Specifier)
	i = 0;
	while (arg_type_list[i].keyword != NULL) {
		if ((strlen(arg) == strlen(arg_type_list[i].keyword)) &&
		    !strncasecmp(arg, arg_type_list[i].keyword,
				 strlen(arg_type_list[i].keyword))) {
			return arg_type_list[i].arg_type;
		}
		i++;
	}

	// If not, is it an expected value type (Scalar, String,
	//              IPV4 address, MAC address

	// Is it a MAC Address?
	if ((sscanf(arg, "%02x:%02x:%02x:%02x:%02x:%02x",
		    &mac0, &mac1, &mac2, &mac3, &mac4, &mac5)) == 6) {
		return Cx_Fabric_Arg_Value_MAC_Address;
	}
	// Is it an IPV4 Address?
	if ((sscanf(arg, "%d.%d.%d.%d", &ip0, &ip1, &ip2, &ip3)) == 4) {
		return Cx_Fabric_Arg_Value_IPV4_Address;
	}

	if ((sscanf(arg, "%d.%d", &ls0, &ls1)) == 2) {
		return Cx_Fabric_Arg_Value_Scalar;
	}

	// Is it a string?
	if (isalpha(arg[0])) {
		// Probably...
		return Cx_Fabric_Arg_Value_String;
	}

	// Is it a node range?
	if (strchr(arg, '-') || strchr(arg, ',')) {
		return Cx_Fabric_Arg_Value_Bitmap;
	}

	// Is it scalar?
	val = strtol(arg, NULL, 10);
	if (errno == 0) {
		return Cx_Fabric_Arg_Value_Scalar;
	}

	return Cx_Fabric_Arg_Invalid;
}

cx_fabric_cmd_t *cx_fabric_get_cmd(cx_fabric_arg_t * arg_type_list, char *arg)
{
	int i;

	errno = 0;

	i = 0;
	while (arg_type_list[i].keyword != NULL) {
		if (!strncasecmp(arg, arg_type_list[i].keyword,
				 strlen(arg_type_list[i].keyword))) {
			return ((cx_fabric_cmd_t *) arg_type_list[i].data);
		}
		i++;
	}
	return NULL;
}

cx_fabric_param_t *cx_fabric_get_param(cx_fabric_arg_t * arg_type_list,
				       char *arg)
{
	int i;

	errno = 0;

	i = 0;
	while (arg_type_list[i].keyword != NULL) {
		if (!strncasecmp(arg, arg_type_list[i].keyword,
				 strlen(arg_type_list[i].keyword))) {
			return ((cx_fabric_param_t *) arg_type_list[i].data);
		}
		i++;
	}
	return NULL;
}

cx_fabric_spec_t *cx_fabric_get_spec(cx_fabric_arg_t * arg_type_list, char *arg)
{
	int i;

	errno = 0;

	i = 0;
	while (arg_type_list[i].keyword != NULL) {
		if (!strncasecmp(arg, arg_type_list[i].keyword,
				 strlen(arg_type_list[i].keyword))) {
			return ((cx_fabric_spec_t *) arg_type_list[i].data);
		}
		i++;
	}
	return NULL;
}

int ranges_to_bitmap(char *arg, uint8_t *bitmap)
{
	int start, end, i = 0;
	char *ptr = arg;
	while(*ptr) {
		//printf("ptr = %s\n", ptr);
		start = strtol(ptr, &ptr, 10);
		if (*ptr == '-') {
			ptr++;
			end = strtol(ptr, &ptr, 10);
			for (i = start; i <= end; i++) {
				bitmap[i/8] |= (1 << (i%8));
			}
		} else {
			bitmap[start/8] |= (1 << (start%8));
		}

		if (*ptr == ',') {
			ptr++;
		}
	}
}

int
cx_fabric_get_value(cx_fabric_arg_type_t val_type, char *arg,
		    cx_fabric_value_t * value)
{
	int val;
	int i;

	value->val_type = val_type;
	switch (val_type) {
	case Cx_Fabric_Arg_Value_Scalar:
		val = strtol(arg, NULL, 10);
		value->val.scalar[0] = val & 0xff;
		value->val.scalar[1] = ((val >> 8) & 0xff);
		value->val.scalar[2] = ((val >> 16) & 0xff);
		value->val.scalar[3] = ((val >> 24) & 0xff);
		value->val_len = 4;
		break;
	case Cx_Fabric_Arg_Value_String:
		strncpy(value->val.string, arg, MAX_VAL_STRING);
		value->val_len = strlen(value->val.string);
		break;
	case Cx_Fabric_Arg_Value_IPV4_Address:
		sscanf(arg, "%d.%d.%d.%d",
		       (int *)&value->val.ipv4_addr[0],
		       (int *)&value->val.ipv4_addr[1],
		       (int *)&value->val.ipv4_addr[2],
		       (int *)&value->val.ipv4_addr[3]);
		value->val_len = 4;
		break;
	case Cx_Fabric_Arg_Value_MAC_Address:
		sscanf(arg, "%02x:%02x:%02x:%02x:%02x:%02x",
		       (int *)&value->val.mac_addr[0],
		       (int *)&value->val.mac_addr[1],
		       (int *)&value->val.mac_addr[2],
		       (int *)&value->val.mac_addr[3],
		       (int *)&value->val.mac_addr[4],
		       (int *)&value->val.mac_addr[5]);
		value->val_len = 6;
		fprintf(stdout, "ADDR = %02x:%02x:%02x:%02x:%02x:%02x\n",
			value->val.mac_addr[0], value->val.mac_addr[1],
			value->val.mac_addr[2], value->val.mac_addr[3],
			value->val.mac_addr[4], value->val.mac_addr[5]);

		break;
	case Cx_Fabric_Arg_Value_Bitmap:
		memset(value->val.bitmap, 0, MAX_VAL_BITMAP);
		ranges_to_bitmap(arg, value->val.bitmap);
		value->val_len = MAX_VAL_BITMAP;
		break;
	default:
		return -1;
		break;
	};
	return 0;
}

#define MAX_SPECS 8
int
cx_fabric_cmd_parser(struct ipmi_intf *intf,
		     cx_fabric_arg_t * args, int argc, char **argv)
{
	int ret, i, j, cur_arg = 0;
	cx_fabric_arg_type_t arg_type;
	struct ipmi_rq req;
	struct ipmi_rs *rsp;
	uint8_t msg_data[128];
	cx_fabric_cmd_t *cmd = NULL;
	cx_fabric_param_t *param = NULL;
	cx_fabric_value_t param_value;
	cx_fabric_spec_t *spec[] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	cx_fabric_value_t spec_value[MAX_SPECS];
	uint8_t spec_count = 0, req_specs = 0, req_specs_found = 0;
	int data_pos = 0;


	if (argc < 1 || strncmp(argv[0], "help", 4) == 0) {
		cx_fabric_usage();
		return 0;
	}

	param_value.val_type = Cx_Fabric_Arg_Invalid;
	memset(&spec_value[0], 0, MAX_SPECS * sizeof(cx_fabric_value_t));
	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 128);
	req.msg.netfn = IPMI_NETFN_OEM_SS;

	// Each argument is either a command, a parameter, a value, or a specifier
	// Commands are config, get, set, update
	// Parameters are ipaddr, ipsrc, netmask, defgw, macaddr,
	//    linkspeed, uplink
	// Specifiers are node, interface
	// Values can be a decimal number, ipv4 address, mac address, or
	//    the strings "static" or "dynamic"

	while (cur_arg < argc) {
	        //printf("argv[%d] = .%s.\n", cur_arg, argv[cur_arg]);
		arg_type = cx_fabric_find_arg_type(args, argv[cur_arg]);

		if (arg_type == Cx_Fabric_Arg_Command) {
			cmd = cx_fabric_get_cmd(args, argv[cur_arg]);
			if (cmd == NULL) {
				lprintf(LOG_NOTICE,
					"No defined activity for cmd %s\n",
					argv[cur_arg]);
				cur_arg++;
				continue;
			}
			req.msg.cmd = cmd->ipmi_cmd;
		} else if (arg_type == Cx_Fabric_Arg_Parameter) {
			param = cx_fabric_get_param(args, argv[cur_arg]);

			if ((cmd && cmd->parameter_value_expected) &&
			    (param->val_type != Cx_Fabric_Arg_Invalid)) {

				if ((cur_arg + 1) >= argc) {
					lprintf(LOG_ERR,
						"No value specified for parameter %s\n",
						param->keyword);
					return -1;

				}
				// Now we need to look at its value
				cur_arg++;

				arg_type = cx_fabric_find_arg_type(args,
								   argv
								   [cur_arg]);
				if ((arg_type == Cx_Fabric_Arg_Value_Scalar) && (param->val_type == Cx_Fabric_Arg_Value_Bitmap)) {
					arg_type = Cx_Fabric_Arg_Value_Bitmap;
				}
				if (arg_type != param->val_type) {
					lprintf(LOG_ERR,
						"Invalid value type for parameter %s\n",
						param->keyword);
					return -1;
				}

				ret =
				    cx_fabric_get_value(arg_type, argv[cur_arg],
							&param_value);
			} else if (!cmd) {
				lprintf(LOG_ERR,
					"No valid command specified\n");
				goto cx_fabric_main_error_out;
			}
		} else if (arg_type == Cx_Fabric_Arg_Specifier) {
			spec[spec_count] =
			    cx_fabric_get_spec(args, argv[cur_arg]);

			if (spec[spec_count]->val_type != Cx_Fabric_Arg_Invalid) {

				cur_arg++;

				if ((cur_arg) >= argc) {
					lprintf(LOG_ERR,
						"No  value specified for specifier %s\n",
						spec[spec_count]->keyword);
					return -1;

				}
				// Now we need to look at its value
				arg_type = cx_fabric_find_arg_type(args,
								   argv
								   [cur_arg]);
				if (arg_type != spec[spec_count]->val_type) {
					lprintf(LOG_ERR,
						"Invalid value type for specifier %s\n",
						spec[spec_count]->keyword);
					return -1;
				}

				ret =
				    cx_fabric_get_value(arg_type, argv[cur_arg],
							&spec_value
							[spec_count]);
			} else {
				spec_value[spec_count].val_type =
				    Cx_Fabric_Arg_Invalid;
				spec_value[spec_count].val.scalar[0] = 0;
				spec_value[spec_count].val_len = 1;

			}
			spec_count++;
		} else {
			lprintf(LOG_ERR, "Unexpected argument\n");
			goto cx_fabric_main_error_out;
		}

		cur_arg++;
	}

	if (cmd == NULL) {
		goto cx_fabric_main_error_out;
	}
	// Now, sanity check everything before forming the message
	// Does this command require a parameter, if so do we have one?
	if (cmd->parameter_required) {
		if (param == NULL) {
			lprintf(LOG_ERR,
				"Required parameter for cmd %s missing\n",
				cmd->keyword);
			goto cx_fabric_main_error_out;

		}
	}
	// Does this command accept the parameter being passed?
	if (param) {
		for (i = 0; i < MAX_PERMITTED_PARAMS; i++) {
			if (param->param == cmd->permitted_params[i]) {
				break;
			}
		}
		if (i == MAX_PERMITTED_PARAMS) {
			lprintf(LOG_ERR,
				"Parameter %s not permitted for cmd %s\n",
				param->keyword, cmd->keyword);
			goto cx_fabric_main_error_out;
		}
	}
	// Does this command accept the specifiers that are given
	for (j = 0; j < MAX_SPECS; j++) {
		if (spec[j]) {
			for (i = 0; i < MAX_PERMITTED_SPECIFIERS; i++) {
				if (spec[j]->spec ==
				    cmd->permitted_specifiers[i]) {
					break;
				}
			}
			if (i == MAX_PERMITTED_SPECIFIERS) {
				lprintf(LOG_ERR,
					"Specifier %s not permitted for cmd %s\n",
					spec[j]->keyword, cmd->keyword);
				goto cx_fabric_main_error_out;
			}
		}
	}
	// Are all required specifiers for the command present?
	for (j = 0; j < MAX_REQUIRED_SPECIFIERS; j++) {
		if (cmd->required_specifiers[j] != 0) {
			req_specs++;
			for (i = 0; i < MAX_SPECS; i++) {
				if (spec[i]) {
					if (spec[i]->spec ==
					    cmd->required_specifiers[j]) {
						req_specs_found++;
					}
				}
			}
		}
	}
	if (req_specs != req_specs_found) {
		lprintf(LOG_ERR, "Required specifiers for command %s missing\n",
			cmd->keyword);
		goto cx_fabric_main_error_out;
	}
	// Are all the required specifiers for the parameter present
	if (param) {
		for (j = 0; j < MAX_REQUIRED_SPECIFIERS; j++) {
			if (param->required_specifiers[j] != 0) {
				req_specs++;
				for (i = 0; i < MAX_SPECS; i++) {
					if (spec[i]) {
						if (spec[i]->spec ==
						    param->
						    required_specifiers[j]) {
							req_specs_found++;
						}
					}
				}
			}
		}
	}
	if (req_specs != req_specs_found) {
		lprintf(LOG_ERR,
			"Required specifiers for parameter %s missing\n",
			param->keyword);
		goto cx_fabric_main_error_out;
	}
	// Start filling in msg_data
	if (param) {
		msg_data[data_pos++] = param->param;

		if (param_value.val_type != Cx_Fabric_Arg_Invalid) {
			switch (param_value.val_type) {
			case Cx_Fabric_Arg_Value_Scalar:
				msg_data[data_pos++] =
				    MSG_PARAM_VAL_START_SCALAR;
				for (i = 0; i < param_value.val_len; i++) {
					msg_data[data_pos++] =
					    param_value.val.scalar[i];
				}
				msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
				break;
			case Cx_Fabric_Arg_Value_String:
				msg_data[data_pos++] =
				    MSG_PARAM_VAL_START_STRING;
				for (i = 0; i < param_value.val_len; i++) {
					msg_data[data_pos++] =
					    param_value.val.string[i];
				}
				msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
				break;
			case Cx_Fabric_Arg_Value_IPV4_Address:
				msg_data[data_pos++] =
				    MSG_PARAM_VAL_START_IPV4_ADDR;
				for (i = 0; i < param_value.val_len; i++) {
					msg_data[data_pos++] =
					    param_value.val.ipv4_addr[i];
				}
				msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
				break;
			case Cx_Fabric_Arg_Value_MAC_Address:
				msg_data[data_pos++] =
				    MSG_PARAM_VAL_START_MAC_ADDR;
				for (i = 0; i < param_value.val_len; i++) {
					msg_data[data_pos++] =
					    param_value.val.mac_addr[i];
				}
				msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
				break;
			case Cx_Fabric_Arg_Value_Bitmap:
				msg_data[data_pos++] =
				    MSG_PARAM_VAL_START_BITMAP;
				for (i = 0; i < param_value.val_len; i++) {
					msg_data[data_pos++] =
					    param_value.val.bitmap[i];
				}
				msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
				break;
			}
		}
	}
	for (j = 0; j < spec_count; j++) {
		msg_data[data_pos++] = spec[j]->spec;
		switch (spec[j]->val_type) {
		case Cx_Fabric_Arg_Value_Scalar:
			for (i = 0; i < spec_value[j].val_len; i++) {
				msg_data[data_pos++] =
				    spec_value[j].val.scalar[i];
			}
			msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
			break;
		case Cx_Fabric_Arg_Value_String:
			for (i = 0; i < spec_value[j].val_len; i++) {
				msg_data[data_pos++] =
				    spec_value[j].val.string[i];
			}
			msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
			break;
		case Cx_Fabric_Arg_Value_IPV4_Address:
			for (i = 0; i < spec_value[j].val_len; i++) {
				msg_data[data_pos++] =
				    spec_value[j].val.ipv4_addr[i];
			}
			msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
			break;
		case Cx_Fabric_Arg_Value_MAC_Address:
			for (i = 0; i < spec_value[j].val_len; i++) {
				msg_data[data_pos++] =
				    spec_value[j].val.mac_addr[i];
			}
			msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
			break;
		case Cx_Fabric_Arg_Value_Bitmap:
			msg_data[data_pos++] =
			    MSG_PARAM_VAL_START_BITMAP;
			for (i = 0; i < param_value.val_len; i++) {
				msg_data[data_pos++] =
				    param_value.val.bitmap[i];
			}
			msg_data[data_pos++] = MSG_ELEMENT_TERMINATOR;
			break;
		}
	}

	req.msg.data = msg_data;
	req.msg.data_len = data_pos;

	rsp = intf->sendrecv(intf, &req);
	//lprintf(LOG_ERR, "req: netfn: 0x%x, lun: 0x%x, \n"
	//"cmd: 0x%x, target_cmd: 0x%x, data_len: 0x%x\n"
	//"data: \n"
	//"%02x %02x %02x %02x %02x %02x %02x %02x \n"
	//"%02x %02x %02x %02x %02x %02x %02x %02x \n"
	//"rsp_data0 0x%x rsp_data1 0x%x\n",
	//req.msg.netfn, req.msg.lun, req.msg.cmd,
	//req.msg.target_cmd, req.msg.data_len,
	//req.msg.data[0], req.msg.data[1], req.msg.data[2], req.msg.data[3],
	//req.msg.data[4], req.msg.data[5], req.msg.data[6], req.msg.data[7],
	//req.msg.data[8], req.msg.data[9], req.msg.data[10], req.msg.data[11],
	//req.msg.data[12], req.msg.data[13], req.msg.data[14], req.msg.data[15],
	//*(rsp->data), *((rsp->data)+1));
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error during fabric command\n");
		return -1;
	}

	if (rsp->ccode == 0) {
		if ((cmd->ipmi_cmd == IPMI_CMD_OEM_FABRIC_GET) ||
		    ((cmd->ipmi_cmd == IPMI_CMD_OEM_FABRIC_CONFIG_GET) &&
		     (param->val_len)) ||
		    ((cmd->ipmi_cmd == IPMI_CMD_OEM_FABRIC_HEALTH_MONITOR) &&
		     (req.msg.data[0] == IPMI_CMD_OEM_FABRIC_PARAMETER_STATUS_STRING) &&
		     (param->val_len))) {
			memcpy(param_value.val.scalar, rsp->data,
			       param->val_len);
			param->printer(&param_value, param->val_len);
		}
	} else {
		lprintf(LOG_ERR, "Command failed: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return 0;

cx_fabric_main_error_out:
//      cx_fabric_usage();
	return -1;
}

int cx_fabric_main(struct ipmi_intf *intf, int argc, char **argv)
{
	if ((argc > 1) && (!strcmp("config", argv[0]))) {
		cx_fabric_cmd_parser(intf, cx_fabric_config_arg, argc - 1,
				     &argv[1]);
	} else {
		cx_fabric_cmd_parser(intf, cx_fabric_main_arg, argc, &argv[0]);
	}
}

static void cx_data_usage(void)
{
	lprintf(LOG_NOTICE,
		"\n"
		"Usage: ipmitool cxoem data <type> <command> [option...]\n"
		"\n"
		"Data Commands: \n"
		"\n"
		"  mem  <read/write> <width>  <address> [fmt] [data] \n"
		"  cdb  <read/write> <length> <cid> [fmt] [data] \n"
		"where fmt is an optional formatting hint, one of,\n"
		"    'int' -- decimal integer\n"
		"    'uint' -- unsigned decimal integer\n"
		"    'xint' -- a hexadecimal integer\n"
		"    'ascii' -- an ascii string\n"
		"    'xstr' -- a byte string expressed in hex (i.e. 01ef23)\n"
		"\n");
}

static void cx_info_usage(void)
{
	lprintf(LOG_NOTICE,
		"\n"
		"Usage: ipmitool cxoem info <Type>\n"
		"\n"
		"Type Commands: \n"
		"\n"
		"  basic \n" "  partnum \n" "  chassis \n" "  card \n" "  node \n" "\n");
}

/* Interpret the string pointed to by valrep according to the length contraint
   and the claimed format.  Put the result byte-by-byte into the out array.
   Use the fmt parameter to decide whether to make integer values
   little-endian (ints are encoded little-endian).
*/
static int
asc_to_bin(const char *valrep, int length, int fmt, unsigned char *out)
{
	int i;
	const char *p;
	unsigned int intval = 0;
	memset(out, 0, length);
	// the string types (ascii and xstr) are easy: they just get stuffed
	// into the output, byte-for-byte
	if (fmt == CX_DATA_FMT_ASCII) {
		for (i = 0; i < length && valrep[i]; i++)
			out[i] = (unsigned int)valrep[i];
	} else if (fmt == CX_DATA_FMT_XSTR) {
		int vallen = strlen(valrep);
		if (vallen & 1) {	// input can't have an odd number of chars
			lprintf(LOG_ERR,
				"<value> must have an even number of hex digits\n");
			return CX_DATA_BAD_VALUE;
		}
		if (vallen < (2 * length)) {
			lprintf(LOG_ERR, "<value> must have enough characters "
				"to encode <length> bytes.\n");
			return CX_DATA_BAD_VALUE;
		}
		p = valrep;
		if (strncmp(valrep, "0x", 2) == 0 ||
		    strncmp(valrep, "0X", 2) == 0)
			p += 2;
		for (i = 0; i < length && *p; i++) {
			char byterep[3];
			int j = 2 * i;
			byterep[0] = *p++;
			byterep[1] = *p++;
			byterep[2] = 0;
			out[i] = strtoul(byterep, NULL, 16);
			if (errno) {
				lprintf(LOG_ERR,
					"<value> is not a valid hex string\n");
				return CX_DATA_BAD_VALUE;
			}
		}
	}
	// For the integer types we have to get the value, then
	// pack the out buffer little-endian.  Fortunately, this is the
	// same for memory locations and cdb values, so all we have to
	// worry about is length, which is guaranteed to be 1 or 4.
	else {
		if (length < 1 || length > 4) {
			lprintf(LOG_ERR, "<width> must be either 1 or 4\n");
			return CX_DATA_BAD_LENGTH;
		}
		if (fmt == CX_DATA_FMT_INT) {
			intval = (unsigned int)strtol(valrep, NULL, 10);
		} else if (fmt == CX_DATA_FMT_UINT) {
			intval = strtoul(valrep, NULL, 10);
		} else if (fmt == CX_DATA_FMT_XINT) {
			intval = strtoul(valrep, NULL, 16);
		}
		if (errno) {
			lprintf(LOG_ERR,
				"<value> is not a valid integer value.\n");
			return CX_DATA_BAD_VALUE;
		}
		out[0] = intval & 0xff;
		if (length == 4) {
			out[1] = (intval >> 8) & 0xff;
			out[2] = (intval >> 16) & 0xff;
			out[3] = (intval >> 24) & 0xff;
		}
	}
	return CX_DATA_OK;
}

/*
  Print a value or a series of values according to the specified format.
  This function can present one or more ints or bytes.  Ints are space-
  separated.  Bytes are not separated.
*/
static int print_value(int length, int format, const unsigned char *value)
{
	int rc = CX_DATA_OK;
	int datatype = CX_DATA_INT_TYPE;
	char *prntfmt = "0x%08x";
	printf("Value    :");
	if (length > 0) {
		switch (format) {
		case CX_DATA_FMT_INT:
			datatype = CX_DATA_INT_TYPE;
			prntfmt = " %d";
			break;
		case CX_DATA_FMT_UINT:
			datatype = CX_DATA_INT_TYPE;
			prntfmt = " %u";
			break;
		case CX_DATA_FMT_XINT:
			datatype = CX_DATA_INT_TYPE;
			prntfmt = " 0x%08x";
			break;
		case CX_DATA_FMT_ASCII:
			datatype = CX_DATA_BYTE_TYPE;
			prntfmt = "%c";
			break;
		case CX_DATA_FMT_XSTR:
			datatype = CX_DATA_BYTE_TYPE;
			prntfmt = "%02x";
			break;
		}		// switch
		if (datatype == CX_DATA_INT_TYPE) {	// integer
			int i;
			if (length == 1) {
				printf(prntfmt, value[0]);
			} else {
				for (i = 0; (4 * i) + 3 < length; i++) {
					int n = i * 4;
					unsigned int iv;
					iv = ((unsigned int)value[n + 3] << 24)
					    +
					    ((unsigned int)value[n + 2] << 16) +
					    ((unsigned int)value[n + 1] << 8) +
					    (unsigned int)value[n];
					printf(prntfmt, iv);
				}
			}
		} else {	// string data
			int i;
			printf(" ");
			for (i = 0; i < length; i++) {
				printf(prntfmt, value[i]);
			}
		}
		printf("\n");
	} else {
		rc = CX_DATA_BAD_LENGTH;
	}
	return rc;
}

/*  Execute commands to access the configuration data base
        Initialize the ipmi message
	Send the message
        On a read:
          print the value returned.
*/
int
cx_data_cdb(struct ipmi_intf *intf, int access, int length,
	    unsigned int cid, unsigned int fmt, unsigned char *value)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[8 + MAX_RETURNABLE_CDB_LEN];
	char out[5];
	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_DATA_ACCESS;
	msg_data[0] = 2;	// 2 = cdb access
	msg_data[1] = access;	// direction, i.e. read/write
	msg_data[2] = length & 0xff;
	msg_data[3] = (length >> 8) & 0xff;
	msg_data[4] = cid & 0xff;
	msg_data[5] = (cid >> 8) & 0xff;
	msg_data[6] = (cid >> 16) & 0xff;
	msg_data[7] = (cid >> 24) & 0xff;
	if (access == CX_DATA_ACCESS_WRITE) {
		memcpy((void *)(msg_data + 8), (void *)value, length);
		req.msg.data_len = length + 8;
	} else {
		req.msg.data_len = 8;
	}
	req.msg.data = msg_data;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error during cdb data command\n");
		return -1;
	}

	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "cxoem data cdb command failed: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	if ((rsp->ccode == 0) && (access == CX_DATA_ACCESS_READ)) {
		unsigned int value;
		unsigned int dlength = 0;
		unsigned int actual_length = 0;
		int n = 2;
		int datatype = 1;
		const char *prntfmt = " %d";

		actual_length = rsp->data[0] & 0xff;
		actual_length |= (rsp->data[1] << 8) & 0xff;
		dlength = rsp->data[2] & 0xff;
		dlength |= (rsp->data[3] << 8) & 0xff;
		if (dlength > MAX_RETURNABLE_CDB_LEN) {
			printf("CDB read length too lengthy\n");
			return -1;
		}
		printf("Data size: %d\n", dlength);
		printf("CID size :  %d\n", actual_length);
		print_value(dlength, fmt, &rsp->data[4]);
	}
	return rc;
}




/*  Execute commands to access cxoem memory mapped registers
       Initialize the msg
       Send the msg
       On a read:
          print the value returned.
 */
int
cx_data_mem(struct ipmi_intf *intf, int access, int width,
	    unsigned int address, int fmt, const char *value)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[16];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_DATA_ACCESS;
	msg_data[0] = 1;	// 1 = memory access
	msg_data[1] = (access == CX_DATA_ACCESS_READ) ? 1 : 2;
	msg_data[2] = width;
	msg_data[3] = address & 0xff;
	msg_data[4] = (address >> 8) & 0xff;
	msg_data[5] = (address >> 16) & 0xff;
	msg_data[6] = (address >> 24) & 0xff;
	if (access == CX_DATA_ACCESS_WRITE) {
		msg_data[7] = value[0];
		if (width > 1) {
			msg_data[8] = value[1];
			msg_data[9] = value[2];
			msg_data[10] = value[3];
		}
		req.msg.data_len = 11;
	} else {
		req.msg.data_len = 7;
	}
	req.msg.data = msg_data;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error during cxoem data mem command\n");
		return -1;
	}

	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "cxoem data mem command failed: %s",
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	if ((rsp->ccode == 0) && (access == CX_DATA_ACCESS_READ)) {
		print_value(width, fmt, rsp->data);
	}

	return rc;
}

static int str_to_fmt(const char *fmtstr)
{
	struct _sftbl {
		const char *fmtstr;
		unsigned int fmt;
	};
	struct _sftbl sftbl[] = {
		{"int", CX_DATA_FMT_INT},
		{"uint", CX_DATA_FMT_UINT},
		{"xint", CX_DATA_FMT_XINT},
		{"ascii", CX_DATA_FMT_ASCII},
		{"xstr", CX_DATA_FMT_XSTR},
		{0, 0}
	};
	int i;
	for (i = 0; sftbl[i].fmtstr; i++)
		if (!strcmp(fmtstr, sftbl[i].fmtstr))
			return sftbl[i].fmt;
	lprintf(LOG_ERR,
		"<fmt> isn't a valid format\n"
		"It sould be one of 'int', 'uint',"
		"'xint', 'ascii or 'xstr', or omitted.\n");
	return CX_DATA_FMT_DEFAULT;
}

/* For the cxoem data read/write mem n command,
      edit the data length (n) -- we handle only byte and word access for mem
      extract the address
      for reads:
         extract the optional formatting hint
      for writes:
         extract the optional formatting hint
         extract the value to be written
      access the memory
 */
static int
cx_data_mem_main(struct ipmi_intf *intf, int argc, char **argv,
		 int access, int length)
{
	int ret = 0;
	unsigned int addr;
	int fmt = CX_DATA_FMT_DEFAULT;
	const char *valptr = argv[4];

	if (length < 1 || length > 64) {
		lprintf(LOG_ERR, "<length> out of range. must be 1-64\n");
		return -1;
	}
	addr = strtoul(argv[3], (char **)NULL, 16);
	unsigned char value[4];
	if (!errno) {
		printf("Addr     : %08x\n", addr);
	} else {
		lprintf(LOG_ERR, "<addr> doesn't look like a valid value\n");
		return -1;
	}

	if (access == CX_DATA_ACCESS_READ && argc > 4) {
		fmt = str_to_fmt(argv[4]);
		if (fmt == CX_DATA_FMT_DEFAULT) {
			return -1;
		}
	}
	if (access == CX_DATA_ACCESS_WRITE) {
		if (argc > 5) {
			fmt = str_to_fmt(argv[4]);
			valptr = argv[5];
		} else if (argc > 4) {
			fmt = CX_DATA_FMT_XINT;
			valptr = argv[4];
		} else {
			lprintf(LOG_ERR, "<value> wasn't specified\n");
			return -1;
		}
		if (fmt != CX_DATA_FMT_INT)
			fmt = CX_DATA_FMT_XINT;
		if (asc_to_bin(valptr, length, fmt, value) == CX_DATA_OK) {
			print_value(length, fmt, value);
		} else {
			return -1;
		}
	}
	return cx_data_mem(intf, access, length, addr, fmt, value);

}

/* For the cxoem data read/write mem n command,
      Extract the CID (configuration id)
      On a read:
         extract the optional format hint.
      On a write:
         extract the optional format hint.
         extract the data to be written
      Access the cdb
 */
static int
cx_data_cdb_main(struct ipmi_intf *intf, int argc,
		 char **argv, int access, int length)
{
	int width = 4;		// default to 4-bytes
	unsigned int addr;
	int fmt = CX_DATA_FMT_DEFAULT;
	unsigned char value[MAX_RETURNABLE_CDB_LEN];
	unsigned int cid = 0;
	char *valptr = argv[4];

	cid = strtoul(argv[3], (char **)NULL, 16);
	if (!errno) {
		printf("Cid      : %08x\n", cid);
	} else {
		lprintf(LOG_ERR, "<cid> doesn't look like a valid value\n");
		return -1;
	}

	if (access == CX_DATA_ACCESS_READ && argc > 4) {
		fmt = str_to_fmt(argv[4]);
		if (fmt == CX_DATA_FMT_DEFAULT) {
			return -1;
		}
	}
	if (access == CX_DATA_ACCESS_WRITE) {
		// at this point, we have either a value or a format and
		// value left to parse from the cmdline.
		if (argc > 5) {
			fmt = str_to_fmt(argv[4]);
			valptr = argv[5];
		} else if (argc > 4) {
			fmt = CX_DATA_FMT_XSTR;
			valptr = argv[4];
		} else {
			lprintf(LOG_ERR, "<value> wasn't specified\n");
			return -1;
		}
		if (asc_to_bin(valptr, length, fmt, value) != CX_DATA_OK) {
			return -1;
		} else {
			print_value(length, fmt, value);
		}
	}
	if (fmt == CX_DATA_FMT_DEFAULT)
		fmt = CX_DATA_FMT_XSTR;
	return cx_data_cdb(intf, access, length, cid, fmt, value);
}

static int get_access(int argc, char **argv)
{
	int access = CX_DATA_ACCESS_UNKNOWN;
	if (argc > 1) {
		if (strncmp(argv[1], "read", 4) == 0)
			access = CX_DATA_ACCESS_READ;
		else if (strncmp(argv[1], "write", 4) == 0)
			access = CX_DATA_ACCESS_WRITE;
	}
	return access;
}

/*  For the cxoem data command, extract the common fields:
       target (cdb or memory)
       access (read or write)
       length of data
    then call the appropriate handler for the target.
*/
static int cx_data_main(struct ipmi_intf *intf, int argc, char **argv)
{
	int rv = 0;
	int target = CX_DATA_TARGET_UNKNOWN;
	int length = 0;
	int maxwidth = 64;
	int access;
	errno = 0;

	if (argc < 1 || strncmp(argv[0], "help", 4) == 0) {
		cx_data_usage();
		return 0;
	}
	if (strncmp(argv[0], "mem", 3) == 0) {
		target = CX_DATA_TARGET_MEM;
	} else if (strncmp(argv[0], "cdb", 3) == 0) {
		target = CX_DATA_TARGET_CDB;
		maxwidth = MAX_RETURNABLE_CDB_LEN;
	} else {
		cx_data_usage();
		rv = -1;
	}
	access = get_access(argc, argv);
	if ((access == CX_DATA_ACCESS_READ && argc < 4) ||
	    (access == CX_DATA_ACCESS_WRITE && argc < 5) ||
	    access == CX_DATA_ACCESS_UNKNOWN) {
		cx_data_usage();
		return -1;
	}

	length = strtol(argv[2], (char **)NULL, 10);
	if (!errno) {
		if (length < 1 || length > maxwidth) {
			lprintf(LOG_ERR, "<length> out of range\n");
			return -1;
		} else {
			printf("Length   : %d\n", length);
		}
	} else {
		lprintf(LOG_ERR, "<length> doesn't look like a valid value\n");
		return -1;
	}


	switch (target) {
	case CX_DATA_TARGET_MEM:
		rv = cx_data_mem_main(intf, argc, argv, access, length);
		break;
	case CX_DATA_TARGET_CDB:
		rv = cx_data_cdb_main(intf, argc, argv, access, length);
		break;
	default:
		cx_data_usage();
		rv = -1;
	}

	return rv;
}

#define MAX_MSG_DATA_SIZE 	256
/**
 * Generic Execute IPMI command
 *
 * @param intf       IPMI Interface
 *
 * @param net_fn     Net Function
 * @param command    Command to be send
 * @param input_buf  Input Buffer that contains the data
 * @param input_bufsize
 *                   Input Buffer Size.  Must be less than or equal to 256
 * @param output_buf IPMI Response will be stored here.
 * @param output_bufsize
 *                   Buffer size of the output_buffer, and on return it
 *                   contains the actual number of bytes of data
 * @param completion_code
 *                   Command completion code
 *
 * @return 0  = successful
 *         -1 = failure
 */
int
cx_send_ipmi_cmd(struct ipmi_intf *intf,
		 uint8_t net_fn, uint8_t command,
		 uint8_t * input_buf, int input_bufsize,
		 uint8_t * output_buf, int *output_bufsize,
		 uint8_t * completion_code)
{
	int rc = CXOEM_SUCCESS;
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[MAX_MSG_DATA_SIZE];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	if (input_bufsize > MAX_MSG_DATA_SIZE) {
		lprintf(LOG_ERR,
			"[cx_send_ipmi_cmd] message length exceeded.\n");
		return -1;
	}
	req.msg.netfn = net_fn;
	req.msg.cmd = command;
	if (input_bufsize) {
		if (input_buf) {
			memcpy(msg_data, input_buf, input_bufsize);
		} else {
			lprintf(LOG_ERR,
				"[cx_send_ipmi_cmd] Input buffer is null.\n");
			rc = CXOEM_ERROR;
		}
	}

	if (CXOEM_SUCCESS == rc) {
		req.msg.data = msg_data;
		req.msg.data_len = input_bufsize;

		rsp = intf->sendrecv(intf, &req);
		if (rsp == NULL) {
			lprintf(LOG_ERR,
				"[cx_send_ipmi_cmd] sendrecv failed.\n");
			rc = CXOEM_ERROR;
		} else {
			*completion_code = rsp->ccode;
			if (rsp->data_len > *output_bufsize) {
				lprintf(LOG_ERR,
					"[cx_send_ipmi_cmd] output buffer size is too small: (%d, %d).\n",
					*output_bufsize, rsp->data_len);
				rc = CXOEM_ERROR;
			} else {
				*output_bufsize = rsp->data_len;
				if (rsp->data_len) {
					if (output_buf) {
						memcpy(output_buf, rsp->data,
						       rsp->data_len);
					} else {
						lprintf(LOG_ERR,
							"[cx_send_ipmi_cmd] output buffer is null.\n");
						rc = CXOEM_ERROR;
					}
				}
			}

		}
	}

	return rc;
}

/**
 * Ping the "BMC" to see if this is Calxeda SoC
 *
 * @param intf     IPMI interface
 * @param to_print TRUE to print the result
 *                 FALSE not to print the result
 *
 * @return TRUE if this is Calxeda SoC
 *         FALSE otherwise.
 */
tboolean cx_is_CalxedaSoc(struct ipmi_intf * intf, tboolean to_print)
{
	tboolean is_Calxeda_soc = 0;	/* Assuming it's not Calxeda */
	int rv = 0;
	uint8_t rs_data[MAX_MSG_DATA_SIZE] = {0};
	int rs_data_size = MAX_MSG_DATA_SIZE;
	uint8_t completion_code = 0;
	cx_info_basic_t *basic_rs = (void *)rs_data;

	rs_data[0] = 0x01;	/* Basic Info */
	rv = cx_send_ipmi_cmd(intf, IPMI_NETFN_OEM_SS,
			      IPMI_CMD_OEM_GET_DEVICE_INFO, rs_data, 1, rs_data,
			      &rs_data_size, &completion_code);
	if (rv == 0) {
		if (completion_code) {
			printf("command failed with 0x%X completion code\n",
			       completion_code & 0xFF);
		} else {
			time_t lt;
			if (0x96CD == basic_rs->rev1.iana) {
				is_Calxeda_soc = 1;
				if (to_print) {
					printf("Calxeda SoC (0x%6.6X)\n",
					       basic_rs->rev1.iana);
					if (basic_rs->rev1.parameter_revision == 1)
					{
						/* Revision 1 */
						printf("  Firmware Version: %s\n",
						       basic_rs->rev1.firmware_version);
						printf("  SoC Version: v%d.%d.%d\n",
						       basic_rs->rev1.ecme_major_version,
						       basic_rs->rev1.ecme_minor_version,
						       basic_rs->rev1.ecme_revision);
						printf("  Build Number: %X %s\n",
						       basic_rs->rev1.ecme_build_number,
						       ((basic_rs->rev1.
							 ecme_build_number & 0x0F) ==
							0x0D) ? "(Dirty)" : "");
						lt = basic_rs->rev1.ecme_timestamp;
						printf("  Timestamp (%d): %s\n",
						       basic_rs->rev1.ecme_timestamp,
						       asctime(localtime(&lt)));
					}
					else if (basic_rs->rev1.parameter_revision == 2)
					{
						/* Revision 2 */
						printf("  Firmware Version: %s\n",
						       basic_rs->rev2.firmware_version);
						printf("  SoC Version: %s\n",
						       basic_rs->rev2.ecme_version);
						lt = basic_rs->rev2.ecme_timestamp;
						printf("  Timestamp (%d): %s\n",
						       basic_rs->rev2.ecme_timestamp,
						       asctime(localtime(&lt)));
					}
					else
					{
						/* Don't know how to read it */
						printf("  Unknown parameter revision\n");
					}
				}
			} else {
				printf("This is not Calxeda SoC\n");
			}
		}
	}
	return is_Calxeda_soc;
}

/*  For the cxoem info command, extract the common fields:
    then call the appropriate handler for the target.
*/
static int cx_info_main(struct ipmi_intf *intf, int argc, char **argv)
{

	int rv = -1;		// Assuming error
	uint8_t rs_data[MAX_MSG_DATA_SIZE];
	int rs_data_size = MAX_MSG_DATA_SIZE;
	uint8_t completion_code;
	int i;

	if (argc < 1 || strncmp(argv[0], "help", 4) == 0) {
		cx_info_usage();
		return 0;
	}
	if (strncmp(argv[0], "basic", 5) == 0) {
		if (cx_is_CalxedaSoc(intf, TRUE)) {
			rv = 0;
		}
	} else if (strncmp(argv[0], "partnum", 7) == 0) {
		if (cx_is_CalxedaSoc(intf, FALSE)) {
		}
	} else if (strncmp(argv[0], "chassis", 7) == 0) {
		if (cx_is_CalxedaSoc(intf, FALSE)) {
		}
	} else if (strncmp(argv[0], "card", 4) == 0) {
		struct oem_device_info_card_s {
			uint16_t	card_id;
			uint16_t	card_rev;
		} __attribute__ ((packed));
		typedef struct oem_device_info_card_s oem_device_info_card_t;
		char board_type[32];

		oem_device_info_card_t *card_rs;
		card_rs = (void *) rs_data;

		if (cx_is_CalxedaSoc(intf, FALSE)) {
			rs_data[0] = 0x06;	/* Card Info */
			rv = cx_send_ipmi_cmd(intf, IPMI_NETFN_OEM_SS,
					      IPMI_CMD_OEM_GET_DEVICE_INFO,
					      rs_data, 1, rs_data,
					      &rs_data_size, &completion_code);
			if (rv == 0) {
				if (completion_code) {
					printf
					    ("command failed with 0x%X completion code\n",
					     completion_code & 0xFF);
					rv = -1;
				} else {
					switch (card_rs->card_id) {
					/* Case 0 isn't really energycard, but
					   old versions will return that, so
					   we'll just go with it. */
					case 0:
					case 1:
						strcpy(board_type, "EnergyCard");
						break;
					case 7:
						strcpy(board_type, "Slingshot");
						break;
					default:
						sprintf(board_type, "Unknown (%X)", card_rs->card_id);
						break;
					}
					printf("  Board Type: %s\n", board_type);
					printf("  Board Revision: %d\n", card_rs->card_rev);
				}
			}

		}
	} else if (strncmp(argv[0], "node", 4) == 0) {
		struct oem_device_info_node_s {
			uint8_t oui[3];
			uint16_t fabric_node_id;
			uint8_t slot_number;
			uint8_t local_node_id;
		} __attribute__ ((packed));
		typedef struct oem_device_info_node_s oem_device_info_node_t;

		oem_device_info_node_t *node_rs;
		node_rs = (void *)rs_data;

		if (cx_is_CalxedaSoc(intf, FALSE)) {
			rs_data[0] = 0x04;	/* Node Info */
			rv = cx_send_ipmi_cmd(intf, IPMI_NETFN_OEM_SS,
					      IPMI_CMD_OEM_GET_DEVICE_INFO,
					      rs_data, 1, rs_data,
					      &rs_data_size, &completion_code);
			if (rv == 0) {
				if (completion_code) {
					printf("command failed with 0x%X completion code\n",
                           completion_code & 0xFF);
					rv = -1;
				} else {
					printf("OUI = 0x%X%X%X\n",
					       node_rs->oui[2], node_rs->oui[1],
					       node_rs->oui[0]);
					printf("Fabric Node ID = %d\n",
					       node_rs->fabric_node_id);
					printf("Slot Number = %d\n",
					       node_rs->slot_number);
					printf("Local Node ID = %d\n",
					       node_rs->local_node_id);
				}
			}
		}
	} else if (strncmp(argv[0], "wafer", 4) == 0) {
		struct oem_device_info_wafer_s {
			uint8_t wafer_info[16];
		} __attribute__ ((packed));
		typedef struct oem_device_info_wafer_s oem_device_info_wafer_t;

		oem_device_info_wafer_t *wafer_rs;
		wafer_rs = (void *)rs_data;

		if (cx_is_CalxedaSoc(intf, FALSE)) {
			rs_data[0] = 0x05;	/* Wafer Info */
			rv = cx_send_ipmi_cmd(intf, IPMI_NETFN_OEM_SS,
					      IPMI_CMD_OEM_GET_DEVICE_INFO,
					      rs_data, 1, rs_data,
					      &rs_data_size, &completion_code);
			if (rv == 0) {
				if (completion_code) {
					printf
					    ("command failed with 0x%X completion code\n",
					     completion_code & 0xFF);
					rv = -1;
				} else {
					char wafer_string[16];
					printf("Wafer Info\n");
					printf("   Raw : ");
					for (i = 0;
					     i < sizeof(wafer_rs->wafer_info);
					     i++) {
						printf("%2.2X ",
						       wafer_rs->
						       wafer_info[i] & 0xFF);
					}
					printf("\n");
					printf("   X-Coord	 : %d\n",
					       wafer_rs->wafer_info[0] & 0xFF);
					printf("   Y-Coord	 : %d\n",
					       wafer_rs->wafer_info[1] & 0xFF);
					printf("   Number 	 : %d\n",
					       wafer_rs->wafer_info[2] & 0xFF);
					memset(wafer_string, 0, 16);
					/*
					   for (i = 0; i < 8; i++) {
					   wafer_string[i] = wafer_rs->wafer_info[10-i];
					   }
					 */
					memcpy(wafer_string,
					       &(wafer_rs->wafer_info[3]), 8);
					printf("   Lot Number: %s\n",
					       wafer_string);
				}
			}
		}
	} else {
		cx_info_usage();
	}
	return rv;
}

static const char *tps_to_string(unsigned char state)
{
	int num_elements;

	num_elements = sizeof(tps_table)/sizeof(*tps_table);
	if (state < num_elements) {
		return tps_table[state];
	}
	return "";
}


#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

static int index_of_string(char *str,
                           const struct valstr *vals,
                           int n_vals,
                           int honor_case)
{
	int i;
	int cmp;

	for (i = 0; i < n_vals; ++i) {
		if (honor_case) {
			cmp = strcmp(str, vals[i].str);
		} else {
			cmp = strcasecmp(str, vals[i].str);
		}
		if (cmp == 0) {
			return i;
		}
	}
	return -1;
}

static int cx_feature_main(struct ipmi_intf *intf, int argc, char **argv)
{
	uint8_t rs_data[MAX_MSG_DATA_SIZE];
	int rs_data_size = MAX_MSG_DATA_SIZE;
	int rq_data_size = 0;
	uint8_t *rq_data;
	uint8_t completion_code;
	int get_op = 0;
	const struct valstr oem_features[] = {
		{0x01, "selaging"},
		{0x02, "hwwd"},
		{0x03, "tps"},
		{0x04, "mansen"},
	};
	int rv = 0;
	int i;
	int feature_index = 0;

	if (argc < 2 || strncmp(argv[0], "help", 4) == 0) {
		cx_feature_usage();
		return 0;
	}

	rq_data = rs_data;
	if (strncmp(argv[0], "status", 6) == 0) {
		rq_data_size = 2;
		rq_data[0] = 2;	// Get Operation
		get_op = 1;
	} else if (strncmp(argv[0], "enable", 6) == 0) {
		rq_data[2] = 1;	// Enable
		rq_data_size = 3;
		rq_data[0] = 1;	// Set Operation
	} else if (strncmp(argv[0], "disable", 7) == 0) {
		rq_data[2] = 0;	// Disable
		rq_data_size = 3;
		rq_data[0] = 1;	// Set Operation
	} else {
		rv = -1;
	}

	if (0 == rv) {
		i = index_of_string(argv[1],
				   oem_features,
				   ARRAY_SIZE(oem_features),
				   1);
		if (i < 0) {
			rv = -1;
		} else {
			feature_index = i;
			rq_data[1] = oem_features[i].val;
		}
	}

	if (0 == rv) {

		rv = cx_send_ipmi_cmd(intf, IPMI_NETFN_OEM_SS,
				      IPMI_CMD_OEM_FEATURES_ENABLE, rq_data,
				      rq_data_size, rs_data, &rs_data_size,
				      &completion_code);
		if (0 == rv) {
			if (get_op) {
				if (2 == feature_index) {
					printf("   %s state is %d %s\n", oem_features[feature_index].str,
						   rs_data[0], tps_to_string(rs_data[0]));
				} else {
					printf("   %s is %s\n",
						   oem_features[feature_index].str,
						   rs_data[0] ? "enabled" : "disabled");
				}
			}
		}
	}

	if (rv) {
		cx_feature_usage();
	}

	return rv;
}




#define CXOEM_PMIC_PARAM_UNKNOWN	0
#define CXOEM_PMIC_PARAM_VERSION	1
#define CXOEM_PMIC_PARAM_STATUS		2
#define CXOEM_PMIC_PARAM_TYPE		3
#define CXOEM_PMIC_N_PARAMS		4

const struct valstr cx_pmic_params[] = {
	{CXOEM_PMIC_PARAM_VERSION,"version"},
	{CXOEM_PMIC_PARAM_STATUS, "status"},
	{CXOEM_PMIC_PARAM_TYPE, "type"},
};


#define CXOEM_PMIC_TYPE_UNKNOWN		0
#define CXOEM_PMIC_TYPE_EXAR7724	1

const struct valstr cx_pmic_types[] = {
	{0x00, "Unknown"},
	{0x01, "Exar 7724"},
};


#define PMIC_STATUS_READY		0
#define PMIC_STATUS_INVALID		1
#define PMIC_STATUS_IN_PROGRESS		2
#define PMIC_STATUS_FAILED		3
#define PMIC_STATUS_SUCCESSFUL		4

const struct valstr cx_pmic_status[] = {
	{PMIC_STATUS_READY, "Ready"},
	{PMIC_STATUS_INVALID, "Invalid"},
	{PMIC_STATUS_IN_PROGRESS, "In progress"},
	{PMIC_STATUS_FAILED, "Failed"},
	{PMIC_STATUS_SUCCESSFUL, "Successful"},
};


static int cx_pmic_get_param(struct ipmi_intf *intf,
			     int cx_pmic_param, uint16_t handle)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	uint8_t msg_data[16];
	int pmic_type;
	int i;

	if (cx_pmic_param <= CXOEM_PMIC_PARAM_UNKNOWN
	    || cx_pmic_param > CXOEM_PMIC_N_PARAMS) {
		lprintf(LOG_ERR,
			"Unknown PMIC parameter %d", cx_pmic_param);
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_PMIC_GET_PARAM;
	req.msg.data = msg_data;

	msg_data[0] = cx_pmic_param;
	req.msg.data_len = 1;

	if (cx_pmic_param == CXOEM_PMIC_PARAM_STATUS) {
		msg_data[1] = handle & 0xff;
		msg_data[2] = (handle >> 8) & 0xff;
		req.msg.data_len += 2;
	}

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR,
			"Error getting PMIC parameter %s",
			val2str(cx_pmic_param, cx_pmic_params));
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR,
			"PMIC get %s failed: %s",
			val2str(cx_pmic_param, cx_pmic_params),
			val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	if (rsp->data[0] != cx_pmic_param) {
		lprintf(LOG_ERR, "Mismatched PMIC status response");
		lprintf(LOG_ERR, "received %d, but wanted %d\n",
			rsp->data[0], cx_pmic_param);
		return -1;
	}

	/*
	 * This is specific to the Exar 7724, perhaps.
	 * Maybe someday some other part will be supported.
	 */
	pmic_type = rsp->data[1];
	if (pmic_type != CXOEM_PMIC_TYPE_EXAR7724) {
		lprintf(LOG_ERR,
			"Can't interpret response for PMIC type %s",
			val2str(pmic_type, cx_pmic_types));
		return -1;
	}

	switch (cx_pmic_param) {
	case CXOEM_PMIC_PARAM_VERSION:
		printf("PMIC FW Version : %d\n", rsp->data[2]);
		break;

	case CXOEM_PMIC_PARAM_STATUS:
		printf("PMIC FW Status : %s\n",
		       val2str(rsp->data[2], cx_pmic_status));
		break;

	case CXOEM_PMIC_PARAM_TYPE:
		printf("PMIC Type : %s\n",
		       val2str(rsp->data[1], cx_pmic_types));
		break;
	}

	return CXOEM_SUCCESS;
}


#define CXOEM_FW_MAX_RECV_SIZE		128

struct cx_oem_pmic_fw_write_rq {
	uint8_t image_type;
	uint16_t offset;
	unsigned char data[CXOEM_FW_MAX_RECV_SIZE];
} __attribute__ ((packed));


#define MIN(a, b)	((a) < (b) ? (a) : (b))


static int cx_pmic_fw_write(struct ipmi_intf *intf, uint8_t *image, int len)
{
	struct ipmi_rs *rsp;
	struct ipmi_rq req;
	int pmic_type;
	struct cx_oem_pmic_fw_write_rq rq_data;
	int offset, size;

	memset(&req, 0, sizeof(req));
	memset(&rq_data, 0, sizeof(rq_data));

	req.msg.netfn = IPMI_NETFN_OEM_SS;
	req.msg.cmd = IPMI_CMD_OEM_PMIC_FW_WRITE;
	req.msg.data = (void *)&rq_data;

	rq_data.image_type = CXOEM_PMIC_TYPE_EXAR7724;	/* 'cuz. */
	rq_data.offset = 0;

	for (offset = 0; offset < len; offset += CXOEM_FW_MAX_RECV_SIZE) {
		/*
		 * Send image at offset for size bytes.
		 */
		size = MIN(len - offset, CXOEM_FW_MAX_RECV_SIZE);
		memcpy(rq_data.data, &image[offset], size);
		req.msg.data_len = sizeof(rq_data)
			- sizeof(rq_data.data) + size;
		rsp = intf->sendrecv(intf, &req);
		if (rsp == NULL) {
			lprintf(LOG_ERR, "Error: PMIC FW write failed");
			return -1;
		}
		if (rsp->ccode > 0) {
			lprintf(LOG_ERR, "Error: PMIC FW write failed (%s)",
				val2str(rsp->ccode, completion_code_vals));
			return -1;
		}

		/*
		 * Talk about the transaction id as it goes by...
		 */
		if (rsp->ccode == 0 && offset == 0) {
			uint16_t handle;
			handle = (unsigned int)rsp->data[0];
			handle |= (unsigned int)(rsp->data[1] << 8);
			printf("PMIC FW Write Handle ID: %d\n", handle);
		}

		rq_data.offset += size;
	}

	/*
	 * If the last block sent was short, that will terminate
	 * the receive.  Otherwise an additional (but empty) block
	 * needs to be sent to ensure the termination.
	 */
	if (offset - len == 0) {
		req.msg.data_len = sizeof(rq_data);
		rsp = intf->sendrecv(intf, &req);
		if (rsp == NULL) {
			lprintf(LOG_ERR, "Error: PMIC FW write failed");
			return -1;
		}
		if (rsp->ccode > 0) {
			lprintf(LOG_ERR, "Error: PMIC FW write failed (%s)",
				val2str(rsp->ccode, completion_code_vals));
			return -1;
		}
	}

	return 0;
}


static void cx_pmic_usage(void)
{
	lprintf(LOG_NOTICE,
		"\n"
		"Usage: ipmitool cxoem pmic <command> [option...]\n"
		"\n"
		"PMIC Commands: \n"
		"\n"
		"  get [type|version|status <handle>]\n"
		"  fwwrite <fw_file_ihex>\n"
		"where:\n"
		"    <handle> is a FW write transaction handle\n"
		"    <fw_file_hex> is a hex format FW image filename\n"
		"\n");
}


#define PMIC_EXAR_7724_IMAGE_SIZE	7 * 64

static int cx_pmic_main(struct ipmi_intf *intf, int argc, char **argv)
{
	int rv = -1;		// Assuming error
	uint8_t rs_data[MAX_MSG_DATA_SIZE];
	int rs_data_size = MAX_MSG_DATA_SIZE;
	uint8_t completion_code;

	if (argc < 1 || strncmp(argv[0], "help", 4) == 0) {
		cx_pmic_usage();
		return 0;
	}

	if (strncmp(argv[0], "get", 3) == 0
	    && (argc == 2 || argc == 3)) {
		int param;
		int ret;
		int handle = 0;
		int i;

		i = index_of_string(argv[1],
		                   cx_pmic_params,
		                   ARRAY_SIZE(cx_pmic_params),
		                   0);
		param = cx_pmic_params[i].val;
		if (param < 0) {
			cx_pmic_usage();
			return -1;
		}
		if (param == CXOEM_PMIC_PARAM_STATUS && argc == 3) {
			handle = strtol(argv[2], 0, 0);
			handle &= 0xFFFF;
		} else if (argc == 3) {
			cx_pmic_usage();
			return -1;
		}

		ret = cx_pmic_get_param(intf, param, handle);
		return ret;
	}

	if (strncmp(argv[0], "fwwrite", 7) == 0 && argc == 2) {
		char *filename;
		uint8_t image[65536];
		int addr_min, addr_max;
		int ret;

		filename = argv[1];

		if (strlen(filename) == 0) {
			lprintf(LOG_ERR,
				"Need the filename of a hex image.\n");
			return -1;
		}

		addr_min = 65536;
		addr_max = 0;
		memset(image, 0, 65536);

		ret = ihex_read_file(filename, image, &addr_min, &addr_max);

		if (ret < 0) {
			if (ret == -2) {
				lprintf(LOG_ERR,
					"File '%s' fails internal CRC check\n",
					filename);
			}
			return -1;
		}

		/*
		 * Check for Exar 77724 image sizes.
		 * Anything else is destined for trouble still...
		 */
		if (addr_min != 0
		    || addr_max != PMIC_EXAR_7724_IMAGE_SIZE - 1) {
			lprintf(LOG_ERR,
				"Wrong sizes for an Exar 7724 image.\n");
			return -1;
		}

		ret = cx_pmic_fw_write(intf, image, PMIC_EXAR_7724_IMAGE_SIZE);

		return ret;
	}

	cx_pmic_usage();
	return -1;
}


int ipmi_cxoem_main(struct ipmi_intf *intf, int argc, char **argv)
{
	int rc = 0;

	if (argc == 0 || strncmp(argv[0], "help", 4) == 0) {
		ipmi_cxoem_usage();
		return 0;
	} else if (!strncmp(argv[0], "fw", 2)) {
		rc = cx_fw_main(intf, argc - 1, &argv[1]);
	} else if (!strncmp(argv[0], "fabric", 6)) {
		rc = cx_fabric_main(intf, argc - 1, &argv[1]);
	} else if (!strncmp(argv[0], "data", 4)) {
		rc = cx_data_main(intf, argc - 1, &argv[1]);
	} else if (!strncmp(argv[0], "info", 4)) {
		rc = cx_info_main(intf, argc - 1, &argv[1]);
	} else if (!strncmp(argv[0], "feature", 7)) {
		rc = cx_feature_main(intf, argc - 1, &argv[1]);
	} else if (!strncmp(argv[0], "pmic", 4)) {
		rc = cx_pmic_main(intf, argc - 1, &argv[1]);
	}

	return rc;
}
