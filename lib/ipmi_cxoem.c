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

const struct valstr cx_ptypes[] = {
	{ 0x00, "DEL"      },
	{ 0x01, "DEL1"     },
	{ 0x02, "S2_ELF"   },
	{ 0x03, "SOC_ELF"  },
	{ 0x04, "A9_UEFI"  },
	{ 0x05, "A9_UBOOT" },
	{ 0x06, "A9_ELF"   },
	{ 0x07, "A9_EXEC"  },
	{ 0x08, "SOCDATA"  },
	{ 0x09, "DTB"      },
	{ 0x0a, "CDB"      },
	{ 0x0b, "UBOOTENV" },
	{ 0x0c, "SEL"      },
	{ 0x0d, "TOPOBLOB" },
	{ 0x0e, "UEFI_ENV" },
};

const struct valstr cx_tftp_status[] = {
	{ 0x00, "Invalid"     },
	{ 0x01, "In progress" },
	{ 0x02, "Failed"      },
	{ 0x03, "Complete"    },
	{ 0x04, "Canceled"    },
};

static void
ipmi_cxoem_usage(void)
{
	lprintf(LOG_NOTICE, 
	"Usage: ipmitool cxoem <command> [option...]\n"
	"\n"
	"Commands: \n"
	"\n"
	"  fw fabric mac log data\n");
}

static void
cx_fw_usage(void)
{
	lprintf(LOG_NOTICE,
	"\n"
	"Usage: ipmitool cxoem fw <command> [option...]\n"
	"\n"
	"Firmware Commands: \n"
	"\n"
	"  download   <filename> <slot> <type> <tftp ip[:port]>\n"
	"  upload     <slot> <filename> <type> <tftp ip[:port]>\n"
	"  activate   <slot>\n"
	"  invalidate <slot>\n"
	"  flags       <slot> <flags> \n"
	"  status     <job id>      - returns status of the transfer by <job id>\n"
	"  check      <slot>        - force a crc check\n"
	"  cancel     <job id>\n"   
	"  info       \n"      
	"  get        <filename> <offset> <size> <tftp ip[:port]>\n"
	"  put        <filename> <offset> <size> <tftp ip[:port]>\n"
	"\n");
}

static void
cx_fabric_usage(void)
{
	lprintf(LOG_NOTICE,
	"\n"
	"Usage: ipmitool cxoem fabric <command> [option...]\n"
	"\n"
	"Fabric Commands: \n"
	"\n"
	"  set|get  <parameter> <value> \n"
	"     where  \n"
	"  parameter = node, adaptive, jumbo \n"
	"\n");
}


int cx_fw_download(struct ipmi_intf *intf, char *filename, int slot, int type,
		           int ip1, int ip2, int ip3, int ip4, int port)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FW_DOWNLOAD;
	msg_data[0] = type;
	msg_data[1] = slot;
	msg_data[2] = CXOEM_FWDL_START;
	msg_data[3] = 0;
	msg_data[4] = 0;
	msg_data[5] = 6; // ipv4 addresses by default (for now)
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
		unsigned int handle;
		handle = (unsigned int)rsp->data[0];
		handle |= (unsigned int)(rsp->data[1] << 8);
      	printf("TFTP Handle ID:  %d\n", handle);
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Start FW download failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}

int cx_fw_upload(struct ipmi_intf *intf, char *filename, int slot, int type,
		           int ip1, int ip2, int ip3, int ip4, int port)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FW_DOWNLOAD;
	msg_data[0] = type;
	msg_data[1] = slot;
	msg_data[2] = CXOEM_FWUL_START;
	msg_data[3] = 0;
	msg_data[4] = 0;
	msg_data[5] = 6; // ipv4 addresses by default (for now)
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
		lprintf(LOG_ERR, "Error starting fw upload");
		return -1;
	}
	if (rsp->ccode == 0) {
		unsigned int handle;
		handle = (unsigned int)rsp->data[0];
		handle |= (unsigned int)(rsp->data[1] << 8);
      	printf("TFTP Handle ID:  %d\n", handle);
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Start FW upload failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}

int cx_fw_raw(struct ipmi_intf *intf, char *filename, unsigned int address, 
		      unsigned int size, int dir,
		      int ip1, int ip2, int ip3, int ip4, int port)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FW_RAW;
	msg_data[0] = dir;
	msg_data[1] = address & 0xff;
	msg_data[2] = (address >> 8) & 0xff;
	msg_data[3] = (address >> 16) & 0xff;
	msg_data[4] = (address >> 24) & 0xff;
	msg_data[5] = size & 0xff;
	msg_data[6] = (size >> 8) & 0xff;
	msg_data[7] = (size >> 16) & 0xff;
	msg_data[8] = (size >> 24) & 0xff;
	msg_data[9]  = ip1;
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
		unsigned int handle;
		handle = (unsigned int)rsp->data[0];
		handle |= (unsigned int)(rsp->data[1] << 8);
      	printf("TFTP Handle ID:  %d\n", handle);
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Start raw transfer failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}

int
cx_fw_status(struct ipmi_intf *intf, int handle)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[16];
	int status = -1;

	memset(&req, 0, sizeof(req));
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FW_GET_STATUS;
	msg_data[0] = 0;
	msg_data[1] = 1; // param 1 = download status
	msg_data[2] = handle & 0xff;
	msg_data[3] = (handle >> 8) & 0xff;
	req.msg.data = msg_data;
	req.msg.data_len = 3;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error checking fw status");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Check FW status failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	status = rsp->data[1];

	printf("Status : %s\n", val2str(status, cx_tftp_status));

	return rc;
}

int
cx_fw_check(struct ipmi_intf *intf, int slot)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FW_GET_STATUS;
	msg_data[0] = 0;
	msg_data[1] = 4; // param 4 = check image
	msg_data[2] = slot;
	req.msg.data = msg_data;
	req.msg.data_len = 3;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error during firmware check\n");
		return -1;
	}

	if (rsp->ccode == 0) {
		unsigned int crc32;
		crc32 = (unsigned int)rsp->data[5];
		crc32 |= (unsigned int)(rsp->data[4] << 8);
		crc32 |= (unsigned int)(rsp->data[3] << 16);
		crc32 |= (unsigned int)(rsp->data[2] << 24);
		if (rsp->data[1] == 0) {
			printf("CRC32 :  %08x\n", crc32);
		} else {
			printf("Error : %02x\n", rsp->data[0]);
			return -1;
		}
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Firmware check failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}

int
cx_fw_info(struct ipmi_intf *intf, int slot)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[64];
	int i;
	struct cx_fw_info_rs *s;
	img_info_t *ii;

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FW_GET_STATUS;
	msg_data[0] = 0;
	msg_data[1] = 2; // param 2 = info
	msg_data[2] = slot;
	req.msg.data = msg_data;
	req.msg.data_len = 2;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error starting fw download");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Start FW download failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	if (rsp->data_len < sizeof(struct cx_fw_info_rs))
		return -1;

	s = (struct cx_fw_info_rs *)&rsp->data[0];
	ii = &s->img_info;

	printf("\n");
	for (i = 0; i < (s->count / sizeof(img_info_t)); i++) {
		printf("%-18s : %02x\n", "Slot", ii[i].id);
		printf("%-18s : %02x (%s)\n", "Type", ii[i].type,
				val2str(ii[i].type, cx_ptypes));
		printf("%-18s : %08x\n", "Offset", ii[i].img_addr);
		printf("%-18s : %08x\n", "Size", ii[i].img_size);
		printf("%-18s : %08x\n\n", "Flags", ii[i].flags);
	}

	return rc;
}


int
cx_fw_flags(struct ipmi_intf *intf, int slot, uint32_t flags)
{
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[16];
	int i;

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FW_SET_STATUS;
	msg_data[0] = 0; // resvd
	msg_data[1] = 1; // param = 1 = "set flags"
	msg_data[2] = slot; 
	msg_data[3] = (uint8_t)((flags >> 24) & 0xff);
	msg_data[4] = (uint8_t)((flags >> 16) & 0xff);
	msg_data[5] = (uint8_t)((flags >> 8) & 0xff);
	msg_data[6] = (uint8_t)(flags & 0xff);
	req.msg.data = msg_data;
	req.msg.data_len = 7;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error starting fw download");
		return -1;
	}
	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "FW set flags failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return 0;
}


int
cx_fw_get_flags(struct ipmi_intf *intf, int slot, unsigned int *flags)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[64];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 64);
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FW_GET_STATUS;
	msg_data[0] = 0;
	msg_data[1] = 3; // param 3 = get SIMG header
	msg_data[2] = slot;
	req.msg.data = msg_data;
	req.msg.data_len = 3;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error reading SIMG info\n");
		return -1;
	}

	if (rsp->ccode == 0) {
		*flags = (unsigned int)rsp->data[21];
		*flags |= (unsigned int)(rsp->data[22] << 8);
		*flags |= (unsigned int)(rsp->data[23] << 16);
		*flags |= (unsigned int)(rsp->data[24] << 24);
	} else if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "SIMG read failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	return rc;
}


int
cx_fw_activate(struct ipmi_intf *intf, int slot)
{
	unsigned int flags;

	if (cx_fw_get_flags(intf, slot, &flags)) {
		return -1;
	}

	//printf("activate: read flags <%08x>\n", flags);
	flags &= (~0x02);  // bit 1 = SIMG_FLAG_ACTIVE
	printf("activate: write flags <%08x>\n", flags);

	cx_fw_flags(intf, slot, flags);

	return 0;
}


int
cx_fw_invalidate(struct ipmi_intf *intf, int slot)
{
	unsigned int flags;

	if (cx_fw_get_flags(intf, slot, &flags)) {
		return -1;
	}

	//printf("invalidate: read flags <%08x>\n", flags);
	flags &= (~0x04);  // bit 2 = SIMG_FLAG_INVALID
	printf("invalidate: write flags <%08x>\n", flags);

	cx_fw_flags(intf, slot, flags);

	return 0;
}


int
cx_fw_main(struct ipmi_intf * intf, int argc, char ** argv)
{
	char filename[65];
	int rv = 0;
	int slot, type;
	int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;
	int port = 0;

	errno = 0;

	if (argc < 1 || strncmp(argv[0], "help", 4) == 0) {
		cx_fw_usage();
		return 0;
	}

	if (strncmp(argv[0], "download", 8) == 0) {
		if((argc > 3) && (argc < 7) && (strlen(argv[1]) > 0))
		{
			/* There is a file name in the parameters */
			if(strlen(argv[1]) < 32)
			{
			   strcpy((char *)filename, argv[1]);
			   printf("File Name         : %s\n", filename);
			}
			else
			{
			   fprintf(stderr,"File name must be smaller than 32 bytes\n");
			}

			slot = strtol(argv[2], (char **)NULL, 10);
			if (!errno) {
				printf("Slot              : %d\n", slot);
			}
			else {
				fprintf(stderr,"<slot> doesn't look like a valid value\n");
				return -1;
			}

			if (isdigit(argv[3][0])) {
				type = strtol(argv[3], (char **)NULL, 10);
			}
			else {
				type = str2val(argv[3], cx_ptypes);
				if (type < 1 || type > 14)
					errno = -1;
			}
			if (!errno) {
				printf("Type              : %d\n", type);
			}
			else {
				fprintf(stderr,"<type> doesn't look like a valid value\n");
				return -1;
			}

			if (argc > 5 &&
				strncmp(argv[4], "tftp", 4) == 0) {
				if (strchr(argv[5], ':')) {
					if (sscanf(argv[5], "%d.%d.%d.%d:%d", 
							&ip1, &ip2, &ip3, &ip4, &port) != 5) {
						lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d:%d\n", ip1, ip2, ip3, ip4, port);
				} else {
					if (sscanf(argv[5], "%d.%d.%d.%d", 
							&ip1, &ip2, &ip3, &ip4) != 4) {
						lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
				}
			}
			else {
				cx_fw_usage();
				return -1;
			}
			cx_fw_download(intf, filename, slot, type, 
					       ip1, ip2, ip3, ip4, port);
		}
		else
		{
			cx_fw_usage();
			return -1;
		}
	}
	else if (strncmp(argv[0], "upload", 8) == 0) {
		if((argc > 3) && (argc < 7) && (strlen(argv[1]) > 0))
		{
			/* There is a file name in the parameters */
			if(strlen(argv[2]) < 32)
			{
			   strcpy((char *)filename, argv[2]);
			   printf("File Name         : %s\n", filename);
			}
			else
			{
			   fprintf(stderr,"File name must be smaller than 32 bytes\n");
			}

			slot = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Slot              : %d\n", slot);
			}
			else {
				fprintf(stderr,"<slot> doesn't look like a valid value\n");
				return -1;
			}

			if (isdigit(argv[3][0])) {
				type = strtol(argv[3], (char **)NULL, 10);
			}
			else {
				type = str2val(argv[3], cx_ptypes);
				if (type < 1 || type > 14)
					errno = -1;
			}
			if (!errno) {
				printf("Type              : %d\n", type);
			}
			else {
				fprintf(stderr,"<type> doesn't look like a valid value\n");
				return -1;
			}

			if (argc > 5 &&
				strncmp(argv[4], "tftp", 4) == 0) {
				if (strchr(argv[5], ':')) {
					if (sscanf(argv[5], "%d.%d.%d.%d:%d", 
							&ip1, &ip2, &ip3, &ip4, &port) != 5) {
						lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d:%d\n", ip1, ip2, ip3, ip4, port);
				} else {
					if (sscanf(argv[5], "%d.%d.%d.%d", 
							&ip1, &ip2, &ip3, &ip4) != 4) {
						lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
				}
			}
			else {
				cx_fw_usage();
				return -1;
			}
			cx_fw_upload(intf, filename, slot, type, 
					       ip1, ip2, ip3, ip4, port);
		}
		else
		{
			cx_fw_usage();
			return -1;
		}
	}
	else if (strncmp(argv[0], "put", 3) == 0) {
		unsigned int addr = 0;
		unsigned int size = 0;
		int dir = 0; // 0 = download, 1 = upload
		if((argc > 3) && (argc < 7) && (strlen(argv[1]) > 0))
		{
			/* There is a file name in the parameters */
			if(strlen(argv[1]) < 32)
			{
			   strcpy((char *)filename, argv[1]);
			   printf("File Name         : %s\n", filename);
			}
			else
			{
			   fprintf(stderr,"File name must be smaller than 32 bytes\n");
			}

			addr = strtoul(argv[2], (char **)NULL, 0);
			if (!errno) {
				printf("Address   : %08x\n", addr);
			}
			else {
				fprintf(stderr,"<address> doesn't look like a valid value\n");
				return -1;
			}

			size = strtoul(argv[3], (char **)NULL, 0);
			if (!errno) {
				printf("Size      : %08x\n", size);
			}
			else {
				fprintf(stderr,"<size> doesn't look like a valid value\n");
				return -1;
			}

			if (argc > 5 &&
				strncmp(argv[4], "tftp", 4) == 0) {
				if (strchr(argv[5], ':')) {
					if (sscanf(argv[5], "%d.%d.%d.%d:%d", 
							&ip1, &ip2, &ip3, &ip4, &port) != 5) {
						lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d:%d\n", ip1, ip2, ip3, ip4, port);
				} else {
					if (sscanf(argv[5], "%d.%d.%d.%d", 
							&ip1, &ip2, &ip3, &ip4) != 4) {
						lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
				}
			}
			else {
				cx_fw_usage();
				return -1;
			}
			cx_fw_raw(intf, filename, addr, size, dir, 
					       ip1, ip2, ip3, ip4, port);
		}
		else
		{
			cx_fw_usage();
			return -1;
		}
	}
	else if (strncmp(argv[0], "get", 3) == 0) {
		unsigned int addr = 0;
		unsigned int size = 0;
		int dir = 1; // 0 = download, 1 = upload
		if((argc > 3) && (argc < 7) && (strlen(argv[1]) > 0))
		{
			/* There is a file name in the parameters */
			if(strlen(argv[1]) < 32)
			{
			   strcpy((char *)filename, argv[1]);
			   printf("File Name         : %s\n", filename);
			}
			else
			{
			   fprintf(stderr,"File name must be smaller than 32 bytes\n");
			}

			addr = strtoul(argv[2], (char **)NULL, 0);
			if (!errno) {
				printf("Address   : %08x\n", addr);
			}
			else {
				fprintf(stderr,"<address> doesn't look like a valid value\n");
				return -1;
			}

			size = strtoul(argv[3], (char **)NULL, 0);
			if (!errno) {
				printf("Size      : %08x\n", size);
			}
			else {
				fprintf(stderr,"<size> doesn't look like a valid value\n");
				return -1;
			}

			if (argc > 5 &&
				strncmp(argv[4], "tftp", 4) == 0) {
				if (strchr(argv[5], ':')) {
					if (sscanf(argv[5], "%d.%d.%d.%d:%d", 
							&ip1, &ip2, &ip3, &ip4, &port) != 5) {
						lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d:%d\n", ip1, ip2, ip3, ip4, port);
				} else {
					if (sscanf(argv[5], "%d.%d.%d.%d", 
							&ip1, &ip2, &ip3, &ip4) != 4) {
						lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
						return -1;
					}
					printf("IP = %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
				}
			}
			else {
				cx_fw_usage();
				return -1;
			}
			cx_fw_raw(intf, filename, addr, size, dir, 
					       ip1, ip2, ip3, ip4, port);
		}
		else
		{
			cx_fw_usage();
			return -1;
		}
	}
	else if (strncmp(argv[0], "status", 6) == 0) {
		int handle = 0;

		if (argc == 2) {
			handle = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Handle : %d\n", handle);
			}
			else {
				fprintf(stderr,"<handle> doesn't look like a valid value\n");
				return -1;
			}
		}
		cx_fw_status(intf, handle);
		rv = 0;
	}
	else if (strncmp(argv[0], "info", 4) == 0) {
		int slot = -1;

		if (argc > 3 ) {
			slot = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Slot              : %d\n", slot);
			}
			else {
				fprintf(stderr,"<slot> doesn't look like a valid value\n");
				return -1;
			}
		}
		cx_fw_info(intf, slot);
	}
	else if (strncmp(argv[0], "activate", 8) == 0) {
		int slot = -1;

		if (argc == 2) {
			slot = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Slot              : %d\n", slot);
			}
			else {
				fprintf(stderr,"<slot> doesn't look like a valid value\n");
				return -1;
			}
		}
		else {
			cx_fw_usage();
			return -1;
		}
		cx_fw_activate(intf, slot);
	}
	else if (strncmp(argv[0], "invalidate", 10) == 0) {
		int slot = -1;

		if (argc == 2) {
			slot = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Slot              : %d\n", slot);
			}
			else {
				fprintf(stderr,"<slot> doesn't look like a valid value\n");
				return -1;
			}
		}
		else {
			cx_fw_usage();
			return -1;
		}
		cx_fw_invalidate(intf, slot);
	}
	else if (strncmp(argv[0], "flags", 5) == 0) {
		int slot = -1;
		uint32_t flags = 0xffffffff;

		if (argc == 3) {
			slot = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Slot              : %d\n", slot);
			}
			else {
				fprintf(stderr,"<slot> doesn't look like a valid value\n");
				return -1;
			}
			flags = strtoul(argv[2], (char **)NULL, 16);
			if (!errno) {
				printf("Flags             : %08x\n", flags);
			}
			else {
				fprintf(stderr,"<flags> doesn't look like a valid value\n");
				return -1;
			}
		}
		else {
			cx_fw_usage();
			return -1;
		}
		cx_fw_flags(intf, slot, flags);
	}
	else if (strncmp(argv[0], "check", 5) == 0) {
		int slot = -1;

		if (argc == 2) {
			slot = strtol(argv[1], (char **)NULL, 10);
			if (!errno) {
				printf("Slot  :  %d\n", slot);
			}
			else {
				fprintf(stderr,"<slot> doesn't look like a valid value\n");
				return -1;
			}
		}
		else {
			cx_fw_usage();
			return -1;
		}
		cx_fw_check(intf, slot);
		rv = 0;
	}
	else {
		cx_fw_usage();
		return -1;
	}


	return rv;
}


int
cx_fabric_param(struct ipmi_intf *intf, int direction, 
		        unsigned short param, int value)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[8];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, 8);
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_FABRIC_GET_PARAM;
	req.msg.cmd      += direction;
	msg_data[0] = 0;
	msg_data[1] = 1; // only get switch, i.e. "1", params for now
	msg_data[2] = param;
	msg_data[3] = value;
	req.msg.data = msg_data;
	req.msg.data_len = 3 + direction;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error during fabric param command\n");
		return -1;
	}

	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Fabric param command failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	if ((rsp->ccode == 0) && !direction) {
		unsigned int value;
		value = (unsigned int)(rsp->data[2] << 8);
		value |= (unsigned int)rsp->data[1];
		printf("Value :  %x\n", value);
	} 

	return rc;
}


int
cx_fabric_main(struct ipmi_intf * intf, int argc, char ** argv)
{
	int rv = 0;
	int argnum = 3;
	int value;
	int direction;

	errno = 0;

	if (argc < 1 || strncmp(argv[0], "help", 4) == 0) {
		cx_fabric_usage();
		return 0;
	}

	if (strncmp(argv[0], "get", 3) == 0) {
		direction = 0;
	} else if (strncmp(argv[0], "set", 3) == 0) {
		direction = 1;
	}
	else {
		cx_fabric_usage();
		return 0;
	}

	argnum += direction;

	if (direction) {
			if (argv[2] == NULL) {
				fprintf(stderr, "No param value was found\n");
				return -1;
			}
			value = strtol(argv[2], (char **)NULL, 10);
			if (!errno) {
				printf("Value   : %d\n", value);
			}
			else {
				fprintf(stderr,"<value> doesn't look valid\n");
				return -1;
			}
	}

	if (strncmp(argv[1], "node", 4) == 0) {

		cx_fabric_param(intf, direction, 1, value);

	}
	else if (strncmp(argv[1], "adaptive", 8) == 0) {

		cx_fabric_param(intf, direction, 2, value);

	}
	else if (strncmp(argv[1], "jumbo", 6) == 0) {

		cx_fabric_param(intf, direction, 4, value);

	}
	else {
		cx_fabric_usage();
		return -1;
	}

	return rv;
}

static void
cx_data_usage(void)
{
	lprintf(LOG_NOTICE,
	"\n"
	"Usage: ipmitool cxoem data <type> <command> [option...]\n"
	"\n"
	"Data Commands: \n"
	"\n"
	"  mem  <read/write> <width>  <address> [data] \n"
	"  cdb  <read/write> <length> <cid>     [data] \n"
	"\n");
}

int
cx_data_cdb(struct ipmi_intf *intf, int access, int length,
		        unsigned int cid, unsigned int value)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[16];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_DATA_ACCESS;
	msg_data[0] = 2;      // 2 = cdb access
	msg_data[1] = access; // direction, i.e. read/write
	msg_data[2] = length & 0xff;
	msg_data[3] = (length >> 8) & 0xff;
	msg_data[4] = cid & 0xff;
	msg_data[5] = (cid >> 8) & 0xff;
	msg_data[6] = (cid >> 16) & 0xff;
	msg_data[7] = (cid >> 24) & 0xff;
	if (access > 1) {
		msg_data[8] = value & 0xff;
		msg_data[9] = (value >> 8) & 0xff;
		msg_data[10] = (value >> 16) & 0xff;
		msg_data[11] = (value >> 24) & 0xff;
		req.msg.data_len = 12;
	}
	else {
		req.msg.data_len = 8;
	}
	req.msg.data = msg_data;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error during fabric param command\n");
		return -1;
	}

	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Fabric param command failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	if ((rsp->ccode == 0) && (access == 1)) {
		unsigned int value;
		int length = 0;

		length = rsp->data[0] & 0xff;
		length |= (rsp->data[1] << 8) & 0xff;

		if (length > 4) {
			printf("CDB read length too lengthy\n");
			return -1;
		}

		value = (unsigned int)(rsp->data[5] << 24);
		value = (unsigned int)(rsp->data[4] << 16);
		value = (unsigned int)(rsp->data[3] << 8);
		value |= (unsigned int)rsp->data[2];
		printf("Value    : %x\n", value);
	} 

	return rc;
}


int
cx_data_mem(struct ipmi_intf *intf, int access, int width,
		        unsigned int address, unsigned int value)
{
	int    rc = CXOEM_SUCCESS;
	struct ipmi_rs * rsp;
	struct ipmi_rq   req;
	uint8_t msg_data[16];

	memset(&req, 0, sizeof(req));
	memset(msg_data, 0, sizeof(msg_data));
	req.msg.netfn    = IPMI_NETFN_CXOEM;
	req.msg.cmd      = IPMI_CXOEM_DATA_ACCESS;
	msg_data[0] = 1;      // 1 = memory access
	msg_data[1] = access;
	msg_data[2] = width;
	msg_data[3] = address & 0xff;
	msg_data[4] = (address >> 8) & 0xff;
	msg_data[5] = (address >> 16) & 0xff;
	msg_data[6] = (address >> 24) & 0xff;
	if (access > 1) {
		msg_data[7] = value & 0xff;
		msg_data[8] = (value >> 8) & 0xff;
		msg_data[9] = (value >> 16) & 0xff;
		msg_data[10] = (value >> 24) & 0xff;
		req.msg.data_len = 11;
	}
	else {
		req.msg.data_len = 7;
	}
	req.msg.data = msg_data;

	rsp = intf->sendrecv(intf, &req);
	if (rsp == NULL) {
		lprintf(LOG_ERR, "Error during fabric param command\n");
		return -1;
	}

	if (rsp->ccode > 0) {
		lprintf(LOG_ERR, "Fabric param command failed: %s",
					val2str(rsp->ccode, completion_code_vals));
		return -1;
	}

	if ((rsp->ccode == 0) && (access == 1)) {
		value = (unsigned int)(rsp->data[3] << 24);
		value |= (unsigned int)(rsp->data[2] << 16);
		value |= (unsigned int)(rsp->data[1] << 8);
		value |= (unsigned int)rsp->data[0];
		printf("Value    : %08x\n", value);
	} 

	return rc;
}


int
cx_data_main(struct ipmi_intf * intf, int argc, char ** argv)
{
	int rv = 0;
	int access;
	int width = 4;          // default to 4-bytes
	unsigned int addr;
	unsigned int value = 0;

	errno = 0;

	if (argc < 1 || strncmp(argv[0], "help", 4) == 0) {
		cx_data_usage();
		return 0;
	}

	if (strncmp(argv[0], "mem", 3) == 0) {

		if (strncmp(argv[1], "read", 4) == 0) {
			if (argc != 4) {
				cx_data_usage();
				return 0;
			}
			access = 1;
		}
		else if (strncmp(argv[1], "write", 4) == 0) {
			if (argc != 5) {
				cx_data_usage();
				return 0;
			}
			access = 2;
		}
		else {
			cx_data_usage();
			return -1;
		}

		width = strtol(argv[2], (char **)NULL, 10);
		if (width < 1 || width > 4) {
			fprintf(stderr,"<width> out of range\n");
			return -1;
		}
		if (!errno) {
			printf("Width    : %d\n", width);
		}
		else {
			fprintf(stderr,"<width> doesn't look like a valid value\n");
			return -1;
		}
		addr = strtoul(argv[3], (char **)NULL, 16);
		if (!errno) {
			printf("Addr     : %08x\n", addr);
		}
		else {
			fprintf(stderr,"<addr> doesn't look like a valid value\n");
			return -1;
		}

		if (access > 1) {
			value = strtoul(argv[4], (char **)NULL, 16);
			if (!errno) {
				printf("Value    : %08x\n", value);
			}
			else {
				fprintf(stderr,"<value> doesn't look like a valid value\n");
				return -1;
			}
		}

		cx_data_mem(intf, access, width, addr, value);

	} else if (strncmp(argv[0], "cdb", 3) == 0) {

		unsigned int cid = 0;
		int length = 0;

		if (strncmp(argv[1], "read", 4) == 0) {
			if (argc != 4) {
				cx_data_usage();
				return 0;
			}
			access = 1;
		}
		else if (strncmp(argv[1], "write", 4) == 0) {
			if (argc != 5) {
				cx_data_usage();
				return 0;
			}
			access = 2;
		}
		else {
			cx_data_usage();
			return -1;
		}

		length = strtol(argv[2], (char **)NULL, 10);
		if (length < 1 || width > 4) {
			fprintf(stderr,"<length> out of range\n");
			return -1;
		}
		if (!errno) {
			printf("Length   : %d\n", length);
		}
		else {
			fprintf(stderr,"<length> doesn't look like a valid value\n");
			return -1;
		}
		cid = strtoul(argv[3], (char **)NULL, 16);
		if (!errno) {
			printf("Cid      : %08x\n", cid);
		}
		else {
			fprintf(stderr,"<cid> doesn't look like a valid value\n");
			return -1;
		}

		if (access > 1) {
			value = strtoul(argv[4], (char **)NULL, 16);
			if (!errno) {
				printf("Value    : %08x\n", value);
			}
			else {
				fprintf(stderr,"<value> doesn't look like a valid value\n");
				return -1;
			}
		}

		cx_data_cdb(intf, access, length, cid, value);

	} else {
		cx_data_usage();
		return -1;
	}

	return rv;
}

int
ipmi_cxoem_main(struct ipmi_intf * intf, int argc, char ** argv)
{
	int rc = 0;

	if (argc == 0 || strncmp(argv[0], "help", 4) == 0) {
		ipmi_cxoem_usage();
		return 0;
	}
	else if (!strncmp(argv[0], "fw", 2))
	{
		cx_fw_main(intf, argc-1, &argv[1]);
	}
	else if (!strncmp(argv[0], "fabric", 6))
	{
		cx_fabric_main(intf, argc-1, &argv[1]);
	}
	else if (!strncmp(argv[0], "data", 4))
	{
		cx_data_main(intf, argc-1, &argv[1]);
	}

	return rc;
}
