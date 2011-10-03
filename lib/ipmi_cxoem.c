
#pragma GCC optimize("O0")

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

static void
ipmi_cxoem_usage(void)
{
	lprintf(LOG_NOTICE, 
	"Usage: ipmitool cxoem <command> [option...]\n"
	"\n"
	"Commands: \n"
	"\n"
	"  fw fabric mac log \n");
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
	"  download   <filename> <slot> <type> [tftp <ip[:port]>]\n"
	"  upload     <slot> <filename> [tftp <ip[:port]>]\n"
	"  activate   [slot]\n"
	"  deactivate [slot]\n"
	"  flags       <slot> <flags> \n"
	"  status                   - returns status and job id of the \n"
	"                             most recent upload/download\n"
	"  check      [slot]        - force a crc check\n"
	"  cancel     [job id]\n"   
	"  info       [slot]\n"      
	"  blow       <filename> [size [offset]]\n"
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
	msg_data[10] = ((port & 0xff) >> 8);
	msg_data[11] = (port & 0xff);
	msg_data[12] = strlen(filename) + 1;
	memcpy(&msg_data[13], filename, msg_data[12]);
	req.msg.data = msg_data;
	req.msg.data_len = msg_data[12] + 13;

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
	msg_data[3] = (uint8_t)(flags & 0xff);
	req.msg.data = msg_data;
	req.msg.data_len = 4;

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
cx_fw_main(struct ipmi_intf * intf, int argc, char ** argv)
{
	char filename[65];
	int rv = 0;
	int slot, type;
	int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;
	int port = 0;

	errno = 0;

#if 0
	{
		int i;
		printf("\n argc<%d> ", argc);
		for (i = 0; i < argc; i++) {
			printf("<%s> ", argv[i]);
		}
		printf("\n");
	}
#endif

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
				if (sscanf(argv[5], "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4) != 4) {
					lprintf(LOG_ERR, "Invalid IP address: %s", argv[5]);
					return -1;
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
	else if (strncmp(argv[0], "status", 6) == 0) {
		printf("Status is as status does\n");
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
//		cx_fw_activate(intf, slot);
	}
	else if (strncmp(argv[0], "deactivate", 10) == 0) {
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
//		cx_fw_deactivate(intf, slot);
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
			flags = strtol(argv[2], (char **)NULL, 16);
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
		printf("Check *this*!\n");
		rv = 0;
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

	return rc;
}
