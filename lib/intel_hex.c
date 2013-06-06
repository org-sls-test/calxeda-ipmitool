/*
 * Copyright 2013 Calxeda, Inc.  All Rights Reserved.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "intel_hex.h"


static int
ihex_line(char *line, uint8_t *image, int *addr_min, int *addr_max)
{
	int i;
	int sum;
	int len;
	int addr;
	int type;
	int cksum;
	char *ptr;

	if (line[0] != ':')
		return -1;

	if (strlen(line) < 11)
		return -1;
	ptr = line + 1;

	if (!sscanf(ptr, "%02x", &len))
		return -1;
	ptr += 2;
	sum = len & 0xff;

	if (strlen(line) < 11 + len * 2)
		return -1;

	if (!sscanf(ptr, "%04x", &addr))
		return -1;
	ptr += 4;
	sum += ((addr >> 8) & 0xff) + (addr & 0xff);

	if (addr < *addr_min)
		*addr_min = addr;

	if (addr > *addr_max)
		*addr_max = addr;

	if (!sscanf(ptr, "%02x", &type))
		return -1;
	ptr += 2;
	sum += type & 0xff;

	/*
	 * EOF record?
	 */
	if (type == 1) {
		return 1;
	}

	/*
	 * Data Record?
	 */
	if (type == 0) {
		int byte;

		for (i = 0; i < len; i++) {
			if (!sscanf(ptr, "%02x", &byte))
				return 0;
			ptr += 2;
			sum += byte & 0xff;
			image[addr++] = byte;
		}
	}

	if (addr - 1 > *addr_max)
		*addr_max = addr - 1;

	if (!sscanf(ptr, "%02x", &cksum))
		return -1;

	if (((sum + cksum) & 0xff) != 0)
		return -2;

	/*
	 * All is well; keep going.
	 */
	return 0;
}


#define MAX_LINE	200

int ihex_read_file(char *filename,
		   uint8_t *image,
		   int *addr_min,
		   int *addr_max)
{
	FILE *f;
	char line[MAX_LINE];
	int ret;

	f = fopen(filename, "r");
	if (f == NULL) {
		printf("Can't read file '%s'\n", filename);
		return -1;
	}

	while (!feof(f)) {
		line[0] = 0;
		fgets(line, MAX_LINE, f);
		ret = ihex_line(line, image, addr_min, addr_max);
		if (ret != 0) {
			break;
		}
	}

	fclose(f);

	if (ret < 0)
		return ret;

	return 0;
}
