/*
 * convert from binary form of SA ID to text
 * Copyright (C) 2000, 2001  Henry Spencer.
 * Copyright (C) 2012 David McCullough <david_mccullough@mcafee.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#include <string.h>
#include <stdio.h>

#include "ip_said.h"
#include "ip_info.h"
#include "jambuf.h"
#include "libreswan/passert.h"

/*
   - satot - convert SA to text "ah507@1.2.3.4"
 */
size_t                          /* space needed for full conversion */
satot(sa, format, dst, dstlen)
const ip_said * sa;
int format;                     /* character */
char *dst;                      /* need not be valid if dstlen is 0 */
size_t dstlen;
{
	size_t len = 0;         /* 0 means "not recognized yet" */
	int base;
	int showversion;        /* use delimiter to show IP version? */
	char *p;
	char buf[10 + 1 + ULTOT_BUF + ADDRTOT_BUF];

	switch (format) {
	case 0:
		base = 16;
		showversion = 1;
		break;
	case 'f':
		base = 17;
		showversion = 1;
		break;
	case 'x':
		base = 'x';
		showversion = 0;
		break;
	case 'd':
		base = 10;
		showversion = 0;
		break;
	default:
		if (dstlen > 0) {
			strncpy(dst, "(error)", dstlen-1);
			dst[dstlen-1] = '\0';
		}
		return 0;

		break;
	}

	memset(buf, 0, sizeof(buf));

	/* const ip_protocol *proto = sa->proto; */
	const struct ip_protocol *proto = sa->proto;
	const char *pre = (proto == NULL ? "unk" : proto->prefix);

	if (strcmp(pre, PASSTHROUGHTYPE) == 0 &&
	    sa->spi == PASSTHROUGHSPI &&
	    isanyaddr(&sa->dst)) {
		strcpy(buf, (said_type(sa) == &ipv4_info) ?
		       PASSTHROUGH4NAME :
		       PASSTHROUGH6NAME);
		len = strlen(buf);
	}

	if (sa->proto == SA_INT) {
		char intunk[10];

		switch (ntohl(sa->spi)) {
		case SPI_PASS:
			p = "%pass";
			break;
		case SPI_DROP:
			p = "%drop";
			break;
		case SPI_REJECT:
			p = "%reject";
			break;
		case SPI_HOLD:
			p = "%hold";
			break;
		case SPI_TRAP:
			p = "%trap";
			break;
		case SPI_TRAPSUBNET:
			p = "%trapsubnet";
			break;
		default:
			snprintf(intunk, sizeof(intunk), "%%unk-%d",
				 ntohl(sa->spi));
			p = intunk;
			break;
		}
		if (p != NULL) {
			strcpy(buf, p);
			len = strlen(buf);
		}
	}

	if (len == 0) {                 /* general case needed */
		strcpy(buf, pre);
		len = strlen(buf);
		if (showversion) {
			*(buf +
			  len) = (said_type(sa) == &ipv4_info) ?
				'.' : ':';
			len++;
			*(buf + len) = '\0';
		}
		len += ultot(ntohl(sa->spi), base, buf + len, sizeof(buf) - len);
		*(buf + len - 1) = '@';
		/* jambuf's are always '\0' terminated */
		jambuf_t b = array_as_jambuf(buf + len, sizeof(buf) - len);
		jam_address(&b, &sa->dst);
		/* "pos" is always '\0' */
		const char *end = jambuf_cursor(&b);
		passert(*end == '\0');
		/* *tot() functions lengh includes the NULL */
		len = end-buf+1;
	}

	if (dst != NULL) {
		if (len > dstlen)
			*(buf + dstlen - 1) = '\0';
		strcpy(dst, buf);
	}
	return len;
}
