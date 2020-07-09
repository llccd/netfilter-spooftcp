#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>

#include "xt_SPOOFTCP.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*a))
#endif

enum {
	O_TTL,
	O_TCP_FLAGS,
	O_CORRUPT_CHKSUM,
	O_CORRUPT_SEQ,
	O_CORRUPT_ACK,
	O_DELAY,
	O_PAYLOAD_LEN,
	O_REPEAT,
	O_MD5_OPT,
	O_TS_OPT,
	O_MASQ,
};

/* Copied from libxt_tcp.c */
struct tcp_flag_names {
	const char *name;
	__u8 flag;
};

static const struct tcp_flag_names tcp_flag_names[]
= { { "FIN", 0x01 },
    { "SYN", 0x02 },
    { "RST", 0x04 },
    { "PSH", 0x08 },
    { "ACK", 0x10 },
    { "URG", 0x20 },
    { "ECE", 0x40 },
    { "CWR", 0x80 },
    { "ALL", 0xFF },
    { "NONE", 0 },
};

static __u8 parse_tcp_flag(const char *flags)
{
	__u8 ret = 0;
	char *ptr;
	char *buffer;

	buffer = strdup(flags);

	for (ptr = strtok(buffer, ","); ptr; ptr = strtok(NULL, ",")) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(tcp_flag_names); ++i)
			if (strcasecmp(tcp_flag_names[i].name, ptr) == 0) {
				ret |= tcp_flag_names[i].flag;
				break;
			}
		if (i == ARRAY_SIZE(tcp_flag_names))
			xtables_error(PARAMETER_PROBLEM,
				   "Unknown TCP flag `%s'", ptr);
	}

	free(buffer);
	return ret;
}

static void print_tcpf(__u8 flags)
{
	int have_flag = 0;

	while (flags) {
		unsigned int i;

		for (i = 0; (flags & tcp_flag_names[i].flag) == 0; i++);

		if (have_flag)
			printf(",");
		printf("%s", tcp_flag_names[i].name);
		have_flag = 1;

		flags &= ~tcp_flag_names[i].flag;
	}

	if (!have_flag)
		printf("NONE");
}

static void SPOOFTCP_help()
{
	puts("SPOOFTCP target options:\n"
		" --ttl value\tThe hop limit/ttl value of spoofed packet (0 for inherit)\n"
		" --tcp-flags\tTCP FLAGS of spoofed packet\n"
		" --corrupt-checksum\tInvert checksum for spoofed packet\n"
		" --corrupt-seq\tInvert TCP SEQ # for spoofed packet\n"
		" --corrupt-ack\tInvert TCP ACK # for spoofed packet\n"
		" --delay value\tDelay the matched(original) packet by <value> us (max 65535)\n"
		" --payload-length value\tLength of TCP payload (max 255)\n"
		" --repeat value\tRepeat sending spoofed packet <value> times (max 255)\n"
		" --md5\tAdd TCP MD5 (Option 19) header\n"
		" --ts\tAdd TCP Timestamp (Option 8) header\n"
		" --masq\tEnable MASQUERADE workaround\n");
}

static const struct xt_option_entry SPOOFTCP_opts[] = {
	{
		.name	= "ttl",
		.id	= O_TTL,
		.type	= XTTYPE_UINT8,
		.min	= 0,
		.max	= UINT8_MAX,
		.flags	= XTOPT_PUT, XTOPT_POINTER(struct xt_spooftcp_info, ttl),
	},
	{
		.name	= "tcp-flags",
		.id	= O_TCP_FLAGS,
		.type	= XTTYPE_STRING,
	},
	{
		.name	= "corrupt-checksum",
		.id	= O_CORRUPT_CHKSUM,
		.type	= XTTYPE_NONE,
	},
	{
		.name	= "corrupt-seq",
		.id	= O_CORRUPT_SEQ,
		.type	= XTTYPE_NONE,
	},
	{
		.name	= "corrupt-ack",
		.id	= O_CORRUPT_ACK,
		.type	= XTTYPE_NONE,
	},
	{
		.name	= "delay",
		.id	= O_DELAY,
		.type	= XTTYPE_UINT16,
		.min	= 0,
		.max	= UINT16_MAX,
		.flags	= XTOPT_PUT, XTOPT_POINTER(struct xt_spooftcp_info, delay),
	},
	{
		.name	= "payload-length",
		.id	= O_PAYLOAD_LEN,
		.type	= XTTYPE_UINT8,
		.min	= 0,
		.max	= UINT8_MAX,
		.flags	= XTOPT_PUT, XTOPT_POINTER(struct xt_spooftcp_info, payload_len),
	},
	{
		.name	= "repeat",
		.id	= O_REPEAT,
		.type	= XTTYPE_UINT8,
		.min	= 0,
		.max	= UINT8_MAX,
		.flags	= XTOPT_PUT, XTOPT_POINTER(struct xt_spooftcp_info, repeat),
	},
	{
		.name	= "md5",
		.id	= O_MD5_OPT,
		.type	= XTTYPE_NONE,
	},
	{
		.name	= "ts",
		.id	= O_TS_OPT,
		.type	= XTTYPE_NONE,
	},
	{
		.name	= "masq",
		.id	= O_MASQ,
		.type	= XTTYPE_NONE,
	},
	XTOPT_TABLEEND,
};

static void SPOOFTCP_parse(struct xt_option_call *cb)
{
	struct xt_spooftcp_info *info = cb->data;
	const struct xt_option_entry *entry = cb->entry;

	xtables_option_parse(cb);

	switch(entry->id)
	{
		case O_TTL:
		case O_DELAY:
		case O_PAYLOAD_LEN:
		case O_REPEAT:
			break; // Do nothing
		case O_TCP_FLAGS:
			info->tcp_flags = parse_tcp_flag(cb->arg);
			break;
		case O_CORRUPT_CHKSUM:
			info->corrupt_chksum = true;
			break;
		case O_CORRUPT_SEQ:
			info->corrupt_seq = true;
			break;
		case O_CORRUPT_ACK:
			info->corrupt_ack = true;
			break;
		case O_MD5_OPT:
			info->md5 = true;
			break;
		case O_TS_OPT:
			info->ts = true;
			break;
		case O_MASQ:
			info->masq = true;
			break;
	}
}

static void SPOOFTCP_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & (1 << O_TCP_FLAGS)))
		xtables_error(PARAMETER_PROBLEM,
		           "SPOOFTCP target: --tcp-flags is required");
}

static void SPOOFTCP_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
	const struct xt_spooftcp_info *info =
		(const struct xt_spooftcp_info *)target->data;
	if (info->ttl)
		printf(" SPOOFTCP ttl = %u", info->ttl);
	else
		printf(" SPOOFTCP ttl inherit");

	printf(" tcp flags ");
	if (numeric)
		printf("0x%02X", info->tcp_flags);
	else
		print_tcpf(info->tcp_flags);

	if (info->corrupt_chksum)
		printf(" Corrupt checksum");

	if (info->corrupt_seq)
		printf(" Corrupt SEQ");

	if (info->corrupt_ack)
		printf(" Corrupt ACK");

	if (info->delay)
		printf(" Delay by %uus", info->delay);

	if (info->payload_len)
		printf(" Payload length %u", info->payload_len);

	if (info->repeat)
		printf(" Repeat %u times", info->repeat);

	if (info->md5)
		printf(" with MD5 option");

	if (info->ts)
		printf(" with Timestamp option");

	if (info->masq)
		printf(" with MASQUERADE workaround");
}

static void SPOOFTCP_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_spooftcp_info *info =
		(const struct xt_spooftcp_info *)target->data;

	if (info->ttl)
		printf(" --%s %u", SPOOFTCP_opts[O_TTL].name, info->ttl);

	printf(" --%s ", SPOOFTCP_opts[O_TCP_FLAGS].name);
	print_tcpf(info->tcp_flags);

	if (info->corrupt_chksum)
		printf(" --%s", SPOOFTCP_opts[O_CORRUPT_CHKSUM].name);

	if (info->corrupt_seq)
		printf(" --%s", SPOOFTCP_opts[O_CORRUPT_SEQ].name);

	if (info->corrupt_ack)
		printf(" --%s", SPOOFTCP_opts[O_CORRUPT_ACK].name);

	if (info->delay)
		printf(" --%s %u", SPOOFTCP_opts[O_DELAY].name, info->delay);

	if (info->payload_len)
		printf(" --%s %u", SPOOFTCP_opts[O_PAYLOAD_LEN].name, info->payload_len);

	if (info->repeat)
		printf(" --%s %u", SPOOFTCP_opts[O_REPEAT].name, info->repeat);

	if (info->md5)
		printf(" --%s", SPOOFTCP_opts[O_MD5_OPT].name);

	if (info->ts)
		printf(" --%s", SPOOFTCP_opts[O_TS_OPT].name);

	if (info->masq)
		printf(" --%s", SPOOFTCP_opts[O_MASQ].name);
}

static struct xtables_target spooftcp_tg_reg = {
	.family		= NFPROTO_UNSPEC,
	.name		= "SPOOFTCP",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_spooftcp_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_spooftcp_info)),
	.help		= SPOOFTCP_help,
	.print		= SPOOFTCP_print,
	.save		= SPOOFTCP_save,
	.x6_parse	= SPOOFTCP_parse,
	.x6_fcheck	= SPOOFTCP_check,
	.x6_options	= SPOOFTCP_opts,
};

void _init(void)
{
	xtables_register_target(&spooftcp_tg_reg);
}
