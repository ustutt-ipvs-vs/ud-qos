/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * m_ud_qos.c	UD-QoS.
 *
 * based on: m_simple.c
 *
 * Authors:	Jona Herrmann
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "utils.h"
#include "tc_util.h"
#include <linux/tc_act/tc_defact.h>

#ifndef SIMP_MAX_DATA
#define SIMP_MAX_DATA   32
#endif
static void explain(void)
{
	fprintf(stderr,
		"Usage:... ud_qos sdata STRING\n");
}

static void usage(void)
{
	explain();
	exit(-1);
}

static int
parse_ud_qos(struct action_util *a, int *argc_p, char ***argv_p, int tca_id,
	     struct nlmsghdr *n)
{
	struct tc_defact sel = {};
	int argc = *argc_p;
	char **argv = *argv_p;
	int ok = 1;
	struct rtattr *tail;
	char *simpdata = NULL;

	while (argc > 0) {
		if (matches(*argv, "ud_qos") == 0) {
			NEXT_ARG();
		} else if (matches(*argv, "sdata") == 0) {
			NEXT_ARG();
			ok += 1;
			simpdata = *argv;
			argc--;
			argv++;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}
	}

	parse_action_control_dflt(&argc, &argv, &sel.action, false,
				  TC_ACT_PIPE);

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&sel.index, *argv, 10)) {
				fprintf(stderr, "simple: Illegal \"index\" (%s)\n",
					*argv);
				return -1;
			}
			ok += 1;
			argc--;
			argv++;
		}
	}

	if (!ok) {
		explain();
		return -1;
	}

	if (simpdata && (strlen(simpdata) > (SIMP_MAX_DATA - 1))) {
		fprintf(stderr, "simple: Illegal string len %zu <%s>\n",
			strlen(simpdata), simpdata);
		return -1;
	} 
	
	tail = addattr_nest(n, MAX_MSG, tca_id);
	addattr_l(n, MAX_MSG, TCA_DEF_PARMS, &sel, sizeof(sel));
	if (simpdata)
		addattr_l(n, MAX_MSG, TCA_DEF_DATA, simpdata, SIMP_MAX_DATA);
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int print_ud_qos(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct tc_defact *sel;
	struct rtattr *tb[TCA_DEF_MAX + 1];
	char *simpdata;

	if (arg == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_DEF_MAX, arg);

	if (tb[TCA_DEF_PARMS] == NULL) {
		fprintf(stderr, "Missing simple parameters\n");
		return -1;
	}
	sel = RTA_DATA(tb[TCA_DEF_PARMS]);

	if (tb[TCA_DEF_DATA] == NULL) {
		fprintf(stderr, "Missing simple string\n");
		return -1;
	}

	simpdata = RTA_DATA(tb[TCA_DEF_DATA]);

	fprintf(f, "Simple <%s>\n", simpdata);
	fprintf(f, "\t index %u ref %d bind %d", sel->index,
		sel->refcnt, sel->bindcnt);

	if (show_stats) {
		if (tb[TCA_DEF_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_DEF_TM]);

			print_tm(f, tm);
		}
	}
	print_nl();

	return 0;
}

struct action_util ud_qos_action_util = {
	.id = "ud_qos",
	.parse_aopt = parse_ud_qos,
	.print_aopt = print_ud_qos,
};
