/*
 * Copyright (C) 2009 kamailio.org
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*!
 * \file
 * \brief Kamailio topoh :: Module interface
 * \ingroup topoh
 * Module: \ref topoh
 */

/*! \defgroup topoh Kamailio :: Topology hiding
 *
 * This module hides the SIP routing headers that show topology details.
 * It is not affected by the server being transaction stateless or
 * stateful. The script interpreter gets the SIP messages decoded, so all
 * existing functionality is preserved.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../core/sr_module.h"
#include "../../core/events.h"
#include "../../core/dprint.h"
#include "../../core/tcp_options.h"
#include "../../core/ut.h"
#include "../../core/forward.h"
#include "../../core/config.h"
#include "../../core/fmsg.h"
#include "../../core/onsend.h"
#include "../../core/kemi.h"
#include "../../core/parser/msg_parser.h"
#include "../../core/parser/parse_uri.h"
#include "../../core/parser/parse_to.h"
#include "../../core/parser/parse_from.h"

#include "../../modules/sanity/api.h"

#include "b2bua_mod.h"



MODULE_VERSION

str b2b_mask_key = str_init("123asd.c34");
str b2b_via_param_name = str_init("Role");
str b2b_callid_prefix = str_init("b2bua");
str b2b_default_socket       = STR_NULL;
int b2b_sanity_checks = 0;


/** module functions */
/* Module init function prototype */
static int mod_init(void);
/* Module child-init function prototype */
//static int child_init(int rank);
/* Module destroy function prototype */
//static void destroy(void);

static int w_b2bua_send(sip_msg_t *msg);
static int b2b_msg_received(sr_event_param_t *evp);

static param_export_t params[]={
	{"mask_key",		PARAM_STR, &b2b_mask_key},
	{"via_param_name",	PARAM_STR, &b2b_via_param_name},
	{"callid_prefix",	PARAM_STR, &b2b_callid_prefix},
	{"sanity_checks",	PARAM_INT, &b2b_sanity_checks},
	{"b2b_default_socket",	PARAM_STR, &b2b_default_socket},
	{0,0,0}
};

static cmd_export_t cmds[] = {
	{"b2bua_send",    (cmd_function)w_b2bua_send,
	0, 0,  0, REQUEST_ROUTE},
	{0, 0, 0, 0, 0}
};


/** module exports */
struct module_exports exports= {
	"b2bua",         /* module name */
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,            /* cmd (cfg function) exports */
	params,          /* param exports */
	0,               /* exported rpc functions */
	0,         /* exported pseudo-variables */
	0,               /* response handling function */
	mod_init,        /* module init function */
	0,               /* per-child init function */
	0                /* module destroy function */
};



/**
 * init module function
 */
static int mod_init(void)
{
	if(faked_msg_init()<0) {
		LM_ERR("failed to init fmsg\n");
		return -1;
	}

	sr_event_register_cb(SREV_NET_DATA_IN,  b2b_msg_received);

	return 0;
}

static int w_b2bua_send(sip_msg_t *msg)
{




	return 0;
}


static int b2b_msg_received(sr_event_param_t *evp)
{



return 0;
}
