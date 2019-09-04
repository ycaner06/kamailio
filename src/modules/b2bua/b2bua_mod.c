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
#include "../../lib/ims/useful_defs.h"
#include "../../modules/tm/tm_load.h"
#include "../rr/api.h"
#include "b2bua_mod.h"



MODULE_VERSION

str b2b_mask_key = str_init("123asd.c34");
str b2b_via_param_name = str_init("Role");
str b2b_via_param_val = str_init("1");
str b2b_callid_prefix = str_init("b2bua");
str b2b_default_socket       = STR_NULL;
int b2b_sanity_checks = 0;
str b2b_contact_uri = str_init("Contact : <sip:b2b@192.168.1.39:5060>\r\n");
str b2b_max_fwds_hdr = str_init("Max-Forwards: 10\r\n");


struct tm_binds t_binds;

/** module functions */
/* Module init function prototype */
static int mod_init(void);
/* Module child-init function prototype */
//static int child_init(int rank);
/* Module destroy function prototype */
//static void destroy(void);

static int w_b2bua_send(sip_msg_t *msg);
static int b2b_msg_received(sr_event_param_t *evp);
void b2b_response_cb(struct cell* t, int type, struct tmcb_params* ps);


static param_export_t params[]={
	{"mask_key",		PARAM_STR, &b2b_mask_key},
	{"via_param_name",	PARAM_STR, &b2b_via_param_name},
	{"callid_prefix",	PARAM_STR, &b2b_callid_prefix},
	{"sanity_checks",	PARAM_INT, &b2b_sanity_checks},
	{"b2b_default_socket",	PARAM_STR, &b2b_default_socket},
	{"b2b_contact_uri",	PARAM_STR, &b2b_contact_uri},
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
		/* load the TM API */
	if (load_tm_api(&t_binds)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	sr_event_register_cb(SREV_NET_DATA_IN,  b2b_msg_received);

	return 0;
}

static int w_b2bua_send(sip_msg_t *msg)
{
	uac_req_t uac_req;
	str headers = {0, 0};
	str method = str_init("INVITE");
	str to_header = str_init("sip:deneme@192.168.1.39");
	str from_header = str_init("sip:yc@192.168.1.39");
	str next_hop = str_init("sip:192.168.1.39:5061");
	str ruri = str_init("sip:123@192.168.1.39:5061");

	LM_ERR("Giriş ok\r\n");
	if (parse_msg(msg->buf, msg->len, msg)!=0)
	{
		LM_DBG("outbuf buffer parsing failed!");
		return 1;
	}

	if(msg->first_line.type==SIP_REQUEST)
	{
		if(!IS_SIP(msg))
		{
			LM_DBG("non sip request message\n");
			return 1;
		}
	} else if(msg->first_line.type!=SIP_REPLY) {
		LM_DBG("non sip message\n");
		return 1;
	}
	if (parse_headers(msg, HDR_EOH_F, 0)==-1)
	{
		LM_DBG("parsing headers failed [[%.*s]]\n",
				msg->len, msg->buf);
		return 2;
	}

		/* force 2nd via parsing here - it helps checking it later */
	if (parse_headers(msg, HDR_VIA2_F, 0)==-1
		|| (msg->via2==0) || (msg->via2->error!=PARSE_OK))
	{
		LM_DBG("no second via in this message \n");
	}
		if(parse_from_header(msg)<0)
	{
		LM_ERR("cannot parse FROM header\n");
		return 3;
	}

	if(parse_to_header(msg)<0 || msg->to==NULL)
	{
		LM_ERR("cannot parse TO header\n");
		return 3;
	}

	if(get_to(msg)==NULL)
	{
		LM_ERR("cannot get TO header\n");
		return 3;
	}

	if(msg->via1==NULL || msg->callid==NULL) {
		LM_ERR("mandatory headers missing - via1: %p callid: %p\n",
				msg->via1, msg->callid);
		return 4;
	}

	LM_ERR("Kontroller ok \r\n");

  if(msg->first_line.type==SIP_REQUEST) {
			headers.len=b2b_contact_uri.len;

			headers.s = pkg_malloc(headers.len);
			 if (!headers.s) {
				 LM_ERR("Error allocating %d bytes\n", headers.len);
				 headers.len = 0;
				 return -1;
			 }

			 memset(headers.s,0,headers.len);
			 headers.len=0;

			 STR_APPEND(headers,b2b_contact_uri);
		//	STR_APPEND(headers,b2b_max_fwds_hdr);

			set_uac_req(&uac_req, &method, &headers, NULL, 0,
	    TMCB_RESPONSE_IN | TMCB_ON_FAILURE | TMCB_LOCAL_COMPLETED,
	    b2b_response_cb, &msg->first_line.u.request.uri);
			LM_ERR("uac_req ok URI [%.*s] \r\n",msg->first_line.u.request.uri.len,msg->first_line.u.request.uri.s);
			t_binds.t_request(&uac_req,&ruri,&to_header,&from_header,0);
			LM_ERR("t_request ok \r\n");


	}

	pkg_free(headers.s);


	return 1;
}

void b2b_response_cb(struct cell* t, int type, struct tmcb_params* ps){

	LM_ERR("b2b response cb \r\n");



}

static int b2b_msg_received(sr_event_param_t *evp)
{

	LM_ERR("CEVAPLAR \r\n");

return 1;
}
