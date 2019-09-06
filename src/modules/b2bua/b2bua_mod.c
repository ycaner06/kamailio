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
#include "../../core/data_lump.h"

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
struct depo *get_root(void);
int recollect_via(sip_msg_t *msg, str *via_body);
int b2b_sip_rw(char *s, int len);
int b2b_prepare_msg(sip_msg_t *msg);
char* b2b_msg_update(sip_msg_t *msg, unsigned int *olen);

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

typedef struct depo {
	str callid;
	str fromtag;
	str via0;

	struct depo *next;
} depo_t;

/**
 * init module function
 */
#ifndef WITH_DEPOCUK
#define WITH_DEPOCUK

depo_t *depocuk=NULL;
#endif


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
	struct to_body *from_b;
	str headers = {0, 0};
	str method = str_init("INVITE");
	str to_header = str_init("sip:deneme@192.168.1.39");
	str from_header = str_init("sip:yc@192.168.1.39");
	//str next_hop = str_init("sip:192.168.1.39:5062");
	str ruri = str_init("sip:123@192.168.1.39:5062");
	struct depo *mydepo;


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

	if(msg->callid){
		LM_ERR("CALLID %.*s \r\n",msg->callid->body.len,msg->callid->body.s);
	}


	if(msg->from->parsed){
		from_b = msg->from->parsed;

		LM_ERR("FROM TAG %.*s \r\n",from_b->tag_value.len,from_b->tag_value.s);
	}

	mydepo = (struct depo *)shm_malloc(sizeof(struct depo));

	if(mydepo == 0) {
		SHM_MEM_ERROR;
		shm_free(mydepo);
		return -1;
	}

	memset(mydepo,'0',sizeof(depo_t));

	LM_ERR("11111 VIA [%.*s]\r\n",msg->h_via1->body.len,msg->h_via1->body.s);

	mydepo->callid.s =(char *)shm_malloc(msg->callid->body.len);
	mydepo->fromtag.s =(char *)shm_malloc(from_b->tag_value.len);
	mydepo->via0.s =(char *)shm_malloc(msg->h_via1->body.len);
	/*mydepo->callid.s =msg->callid->body.s;
	mydepo->callid.len =msg->callid->body.len;
*/
if(mydepo->callid.s){
	LM_ERR("XXXXX1X %p \r\n",mydepo->callid.s);
	LM_ERR("XXXXX2X %p \r\n",msg->callid->body.s);
	LM_ERR("XXXXX1X %p \r\n",mydepo->fromtag.s);

}

	memcpy(mydepo->callid.s,msg->callid->body.s,msg->callid->body.len);
	LM_ERR("222222 \r\n");
	//mydepo->fromtag.s =from_b->tag_value.s;
//	mydepo->fromtag.len =from_b->tag_value.len;
	memcpy(mydepo->fromtag.s,from_b->tag_value.s,from_b->tag_value.len);
	LM_ERR("33333 \r\n");


	memcpy(mydepo->via0.s,msg->h_via1->body.s,msg->h_via1->body.len);
	mydepo->via0.len = msg->h_via1->body.len;
	mydepo->fromtag.len=from_b->tag_value.len;
	mydepo->callid.len = msg->callid->body.len;
	mydepo->next = depocuk;

	LM_ERR("444444 \r\n");

	depocuk = mydepo;

	LM_ERR("55555 %p \r\n",mydepo);
	LM_ERR("66666 %p \r\n",depocuk);


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
/*
	struct depo *dep = get_root();
	LM_ERR("b2b response cb \r\n");
	LM_ERR("11111 %p\r\n",dep);
	if(dep){
		LM_ERR("22222 %p\r\n",dep);
		if(dep->callid.len>0 && dep->callid.s){
			LM_ERR("333333 %p \r\n",dep->callid.s);

			LM_ERR("Depocuk %.*s\r\n",dep->callid.len,dep->callid.s);}
		}
*/

}

struct depo *get_root(void){

	return depocuk;
}

static int b2b_msg_received(sr_event_param_t *evp)
{
	sip_msg_t msg;
	str *obuf;
  char *nbuf = NULL;
	struct ip_addr hope;
	struct depo *dep = depocuk;
	str hopestr = str_init("192.168.1.39");


	if(str2ipbuf(&hopestr,&hope)<0){
				LM_ERR("Couldn't get sdp c line IP address\n");
				return -1;
	}

	if(!ip_addr_cmp(&evp->rcv->src_ip,&hope)){
		return -1;
	}

	LM_ERR("11111 %p\r\n",dep);


	obuf = (str*)evp->data;
	memset(&msg, 0, sizeof(sip_msg_t));
	msg.buf = obuf->s;
	msg.len = obuf->len;


	LM_ERR("MSG  [%.*s]   \r\n",msg.len,msg.buf);
	if(b2b_prepare_msg(&msg)!=0){
			LM_ERR("b2b_prepare_msg ERROR   \r\n");
			return -1;
	}

	if(dep){
		LM_ERR("22222 %p\r\n",dep);
		if(dep->callid.len>0 && dep->callid.s){
			LM_ERR("333333 %p \r\n",dep->callid.s);

			LM_ERR("Depocuk [%.*s][%d]\r\n",dep->callid.len,dep->callid.s,dep->callid.len);
			LM_ERR("VIA [%.*s][%d]\r\n",dep->via0.len,dep->via0.s,dep->via0.len);
			}
		}
		if(msg.first_line.type==SIP_REQUEST)
		{
				return 0;

		}else{ //reply

			int sonuc = recollect_via(&msg,&dep->via0);
			LM_ERR("Recollect_via sonuc[%d] \r\n",sonuc);

			LM_INFO("msg after collect via [%.*s] \r\n",msg.len,msg.buf);

			nbuf = b2b_msg_update(&msg, (unsigned int*)&obuf->len);
			if(nbuf){
				LM_ERR("NBUF [%s]\r\n",nbuf);
			}

			if(obuf->len>=BUF_SIZE)
			{
				LM_ERR("new buffer overflow (%d)\n", obuf->len);
				return -1;
			}
			memcpy(obuf->s, nbuf, obuf->len);
			obuf->s[obuf->len] = '\0';

		}
return 1;
}


char* b2b_msg_update(sip_msg_t *msg, unsigned int *olen)
{
	struct dest_info dst;

	init_dest_info(&dst);
	dst.proto = PROTO_UDP;
	return build_req_buf_from_sip_req(msg,
			olen, &dst, BUILD_NO_LOCAL_VIA|BUILD_NO_VIA1_UPDATE);
}



int recollect_via(sip_msg_t *msg, str *via_body)
{
	hdr_field_t *hdr;
	struct via_body *via;
	struct lump* l;
	int i;
	str out;
	int vlen;

	i=0;
	for(hdr=msg->h_via1; hdr; hdr=next_sibling_hdr(hdr))
	{
		for(via=(struct via_body*)hdr->parsed; via; via=via->next)
		{
				i++;
				vlen = b2b_sip_rw(via->name.s, via->bsize);
				LM_ERR("LUMPING [%d]\n", vlen);

				l=del_lump(msg, via->name.s-msg->buf, vlen, 0);
				if (l==0)
				{
					LM_ERR("failed deleting via [%d]\n", i);
					return -1;
				}
				if (insert_new_lump_after(l, via_body->s, via_body->len, 0)==0)
				{
					LM_ERR("could not insert new lump\n");
					return -1;
				}
			}
	}

	return 0;
}

int b2b_sip_rw(char *s, int len)
{
	while(len>0)
	{
		if(s[len-1]==' ' || s[len-1]=='\t' || s[len-1]=='\n' || s[len-1]=='\r'
				|| s[len-1]==',')
			len--;
		else return len;
	}
	return 0;
}



/**
 *
 */

int b2b_prepare_msg(sip_msg_t *msg)
{
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
		LM_ERR("parsing headers failed [[%.*s]]\n",
				msg->len, msg->buf);
		return 2;
	}

	/* force 2nd via parsing here - it helps checking it later */
	if (parse_headers(msg, HDR_VIA2_F, 0)==-1
		|| (msg->via2==0) || (msg->via2->error!=PARSE_OK))
	{
		LM_INFO("no second via in this message \n");
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

	return 0;
}
