/* modules/m_xline.c
 *
 *  Copyright (C) 2002-2003 Lee Hardy <lee@leeh.co.uk>
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3.The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "stdinc.h"
#include "send.h"
#include "channel.h"
#include "client.h"
#include "defaults.h"
#include "class.h"
#include "ircd.h"
#include "numeric.h"
#include "logger.h"
#include "s_serv.h"
#include "whowas.h"
#include "match.h"
#include "hash.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "reject.h"
#include "bandbi.h"
#include "operhash.h"

static const char xline_desc[] =
	"Provides management of GECOS bans via (UN)XLINE command";

static void mo_xline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void ms_xline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void me_xline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void mo_unxline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc,
		      const char *parv[]);
static void ms_unxline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc,
		      const char *parv[]);
static void me_unxline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc,
		      const char *parv[]);

static bool valid_xline(struct Client *, const char *, const char *);
static void apply_xline(struct Client *client_p, const char *name,
			const char *reason, int temp_time, bool propagated);
static void propagate_xline(struct Client *source_p, const char *target,
			    int temp_time, const char *name, const char *type, const char *reason);
static void cluster_xline(struct Client *source_p, int temp_time,
			  const char *name, const char *reason);

static void handle_remote_xline(struct Client *source_p, int temp_time,
				const char *name, const char *reason);
static void handle_remote_unxline(struct Client *source_p, const char *name);
static void remove_xline(struct Client *source_p, const char *name,
			 bool propagated);

struct Message xline_msgtab = {
	"XLINE", 0, 0, 0, 0,
	{mg_unreg, mg_not_oper, {ms_xline, 5}, {ms_xline, 5}, {me_xline, 5}, {mo_xline, 3}}
};

struct Message unxline_msgtab = {
	"UNXLINE", 0, 0, 0, 0,
	{mg_unreg, mg_not_oper, {ms_unxline, 3}, {ms_unxline, 3}, {me_unxline, 2}, {mo_unxline, 2}}
};

mapi_clist_av1 xline_clist[] = { &xline_msgtab, &unxline_msgtab, NULL };

DECLARE_MODULE_AV2(xline, NULL, NULL, xline_clist, NULL, NULL, NULL, NULL, xline_desc);

/* m_xline()
 *
 * parv[1] - thing to xline
 * parv[2] - optional type/reason
 * parv[3] - reason
 */
static void
mo_xline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct ConfItem *aconf;
	const char *name;
	const char *reason;
	const char *target_server = NULL;
	int temp_time;
	int loc = 1;
	bool propagated = true;

	if(!IsOperXline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "xline");
		return;
	}

	if((temp_time = valid_temp_time(parv[loc])) >= 0)
		loc++;
	/* we just set temp_time to -1! */
	else
		temp_time = 0;

	name = parv[loc];
	loc++;

	/* XLINE <gecos> ON <server> :<reason> */
	if(parc >= loc + 2 && !irccmp(parv[loc], "ON"))
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				   me.name, source_p->name, "remoteban");
			return;
		}

		target_server = parv[loc + 1];
		loc += 2;
	}

	if(parc <= loc || EmptyString(parv[loc]))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   me.name, source_p->name, "XLINE");
		return;
	}

	reason = parv[loc];

	if(target_server != NULL)
	{
		if (temp_time)
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is adding a temporary %d min. X-Line for [%s] on %s [%s]",
					get_oper_name(source_p), temp_time / 60, name, target_server, reason);
		else
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is adding a permanent X-Line for [%s] on %s [%s]",
					get_oper_name(source_p), name, target_server, reason);

		propagate_xline(source_p, target_server, temp_time, name, "2", reason);

		if(!match(target_server, me.name))
			return;

		/* Set as local-only. */
		propagated = false;
	}
	else if(!propagated)
		cluster_xline(source_p, temp_time, name, reason);

	if((aconf = find_xline_mask(name)) != NULL)
	{
		sendto_one(source_p, ":%s NOTICE %s :[%s] already X-Lined by [%s] - %s",
			   me.name, source_p->name, name, aconf->host, aconf->passwd);
		return;
	}

	if(!valid_xline(source_p, name, reason))
		return;

	if(propagated && temp_time == 0)
	{
		sendto_one_notice(source_p, ":Cannot set a permanent global ban");
		return;
	}

	apply_xline(source_p, name, reason, temp_time, propagated);
}

/* ms_xline()
 *
 * handles a remote xline
 */
static void
ms_xline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* parv[0]  parv[1]      parv[2]  parv[3]  parv[4]
	 * oper     target serv  xline    type     reason
	 */
	propagate_xline(source_p, parv[1], 0, parv[2], parv[3], parv[4]);

	if(!IsPerson(source_p))
		return;

	/* destined for me? */
	if(!match(parv[1], me.name))
		return;

	handle_remote_xline(source_p, 0, parv[2], parv[4]);
}

static void
me_xline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* time name type :reason */
	if(!IsPerson(source_p))
		return;

	handle_remote_xline(source_p, atoi(parv[1]), parv[2], parv[4]);
}

static void
handle_remote_xline(struct Client *source_p, int temp_time, const char *name, const char *reason)
{
	struct ConfItem *aconf;

	if(!valid_xline(source_p, name, reason))
		return;

	/* already xlined */
	if((aconf = find_xline_mask(name)) != NULL)
	{
		sendto_one_notice(source_p, ":[%s] already X-Lined by [%s] - %s", name, aconf->host,
				  aconf->passwd);
		return;
	}

	apply_xline(source_p, name, reason, temp_time, false);
}

/* valid_xline()
 *
 * inputs	- client xlining, gecos, reason and whether to warn
 * outputs	-
 * side effects - checks the xline for validity, erroring if needed
 */
static bool
valid_xline(struct Client *source_p, const char *gecos, const char *reason)
{
	if(EmptyString(reason))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   get_id(&me, source_p), get_id(source_p, source_p), "XLINE");
		return false;
	}

	if(!valid_wild_card_simple(gecos))
	{
		sendto_one_notice(source_p,
				  ":Please include at least %d non-wildcard "
				  "characters with the xline",
				  ConfigFileEntry.min_nonwildcard_simple);
		return false;
	}

	return true;
}

void
apply_xline(struct Client *source_p, const char *name, const char *reason, int temp_time, bool propagated)
{
	struct ConfItem *aconf;

	aconf = make_conf();
	aconf->status = CONF_XLINE;
	aconf->created = rb_current_time();
	aconf->host = rb_strdup(name);
	aconf->passwd = rb_strdup(reason);
	collapse(aconf->host);

	aconf->info.oper = operhash_add(get_oper_name(source_p));

	if(propagated)
	{
		aconf->flags |= CONF_FLAGS_MYOPER | CONF_FLAGS_TEMPORARY;
		aconf->hold = rb_current_time() + temp_time;
		aconf->lifetime = aconf->hold;

		replace_old_ban(aconf);
		add_prop_ban(aconf);

		sendto_realops_snomask(SNO_GENERAL, L_ALL,
				       "%s added global %d min. X-Line for [%s] [%s]",
				       get_oper_name(source_p), temp_time / 60,
				       aconf->host, reason);
		ilog(L_KLINE, "X %s %d %s %s",
		     get_oper_name(source_p), temp_time / 60, name, reason);
		sendto_one_notice(source_p, ":Added global %d min. X-Line [%s]",
				  temp_time / 60, aconf->host);
		sendto_server(NULL, NULL, CAP_BAN|CAP_TS6, NOCAPS,
				":%s BAN X * %s %lu %d %d * :%s",
				source_p->id, aconf->host,
				(unsigned long)aconf->created,
				(int)(aconf->hold - aconf->created),
				(int)(aconf->lifetime - aconf->created),
				reason);
	}
	else if(temp_time > 0)
	{
		aconf->hold = rb_current_time() + temp_time;

		sendto_realops_snomask(SNO_GENERAL, L_ALL,
				       "%s added temporary %d min. X-Line for [%s] [%s]",
				       get_oper_name(source_p), temp_time / 60,
				       aconf->host, reason);
		ilog(L_KLINE, "X %s %d %s %s",
		     get_oper_name(source_p), temp_time / 60, name, reason);
		sendto_one_notice(source_p, ":Added temporary %d min. X-Line [%s]",
				  temp_time / 60, aconf->host);
	}
	else
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL, "%s added X-Line for [%s] [%s]",
				       get_oper_name(source_p), aconf->host, aconf->passwd);
		sendto_one_notice(source_p, ":Added X-Line for [%s] [%s]",
				  aconf->host, aconf->passwd);

		bandb_add(BANDB_XLINE, source_p, aconf->host, NULL, aconf->passwd, NULL, 0);
		ilog(L_KLINE, "X %s 0 %s %s", get_oper_name(source_p), name, aconf->passwd);
	}

	rb_dlinkAddAlloc(aconf, &xline_conf_list);
	check_xlines();
}

static void
propagate_xline(struct Client *source_p, const char *target,
		int temp_time, const char *name, const char *type, const char *reason)
{
	if(!temp_time)
	{
		sendto_match_servs(source_p, target, CAP_CLUSTER, NOCAPS,
				   "XLINE %s %s %s :%s", target, name, type, reason);
		sendto_match_servs(source_p, target, CAP_ENCAP, CAP_CLUSTER,
				   "ENCAP %s XLINE %d %s 2 :%s", target, temp_time, name, reason);
	}
	else
		sendto_match_servs(source_p, target, CAP_ENCAP, NOCAPS,
				   "ENCAP %s XLINE %d %s %s :%s",
				   target, temp_time, name, type, reason);
}

static void
cluster_xline(struct Client *source_p, int temp_time, const char *name, const char *reason)
{
	/* old protocol cant handle temps, and we dont really want
	 * to convert them to perm.. --fl
	 */
	if(!temp_time)
	{
		sendto_server(source_p, NULL, CAP_CLUSTER, NOCAPS,
				   "XLINE * %s 2 :%s", name, reason);
		sendto_server(source_p, NULL, CAP_ENCAP, CAP_CLUSTER,
				   "ENCAP * XLINE 0 %s 2 :%s",
				   name, reason);
	}
	else
		sendto_server(source_p, NULL, CAP_ENCAP, NOCAPS,
				   "ENCAP * XLINE %d %s 2 :%s",
				   temp_time, name, reason);
}

/* mo_unxline()
 *
 * parv[1] - thing to unxline
 */
static void
mo_unxline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	bool propagated = true;

	if(!IsOperXline(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "xline");
		return;
	}

	if(parc == 4 && !(irccmp(parv[2], "ON")))
	{
		if(!IsOperRemoteBan(source_p))
		{
			sendto_one(source_p, form_str(ERR_NOPRIVS),
				   me.name, source_p->name, "remoteban");
			return;
		}

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is removing the X-Line for [%s] on %s.",
				get_oper_name(source_p), parv[1], parv[3]);

		propagate_generic(source_p, "UNXLINE", parv[3], CAP_CLUSTER, "%s", parv[1]);

		if(match(parv[3], me.name) == 0)
			return;

		propagated = false;
	}

	remove_xline(source_p, parv[1], propagated);
}

/* ms_unxline()
 *
 * handles a remote unxline
 */
static void
ms_unxline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* parv[0]  parv[1]        parv[2]
	 * oper     target server  gecos
	 */
	propagate_generic(source_p, "UNXLINE", parv[1], CAP_CLUSTER, "%s", parv[2]);

	if(!match(parv[1], me.name))
		return;

	if(!IsPerson(source_p))
		return;

	handle_remote_unxline(source_p, parv[2]);
}

static void
me_unxline(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* name */
	if(!IsPerson(source_p))
		return;

	handle_remote_unxline(source_p, parv[1]);
}

static void
handle_remote_unxline(struct Client *source_p, const char *name)
{
	remove_xline(source_p, name, false);
}

static void
remove_xline(struct Client *source_p, const char *name, bool propagated)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;
	time_t now;

	RB_DLINK_FOREACH(ptr, xline_conf_list.head)
	{
		aconf = ptr->data;

		if(!irccmp(aconf->host, name))
		{
			if(aconf->lifetime)
			{
				if(!propagated)
				{
					sendto_one_notice(source_p, ":Cannot remove global X-Line %s on specific servers", name);
					return;
				}
				if (!lookup_prop_ban(aconf))
					return;
				sendto_one_notice(source_p, ":X-Line for [%s] is removed", name);
				sendto_realops_snomask(SNO_GENERAL, L_ALL,
						       "%s has removed the global X-Line for: [%s]",
						       get_oper_name(source_p), name);
				ilog(L_KLINE, "UX %s %s", get_oper_name(source_p), name);
				now = rb_current_time();
				if(aconf->created < now)
					aconf->created = now;
				else
					aconf->created++;
				aconf->hold = aconf->created;
				operhash_delete(aconf->info.oper);
				aconf->info.oper = operhash_add(get_oper_name(source_p));
				aconf->flags |= CONF_FLAGS_MYOPER | CONF_FLAGS_TEMPORARY;
				sendto_server(NULL, NULL, CAP_BAN|CAP_TS6, NOCAPS,
						":%s BAN X * %s %lu %d %d * :*",
						source_p->id, aconf->host,
						(unsigned long)aconf->created,
						0,
						(int)(aconf->lifetime - aconf->created));
				remove_reject_mask(aconf->host, NULL);
				deactivate_conf(aconf, now);
				return;
			}
			else if(propagated)
				cluster_generic(source_p, "UNXLINE", SHARED_UNXLINE, CAP_CLUSTER, "%s", name);
			if(!aconf->hold)
			{
				bandb_del(BANDB_XLINE, aconf->host, NULL);

				sendto_one_notice(source_p, ":X-Line for [%s] is removed", aconf->host);
				sendto_realops_snomask(SNO_GENERAL, L_ALL,
						       "%s has removed the X-Line for: [%s]",
						       get_oper_name(source_p), aconf->host);
				ilog(L_KLINE, "UX %s %s", get_oper_name(source_p), aconf->host);
			}
			else
			{
				sendto_one_notice(source_p, ":X-Line for [%s] is removed", name);
				sendto_realops_snomask(SNO_GENERAL, L_ALL,
						       "%s has removed the temporary X-Line for: [%s]",
						       get_oper_name(source_p), name);
				ilog(L_KLINE, "UX %s %s", get_oper_name(source_p), name);
			}

			remove_reject_mask(aconf->host, NULL);
			free_conf(aconf);
			rb_dlinkDestroy(ptr, &xline_conf_list);
			return;
		}
	}

	if(propagated)
		cluster_generic(source_p, "UNXLINE", SHARED_UNXLINE, CAP_CLUSTER, "%s", name);

	sendto_one_notice(source_p, ":No X-Line for %s", name);
}
