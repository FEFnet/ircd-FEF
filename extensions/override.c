/*
 * oper-override for solanum.
 *
 * adds usermode +p and has a timer event that is iterated over to disable
 * usermode +p after a while...
 *
 * you need to have oper:override permission on the opers you want to be
 * able to use this extension.
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "privilege.h"
#include "s_newconf.h"

static const char override_desc[] =
	"Adds user mode +p, an operator-only user mode that grants privileges to override anything";

static void check_umode_change(void *data);
static void hack_channel_access(void *data);
static void hack_can_join(void *data);
static void hack_can_kick(void *data);
static void hack_can_send(void *data);
static void hack_can_invite(void *data);

mapi_hfn_list_av1 override_hfnlist[] = {
	{ "umode_changed", check_umode_change },
	{ "get_channel_access", hack_channel_access, HOOK_HIGHEST },
	{ "can_join", hack_can_join, HOOK_HIGHEST },
	{ "can_kick", hack_can_kick, HOOK_HIGHEST },
	{ "can_send", hack_can_send, HOOK_HIGHEST },
	{ "can_invite", hack_can_invite, HOOK_HIGHEST },
	{ NULL, NULL }
};

#define CHFL_OVERRIDE		0x0004
#define IsOperOverride(x)	(HasPrivilege((x), "oper:override"))

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	if (data->oldumodes & UMODE_OPER && !IsOper(source_p))
		source_p->umodes &= ~user_modes['p'];

	if (source_p->umodes & user_modes['p'])
	{
		if (!IsOperOverride(source_p))
		{
			sendto_one_notice(source_p, ":*** You need oper:override privilege for +p");
			source_p->umodes &= ~user_modes['p'];
			return;
		}
	}
}

static void
hack_channel_access(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *) vdata;

	if (data->dir == MODE_QUERY)
		return;

	if (data->approved == CHFL_CHANOP)
		return;

	if (data->client->umodes & user_modes['p'])
	{
		data->approved = CHFL_OVERRIDE;

		/* we only want to report modehacks, which are always non-NULL */
		if (data->modestr)
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is using oper-override on %s (modehacking: %s)",
					       get_oper_name(data->client), data->chptr->chname, data->modestr);
	}
}

static void
hack_can_join(void *vdata)
{
	hook_data_channel *data = (hook_data_channel *) vdata;

	if (data->approved == 0)
		return;

	if (data->client->umodes & user_modes['p'])
	{
		data->approved = 0;

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is using oper-override on %s (banwalking)",
				       get_oper_name(data->client), data->chptr->chname);
	}
}

static void
hack_can_kick(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *) vdata;
	int alevel;

	alevel = get_channel_access(data->client, data->chptr, data->msptr, data->dir, NULL);
	if (alevel != CHFL_OVERRIDE)
		return;

	if (data->client->umodes & user_modes['p'])
	{
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is using oper-override on %s (KICK %s)",
				       get_oper_name(data->client), data->chptr->chname, data->target->name);
	}
}

static void
hack_can_send(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *) vdata;

	if (data->dir == MODE_QUERY)
		return;

	if (data->approved == CAN_SEND_NONOP || data->approved == CAN_SEND_OPV)
		return;

	if (data->client->umodes & user_modes['p'])
	{
		data->approved = CAN_SEND_NONOP;

		if (MyClient(data->client))
		{
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is using oper-override on %s (forcing message)",
					       get_oper_name(data->client), data->chptr->chname);
		}
	}
}

static void
hack_can_invite(void *vdata)
{
	hook_data_channel_approval *data = vdata;

	if (data->approved == 0)
		return;

	if (data->client->umodes & user_modes['p'])
	{
		data->approved = 0;
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is using oper-override on %s (invite: %s)",
				       get_oper_name(data->client), data->chptr->chname, data->target->name);
	}
}

static int
_modinit(void)
{
	rb_dlink_node *ptr;

	/* add the usermode to the available slot */
	user_modes['p'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	rb_dlink_node *n, *tn;

	/* disable the umode and remove it from the available list */
	user_modes['p'] = 0;
	construct_umodebuf();
}

DECLARE_MODULE_AV2(override, _modinit, _moddeinit, NULL, NULL,
			override_hfnlist, NULL, NULL, override_desc);
