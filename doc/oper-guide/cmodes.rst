Channel modes
=============

Channel modes are determined by the various plugins loaded by the
server. The following consists only of a base list of common modes:
your server may have more plugins available, which you can see with
the following server command, depending on your IRC client::

  /QUOTE HELP CMODE

or::

  /RAW HELP CMODE

``+b``, channel ban
-------------------

Bans take one parameter which can take several forms. The most common
form is ``+b nick!user@host``. The wildcards ``*`` and ``?`` are
allowed, matching zero-or-more, and exactly-one characters
respectively. The masks will be trimmed to fit the maximum allowable
length for the relevant element.  Bans are also checked against the IP
address, even if it resolved or is spoofed. CIDR is supported, like
``*!*@10.0.0.0/8``. This is most useful with IPv6. Bans are not
checked against the real hostname behind any kind of spoof, except if
host mangling is in use (e.g.  ``extensions/ip_cloaking_4.0.so``): if the
user's host is mangled, their real hostname is checked additionally,
and if a user has no spoof but could enable mangling, the mangled form
of their hostname is checked additionally. Hence, it is not possible
to evade bans by toggling host mangling.

The second form (extban) is ``+b $type`` or ``+b $type:data``. type is
a single character (case insensitive) indicating the type of match,
optionally preceded by a tilde (``~``) to negate the comparison. data
depends on type.  Each type is loaded as a module. The available types
(if any) are listed in the ``EXTBAN`` token of the 005
(``RPL_ISUPPORT``) numeric. See ``doc/extban.txt`` in the source
distribution or ``HELP EXTBAN`` for more information.

If no parameter is given, the list of bans is returned. All users can
use this form. The plus sign should also be omitted.

Matching users will not be allowed to join the channel or knock on it.
If they are already on the channel, they may not send to it or change
their nick.

``+c``, colour filter
---------------------

This cmode activates the colour filter for the channel. This filters out
bold, underline, reverse video, beeps, mIRC colour codes, and ANSI
escapes. Note that escape sequences will usually leave cruft sent to the
channel, just without the escape characters themselves.

``+e``, ban exemption
---------------------

This mode takes one parameter of the same form as bans, which overrides
``+b`` and ``+q`` bans for all clients it matches.

This can be useful if it is necessary to ban an entire ISP due to
persistent abuse, but some users from that ISP should still be allowed
in. For example::

  /mode #channel +be *!*@*.example.com *!*someuser@host3.example.com

Only channel operators can see ``+e`` changes or request the list.

``+f``, channel forwarding
--------------------------

This mode takes one parameter, the name of a channel (``+f
#channel``). If the channel also has the ``+i`` cmode set, and
somebody attempts to join without either being expliticly invited, or
having an invex (``+I``), then they will instead join the channel
named in the mode parameter. The client will also be sent a 470
numeric giving the original and target channels.

Users are similarly forwarded if the ``+j`` cmode is set and their attempt
to join is throttled, if ``+l`` is set and there are already too many users
in the channel or if ``+r`` is set and they are not identified.

Forwards may only be set to ``+F`` channels, or to channels the setter has
ops in.

Without parameter (``/mode #channel f`` or ``/mode #channel +f``) the forward
channel is returned. This form also works off channel.

``+F``, allow anybody to forward to this
----------------------------------------

When this mode is set, anybody may set a forward from a channel they
have ops in to this channel. Otherwise they have to have ops in this
channel.

``+g``, allow anybody to invite
-------------------------------

When this mode is set, anybody may use the ``INVITE`` command on the channel
in question. When it is unset, only channel operators may use the ``INVITE``
command.

When this mode is set together with ``+i``, ``+j``, ``+l`` or ``+r``, all channel
members can influence who can join.

``+i``, invite only
-------------------

When this cmode is set, no client can join the channel unless they have
an invex (``+I``) or are invited with the ``INVITE`` command.

``+I``, invite exception (invex)
--------------------------------

This mode takes one parameter of the same form as bans. Matching clients
do not need to be invited to join the channel when it is invite-only
(``+i``). Unlike the ``INVITE`` command, this does not override ``+j``, ``+l`` and ``+r``.

Only channel operators can see ``+I`` changes or request the list.

``+j``, join throttling
-----------------------

This mode takes one parameter of the form n:t, where n and t are
positive integers. Only n users may join in each period of t seconds.

Invited users can join regardless of ``+j``, but are counted as normal.

Due to propagation delays between servers, more users may be able to
join (by racing for the last slot on each server).

``+k``, key (channel password)
------------------------------

Taking one parameter, when set, this mode requires a user to supply the
key in order to join the channel: ``/JOIN #channel key``.

``+l``, channel member limit
----------------------------

Takes one numeric parameter, the number of users which are allowed to be
in the channel before further joins are blocked. Invited users may join
regardless.

Due to propagation delays between servers, more users may be able to
join (by racing for the last slot on each server).

``+L``, large ban list
----------------------

Channels with this mode will be allowed larger banlists (by default, 500
instead of 50 entries for ``+b``, ``+q``, ``+e`` and ``+I`` together). Only network
operators with resv privilege may set this mode.

``+m``, moderated
-----------------

When a channel is set ``+m``, only users with ``+o`` or ``+v`` on the channel can
send to it.

Users can still knock on the channel or change their nick.

``+n``, no external messages
----------------------------

When set, this mode prevents users from sending to the channel without
being in it themselves. This is recommended.

``+o``, channel operator
------------------------

This mode takes one parameter, a nick, and grants or removes channel
operator privilege to that user. Channel operators have full control
over the channel, having the ability to set all channel modes except ``+L``
and ``+P``, and kick users. Like voiced users, channel operators can always
send to the channel, overriding ``+b``, ``+m`` and ``+q`` modes and the per-channel
flood limit. In most clients channel operators are marked with an '@'
sign.

The privilege is lost if the user leaves the channel or server in any
way.

Most networks will run channel registration services (e.g. ChanServ)
which ensure the founder (and users designated by the founder) can
always gain channel operator privileges and provide some features to
manage the channel.

``+p``, paranoid channel
------------------------

When set, the ``KNOCK`` command cannot be used on the channel to request an
invite, and users will not be shown the channel in ``WHOIS`` replies unless
they are on it. Unlike in traditional IRC, ``+p`` and ``+s`` can be set
together.

``+P``, permanent channel
-------------------------

Channels with this mode (which is accessible only to network operators
with resv privilege) set will not be destroyed when the last user
leaves.

This makes it less likely modes, bans and the topic will be lost and
makes it harder to abuse network splits, but also causes more unwanted
restoring of old modes, bans and topics after long splits.

``+q``, quiet
-------------

This mode behaves exactly like ``+b`` (ban), except that the user may still
join the channel. The net effect is that they cannot knock on the
channel, send to the channel or change their nick while on channel.

``+Q``, block forwarded users
-----------------------------

Channels with this mode set are not valid targets for forwarding. Any
attempt to forward to this channel will be ignored, and the user will be
handled as if the attempt was never made (by sending them the relevant
error message).

This does not affect the ability to set ``+f``.

``+r``, block unidentified
--------------------------

When set, this mode prevents unidentified users from joining. Invited
users can still join.

``+s``, secret channel
----------------------

When set, this mode prevents the channel from appearing in the output of
the ``LIST``, ``WHO`` and ``WHOIS`` command by users who are not on it. Also, the
server will refuse to answer ``WHO``, ``NAMES``, ``TOPIC`` and ``LIST`` queries from
users not on the channel.

``+t``, topic limit
-------------------

When set, this mode prevents users who are not channel operators from
changing the topic.

``+v``, voice
-------------

This mode takes one parameter, a nick, and grants or removes voice
privilege to that user. Voiced users can always send to the channel,
overriding ``+b``, ``+m`` and ``+q`` modes and the per-channel flood limit. In most
clients voiced users are marked with a plus sign.

The privilege is lost if the user leaves the channel or server in any
way.

``+z``, reduced moderation
--------------------------

When ``+z`` is set, the effects of ``+m``, ``+b`` and ``+q`` are relaxed. For each
message, if that message would normally be blocked by one of these
modes, it is instead sent to all channel operators. This is intended for
use in moderated debates.

Note that ``+n`` is unaffected by this. To silence a given user completely,
remove them from the channel.
