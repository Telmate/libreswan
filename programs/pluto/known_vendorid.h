/* Libreswan ISAKMP VendorID
 *
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef _KNOWN_VENDORID_H_
#define _KNOWN_VENDORID_H_

enum known_vendorid {
	VID_none = 0,	/* when none seen, this will appear */

	/* Implementation names */

	VID_OPENPGP,
	VID_KAME_RACOON,
	VID_MS_WIN2K,
	VID_MS_WINXP,
	VID_MS_WIN2003,
	VID_MS_WINVISTA,
	VID_MS_WIN2008,
	VID_MS_WIN7,
	VID_MS_WIN2008R2,
	VID_MS_WINKSINK09,
	VID_MS_WINKEYMODS_IKE,
	VID_MS_WINKEYMODS_AUTHIP,
	VID_MS_WINKEYMODS_IKEv2,
	VID_MS_AUTHIP_KE_DH_NONE,
	VID_MS_AUTHIP_KE_DH1,
	VID_MS_AUTHIP_KE_DH2,
	VID_MS_AUTHIP_KE_DH14,
	VID_MS_AUTHIP_KE_DH19,
	VID_MS_AUTHIP_KE_DH20,
	VID_MS_AUTHIP_KE_DH21,
	VID_MS_AUTHIP_KE_DHMAX,
	VID_MS_NLBS_PRESENT,
	VID_MS_MAMIEEXISTS,
	VID_MS_CGAv1,
	VID_MS_NEGDISCCAP,
	VID_MS_XBOX_ONE_2013,
	VID_MS_XBOX_IKEv2,
	VID_MS_SEC_REALM_ID,
	VID_SSH_SENTINEL,
	VID_SSH_SENTINEL_1_1,
	VID_SSH_SENTINEL_1_2,
	VID_SSH_SENTINEL_1_3,
	VID_SSH_IPSEC_1_1_0,
	VID_SSH_IPSEC_1_1_1,
	VID_SSH_IPSEC_1_1_2,
	VID_SSH_IPSEC_1_2_1,
	VID_SSH_IPSEC_1_2_2,
	VID_SSH_IPSEC_2_0_0,
	VID_SSH_IPSEC_2_1_0,
	VID_SSH_IPSEC_2_1_1,
	VID_SSH_IPSEC_2_1_2,
	VID_SSH_IPSEC_3_0_0,
	VID_SSH_IPSEC_3_0_1,
	VID_SSH_IPSEC_4_0_0,
	VID_SSH_IPSEC_4_0_1,
	VID_SSH_IPSEC_4_1_0,
	VID_SSH_IPSEC_4_2_0,
	VID_CISCO_UNITY,
	VID_CISCO_VPN_REV_02,
	VID_CISCO3K,
	VID_CISCO_IOS,
	VID_CISCO_IKE_FRAGMENTATION,
	VID_CISCO_UNITY_FWTYPE,
	VID_CISCO_DELETE_REASON,
	VID_CISCO_FLEXVPN_SUPPORTED,
	VID_CISCO_DYNAMIC_ROUTE,
	VID_SSH_SENTINEL_1_4,
	VID_SSH_SENTINEL_1_4_1,
	VID_TIMESTEP,
	VID_FSWAN_2_00_VID,
	VID_FSWAN_2_00_X509_1_3_1_VID,
	VID_FSWAN_2_00_X509_1_3_1_LDAP_VID,
	VID_SAFENET,
	VID_NORTEL,
	VID_OPENSWAN2,
	VID_XOPENSWAN,
	VID_OPENSWANORG,
	VID_ELVIS,
	VID_MACOSX,
	VID_OPPORTUNISTIC,
	VID_LIBRESWANSELF,
	VID_LIBRESWAN,
	VID_LIBRESWAN_OLD,
	VID_NCP,
	VID_SONICWALL_1,
	VID_SONICWALL_2,
	VID_SHREWSOFT,
	VID_NETSCREEN_01,
	VID_NETSCREEN_02,
	VID_NETSCREEN_03,
	VID_NETSCREEN_04,
	VID_NETSCREEN_05,
	VID_NETSCREEN_06,
	VID_NETSCREEN_07,
	VID_NETSCREEN_08,
	VID_NETSCREEN_09,
	VID_NETSCREEN_10,
	VID_NETSCREEN_11,
	VID_NETSCREEN_12,
	VID_NETSCREEN_13,
	VID_NETSCREEN_14,
	VID_NETSCREEN_15,
	VID_NETSCREEN_16,
	VID_ZYWALL,
	VID_SIDEWINDER,
	VID_WATCHGUARD,
	VID_LUCENT_GW9,
	VID_LUCENT_CL7,
	VID_CHECKPOINT,
	VID_GSSAPI,
	VID_GSSAPILONG,

	/* NAT-Traversal */
	VID_NATT_STENBERG_01,
	VID_NATT_STENBERG_02,
	VID_NATT_HUTTUNEN,
	VID_NATT_HUTTUNEN_ESPINUDP,
	VID_NATT_IETF_00,
	VID_NATT_IETF_01,
	VID_NATT_IETF_02_N,
	VID_NATT_IETF_02,
	VID_NATT_IETF_03,
	VID_NATT_IETF_04,
	VID_NATT_IETF_05,
	VID_NATT_IETF_06,
	VID_NATT_IETF_07,
	VID_NATT_IETF_08,
	VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE,
	VID_NATT_RFC,

	/* World of Microsoft */

	VID_VISTA_AUTHIP,
	VID_VISTA_AUTHIP2,
	VID_VISTA_AUTHIP3,

	/* Strongswan */

	VID_STRONGSWAN,
	VID_STRONGSWAN_2_2_0,
	VID_STRONGSWAN_2_2_1,
	VID_STRONGSWAN_2_2_2,
	VID_STRONGSWAN_2_3_0,
	VID_STRONGSWAN_2_3_1,
	VID_STRONGSWAN_2_3_2,
	VID_STRONGSWAN_2_4_0,
	VID_STRONGSWAN_2_4_1,
	VID_STRONGSWAN_2_4_2,
	VID_STRONGSWAN_2_4_3,
	VID_STRONGSWAN_2_4_4,
	VID_STRONGSWAN_2_5_0,
	VID_STRONGSWAN_2_5_1,
	VID_STRONGSWAN_2_5_2,
	VID_STRONGSWAN_2_5_3,
	VID_STRONGSWAN_2_5_4,
	VID_STRONGSWAN_2_5_5,
	VID_STRONGSWAN_2_5_6,
	VID_STRONGSWAN_2_5_7,
	VID_STRONGSWAN_2_6_0,
	VID_STRONGSWAN_2_6_1,
	VID_STRONGSWAN_2_6_2,
	VID_STRONGSWAN_2_6_3,
	VID_STRONGSWAN_2_6_4,
	VID_STRONGSWAN_2_7_0,
	VID_STRONGSWAN_2_7_1,
	VID_STRONGSWAN_2_7_2,
	VID_STRONGSWAN_2_7_3,
	VID_STRONGSWAN_2_8_0,
	VID_STRONGSWAN_2_8_1,
	VID_STRONGSWAN_2_8_2,
	VID_STRONGSWAN_2_8_3,
	VID_STRONGSWAN_2_8_4,
	VID_STRONGSWAN_2_8_5,
	VID_STRONGSWAN_2_8_6,
	VID_STRONGSWAN_2_8_7,
	VID_STRONGSWAN_2_8_8,

	VID_STRONGSWAN_4_0_0,
	VID_STRONGSWAN_4_0_1,
	VID_STRONGSWAN_4_0_2,
	VID_STRONGSWAN_4_0_3,
	VID_STRONGSWAN_4_0_4,
	VID_STRONGSWAN_4_0_5,
	VID_STRONGSWAN_4_0_6,
	VID_STRONGSWAN_4_0_7,
	VID_STRONGSWAN_4_1_0,
	VID_STRONGSWAN_4_1_1,
	VID_STRONGSWAN_4_1_2,
	VID_STRONGSWAN_4_1_3,
	VID_STRONGSWAN_4_1_4,
	VID_STRONGSWAN_4_1_5,
	VID_STRONGSWAN_4_1_6,
	VID_STRONGSWAN_4_1_7,
	VID_STRONGSWAN_4_1_8,
	VID_STRONGSWAN_4_1_9,
	VID_STRONGSWAN_4_1_10,
	VID_STRONGSWAN_4_1_11,
	VID_STRONGSWAN_4_2_0,
	VID_STRONGSWAN_4_2_1,
	VID_STRONGSWAN_4_2_2,
	VID_STRONGSWAN_4_2_3,

	/* Misc */

	VID_MISC_XAUTH,
	VID_MISC_DPD,
	VID_MISC_HEARTBEAT_NOTIFY,
	VID_IKE_FRAGMENTATION,
	VID_INITIAL_CONTACT,
	VID_MISC_IKEv2,
	VID_DPD1_NG,
};

#endif /* _KNOWN_VENDORID_H_ */
