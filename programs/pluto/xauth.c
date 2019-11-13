/* XAUTH PAM auth & session handling
 *
 * Copyright (C) 2019 Avi Saranga <avi@opebsd.org.il>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifdef XAUTH_HAVE_PAM

#include <pthread.h> /* Must be the first include file */

#include <stdlib.h>

#include "constants.h"
#include "lswlog.h"
#include "defs.h"
#include "log.h"
#include "xauth.h"
#include "pam_conv.h"
#include "event.h"
#include "state.h"
#include "connections.h"
#include "server.h"
#include "id.h"
#include "pluto_stats.h"
#include "log.h"
#include "ip_address.h"
#include <pthread.h>

/* information for tracking xauth PAM work in flight */

void xauth_start_pam_thread(struct state *st,
			    const char *name,
			    const char *password,
			    const char *atype,
			    xauth_callback_t *callback)
{
	so_serial_t serialno = st->st_serialno;
    pthread_t thread_id;

	passert(pthread_equal(main_thread, pthread_self()));

	struct xauth *xauth = alloc_thing(struct xauth, "xauth arg");

	xauth->callback = callback;
	xauth->serialno = serialno;
	gettimeofday(&xauth->tv0, NULL);

	/* fill in pam_thread_arg with info for the child process */

	xauth->ptarg.name = clone_str(name, "pam name");
	xauth->ptarg.password = clone_str(password, "pam password");
	xauth->ptarg.c_name = clone_str(st->st_connection->name, "pam connection name");

	ipstr_buf ra;
	xauth->ptarg.ra = clone_str(ipstr(&st->st_remoteaddr, &ra), "pam remoteaddr");
	xauth->ptarg.st_serialno = serialno;
	xauth->ptarg.c_instance_serial = st->st_connection->instance_serial;
	xauth->ptarg.atype = atype;

	DBG(DBG_XAUTH,
	    DBG_log("XAUTH: #%lu: main-process starting PAM-process for authenticating user '%s'",
		    xauth->serialno, xauth->ptarg.name));

	xauth->ptarg.ptr_state = (void *) st; // pass connection state object PTR so we could complete the transaction when PAM_AUTH is happy
    xauth->ptarg.pam_do_state = PAM_AUTH; // start with AUTH
    xauth->ptarg.pam_state = PAM_RESULT_UNKNOWN; // if you don't know - you know.
    xauth->abort = TRUE;

    int t_ret = pthread_create(&thread_id, NULL, pam_thread, (void*) xauth);
    pthread_detach(thread_id);
    libreswan_log("XAUTH: User: '%s' password: '%s' authenticating...", name, password);

	if (t_ret) {
		libreswan_log("XAUTH: #%lu: creation of PAM thread for user '%s' failed", xauth->serialno, xauth->ptarg.name);
		pfree_xauth(xauth);
		return;
	} else {
      	st->st_xauth = xauth;
    	pstats_xauth_started++;

	}

}

#endif
