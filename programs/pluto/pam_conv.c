/* PAM Authentication and Autherization related functions
 *
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
 * Copyright (C) 2009 Ken Wilson <Ken_Wilson@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2013 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013-2015 Antony Antony <antony@phenome.org>
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
 *
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

#include <string.h>
#include <stdlib.h>
#include <security/pam_appl.h> /* needed for pam_handle_t */

#include "defs.h"
#include "lswlog.h"
#include "pam_conv.h"
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <asm/errno.h>
#include "log.h"
#include "state.h"


static char *pam_state_enum[] = {
    "PAM_AUTH","PAM_SESSION_START", "PAM_SESSION_END", "PAM_TERM", "PAM_STATE_UNKNOWN", "PAM_DO_NOTHING"
};

static char *pam_result_state_enum[] = { "PAM_AUTH_SUCCESS", "PAM_AUTH_FAIL", "PAM_SESSION_START_SUCCESS", "PAM_SESSION_START_FAIL", "PAM_SESSION_END_SUCCESS", "PAM_SESSION_END_FAIL", "PAM_TERM_SUCCESS", "PAM_TERM_FAIL", "PAM_RESULT_UNKNOWN"
};

/* BEWARE: This code is multi-threaded.
 *
 * Any static object is likely shared and probably has to be protected by
 * a lock.
 * Any other shared object needs to be protected.
 * Beware of calling functions that are not thread-safe.
 *
 * Non-thread-safe functions:
 * - ??? pam_*?
 */

/*
 * PAM conversation
 *
 * @param num_msg Int.
 * @param msgm Pam Message Struct
 * @param response Where PAM will put the results
 * @param appdata_ptr Pointer to data struct (as we are using threads)
 * @return int PAM Return Code (possibly fudged)
 */
static int pam_conv(int num_msg,
		    const struct pam_message **msgm,
		    struct pam_response **response,
		    void *appdata_ptr)
{
	struct pam_thread_arg *const arg = appdata_ptr;
	int count = 0;
	struct pam_response *reply;

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	/*
	 *   According to pam_conv(3), caller will free(3) reply
	 *   so we must allocate it with malloc.
	 */
	reply = malloc(num_msg * sizeof(struct pam_response));

	for (count = 0; count < num_msg; ++count) {
		const char *s = NULL;

		switch (msgm[count]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			s = arg->password;
			break;
		case PAM_PROMPT_ECHO_ON:
			s = arg->name;
			break;
		}

		reply[count].resp_retcode = 0;
		reply[count].resp = NULL;       /* for unhandled case */

		if (s != NULL) {
			/*
			 * Add s to list of responses.
			 * According to pam_conv(3), our caller will
			 * use free(3) to free these arguments so
			 * we must allocate them with malloc,
			 * not our own allocators.
			 */
			size_t len = strlen(s) + 1;
			char *t = malloc(len);	/* must be malloced */

			memcpy(t, s, len);
			reply[count].resp = t;
		}
	}

	*response = reply;
	return PAM_SUCCESS;
}

static void log_pam_step(const struct pam_thread_arg *arg, const char *what)
{
	DBG(DBG_XAUTH,
		DBG_log("%s helper thread %s for state #%lu, %s[%lu] user=%s.",
			arg->atype, what,
			arg->st_serialno, arg->c_name,
			arg->c_instance_serial, arg->name));
}


void pfree_xauth(struct xauth *x)
{
  pfree(x->ptarg.name);
  pfree(x->ptarg.password);
  pfree(x->ptarg.c_name);
  pfree(x->ptarg.ra);

  pfree(x);
}

int thread_operation(pthread_mutex_t *mx)
{

  switch(pthread_mutex_trylock(mx)) {

    case 0: // we have a lock unlock and return true
      pthread_mutex_unlock(mx);
      return 1;

    case EBUSY: // return false if the mutex was locked
      return 0;
  }

  return 1;
}

void *pam_thread(void *parg)
{
  pthread_mutex_t thread_run_m; // thread control mutex
  struct xauth *ptr_xauth = (struct xauth*) parg;
  pam_handle_t *pamh = NULL;
  ptr_xauth->ptarg.ptr_pam_handle = (void*) pamh;
  struct pam_conv conv = {NULL, NULL};
  const char *what;
  int retval = -1;
  int _pam_state = 0;
  int _pam_do_state = 0;
  long _serialno = 0;


  conv.conv = pam_conv;
  conv.appdata_ptr = &ptr_xauth->ptarg;

  pthread_mutex_init(&ptr_xauth->ptarg.m_destructor,NULL); // thread loop control mutex
  pthread_mutex_lock(&ptr_xauth->ptarg.m_destructor); // lock it.

  pthread_mutex_init(&thread_run_m,NULL); // thread loop control mutex
  pthread_mutex_lock(&thread_run_m); // lock it.

  do {
//    libreswan_log(" %d", (int)pthread_mutex_trylock(&ptr_xauth->ptarg.m_destructor));
    if ((int)pthread_mutex_trylock(&ptr_xauth->ptarg.m_destructor) != EBUSY) {
      ptr_xauth->ptarg.pam_do_state = PAM_SESSION_END;
    }


    /*    if( ptr_xauth->ptarg.m_destructor != N) { // in case we iterate one more time after this object has gone away
    }*/

    if(ptr_xauth->ptarg.pam_do_state == PAM_AUTH) {

      for (int i = 0; i < 5; i++) {

        what = "pam_start";
        retval = pam_start("pluto", ptr_xauth->ptarg.name, &conv, &pamh);
        log_pam_step((struct pam_thread_arg *) &ptr_xauth->ptarg, what);

        if (retval == PAM_SUCCESS) {
          /* do pam_set_item */
          for (int i = 0; i < 5; i++) {

            what = "pam_set_item";
            retval = pam_set_item(pamh, PAM_RHOST, ptr_xauth->ptarg.ra);
            log_pam_step((struct pam_thread_arg *) &ptr_xauth->ptarg, what);
            if (retval == PAM_SUCCESS) {
              /* do pam_authenticate */

              what = "pam_authenticate";
              retval = pam_authenticate(pamh, PAM_SILENT); /* is user really user? */
              log_pam_step((struct pam_thread_arg *) &ptr_xauth->ptarg, what);
              if (retval == PAM_SUCCESS) {
                /* do pam_acct_mgmt */
                for (int i = 0; i < 5; i++) {

                  what = "pam_acct_mgmt";
                  retval = pam_acct_mgmt(pamh, 0); /* permitted access? */
                  log_pam_step((struct pam_thread_arg *) &ptr_xauth->ptarg, what);
                  if (retval == PAM_SUCCESS) {
                    /* do promotion to session start */
                    ptr_xauth->ptarg.pam_state = PAM_AUTH_SUCCESS;
                    ptr_xauth->ptarg.pam_do_state = PAM_SESSION_START;

                    break; //  break out of pam_acct_mgmt loop

                  } else { /* failed pam_acct_mgmt */
                    ptr_xauth->ptarg.pam_state = PAM_AUTH_FAIL;
                    ptr_xauth->ptarg.pam_do_state = PAM_TERM;

                  }
                }
                break; // break out of pam_authenticate loop

              } else { /* failed pam_authenticate */
                ptr_xauth->ptarg.pam_state = PAM_AUTH_FAIL;
                ptr_xauth->ptarg.pam_do_state = PAM_TERM;
              }

            } else { /* failed pam_set_item */
              ptr_xauth->ptarg.pam_state = PAM_AUTH_FAIL;
              ptr_xauth->ptarg.pam_do_state = PAM_TERM;
            }


          }
          break; // pam_start

        } else { /* failed pam_start */
          ptr_xauth->ptarg.pam_state = PAM_AUTH_FAIL;
          ptr_xauth->ptarg.pam_do_state = PAM_TERM;
        }

      }

    } else if(ptr_xauth->ptarg.pam_do_state == PAM_SESSION_START) {

      for (int i = 0; i < 5; i++) {
        what = "pam_open_session";
        retval = pam_open_session(pamh, PAM_SILENT);
        log_pam_step((struct pam_thread_arg *)&ptr_xauth->ptarg, what);
        if (retval == PAM_SUCCESS) {

          bool success = TRUE;
          struct state *st = state_with_serialno(ptr_xauth->serialno);
          passert(st != NULL);
          so_serial_t old_state = push_cur_state(st);

          libreswan_log("XAUTH: #%lu: completed for user '%s' with status %s ::: pam_open_session",
                        ptr_xauth->ptarg.st_serialno, ptr_xauth->ptarg.name,
                        success ? "SUCCESSS" : "FAILURE");

          ptr_xauth->callback(st, ptr_xauth->ptarg.name, success);
          pop_cur_state(old_state);

          //st->st_xauth = NULL; // all "done" (i really keep the st_xauth_ptr for my use later on)

          ptr_xauth->ptarg.pam_state = PAM_SESSION_START_SUCCESS;
          ptr_xauth->ptarg.pam_do_state = PAM_DO_NOTHING;

          break;
        } else {
          ptr_xauth->ptarg.pam_state = PAM_SESSION_START_FAIL;
          ptr_xauth->ptarg.pam_do_state = PAM_TERM;
        }
      }
      /* Failed pam_open_session */


    } else if(ptr_xauth->ptarg.pam_do_state == PAM_SESSION_END) {

      for (int i = 0; i < 5; i++) {
        what = "pam_close_session";
        retval = pam_close_session(pamh, PAM_SILENT);
        log_pam_step((struct pam_thread_arg *)&ptr_xauth->ptarg, what);
        if (retval == PAM_SUCCESS) {
          ptr_xauth->ptarg.pam_state = PAM_SESSION_END_SUCCESS;
          ptr_xauth->ptarg.pam_do_state = PAM_TERM;
          break;
        } else {  /* Failed pam_close_session */
          ptr_xauth->ptarg.pam_state = PAM_SESSION_END_FAIL;
          ptr_xauth->ptarg.pam_do_state = PAM_TERM;
        }
      }


    } else if(ptr_xauth->ptarg.pam_do_state == PAM_TERM) {

      ptr_xauth->abort = TRUE;
      what = "pam_end";
      retval = pam_end(pamh, retval);
      log_pam_step((struct pam_thread_arg *)&ptr_xauth->ptarg, what);
      _serialno = (ptr_xauth->serialno);
      _pam_do_state = ((int)ptr_xauth->ptarg.pam_do_state);
      _pam_state = ((int) ptr_xauth->ptarg.pam_state);


      pfree_xauth(ptr_xauth);
      pthread_mutex_destroy(&ptr_xauth->ptarg.m_destructor);

      if (retval == PAM_SUCCESS) {
        /* TODO: @avi release ALL RESOURCES before this thread completes */
        ptr_xauth->ptarg.pam_state = PAM_TERM_SUCCESS;
        pthread_mutex_unlock(&thread_run_m); // TODO: make sure we only unlock when all resources are released.


        break;
      } else {
        /* TODO: pam_end failed, we still want to release all of our resources */

        ptr_xauth->ptarg.pam_state = PAM_TERM_FAIL;
        libreswan_log("XAUTH: PAM_TERM_FAIL --- FATAL!!!! pam_handle leakage, memory and resource exhaustion!!!!!");

      }
      libreswan_log("XAUTH: #%lu: PAM thread completed pam_do_state == %s pam_state == %s", _serialno,
                    pam_state_enum[(int)_pam_do_state], pam_result_state_enum[(int)_pam_state] );

    }

    usleep(100000); // 100ms because, because we are efficient pffft.

  } while(thread_operation(&thread_run_m) == 0);

  pthread_mutex_destroy(&thread_run_m);



  return NULL;
}
