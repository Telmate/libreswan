/* PAM Authentication and Autherization related
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

#ifdef XAUTH_HAVE_PAM

enum pam_state_t {
    PAM_AUTH = 0,
    PAM_SESSION_START = 1,
    PAM_SESSION_END = 2,
    PAM_TERM = 3,
    PAM_STATE_UNKNOWN = 4

};

enum pam_result_state_t {
    PAM_AUTH_SUCCESS = 0,
    PAM_AUTH_FAIL = 1,
    PAM_SESSION_START_SUCCESS = 2,
    PAM_SESSION_START_FAIL = 3,
    PAM_SESSION_END_SUCCESS = 4,
    PAM_SESSION_END_FAIL = 5,
    PAM_TERM_SUCCESS = 6,
    PAM_TERM_FAIL = 7,
    PAM_RESULT_UNKNOWN = 8
};

struct pam_thread_arg {
	char *name;
	char *password;
	char *c_name;
	char *ra;
	so_serial_t st_serialno;
	unsigned long c_instance_serial;
	const char *atype;  /* string XAUTH or IKEv2 */
	void *ptr_pam_handle;
	pthread_mutex_t thread_run_m;
    	enum pam_state_t pam_do_state;
    	enum pam_result_state_t pam_state;
};

extern bool do_pam_authentication(struct pam_thread_arg *arg);
extern bool do_pam_session_closure(struct pam_thread_arg *arg);
extern void *pam_thread(void *parg);
int thread_operation(pthread_mutex_t *mx);
#endif /* XAUTH_HAVE_PAM */
