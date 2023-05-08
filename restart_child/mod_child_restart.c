#include <stdio.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mpm_common.h"

static void (*child_restart)(void) = NULL;

/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module AP_MODULE_DECLARE_DATA child_restart_module;

static int child_restart_handler(request_rec *r)
{
    if (strcmp(r->handler, "mod_child-restart") == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "child_restart_handler CALLED!");
        if (child_restart != NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "child_restart_handler DOING!");
            child_restart();
        }
        return (OK);
    }
    return DECLINED;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Which functions are responsible for which hooks in the server.           */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static void register_hooks(apr_pool_t *p)
{
    const char *mpm;
    ap_hook_handler(child_restart_handler, NULL, NULL, APR_HOOK_MIDDLE);
    /* "gracefull" , "winnt", "0" */
    mpm = ap_run_mpm_get_name();
    child_restart =  ap_lookup_provider("gracefull", mpm, "0");

}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* The list of callback routines and data structures that provide           */
/* the static hooks into our module from the other parts of the server.     */
/*                                                                          */
/*--------------------------------------------------------------------------*/
module AP_MODULE_DECLARE_DATA child_restart_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                    /* per-directory config creator                */
    NULL,                    /* dir config merger                           */
    NULL,                    /* server config creator                       */
    NULL,                     /* server config merger                        */
    NULL,               /* command table                               */
    register_hooks,          /* set up other request processing hooks       */
    AP_MODULE_FLAG_NONE      /* flags */
};
