// PAM module for S/KEY-factor authentication.
//
// Copyright 2016 Ernst-Georg Schmid
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/* Define which PAM interfaces we provide */
//#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
//#define PAM_SM_PASSWORD
//#define PAM_SM_SESSION

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <mhash.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define MODULE_NAME "pam_skey"
#define SECRET "%s/.skey"
#define HASHSZ_BYTES 16
#define HASHSZ_TEXT 32
#define BUFSZ 1024
#define CNTBASE 48
#define MAXTOKENS 50
#define WARN_TOKENS 10
#define BLOCKSZ 4

static  void log_message(int priority, const pam_handle_t * const pamh,
                         const char * const format, ...)
{
    char *service = NULL;
    if (pamh)
        pam_get_item(pamh, PAM_SERVICE, (void *)&service);
    if (!service)
        service = "";

    char logname[80];
    snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

    va_list args;
    va_start(args, format);

    openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(priority, format, args);
    closelog();

    va_end(args);

    if (priority == LOG_EMERG)
    {
        // Something really bad happened. There is no way we can proceed safely.
        _exit(1);
    }
}

static  int setuser(int uid)
{
    // The semantics for setfsuid() are a little unusual. On success, the
    // previous user id is returned. On failure, the current user id is returned.
    int old_uid = setfsuid(uid);
    if (uid != setfsuid(uid))
    {
        setfsuid(old_uid);
        return -1;
    }

    return old_uid;
}

static int setgroup(int gid)
{

    // The semantics of setfsgid() are a little unusual. On success, the
    // previous group id is returned. On failure, the current groupd id is
    // returned.
    int old_gid = setfsgid(gid);
    if (gid != setfsgid(gid))
    {
        setfsgid(old_gid);
        return -1;
    }

    return old_gid;
}

static  int drop_privileges(const pam_handle_t * const pamh, const char * const username, uid_t uid,
                            uid_t *old_uid, gid_t  *old_gid)
{
    // Try to become the new user. This might be necessary for NFS mounted home
    // directories.

    // First, look up the user's default group

    int len = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (len <= 0)
    {
        len = 4096;
    }

    char *buf = malloc(len);
    if (!buf)
    {
        log_message(LOG_ERR, pamh, "Out of memory");
        return -1;
    }
    struct passwd pwbuf, *pw;
    if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw)
    {
        log_message(LOG_ERR, pamh, "Cannot look up user id %d", uid);
        free(buf);
        return -1;
    }
    gid_t gid = pw->pw_gid;
    free(buf);

    int gid_o = setgroup(gid);
    int uid_o = setuser(uid);
    if (uid_o < 0)
    {
        if (gid_o >= 0)
        {
            if (setgroup(gid_o) < 0 || setgroup(gid_o) != gid_o)
            {
                // Inform the caller that we were unsuccessful in resetting the group.
                *old_gid = gid_o;
            }
        }
        log_message(LOG_ERR, pamh, "Failed to change user id to \"%s\"",
                    username);
        return -1;
    }
    if (gid_o < 0 && (gid_o = setgroup(gid)) < 0)
    {
        // In most typical use cases, the PAM module will end up being called
        // while uid=0. This allows the module to change to an arbitrary group
        // prior to changing the uid. But there are many ways that PAM modules
        // can be invoked and in some scenarios this might not work. So, we also
        // try changing the group _after_ changing the uid. It might just work.
        if (setuser(uid_o) < 0 || setuser(uid_o) != uid_o)
        {
            // Inform the caller that we were unsuccessful in resetting the uid.
            *old_uid = uid_o;
        }
        log_message(LOG_ERR, pamh,
                    "Failed to change group id for user \"%s\" to %d", username,
                    (int)gid);
        return -1;
    }

    *old_uid = uid_o;
    *old_gid = gid_o;
    return 0;
}

static  int converse(const pam_handle_t * const pamh, int nargs,
                     const struct pam_message **message,
                     struct pam_response **response)
{
    struct pam_conv *conv;
    int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }
    return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static  char *request_pass(const pam_handle_t * const pamh, int echocode,
                           const char * const prompt)
{
    // Query user for verification code
    const struct pam_message msg = { .msg_style = echocode, .msg = prompt};
    const struct pam_message *msgs = &msg;
    struct pam_response *resp = NULL;
    int retval = converse(pamh, 1, &msgs, &resp);
    char *ret = NULL;
    if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
            *resp->resp == '\000')
    {
        //log_message(LOG_ERR, pamh, "Did not receive verification code from user");
        if (retval == PAM_SUCCESS && resp && resp->resp)
        {
            ret = resp->resp;
        }
    }
    else
    {
        ret = resp->resp;
    }

    // Deallocate temporary storage
    if (resp)
    {
        if (!ret)
        {
            free(resp->resp);
        }
        free(resp);
    }

    return ret;
}

static  char *normalize(char * const pwd)
{
    memmove(&pwd[4], &pwd[5], BLOCKSZ*sizeof(char));
    memmove(&pwd[8], &pwd[10], BLOCKSZ*sizeof(char));
    memmove(&pwd[12], &pwd[15], BLOCKSZ*sizeof(char));
    memmove(&pwd[16], &pwd[20], BLOCKSZ*sizeof(char));
    memmove(&pwd[20], &pwd[25], BLOCKSZ*sizeof(char));
    memmove(&pwd[24], &pwd[30], BLOCKSZ*sizeof(char));
    memmove(&pwd[28], &pwd[35], BLOCKSZ*sizeof(char));

    memset(&pwd[32],0x0,7);

    return pwd;
}

static  char* do_hash(const char * const p, const char * const pwd, char * const password_hash)
{
    char hb[33];
    MHASH hc = NULL;
    unsigned char digest[HASHSZ_BYTES];

    memset(hb,0x0, sizeof(hb));
    memset(digest,0x0, sizeof(digest));

    //memcpy(&hb[0],p, HASHSZ_TEXT);

    memcpy(&hb[0],pwd, HASHSZ_TEXT);

    if (strlen(hb) != HASHSZ_TEXT)
    {
        return(NULL);
    }

    hc = mhash_hmac_init(MHASH_RIPEMD128, (void *) p, HASHSZ_TEXT, mhash_get_hash_pblock(MHASH_RIPEMD128));

    mhash(hc, hb, strlen((const char *)hb));

    mhash_hmac_deinit(hc, digest);

    memset(password_hash, 0x0, HASHSZ_TEXT+1);

    for (int i=0; i<HASHSZ_BYTES; i++)
    {
        sprintf(&password_hash[i*2], "%02x", (unsigned int)digest[i]);
    }

    for (int i=0; i<999998; i++)
    {
        hc = mhash_hmac_init(MHASH_RIPEMD128, (void *) p, HASHSZ_TEXT, mhash_get_hash_pblock(MHASH_RIPEMD128));

        memset(hb,0x0, sizeof(hb));

        //memcpy(&hb[0],p, HASHSZ_TEXT);

        memcpy(&hb[0],password_hash, HASHSZ_TEXT);

        if (strlen(hb) != HASHSZ_TEXT)
        {
            return(NULL);
        }

        mhash(hc, hb, strlen((const char *)hb));

        mhash_hmac_deinit(hc, digest);

        memset(password_hash, 0x0, HASHSZ_TEXT+1);

        for (int j=0; j<HASHSZ_BYTES; j++)
        {
            sprintf(&password_hash[j*2], "%02x", (unsigned int)digest[j]);
        }
    }

    return password_hash;
}

/* PAM entry point for session creation */
/*int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}*/

/* PAM entry point for session cleanup */
/*int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}*/

/* PAM entry point for accounting */
/*int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}*/

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct passwd *pw = NULL, pw_s;
    const char *user = NULL;
    char buffer[BUFSZ], checkfile[BUFSZ], p[33], next_hash[33], password_hash[33], pwd[40];
    int pgu_ret, gpn_ret, snp_ret;
    uid_t old_uid = -1;
    gid_t old_gid = -1;
    unsigned char cnt = 0;
    FILE * fp;
    const char *prompt = "S/KEY token:";
    char *temp_pw = NULL;

    pgu_ret = pam_get_user(pamh, &user, NULL);
    if (pgu_ret != PAM_SUCCESS || user == NULL)
    {
        return(PAM_IGNORE);
    }

    gpn_ret = getpwnam_r(user, &pw_s, buffer, sizeof(buffer), &pw);
    if (gpn_ret != 0 || pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/')
    {
        return(PAM_IGNORE);
    }

    if(drop_privileges(pamh, user, pw->pw_uid, &old_uid, &old_gid) != 0)
    {
        log_message(LOG_EMERG, pamh, "Could not drop privileges!");
        return(PAM_IGNORE);
    }

    memset(pwd,0x0,sizeof(pwd));

    temp_pw = request_pass(pamh, PAM_PROMPT_ECHO_OFF, prompt);

    if(temp_pw == NULL || strlen(temp_pw) != 39)
    {
        return(PAM_AUTHINFO_UNAVAIL);
    }

    strncpy(pwd, temp_pw, sizeof(pwd));

    memset(temp_pw,0x0,strlen(temp_pw));

    free(temp_pw);

    temp_pw = NULL;

    snp_ret = snprintf(checkfile, sizeof(checkfile), SECRET, pw->pw_dir);

    if (snp_ret >= sizeof(checkfile))
    {
        return(PAM_IGNORE);
    }

    fp = fopen (checkfile, "r");
    if (fp == NULL)
    {
        return(PAM_IGNORE);
    }

    memset(buffer,0x0,sizeof(buffer));

    if (fgets(buffer, sizeof(buffer), fp) == NULL)
    {
        fclose(fp);
        return(PAM_IGNORE);
    }

    if (fclose(fp) != 0)
    {
        return(PAM_IGNORE);
    }

    if(strlen(buffer) != 65)
    {
        return(PAM_IGNORE);
    }

    cnt = buffer[0] - CNTBASE;

    if(cnt < 0 || cnt > MAXTOKENS)
    {
        return(PAM_IGNORE);
    }

    if (cnt < 1)
    {
        log_message(LOG_EMERG, pamh, "No S/KEY tokens left!");
        return(PAM_AUTH_ERR);
    }

    memset(p,0x0,sizeof(p));

    memcpy(p,&buffer[1],HASHSZ_TEXT);

    if (strlen(p) != HASHSZ_TEXT)
    {
        return(PAM_IGNORE);
    }

    memset(next_hash,0x0,sizeof(next_hash));

    memcpy(next_hash,&buffer[33],HASHSZ_TEXT);

    if (strlen(p) != HASHSZ_TEXT)
    {
        return(PAM_IGNORE);
    }

    normalize(pwd);

    if (strlen(pwd) != HASHSZ_TEXT)
    {
        return(PAM_IGNORE);
    }

    if(do_hash(p,pwd,password_hash) == NULL)
    {
        return(PAM_IGNORE);
    }

    if(strncmp(next_hash, password_hash,HASHSZ_TEXT) != 0)
    {
        return(PAM_AUTH_ERR);
    }

    if(chmod(checkfile,S_IWUSR) != 0)
    {
        return(PAM_IGNORE);
    }

    fp = fopen (checkfile, "w");

    if (fp == NULL)
    {
        return(PAM_IGNORE);
    }

    if (fprintf(fp,"%c", ((--cnt) + CNTBASE)) != 1)
    {
        fclose(fp);
        return(PAM_IGNORE);
    }

    if(fprintf(fp,"%s", p) != HASHSZ_TEXT)
    {
        fclose(fp);
        return(PAM_IGNORE);
    }

    if(fprintf(fp,"%s", pwd) != HASHSZ_TEXT)
    {
        fclose(fp);
        return(PAM_IGNORE);
    }

    memset(pwd,0x0,sizeof(pwd));

    if (fclose(fp) != 0)
    {
        return(PAM_IGNORE);
    }

    if(chmod(checkfile,S_IRUSR) != 0)
    {
        return(PAM_IGNORE);
    }

    if (cnt < WARN_TOKENS)
    {
        log_message(LOG_WARNING, pamh, "Only %d S/KEY tokens left!", cnt);
    }

    return(PAM_SUCCESS);
}

/*
   PAM entry point for setting user credentials (that is, to actually
   establish the authenticated user's credentials to the service provider)
 */
/*int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}*/

/* PAM entry point for authentication token (password) changes */
/*int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}*/
