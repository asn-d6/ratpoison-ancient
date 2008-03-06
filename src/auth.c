#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include "auth.h"


int check_conv (int num_msg, struct pam_message **msg,struct pam_response **resp, void *app_data){
     struct pam_message *m = *msg;
     struct pam_response *r;
     int i;
     char *ct_passwd;
     if ((num_msg <= 0) || (num_msg >= PAM_MAX_NUM_MSG)) {
         fprintf (stderr, "Invalid number of messages\n");
         *resp = NULL;
         return (PAM_CONV_ERR);
     }
     if ((*resp = r = calloc (num_msg, sizeof (struct pam_response))) == NULL)
         return (PAM_BUF_ERR);
     for (i = 0; i < num_msg; i++) {
         switch (m->msg_style) {
             case PAM_PROMPT_ECHO_OFF:
                 ct_passwd = passtok;
                 r->resp = strdup (ct_passwd);
                 m++;
                 r++;
                 break;
             case PAM_PROMPT_ECHO_ON:
                 if (m->msg)
                     fputs (m->msg, stdout);
                 r->resp = NULL;
                 m++;
                 r++;
                 break;
             case PAM_ERROR_MSG:
                 if (m->msg)
                     fprintf (stderr, "%s\n", m->msg);
                 m++;
                 r++;
                 break;
             case PAM_TEXT_INFO:
                 if (m->msg)
                     printf ("%s\n", m->msg);
                 m++;
                 r++;
                 break;
         }
         return (PAM_SUCCESS);
     }
}
int check_auth(void){

        pam_handle_t *pamh;
        struct passwd *user_info;
        int pam_status;
        char *user;

        static struct pam_conv conv = {check_conv,NULL};

        if((user_info=getpwuid(getuid()))==NULL){
            perror("getpwuid");
            exit(EXIT_FAILURE);
        }
        pam_status = pam_start("login", user_info->pw_name, &conv, &pamh);
                

        if (pam_status == PAM_SUCCESS)
            pam_status = pam_authenticate(pamh,PAM_SILENT);

        if (pam_status == PAM_SUCCESS){
            pam_get_item(pamh, PAM_USER, (const void **)&user);
            fprintf(stdout, "Greetings %s\n", user);
        } 
        else{
                printf("%s\n", pam_strerror(pamh, pam_status));
        }

        pam_end(pamh, pam_status);
        return pam_status;
}

