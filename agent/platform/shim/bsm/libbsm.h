#ifndef WISP_SHIM_BSM_H
#define WISP_SHIM_BSM_H
#include <sys/types.h>
typedef struct { unsigned int val[8]; } audit_token_t;
pid_t audit_token_to_pid(audit_token_t t);
uid_t audit_token_to_euid(audit_token_t t);
#endif
