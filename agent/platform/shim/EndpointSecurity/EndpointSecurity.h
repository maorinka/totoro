/* Documented-API declarations for compile-checking sensor_macos.m on a
 * non-macOS host. NOT Apple's SDK: on macOS you link the real framework.
 * Shapes follow developer.apple.com/documentation/endpointsecurity. */
#ifndef WISP_SHIM_ES_H
#define WISP_SHIM_ES_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <bsm/libbsm.h>

typedef struct es_client_s es_client_t;
typedef struct { size_t length; const char *data; } es_string_token_t;
typedef struct { es_string_token_t path; } es_file_t;
typedef struct {
    audit_token_t audit_token;
    pid_t ppid;
    es_file_t *executable;
} es_process_t;
typedef struct { es_process_t *target; } es_event_exec_t;
typedef enum { ES_EVENT_TYPE_NOTIFY_EXEC = 9 } es_event_type_t;
typedef struct {
    es_event_type_t event_type;
    union { es_event_exec_t exec; } event;
} es_message_t;
typedef enum { ES_NEW_CLIENT_RESULT_SUCCESS = 0 } es_new_client_result_t;
typedef enum { ES_RETURN_SUCCESS = 0, ES_RETURN_ERROR = 1 } es_return_t;

es_new_client_result_t es_new_client(es_client_t **client,
        void (^handler)(es_client_t *, const es_message_t *));
es_return_t es_subscribe(es_client_t *client, const es_event_type_t *events, uint32_t count);
uint32_t es_exec_arg_count(const es_event_exec_t *event);
es_string_token_t es_exec_arg(const es_event_exec_t *event, uint32_t index);
#endif
