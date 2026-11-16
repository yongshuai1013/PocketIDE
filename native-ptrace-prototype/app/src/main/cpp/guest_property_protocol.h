#ifndef GINGERVM_GUEST_PROPERTY_PROTOCOL_H
#define GINGERVM_GUEST_PROPERTY_PROTOCOL_H

#include <stdint.h>

/* Android 2.3.7_r1 Bionic sys/system_properties.h and _system_properties.h:
 * PROP_NAME_MAX=32, PROP_VALUE_MAX=92, PROP_MSG_SETPROP=1. The API10
 * libcutils property client sends one fixed-size prop_msg over the connected
 * AF_UNIX stream; init receives sizeof(prop_msg) and closes the accepted fd. */
#define GUEST_API10_PROP_NAME_MAX 32u
#define GUEST_API10_PROP_VALUE_MAX 92u
#define GUEST_API10_PROP_MSG_SETPROP 1u

struct guest_api10_prop_msg {
    uint32_t cmd;
    char name[GUEST_API10_PROP_NAME_MAX];
    char value[GUEST_API10_PROP_VALUE_MAX];
};

#if defined(__cplusplus)
static_assert(sizeof(guest_api10_prop_msg) == 128u,
              "API10 property set message must remain exactly 128 bytes");
#else
_Static_assert(sizeof(struct guest_api10_prop_msg) == 128u,
               "API10 property set message must remain exactly 128 bytes");
#endif

#endif
