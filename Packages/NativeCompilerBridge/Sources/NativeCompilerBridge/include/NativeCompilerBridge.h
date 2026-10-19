#ifndef POCKETIDE_NATIVE_COMPILER_BRIDGE_H
#define POCKETIDE_NATIVE_COMPILER_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NCB_ABI_VERSION 1u

typedef struct NCB_Diagnostics {
  char *text; /* UTF-8; owned by result; release with ncb_dispose_diagnostics */
  size_t length;
} NCB_Diagnostics;

typedef struct NCB_Result {
  int32_t status; /* 0 success; nonzero failure */
  NCB_Diagnostics diagnostics;
} NCB_Result;

typedef struct NCB_Capabilities {
  uint32_t abi_version;
  uint32_t flags;
} NCB_Capabilities;

enum {
  NCB_CAP_COMPILE = 1u << 0,
  NCB_CAP_LINK = 1u << 1,
  NCB_CAP_EMBEDDED_LLVM = 1u << 2
};

/* argv is an argument vector (not a shell command); argc must be >= 1. */
NCB_Capabilities ncb_get_capabilities(void);
NCB_Result ncb_compile_driver_argv(int32_t argc, const char *const *argv);
NCB_Result ncb_link_lld_argv(int32_t argc, const char *const *argv);
void ncb_dispose_diagnostics(NCB_Diagnostics *diagnostics);

#ifdef __cplusplus
}
#endif
#endif
