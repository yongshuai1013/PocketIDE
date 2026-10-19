#include "NativeCompilerBridge.h"
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#if defined(POCKETIDE_EMBEDDED_LLVM) && POCKETIDE_EMBEDDED_LLVM
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticIDs.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/Job.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/CodeGen/CodeGenAction.h"
#include "llvm/Support/Casting.h"
#include "lld/Common/Driver.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/IntrusiveRefCntPtr.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetSelect.h"
LLD_HAS_DRIVER(macho)
#endif

namespace {
constexpr int32_t kUnavailable = 2;
constexpr int32_t kInvalid = 1;
NCB_Result result(int32_t status, const std::string &text) {
  NCB_Result r{};
  r.status = status;
  r.diagnostics.length = text.size();
  r.diagnostics.text = static_cast<char *>(std::malloc(text.size() + 1));
  if (r.diagnostics.text) {
    std::memcpy(r.diagnostics.text, text.data(), text.size());
    r.diagnostics.text[text.size()] = '\0';
  } else { r.diagnostics.length = 0; r.status = kInvalid; }
  return r;
}
bool validArgs(int32_t argc, const char *const *argv) {
  if (argc < 1 || argc > 512 || !argv) return false;
  for (int32_t i = 0; i < argc; ++i) if (!argv[i]) return false;
  return true;
}
#if defined(POCKETIDE_EMBEDDED_LLVM) && POCKETIDE_EMBEDDED_LLVM
std::mutex compilerMutex;
bool linkerMayRunAgain = true;
// This ABI is deliberately a narrow C object-build interface, not an arbitrary driver.
bool safeCompileArg(const char *arg) {
  std::string a(arg);
  if (a.empty() || a[0] == '@') return false;
  if (a[0] != '-') return true;
  static const char *allowed[] = {
    "-c", "-fno-color-diagnostics", "-fno-modules", "-ffreestanding", "-fno-builtin",
    "-target", "-isysroot", "-resource-dir", "-o", "-std=c17",
    "-miphoneos-version-min=15.0"
  };
  for (auto x : allowed) if (a == x) return true;
  return false;
}
bool safeLinkArg(const char *arg) {
  std::string a(arg);
  if (a.empty() || a[0] == '@') return false;
  if (a[0] != '-') return true;
  static const char *allowed[] = {"-arch", "-syslibroot", "-platform_version", "-no_adhoc_codesign", "-o", "-lSystem", "-e"};
  for (auto x : allowed) if (a == x) return true;
  return false;
}
#endif
}

extern "C" NCB_Capabilities ncb_get_capabilities(void) {
#if defined(POCKETIDE_EMBEDDED_LLVM) && POCKETIDE_EMBEDDED_LLVM
  std::lock_guard<std::mutex> lock(compilerMutex);
  return {NCB_ABI_VERSION, static_cast<uint32_t>(NCB_CAP_COMPILE | NCB_CAP_EMBEDDED_LLVM | (linkerMayRunAgain ? NCB_CAP_LINK : 0))};
#else
  return {NCB_ABI_VERSION, 0};
#endif
}

extern "C" NCB_Result ncb_compile_driver_argv(int32_t argc, const char *const *argv) {
  if (!validArgs(argc, argv)) return result(kInvalid, "invalid compile argv");
#if !defined(POCKETIDE_EMBEDDED_LLVM) || !POCKETIDE_EMBEDDED_LLVM
  return result(kUnavailable, "NativeCompilerBridge built without embedded LLVM");
#else
  std::lock_guard<std::mutex> lock(compilerMutex);
  if (std::string(argv[0]) != "clang") return result(kInvalid, "expected clang at argv[0]");
  for (int i = 1; i < argc; ++i) if (!safeCompileArg(argv[i])) return result(kInvalid, std::string("unsupported compile argument: ") + argv[i]);
  static const bool initialized = [] {
    llvm::InitializeAllTargetInfos(); llvm::InitializeAllTargets();
    llvm::InitializeAllTargetMCs(); llvm::InitializeAllAsmPrinters(); return true;
  }();
  (void)initialized;
  std::string text;
  llvm::raw_string_ostream diagnostics(text);
  llvm::IntrusiveRefCntPtr<clang::DiagnosticOptions> diagOpts(new clang::DiagnosticOptions());
  auto printer = std::make_unique<clang::TextDiagnosticPrinter>(diagnostics, &*diagOpts);
  llvm::IntrusiveRefCntPtr<clang::DiagnosticsEngine> diags(new clang::DiagnosticsEngine(new clang::DiagnosticIDs(), &*diagOpts, printer.get(), false));
  clang::driver::Driver driver(argv[0], llvm::sys::getDefaultTargetTriple(), *diags);
  driver.setCheckInputsExist(true);
  std::vector<const char *> args(argv, argv + argc);
  std::unique_ptr<clang::driver::Compilation> comp(driver.BuildCompilation(args));
  if (!comp || diags->hasErrorOccurred()) return result(kInvalid, text.empty() ? "clang driver rejected arguments" : text);
  auto &jobs = comp->getJobs();
  if (jobs.size() != 1) return result(kInvalid, "compile requires exactly one frontend job");
  auto *command = llvm::dyn_cast<clang::driver::Command>(&*jobs.begin());
  if (!command) return result(kInvalid, "compile request did not produce a direct clang cc1 command");
  const auto &cc1 = command->getArguments();
  if (cc1.empty() || std::string(cc1.front()) != "-cc1") return result(kInvalid, "invalid generated cc1 command");
  std::vector<const char *> cc1args(cc1.begin() + 1, cc1.end());
  clang::CompilerInvocation invocation;
  if (!clang::CompilerInvocation::CreateFromArgs(invocation, cc1args, *diags, argv[0]) || diags->hasErrorOccurred())
    return result(kInvalid, text.empty() ? "clang frontend rejected arguments" : text);
  clang::CompilerInstance ci;
  ci.setInvocation(std::make_shared<clang::CompilerInvocation>(std::move(invocation)));
  ci.createDiagnostics(printer.get(), false);
  if (!ci.hasDiagnostics()) return result(kInvalid, "unable to initialize clang diagnostics");
  clang::EmitObjAction action;
  bool ok = ci.ExecuteAction(action);
  return result(ok ? 0 : kInvalid, text.empty() && !ok ? "clang frontend compilation failed" : text);
#endif
}

extern "C" NCB_Result ncb_link_lld_argv(int32_t argc, const char *const *argv) {
  if (!validArgs(argc, argv)) return result(kInvalid, "invalid link argv");
#if !defined(POCKETIDE_EMBEDDED_LLVM) || !POCKETIDE_EMBEDDED_LLVM
  return result(kUnavailable, "NativeCompilerBridge built without embedded LLVM");
#else
  std::lock_guard<std::mutex> lock(compilerMutex);
  if (!linkerMayRunAgain) return result(kInvalid, "LLD cannot safely be called again; restart the app before building again");
  if (std::string(argv[0]) != "ld64.lld") return result(kInvalid, "expected ld64.lld at argv[0]");
  for (int i = 1; i < argc; ++i) if (!safeLinkArg(argv[i])) return result(kInvalid, std::string("unsupported linker argument: ") + argv[i]);
  std::string text;
  llvm::raw_string_ostream diagnostics(text);
  std::vector<const char *> args(argv, argv + argc);
  lld::DriverDef drivers[] = {{lld::Flavor::Darwin, lld::macho::link}};
  auto r = lld::lldMain(args, diagnostics, diagnostics, drivers);
  linkerMayRunAgain = r.canRunAgain;
  if (!r.canRunAgain) {
    text += "\nLLD state is not reusable. Restart the app before the next build.";
    return result(kInvalid, text);
  }
  return result(r.retCode == 0 ? 0 : kInvalid, text.empty() && r.retCode != 0 ? "LLD Mach-O link failed" : text);
#endif
}

extern "C" void ncb_dispose_diagnostics(NCB_Diagnostics *d) {
  if (!d) return;
  std::free(d->text);
  d->text = nullptr;
  d->length = 0;
}
