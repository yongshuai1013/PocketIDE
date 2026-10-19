#include "NativeCompilerBridge.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

static void check(NCB_Result r, bool success, const char *diagnostic = nullptr) {
  if ((r.status == 0) != success || (diagnostic && (!r.diagnostics.text || !std::strstr(r.diagnostics.text, diagnostic)))) {
    std::fprintf(stderr, "unexpected status %d: %s\n", r.status, r.diagnostics.text ? r.diagnostics.text : "(none)");
    std::abort();
  }
  ncb_dispose_diagnostics(&r.diagnostics);
}
static NCB_Result compile(const std::string &source, const std::string &object) {
  const char *args[] = {"clang", "-target", "arm64-apple-ios15.0", "-ffreestanding", "-fno-builtin", "-c", source.c_str(), "-o", object.c_str()};
  return ncb_compile_driver_argv(9, args);
}
static NCB_Result link(const std::string &object, const std::string &executable, const char *entry = "_main") {
  const char *args[] = {"ld64.lld", "-arch", "arm64", "-platform_version", "ios", "15.0", "18.5", "-e", entry, "-no_adhoc_codesign", object.c_str(), "-o", executable.c_str()};
  return ncb_link_lld_argv(13, args);
}
static void validate(const std::string &path, unsigned fileType) {
  unsigned char header[32]{};
  std::ifstream input(path, std::ios::binary);
  input.read(reinterpret_cast<char *>(header), 32);
  assert(input.gcount() == 32 && header[0] == 0xcf && header[1] == 0xfa && header[2] == 0xed && header[3] == 0xfe);
  assert(header[4] == 12 && header[7] == 1 && header[12] == fileType);
}
int main(int argc, char **argv) {
  assert(argc == 2);
  const auto capabilities = ncb_get_capabilities();
  assert(capabilities.flags == (NCB_CAP_COMPILE | NCB_CAP_LINK | NCB_CAP_EMBEDDED_LLVM));
  const std::string directory = std::string(argv[1]) + "/paths with spaces";
  std::filesystem::create_directories(directory);
  const auto source = directory + "/main input.c";
  const auto object = directory + "/main output.o";
  const auto executable = directory + "/main executable";
  { std::ofstream f(source); f << "int main(void){return 7;}\n"; }
  check(compile(source, object), true);
  check(compile(source, object), true);
  validate(object, 1);
  { std::ofstream f(source); f << "int main( {\n"; }
  check(compile(source, object), false, "error:");
  { std::ofstream f(source); f << "int main(void){return 7;}\n"; }
  check(compile(source, object), true);
  for (const char *flag : {"-fplugin=/tmp/no.so", "-fpass-plugin=/tmp/no.so", "-Xclang", "@/tmp/options"}) {
    const char *bad[] = {"clang", flag, source.c_str()};
    check(ncb_compile_driver_argv(3, bad), false, "unsupported compile argument");
  }
  check(link(object, executable), true);
  validate(executable, 2);
  check(link(object, executable, "_does_not_exist"), false, "undefined");
  check(link(object, executable), true);
  check(link(object, executable), true);
  validate(executable, 2);
  std::vector<std::thread> threads;
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back([&, i] {
      const auto output = directory + "/concurrent " + std::to_string(i) + ".o";
      check(compile(source, output), true);
      validate(output, 1);
    });
  }
  for (auto &thread : threads) thread.join();
  std::puts("Embedded LLVM host smoke passed: real arm64 objects/executable, repeat calls, captured diagnostics, error recovery, plugin/response-file denial, concurrent callers.");
}
