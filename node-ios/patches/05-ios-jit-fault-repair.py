#!/usr/bin/env python3
import io
import os
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("NODE_TREE", ".")
DARWIN = os.path.join(SRC, "deps/v8/src/base/platform/platform-darwin.cc")
PLATFORM_H = os.path.join(SRC, "deps/v8/src/base/platform/platform.h")
NODE_CC = os.path.join(SRC, "src/node.cc")
MARK = "FixJitFetchFault"

def read(p):
    return io.open(p, encoding="utf-8", errors="replace").read()

def write(p, s):
    io.open(p, "w", encoding="utf-8", newline="\n").write(s)

def fail(msg):
    sys.exit("  05 FAIL: " + msg)

# ------------------------------------------------------------------ darwin.cc
s = read(DARWIN)
if MARK in s:
    print("  platform-darwin.cc: already repairs faults")
else:
    anchor = "V8_BASE_EXPORT void ApplyJitProtectionTo(void* addr, size_t size) {"
    if anchor not in s:
        fail("platform-darwin.cc: ApplyJitProtectionTo not found")
    helpers = '''// DSH-IOS-JITFIX: the two halves of the fault repair.
namespace {
int RepairPage(uintptr_t addr, int prot) {
  if (g_code_base == nullptr || g_code_size == 0) return 0;
  const uintptr_t base = reinterpret_cast<uintptr_t>(g_code_base);
  if (addr < base || addr >= base + g_code_size) return 0;
  void* page = reinterpret_cast<void*>(addr & ~(kPage - 1));
  if (mprotect(page, kPage, prot) != 0) return 0;
  static int reported = 0;
  if (++reported <= 8) {
    fprintf(stderr, "[jitscope] repaired %p as %s (#%d)\\n", page,
            prot == (PROT_READ | PROT_EXEC) ? "executable" : "writable", reported);
  }
  return 1;
}
}  // namespace

int FixJitFetchFault(void* addr) {
  return RepairPage(reinterpret_cast<uintptr_t>(addr), PROT_READ | PROT_EXEC);
}

int FixJitWriteFault(void* addr) {
  const int fixed =
      RepairPage(reinterpret_cast<uintptr_t>(addr), PROT_READ | PROT_WRITE);
  if (fixed) {
    g_executable = 0;
  }
  return fixed;
}

'''
    s = s.replace(anchor, helpers + anchor, 1)
    write(DARWIN, s)
    print("  platform-darwin.cc: fetch and write fault repair added")

# ----------------------------------------------------------------- platform.h
s = read(PLATFORM_H)
if "FixJitFetchFault" in s:
    print("  platform.h: already declares the repairs")
else:
    anchor = "V8_BASE_EXPORT void ApplyJitProtectionTo(void* addr, size_t size);"
    if anchor not in s:
        fail("platform.h: ApplyJitProtectionTo declaration not found")
    s = s.replace(
        anchor,
        anchor + "\n"
        "V8_BASE_EXPORT int FixJitFetchFault(void* addr);\n"
        "V8_BASE_EXPORT int FixJitWriteFault(void* addr);", 1)
    write(PLATFORM_H, s)
    print("  platform.h: repairs declared")

# ------------------------------------------------------------------- node.cc
s = read(NODE_CC)
if "FixJitFetchFault" in s:
    print("  node.cc: already hooked up, enforcing reinterpret_cast")
    s = re.sub(r'static_cast<uintptr_t>\s*\(\s*uc->uc_mcontext->__ss\.__pc\s*\)', 'reinterpret_cast<uintptr_t>(uc->uc_mcontext->__ss.__pc)', s)
    s = re.sub(r'static_cast<uintptr_t>\s*\(\s*reinterpret_cast<void\*>\s*\(\s*uc->uc_mcontext->__es\.__far\s*\)\s*\)', 'reinterpret_cast<uintptr_t>(uc->uc_mcontext->__es.__far)', s)
    write(NODE_CC, s)
else:
    anchor = '#include "node.h"'
    if anchor not in s:
        fail("node.cc: #include \"node.h\" not found")
    decl = anchor + '''
namespace v8 {
namespace base {
int FixJitFetchFault(void* addr);
int FixJitWriteFault(void* addr);
}  // namespace base
}  // namespace v8
'''
    s = s.replace(anchor, decl, 1)

    probe = ("void TrapWebAssemblyOrContinue(int signo, siginfo_t* info, void* ucontext) {\n"
             "  if (!v8::TryHandleWebAssemblyTrapPosix(signo, info, ucontext)) {")
    if probe not in s:
        fail("node.cc: TrapWebAssemblyOrContinue anchor not found")
    hooked = '''void TrapWebAssemblyOrContinue(int signo, siginfo_t* info, void* ucontext) {
#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
  {
    const ucontext_t* uc = static_cast<const ucontext_t*>(ucontext);
    const uintptr_t pc = reinterpret_cast<uintptr_t>(uc->uc_mcontext->__ss.__pc);
    const uintptr_t far = reinterpret_cast<uintptr_t>(uc->uc_mcontext->__es.__far);
    if (pc == far && ::v8::base::FixJitFetchFault(reinterpret_cast<void*>(pc))) {
      return;
    }
    if (pc != far && ::v8::base::FixJitWriteFault(reinterpret_cast<void*>(far))) {
      return;
    }
  }
#endif
  if (!v8::TryHandleWebAssemblyTrapPosix(signo, info, ucontext)) {'''
    s = s.replace(probe, hooked, 1)
    write(NODE_CC, s)
    print("  node.cc: handler repairs the page and retries")

print("  05 done")
