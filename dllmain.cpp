#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <windows.h>
#include <d3d9.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <direct.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

#include "../third_party/SkipHook/skiphook.h"
#include "../third_party/imgui/imgui.h"
#include "../third_party/imgui/backends/imgui_impl_dx9.h"
#include "../third_party/imgui/backends/imgui_impl_win32.h"
#include "netc.h"

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

static_assert(sizeof(void*) == 4, "Win32/x86 only.");

#define MTA_LOG_PATH "C:\\mta.log"
#define RM_MODS_DIR  "C:\\Mods"

/* ------------------------------------------------------------------ log */
static void mta_logf(const char* tag, const char* fmt, ...) {
    char msg[768];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char line[1024];
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02u:%02u:%02u.%03u][%s] %s\n",
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
        (unsigned)st.wMilliseconds, tag ? tag : "log", msg);

    OutputDebugStringA(line);
    FILE* f = nullptr;
    if (fopen_s(&f, MTA_LOG_PATH, "a") == 0 && f) {
        fputs(line, f);
        fclose(f);
    }
}

/* ----------------------------------------------------------- memory/PE */
static uint32_t g_minAppPtr = 0x00010000u;
static uint32_t g_maxAppPtr = 0xFFFEFFFFu;

static void init_ptr_bounds() {
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    uint32_t lo = (uint32_t)(uintptr_t)si.lpMinimumApplicationAddress;
    uint32_t hi = (uint32_t)(uintptr_t)si.lpMaximumApplicationAddress;
    if (lo >= 0x10000u) g_minAppPtr = lo;
    if (hi > g_minAppPtr) g_maxAppPtr = hi;
}

static inline bool is_valid_ptr(uint32_t p) {
    return p >= g_minAppPtr && p <= g_maxAppPtr;
}

static uint32_t rd32(uint32_t a) {
    if (!is_valid_ptr(a)) return 0;
    uint32_t v = 0;
    __try { v = *(uint32_t*)(uintptr_t)a; }
    __except (EXCEPTION_EXECUTE_HANDLER) { v = 0; }
    return v;
}

static bool rd_bytes(uint32_t a, void* out, size_t len) {
    if (!is_valid_ptr(a) || !len) return false;
    __try {
        memcpy(out, (const void*)(uintptr_t)a, len);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool get_module_bounds(const char* mod_name, uint32_t& base_out, uint32_t& end_out) {
    HMODULE hMod = GetModuleHandleA(mod_name);
    if (!hMod) return false;
    __try {
        uint32_t base = (uint32_t)(uintptr_t)hMod;
        auto* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        base_out = base;
        end_out  = base + nt->OptionalHeader.SizeOfImage;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static void writable_range(uint32_t base, uint32_t end, uint32_t& s_out, uint32_t& e_out) {
    s_out = e_out = 0;
    __try {
        auto* dos = (IMAGE_DOS_HEADER*)base;
        auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        uint32_t best = 0;
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
            if ((sec[s].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sec[s].Characteristics & IMAGE_SCN_MEM_READ)) {
                uint32_t a = base + sec[s].VirtualAddress;
                uint32_t b = a + sec[s].Misc.VirtualSize;
                if (b > end) b = end;
                if (b > a && (b - a) > best) {
                    best = b - a;
                    s_out = a;
                    e_out = b;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

/* ----------------------------------------------------------- scan/patch */
static void* scan_mask(HMODULE mod, const char* pattern, const char* mask, unsigned occurrence = 1) {
    if (!mod || !pattern || !mask) return nullptr;
    size_t len = strlen(mask);
    if (!len) return nullptr;

    uint8_t* base = (uint8_t*)mod;
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    unsigned found = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint8_t* s = base + sec[i].VirtualAddress;
        size_t sz = sec[i].Misc.VirtualSize;
        if (sz < len) continue;
        size_t last = sz - len;
        for (size_t o = 0; o <= last; ++o) {
            bool ok = true;
            for (size_t k = 0; k < len; ++k) {
                if (mask[k] == '?') continue;
                if (s[o + k] != (unsigned char)pattern[k]) { ok = false; break; }
            }
            if (ok && ++found == occurrence) return s + o;
        }
    }
    return nullptr;
}

struct PatchRecord {
    void*   addr;
    uint8_t original[5];
    void*   detour;
};
static PatchRecord g_patches[96];
static int         g_patch_count = 0;

template<typename T>
static bool patch_jmp(void* addr, T detour, T& original_out) {
    if (!addr || !detour) return false;
    T tramp = skip_hook::make_full_hook<T>((uint64_t)addr, 5);
    if (!tramp) return false;

    DWORD old = 0;
    if (!VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &old))
        return false;

    if (g_patch_count < 96) {
        g_patches[g_patch_count].addr = addr;
        memcpy(g_patches[g_patch_count].original, addr, 5);
        g_patches[g_patch_count].detour = (void*)detour;
        ++g_patch_count;
    }

    uint8_t* p = (uint8_t*)addr;
    p[0] = 0xE9;
    *(int32_t*)(p + 1) = (int32_t)((uintptr_t)detour - (uintptr_t)addr - 5);

    VirtualProtect(addr, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, 5);

    original_out = tramp;
    return true;
}

static void unpatch_all() {
    for (int i = 0; i < g_patch_count; ++i) {
        DWORD old = 0;
        if (VirtualProtect(g_patches[i].addr, 5, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(g_patches[i].addr, g_patches[i].original, 5);
            VirtualProtect(g_patches[i].addr, 5, old, &old);
            FlushInstructionCache(GetCurrentProcess(), g_patches[i].addr, 5);
        }
    }
    g_patch_count = 0;
}

/* --------------------------------------------------------- netc detours */
static uint32_t g_netc_base = 0;
static uint32_t g_netc_size = 0;

static void*          g_sendPacketAddr = nullptr;
static void* volatile g_cnetPtr        = nullptr;
static int   volatile g_cnetSendIdx    = -1;
static uint32_t       g_cnetPollTick   = 0;
static char           g_cnetServer[96] = "";
static bool  volatile g_cnetConn       = false;
static CRITICAL_SECTION g_cnetCs;
static volatile LONG    g_cnetCsReady  = 0;

static bool cnet_valid_str(const char* s, char* out, size_t cap) {
    if (!s || !s[0]) return false;
    size_t i = 0;
    for (; i + 1 < cap && s[i]; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c >= 0x7F) return false;
        out[i] = (char)c;
    }
    if (s[i] != 0) return false;
    out[i] = 0;
    return i >= 3;
}

static void cnet_try_capture(void* ecx) {
    if (!ecx || g_cnetPtr || !g_sendPacketAddr || !g_netc_base || !g_netc_size) return;
    uintptr_t p = (uintptr_t)ecx;
    if (!is_valid_ptr((uint32_t)p)) return;
    __try {
        uint32_t vt = *(uint32_t*)p;
        if (vt < g_netc_base || vt + 16u * 4u > g_netc_base + g_netc_size) return;
        uint32_t want = (uint32_t)(uintptr_t)g_sendPacketAddr;
        for (int idx = 8; idx <= 14; ++idx) {
            if (((uint32_t*)vt)[idx] == want) {
                uint32_t fnConn = ((uint32_t*)vt)[idx - 6];
                uint32_t fnSrv  = ((uint32_t*)vt)[idx + 2];
                if (fnConn >= g_netc_base && fnConn < g_netc_base + g_netc_size &&
                    fnSrv  >= g_netc_base && fnSrv  < g_netc_base + g_netc_size) {
                    g_cnetSendIdx = idx;
                    g_cnetPtr     = ecx;
                    mta_logf("net", "CNet capturado @ %p (SendPacket slot=%d)", ecx, idx);
                }
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void cnet_poll_main_thread(bool force) {
    void* cnet = g_cnetPtr;
    int idx = g_cnetSendIdx;
    if (!cnet || idx < 6) return;
    uint32_t now = GetTickCount();
    if (!force && (now - g_cnetPollTick < 400u)) return;
    g_cnetPollTick = now;

    using fn_IsConn = bool(__thiscall*)(void*);
    using fn_GetSrv = const char*(__thiscall*)(void*, bool);

    char buf[96] = "";
    bool conn = false;
    bool ok = false;
    __try {
        uint32_t vt = *(uint32_t*)cnet;
        if (vt >= g_netc_base && vt + (uint32_t)(idx + 3) * 4u <= g_netc_base + g_netc_size) {
            auto pConn = (fn_IsConn)(uintptr_t)((uint32_t*)vt)[idx - 6];
            auto pSrv  = (fn_GetSrv)(uintptr_t)((uint32_t*)vt)[idx + 2];
            conn = pConn(cnet);
            const char* srv = pSrv(cnet, true);
            if (srv && srv[0]) cnet_valid_str(srv, buf, sizeof(buf));
            ok = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }

    if (ok && InterlockedCompareExchange(&g_cnetCsReady, 0, 0)) {
        EnterCriticalSection(&g_cnetCs);
        g_cnetConn = conn;
        snprintf(g_cnetServer, sizeof(g_cnetServer), "%s", buf);
        LeaveCriticalSection(&g_cnetCs);
    }
}

using fn_send_packet    = bool(__fastcall*)(void*, void*, unsigned char, void*, int, int, int);
using fn_send_lua_check = int (__fastcall*)(DWORD*, void*, unsigned __int8);
using fn_sub_102BDFDE   = int (__cdecl*)(__int64*);

using fn_ac_check_hooking_function = bool (__fastcall*)(void*, void*);
using fn_ac_send_client_kick       = int  (__fastcall*)(void*, void*, DWORD*, int);
using fn_add_ac_log_path_hook      = int  (__stdcall*)(const char*);
using fn_ac_watchdog               = int  (__stdcall*)(void*);

static fn_send_packet    g_o_send_packet    = nullptr;
static fn_send_lua_check g_o_send_lua_check = nullptr;
static fn_sub_102BDFDE   g_o_sub_102BDFDE   = nullptr;

static bool   __cdecl    d_advanced_memory_validator(int, int, int, DWORD*, int*, DWORD*)           { return true; }
static int    __fastcall d_network_packet_state_validator(DWORD*, void*, int, unsigned __int8, unsigned __int16) { return 1; }
static char   __stdcall  d_animation_packet_validator(int*)                                         { return 1; }

static bool __fastcall d_send_packet(void* ECX, void* EDX, unsigned char id, void* bs,
                                     int prio, int rel, int ord) {
    if (ECX && !g_cnetPtr) cnet_try_capture(ECX);
    if (g_cnetPtr) cnet_poll_main_thread(false);
    return g_o_send_packet ? g_o_send_packet(ECX, EDX, id, bs, prio, rel, ord) : false;
}

static int    __cdecl    d_send_report(char, void*, int, int, int) { return 1; }
static HANDLE __stdcall  d_send_driver_report(LPCWSTR, ACCESS_MASK, DWORD, LPSECURITY_ATTRIBUTES, ULONG, ULONG) { return NULL; }
static void   __fastcall d_send_client_kick(int, int, unsigned int, int, DWORD*, int) {}
static void   __fastcall d_send_client_local_kick(int, char) {}
static void   __fastcall d_send_client_ban(int, int, int*, int*, char, int) {}

static int __fastcall d_send_lua_check(DWORD* inst, void* edx, unsigned __int8 chk) {
    *(int*)(inst + 46) = 0;
    *(int*)(inst + 47) = 0;
    return g_o_send_lua_check ? g_o_send_lua_check(inst, edx, chk) : 0;
}

static void         __fastcall d_sub_10056A50(void*, void*) {}
static unsigned int __fastcall d_sub_10293EC0(void*, void*, int) { return 1; }
static int          __fastcall d_sub_10159D50(void*, void*) { return 1; }
static int          __cdecl    d_sub_10141000(void*) { return 1; }
static int          __fastcall d_sub_101731D0(void*, void*, int, void*, int, const char*, const char*) { return 1; }
static bool         __cdecl    d_sub_1028CB90() { return true; }
static bool         __cdecl    d_detect_hook_new2(char*) { return false; }
static bool         __cdecl    d_detect_hook_new(char*)  { return false; }
static char         __cdecl    d_detect_hook(char*)      { return 0; }
static void         __cdecl    d_sub_1006CC80(const char*) {}
static char         __fastcall d_bypassnew(void*, void*, int, int) { return 1; }
static int          __fastcall d_bypass(void*, void*, int, int)    { return 1; }
static int          __fastcall d_sub_new(unsigned int, void*, int) { return 1; }
static int          __stdcall  d_send_crash_hook(int)              { return 1; }
static unsigned int __fastcall d_sub_100D57B0(int, int, unsigned int) { return 0; }

static int __cdecl d_sub_102BDFDE(__int64* a1) {
    static __int64 tempo = 0;
    if (tempo == 0 && g_o_sub_102BDFDE) g_o_sub_102BDFDE(&tempo);
    if (a1) *a1 = tempo;
    return (int)tempo;
}

static LONG  __stdcall  d_veh_stack(void*)                         { return 0; }
static DWORD __stdcall  d_ac_start_watchdog(void*)                 { return 0; }
static bool  __fastcall d_ac_check_hooking_function(void*, void*)  { return false; }
static int   __fastcall d_ac_send_client_kick(void*, void*, DWORD*, int) { return 1; }
static int   __stdcall  d_add_ac_log_path_hook(const char*)        { return 1; }
static int   __stdcall  d_ac_watchdog(void*)                       { return 0; }

static void __fastcall w_send_client_kick(int a, int b, unsigned int c, int d, DWORD* e, int f) {
    d_send_client_kick(a, b, c, d, e, f);
}
static void __fastcall w_send_client_local_kick(int a, char b) {
    d_send_client_local_kick(a, b);
}
static void __fastcall w_send_client_ban(int a, int b, int* c, int* d, char e, int f) {
    d_send_client_ban(a, b, c, d, e, f);
}

static unsigned g_ok = 0, g_miss = 0, g_fail = 0;

template<typename T>
static bool try_install_global(const char* name, const char* pat, const char* msk,
                               unsigned occ, T detour, T& original_out) {
    if (g_patch_count >= 92) { ++g_fail; return false; }
    void* addr = scan_mask(GetModuleHandleA("netc.dll"), pat, msk, occ);
    if (!addr) { ++g_miss; mta_logf("miss", "%s", name); return false; }
    if (!patch_jmp(addr, detour, original_out)) { ++g_fail; mta_logf("fail", "%s", name); return false; }
    if (!strcmp(name, "send_packet")) g_sendPacketAddr = addr;
    ++g_ok;
    mta_logf("hook", "%-32s @ %p", name, addr);
    return true;
}

template<typename T>
static bool try_install(const char* name, const char* pat, const char* msk, unsigned occ, T detour) {
    T dummy = nullptr;
    return try_install_global<T>(name, pat, msk, occ, detour, dummy);
}

template<typename T>
static bool try_install_rva(const char* name, uint32_t rva, T detour) {
    if (g_patch_count >= 92) { ++g_fail; return false; }
    if (!g_netc_base || !g_netc_size) { ++g_miss; return false; }
    uint32_t addr = g_netc_base + rva;
    if (!is_valid_ptr(addr) || addr + 5 > g_netc_base + g_netc_size) {
        ++g_miss;
        return false;
    }

    void* a = (void*)(uintptr_t)addr;
    __try { volatile uint8_t b = *(uint8_t*)a; (void)b; }
    __except (EXCEPTION_EXECUTE_HANDLER) { ++g_miss; return false; }

    T tramp = nullptr;
    if (!patch_jmp(a, detour, tramp)) {
        ++g_fail;
        mta_logf("fail", "%s rva=%05X", name, rva);
        return false;
    }
    ++g_ok;
    mta_logf("hook", "%-32s @ %08X (rva %05X)", name, addr, rva);
    return true;
}

/* ============================================================================
   MTA RESOURCE MANAGER — layouts verificados em multitheftauto/mtasa-blue:
   - CResourceManager:
       +0x00 CMappedList<CResource*> m_resources (SharedUtil.Misc.h):
             std::map<CResource*, int> m_Map  (+0x00, 8B IDL0 / 12B IDL>=1)
             std::list<CResource*>     m_List (+0x08 IDL0 / +0x0C IDL>=1)
       +0x10 std::map<ushort, CResource*> m_NetIdResourceMap
       +0x18 std::map<SString, CDownloadableResource*> m_ResourceFileMap
   - CResource (CResource.h, sem vptr; SString/CMtaVersion = 24B MSVC x86 IDL0):
       +0x00 ushort m_usNetID
       +0x04 uint   m_uiScriptID (CIdArray::PopUniqueId -> 0x02000000..0x02FFFFFF)
       +0x08 uint   m_startCounter
       +0x0C SString m_strResourceName
       +0x30 bool m_bActive | +0x31 m_bStarting | +0x32 m_bStopping
       +0xDC std::list<CResourceFile*>       m_ResourceFiles
       +0xE4 std::list<CResourceConfigItem*> m_ConfigFiles
   - CDownloadableResource (CDownloadableResource.h, virtual ~dtor -> vptr@+0x00):
       +0x00 vptr
       +0x04 CResource* m_pResource
       +0x08 eResourceType m_resourceType (0..6)
       +0x0C SString m_strName (caminho completo em disco)
       +0x24 SString m_strNameShort (caminho relativo do meta.xml)
   ============================================================================ */

/* forward declarations globais (usadas dentro de namespace rm) */
static HMODULE g_netc_pin = nullptr;
bool pin_netc();

namespace rm {

enum : uint32_t {
    RES_NETID       = 0x00u,
    RES_SCRIPTID    = 0x04u,
    RES_STARTCNT    = 0x08u,
    RES_NAME        = 0x0Cu,
    RES_ACTIVE      = 0x30u,
    RES_STOPPING    = 0x32u,
    RES_FILES_OFF   = 0xDCu,
    RES_FILES_COUNT = 512u,
    RES_MAX         = 2000u,
    RES_PROVE_MAX   = 12u,

    ID_ARRAY_BASE   = 0x02000000u,
    ID_ARRAY_LIMIT  = 0x10000000u,

    CFILE_OWNER     = 0x04u,
    CFILE_TYPE      = 0x08u,
    CFILE_NAME_FULL = 0x0Cu,
    CFILE_NAME_REL  = 0x24u,

    SCAN_CHUNK      = 1024u * 1024u,
    SCAN_TICK_MS    = 250u,
    TICK_MS         = 1000u,
    TCP_POLL_MS     = 2000u,
    COLLECT_EVERY   = 8u,
    TICK_BUDGET     = 1200000u
};

struct ListShape {
    uint32_t    listOff;       /* offset do std::list dentro do CResourceManager */
    uint32_t    headOff;       /* _Myhead dentro do std::list */
    uint32_t    sizeOff;       /* _Mysize dentro do std::list */
    uint32_t    valOff;        /* valor dentro do _List_node */
    uint32_t    mapHeadOff;    /* m_Map._Myhead (CMappedList) */
    uint32_t    mapSizeOff;    /* m_Map._Mysize */
    uint32_t    netMapHeadOff; /* m_NetIdResourceMap._Myhead */
    uint32_t    netMapSizeOff; /* m_NetIdResourceMap._Mysize */
    bool        hasMaps;
    bool        inlineSent;
    bool        encoded;
    const char* desc;
};

static ListShape kShapes[] = {
    { 0x08u, 0x00u, 0x04u, 0x08u, 0x00u, 0x04u, 0x10u, 0x14u, true,  false, false, "CMappedList IDL0 (+0x08)" },
    { 0x0Cu, 0x04u, 0x08u, 0x0Cu, 0x04u, 0x08u, 0x1Cu, 0x20u, true,  false, false, "CMappedList IDL>=1 (+0x0C)" },
    { 0x00u, 0x00u, 0x04u, 0x08u, 0x00u, 0x00u, 0x00u, 0x00u, false, false, false, "std::list IDL0 (+0x00)" },
    { 0x00u, 0x04u, 0x08u, 0x0Cu, 0x00u, 0x00u, 0x00u, 0x00u, false, false, false, "std::list IDL>=1 (+0x00)" },
    { 0x08u, 0x00u, 0x08u, 0x08u, 0x00u, 0x00u, 0x00u, 0x00u, false, true,  false, "inline sentinel (+0x08)" },
    { 0x00u, 0x00u, 0x08u, 0x08u, 0x00u, 0x00u, 0x00u, 0x00u, false, true,  false, "inline sentinel (+0x00)" },
    { 0x00u, 0x00u, 0x04u, 0x08u, 0x00u, 0x00u, 0x00u, 0x00u, false, false, false, "dynamic std::list" }
};
static int kShapesActiveN = 6;

struct Offsets {
    int      tried;
    char     module[32];
    char     modUsed[32];
    uint32_t mgrGlobal, mgrVt, resMgrField;
    uint32_t fn0, fn1, fn39;
    uint32_t clientBase, clientHi, inst;
    int      ok, loaded;
};

#define RM_OFF_DEF_MODULE   "client.dll"
#define RM_OFF_DEF_GLOBAL   0u
#define RM_OFF_DEF_VTABLE   0x3B5AC4u
#define RM_OFF_DEF_RESFIELD 0x74u
#define RM_OFF_DEF_FN0      0x64F10u
#define RM_OFF_DEF_FN1      0x656C0u
#define RM_OFF_DEF_FN39     0x45A7D0u

struct SweepMod { char name[32]; uint32_t base, end, secLo, secHi; };
#define RM_SWEEP_MAX 64

struct ModEntry {
    char name[128];
    uint32_t resPtr;
    int  seenFiles;
    int  metaFiles;
    int  netID;
    int  scriptID;
    bool stopped;
    std::vector<std::string> fileList;
    ModEntry() : resPtr(0), seenFiles(0), metaFiles(-1), netID(-1), scriptID(-1), stopped(false) { name[0] = 0; }
};

struct DownloadJob {
    bool active;
    char mod[128];
    int  total, done, fail;
    char status[160];
    std::vector<std::string> queue;
    std::vector<std::string> batchMods;
};

enum ActionType {
    ACT_NONE = 0,
    ACT_STOP_ONE,
    ACT_STOP_ALL
};

struct ActionCmd {
    int      type;
    uint32_t resPtr;
};

enum ScanState {
    ST_WAIT_SERVER = 0,
    ST_SCAN_MGR,
    ST_COLLECT,
    ST_REARM,
    ST_OFF
};

struct RuntimeState {
    int      state;
    int      scanPhase; /* 0 = fast (direct + CClientManager), 1 = deep (CClientGame) */
    uint32_t cursor;
    uint32_t lo, hi;
    int      miss;
    uint32_t modSig, tick, tCount, tCollect, needHttp;
    uint32_t tcpAt, tName, tcpBad;
    int      modIdx;
    int      cfgDone;
    int      relax;
};

static HMODULE  g_clientMod       = nullptr;
static uint32_t g_clientGameSlot  = 0;
static uint32_t g_clientGamePtr   = 0;
static uint32_t g_resMgr          = 0;
static uint32_t g_luaResMgrSlot   = 0;
static uint32_t g_rttiClientMgrVt = 0;
static uint32_t g_fnResStop       = 0;
static uint32_t g_fnResRemove     = 0;
static uint32_t g_fnResMagic      = 0;
static bool     g_resMagicLogged  = false;
static bool     g_clientFuncsDone = false;
static uint32_t g_resNameOff      = 0xFFFFFFFFu;
static uint32_t g_resFilesOff     = 0xFFFFFFFFu;
static uint32_t g_cfileOff        = CFILE_NAME_REL;
static int      g_shapeIdx        = -1;
static int      g_filesShapeIdx   = -1;

static std::vector<ActionCmd> g_actQueue;
static CRITICAL_SECTION       g_actCs;
static volatile LONG          g_actCsReady = 0;

static uint32_t g_budget       = TICK_BUDGET;
static uint32_t g_reads        = 0;
static bool     g_budgetSpent  = false;

static Offsets      g_off;
static SweepMod     g_sweepMods[RM_SWEEP_MAX];
static int          g_sweepN = 0;
static RuntimeState g_rt;

static bool         g_inited      = false;
static bool         g_menuOpen    = true;
static int          g_activeTab   = 0;  // 0 = Manager, 1 = Features
static bool         g_explodeEnabled = false;  /* explode so desativado fora do servidor */
static char         g_serialBuf[64]     = "";  /* serial atual (input) */
static void*        g_hwndMain    = nullptr;
static char         g_curServer[64]     = "";
static char         g_httpServer[160]   = "";
static char         g_clientUrl[160]    = "";
static char         g_srvName[96]       = "";
static bool         g_urlCserver        = false;

static std::vector<ModEntry> g_mods;
static CRITICAL_SECTION      g_modsCs;
static DownloadJob           g_job;
static HANDLE                g_workEv = nullptr;
static CRITICAL_SECTION      g_workCs;
static volatile bool         g_quit   = false;

static void budget_reset() { g_budget = TICK_BUDGET; g_reads = 0; g_budgetSpent = false; }
static bool spend(uint32_t n) {
    if (g_budget < n) { g_budgetSpent = true; return false; }
    g_budget -= n;
    g_reads  += n;
    return true;
}

static void shape_reset() { g_shapeIdx = -1; g_filesShapeIdx = -1; }

static uint32_t list_sent(const ListShape& sh, uint32_t cont) {
    return sh.inlineSent ? (cont + sh.headOff) : rd32(cont + sh.headOff);
}
static uint32_t list_nodes(const ListShape& sh, uint32_t cont) {
    return rd32(cont + sh.sizeOff);
}

/* ----------------------------------------------------- string & xml */
static void trim(std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) { s.clear(); return; }
    size_t e = s.find_last_not_of(" \t\r\n");
    s = s.substr(a, e - a + 1);
}

static std::string xml_attr(const std::string& tag, const char* name) {
    size_t p = tag.find(name);
    if (p == std::string::npos) return "";
    p += strlen(name);
    while (p < tag.size() && (tag[p] == ' ' || tag[p] == '\t')) ++p;
    if (p >= tag.size() || tag[p] != '=') return "";
    ++p;
    while (p < tag.size() && (tag[p] == ' ' || tag[p] == '\t')) ++p;
    if (p >= tag.size()) return "";
    char q = tag[p];
    if (q != '"' && q != '\'') return "";
    ++p;
    size_t e = tag.find(q, p);
    return (e == std::string::npos) ? "" : tag.substr(p, e - p);
}

static std::string norm_rel_path(std::string raw) {
    trim(raw);
    if (raw.empty() || raw.size() > 512) return "";
    size_t lead = 0;
    while (lead < raw.size() && (raw[lead] == '\\' || raw[lead] == '/')) ++lead;
    if (lead > 0 && raw[0] == '/') return "";
    std::string str = raw.substr(lead);
    for (auto& c : str) if (c == '\\') c = '/';
    if (str.size() > 1 && str[1] == ':') return "";
    std::vector<std::string> parts;
    size_t i = 0;
    while (i < str.size()) {
        size_t j = str.find('/', i);
        if (j == std::string::npos) j = str.size();
        std::string seg = str.substr(i, j - i);
        if (seg == "..") return "";
        if (!seg.empty() && seg != ".") parts.push_back(seg);
        i = j + 1;
    }
    std::string out;
    for (size_t k = 0; k < parts.size(); ++k) {
        if (k) out += '/';
        out += parts[k];
    }
    return out;
}

static bool valid_res_name(const char* n) {
    if (!n || !n[0]) return false;
    size_t len = strlen(n);
    if (len > 255) return false;
    if (strcmp(n, ".") == 0 || strcmp(n, "..") == 0) return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)n[i];
        if (c < 0x20 || c == 0x7F) return false;
        if (c == '/' || c == '\\' || c == ':' || c == '*' ||
            c == '?' || c == '"'  || c == '<' || c == '>' || c == '|')
            return false;
    }
    return true;
}

static bool parse_meta(const std::string& xml, std::vector<std::string>& out) {
    out.clear();
    bool found = false;
    size_t p = 0;
    while ((p = xml.find('<', p)) != std::string::npos) {
        size_t e = xml.find('>', p);
        if (e == std::string::npos) break;
        std::string tag = xml.substr(p, e - p + 1);
        p = e + 1;
        if (tag.size() < 3 || tag[1] == '/' || tag[1] == '!' || tag[1] == '?') continue;
        std::string lname;
        for (size_t i = 1; i < tag.size(); ++i) {
            char ch = tag[i];
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '/' || ch == '>') break;
            lname += (char)tolower((unsigned char)ch);
        }
        bool isScript = lname == "script";
        bool isFile   = lname == "file";
        bool isCustom = lname == "customfile";
        bool isImg    = lname == "customimage";
        if (!isScript && !isFile && !isCustom && !isImg) continue;
        found = true;
        std::string path = norm_rel_path(xml_attr(tag, "src"));
        if (path.empty()) continue;
        std::string type = xml_attr(tag, "type");
        for (auto& c : type) c = (char)tolower((unsigned char)c);
        std::string cli = xml_attr(tag, "client");
        for (auto& c : cli) c = (char)tolower((unsigned char)c);
        bool clientSide;
        if (isScript)      clientSide = !(type == "server" || type == "server-side" || type == "server/side");
        else if (isCustom) clientSide = (cli == "true");
        else               clientSide = true;
        if (clientSide) out.push_back(path);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return found;
}

static uint32_t crc32(const void* data, size_t len) {
    static uint32_t tab[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            tab[i] = c;
        }
        init = true;
    }
    const auto* p = (const uint8_t*)data;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) c = tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ----------------------------------------------------- SString readers */
/* MSVC x86 std::string (IDL=0): _Bx[16]@+0x00, _Mysize@+0x10, _Myres@+0x14 */
static bool sstring_valid_at(uint32_t addr, uint32_t maxLen, char* out, size_t cap) {
    if (!is_valid_ptr(addr)) return false;
    uint32_t hdr[6] = {};
    if (!rd_bytes(addr, hdr, sizeof(hdr))) return false;
    uint32_t size = hdr[4];
    uint32_t res  = hdr[5];
    if (size < 1 || size > maxLen || res < 15u || res < size || res > 4096u) return false;

    uint32_t src = (res < 16u) ? addr : hdr[0];
    if (!is_valid_ptr(src)) return false;

    char tmp[512];
    uint32_t readLen = size + 1;
    if (readLen > sizeof(tmp)) return false;
    if (!rd_bytes(src, tmp, readLen)) return false;
    if (tmp[size] != 0) return false;
    for (uint32_t i = 0; i < size; ++i) {
        unsigned char c = (unsigned char)tmp[i];
        if (c < 0x20 || c == 0x7F) return false;
    }
    if (out && cap) {
        size_t copyLen = std::min<size_t>(size, cap - 1);
        memcpy(out, tmp, copyLen);
        out[copyLen] = 0;
    }
    return true;
}

/* --------------------------------------------------------- network / cfg */
static uint32_t parse_ipv4(const char* ip) {
    uint32_t out = 0, part = 0, digits = 0, dots = 0;
    if (!ip) return 0;
    for (const char* c = ip;; ++c) {
        if (*c >= '0' && *c <= '9') {
            part = part * 10u + (uint32_t)(*c - '0');
            if (++digits > 3 || part > 255u) return 0;
        } else if (*c == '.' || *c == 0) {
            if (!digits) return 0;
            out |= (part & 0xFFu) << (dots * 8);
            part = 0; digits = 0;
            if (*c == 0) break;
            if (++dots > 3) return 0;
        } else return 0;
    }
    return dots == 3 ? out : 0;
}

static void cfg_path(char* path, size_t cap) {
    DWORD n = GetEnvironmentVariableA("MTARM_SERVER", path, (DWORD)cap - 1);
    if (!n || n >= (DWORD)cap - 1) snprintf(path, cap, "C:\\mta.txt");
}

static bool server_from_cfg(char* out, size_t cap) {
    char path[MAX_PATH] = "";
    cfg_path(path, sizeof(path));
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rt") != 0 || !f) return false;
    char ln[128] = "";
    bool ok = false;
    if (fgets(ln, sizeof(ln), f)) {
        size_t b = 0;
        while (b < sizeof(ln) && (ln[b] == ' ' || ln[b] == '\t')) ++b;
        size_t e = strlen(ln + b);
        while (e && (ln[b + e - 1] == '\r' || ln[b + e - 1] == '\n' ||
                     ln[b + e - 1] == ' '  || ln[b + e - 1] == '\t')) --e;
        if (e > 6 && e + 1 < cap) {
            char tmp[128] = "";
            memcpy(tmp, ln + b, e); tmp[e] = 0;
            char* colon = strrchr(tmp, ':');
            if (colon) {
                *colon = 0;
                unsigned long port = strtoul(colon + 1, nullptr, 10);
                bool good = parse_ipv4(tmp) && (colon - tmp) >= 7 && port >= 1 && port <= 65535;
                *colon = ':';
                if (good) { snprintf(out, cap, "%s", tmp); ok = true; }
            }
        }
    }
    fclose(f);
    if (ok) mta_logf("cfg", "%s -> %s", path, out);
    return ok;
}

static bool ase_parse(const char* buf, size_t len, char* name, size_t nameCap,
                      unsigned& httpPort, unsigned& gamePort) {
    httpPort = 0; gamePort = 0;
    if (name && nameCap) name[0] = 0;
    if (len < 8 || memcmp(buf, "EYE2", 4) != 0) return false;
    size_t p = 4;
    std::string fields[5];
    for (int f = 0; f < 5; ++f) {
        if (p >= len) return false;
        unsigned l = (unsigned char)buf[p++];
        if (p + l > len) return false;
        fields[f].assign(buf + p, l ? l - 1 : 0);
        p += l;
    }
    gamePort = (unsigned)atoi(fields[1].c_str());
    if (name && nameCap) snprintf(name, nameCap, "%s", fields[2].c_str());
    std::vector<std::string> sub;
    const std::string& mb = fields[4];
    size_t q = 0;
    for (;;) {
        size_t e = mb.find('\0', q);
        if (e == std::string::npos) { if (q < mb.size()) sub.push_back(mb.substr(q)); break; }
        sub.push_back(mb.substr(q, e - q));
        q = e + 1;
    }
    if (sub.size() >= 8 && !sub[7].empty()) httpPort = (unsigned)atoi(sub[7].c_str());
    return (name && name[0]) || httpPort || gamePort;
}

static bool resolve_host_ipv4(const char* host, char* ipOut, size_t cap) {
    if (!host || !host[0] || !ipOut || !cap) return false;
    if (parse_ipv4(host)) { snprintf(ipOut, cap, "%s", host); return true; }
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return false;
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    bool ok = false;
    if (getaddrinfo(host, nullptr, &hints, &res) == 0 && res) {
        for (addrinfo* p = res; p; p = p->ai_next) {
            if (p->ai_family == AF_INET && p->ai_addr) {
                uint32_t a = ((sockaddr_in*)p->ai_addr)->sin_addr.s_addr;
                snprintf(ipOut, cap, "%u.%u.%u.%u",
                         a & 0xFFu, (a >> 8) & 0xFFu, (a >> 16) & 0xFFu, (a >> 24) & 0xFFu);
                ok = true;
                break;
            }
        }
        freeaddrinfo(res);
    }
    WSACleanup();
    return ok;
}

static bool xml_tag_val(const std::string& xml, const char* tag, std::string& out) {
    std::string open = std::string("<") + tag + ">";
    std::string close = std::string("</") + tag + ">";
    size_t a = xml.find(open);
    if (a == std::string::npos) return false;
    a += open.size();
    size_t b = xml.find(close, a);
    if (b == std::string::npos) return false;
    out = xml.substr(a, b - a);
    trim(out);
    return !out.empty();
}

static bool server_from_coreconfig(char* out, size_t cap) {
    if (out && cap) out[0] = 0;
    HMODULE hCore = GetModuleHandleA("core.dll");
    if (!hCore) return false;
    char cfgPath[MAX_PATH] = "";
    if (!GetModuleFileNameA(hCore, cfgPath, sizeof(cfgPath) - 1)) return false;
    char* slash = strrchr(cfgPath, '\\');
    if (!slash) slash = strrchr(cfgPath, '/');
    if (!slash) return false;
    snprintf(slash + 1, sizeof(cfgPath) - (size_t)(slash + 1 - cfgPath), "config\\coreconfig.xml");

    FILE* f = nullptr;
    if (fopen_s(&f, cfgPath, "rb") != 0 || !f) return false;
    std::string xml;
    char chunk[4096];
    size_t rd = 0;
    while (xml.size() < 256u * 1024u && (rd = fread(chunk, 1, sizeof(chunk), f)) > 0)
        xml.append(chunk, rd);
    fclose(f);

    std::string host, portStr;
    if (!xml_tag_val(xml, "host", host) || !xml_tag_val(xml, "port", portStr)) return false;
    unsigned port = (unsigned)atoi(portStr.c_str());
    if (port < 1u || port > 65535u) return false;

    char ip[64] = "";
    if (resolve_host_ipv4(host.c_str(), ip, sizeof(ip))) {
        snprintf(out, cap, "%s:%u", ip, port);
    } else {
        snprintf(out, cap, "%s:%u", host.c_str(), port);
    }
    return out[0] != 0;
}

static bool udp_query(const char* ip, unsigned short port, char* out, size_t outCap, unsigned& lenOut) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return false;
    bool got = false;
    SOCKET so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (so != INVALID_SOCKET) {
        sockaddr_in sa = {};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        uint32_t addr = parse_ipv4(ip);
        if (addr) {
            sa.sin_addr.s_addr = addr;
            DWORD tmo = 1200;
            setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
            if (sendto(so, "b", 1, 0, (sockaddr*)&sa, sizeof(sa)) != SOCKET_ERROR) {
                int n = recvfrom(so, out, (int)outCap - 1, 0, nullptr, nullptr);
                if (n > 8) { out[n] = 0; lenOut = (unsigned)n; got = true; }
            }
        }
        closesocket(so);
    }
    WSACleanup();
    return got;
}

static void resolve_http() {
    char cur[64], cliUrl[160];
    EnterCriticalSection(&g_modsCs);
    snprintf(cur, sizeof(cur), "%s", g_curServer);
    snprintf(cliUrl, sizeof(cliUrl), "%s", g_clientUrl);
    LeaveCriticalSection(&g_modsCs);
    if (!cur[0]) return;

    char httpBuf[160] = "";
    char srvBuf[96]   = "";
    snprintf(httpBuf, sizeof(httpBuf), "%s", cliUrl[0] ? cliUrl : cur);

    char host[64] = "", ip[64] = "";
    const char* col = strrchr(cur, ':');
    if (!col) return;
    size_t n = (size_t)(col - cur);
    if (n >= sizeof(host)) return;
    memcpy(host, cur, n); host[n] = 0;
    unsigned gport = (unsigned)atoi(col + 1);
    if (!resolve_host_ipv4(host, ip, sizeof(ip))) return;

    char buf[1400] = "";
    unsigned len = 0, hp = 0, gp = 0;
    char nm[96] = "";
    const unsigned probes[4] = {
        (gport > 123 ? gport : 22003u) + 123u,
        (gport > 123 ? gport : 22003u) + 124u,
        (gport > 125 ? gport - 2u : 22003u) + 123u,
        22126u
    };
    for (int i = 0; i < 4 && (!hp || !nm[0]); ++i) {
        if (udp_query(ip, (unsigned short)probes[i], buf, sizeof(buf), len)) {
            if (ase_parse(buf, len, nm, sizeof(nm), hp, gp)) {
                if (nm[0] && !srvBuf[0]) snprintf(srvBuf, sizeof(srvBuf), "%s", nm);
                if (hp && !cliUrl[0]) snprintf(httpBuf, sizeof(httpBuf), "%s:%u", ip, hp);
            }
        }
    }
    if (!hp && !cliUrl[0] && gport) snprintf(httpBuf, sizeof(httpBuf), "%s:%u", ip, gport + 2u);
    if (!srvBuf[0] && g_hwndMain) {
        char ttl[160] = "";
        if (GetWindowTextA((HWND)g_hwndMain, ttl, (int)sizeof(ttl) - 1) > 0) {
            char* dash = strstr(ttl, " - ");
            if (dash && dash[3]) {
                snprintf(srvBuf, sizeof(srvBuf), "%s", dash + 3);
                size_t l = strlen(srvBuf);
                while (l && (srvBuf[l - 1] == '\r' || srvBuf[l - 1] == '\n' || srvBuf[l - 1] == ' '))
                    srvBuf[--l] = 0;
                if (l <= 1 || parse_ipv4(srvBuf)) srvBuf[0] = 0;
            }
        }
    }

    EnterCriticalSection(&g_modsCs);
    snprintf(g_httpServer, sizeof(g_httpServer), "%s", httpBuf);
    if (srvBuf[0]) snprintf(g_srvName, sizeof(g_srvName), "%s", srvBuf);
    LeaveCriticalSection(&g_modsCs);
    mta_logf("ase", "%s -> http=%s name='%s'", cur, httpBuf, srvBuf);
}

static uint32_t net_port(uint32_t netOrder) {
    uint32_t p = netOrder & 0xFFFFu;
    return ((p & 0xFFu) << 8) | (p >> 8);
}

static bool is_web_noise_port(uint32_t p) {
    static const uint32_t w[] = { 21u, 22u, 25u, 53u, 80u, 110u, 123u, 143u, 443u,
                                  465u, 587u, 993u, 995u, 1194u, 1433u, 3306u,
                                  3389u, 5060u, 5222u, 8080u, 8443u };
    for (uint32_t x : w) if (x == p) return true;
    return false;
}

typedef struct { uint32_t state, localAddr, localPort, remAddr, remPort, pid; } TcpRow;
typedef DWORD (WINAPI *FnGetTcpTable)(void*, unsigned long*, int, unsigned long, unsigned long, unsigned long);

static int server_from_tcp(const char* curServer, char* out, size_t cap) {
    if (out && cap) out[0] = 0;
    HMODULE iph = GetModuleHandleA("iphlpapi.dll");
    if (!iph) iph = LoadLibraryA("iphlpapi.dll");
    if (!iph) return -1;
    auto pGet = (FnGetTcpTable)(void*)GetProcAddress(iph, "GetExtendedTcpTable");
    if (!pGet) return -1;

    unsigned long need = 0;
    DWORD r0 = pGet(nullptr, &need, 1, 2, 5, 0);
    if (r0 != 0 && r0 != 122) return -1;
    if (r0 == 0 && need < 8u) return 0;
    if (need < 28u) need = 28u;
    if (need > 512u * 1024u) return -1;

    for (int attempt = 0; attempt < 4; ++attempt) {
        std::vector<uint8_t> buf((size_t)need);
        DWORD r = pGet(buf.data(), &need, 1, 2, 5, 0);
        if (r == 122) { need += need / 2u + 64u; if (need >= 512u * 1024u) return -1; continue; }
        if (r != 0) return -1;
        uint32_t cnt = 0;
        memcpy(&cnt, buf.data(), 4);
        if (cnt > 2048u) return -1;
        DWORD mine = GetCurrentProcessId();
        int bestRank = 3;
        for (uint32_t i = 0; i < cnt; ++i) {
            size_t o = 4u + (size_t)i * sizeof(TcpRow);
            if (o + sizeof(TcpRow) > buf.size()) break;
            TcpRow rw;
            memcpy(&rw, &buf[o], sizeof(rw));
            if (rw.state != 5u || rw.pid != mine) continue;
            uint32_t port = net_port(rw.remPort);
            if (port < 1u || port > 65535u) continue;
            char cand[48];
            snprintf(cand, sizeof(cand), "%u.%u.%u.%u:%u",
                     rw.remAddr & 0xFFu, (rw.remAddr >> 8) & 0xFFu,
                     (rw.remAddr >> 16) & 0xFFu, (rw.remAddr >> 24) & 0xFFu, port);
            int rank = 3;
            if (curServer && curServer[0] && !strcmp(curServer, cand)) rank = 0;
            else if (port >= 22000u && port <= 22999u) rank = 1;
            else if (!is_web_noise_port(port)) rank = 2;
            if (rank < bestRank) { bestRank = rank; snprintf(out, cap, "%s", cand); }
        }
        return out[0] ? 1 : 0;
    }
    return -1;
}

/* ------------------------------------------- offsets & module sweep */
static void off_defaults() {
    snprintf(g_off.module, sizeof(g_off.module), "%s", RM_OFF_DEF_MODULE);
    g_off.mgrGlobal   = RM_OFF_DEF_GLOBAL;
    g_off.mgrVt       = RM_OFF_DEF_VTABLE;
    g_off.resMgrField = RM_OFF_DEF_RESFIELD;
    g_off.fn0         = RM_OFF_DEF_FN0;
    g_off.fn1         = RM_OFF_DEF_FN1;
    g_off.fn39        = RM_OFF_DEF_FN39;
    g_off.clientBase  = g_off.clientHi = g_off.inst = 0;
    g_off.ok = g_off.loaded = 0;
}

static void off_parse_line(const char* line) {
    while (*line == ' ' || *line == '\t') ++line;
    if (!*line || *line == '#' || *line == '/') return;
    const char* eq = strchr(line, '=');
    if (!eq) return;
    char key[56]; size_t k = 0;
    while (k + 1 < sizeof(key) && line[k] && &line[k] != eq) { key[k] = line[k]; ++k; }
    key[k] = 0;
    while (k && (key[k - 1] == ' ' || key[k - 1] == '\t')) key[--k] = 0;
    const char* val = eq + 1;
    while (*val == ' ' || *val == '\t') ++val;
    if (!strcmp(key, "module")) { snprintf(g_off.module, sizeof(g_off.module), "%s", val); return; }
    char* end = nullptr;
    unsigned long pv = strtoul(val, &end, 0);
    if (end == val) return;
    uint32_t v = (uint32_t)pv;
    if      (!strcmp(key, "global.CClientManager"))                  g_off.mgrGlobal   = v;
    else if (!strcmp(key, "vtable.CClientManager"))                  g_off.mgrVt       = v;
    else if (!strcmp(key, "field.CClientManager.m_pResourceManager")) g_off.resMgrField = v;
    else if (!strcmp(key, "fn.CClientManager.000"))                  g_off.fn0         = v;
    else if (!strcmp(key, "fn.CClientManager.001"))                  g_off.fn1         = v;
    else if (!strcmp(key, "fn.CClientManager.039"))                  g_off.fn39        = v;
}

static void off_load() {
    off_defaults();
    char path[MAX_PATH] = "";
    DWORD pn = GetEnvironmentVariableA("MTARM_OFFSETS", path, sizeof(path) - 1);
    if (!pn || pn >= sizeof(path) - 1) snprintf(path, sizeof(path), "C:\\mta_offsets.txt");
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rt") != 0 || !f) return;
    char ln[192];
    while (fgets(ln, sizeof(ln), f)) {
        char* c = strpbrk(ln, "\r\n");
        if (c) *c = 0;
        off_parse_line(ln);
    }
    fclose(f);
    g_off.loaded = 1;
}

static void fill_mod_sections(const char* name, uint32_t b, uint32_t e) {
    __try {
        auto* dos = (IMAGE_DOS_HEADER*)(uintptr_t)b;
        auto* nt  = (IMAGE_NT_HEADERS*)(uintptr_t)(b + dos->e_lfanew);
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections && g_sweepN < RM_SWEEP_MAX; ++s) {
            if ((sec[s].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sec[s].Characteristics & IMAGE_SCN_MEM_READ)) {
                uint32_t sa = b + sec[s].VirtualAddress;
                uint32_t sb = sa + (sec[s].Misc.VirtualSize ? sec[s].Misc.VirtualSize : sec[s].SizeOfRawData);
                if (sb > e) sb = e;
                if (sb > sa + 16u) {
                    snprintf(g_sweepMods[g_sweepN].name, sizeof(g_sweepMods[g_sweepN].name), "%s", name);
                    g_sweepMods[g_sweepN].base  = b;
                    g_sweepMods[g_sweepN].end   = e;
                    g_sweepMods[g_sweepN].secLo = sa;
                    g_sweepMods[g_sweepN].secHi = sb;
                    ++g_sweepN;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void fill_sweep() {
    static const char* const pref[] = { "client.dll", "client_d.dll" };
    g_sweepN = 0;
    for (const char* name : pref) {
        if (g_sweepN >= RM_SWEEP_MAX) break;
        uint32_t b = 0, e = 0;
        if (!get_module_bounds(name, b, e) || !b || e <= b) continue;
        bool dup = false;
        for (int k = 0; k < g_sweepN; ++k) if (g_sweepMods[k].base == b) { dup = true; break; }
        if (dup) continue;
        int before = g_sweepN;
        fill_mod_sections(name, b, e);
        if (g_sweepN == before) {
            uint32_t ds = 0, de = 0;
            writable_range(b, e, ds, de);
            if (ds && de > ds && g_sweepN < RM_SWEEP_MAX) {
                snprintf(g_sweepMods[g_sweepN].name, sizeof(g_sweepMods[g_sweepN].name), "%s", name);
                g_sweepMods[g_sweepN].base  = b;
                g_sweepMods[g_sweepN].end   = e;
                g_sweepMods[g_sweepN].secLo = ds;
                g_sweepMods[g_sweepN].secHi = de;
                ++g_sweepN;
            }
        }
    }
}

static bool off_find_module(uint32_t vtRva, uint32_t& baseOut, uint32_t& hiOut, const char** nameOut) {
    fill_sweep();
    if (!g_sweepN) return false;
    const bool fp = (g_off.fn0 || g_off.fn1 || g_off.fn39);
    for (int i = 0; i < g_sweepN; ++i) {
        uint32_t b = g_sweepMods[i].base, e = g_sweepMods[i].end;
        if (!b || e <= b || vtRva >= e - b) continue;
        if (!fp) { baseOut = b; hiOut = e; *nameOut = g_sweepMods[i].name; return true; }
        uint32_t vt = b + vtRva;
        bool ok0  = !g_off.fn0  || rd32(vt)           == b + g_off.fn0;
        bool ok1  = !g_off.fn1  || rd32(vt + 4u)      == b + g_off.fn1;
        bool ok39 = !g_off.fn39 || rd32(vt + 4u * 39u)== b + g_off.fn39;
        if (ok0 && ok1 && ok39) {
            baseOut = b; hiOut = e; *nameOut = g_sweepMods[i].name;
            return true;
        }
    }
    return false;
}

/* ------------------------------------------- CResource / CResourceManager */
static uint32_t read_res_magic(bool& ok) {
    ok = false;
    if (!g_fnResMagic) return 0;
    uint8_t b[16] = {};
    if (!rd_bytes(g_fnResMagic, b, sizeof(b))) return 0;
    uint32_t val = 0;
    if (b[0] == 0xB8u && b[5] == 0xC3u) {
        val = *(const uint32_t*)(b + 1);
        ok = true;
    } else if (b[0] == 0xA1u && b[5] == 0xC3u) {
        val = rd32(*(const uint32_t*)(b + 1));
        ok = true;
    } else {
        __try {
            typedef uint32_t (__cdecl *MagicFn)();
            val = ((MagicFn)(uintptr_t)g_fnResMagic)();
            ok = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = false;
            val = 0;
        }
    }
    if (!g_resMagicLogged) {
        g_resMagicLogged = true;
        mta_logf("rt", "ResMagic(%08X) -> %08X (ok=%d)", g_fnResMagic, val, ok ? 1 : 0);
    }
    return val;
}

static uint32_t list_item_at(uint32_t mgr, const ListShape& sh, uint32_t node) {
    if (!is_valid_ptr(node)) return 0;
    if (!sh.encoded) return rd32(node + sh.valOff);
    bool ok = false;
    uint32_t magic = read_res_magic(ok);
    if (!ok) return 0;
    uint32_t usNetID = rd32(node + 8u) & 0xFFFFu;
    uint32_t encPtr  = rd32(node + 12u);
    uint32_t ecx     = usNetID << 16;
    uint32_t edi     = usNetID | 0x51A3u;
    uint32_t eax     = magic ^ ecx ^ edi ^ mgr;
    uint32_t mask    = (eax != 0) ? eax : 0x2468ACE1u;
    return encPtr ^ mask;
}

static bool cres_name(uint32_t res, uint32_t nameOff, char* out, size_t cap) {
    if (!sstring_valid_at(res + nameOff, 255u, out, cap)) return false;
    return valid_res_name(out);
}

static bool cres_hdr_ok(uint32_t item, bool relaxedId) {
    if (!is_valid_ptr(item)) return false;
    uint32_t hdr[4] = {};
    if (!rd_bytes(item, hdr, sizeof(hdr))) return false;
    uint32_t net = hdr[0] & 0xFFFFu;
    uint32_t sid = hdr[1];
    bool ok0 = (net < 65535u) &&
               ((sid >= ID_ARRAY_BASE && sid < ID_ARRAY_LIMIT) ||
                (relaxedId && sid != 0 && sid != 0xFFFFFFFFu));
    /* Caso CResource possua vptr (+0x00) em builds customizados */
    bool okVt = (hdr[0] >= 0x10000000u) &&
                ((hdr[1] & 0xFFFFu) < 65535u) &&
                ((hdr[2] >= ID_ARRAY_BASE && hdr[2] < ID_ARRAY_LIMIT) ||
                 (relaxedId && hdr[2] != 0 && hdr[2] != 0xFFFFFFFFu));
    if (!ok0 && !okVt) return false;
    static const uint32_t kNo[] = { 0x0Cu, 0x10u, 0x08u, 0x14u, 0x18u };
    for (uint32_t o : kNo) {
        if (sstring_valid_at(item + o, 255u, nullptr, 0)) return true;
    }
    return false;
}

/* Filtro rapido (6 leituras) para o layout literal do CResourceManager:
   m_resources.m_Map._Mysize == m_resources.m_List._Mysize == m_NetIdResourceMap._Mysize */
static bool mgr_prefilter(uint32_t mgr, int* shapeHint = nullptr) {
    if (!is_valid_ptr(mgr)) return false;
    uint32_t dw[9] = {};
    if (!rd_bytes(mgr, dw, sizeof(dw))) return false;

    for (int si = 0; si < 2; ++si) {
        const ListShape& sh = kShapes[si];
        uint32_t mh  = dw[sh.mapHeadOff / 4u];
        uint32_t ms  = dw[sh.mapSizeOff / 4u];
        uint32_t lh  = dw[(sh.listOff + sh.headOff) / 4u];
        uint32_t ls  = dw[(sh.listOff + sh.sizeOff) / 4u];
        uint32_t nh  = dw[sh.netMapHeadOff / 4u];
        uint32_t ns  = dw[sh.netMapSizeOff / 4u];
        if (!is_valid_ptr(mh) || !is_valid_ptr(lh) || !is_valid_ptr(nh)) continue;
        if (mh == lh || lh == nh) continue;
        if (ls < 1u || ls > RES_MAX) continue;
        if (ms != ls || ns != ls) continue;
        uint32_t firstNode = rd32(lh);
        if (!is_valid_ptr(firstNode) || firstNode == lh) continue;
        uint32_t item = rd32(firstNode + sh.valOff);
        if (cres_hdr_ok(item, true)) {
            if (shapeHint) *shapeHint = si;
            return true;
        }
    }
    /* Fallback: m_Map._Mysize == m_List._Mysize e CResource com CIdArray estrito */
    for (int si = 0; si < 2; ++si) {
        const ListShape& sh = kShapes[si];
        uint32_t mh  = dw[sh.mapHeadOff / 4u];
        uint32_t ms  = dw[sh.mapSizeOff / 4u];
        uint32_t lh  = dw[(sh.listOff + sh.headOff) / 4u];
        uint32_t ls  = dw[(sh.listOff + sh.sizeOff) / 4u];
        if (!is_valid_ptr(mh) || !is_valid_ptr(lh) || mh == lh) continue;
        if (ls < 1u || ls > RES_MAX || ms != ls) continue;
        uint32_t firstNode = rd32(lh);
        if (!is_valid_ptr(firstNode) || firstNode == lh) continue;
        uint32_t item = rd32(firstNode + sh.valOff);
        if (cres_hdr_ok(item, false)) {
            if (shapeHint) *shapeHint = si;
            return true;
        }
    }
    return false;
}

static int validate_cres_list(uint32_t mgr, const ListShape& sh, uint32_t nameOff) {
    uint32_t cont = mgr + sh.listOff;
    if (sh.hasMaps) {
        uint32_t mh = rd32(mgr + sh.mapHeadOff);
        uint32_t ms = rd32(mgr + sh.mapSizeOff);
        uint32_t nh = rd32(mgr + sh.netMapHeadOff);
        uint32_t ns = rd32(mgr + sh.netMapSizeOff);
        uint32_t ls = list_nodes(sh, cont);
        if (!is_valid_ptr(mh) || !is_valid_ptr(nh) || mh == nh) return -1;
        if (ls < 1u || ls > RES_MAX || ms != ls || ns != ls) return -1;
    }

    uint32_t S    = list_sent(sh, cont);
    uint32_t size = list_nodes(sh, cont);
    if (!is_valid_ptr(S) || size < 1u || size > RES_MAX) return -1;

    uint32_t n = rd32(S);
    if (!is_valid_ptr(n) || n == S) return -1;

    uint32_t netSeen[RES_PROVE_MAX] = {};
    uint32_t walked = 0;
    char nm[260] = "";
    uint32_t want = size < RES_PROVE_MAX ? size : RES_PROVE_MAX;

    for (uint32_t i = 0; i < want; ++i) {
        if (!spend(12)) return -2;
        if (n == S || !is_valid_ptr(n)) return -1;
        uint32_t item = list_item_at(mgr, sh, n);
        if (sh.encoded) {
            if (!is_valid_ptr(item)) return -1;
            uint32_t nodeNet = rd32(n + 8u) & 0xFFFFu;
            if ((rd32(item) & 0xFFFFu) != nodeNet) return -1;
        } else {
            if (!cres_hdr_ok(item, sh.hasMaps)) return -1;
        }
        if (!cres_name(item, nameOff, nm, sizeof(nm))) return -1;
        uint32_t raw0 = rd32(item + RES_NETID);
        uint32_t net = (!sh.encoded && raw0 >= 0x10000000u) ? (rd32(item + 4u) & 0xFFFFu) : (raw0 & 0xFFFFu);
        for (uint32_t k = 0; k < walked; ++k) if (netSeen[k] == net) return -1;
        netSeen[walked++] = net;
        uint32_t nx = rd32(n);
        if (!is_valid_ptr(nx) || nx == n) return -1;
        n = nx;
    }

    for (uint32_t i = walked; i < size; ++i) {
        if (!spend(3)) return -2;
        if (n == S || !is_valid_ptr(n)) return -1;
        uint32_t item = list_item_at(mgr, sh, n);
        if (!is_valid_ptr(item)) return -1;
        uint32_t nx = rd32(n);
        if (nx == n) return -1;
        n = nx;
    }
    return (n == S) ? (int)size : -1;
}

static bool prove_mgr(uint32_t mgr, int preferredShape = -1) {
    if (!is_valid_ptr(mgr)) return false;
    const int nShapes = kShapesActiveN;
    static const uint32_t kNameOffs[] = { RES_NAME, RES_NAME + 4u, RES_STARTCNT, 0x14u, 0x18u };
    auto try_shape = [&](int si) -> bool {
        for (uint32_t nameOff : kNameOffs) {
            int good = validate_cres_list(mgr, kShapes[si], nameOff);
            if (good >= 1) {
                g_shapeIdx    = si;
                g_resNameOff  = nameOff;
                g_resFilesOff = 0xFFFFFFFFu;
                g_cfileOff    = CFILE_NAME_REL;
                mta_logf("rt", "CResourceManager=%08X (%s, %d resources, nome@+%02X)",
                         mgr, kShapes[si].desc, good, nameOff);
                return true;
            }
            if (good == -2) return false;
        }
        return false;
    };

    if (preferredShape >= 0 && preferredShape < nShapes) {
        if (try_shape(preferredShape)) return true;
        if (g_budgetSpent) return false;
    }
    for (int si = 0; si < nShapes; ++si) {
        if (si == preferredShape) continue;
        if (try_shape(si)) return true;
        if (g_budgetSpent) return false;
    }
    return false;
}

static bool cfile_name_ok(uint32_t f, uint32_t ownerRes, uint32_t nameOff, char* out, size_t cap) {
    if (!is_valid_ptr(f)) return false;
    uint32_t owner = rd32(f + CFILE_OWNER);
    uint32_t rtype = rd32(f + CFILE_TYPE);
    if (ownerRes && owner != ownerRes) return false;
    if (rtype > 6u) return false;
    char tmp[260] = "";
    if (!sstring_valid_at(f + nameOff, 255u, tmp, sizeof(tmp))) return false;
    if (!tmp[0] || strchr(tmp, '\\') || strchr(tmp, ':')) return false;
    if (out && cap) snprintf(out, cap, "%s", tmp);
    return true;
}

static int files_list_at(uint32_t res, uint32_t off, uint32_t nameOff, int shapeIdx, std::vector<std::string>* out) {
    if (shapeIdx < 0) shapeIdx = (g_filesShapeIdx >= 0) ? g_filesShapeIdx : g_shapeIdx;
    if (shapeIdx < 0) return -1;
    const ListShape& sh = kShapes[shapeIdx];
    uint32_t cont = res + off;
    uint32_t S    = list_sent(sh, cont);
    uint32_t size = list_nodes(sh, cont);
    if (!is_valid_ptr(S)) return -1;
    if (size == 0) {
        uint32_t nx = rd32(S);
        uint32_t pv = rd32(S + 4u);
        return (nx == S && pv == S) ? 0 : -1;
    }
    if (size > RES_FILES_COUNT) return -1;

    uint32_t n = rd32(S);
    if (!is_valid_ptr(n) || n == S) return -1;

    std::vector<std::string> tmp;
    tmp.reserve(size);
    for (uint32_t i = 0; i < size; ++i) {
        if (n == S || !is_valid_ptr(n)) return -1;
        uint32_t f = rd32(n + sh.valOff);
        char nm[260] = "";
        if (!cfile_name_ok(f, res, nameOff, nm, sizeof(nm))) return -1;
        std::string np = norm_rel_path(nm);
        if (np.empty()) return -1;
        tmp.push_back(np);
        uint32_t nx = rd32(n);
        if (nx == n) return -1;
        n = nx;
    }
    if (n != S) return -1;
    if (out) out->swap(tmp);
    return (int)size;
}

static void read_res_files(uint32_t res, std::vector<std::string>& out) {
    out.clear();
    if (g_resFilesOff == 0xFFFFFFFFu) {
        static const uint32_t nameOffs[] = { CFILE_NAME_REL, 0x28u, 0x20u, CFILE_NAME_FULL, 0x08u };
        int probe = files_list_at(res, RES_FILES_OFF, CFILE_NAME_REL, 0, nullptr);
        if (probe >= 0) {
            g_resFilesOff = RES_FILES_OFF;
            g_cfileOff    = CFILE_NAME_REL;
            g_filesShapeIdx = 0;
            mta_logf("rm", "m_ResourceFiles @ +%02X, m_strNameShort @ +%02X", g_resFilesOff, g_cfileOff);
        } else {
            static const int kFShapes[] = { 0, 2, 1, 3 };
            bool found = false;
            for (int fsi : kFShapes) {
                for (uint32_t o = 0x40u; o <= 0x1A0u && !found; o += 4u) {
                    for (uint32_t no : nameOffs) {
                        if (files_list_at(res, o, no, fsi, nullptr) > 0) {
                            g_resFilesOff   = o;
                            g_cfileOff      = no;
                            g_filesShapeIdx = fsi;
                            found           = true;
                            mta_logf("rm", "m_ResourceFiles detectado @ +%02X (shape=%d), nome @ +%02X", o, fsi, no);
                            break;
                        }
                    }
                }
                if (found) break;
            }
            if (!found) return;
        }
    }
    files_list_at(res, g_resFilesOff, g_cfileOff, g_filesShapeIdx, &out);

    std::vector<std::string> cfgFiles;
    if (files_list_at(res, g_resFilesOff + 8u, g_cfileOff, g_filesShapeIdx, &cfgFiles) > 0) {
        out.insert(out.end(), cfgFiles.begin(), cfgFiles.end());
    }
}

static uint32_t mod_list_sig() {
    if (!g_resMgr || g_shapeIdx < 0) return 0;
    const ListShape& sh = kShapes[g_shapeIdx];
    uint32_t cont = g_resMgr + sh.listOff;
    uint32_t S    = list_sent(sh, cont);
    uint32_t sz   = list_nodes(sh, cont);
    if (!is_valid_ptr(S) || sz > RES_MAX) return 0;
    uint32_t sig = S ^ (sz << 2) ^ 0xA5A5A5A5u;
    uint32_t n = rd32(S);
    for (int i = 0; i < 6; ++i) {
        if (!is_valid_ptr(n) || n == S) break;
        uint32_t val = list_item_at(g_resMgr, sh, n);
        uint32_t nx  = rd32(n);
        sig = (sig << 3) ^ val ^ nx;
        if (nx == n) break;
        n = nx;
    }
    return sig;
}

static void reset_session(const char* reason) {
    mta_logf("rt", "limpando estado (%s)", reason);
    g_off.ok = 0;
    g_off.inst = 0;
    g_off.clientBase = g_off.clientHi = 0;
    g_clientGameSlot  = 0;
    g_clientGamePtr   = 0;
    kShapesActiveN    = 6;
    g_resMgr          = 0;
    g_luaResMgrSlot   = 0;
    g_rttiClientMgrVt = 0;
    g_fnResStop       = 0;
    g_fnResRemove     = 0;
    g_fnResMagic      = 0;
    g_resMagicLogged  = false;
    g_clientFuncsDone = false;
    shape_reset();
    g_resNameOff  = 0xFFFFFFFFu;
    g_resFilesOff = 0xFFFFFFFFu;
    g_cfileOff    = CFILE_NAME_REL;
    g_rt.modSig   = 0;
    g_rt.miss     = 0;
    g_rt.state    = ST_WAIT_SERVER;
    g_rt.scanPhase = 0;
    g_rt.cursor   = 0;
    g_rt.lo       = g_rt.hi = 0;
    g_rt.modIdx   = 0;
    if (InterlockedCompareExchange(&g_actCsReady, 0, 0)) {
        EnterCriticalSection(&g_actCs);
        g_actQueue.clear();
        LeaveCriticalSection(&g_actCs);
    }
    EnterCriticalSection(&g_modsCs);
    g_mods.clear();
    g_curServer[0]  = 0;
    g_explodeEnabled = false;
    g_httpServer[0] = 0;
    g_clientUrl[0]  = 0;
    g_srvName[0]    = 0;
    LeaveCriticalSection(&g_modsCs);
}

static void collect_mods() {
    if (!g_resMgr) return;
    if (g_shapeIdx < 0 && !prove_mgr(g_resMgr)) return;

    const ListShape& sh = kShapes[g_shapeIdx];
    uint32_t cont = g_resMgr + sh.listOff;
    uint32_t S    = list_sent(sh, cont);
    uint32_t size = list_nodes(sh, cont);

    if (!is_valid_ptr(S) || size > RES_MAX) {
        reset_session("CResourceManager destruido/invalido");
        return;
    }
    if (size == 0) {
        EnterCriticalSection(&g_modsCs);
        if (!g_mods.empty()) g_mods.clear();
        LeaveCriticalSection(&g_modsCs);
        return;
    }

    std::vector<ModEntry> fresh;
    fresh.reserve(size);
    uint32_t n = rd32(S);
    uint32_t skipped = 0;

    for (uint32_t i = 0; i < size && n != S && is_valid_ptr(n); ++i) {
        uint32_t r = list_item_at(g_resMgr, sh, n);
        char nm[128] = "";
        if (is_valid_ptr(r) && cres_name(r, g_resNameOff, nm, sizeof(nm))) {
            ModEntry m;
            snprintf(m.name, sizeof(m.name), "%s", nm);
            m.resPtr   = r;
            if (sh.encoded) {
                m.netID    = (int)(rd32(r) & 0xFFFFu);
                m.scriptID = (int)rd32(r + RES_SCRIPTID);
                uint32_t flags = rd32(r + 0x34u);
                m.stopped  = ((flags >> 16) & 0xFFu) != 0; /* m_bStopping @ +0x36 */
            } else {
                uint32_t raw0 = rd32(r + RES_NETID);
                uint32_t shift = (raw0 >= 0x10000000u) ? 4u : 0u;
                m.netID    = (int)(rd32(r + RES_NETID + shift) & 0xFFFFu);
                m.scriptID = (int)rd32(r + RES_SCRIPTID + shift);
                uint32_t flags = rd32(r + RES_ACTIVE + ((g_resNameOff >= 0x10u) ? 4u : shift));
                m.stopped  = ((flags >> 16) & 0xFFu) != 0; /* m_bStopping @ +0x32 (ou +0x36) */
            }
            read_res_files(r, m.fileList);
            m.metaFiles = (int)m.fileList.size();
            m.seenFiles = m.metaFiles;
            fresh.push_back(std::move(m));
        } else {
            ++skipped;
        }
        uint32_t nx = rd32(n);
        if (nx == n) break;
        n = nx;
    }

    if (fresh.empty() && size > 0 && skipped == size) {
        reset_session("lista de resources invalida");
        return;
    }

    size_t count = fresh.size();
    EnterCriticalSection(&g_modsCs);
    g_mods.swap(fresh);
    LeaveCriticalSection(&g_modsCs);
    mta_logf("rm", "listados %d/%u mod(s) (%u ignorado(s))",
             (int)count, (unsigned)size, (unsigned)skipped);
}

static bool mgr_contains_res(uint32_t resPtr) {
    if (!g_resMgr || g_shapeIdx < 0 || !is_valid_ptr(resPtr)) return false;
    const ListShape& sh = kShapes[g_shapeIdx];
    uint32_t cont = g_resMgr + sh.listOff;
    uint32_t S    = list_sent(sh, cont);
    uint32_t size = list_nodes(sh, cont);
    if (!is_valid_ptr(S) || size == 0 || size > RES_MAX) return false;
    uint32_t n = rd32(S);
    for (uint32_t i = 0; i < size && n != S && is_valid_ptr(n); ++i) {
        if (list_item_at(g_resMgr, sh, n) == resPtr) return true;
        uint32_t nx = rd32(n);
        if (nx == n) break;
        n = nx;
    }
    return false;
}

static bool call_res_remove_seh(uint32_t fnRemove, uint32_t mgr, uint32_t res) {
    __try {
        using fn_t = void(__thiscall*)(void*, void*);
        ((fn_t)(uintptr_t)fnRemove)((void*)(uintptr_t)mgr, (void*)(uintptr_t)res);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static void queue_stop_one(uint32_t resPtr) {
    if (!resPtr || !g_fnResRemove || !g_resMgr) return;
    if (!InterlockedCompareExchange(&g_actCsReady, 0, 0)) return;
    EnterCriticalSection(&g_actCs);
    g_actQueue.push_back({ ACT_STOP_ONE, resPtr });
    LeaveCriticalSection(&g_actCs);
}

static void queue_stop_all() {
    if (!g_fnResRemove || !g_resMgr) return;
    if (!InterlockedCompareExchange(&g_actCsReady, 0, 0)) return;
    EnterCriticalSection(&g_actCs);
    g_actQueue.push_back({ ACT_STOP_ALL, 0u });
    LeaveCriticalSection(&g_actCs);
}

static void process_main_actions() {
    if (!InterlockedCompareExchange(&g_actCsReady, 0, 0)) return;
    std::vector<ActionCmd> todo;
    EnterCriticalSection(&g_actCs);
    if (!g_actQueue.empty()) todo.swap(g_actQueue);
    LeaveCriticalSection(&g_actCs);
    if (todo.empty()) return;

    if (!g_resMgr || !g_fnResRemove || g_shapeIdx < 0) return;

    bool changed = false;
    for (size_t i = 0; i < todo.size(); ++i) {
        const ActionCmd& cmd = todo[i];
        if (cmd.type == ACT_STOP_ONE) {
            if (mgr_contains_res(cmd.resPtr)) {
                char nm[128] = "";
                cres_name(cmd.resPtr, g_resNameOff, nm, sizeof(nm));
                bool ok = call_res_remove_seh(g_fnResRemove, g_resMgr, cmd.resPtr);
                mta_logf("act", "stop '%s' (%08X) -> %s", nm[0] ? nm : "?", cmd.resPtr, ok ? "ok" : "exc");
                changed = true;
            }
        } else if (cmd.type == ACT_STOP_ALL) {
            const ListShape& sh = kShapes[g_shapeIdx];
            uint32_t cont = g_resMgr + sh.listOff;
            uint32_t S    = list_sent(sh, cont);
            uint32_t size = list_nodes(sh, cont);
            uint32_t ptrs[512] = {};
            uint32_t cnt = 0;
            if (is_valid_ptr(S) && size > 0 && size <= RES_MAX) {
                uint32_t n = rd32(S);
                for (uint32_t k = 0; k < size && n != S && is_valid_ptr(n) && cnt < 512; ++k) {
                    uint32_t r = list_item_at(g_resMgr, sh, n);
                    if (is_valid_ptr(r)) ptrs[cnt++] = r;
                    uint32_t nx = rd32(n);
                    if (nx == n) break;
                    n = nx;
                }
            }
            uint32_t okCnt = 0;
            for (uint32_t k = 0; k < cnt; ++k) {
                if (mgr_contains_res(ptrs[k])) {
                    if (call_res_remove_seh(g_fnResRemove, g_resMgr, ptrs[k])) ++okCnt;
                    else break;
                }
            }
            mta_logf("act", "stop all: %u/%u resource(s) removido(s)", okCnt, cnt);
            changed = true;
        }
    }

    if (changed) {
        g_rt.tCollect = 0;
        g_rt.modSig   = 0;
        if (g_workEv) SetEvent(g_workEv);
    }
}

/* ----------------------------------------------------- resolvers & scan */
static bool mgr_looks_valid_empty(uint32_t mgr) {
    if (!is_valid_ptr(mgr)) return false;
    uint32_t dw[9] = {};
    if (!rd_bytes(mgr, dw, sizeof(dw))) return false;
    for (int si = 0; si < 2; ++si) {
        const ListShape& sh = kShapes[si];
        uint32_t mh = dw[sh.mapHeadOff / 4u];
        uint32_t ms = dw[sh.mapSizeOff / 4u];
        uint32_t lh = dw[(sh.listOff + sh.headOff) / 4u];
        uint32_t ls = dw[(sh.listOff + sh.sizeOff) / 4u];
        uint32_t nh = dw[sh.netMapHeadOff / 4u];
        uint32_t ns = dw[sh.netMapSizeOff / 4u];
        if (!is_valid_ptr(mh) || !is_valid_ptr(lh) || !is_valid_ptr(nh)) continue;
        if (mh == lh || lh == nh) continue;
        if (ls <= RES_MAX && ms == ls && ns == ls) return true;
    }
    return false;
}

static void extract_clientgame_http_url(uint32_t pGame) {
    if (!is_valid_ptr(pGame)) return;
    g_clientGamePtr = pGame;
    char url[160] = "";
    for (uint32_t off = 0x100u; off <= 0x700u; off += 4u) {
        if (!sstring_valid_at(pGame + off, 155u, url, sizeof(url))) continue;
        if (_strnicmp(url, "http://", 7) == 0 || _strnicmp(url, "https://", 8) == 0) {
            EnterCriticalSection(&g_modsCs);
            bool changed = strcmp(g_clientUrl, url) != 0;
            if (changed) {
                snprintf(g_clientUrl, sizeof(g_clientUrl), "%s", url);
                snprintf(g_httpServer, sizeof(g_httpServer), "%s", url);
            }
            LeaveCriticalSection(&g_modsCs);
            if (changed) mta_logf("net", "m_strHTTPDownloadURL @ CClientGame+%03X: %s", off, url);
            return;
        }
    }
}

static void resolve_from_offsets() {
    if (g_off.ok || g_resMgr) return;
    if (!g_clientMod || !g_off.mgrVt || !g_off.resMgrField) return;

    if (!g_off.clientBase) {
        const char* usedName = g_off.module;
        if (!off_find_module(g_off.mgrVt, g_off.clientBase, g_off.clientHi, &usedName)) return;
        snprintf(g_off.modUsed, sizeof(g_off.modUsed), "%s", usedName);
    }

    if (g_off.inst && is_valid_ptr(g_off.inst) && rd32(g_off.inst) == g_off.clientBase + g_off.mgrVt) {
        uint32_t mgr = rd32(g_off.inst + g_off.resMgrField);
        if (is_valid_ptr(mgr)) {
            g_resMgr = mgr;
            g_off.ok = 1;
            return;
        }
        g_off.inst = 0;
    }

    uint32_t want = g_off.clientBase + g_off.mgrVt;
    if (g_off.mgrGlobal) {
        uint32_t g = rd32(g_off.clientBase + g_off.mgrGlobal);
        uint32_t use = (is_valid_ptr(g) && rd32(g) == want) ? g : 0u;
        if (use) {
            uint32_t mgr = rd32(use + g_off.resMgrField);
            if (is_valid_ptr(mgr) && (prove_mgr(mgr) || mgr_looks_valid_empty(mgr))) {
                g_off.inst = use;
                g_off.ok   = 1;
                g_resMgr   = mgr;
                return;
            }
        }
    }
}

static bool accept_mgr(uint32_t mgr, int shapeHint, const char* how, uint32_t src) {
    if (!prove_mgr(mgr, shapeHint)) return false;
    g_resMgr      = mgr;
    g_rt.state    = ST_COLLECT;
    g_rt.cursor   = 0;
    g_rt.miss     = 0;
    g_rt.modIdx   = 0;
    mta_logf("rt", "CResourceManager=%08X via %s (src=%08X)", mgr, how, src);
    if (!strcmp(how, "CClientGame")) extract_clientgame_http_url(src);
    return true;
}

static bool try_accept_cand(uint32_t cand, const char* how, uint32_t src) {
    if (!is_valid_ptr(cand)) return false;
    int hint = -1;
    if (mgr_prefilter(cand, &hint) && accept_mgr(cand, hint, how, src)) return true;
    if (mgr_prefilter(cand + 4u, &hint) && accept_mgr(cand + 4u, hint, how, src)) return true;
    return false;
}

static bool pe_get_ranges(HMODULE mod, uint32_t& textLo, uint32_t& textHi,
                          uint32_t& rdataLo, uint32_t& rdataHi,
                          uint32_t& dataLo, uint32_t& dataHi) {
    textLo = textHi = rdataLo = rdataHi = dataLo = dataHi = 0;
    if (!mod) return false;
    __try {
        uint8_t* base = (uint8_t*)mod;
        auto* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            uint32_t s = (uint32_t)(uintptr_t)base + sec[i].VirtualAddress;
            uint32_t sz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            uint32_t e = s + sz;
            DWORD ch = sec[i].Characteristics;
            if (ch & IMAGE_SCN_MEM_EXECUTE) {
                if (!textLo || s < textLo) textLo = s;
                if (e > textHi) textHi = e;
            } else if (ch & IMAGE_SCN_MEM_WRITE) {
                if (!dataLo || s < dataLo) dataLo = s;
                if (e > dataHi) dataHi = e;
            } else if (ch & IMAGE_SCN_MEM_READ) {
                if (!rdataLo || s < rdataLo) rdataLo = s;
                if (e > rdataHi) rdataHi = e;
            }
        }
        if (!rdataLo) { rdataLo = textLo; rdataHi = textHi; }
        return textLo && textHi > textLo;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool page_readable(DWORD prot, bool execOnly) {
    if (prot & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    DWORD p = prot & 0xFFu;
    if (execOnly) {
        return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static uint32_t find_mem_bytes_raw(uint32_t lo, uint32_t hi, const void* pat, size_t len) {
    if (!lo || hi <= lo || len == 0 || (hi - lo) < len) return 0;
    __try {
        const uint8_t* p = (const uint8_t*)(uintptr_t)lo;
        const uint8_t* end = (const uint8_t*)(uintptr_t)(hi - len);
        const uint8_t* b = (const uint8_t*)pat;
        for (; p <= end; ++p) {
            if (*p == b[0] && memcmp(p, b, len) == 0) return (uint32_t)(uintptr_t)p;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

static uint32_t find_mem_bytes(uint32_t lo, uint32_t hi, const void* pat, size_t len, bool execOnly = false) {
    if (!lo || hi <= lo || len == 0 || (hi - lo) < len) return 0;
    uint32_t cur = lo;
    while (cur < hi) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery((LPCVOID)(uintptr_t)cur, &mbi, sizeof(mbi)) || mbi.RegionSize == 0) {
            cur += 0x1000u;
            continue;
        }
        uint32_t rEnd = (uint32_t)(uintptr_t)mbi.BaseAddress + (uint32_t)mbi.RegionSize;
        if (rEnd <= cur) break;
        uint32_t segHi = (rEnd < hi) ? rEnd : hi;
        if (mbi.State == MEM_COMMIT && page_readable(mbi.Protect, execOnly)) {
            uint32_t hit = find_mem_bytes_raw(cur, segHi, pat, len);
            if (hit) return hit;
        }
        cur = segHi;
    }
    return 0;
}

static uint32_t find_rtti_vtable(uint32_t modBase, uint32_t modEnd, const char* mangledName) {
    size_t nlen = strlen(mangledName) + 1u;
    uint32_t sName = find_mem_bytes(modBase, modEnd, mangledName, nlen, false);
    if (!sName || sName < modBase + 8u) return 0;
    uint32_t tdAddr = sName - 8u; /* TypeDescriptor { pVFTable(+0), spare(+4), name(+8) } */

    /* RTTICompleteObjectLocator (x86): sig(0), offset(0), cdOffset, pTypeDescriptor(tdAddr), pClassDescriptor */
    uint32_t cur = modBase;
    while (cur + 20u <= modEnd) {
        uint32_t hit = find_mem_bytes(cur, modEnd, &tdAddr, 4u, false);
        if (!hit) break;
        if (hit >= modBase + 12u) {
            uint32_t col = hit - 12u;
            uint32_t hdr[5] = {};
            if (rd_bytes(col, hdr, sizeof(hdr)) &&
                hdr[0] == 0u && hdr[1] == 0u && hdr[3] == tdAddr &&
                hdr[4] >= modBase && hdr[4] < modEnd) {
                uint32_t vtRef = find_mem_bytes(modBase, modEnd, &col, 4u, false);
                while (vtRef) {
                    uint32_t vt = vtRef + 4u;
                    uint32_t fn0 = rd32(vt);
                    if (fn0 >= modBase && fn0 < modEnd) return vt;
                    vtRef = find_mem_bytes(vtRef + 4u, modEnd, &col, 4u, false);
                }
            }
        }
        cur = hit + 4u;
    }
    return 0;
}

static void log_pe_sections(HMODULE mod) {
    __try {
        uint8_t* base = (uint8_t*)mod;
        auto* dos = (IMAGE_DOS_HEADER*)base;
        auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections && i < 16; ++i) {
            char nm[9] = {};
            memcpy(nm, sec[i].Name, 8);
            mta_logf("pe", "sec[%u] %-8s va=%08X vsz=%06X ch=%08X",
                     (unsigned)i, nm,
                     (uint32_t)(uintptr_t)base + sec[i].VirtualAddress,
                     sec[i].Misc.VirtualSize, sec[i].Characteristics);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static uint32_t walk_back_prologue(uint32_t site, uint32_t lo, uint32_t maxBack) {
    if (!site || site <= lo) return 0;
    uint32_t minAddr = (site > lo + maxBack) ? (site - maxBack) : lo;
    __try {
        for (uint32_t a = site - 3u; a >= minAddr; --a) {
            const uint8_t* p = (const uint8_t*)(uintptr_t)a;
            if ((p[0] == 0xCCu && p[1] == 0xCCu) || (p[0] == 0xC3u && p[1] == 0xCCu)) {
                /* Encontrou fim da funcao anterior; evita cruzar outra funcao */
                return 0;
            }
            if (p[0] == 0x55u && p[1] == 0x8Bu && p[2] == 0xECu) {
                uint8_t prev = (a > lo) ? p[-1] : 0xCCu;
                if (prev == 0xCCu || prev == 0xC3u || prev == 0x90u ||
                    (a >= lo + 3u && p[-3] == 0xC2u)) {
                    return a;
                }
            }
        }
        /* Fallback sem verificar byte anterior (caso funcao anterior nao tenha CC/C3 visivel) */
        for (uint32_t a = site - 3u; a >= minAddr; --a) {
            const uint8_t* p = (const uint8_t*)(uintptr_t)a;
            if ((p[0] == 0xCCu && p[1] == 0xCCu) || (p[0] == 0xC3u && p[1] == 0xCCu)) return 0;
            if (p[0] == 0x55u && p[1] == 0x8Bu && p[2] == 0xECu) return a;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

static uint32_t find_unique_call_caller(uint32_t textLo, uint32_t textHi, uint32_t target, int& callCount) {
    callCount = 0;
    uint32_t bestCaller = 0;
    uint32_t bestDist   = 0xFFFFFFFFu;
    if (!textLo || textHi <= textLo + 5u || !target) return 0;
    __try {
        for (uint32_t a = textLo; a + 5u <= textHi; ++a) {
            const uint8_t* p = (const uint8_t*)(uintptr_t)a;
            if (p[0] != 0xE8u) continue;
            int32_t rel = *(const int32_t*)(p + 1);
            uint32_t dst = a + 5u + (uint32_t)rel;
            if (dst == target) {
                ++callCount;
                uint32_t fn = walk_back_prologue(a, textLo, 48u);
                if (fn) {
                    uint32_t dist = a - fn;
                    if (dist < bestDist) {
                        bestDist   = dist;
                        bestCaller = fn;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return (callCount == 1 || bestDist <= 0x24u) ? bestCaller : 0u;
}

static bool probe_code_for_resmgr(uint32_t fnAddr, uint32_t textLo, uint32_t textHi,
                                  uint32_t dataLo, uint32_t dataHi, int depth) {
    if (!fnAddr || fnAddr < textLo || fnAddr >= textHi || depth > 2) return false;
    uint32_t subCalls[4] = {};
    int nSub = 0;
    __try {
        const uint8_t* code = (const uint8_t*)(uintptr_t)fnAddr;
        for (uint32_t i = 0; i < 220u && (fnAddr + i + 6u) <= textHi; ++i) {
            if (i >= 12u && (code[i] == 0xC3u || code[i] == 0xCCu)) break;
            uint32_t refAddr = 0;
            if (code[i] == 0xA1u) {
                refAddr = *(const uint32_t*)(code + i + 1);
            } else if (code[i] == 0x8Bu && (code[i + 1] & 0xC7u) == 0x05u) {
                refAddr = *(const uint32_t*)(code + i + 2);
            } else if (code[i] == 0xE8u && nSub < 4) {
                int32_t rel = *(const int32_t*)(code + i + 1);
                uint32_t dst = fnAddr + i + 5u + (uint32_t)rel;
                if (dst >= textLo && dst < textHi) subCalls[nSub++] = dst;
            }
            if (refAddr >= dataLo && refAddr + 4u <= dataHi) {
                uint32_t cand = rd32(refAddr);
                int hint = -1;
                if (mgr_prefilter(cand, &hint) && accept_mgr(cand, hint, "lua_getResources", refAddr)) {
                    g_luaResMgrSlot = refAddr;
                    return true;
                }
                if (mgr_looks_valid_empty(cand) || cand == 0) {
                    if (!g_luaResMgrSlot) g_luaResMgrSlot = refAddr;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    for (int k = 0; k < nSub; ++k) {
        if (probe_code_for_resmgr(subCalls[k], textLo, textHi, dataLo, dataHi, depth + 1)) return true;
    }
    return false;
}

static void dump_mgr_probe(const char* tag, uint32_t inst, uint32_t mgr) {
    uint32_t d[8] = {};
    rd_bytes(mgr, d, sizeof(d));
    mta_logf("dbg", "%s inst=%08X mgr=%08X dw=[%08X %08X %08X %08X | %08X %08X %08X %08X]",
             tag, inst, mgr, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
    if (is_valid_ptr(d[2])) {
        uint32_t n0 = rd32(d[2]);
        uint32_t item = is_valid_ptr(n0) ? rd32(n0 + 8u) : 0u;
        uint32_t ih[6] = {};
        if (is_valid_ptr(item)) rd_bytes(item, ih, sizeof(ih));
        mta_logf("dbg", "  n0=%08X item=%08X ih=[%08X %08X %08X %08X %08X %08X]",
                 n0, item, ih[0], ih[1], ih[2], ih[3], ih[4], ih[5]);
    }
}

static void log_text_refs_and_probe(const char* label, uint32_t strVa, uint32_t textLo, uint32_t textHi,
                                    uint32_t dataLo, uint32_t dataHi) {
    if (!strVa) {
        mta_logf("xref", "%-22s str=00000000", label);
        return;
    }
    uint32_t cur = textLo;
    int hits = 0;
    while (cur + 4u <= textHi && hits < 4) {
        uint32_t ref = find_mem_bytes(cur, textHi, &strVa, 4u, true);
        if (!ref) break;
        ++hits;
        uint8_t win[80] = {};
        uint32_t wStart = (ref > textLo + 48u) ? (ref - 48u) : textLo;
        rd_bytes(wStart, win, sizeof(win));
        mta_logf("xref", "%-22s str=%08X ref=%08X", label, strVa, ref);
        /* Procura ponteiros para .data (A1 <addr> ou 8B <modrm> <addr>) perto da referencia */
        for (uint32_t i = 0; i + 6u <= sizeof(win); ++i) {
            uint32_t addr = 0;
            if (win[i] == 0xA1u) {
                addr = *(const uint32_t*)(win + i + 1);
            } else if (win[i] == 0x8Bu && (win[i + 1] & 0xC7u) == 0x05u) {
                addr = *(const uint32_t*)(win + i + 2);
            }
            if (addr >= dataLo && addr + 4u <= dataHi) {
                uint32_t val = rd32(addr);
                mta_logf("xref", "  data_ref [%08X] -> %08X", addr, val);
                if (is_valid_ptr(val)) {
                    if ((!strcmp(label, "dupFile") || !strcmp(label, "dlErr")) &&
                        !g_clientGameSlot && rd32(val) <= 12u && rd32(val + 4u) <= 12u) {
                        g_clientGameSlot = addr;
                        mta_logf("rt", "g_pClientGame slot=%08X -> %08X", addr, val);
                    }
                    if (!try_accept_cand(val, label, addr)) {
                        bool hitSub = false;
                        for (uint32_t off = 0x10u; off <= 0x240u; off += 4u) {
                            uint32_t sub = rd32(val + off);
                            if (try_accept_cand(sub, label, val)) { hitSub = true; break; }
                        }
                        if (!hitSub) dump_mgr_probe(label, addr, val);
                    }
                }
            }
        }
        cur = ref + 4u;
    }
    if (!hits) mta_logf("xref", "%-22s str=%08X (sem ref em .text)", label, strVa);
}

static bool probe_client_game_deep(uint32_t pGame, bool allowDump) {
    if (!is_valid_ptr(pGame)) return false;
    uint32_t gh[4] = {};
    if (!rd_bytes(pGame, gh, sizeof(gh))) return false;
    if (allowDump) {
        mta_logf("dbg", "CClientGame=%08X hdr=[%08X %08X %08X %08X]", pGame, gh[0], gh[1], gh[2], gh[3]);
        uint32_t g70[24] = {};
        if (rd_bytes(pGame + 0x70u, g70, sizeof(g70))) {
            for (uint32_t k = 0; k < 24u; k += 4u) {
                mta_logf("dbg", "  g+%03X: %08X %08X %08X %08X", 0x70u + k * 4u,
                         g70[k], g70[k + 1], g70[k + 2], g70[k + 3]);
            }
        }
        uint32_t pMgr = rd32(pGame + 0x28u);
        if (is_valid_ptr(pMgr)) {
            uint32_t mdw[12] = {};
            if (rd_bytes(pMgr + 0x60u, mdw, sizeof(mdw))) {
                mta_logf("dbg", "  mgr(%08X)+60: %08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X",
                         pMgr, mdw[0], mdw[1], mdw[2], mdw[3], mdw[4], mdw[5], mdw[6], mdw[7],
                         mdw[8], mdw[9], mdw[10], mdw[11]);
            }
            for (uint32_t mo = 0x6Cu; mo <= 0x88u; mo += 4u) {
                uint32_t sub = rd32(pMgr + mo);
                if (is_valid_ptr(sub)) {
                    uint32_t sd[16] = {};
                    rd_bytes(sub, sd, sizeof(sd));
                    mta_logf("dbg", "  mgr+%02X=%08X dw=[%08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X]",
                             mo, sub, sd[0], sd[1], sd[2], sd[3], sd[4], sd[5], sd[6], sd[7],
                             sd[8], sd[9], sd[10], sd[11], sd[12], sd[13], sd[14], sd[15]);
                }
            }
        }
        for (uint32_t go = 0x70u; go <= 0x13Cu; go += 4u) {
            uint32_t sub = rd32(pGame + go);
            if (is_valid_ptr(sub)) {
                uint32_t sd[16] = {};
                rd_bytes(sub, sd, sizeof(sd));
                mta_logf("dbg", "  g+%03X=%08X dw=[%08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X]",
                         go, sub, sd[0], sd[1], sd[2], sd[3], sd[4], sd[5], sd[6], sd[7],
                         sd[8], sd[9], sd[10], sd[11], sd[12], sd[13], sd[14], sd[15]);
                if (go == 0x90u) {
                    uint32_t sd2[16] = {};
                    rd_bytes(sub + 0x40u, sd2, sizeof(sd2));
                    mta_logf("dbg", "  g+090+40..7C: [%08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X]",
                             sd2[0], sd2[1], sd2[2], sd2[3], sd2[4], sd2[5], sd2[6], sd2[7],
                             sd2[8], sd2[9], sd2[10], sd2[11], sd2[12], sd2[13], sd2[14], sd2[15]);
                    if (is_valid_ptr(sd2[0])) {
                        uint32_t h40[8] = {}, l40[8] = {}, v40[16] = {};
                        rd_bytes(sd2[0], h40, sizeof(h40));
                        mta_logf("dbg", "  S40(%08X)=[%08X %08X %08X %08X %08X %08X]",
                                 sd2[0], h40[0], h40[1], h40[2], h40[3], h40[4], h40[5]);
                        if (is_valid_ptr(h40[0]) && h40[0] != sd2[0]) {
                            rd_bytes(h40[0], l40, sizeof(l40));
                            mta_logf("dbg", "  N40(%08X)=[%08X %08X %08X %08X %08X %08X]",
                                     h40[0], l40[0], l40[1], l40[2], l40[3], l40[4], l40[5]);
                            if (is_valid_ptr(l40[5])) {
                                rd_bytes(l40[5], v40, sizeof(v40));
                                mta_logf("dbg", "  V40(%08X)=[%08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X]",
                                         l40[5], v40[0], v40[1], v40[2], v40[3], v40[4], v40[5], v40[6], v40[7],
                                         v40[8], v40[9], v40[10], v40[11], v40[12], v40[13], v40[14], v40[15]);
                            }
                        }
                    }
                    if (is_valid_ptr(sd[14])) {
                        uint32_t h38[8] = {};
                        rd_bytes(sd[14], h38, sizeof(h38));
                        mta_logf("dbg", "  S38(%08X)=[%08X %08X %08X %08X %08X %08X]",
                                 sd[14], h38[0], h38[1], h38[2], h38[3], h38[4], h38[5]);
                    }
                }
            }
        }
    }
    for (uint32_t off = 0x10u; off <= 0x240u; off += 4u) {
        uint32_t cand = rd32(pGame + off);
        if (!is_valid_ptr(cand)) continue;
        if (try_accept_cand(cand, "CClientGame", pGame)) return true;
        for (uint32_t mo = 0x6Cu; mo <= 0x88u; mo += 4u) {
            uint32_t sub = rd32(cand + mo);
            if (try_accept_cand(sub, "CClientGame->Mgr", cand)) return true;
        }

        /* Busca generica por std::list<CResource*> dentro de cand+0x00..0x9C */
        uint32_t dw[44] = {};
        if (!rd_bytes(cand, dw, sizeof(dw))) continue;
        static const struct { uint32_t h, s, v; } kVariants[] = {
            { 0u, 4u,  8u },
            { 0u, 4u, 12u },
            { 4u, 8u, 12u }
        };
        for (uint32_t loff = 0x00u; loff <= 0x9Cu; loff += 4u) {
            for (int vi = 0; vi < 3; ++vi) {
                uint32_t hOff = kVariants[vi].h;
                uint32_t sOff = kVariants[vi].s;
                uint32_t vOff = kVariants[vi].v;
                uint32_t S  = dw[(loff + hOff) / 4u];
                uint32_t sz = dw[(loff + sOff) / 4u];
                if (!is_valid_ptr(S) || sz < 1u || sz > RES_MAX) continue;
                uint32_t n0 = rd32(S);
                uint32_t pv = rd32(S + 4u);
                if (!is_valid_ptr(n0) || !is_valid_ptr(pv) || n0 == S || pv == S) continue;
                if (rd32(n0 + 4u) != S || rd32(pv) != S) continue;
                uint32_t item0 = rd32(n0 + vOff);
                if (!is_valid_ptr(item0)) continue;

                if (allowDump && off == 0x90u && loff == 0x38u) {
                    uint32_t nd[6] = {}, idw[16] = {};
                    rd_bytes(n0, nd, sizeof(nd));
                    rd_bytes(item0, idw, sizeof(idw));
                    mta_logf("dbg", "  g+090 list+38(v%d) S=%08X sz=%u n0=[%08X %08X %08X %08X] item0=%08X idw=[%08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X]",
                             vi, S, sz, nd[0], nd[1], nd[2], nd[3], item0,
                             idw[0], idw[1], idw[2], idw[3], idw[4], idw[5], idw[6], idw[7],
                             idw[8], idw[9], idw[10], idw[11]);
                }

                /* Tenta decodificar ponteiro ofuscado (xor_netid) quando vi == 1 ({0,4,12}) */
                if (vi == 1 && g_fnResMagic) {
                    ListShape encSh = { loff, hOff, sOff, vOff, 0u, 0u, 0u, 0u, false, false, true, "CResourceManager xor_netid" };
                    uint32_t dec0 = list_item_at(cand, encSh, n0);
                    uint32_t net0 = rd32(n0 + 8u) & 0xFFFFu;
                    if (is_valid_ptr(dec0) && (rd32(dec0) & 0xFFFFu) == net0) {
                        if (allowDump) {
                            for (uint32_t ro = 0; ro < 0x100u; ro += 0x40u) {
                                uint32_t rdw[16] = {};
                                rd_bytes(dec0 + ro, rdw, sizeof(rdw));
                                mta_logf("dbg", "  decRes(%08X)+%02X: %08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X | %08X %08X %08X %08X",
                                         dec0, ro, rdw[0], rdw[1], rdw[2], rdw[3], rdw[4], rdw[5], rdw[6], rdw[7],
                                         rdw[8], rdw[9], rdw[10], rdw[11], rdw[12], rdw[13], rdw[14], rdw[15]);
                            }
                            for (uint32_t so = 0x04u; so <= 0xE8u; so += 4u) {
                                char ts[128] = "";
                                if (sstring_valid_at(dec0 + so, 120u, ts, sizeof(ts))) {
                                    mta_logf("dbg", "  decRes sstr@+%02X='%s'", so, ts);
                                }
                            }
                        }
                        for (uint32_t no = 0x04u; no <= 0xE8u; no += 4u) {
                            char nm0[128] = "";
                            if (!cres_name(dec0, no, nm0, sizeof(nm0))) continue;
                            if (strchr(nm0, ' ')) continue;
                            bool ok2 = true;
                            if (sz >= 2u) {
                                uint32_t n1 = rd32(n0);
                                uint32_t dec1 = is_valid_ptr(n1) ? list_item_at(cand, encSh, n1) : 0u;
                                uint32_t net1 = is_valid_ptr(n1) ? (rd32(n1 + 8u) & 0xFFFFu) : 0xFFFFFFFFu;
                                char nm1[128] = "";
                                ok2 = is_valid_ptr(dec1) && ((rd32(dec1) & 0xFFFFu) == net1) &&
                                      cres_name(dec1, no, nm1, sizeof(nm1)) && !strchr(nm1, ' ');
                            }
                            if (!ok2) continue;
                            uint32_t curN = n0;
                            bool ringOk = true;
                            uint32_t chk = sz < 64u ? sz : 64u;
                            for (uint32_t k = 0; k < chk; ++k) {
                                if (!is_valid_ptr(curN) || curN == S) { ringOk = false; break; }
                                curN = rd32(curN);
                            }
                            if (sz <= 64u && curN != S) ringOk = false;
                            if (!ringOk) continue;

                            kShapes[6] = encSh;
                            kShapesActiveN = 7;
                            g_shapeIdx     = 6;
                            g_filesShapeIdx = -1;
                            g_resNameOff   = no;
                            g_resFilesOff  = 0xFFFFFFFFu;
                            g_cfileOff     = CFILE_NAME_REL;
                            g_resMgr       = cand;
                            g_rt.state     = ST_COLLECT;
                            g_rt.cursor    = 0;
                            g_rt.miss      = 0;
                            g_rt.modIdx    = 0;
                            mta_logf("rt", "CResourceManager=%08X via xor_netid (game+%03X list+%02X sz=%u nome@+%02X ex='%s')",
                                     cand, off, loff, sz, no, nm0);
                            extract_clientgame_http_url(pGame);
                            return true;
                        }
                    }
                }

                static const uint32_t kNameOffs[] = { 0x0Cu, 0x10u, 0x08u, 0x14u, 0x18u, 0x04u, 0x1Cu, 0x20u, 0x24u, 0x28u, 0x2Cu, 0x30u };
                for (uint32_t no : kNameOffs) {
                    char nm0[128] = "";
                    if (!cres_name(item0, no, nm0, sizeof(nm0))) continue;
                    if (strchr(nm0, ' ')) continue;
                    bool ok2 = cres_hdr_ok(item0, true);
                    if (!ok2 && sz >= 2u) {
                        uint32_t n1 = rd32(n0);
                        uint32_t item1 = is_valid_ptr(n1) ? rd32(n1 + vOff) : 0u;
                        char nm1[128] = "";
                        ok2 = is_valid_ptr(item1) && cres_name(item1, no, nm1, sizeof(nm1)) && !strchr(nm1, ' ');
                    }
                    if (!ok2) continue;
                    uint32_t curN = n0;
                    bool ringOk = true;
                    uint32_t chk = sz < 64u ? sz : 64u;
                    for (uint32_t k = 0; k < chk; ++k) {
                        if (!is_valid_ptr(curN) || curN == S) { ringOk = false; break; }
                        curN = rd32(curN);
                    }
                    if (sz <= 64u && curN != S) ringOk = false;
                    if (!ringOk) continue;

                    kShapes[6] = { loff, hOff, sOff, vOff, 0u, 0u, 0u, 0u, false, false, false, "dynamic std::list" };
                    kShapesActiveN = 7;
                    g_shapeIdx     = 6;
                    g_filesShapeIdx = -1;
                    g_resNameOff   = no;
                    g_resFilesOff  = 0xFFFFFFFFu;
                    g_cfileOff     = CFILE_NAME_REL;
                    g_resMgr       = cand;
                    g_rt.state     = ST_COLLECT;
                    g_rt.cursor    = 0;
                    g_rt.miss      = 0;
                    g_rt.modIdx    = 0;
                    mta_logf("rt", "CResourceManager=%08X via dyn_list (game+%03X list+%02X v%d sz=%u nome@+%02X ex='%s')",
                             cand, off, loff, vi, sz, no, nm0);
                    extract_clientgame_http_url(pGame);
                    return true;
                }
            }
        }
    }
    return false;
}

static void dump_code_hex(const char* tag, uint32_t addr, uint32_t len) {
    uint8_t buf[256] = {};
    if (!addr || !len) return;
    if (len > sizeof(buf)) len = sizeof(buf);
    if (!rd_bytes(addr, buf, len)) return;
    for (uint32_t off = 0; off < len; off += 16u) {
        uint32_t rem = len - off;
        char line[96] = "";
        int pos = 0;
        for (uint32_t i = 0; i < 16u && i < rem; ++i) {
            pos += snprintf(line + pos, sizeof(line) - pos, "%02X ", buf[off + i]);
        }
        mta_logf("code", "%s+%02X (%08X): %s", tag, off, addr + off, line);
    }
}

static void find_client_funcs_and_mgr() {
    if (g_clientFuncsDone || !g_clientMod) return;
    g_clientFuncsDone = true;

    log_pe_sections(g_clientMod);

    uint32_t modBase = 0, modEnd = 0;
    if (!get_module_bounds("client.dll", modBase, modEnd) &&
        !get_module_bounds("client_d.dll", modBase, modEnd)) {
        modBase = (uint32_t)(uintptr_t)g_clientMod;
        modEnd  = modBase + 0x1000000u;
    }

    uint32_t textLo, textHi, rdataLo, rdataHi, dataLo, dataHi;
    if (!pe_get_ranges(g_clientMod, textLo, textHi, rdataLo, rdataHi, dataLo, dataHi)) return;

    /* 0. Localiza vtable do CClientManager / CClientEntity via MSVC RTTI */
    g_rttiClientMgrVt = find_rtti_vtable(modBase, modEnd, ".?AVCClientManager@@");
    uint32_t vtEnt = find_rtti_vtable(modBase, modEnd, ".?AVCClientEntity@@");
    mta_logf("rt", "rtti CClientManager=%08X CClientEntity=%08X", g_rttiClientMgrVt, vtEnt);
    if (g_rttiClientMgrVt && dataLo && dataHi > dataLo) {
        for (uint32_t a = dataLo; a + 4u <= dataHi; a += 4u) {
            uint32_t p = rd32(a);
            if (!is_valid_ptr(p)) continue;
            if (rd32(p) == g_rttiClientMgrVt) {
                uint32_t mgr = rd32(p + g_off.resMgrField);
                if (is_valid_ptr(mgr)) {
                    int hint = -1;
                    if (mgr_prefilter(mgr, &hint) && accept_mgr(mgr, hint, "rtti_cm", p)) break;
                    dump_mgr_probe("rtti_cm_reject", p, mgr);
                }
            }
        }
    }

    /* 1. Localiza CResource::Stop() e CResourceManager::Remove(CResource*) via "onClientResourceStop" */
    static const char kStopStr[] = "onClientResourceStop";
    uint32_t sStop = find_mem_bytes(modBase, modEnd, kStopStr, sizeof(kStopStr), false);
    if (sStop) {
        uint32_t curS = textLo;
        for (int sr = 0; sr < 6; ++sr) {
            uint32_t stopRef = find_mem_bytes(curS, textHi, &sStop, 4u, true);
            if (!stopRef) break;
            uint8_t sb[16] = {};
            if (stopRef > textLo + 8u) rd_bytes(stopRef - 8u, sb, sizeof(sb));
            uint32_t fn = walk_back_prologue(stopRef, textLo, 800u);
            mta_logf("rt", "sStop[%d]=%08X ref=%08X fn=%08X bytes=[%02X %02X %02X %02X %02X %02X %02X %02X | %02X %02X %02X %02X %02X %02X %02X %02X]",
                     sr, sStop, stopRef, fn,
                     sb[0], sb[1], sb[2], sb[3], sb[4], sb[5], sb[6], sb[7],
                     sb[8], sb[9], sb[10], sb[11], sb[12], sb[13], sb[14], sb[15]);
            if (fn && !g_fnResStop) {
                int calls = 0;
                uint32_t rem = find_unique_call_caller(textLo, textHi, fn, calls);
                if (rem || sr > 0) {
                    g_fnResStop = fn;
                    g_fnResRemove = rem;
                    mta_logf("rt", "xref stop=%08X remove=%08X (calls=%d)",
                             g_fnResStop, g_fnResRemove, calls);
                    dump_code_hex("Stop", g_fnResStop, 128u);
                    if (g_fnResRemove) {
                        dump_code_hex("Remove", g_fnResRemove, 160u);
                        /* Localiza funcao da chave XOR de ponteiro (chamada logo antes de OR reg, 0x51A3) */
                        uint8_t rb[128] = {};
                        if (rd_bytes(g_fnResRemove, rb, sizeof(rb))) {
                            if (rb[0x24] == 0xE8u) {
                                int32_t frel = *(const int32_t*)(rb + 0x25);
                                uint32_t ffind = g_fnResRemove + 0x29u + (uint32_t)frel;
                                dump_code_hex("RemFind", ffind, 128u);
                            }
                            for (uint32_t k = 0x10u; k + 12u <= sizeof(rb); ++k) {
                                if (rb[k] == 0x0Fu && rb[k + 1] == 0xB7u && rb[k + 3] == 0xE8u) {
                                    int32_t mrel = *(const int32_t*)(rb + k + 4);
                                    uint32_t candFn = g_fnResRemove + k + 8u + (uint32_t)mrel;
                                    if (candFn >= textLo && candFn < textHi) {
                                        g_fnResMagic = candFn;
                                        g_resMagicLogged = false;
                                        dump_code_hex("ResMagic", g_fnResMagic, 64u);
                                        break;
                                    }
                                }
                            }
                        }
                        int rcalls = 0;
                        __try {
                            for (uint32_t a = textLo; a + 5u <= textHi && rcalls < 6; ++a) {
                                const uint8_t* p = (const uint8_t*)(uintptr_t)a;
                                if (p[0] != 0xE8u) continue;
                                int32_t rel = *(const int32_t*)(p + 1);
                                if (a + 5u + (uint32_t)rel == g_fnResRemove) {
                                    ++rcalls;
                                    uint32_t cfn = walk_back_prologue(a, textLo, 320u);
                                    mta_logf("code", "Remove caller[%d] @ %08X (fn=%08X)",
                                             rcalls, a, cfn);
                                    dump_code_hex("RemCall", (a > textLo + 32u) ? (a - 32u) : textLo, 48u);
                                    if (rcalls == 2 && cfn) dump_code_hex("RemFn2", cfn, 192u);
                                }
                            }
                        } __except (EXCEPTION_EXECUTE_HANDLER) {}
                    }
                }
            }
            curS = stopRef + 4u;
        }
    }

    /* 2. Outras strings-chave do client.dll para achar g_pClientGame / CResourceManager */
    static const char kStartStr[] = "onClientResourceStart";
    static const char kDupStr[]   = "Ignoring duplicate file in resource";
    static const char kDelStr[]   = "Unable to delete old file";
    static const char kDlErrStr[] = "Download error:";
    static const char kGetResN[]  = "getResourceName";
    log_text_refs_and_probe("onResStart",  find_mem_bytes(modBase, modEnd, kStartStr, sizeof(kStartStr) - 1, false), textLo, textHi, dataLo, dataHi);
    log_text_refs_and_probe("dupFile",     find_mem_bytes(modBase, modEnd, kDupStr,   sizeof(kDupStr) - 1,   false), textLo, textHi, dataLo, dataHi);
    log_text_refs_and_probe("delOldFile",  find_mem_bytes(modBase, modEnd, kDelStr,   sizeof(kDelStr) - 1,   false), textLo, textHi, dataLo, dataHi);
    log_text_refs_and_probe("dlErr",       find_mem_bytes(modBase, modEnd, kDlErrStr, sizeof(kDlErrStr) - 1, false), textLo, textHi, dataLo, dataHi);
    log_text_refs_and_probe("getResName",  find_mem_bytes(modBase, modEnd, kGetResN,  sizeof(kGetResN),      false), textLo, textHi, dataLo, dataHi);

    /* 3. Fast-path CResourceManager via tabela Lua {"getResources", fn, "getResourceState", fn} ou push <fn>; push "getResources" */
    if (!g_resMgr && dataLo && dataHi > dataLo) {
        static const char kGetRes[]   = "getResources";
        static const char kGetState[] = "getResourceState";
        uint32_t sGetRes   = find_mem_bytes(modBase, modEnd, kGetRes, sizeof(kGetRes), false);
        uint32_t sGetState = find_mem_bytes(modBase, modEnd, kGetState, sizeof(kGetState), false);
        if (sGetRes && sGetState) {
            uint32_t cur = modBase;
            while (cur + 16u <= modEnd) {
                uint32_t ref = find_mem_bytes(cur, modEnd, &sGetRes, 4u, false);
                if (!ref || ref + 16u > modEnd) break;
                uint32_t dw[4] = {};
                if (rd_bytes(ref, dw, sizeof(dw)) &&
                    dw[0] == sGetRes && dw[2] == sGetState &&
                    dw[1] >= textLo && dw[1] < textHi &&
                    dw[3] >= textLo && dw[3] < textHi) {
                    if (probe_code_for_resmgr(dw[1], textLo, textHi, dataLo, dataHi, 0)) break;
                }
                cur = ref + 4u;
            }
        }
        if (!g_resMgr && !g_luaResMgrSlot && sGetRes) {
            uint32_t ps = find_mem_bytes(textLo, textHi, &sGetRes, 4u, true);
            if (ps && ps > textLo + 16u) {
                __try {
                    for (uint32_t b = ps - 5u; b >= ps - 20u; --b) {
                        const uint8_t* p = (const uint8_t*)(uintptr_t)b;
                        if (p[0] == 0x68u) {
                            uint32_t fn = *(const uint32_t*)(p + 1);
                            if (fn >= textLo && fn < textHi) {
                                if (probe_code_for_resmgr(fn, textLo, textHi, dataLo, dataHi, 0)) break;
                            }
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
        mta_logf("rt", "xref lua: sStop=%08X sGetRes=%08X slot=%08X mgr=%08X (data=%08X..%08X)",
                 sStop, sGetRes, g_luaResMgrSlot, g_resMgr, dataLo, dataHi);
    }
}

static void scan_mgr_pass() {
    if (g_clientGameSlot) {
        uint32_t pGame = rd32(g_clientGameSlot);
        if (is_valid_ptr(pGame)) {
            static int s_lastDumpMiss = -1;
            if (g_rt.miss == 0) s_lastDumpMiss = -1;
            bool allowDump = (g_rt.miss == 1 || g_rt.miss == 4) && (s_lastDumpMiss != g_rt.miss);
            if (allowDump) s_lastDumpMiss = g_rt.miss;
            if (probe_client_game_deep(pGame, allowDump)) return;
        }
    }
    if (!g_rt.cursor) {
        fill_sweep();
        if (!g_sweepN) { g_rt.state = ST_WAIT_SERVER; return; }
        if (g_rt.modIdx >= g_sweepN) g_rt.modIdx = 0;
        uint32_t ds = g_sweepMods[g_rt.modIdx].secLo;
        uint32_t de = g_sweepMods[g_rt.modIdx].secHi;
        if (!ds || de <= ds) { g_rt.state = ST_REARM; return; }
        g_rt.lo = ds;
        g_rt.hi = de;
        g_rt.cursor = ds;
    }

    const uint32_t modBase = g_sweepMods[g_rt.modIdx].base;
    const uint32_t modEnd  = g_sweepMods[g_rt.modIdx].end;
    const uint32_t want    = g_rttiClientMgrVt ? g_rttiClientMgrVt
                           : ((g_off.mgrVt && g_off.clientBase && g_off.resMgrField)
                              ? (g_off.clientBase + g_off.mgrVt) : 0u);

    uint32_t stop = g_rt.cursor + SCAN_CHUNK;
    if (stop > g_rt.hi || stop < g_rt.cursor) stop = g_rt.hi;

    for (; g_rt.cursor + 4u <= stop; g_rt.cursor += 4u) {
        if (g_budgetSpent) return;

        uint32_t p = rd32(g_rt.cursor);
        if (!is_valid_ptr(p)) continue;

        if (g_rt.scanPhase == 0) {
            if (want) {
                if (!spend(2)) return;
                uint32_t inst = (p == want) ? g_rt.cursor : (rd32(p) == want ? p : 0u);
                if (inst) {
                    uint32_t mgr = rd32(inst + g_off.resMgrField);
                    if (is_valid_ptr(mgr)) {
                        if (prove_mgr(mgr) || mgr_looks_valid_empty(mgr)) {
                            g_off.inst = inst;
                            g_off.ok   = 1;
                            g_resMgr   = mgr;
                            g_rt.state = ST_COLLECT;
                            g_rt.cursor = 0;
                            g_rt.miss  = 0;
                            g_rt.modIdx = 0;
                            mta_logf("rt", "vtable ancora inst=%08X -> CResourceManager=%08X", inst, mgr);
                            return;
                        } else if (g_rt.miss == 0) {
                            dump_mgr_probe("scan_vt_reject", inst, mgr);
                        }
                    }
                }
            }

            /* Ignora ponteiros para .text/.rdata do proprio modulo */
            if (p >= modBase && p < g_rt.lo) continue;
            if (p >= g_rt.hi && p < modEnd)  continue;

            if (try_accept_cand(p, "global_ptr", g_rt.cursor)) return;

            for (uint32_t off = 0x6Cu; off <= 0x84u; off += 4u) {
                if (!spend(2)) return;
                uint32_t cand = rd32(p + off);
                if (try_accept_cand(cand, "CClientManager", p)) return;
            }
        } else {
            /* Ignora ponteiros para .text/.rdata do proprio modulo */
            if (p >= modBase && p < g_rt.lo) continue;
            if (p >= g_rt.hi && p < modEnd)  continue;

            /* CClientGame tem m_Status (0..10) + m_ServerType (0..10) ou vtable em +0x00 */
            uint32_t hdr[3] = {};
            if (!spend(2)) return;
            if (!rd_bytes(p, hdr, sizeof(hdr))) continue;
            bool gameHdr = (hdr[0] <= 12u && hdr[1] <= 12u) ||
                           (hdr[0] >= modBase && hdr[0] < modEnd && hdr[1] <= 12u && hdr[2] <= 12u);
            if (!gameHdr) continue;
            for (uint32_t off = 0x10u; off <= 0x240u; off += 4u) {
                if (!spend(2)) return;
                uint32_t cand = rd32(p + off);
                if (try_accept_cand(cand, "CClientGame", p)) return;
            }
        }
    }

    if (g_rt.cursor >= g_rt.hi) {
        g_rt.cursor = 0;
        if (g_rt.scanPhase == 0) {
            g_rt.scanPhase = 1;
            return;
        }
        g_rt.scanPhase = 0;
        if (g_rt.modIdx + 1 < g_sweepN) {
            ++g_rt.modIdx;
        } else {
            g_rt.modIdx = 0;
            ++g_rt.miss;
            if (g_rt.miss == 1 || (g_rt.miss % 10) == 0) {
                mta_logf("rt", "scan miss=%d sweeps=%d want=%08X", g_rt.miss, g_sweepN, want);
            }
        }
    }
}

/* -------------------------------------------------------- runtime tick */
static void rt_init() {
    shape_reset();
    g_rt = {};
    g_rt.state = ST_WAIT_SERVER;
    g_off.tried = 0;
    g_off.ok    = 0;
}

static void update_server_info(uint32_t now, bool inServer) {
    char cnetBuf[96] = "";
    bool cnetConn = false;
    if (InterlockedCompareExchange(&g_cnetCsReady, 0, 0)) {
        EnterCriticalSection(&g_cnetCs);
        cnetConn = g_cnetConn;
        snprintf(cnetBuf, sizeof(cnetBuf), "%s", g_cnetServer);
        LeaveCriticalSection(&g_cnetCs);
    }

    char curCopy[64] = "";
    EnterCriticalSection(&g_modsCs);
    snprintf(curCopy, sizeof(curCopy), "%s", g_curServer);
    LeaveCriticalSection(&g_modsCs);

    char detected[64] = "";
    if (cnetBuf[0]) {
        const char* col = strrchr(cnetBuf, ':');
        if (col && col[1]) {
            char host[64] = "", ip[64] = "";
            size_t n = (size_t)(col - cnetBuf);
            if (n > 0 && n < sizeof(host)) {
                memcpy(host, cnetBuf, n); host[n] = 0;
                if (resolve_host_ipv4(host, ip, sizeof(ip)))
                    snprintf(detected, sizeof(detected), "%s:%u", ip, (unsigned)atoi(col + 1));
                else
                    snprintf(detected, sizeof(detected), "%s", cnetBuf);
            }
        } else {
            char ip[64] = "";
            if (resolve_host_ipv4(cnetBuf, ip, sizeof(ip)))
                snprintf(detected, sizeof(detected), "%s:22003", ip);
        }
    }

    if (!detected[0] && inServer && (now - g_rt.tcpAt >= TCP_POLL_MS || !curCopy[0])) {
        g_rt.tcpAt = now;
        if (!server_from_coreconfig(detected, sizeof(detected))) {
            if (!server_from_cfg(detected, sizeof(detected))) {
                server_from_tcp(curCopy, detected, sizeof(detected));
            }
        }
    }

    if (detected[0]) {
        if (strcmp(detected, curCopy) != 0) {
            EnterCriticalSection(&g_modsCs);
            snprintf(g_curServer, sizeof(g_curServer), "%s", detected);
            rm::g_explodeEnabled = true;
            LeaveCriticalSection(&g_modsCs);
            g_rt.needHttp = 1;
            g_rt.tName    = now;
            mta_logf("net", "servidor detectado: %s", detected);
        }
    } else if (!inServer && !cnetConn && curCopy[0]) {
        EnterCriticalSection(&g_modsCs);
        g_curServer[0]  = 0;
        rm::g_explodeEnabled = false;
        g_httpServer[0] = 0;
        g_clientUrl[0]  = 0;
        g_srvName[0]    = 0;
        LeaveCriticalSection(&g_modsCs);
    }

    if ((detected[0] || curCopy[0]) && !g_srvName[0] && now - g_rt.tName >= 15000u) {
        g_rt.tName    = now;
        g_rt.needHttp = 1;
    }
}

static void rt_tick() {
    if (!g_off.tried) { g_off.tried = 1; off_load(); }
    if (g_rt.state == ST_OFF) return;

    uint32_t now = GetTickCount();
    HMODULE hCli = GetModuleHandleA("client.dll");
    if (!hCli) hCli = GetModuleHandleA("client_d.dll");

    update_server_info(now, hCli != nullptr);
    if (g_rt.needHttp) { g_rt.needHttp = 0; resolve_http(); }

    if (!hCli) {
        if (g_clientMod || g_resMgr || !g_mods.empty()) {
            g_clientMod = nullptr;
            reset_session("saiu do servidor");
        }
        g_rt.state = ST_WAIT_SERVER;
        return;
    }

    if (hCli != g_clientMod) {
        g_clientMod = hCli;
        g_off.ok = 0;
        g_off.inst = 0;
        g_off.clientBase = 0;
        g_luaResMgrSlot = 0;
        g_rttiClientMgrVt = 0;
        g_fnResStop = 0;
        g_fnResRemove = 0;
        g_fnResMagic = 0;
        g_resMagicLogged = false;
        g_clientFuncsDone = false;
        fill_sweep();
        g_rt.state     = ST_SCAN_MGR;
        g_rt.scanPhase = 0;
        g_rt.cursor    = 0;
        g_rt.miss      = 0;
        g_rt.modIdx    = 0;
        mta_logf("rt", "client.dll carregada @ %p", (void*)hCli);
    }

    if (!g_clientFuncsDone) find_client_funcs_and_mgr();
    if (!g_resMgr && g_luaResMgrSlot) {
        uint32_t cand = rd32(g_luaResMgrSlot);
        int hint = -1;
        if (mgr_prefilter(cand, &hint)) accept_mgr(cand, hint, "lua_slot", g_luaResMgrSlot);
    }
    if (!g_off.ok) resolve_from_offsets();
    if (g_off.ok && g_resMgr && g_rt.state != ST_COLLECT) {
        g_rt.state  = ST_COLLECT;
        g_rt.cursor = 0;
    }

    uint32_t interval = (g_rt.state == ST_SCAN_MGR) ? SCAN_TICK_MS : TICK_MS;
    if (now - g_rt.tick < interval) return;
    g_rt.tick = now;
    ++g_rt.tCount;
    budget_reset();

    switch (g_rt.state) {
        case ST_SCAN_MGR:
            scan_mgr_pass();
            if (g_rt.state == ST_COLLECT && g_resMgr) {
                g_rt.modSig   = mod_list_sig();
                g_rt.tCollect = g_rt.tCount;
                collect_mods();
            }
            break;
        case ST_REARM:
            g_rt.cursor    = 0;
            g_rt.scanPhase = 0;
            g_rt.modIdx    = (g_rt.modIdx + 1 < g_sweepN) ? g_rt.modIdx + 1 : 0;
            g_rt.state     = ST_SCAN_MGR;
            break;
        case ST_COLLECT:
            if (g_resMgr) {
                if (g_clientGamePtr && !g_clientUrl[0]) extract_clientgame_http_url(g_clientGamePtr);
                uint32_t sig = mod_list_sig();
                if (g_shapeIdx < 0 || sig != g_rt.modSig || g_rt.tCount - g_rt.tCollect >= COLLECT_EVERY) {
                    g_rt.modSig   = sig;
                    g_rt.tCollect = g_rt.tCount;
                    collect_mods();
                }
            } else {
                g_rt.state = ST_REARM;
            }
            break;
        default: break;
    }
}

/* ----------------------------------------------------------- downloader */
static void set_status(const char* fmt, ...) {
    char m[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(m, sizeof(m), fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_workCs);
    snprintf(g_job.status, sizeof(g_job.status), "%s", m);
    LeaveCriticalSection(&g_workCs);
}

static void mkdirs(const std::string& dir) {
    std::string d;
    for (size_t i = 0; i < dir.size(); ++i) {
        d += dir[i];
        if ((dir[i] == '\\' || dir[i] == '/') && i + 1 < dir.size()) _mkdir(d.c_str());
    }
    _mkdir(dir.c_str());
}

static bool write_file(const std::string& path, const std::string& data) {
    size_t sl = path.find_last_of("\\/");
    if (sl != std::string::npos) mkdirs(path.substr(0, sl));
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    size_t done = 0;
    bool ok = true;
    while (done < data.size()) {
        DWORD n = 0;
        DWORD chunk = (DWORD)std::min<size_t>(data.size() - done, 65536u);
        if (!WriteFile(h, data.data() + done, chunk, &n, nullptr) || !n) { ok = false; break; }
        done += n;
    }
    CloseHandle(h);
    return ok;
}

static bool http_get(const char* ipPort, const std::string& path,
                     std::string& body, unsigned long& status, char* err, size_t errCap,
                     DWORD timeoutMs = 6000) {
    body.clear();
    status = 0;
    if (err && errCap) err[0] = 0;

    std::string host = ipPort ? ipPort : "";
    bool useHttps = false;
    if (host.compare(0, 8, "https://") == 0) { useHttps = true; host = host.substr(8); }
    else if (host.compare(0, 7, "http://") == 0) { host = host.substr(7); }

    std::string basePath;
    size_t s2 = host.find('/');
    if (s2 != std::string::npos) {
        basePath = host.substr(s2);
        while (!basePath.empty() && basePath.back() == '/') basePath.pop_back();
        host = host.substr(0, s2);
    }

    unsigned short port = useHttps ? 443 : 80;
    size_t c = host.rfind(':');
    if (c != std::string::npos) {
        port = (unsigned short)atoi(host.c_str() + c + 1);
        host = host.substr(0, c);
    }
    if (host.empty()) {
        if (err) snprintf(err, errCap, "host vazio");
        return false;
    }

    std::string fullPath = basePath + path;
    std::string esc;
    esc.reserve(fullPath.size() + 16);
    for (char ch : fullPath) {
        if (ch == ' ') esc += "%20";
        else esc += ch;
    }

    wchar_t whost[128] = {}, wpath[640] = {};
    MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, whost, 128);
    MultiByteToWideChar(CP_UTF8, 0, esc.c_str(),  -1, wpath, 640);

    HINTERNET sess = WinHttpOpen(L"MTAResMgr/0.4", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) { if (err) snprintf(err, errCap, "WinHttpOpen"); return false; }
    WinHttpSetTimeouts(sess, (int)timeoutMs, (int)timeoutMs, (int)timeoutMs, (int)timeoutMs);

    HINTERNET conn = WinHttpConnect(sess, whost, (INTERNET_PORT)port, 0);
    bool ok = false;
    if (conn) {
        DWORD flags = useHttps ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET req = WinHttpOpenRequest(conn, L"GET", wpath, nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (req) {
            if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(req, nullptr)) {
                DWORD st = 0, len = sizeof(st);
                WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &st, &len, WINHTTP_NO_HEADER_INDEX);
                status = st;
                for (;;) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(req, &avail) || !avail) break;
                    size_t at = body.size();
                    body.resize(at + avail);
                    DWORD got = 0;
                    if (!WinHttpReadData(req, &body[at], avail, &got) || !got) { body.resize(at); break; }
                    body.resize(at + got);
                    if (body.size() > 64u * 1024u * 1024u) break;
                }
                ok = (status >= 200 && status < 300);
                if (!ok && err) snprintf(err, errCap, "http %lu", status);
            } else if (err) {
                DWORD le = GetLastError();
                if (le == 12002) snprintf(err, errCap, "timeout HTTP (err=12002)");
                else             snprintf(err, errCap, "conexao falhou (err=%lu)", le);
            }
            WinHttpCloseHandle(req);
        }
        WinHttpCloseHandle(conn);
    } else if (err) {
        snprintf(err, errCap, "WinHttpConnect");
    }
    WinHttpCloseHandle(sess);
    return ok;
}

static int find_mod_locked(const char* n) {
    for (size_t i = 0; i < g_mods.size(); ++i)
        if (!strcmp(g_mods[i].name, n)) return (int)i;
    return -1;
}

static void start_download(const char* mod) {
    std::vector<std::string> files;
    bool stopped = false;
    char http[160] = "";
    EnterCriticalSection(&g_modsCs);
    int idx = find_mod_locked(mod);
    if (idx >= 0) { stopped = g_mods[idx].stopped; files = g_mods[idx].fileList; }
    snprintf(http, sizeof(http), "%s", g_httpServer[0] ? g_httpServer : g_curServer);
    LeaveCriticalSection(&g_modsCs);

    if (stopped) { set_status("'%s' esta parado", mod); return; }
    if (!http[0]) { set_status("sem servidor conectado"); return; }

    EnterCriticalSection(&g_workCs);
    if (g_job.active) {
        LeaveCriticalSection(&g_workCs);
        set_status("um download ja esta rodando");
        return;
    }
    g_job.active = true;
    snprintf(g_job.mod, sizeof(g_job.mod), "%s", mod);
    g_job.total = (int)files.size();
    g_job.done  = 0;
    g_job.fail  = 0;
    g_job.queue.swap(files);
    g_job.batchMods.clear();
    snprintf(g_job.status, sizeof(g_job.status),
             g_job.total ? "baixando %d arquivo(s)..." : "obtendo meta.xml...", g_job.total);
    LeaveCriticalSection(&g_workCs);
    if (g_workEv) SetEvent(g_workEv);
}

static void start_download_all() {
    std::vector<std::string> mods;
    char http[160] = "";
    EnterCriticalSection(&g_modsCs);
    snprintf(http, sizeof(http), "%s", g_httpServer[0] ? g_httpServer : g_curServer);
    for (size_t i = 0; i < g_mods.size(); ++i) {
        if (!g_mods[i].stopped && !g_mods[i].fileList.empty())
            mods.push_back(g_mods[i].name);
    }
    LeaveCriticalSection(&g_modsCs);

    if (!http[0]) { set_status("sem servidor conectado"); return; }
    if (mods.empty()) { set_status("nenhum resource com arquivos para baixar"); return; }

    std::string first = mods.front();
    mods.erase(mods.begin());

    std::vector<std::string> firstFiles;
    EnterCriticalSection(&g_modsCs);
    int idx = find_mod_locked(first.c_str());
    if (idx >= 0) firstFiles = g_mods[idx].fileList;
    LeaveCriticalSection(&g_modsCs);

    EnterCriticalSection(&g_workCs);
    if (g_job.active) {
        LeaveCriticalSection(&g_workCs);
        set_status("um download ja esta rodando");
        return;
    }
    g_job.active = true;
    snprintf(g_job.mod, sizeof(g_job.mod), "%s", first.c_str());
    g_job.total = (int)firstFiles.size();
    g_job.done  = 0;
    g_job.fail  = 0;
    g_job.queue.swap(firstFiles);
    g_job.batchMods.swap(mods);
    snprintf(g_job.status, sizeof(g_job.status),
             "baixando %s (%d restantes)...", g_job.mod, (int)g_job.batchMods.size());
    LeaveCriticalSection(&g_workCs);
    if (g_workEv) SetEvent(g_workEv);
}

static void do_download_job() {
    char mod[128] = "";
    std::vector<std::string> queue;
    EnterCriticalSection(&g_workCs);
    snprintf(mod, sizeof(mod), "%s", g_job.mod);
    queue.swap(g_job.queue);
    LeaveCriticalSection(&g_workCs);

    char http[160] = "";
    EnterCriticalSection(&g_modsCs);
    snprintf(http, sizeof(http), "%s", g_httpServer[0] ? g_httpServer : g_curServer);
    LeaveCriticalSection(&g_modsCs);

    if (queue.empty() && http[0]) {
        std::string body;
        unsigned long st = 0;
        char err[64];
        std::string mp = std::string("/") + mod + "/meta.xml";
        if (g_urlCserver) mp = "/cserver" + mp;
        if (http_get(http, mp, body, st, err, sizeof(err))) {
            parse_meta(body, queue);
            EnterCriticalSection(&g_workCs);
            g_job.total = (int)queue.size();
            LeaveCriticalSection(&g_workCs);
        } else {
            EnterCriticalSection(&g_workCs);
            snprintf(g_job.status, sizeof(g_job.status), "meta de '%s' falhou (%s)", mod, err);
            g_job.active = false;
            g_job.batchMods.clear();
            LeaveCriticalSection(&g_workCs);
            return;
        }
    }

    std::string base = std::string(RM_MODS_DIR) + "\\" + mod;
    if (!queue.empty()) mkdirs(base);

    for (size_t i = 0; i < queue.size(); ++i) {
        if (g_quit) break;
        const std::string& f = queue[i];
        std::string p = std::string("/") + mod + "/" + f;
        if (g_urlCserver) p = "/cserver" + p;
        std::string body;
        unsigned long st = 0;
        char err[64];
        bool ok = http_get(http, p, body, st, err, sizeof(err));
        if (!ok) { Sleep(350); ok = http_get(http, p, body, st, err, sizeof(err), 10000); }
        if (ok) {
            std::string outp = base + "\\" + f;
            for (auto& ch : outp) if (ch == '/') ch = '\\';
            if (!write_file(outp, body)) ok = false;
        }
        EnterCriticalSection(&g_workCs);
        if (ok) {
            ++g_job.done;
            snprintf(g_job.status, sizeof(g_job.status), "[%d/%d] %s (%u KB, crc32=%08X)",
                     g_job.done + g_job.fail, g_job.total, f.c_str(),
                     (unsigned)(body.size() / 1024),
                     (unsigned)crc32(body.data(), body.size()));
        } else {
            ++g_job.fail;
            snprintf(g_job.status, sizeof(g_job.status), "[%d/%d] %s -> %s",
                     g_job.done + g_job.fail, g_job.total, f.c_str(), err);
        }
        LeaveCriticalSection(&g_workCs);
    }

    mta_logf("dl", "%s: %d ok %d fail", mod, g_job.done, g_job.fail);

    std::string nextMod;
    std::vector<std::string> nextFiles;
    EnterCriticalSection(&g_workCs);
    if (!g_quit && !g_job.batchMods.empty()) {
        nextMod = g_job.batchMods.front();
        g_job.batchMods.erase(g_job.batchMods.begin());
    } else {
        snprintf(g_job.status, sizeof(g_job.status), "fim: %d ok, %d falha -> %s",
                 g_job.done, g_job.fail, base.c_str());
        g_job.active = false;
    }
    LeaveCriticalSection(&g_workCs);

    if (!nextMod.empty()) {
        EnterCriticalSection(&g_modsCs);
        int idx = find_mod_locked(nextMod.c_str());
        if (idx >= 0) nextFiles = g_mods[idx].fileList;
        LeaveCriticalSection(&g_modsCs);

        EnterCriticalSection(&g_workCs);
        snprintf(g_job.mod, sizeof(g_job.mod), "%s", nextMod.c_str());
        g_job.total = (int)nextFiles.size();
        g_job.done  = 0;
        g_job.fail  = 0;
        g_job.queue.swap(nextFiles);
        snprintf(g_job.status, sizeof(g_job.status), "baixando %s (%d restantes)...",
                 g_job.mod, (int)g_job.batchMods.size());
        LeaveCriticalSection(&g_workCs);
        if (g_workEv) SetEvent(g_workEv);
    }
}

static DWORD WINAPI worker_thread(LPVOID) {
    for (;;) {
        DWORD waitMs = (g_rt.state == ST_SCAN_MGR) ? SCAN_TICK_MS : TICK_MS;
        WaitForSingleObject(g_workEv, waitMs);
        if (g_quit) break;
        for (;;) {
            if (g_quit) break;
            EnterCriticalSection(&g_workCs);
            bool hasJob = g_job.active;
            LeaveCriticalSection(&g_workCs);
            if (!hasJob) break;
            do_download_job();
        }
        rt_tick();
    }
    return 0;
}

/* ---------------------------------------------------------------- explode all (portado de dllmain-2.cpp) */

static const uint32_t EXP_ADDR_PED_POOL   = 0xB74490u;
static const uint32_t EXP_PED_STRIDE      = 0x7C4u;
static const uint32_t EXP_POOL_OBJ_OFF    = 0x00u;
static const uint32_t EXP_POOL_FLAG_OFF   = 0x04u;
static const uint32_t EXP_POOL_SIZE_OFF   = 0x08u;
static const uint32_t EXP_PED_OFF_MATRIX  = 0x14u;
static const uint32_t EXP_CMTX_OFF_POS    = 0x30u;
static const uint32_t EXP_ADDR_EXPLOSION  = 0x736A50u;
static const int      EXP_EXPLOSION_GRENADE = 0;
static const float    EXP_SHAKE           = -1.0f;

struct ExpVec3 { float x, y, z; };

static uint32_t exp_get_local_ped() {
    uint32_t p = 0;
    __try { p = *(uint32_t*)(uintptr_t)0xB6F5F0u; } __except (EXCEPTION_EXECUTE_HANDLER) { p = 0; }
    if (!is_valid_ptr(p)) {
        __try { p = *(uint32_t*)(uintptr_t)0xB7CD98u; } __except (EXCEPTION_EXECUTE_HANDLER) { p = 0; }
    }
    return p;
}

static bool exp_get_ped_world_pos(uint32_t ped, ExpVec3& out) {
    if (!is_valid_ptr(ped)) return false;
    __try {
        uint32_t matrix = *(uint32_t*)(uintptr_t)(ped + EXP_PED_OFF_MATRIX);
        float* pos = nullptr;
        if (is_valid_ptr(matrix)) pos = (float*)(uintptr_t)(matrix + EXP_CMTX_OFF_POS);
        else pos = (float*)(uintptr_t)(ped + 0x04u);
        float x = pos[0], y = pos[1], z = pos[2];
        if (x == 0.0f && y == 0.0f && z == 0.0f) {
            if (is_valid_ptr(matrix)) {
                float* fp = (float*)(uintptr_t)(ped + 0x04u);
                x = fp[0]; y = fp[1]; z = fp[2];
            }
            if (x == 0.0f && y == 0.0f && z == 0.0f) return false;
        }
        if (!(x > -16000.0f && x < 16000.0f)) return false;
        if (!(y > -16000.0f && y < 16000.0f)) return false;
        if (!(z > -5000.0f && z < 10000.0f)) return false;
        out.x = x; out.y = y; out.z = z;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool exp_add_explosion(const ExpVec3& pos, int type, uint32_t owner, uint32_t exploding,
                              uint32_t delay, bool makeSound, float camShake, bool noDamage) {
    typedef void (__cdecl* fn_add_explosion)(uint32_t, uint32_t, int, float, float, float,
                                             uint32_t, uint32_t, float, uint32_t);
    bool ok = false;
    __try {
        fn_add_explosion fn = (fn_add_explosion)(uintptr_t)EXP_ADDR_EXPLOSION;
        fn(exploding, owner, type, pos.x, pos.y, pos.z, delay,
           makeSound ? 1u : 0u, camShake, noDamage ? 1u : 0u);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    return ok;
}

static void exp_explode_all() {
    uint32_t me = exp_get_local_ped();
    int count = 0, exploded = 0;
    __try {
        uint32_t pool = *(uint32_t*)(uintptr_t)EXP_ADDR_PED_POOL;
        if (!is_valid_ptr(pool)) return;
        uint32_t objects = *(uint32_t*)(uintptr_t)(pool + EXP_POOL_OBJ_OFF);
        uint32_t flags  = *(uint32_t*)(uintptr_t)(pool + EXP_POOL_FLAG_OFF);
        uint32_t size   = *(uint32_t*)(uintptr_t)(pool + EXP_POOL_SIZE_OFF);
        if (!is_valid_ptr(objects) || !is_valid_ptr(flags) || size == 0) return;
        if (size > 256) size = 256;
        for (uint32_t i = 0; i < size; ++i) {
            ++count;
            uint8_t flag = *(uint8_t*)(uintptr_t)(flags + i);
            if (flag & 0x80) continue;
            uint32_t ped = objects + i * EXP_PED_STRIDE;
            if (!is_valid_ptr(ped) || ped == me) continue;
            ExpVec3 pos;
            if (!exp_get_ped_world_pos(ped, pos)) continue;
            pos.z += 0.4f;
            if (exp_add_explosion(pos, EXP_EXPLOSION_GRENADE, me, 0, 0, true, EXP_SHAKE, false))
                ++exploded;
        }
        mta_logf("explode", "explode_all: pool=%d explodidos=%d", count, exploded);
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

/* ---------------------------------------------------------------- serial generator (totalmente interno) */

/* Serial MTA SA: 32 caracteres hex (formato MD5-like), gerado inteiramente
 * internamente sem tocar em hardware (sem disco, MAC, nome do PC, etc.).
 * Usa um xorshift64* com semente de GetTickCount + endereco de stack local,
 * produzindo 16 bytes (128 bits) representados como 32 chars hexadecimais. */
static uint64_t xorshift64star(uint64_t* state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static void gen_serial(char* out, int outSize) {
    uint64_t seed = (uint64_t)GetTickCount();
    seed ^= (uint64_t)(uintptr_t)&seed;  /* endereco de stack como entropia extra */
    for (int i = 0; i < 3; ++i) seed = xorshift64star(&seed);

    static const char hex[] = "0123456789ABCDEF";
    uint8_t bytes[16];
    for (int i = 0; i < 16; ++i) {
        bytes[i] = (uint8_t)(xorshift64star(&seed) & 0xFF);
    }

    int pos = 0;
    for (int i = 0; i < 16 && pos + 1 < outSize; ++i) {
        out[pos++] = hex[(bytes[i] >> 4) & 0xF];
        out[pos++] = hex[bytes[i] & 0xF];
    }
    out[pos] = '\0';
}

/* forward declaration: definida abaixo */
static void netc_set_serial(const char* serial);

static void set_serial(const char* serial) {
    if (!serial || !serial[0]) return;
    snprintf(g_serialBuf, sizeof(g_serialBuf), "%s", serial);
    mta_logf("serial", "serial definido (buffer): %s", serial);
    /* Tenta escrever na netc.dll para aplicar de verdade */
    netc_set_serial(serial);
}

/* ---------------------------------------------------------------- serial via netc.dll (leitura e escrita) */

typedef void (__stdcall* fn_GetSerial)(char*, int);

/* Resolve o endereco da funcao GetSerial dentro da netc.dll.
 * Tenta: 1) export por nome, 2) offset base+0x49FB4D (descoberto via ANALISAR na sua build),
 * 3) offset base+0x7CCB0 (versoes antigas). */
static uintptr_t resolve_get_serial_addr() {
    pin_netc();
    HMODULE h = g_netc_pin;
    if (!h) h = GetModuleHandleA("netc.dll");
    if (!h) return 0;

    /* Tentativa 1: export por nome */
    fn_GetSerial p = (fn_GetSerial)GetProcAddress(h, "GetSerial");
    if (p) return (uintptr_t)p;

    /* Tentativa 2: offset descoberto no seu modulo (netc+49FB4D) */
    if (g_netc_base) {
        uintptr_t addr = (uintptr_t)g_netc_base + 0x49FB4Du;
        if (is_valid_ptr((uint32_t)addr)) return addr;
    }

    /* Tentativa 3: offset antigo */
    if (g_netc_base) {
        uintptr_t addr = (uintptr_t)g_netc_base + 0x7CCB0u;
        if (is_valid_ptr((uint32_t)addr)) return addr;
    }

    return 0;
}

/* Le o serial real da netc.dll e coloca em g_serialBuf. */
static void netc_get_serial() {
    char out[64] = {};
    uintptr_t addr = resolve_get_serial_addr();
    if (!addr) {
        mta_logf("serial", "GetSerial nao resolvido na netc.dll");
        return;
    }
    fn_GetSerial pGetSerial = (fn_GetSerial)(void*)addr;
    __try {
        pGetSerial(out, (int)sizeof(out));
        if (out[0]) {
            snprintf(g_serialBuf, sizeof(g_serialBuf), "%s", out);
            mta_logf("serial", "serial lido da netc.dll: %s", out);
        } else {
            mta_logf("serial", "GetSerial retornou vazio");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        mta_logf("serial", "GetSerial excecao ao ler");
    }
}

/* Procura na netc.dll por um local que pareça armazenar um serial (string de 32 hex).
 * Retorna o endereco ou 0 se nao encontrar. Toda leitura eh __try/__except. */
static uintptr_t find_serial_storage_addr() {
    pin_netc();
    HMODULE h = g_netc_pin;
    if (!h) h = GetModuleHandleA("netc.dll");
    if (!h) return 0;

    uint32_t base = (uint32_t)(uintptr_t)h;
    uint32_t size = g_netc_size;
    if (size == 0) {
        __try {
            auto* dos = (IMAGE_DOS_HEADER*)h;
            auto* nt  = (IMAGE_NT_HEADERS*)((uint8_t*)h + dos->e_lfanew);
            size = nt->OptionalHeader.SizeOfImage;
        } __except (EXCEPTION_EXECUTE_HANDLER) { size = 0; }
    }
    if (size == 0) return 0;

    /* Offset hardcoded descoberto na sua build: netc+49FF78 (addr=7196FF78) */
    if (g_netc_base) {
        uintptr_t addr = (uintptr_t)g_netc_base + 0x49FF78u;
        if (is_valid_ptr((uint32_t)addr)) {
            __try {
                const char* s = (const char*)(uintptr_t)addr;
                static const char hex_chars[] = "0123456789ABCDEFabcdef";
                /* Verifica se eh uma string de 32 hex (serial vazio ou preenchido) */
                bool isHex = true;
                for (int i = 0; i < 32; ++i) {
                    bool ok = false;
                    for (int hx = 0; hex_chars[hx]; ++hx) {
                        if (s[i] == hex_chars[hx]) { ok = true; break; }
                    }
                    if (!ok) { isHex = false; break; }
                }
                if (isHex) {
                    mta_logf("serial", "serial storage hardcoded @ netc+%06X (addr=%p)",
                             0x49FF78u, (void*)addr);
                    return addr;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
    }

    /* Fallback: scan automático por strings de 32 chars hexadecimais */
    static const char hex_chars[] = "0123456789ABCDEFabcdef";
    for (uint32_t off = 0; off + 32 <= size; ++off) {
        uint32_t addr = base + off;
        if (!is_valid_ptr(addr)) continue;
        __try {
            const char* s = (const char*)(uintptr_t)addr;
            bool isHex = true;
            for (int i = 0; i < 32; ++i) {
                bool ok = false;
                for (int hx = 0; hex_chars[hx]; ++hx) {
                    if (s[i] == hex_chars[hx]) { ok = true; break; }
                }
                if (!ok) { isHex = false; break; }
            }
            if (isHex && (off == 0 || !isalnum((unsigned char)s[-1])) &&
                       (off + 32 >= size || !isalnum((unsigned char)s[32]))) {
                mta_logf("serial", "candidato a serial armazenado @ netc+%06X (addr=%p): %.32s",
                         off, (void*)addr, s);
                return addr;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    return 0;
}

/* Escreve o serial na memoria da netc.dll para aplicar de verdade.
 * 1) Tenta chamar uma funcao SetSerial se existir.
 * 2) Senão, encontra o local de armazenamento e escreve diretamente. */
static void netc_set_serial(const char* serial) {
    if (!serial || !serial[0]) return;

    pin_netc();
    HMODULE h = g_netc_pin;
    if (!h) h = GetModuleHandleA("netc.dll");
    if (!h) {
        mta_logf("serial", "netc.dll na carregada, impossível gravar serial");
        return;
    }

    /* Tentativa 1: funcao SetSerial por nome */
    typedef void (__stdcall* fn_SetSerial)(const char*);
    fn_SetSerial pSetSerial = (fn_SetSerial)GetProcAddress(h, "SetSerial");
    if (pSetSerial) {
        __try {
            pSetSerial(serial);
            mta_logf("serial", "serial gravado via SetSerial da netc.dll: %s", serial);
            return;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            mta_logf("serial", "SetSerial excecao ao gravar");
        }
    }

    /* Tentativa 2: escrita direta no local de armazenamento descoberto */
    uintptr_t storage = find_serial_storage_addr();
    if (storage) {
        size_t len = strlen(serial);
        if (len > 31) len = 31;
        __try {
            /* Altera protecao da pagina para leitura/escrita */
            DWORD oldProtect = 0;
            if (VirtualProtect((void*)storage, len + 1, PAGE_READWRITE, &oldProtect)) {
                memcpy((void*)storage, serial, len);
                ((char*)(uintptr_t)storage)[len] = '\0';
                /* Restaura protecao original */
                VirtualProtect((void*)storage, len + 1, oldProtect, &oldProtect);
                mta_logf("serial", "serial gravado diretamente na netc.dll @ netc+%06X: %s",
                         (uint32_t)((uintptr_t)storage - (uintptr_t)h), serial);
                return;
            } else {
                mta_logf("serial", "VirtualProtect falhou ao gravar serial");
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            mta_logf("serial", "escrita direta excecao ao gravar");
        }
    }

    mta_logf("serial", "nao foi possível gravar serial na netc.dll (apenas buffer local)");
}

/* Botao Gen Serial (netc): le o serial real da netc.dll e coloca no input */
static void netc_serial_btn() {
    netc_get_serial();
}

/* ---------------------------------------------------------------- analise netc serial */

/* Escaneia a netc.dll procurando strings e referencias relacionadas a serial.
 * Exporta tudo no mta.log para o usuario descobrir onde o modulo do serial
 * esta armazenado. Toda leitura de ponteiro eh guardada por __try/__except. */
static void analyze_netc_serial() {
    pin_netc();
    HMODULE h = g_netc_pin;
    if (!h) h = GetModuleHandleA("netc.dll");
    if (!h) {
        mta_logf("analyze_serial", "netc.dll nao carregada");
        return;
    }

    uint32_t base = (uint32_t)(uintptr_t)h;
    uint32_t size = g_netc_size;
    if (size == 0) {
        __try {
            auto* dos = (IMAGE_DOS_HEADER*)h;
            auto* nt  = (IMAGE_NT_HEADERS*)((uint8_t*)h + dos->e_lfanew);
            size = nt->OptionalHeader.SizeOfImage;
        } __except (EXCEPTION_EXECUTE_HANDLER) { size = 0; }
    }
    mta_logf("analyze_serial", "netc.dll base=%p size=%uKB", (void*)base, size / 1024);

    /* Strings relacionadas a serial que vamos procurar */
    const char* keywords[] = {
        "Serial", "serial", "SERIAL",
        "GetSerial", "getSerial", "getserial",
        "SetSerial", "setSerial", "setserial",
        "serialNetID", "netSerial", "m_serial",
        "mta_serial", "MTA_SERIAL",
        "authserial", "AuthSerial",
        "ban_serial", "BanSerial",
        "player_serial", "PlayerSerial",
        "hw_serial", "HWSerial",
        "machine_serial", "MachineSerial",
        "volume_serial", "VolumeSerial",
        "hdd_serial", "HddSerial",
        "mac_serial", "MacSerial",
        "machine_guid", "MachineGuid",
        "CryptGenRandom", "RtlGenRandom",
        "MD5", "md5", "SHA1", "sha1",
        "netid", "NetID", "usNetID",
        "serialHash", "SerialHash",
        "serialKey", "SerialKey",
        "serialCode", "SerialCode",
        "serialNum", "SerialNum",
        "serialId", "SerialId",
        nullptr
    };

    /* Procura cada string keyword na imagem da netc.dll */
    for (int ki = 0; keywords[ki]; ++ki) {
        const char* kw = keywords[ki];
        size_t klen = strlen(kw);
        if (klen == 0 || klen > 64) continue;

        for (uint32_t off = 0; off + klen <= size; ++off) {
            uint32_t addr = base + off;
            if (!is_valid_ptr(addr)) continue;
            __try {
                if (memcmp((const void*)addr, kw, klen) == 0) {
                    /* Verifica se eh uma string completa (terminada ou rodeada por nao-alfanumerico) */
                    bool okStr = true;
                    if (off > 0) {
                        char prev = *(char*)(uintptr_t)(addr - 1);
                        if ((prev >= 'A' && prev <= 'Z') || (prev >= 'a' && prev <= 'z') ||
                            (prev >= '0' && prev <= '9') || prev == '_') okStr = false;
                    }
                    if (okStr && off + klen < size) {
                        char nxt = *(char*)(uintptr_t)(addr + klen);
                        if ((nxt >= 'A' && nxt <= 'Z') || (nxt >= 'a' && nxt <= 'z') ||
                            (nxt >= '0' && nxt <= '9') || nxt == '_') okStr = false;
                    }
                    if (okStr) {
                        mta_logf("analyze_serial", "string '%s' @ netc+%06X (addr=%p)",
                                 kw, off, (void*)addr);
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
    }

    /* Procura referencias a strings de serial (enderecos que apontam para strings acima) */
    /* Scan rapido de instrucoes lea/mov que carregam enderecos dentro do modulo */
    mta_logf("analyze_serial", "scan de referencias concluido (ver strings acima)");

    /* Dump dos primeiros 256 bytes do .text para referencia */
    __try {
        uint32_t textAddr = base;
        mta_logf("analyze_serial", "inicio do modulo: %02X %02X %02X %02X %02X %02X %02X %02X",
                 *(uint8_t*)(uintptr_t)textAddr,
                 *(uint8_t*)(uintptr_t)(textAddr + 1),
                 *(uint8_t*)(uintptr_t)(textAddr + 2),
                 *(uint8_t*)(uintptr_t)(textAddr + 3),
                 *(uint8_t*)(uintptr_t)(textAddr + 4),
                 *(uint8_t*)(uintptr_t)(textAddr + 5),
                 *(uint8_t*)(uintptr_t)(textAddr + 6),
                 *(uint8_t*)(uintptr_t)(textAddr + 7));
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    /* Tenta encontrar local de armazenamento de serial */
    uintptr_t storage = find_serial_storage_addr();
    if (storage) {
        mta_logf("analyze_serial", "local de armazenamento de serial sugerido: netc+%06X (addr=%p)",
                 (uint32_t)(storage - base), (void*)storage);
    } else {
        mta_logf("analyze_serial", "nenhum local de armazenamento de serial detectado automaticamente");
    }

    mta_logf("analyze_serial", "analise completa - ver strings listadas acima");
}

/* ---------------------------------------------------------------- menu */
static void draw_menu() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2((io.DisplaySize.x - 520) * 0.5f, (io.DisplaySize.y - 380) * 0.5f),
                            ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(520, 380), ImGuiCond_FirstUseEver);
    ImGui::Begin("MTA RESOURCE MANAGER", &g_menuOpen,
                 ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);

    std::vector<ModEntry> snap;
    char curSrv[64] = "";
    EnterCriticalSection(&g_modsCs);
    snap = g_mods;
    snprintf(curSrv, sizeof(curSrv), "%s", g_curServer);
    LeaveCriticalSection(&g_modsCs);

    bool connected = (curSrv[0] != 0 || g_resMgr != 0 || g_clientMod != nullptr);

    /* Status minimalista: apenas circulo + Connected / Offline */
    {
        ImVec2 p = ImGui::GetCursorScreenPos();
        float lineH = ImGui::GetTextLineHeight();
        float r = 5.0f;
        ImU32 dotCol = connected ? IM_COL32(60, 220, 100, 255) : IM_COL32(180, 70, 70, 255);
        ImGui::GetWindowDrawList()->AddCircleFilled(
            ImVec2(p.x + r + 2.0f, p.y + lineH * 0.5f), r, dotCol, 16);
        ImGui::Dummy(ImVec2(r * 2.0f + 8.0f, lineH));
        ImGui::SameLine(0.0f, 0.0f);
        ImGui::TextUnformatted(connected ? "Connected" : "Offline");
    }

    /* Tabs: Manager | Features */
    {
        float avail = ImGui::GetContentRegionAvail().x;
        float tabW = (avail - 8.0f) * 0.5f;
        if (ImGui::Button(g_activeTab == 0 ? "Manager [x]" : "Manager", ImVec2(tabW, 0))) g_activeTab = 0;
        ImGui::SameLine(0.0f, 8.0f);
        if (ImGui::Button(g_activeTab == 1 ? "Features [x]" : "Features", ImVec2(tabW, 0))) g_activeTab = 1;
    }
    ImGui::Separator();

    if (g_activeTab == 0) {
        /* Manager: lista de resources + download/stop */
        EnterCriticalSection(&g_workCs);
        bool busy = g_job.active;
        char jobMod[128]; snprintf(jobMod, sizeof(jobMod), "%s", g_job.mod);
        char jobSt[160];  snprintf(jobSt,  sizeof(jobSt),  "%s", g_job.status);
        int jobDone = g_job.done, jobTotal = g_job.total;
        LeaveCriticalSection(&g_workCs);

        if (!snap.empty()) {
            if (ImGui::SmallButton("baixar tudo") && !busy) start_download_all();
            if (g_fnResRemove && g_resMgr) {
                ImGui::SameLine();
                if (ImGui::SmallButton("stop all")) queue_stop_all();
            }
            if (busy && jobSt[0]) {
                ImGui::SameLine();
                ImGui::TextDisabled("%s", jobSt);
            }
        }
        ImGui::Separator();

        if (ImGui::BeginChild("##browser", ImVec2(0, 0), true)) {
            for (size_t mi = 0; mi < snap.size(); ++mi) {
                const ModEntry& m = snap[mi];
                ImGui::PushID(m.name);
                if (!m.fileList.empty()) {
                    char lbl[192];
                    snprintf(lbl, sizeof(lbl), "%s (%d)", m.name, (int)m.fileList.size());
                    if (ImGui::TreeNode(lbl)) {
                        for (size_t fi = 0; fi < m.fileList.size(); ++fi)
                            ImGui::BulletText("%s", m.fileList[fi].c_str());
                        ImGui::TreePop();
                    }
                } else {
                    ImGui::AlignTextToFramePadding();
                    ImGui::TextUnformatted(m.name);
                }
                ImGui::SameLine();
                if (busy && !strcmp(jobMod, m.name)) {
                    ImGui::Text("[%d/%d]", jobDone, jobTotal);
                } else {
                    if (ImGui::SmallButton("baixar")) start_download(m.name);
                    if (g_fnResRemove && g_resMgr && m.resPtr) {
                        ImGui::SameLine();
                        if (ImGui::SmallButton("stop")) queue_stop_one(m.resPtr);
                    }
                }
                ImGui::PopID();
            }
        }
        ImGui::EndChild();
    } else {
        /* Features */
        ImGui::TextDisabled("Recursos extras");
        ImGui::Separator();
        bool canExplode = rm::g_explodeEnabled;
        if (!canExplode) ImGui::BeginDisabled();
        if (ImGui::Button("Explode All", ImVec2(120, 24))) {
            exp_explode_all();
        }
        if (!canExplode) ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("%s", canExplode ? "Detona granada em todos os peds do pool (exceto o local)."
                                              : "Conecte-se a um servidor para habilitar.");

        /* Serial generator */
        ImGui::Separator();
        ImGui::Text("Serial");
        ImGui::SameLine();
        ImGui::PushItemWidth(200.0f);
        ImGui::InputText("##serial", g_serialBuf, sizeof(g_serialBuf));
        ImGui::PopItemWidth();
        ImGui::SameLine();
        if (ImGui::Button("Gen Serial", ImVec2(80, 24))) {
            char novo[64] = {};
            gen_serial(novo, sizeof(novo));
            snprintf(g_serialBuf, sizeof(g_serialBuf), "%s", novo);
        }
        ImGui::SameLine(0.0f, 8.0f);
        if (ImGui::Button("Set Serial", ImVec2(80, 24))) {
            set_serial(g_serialBuf);
        }
        ImGui::SameLine(0.0f, 8.0f);
        if (ImGui::Button("Gen Serial (netc)", ImVec2(100, 24))) {
            netc_serial_btn();  /* le o serial real da netc.dll e coloca no input */
        }
        ImGui::SameLine(0.0f, 8.0f);
        if (ImGui::Button("ANALISAR", ImVec2(70, 24))) {
            analyze_netc_serial();
        }
    }

    ImGui::End();
}

} // namespace rm

/* ---------------------------------------------------------------- D3D9 */
using fn_EndScene     = HRESULT(__stdcall*)(IDirect3DDevice9*);
using fn_Reset        = HRESULT(__stdcall*)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);
using fn_Present      = HRESULT(__stdcall*)(IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*);
using fn_SetTransform = HRESULT(__stdcall*)(IDirect3DDevice9*, D3DTRANSFORMSTATETYPE, const D3DMATRIX*);

static fn_EndScene     g_o_EndScene     = nullptr;
static fn_Reset        g_o_Reset        = nullptr;
static fn_Present      g_o_Present      = nullptr;
static fn_SetTransform g_o_SetTransform = nullptr;

static bool          g_imgui_init        = false;
static volatile LONG g_imgui_invalidated = 0;
static HWND          g_game_hwnd         = nullptr;
static WNDPROC       g_o_wndproc         = nullptr;
static bool          g_prev_insert       = false;

static LRESULT CALLBACK hk_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_imgui_init) {
        ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam);
        ImGuiIO& io = ImGui::GetIO();
        if (rm::g_menuOpen && io.WantCaptureMouse) {
            switch (msg) {
                case WM_LBUTTONDOWN: case WM_LBUTTONUP:
                case WM_RBUTTONDOWN: case WM_RBUTTONUP:
                case WM_MBUTTONDOWN: case WM_MBUTTONUP:
                case WM_MOUSEWHEEL:  case WM_MOUSEMOVE:
                    return 1;
            }
        }
        if (rm::g_menuOpen && io.WantCaptureKeyboard) {
            switch (msg) {
                case WM_KEYDOWN: case WM_KEYUP: case WM_CHAR:
                    return 1;
            }
        }
    }
    return g_o_wndproc
        ? CallWindowProc(g_o_wndproc, hwnd, msg, wParam, lParam)
        : DefWindowProcA(hwnd, msg, wParam, lParam);
}

static inline ImVec4 rm_rgba(int r, int g, int b, int a) {
    const float k = 1.0f / 255.0f;
    return ImVec4((float)r * k, (float)g * k, (float)b * k, (float)a * k);
}

static void init_imgui(IDirect3DDevice9* pDevice) {
    D3DDEVICE_CREATION_PARAMETERS cp = {};
    pDevice->GetCreationParameters(&cp);
    HWND hwnd = cp.hFocusWindow;
    if (!hwnd || !IsWindow(hwnd)) return;

    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != GetCurrentProcessId()) return;

    g_game_hwnd = hwnd;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
    io.MouseDrawCursor = true;

    char win_dir[MAX_PATH] = {};
    GetWindowsDirectoryA(win_dir, MAX_PATH);
    char arial_r[MAX_PATH];
    snprintf(arial_r, sizeof(arial_r), "%s\\Fonts\\arial.ttf", win_dir);

    ImFont* font = nullptr;
    if (GetFileAttributesA(arial_r) != INVALID_FILE_ATTRIBUTES)
        font = io.Fonts->AddFontFromFileTTF(arial_r, 15.0f);
    if (!font) io.Fonts->AddFontDefault();

    rm::g_hwndMain = hwnd;
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(pDevice);

    ImGui::StyleColorsDark();
    ImGuiStyle& st = ImGui::GetStyle();
    st.WindowRounding    = 0.0f;
    st.FrameRounding     = 0.0f;
    st.GrabRounding      = 0.0f;
    st.ScrollbarRounding = 0.0f;
    st.PopupRounding     = 0.0f;
    st.WindowBorderSize  = 1.0f;
    st.FrameBorderSize   = 0.0f;
    st.ItemInnerSpacing  = ImVec2(6.0f, 4.0f);

    ImVec4* c = st.Colors;
    c[ImGuiCol_WindowBg]            = rm_rgba(0, 0, 0, 235);
    c[ImGuiCol_ChildBg]             = rm_rgba(0, 0, 0, 255);
    c[ImGuiCol_PopupBg]             = rm_rgba(0, 0, 0, 235);
    c[ImGuiCol_Border]              = rm_rgba(90, 90, 90, 160);
    c[ImGuiCol_BorderShadow]        = rm_rgba(0, 0, 0, 0);
    c[ImGuiCol_FrameBg]             = rm_rgba(22, 22, 22, 255);
    c[ImGuiCol_FrameBgHovered]      = rm_rgba(38, 38, 38, 255);
    c[ImGuiCol_FrameBgActive]       = rm_rgba(50, 50, 50, 255);
    c[ImGuiCol_TitleBg]             = rm_rgba(0, 0, 0, 255);
    c[ImGuiCol_TitleBgActive]       = rm_rgba(18, 18, 18, 255);
    c[ImGuiCol_TitleBgCollapsed]    = rm_rgba(0, 0, 0, 255);
    c[ImGuiCol_MenuBarBg]           = rm_rgba(0, 0, 0, 255);
    c[ImGuiCol_ScrollbarBg]         = rm_rgba(0, 0, 0, 255);
    c[ImGuiCol_ScrollbarGrab]       = rm_rgba(58, 58, 58, 255);
    c[ImGuiCol_ScrollbarGrabHovered]= rm_rgba(86, 86, 86, 255);
    c[ImGuiCol_ScrollbarGrabActive] = rm_rgba(110, 110, 110, 255);
    c[ImGuiCol_CheckMark]           = rm_rgba(235, 235, 235, 255);
    c[ImGuiCol_SliderGrab]          = rm_rgba(140, 140, 140, 255);
    c[ImGuiCol_SliderGrabActive]    = rm_rgba(190, 190, 190, 255);
    c[ImGuiCol_Button]              = rm_rgba(30, 30, 30, 255);
    c[ImGuiCol_ButtonHovered]       = rm_rgba(62, 62, 62, 255);
    c[ImGuiCol_ButtonActive]        = rm_rgba(92, 92, 92, 255);
    c[ImGuiCol_Header]              = rm_rgba(34, 34, 34, 255);
    c[ImGuiCol_HeaderHovered]       = rm_rgba(60, 60, 60, 255);
    c[ImGuiCol_HeaderActive]        = rm_rgba(80, 80, 80, 255);
    c[ImGuiCol_Separator]           = rm_rgba(70, 70, 70, 160);
    c[ImGuiCol_ResizeGrip]          = rm_rgba(40, 40, 40, 255);
    c[ImGuiCol_ResizeGripHovered]   = rm_rgba(70, 70, 70, 255);
    c[ImGuiCol_ResizeGripActive]    = rm_rgba(100, 100, 100, 255);
    c[ImGuiCol_Text]                = rm_rgba(232, 232, 232, 255);
    c[ImGuiCol_TextDisabled]        = rm_rgba(150, 150, 150, 150);
    c[ImGuiCol_TextSelectedBg]      = rm_rgba(255, 255, 255, 32);

    g_o_wndproc  = (WNDPROC)SetWindowLongPtrA(hwnd, GWLP_WNDPROC, (LONG_PTR)hk_wndproc);
    g_imgui_init = true;
    mta_logf("ui", "ImGui pronto hwnd=%p", (void*)hwnd);
}

static HRESULT __stdcall hk_Reset(IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* pParams) {
    if (g_imgui_init) ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_o_Reset(pDevice, pParams);
    if (SUCCEEDED(hr) && g_imgui_init) InterlockedExchange(&g_imgui_invalidated, 1);
    return hr;
}

static HRESULT __stdcall hk_Present(IDirect3DDevice9* pDevice,
                                    const RECT* pSrc, const RECT* pDst,
                                    HWND hWnd, const RGNDATA* pDirty) {
    if (g_imgui_init) {
        HRESULT coop = pDevice->TestCooperativeLevel();
        if (coop == D3DERR_DEVICENOTRESET) {
            if (InterlockedCompareExchange(&g_imgui_invalidated, 1, 0) == 0)
                ImGui_ImplDX9_InvalidateDeviceObjects();
        } else if (coop == D3D_OK) {
            InterlockedExchange(&g_imgui_invalidated, 0);
        }
    }
    return g_o_Present(pDevice, pSrc, pDst, hWnd, pDirty);
}

static HRESULT __stdcall hk_SetTransform(IDirect3DDevice9* dev, D3DTRANSFORMSTATETYPE state, const D3DMATRIX* m) {
    return g_o_SetTransform(dev, state, m);
}

static bool g_wasConnected = false;

static HRESULT __stdcall hk_EndScene(IDirect3DDevice9* pDevice) {
    cnet_poll_main_thread(false);
    rm::process_main_actions();

    /* Detecta conectar / sair do servidor e ativa/desativa explode + resource manager.
       Ao sair, desativa para nao disparar AC (ac 4). Ao entrar, reativa. */
    bool connected = (rm::g_curServer[0] != 0);
    if (connected && !g_wasConnected) {
        rm::g_explodeEnabled = true;
        mta_logf("conn", "entrou no servidor: explode + resource manager ativados");
    } else if (!connected && g_wasConnected) {
        rm::g_explodeEnabled = false;
        rm::g_resMgr = 0;
        rm::g_fnResStop = 0;
        rm::g_fnResRemove = 0;
        rm::g_fnResMagic = 0;
        rm::g_rt.state = rm::ST_WAIT_SERVER;
        mta_logf("conn", "saiu do servidor: explode + resource manager desativados");
    }
    g_wasConnected = connected;

    HRESULT coop = pDevice->TestCooperativeLevel();
    if (coop != D3D_OK) return g_o_EndScene(pDevice);

    if (!g_imgui_init) {
        init_imgui(pDevice);
        if (!g_imgui_init) return g_o_EndScene(pDevice);
    }

    bool ins = (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;
    if (ins && !g_prev_insert) rm::g_menuOpen = !rm::g_menuOpen;
    g_prev_insert = ins;

    if (InterlockedCompareExchange(&g_imgui_invalidated, 0, 0)) {
        ImGui_ImplDX9_CreateDeviceObjects();
        InterlockedExchange(&g_imgui_invalidated, 0);
    }

    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ImGui::GetIO().MouseDrawCursor = rm::g_menuOpen;

    if (ImGui::GetIO().DisplaySize.x >= 64.0f && ImGui::GetIO().DisplaySize.y >= 64.0f) {
        if (rm::g_menuOpen) rm::draw_menu();
    }

    ImGui::EndFrame();
    ImGui::Render();
    ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());

    return g_o_EndScene(pDevice);
}

static bool d3d_site_patchable(void* addr) {
    if (!addr) return false;
    uint8_t b[5] = {};
    __try {
        for (int i = 0; i < 5; ++i) b[i] = ((uint8_t*)addr)[i];
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (b[0] == 0xE9 || b[0] == 0xE8 || b[0] == 0xEB) return false;
    if (b[0] == 0xFF && (b[1] == 0x25 || b[1] == 0x15 || b[1] == 0x68)) return false;
    if (b[0] == 0x68 || b[0] == 0x00 || b[0] == 0xCC) return false;
    return true;
}

static void install_d3d9_hooks() {
    HWND hwnd = CreateWindowExA(0, "STATIC", "dummy", WS_POPUP,
                                0, 0, 1, 1, NULL, NULL, NULL, NULL);
    if (!hwnd) return;

    IDirect3D9* d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) { DestroyWindow(hwnd); return; }

    D3DPRESENT_PARAMETERS pp = {};
    pp.Windowed         = TRUE;
    pp.SwapEffect       = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow    = hwnd;
    pp.BackBufferFormat = D3DFMT_UNKNOWN;

    IDirect3DDevice9* dev = nullptr;
    HRESULT hr = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                                   D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);
    if (FAILED(hr)) { d3d->Release(); DestroyWindow(hwnd); return; }

    void** vt = *(void***)dev;
    void* pEndScene     = vt[42];
    void* pReset        = vt[16];
    void* pPresent      = vt[17];
    void* pSetTransform = vt[44];

    dev->Release();
    d3d->Release();
    DestroyWindow(hwnd);

    struct { const char* name; void* addr; } sites[4] = {
        { "EndScene",     pEndScene     },
        { "Reset",        pReset        },
        { "Present",      pPresent      },
        { "SetTransform", pSetTransform },
    };

    bool busy[4] = {};
    for (int i = 0; i < 4; ++i) {
        busy[i] = !d3d_site_patchable(sites[i].addr);
        if (busy[i]) mta_logf("d3d9", "%s ocupado", sites[i].name);
    }
    if (busy[0]) {
        mta_logf("d3d9", "EndScene ocupada — ImGui nao sera desenhado");
        return;
    }

    for (int i = 0; i < 4; ++i) {
        if (busy[i]) continue;
        bool ok = false;
        switch (i) {
            case 0: ok = patch_jmp(sites[0].addr, &hk_EndScene,     g_o_EndScene);     break;
            case 1: ok = patch_jmp(sites[1].addr, &hk_Reset,        g_o_Reset);        break;
            case 2: ok = patch_jmp(sites[2].addr, &hk_Present,      g_o_Present);      break;
            default: ok = patch_jmp(sites[3].addr, &hk_SetTransform, g_o_SetTransform); break;
        }
        if (!ok) mta_logf("d3d9", "patch_jmp falhou em %s", sites[i].name);
    }
}

/* ----------------------------------------------------------- netc boot */
/* g_netc_pin e pin_netc ja declarados acima (forward declaration) */

bool pin_netc() {
    if (g_netc_pin) return true;
    HMODULE h = nullptr;
    for (int i = 0; i < 240; ++i) {
        if (GetModuleHandleExA(0x00000001, "netc.dll", &h) && h) {
            g_netc_pin = h;
            uint32_t size = 0;
            __try {
                auto* dos = (IMAGE_DOS_HEADER*)h;
                auto* nt  = (IMAGE_NT_HEADERS*)((uint8_t*)h + dos->e_lfanew);
                size = nt->OptionalHeader.SizeOfImage;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            mta_logf("pin", "netc.dll @ %p (%uKB)", (void*)h, size / 1024);
            return true;
        }
        Sleep(250);
    }
    mta_logf("pin!", "netc.dll timeout");
    return false;
}

static void install_all() {
    HMODULE mod = nullptr;
    for (int i = 0; i < 60; ++i) {
        mod = GetModuleHandleA("netc.dll");
        if (mod) break;
        Sleep(500);
    }
    if (!mod) return;

    g_netc_base = (uint32_t)(uintptr_t)mod;
    __try {
        auto* dos = (IMAGE_DOS_HEADER*)mod;
        auto* nt  = (IMAGE_NT_HEADERS*)((uint8_t*)mod + dos->e_lfanew);
        g_netc_size = nt->OptionalHeader.SizeOfImage;
    } __except (EXCEPTION_EXECUTE_HANDLER) { g_netc_size = 0; }

    try_install<bool(__cdecl*)(int,int,int,DWORD*,int*,DWORD*)>(
        "advanced_memory_validator", PAT_ADVANCED_MEMORY_VALIDATOR, MSK_ADVANCED_MEMORY_VALIDATOR, 1, &d_advanced_memory_validator);
    try_install<int(__fastcall*)(DWORD*,void*,int,unsigned __int8,unsigned __int16)>(
        "network_packet_state_validator", PAT_NETWORK_PACKET_STATE_VALIDATOR, MSK_NETWORK_PACKET_STATE_VALIDATOR, 1, &d_network_packet_state_validator);
    try_install<char(__stdcall*)(int*)>(
        "animation_packet_validator", PAT_ANIMATION_PACKET_VALIDATOR, MSK_ANIMATION_PACKET_VALIDATOR, 1, &d_animation_packet_validator);

    try_install_global<fn_send_packet>(
        "send_packet", PAT_SEND_PACKET, MSK_SEND_PACKET, 1, &d_send_packet, g_o_send_packet);
    try_install<int(__cdecl*)(char,void*,int,int,int)>(
        "send_report", PAT_SEND_REPORT, MSK_SEND_REPORT, 1, &d_send_report);
    try_install<HANDLE(__stdcall*)(LPCWSTR,ACCESS_MASK,DWORD,LPSECURITY_ATTRIBUTES,ULONG,ULONG)>(
        "send_driver_report", PAT_SEND_DRIVER_REPORT, MSK_SEND_DRIVER_REPORT, 1, &d_send_driver_report);
    try_install<void(__fastcall*)(int,int,unsigned int,int,DWORD*,int)>(
        "send_client_kick", PAT_SEND_CLIENT_KICK, MSK_SEND_CLIENT_KICK, 1, &w_send_client_kick);
    try_install<void(__fastcall*)(int,char)>(
        "send_client_local_kick", PAT_SEND_CLIENT_LOCAL_KICK, MSK_SEND_CLIENT_LOCAL_KICK, 1, &w_send_client_local_kick);
    try_install<void(__fastcall*)(int,int,int*,int*,char,int)>(
        "send_client_ban", PAT_SEND_CLIENT_BAN, MSK_SEND_CLIENT_BAN, 1, &w_send_client_ban);
    try_install_global<fn_send_lua_check>(
        "send_lua_check", PAT_SEND_LUA_CHECK, MSK_SEND_LUA_CHECK, 1, &d_send_lua_check, g_o_send_lua_check);

    try_install<void(__fastcall*)(void*,void*)>(
        "sub_10056A50", PAT_SUB_10056A50, MSK_SUB_10056A50, 1, &d_sub_10056A50);
    try_install<unsigned int(__fastcall*)(void*,void*,int)>(
        "sub_10293EC0", PAT_SUB_10293EC0, MSK_SUB_10293EC0, 1, &d_sub_10293EC0);
    try_install<int(__fastcall*)(void*,void*)>(
        "sub_10159D50", PAT_SUB_10159D50, MSK_SUB_10159D50, 1, &d_sub_10159D50);
    try_install<int(__cdecl*)(void*)>(
        "sub_10141000", PAT_SUB_10141000, MSK_SUB_10141000, 1, &d_sub_10141000);
    try_install<int(__fastcall*)(void*,void*,int,void*,int,const char*,const char*)>(
        "sub_101731D0", PAT_SUB_101731D0, MSK_SUB_101731D0, 1, &d_sub_101731D0);
    try_install<bool(__cdecl*)()>(
        "sub_1028CB90", PAT_SUB_1028CB90, MSK_SUB_1028CB90, 2, &d_sub_1028CB90);

    try_install<bool(__cdecl*)(char*)>(
        "detect_hook_new2", PAT_DETECT_HOOK_NEW2, MSK_DETECT_HOOK_NEW2, 1, &d_detect_hook_new2);
    try_install<bool(__cdecl*)(char*)>(
        "detect_hook_new", PAT_DETECT_HOOK_NEW, MSK_DETECT_HOOK_NEW, 1, &d_detect_hook_new);
    try_install<char(__cdecl*)(char*)>(
        "detect_hook", PAT_DETECT_HOOK, MSK_DETECT_HOOK, 1, &d_detect_hook);
    try_install<void(__cdecl*)(const char*)>(
        "sub_1006CC80", PAT_SUB_1006CC80, MSK_SUB_1006CC80, 1, &d_sub_1006CC80);

    try_install<char(__fastcall*)(void*,void*,int,int)>(
        "bypassnew", PAT_BYPASSNEW, MSK_BYPASSNEW, 1, &d_bypassnew);
    try_install<int(__fastcall*)(void*,void*,int,int)>(
        "bypass", PAT_BYPASS, MSK_BYPASS, 1, &d_bypass);
    try_install<int(__fastcall*)(unsigned int,void*,int)>(
        "sub_new", PAT_SUB_NEW, MSK_SUB_NEW, 2, &d_sub_new);
    try_install<int(__stdcall*)(int)>(
        "send_crash_hook", PAT_SEND_CRASH_HOOK, MSK_SEND_CRASH_HOOK, 1, &d_send_crash_hook);
    try_install_global<fn_sub_102BDFDE>(
        "sub_102BDFDE", PAT_SUB_102BDFDE, MSK_SUB_102BDFDE, 1, &d_sub_102BDFDE, g_o_sub_102BDFDE);
    try_install<unsigned int(__fastcall*)(int,int,unsigned int)>(
        "sub_100D57B0", PAT_SUB_100D57B0, MSK_SUB_100D57B0, 1, &d_sub_100D57B0);

    try_install_rva<fn_ac_check_hooking_function>("ac_check_hooking_function", 0x6BC90,  &d_ac_check_hooking_function);
    try_install_rva<LONG(__stdcall*)(void*)>      ("ac_veh_stack",              0x11E9C0, &d_veh_stack);
    try_install_rva<fn_ac_send_client_kick>       ("ac_send_client_kick",       0x1CCF40, &d_ac_send_client_kick);
    try_install_rva<fn_add_ac_log_path_hook>      ("add_ac_log_path_hook",      0x29910,  &d_add_ac_log_path_hook);
    try_install_rva<fn_ac_watchdog>               ("ac_watchdog",               0x2A8930, &d_ac_watchdog);
    try_install_rva<DWORD(__stdcall*)(void*)>     ("ac_start_watchdog",         0x2A8AD0, &d_ac_start_watchdog);

    mta_logf("netc", "install_all: ok=%u miss=%u fail=%u", g_ok, g_miss, g_fail);
}

static DWORD WINAPI main_thread(LPVOID) {
    init_ptr_bounds();
    mta_logf("boot", "MTA Resource Manager 0.4 (addr=%08X..%08X)", g_minAppPtr, g_maxAppPtr);
    _mkdir(RM_MODS_DIR);
    InitializeCriticalSection(&g_cnetCs);
    InterlockedExchange(&g_cnetCsReady, 1);
    InitializeCriticalSection(&rm::g_actCs);
    InterlockedExchange(&rm::g_actCsReady, 1);
    InitializeCriticalSection(&rm::g_modsCs);
    InitializeCriticalSection(&rm::g_workCs);
    rm::g_inited = true;

    pin_netc();
    install_all();
    install_d3d9_hooks();

    rm::rt_init();
    rm::g_workEv = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    HANDLE hWorker = CreateThread(nullptr, 0, rm::worker_thread, nullptr, 0, nullptr);
    if (hWorker) CloseHandle(hWorker);

    while (!rm::g_quit) Sleep(100);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lpReserved) {
    (void)lpReserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        HANDLE t = CreateThread(nullptr, 0, main_thread, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    } else if (reason == DLL_PROCESS_DETACH) {
        rm::g_quit = true;
        if (rm::g_workEv) SetEvent(rm::g_workEv);
        if (!lpReserved) {
            unpatch_all();
            if (g_imgui_init) {
                ImGui_ImplDX9_Shutdown();
                ImGui_ImplWin32_Shutdown();
                ImGui::DestroyContext();
                g_imgui_init = false;
            }
        }
    }
    return TRUE;
}
