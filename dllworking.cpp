#if 0
/* ============================================================
   Menu/troll DLL para MTA:SA (client) - d3d9 + ImGui (dx9/win32)
   Versao: 2026-11-12 (build 3)

   MENU: janela 650x440, tema preto, cards com fundo transparente e
   contorno vermelho de 1px, sidebar de abas na esquerda, cursor
   desenhado por nos quando o menu esta aberto, fontes/espacamento
   reduzidos e cards 30px mais estreitos / 50px mais curtos.

   ABAS:
     COMBAT   Aimbot (fov, smooth, bone, keybind) e Silent Aim
              (fov, bone, ignore walls; so dispara com o bind).
     VISUALS  ESP por jogador (box, skeleton, nome, distancia, cor);
              amigo aparece em azul com estrela e e ignorado por
              aimbot/silent.
     MISC     Stream proof, bind do menu, add/remove friend,
              config save/load.
     TROLL    Fly (toggle no card: bind, velocity 0.5..100,
              Hold/Toggle, movimento nivelado) e Infinite Ammo.

   BINDINGS PADRAO: menu Insert | Fly F8 | Aimbot Mouse4 | Silent
   Mouse5. F8 > quit fecha limpo (netc intocado).
   Logs no mta.log por tag (fps/esp/fly/silent/...) com throttle.
   ============================================================ */
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d9.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <unordered_map>
#include <math.h>

#include "../third_party/SkipHook/skiphook.h"
#include "../third_party/imgui/imgui.h"
#include "../third_party/imgui/imgui_internal.h"
#include "../third_party/imgui/backends/imgui_impl_dx9.h"
#include "../third_party/imgui/backends/imgui_impl_win32.h"
#include "../third_party/imgui/addons/fontawesome/fontawesome.h"
#include "../third_party/imgui/addons/fontawesome/fonts.h"
#include "netc.h"

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

static_assert(sizeof(void*) == 4, "Win32/x86 only.");

static void out(WORD, const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
}
#define GREEN 0
#define RED   0
#define YELLOW 0
#define DEF   0

static volatile LONG g_init_top = 0;

static void* scan_mask(HMODULE mod, const char* pattern, const char* mask, unsigned occurrence = 1) {
    if (!mod || !pattern || !mask) return nullptr;
    size_t len = strlen(mask);
    if (!len) return nullptr;

    uint8_t* base = (uint8_t*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
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
            if (ok) {
                if (++found == occurrence) return s + o;
            }
        }
    }
    return nullptr;
}

static void silent_retire_hooks();
static void mta_logf(const char* tag, const char* fmt, ...);
static bool is_shutdown_bypass();

static uint32_t      g_netc_base          = 0;
static uint32_t      g_netc_size          = 0;

using fn_send_packet    = bool(__fastcall*)(void*, void*, unsigned char, void*, int, int, int);
using fn_send_lua_check = int(__fastcall*)(DWORD*, void*, unsigned __int8);
using fn_sub_102BDFDE   = int(__cdecl*)(__int64*);

static fn_send_packet    g_o_send_packet    = nullptr;
static fn_send_lua_check g_o_send_lua_check = nullptr;
static fn_sub_102BDFDE   g_o_sub_102BDFDE   = nullptr;

using fn_add_net_report_log_raw    = int  (__stdcall*)(const char*, int);
using fn_ac_check_hooking_function = bool (__fastcall*)(void*, void*);
using fn_ac_send_client_kick       = int  (__fastcall*)(void*, void*, DWORD*, int);
using fn_add_ac_log_path_hook      = int  (__stdcall*)(const char*);
using fn_ac_watchdog               = int  (__stdcall*)(void*);

static fn_add_net_report_log_raw    g_o_add_net_report_log_raw    = nullptr;
static fn_ac_check_hooking_function g_o_ac_check_hooking_function = nullptr;
static fn_ac_send_client_kick       g_o_ac_send_client_kick       = nullptr;
static fn_add_ac_log_path_hook      g_o_add_ac_log_path_hook      = nullptr;
static fn_ac_watchdog               g_o_ac_watchdog               = nullptr;

static bool __cdecl d_advanced_memory_validator(int, int, int, DWORD*, int*, DWORD*) { return true; }
static int  __fastcall d_network_packet_state_validator(DWORD*, void*, int, unsigned __int8, unsigned __int16) { return 1; }
static char __stdcall  d_animation_packet_validator(int*) { return 1; }

// FIX: rastreia último pacote enviado. Serve como sinal REAL de conexão — o ped
// local pode ficar "vivo" 1-2s após disconnect (MTA destrói assincronamente),
// mas os pacotes param IMEDIATAMENTE. Sem isso, ESP/FOV renderizam contra um
// mundo morto durante toda a janela de transição. Precisa estar declarado
// ANTES de d_send_packet (que alimenta o tick) e de session_monitor (que lê).
static volatile LONG g_last_pkt_tick = 0;

static bool __fastcall d_send_packet(void* ECX, void* EDX, unsigned char ucPacketID, void* bitStream,
                                     int packetPriority, int packetReliability, int packetOrdering) {
    // FIX ban: durante shutdown deixa o quit-packet sair para evitar timeout
    // no servidor (interpretado como combat-log em servidores competitivos).
    if (is_shutdown_bypass()) {
        if (g_o_send_packet)
            return g_o_send_packet(ECX, EDX, ucPacketID, bitStream,
                                   packetPriority, packetReliability, packetOrdering);
        return false;
    }

    // FIX: registrar atividade de pacote (ver Fix C em session_monitor).
    {
        uint32_t pkt_now = GetTickCount();
        InterlockedExchange(&g_last_pkt_tick, pkt_now ? pkt_now : 1);
    }

    if (ucPacketID == 33) {

        silent_retire_hooks();
        if (packetReliability == 3) return true;
        if (packetReliability != 1 || !(*(DWORD**)0xBA18FC)) return true;
    }
    if (ucPacketID == 56 || ucPacketID == 71 || ucPacketID == 72 || ucPacketID == 34 ||
        ucPacketID == 91 || ucPacketID == 92 || ucPacketID == 93 || ucPacketID == 25 || ucPacketID == 110)
        return true;
    if (g_o_send_packet)
        return g_o_send_packet(ECX, EDX, ucPacketID, bitStream, packetPriority, packetReliability, packetOrdering);
    return false;
}

static int    __cdecl    d_send_report(char, void*, int, int, int) { return true; }
static HANDLE __stdcall  d_send_driver_report(LPCWSTR, ACCESS_MASK, DWORD, LPSECURITY_ATTRIBUTES, ULONG, ULONG) { return NULL; }
static void   __fastcall d_send_client_kick(int, int, unsigned int, int, DWORD*, int) {}
static void   __fastcall d_send_client_local_kick(int, char) {}
static void   __fastcall d_send_client_ban(int, int, int*, int*, char, int) {}

static int __fastcall d_send_lua_check(DWORD* instance, void* edx, unsigned __int8 checkFlag) {
    *(int*)(instance + 46) = 0;
    *(int*)(instance + 47) = 0;
    if (g_o_send_lua_check)
        return g_o_send_lua_check(instance, edx, checkFlag);
    return 0;
}

static void         __fastcall d_sub_10056A50(void*, void*) {}
static unsigned int __fastcall d_sub_10293EC0(void*, void*, int) { return 1; }
static int          __fastcall d_sub_10159D50(void*, void*) { return 1; }
static int          __cdecl    d_sub_10141000(void*) { return true; }
static int          __fastcall d_sub_101731D0(void*, void*, int, void*, int, const char*, const char*) { return 1; }
static bool         __cdecl    d_sub_1028CB90() { return true; }
static bool         __cdecl    d_detect_hook_new2(char*) { return false; }
static bool         __cdecl    d_detect_hook_new(char*) { return false; }
static char         __cdecl    d_detect_hook(char*) { return 0; }
static void         __cdecl    d_sub_1006CC80(const char*) {}
static char         __fastcall d_bypassnew(void*, void*, int, int) { return true; }
static int          __fastcall d_bypass(void*, void*, int, int) { return true; }
static int          __fastcall d_sub_new(unsigned int, void*, int) { return true; }
static int          __stdcall  d_send_crash_hook(int) { return 1; }

static int __cdecl d_sub_102BDFDE(__int64* a1) {
    static __int64 tempo = 0;
    if (tempo == 0 && g_o_sub_102BDFDE)
        g_o_sub_102BDFDE(&tempo);
    if (a1 != NULL) *a1 = tempo;
    return (int)tempo;
}

static unsigned int __fastcall d_sub_100D57B0(int, int, unsigned int) { return 0; }

static LONG  __stdcall d_veh_stack(void*)          { return 0; }
static DWORD __stdcall d_ac_start_watchdog(void*)  { return 0; }

static int  __stdcall  d_add_net_report_log_raw(const char*, int)             { return 1; }
static bool __fastcall d_ac_check_hooking_function(void*, void*)              { return false; }
static int  __fastcall d_ac_send_client_kick(void*, void*, DWORD*, int)       { return 1; }
static int  __stdcall  d_add_ac_log_path_hook(const char*)                    { return 1; }
static int  __stdcall  d_ac_watchdog(void*)                                   { return 0; }

using fn_add_net_report_log_raw_v2 = int(__stdcall*)(const char*, int);
static fn_add_net_report_log_raw_v2 g_o_add_net_report_log_raw_v2 = nullptr;

static __declspec(naked) void hk_add_net_report_log_raw_v2() {
    __asm {
        xor eax, eax
        ret 8
    }
}

static void diag_dump_ac() {
    uint32_t base = g_netc_base;
    if (!base) { mta_logf("diag", "no netc base"); return; }

    __try {
        uint32_t fn = base + 0x666E0;
        for (int i = 0; i < 96; i += 16) {
            mta_logf("diag", "RepRaw+%02X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                i,
                *(uint8_t*)(fn+i+0),  *(uint8_t*)(fn+i+1),  *(uint8_t*)(fn+i+2),  *(uint8_t*)(fn+i+3),
                *(uint8_t*)(fn+i+4),  *(uint8_t*)(fn+i+5),  *(uint8_t*)(fn+i+6),  *(uint8_t*)(fn+i+7),
                *(uint8_t*)(fn+i+8),  *(uint8_t*)(fn+i+9),  *(uint8_t*)(fn+i+10), *(uint8_t*)(fn+i+11),
                *(uint8_t*)(fn+i+12), *(uint8_t*)(fn+i+13), *(uint8_t*)(fn+i+14), *(uint8_t*)(fn+i+15));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { mta_logf("diag", "RepRaw AV"); }

    __try {
        uint32_t push = base + 0x6EBAB;
        for (int i = -64; i < 96; i += 16) {
            mta_logf("diag", "SendPush%+03d: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                i,
                *(uint8_t*)(push+i+0),  *(uint8_t*)(push+i+1),  *(uint8_t*)(push+i+2),  *(uint8_t*)(push+i+3),
                *(uint8_t*)(push+i+4),  *(uint8_t*)(push+i+5),  *(uint8_t*)(push+i+6),  *(uint8_t*)(push+i+7),
                *(uint8_t*)(push+i+8),  *(uint8_t*)(push+i+9),  *(uint8_t*)(push+i+10), *(uint8_t*)(push+i+11),
                *(uint8_t*)(push+i+12), *(uint8_t*)(push+i+13), *(uint8_t*)(push+i+14), *(uint8_t*)(push+i+15));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { mta_logf("diag", "SendPush AV"); }

    __try {
        uint32_t iat = base + 0x404464;
        for (int i = 0; i < 96; i += 4) {
            uint32_t v = *(uint32_t*)(iat + i);
            mta_logf("diag", "IAT[%02X] = %08X", i, v);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { mta_logf("diag", "IAT AV"); }
}

struct PatchRecord {
    void*   addr;
    uint8_t original[5];
    void*   detour;
};

static PatchRecord g_patches[96];
static int         g_patch_count = 0;

static volatile LONG g_watchdog_stop = 0;
static HANDLE        g_watchdog_handle = nullptr;
static volatile LONG g_watchdog_repatch_count = 0;

template<typename T>
static bool patch_jmp(void* addr, T detour, T& original_out) {
    if (!addr || !detour) return false;
    // FIX OOM: recusar antes de alocar trampolim se não há slot para registrar.
    // Antes, o patch era instalado mesmo com tabela cheia → trampolim órfão
    // (VirtualAlloc 4KB/instância) + hook irreversível.
    if (g_patch_count >= 96) return false;

    T tramp = skip_hook::make_full_hook<T>((uint64_t)addr, 5);
    if (!tramp) return false;

    DWORD old = 0;
    if (!VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &old))
        return false;

    g_patches[g_patch_count].addr = addr;
    memcpy(g_patches[g_patch_count].original, addr, 5);
    g_patches[g_patch_count].detour = (void*)detour;
    ++g_patch_count;

    uint8_t* p = (uint8_t*)addr;
    p[0] = 0xE9;
    *(int32_t*)(p + 1) = (int32_t)((uintptr_t)detour - (uintptr_t)addr - 5);

    VirtualProtect(addr, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, 5);

    original_out = tramp;
    return true;
}

static bool patch_in_netc(uint32_t a);
static void unpatch_all() {
    // FIX crash no FreeLibrary: ao contrário do quit_hard_restore (usado no exit
    // do processo, quando o SO cuida do teardown), aqui a DLL pode ser descarregada
    // com o processo VIVO. Se pularmos as hooks em netc.dll, os JMPs ficam
    // apontando para detours desta DLL (que será desmapeada) → crash na
    // próxima chamada (ex.: d_send_packet no próximo MOD_*). Restaurar TODAS.
    for (int i = 0; i < g_patch_count; ++i) {
        __try {
            DWORD old = 0;
            if (VirtualProtect(g_patches[i].addr, 5, PAGE_EXECUTE_READWRITE, &old)) {
                memcpy(g_patches[i].addr, g_patches[i].original, 5);
                VirtualProtect(g_patches[i].addr, 5, old, &old);
                FlushInstructionCache(GetCurrentProcess(), g_patches[i].addr, 5);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    g_patch_count = 0;
}

static bool g_quit_flushed = false;
static DWORD WINAPI watchdog_thread(LPVOID) {
    while (InterlockedCompareExchange(&g_watchdog_stop, 0, 0) == 0) {
        Sleep(16);

        if (g_quit_flushed) continue;

        for (int i = 0; i < g_patch_count; ++i) {
            __try {
                PatchRecord& pr = g_patches[i];
                uint8_t* bytes = (uint8_t*)pr.addr;

                if (bytes[0] != 0xE9) {
                    bool matched_original = (memcmp(pr.addr, pr.original, 5) == 0);

                    DWORD old = 0;
                    if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &old)) {
                        bytes[0] = 0xE9;
                        *(int32_t*)(bytes + 1) = (int32_t)((uintptr_t)pr.detour - (uintptr_t)pr.addr - 5);
                        VirtualProtect(pr.addr, 5, old, &old);
                        FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);

                        LONG n = InterlockedIncrement(&g_watchdog_repatch_count);
                        if (n == 1 || (n % 100) == 0) {
                            char buf[128];
                            snprintf(buf, sizeof(buf),
                                "[watchdog] re-patched hook #%d (total=%d, original=%d)\n",
                                i, (int)n, matched_original ? 1 : 0);
                            OutputDebugStringA(buf);
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
    return 0;
}
#define FUNC_WORLD_IS_LOS_CLEAR      0x56A490
#define SESSION_HEARTBEAT_MS         600
#define RECONNECT_QUARANTINE_MS      5000
#define RECONNECT_BURST_COUNT        3
#define RECONNECT_BURST_WINDOW_MS    15000
#define LOS_RECHECK_MS               50
#define KICK_BOOT_GRACE_MS           5000
#define KICK_COOLDOWN_MS             30000
#define SWITCH_PARK_MS               4000

static volatile LONG g_session_live      = 0;
static uint32_t      g_session_live_tick = 0;
static volatile LONG g_silent_send_ok    = 0;
static uint32_t      g_reconnect_window  = 0;
static uint32_t      g_reconnect_count   = 0;
static uint32_t      g_quarantine_until  = 0;
static uint32_t      g_session_fail_reason = 0;
static bool          g_session_fail_logged = false;
static uint32_t      g_fail_log_tick       = 0;
static bool          g_fail_clean_done     = false;
static uint32_t      g_server_kick_seen    = 0;
static uint32_t      g_boot_tick           = 0;
static uint32_t      g_kick_last_tick      = 0;
static uint32_t      g_los_tick            = 0;
static uint32_t      g_los_avail_tick      = 0;
static bool          g_los_avail           = false;
static bool          g_los_cached          = false;
static bool          g_los_have_cache      = false;
static float         g_los_cache_a[3]      = {};
static float         g_los_cache_b[3]      = {};
static uint32_t      g_install_generation  = 0;
static uint32_t      g_install_done_generation = 0xFFFFFFFFu;
static uint32_t      g_install_count       = 0;
static uint32_t      g_switch_park_until   = 0;
static bool          g_switch_rebase_seen  = false;

static void silent_retire_hooks();
static void silent_install_hook();
static uint32_t netc_image_size(HMODULE mod);
static HMODULE find_mod();

static bool patch_in_netc(uint32_t a) {
    if (g_netc_base && a >= g_netc_base && a < g_netc_base + g_netc_size) return true;
    HMODULE m = find_mod();
    if (m) {
        uint32_t b = (uint32_t)(uintptr_t)m;
        uint32_t z = netc_image_size(m);
        if (z && a >= b && a < b + z) return true;
    }
    return false;
}
static void silent_install_mid_hooks();
static void reconnect_note(uint32_t);
static void mta_logf(const char* tag, const char* fmt, ...);

static DWORD WINAPI session_heartbeat_thread(LPVOID) {
    while (!InterlockedCompareExchange(&g_watchdog_stop, 0, 0)) {
        Sleep(50);
        if (g_session_live_tick &&
            GetTickCount() - g_session_live_tick > SESSION_HEARTBEAT_MS) {
            InterlockedExchange(&g_session_live, 0);
            InterlockedExchange(&g_silent_send_ok, 0);
        }
    }
    return 0;
}

static void emergency_disable_all();
static void fly_physics_end();

static bool          g_netc_rebase_logged = false;
static bool          g_netc_unload_logged = false;
static bool          g_netc_needs_reinstall = false;
static uint8_t       g_stale_patch_sink[96][8] = {};

static bool patch_is_d3d9_site(uint32_t a) {
    HMODULE m = GetModuleHandleA("d3d9.dll");
    if (!m) return false;
    uint32_t b = (uint32_t)(uintptr_t)m;
    return (a >= b) && (a < b + netc_image_size(m));
}

static bool patch_is_feature(const PatchRecord& pr) {
    uint32_t a = (uint32_t)(uintptr_t)pr.addr;
    if (patch_in_netc(a)) return false;
    if (patch_is_d3d9_site(a)) return false;
    return true;
}

static void patch_set(PatchRecord& pr, bool on) {
    __try {
        uint8_t* p = (uint8_t*)pr.addr;
        if (on) {
            if (p[0] == 0xE9) return;
            DWORD oldp = 0;
            if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &oldp)) {
                p[0] = 0xE9;
                *(int32_t*)(p + 1) = (int32_t)((uintptr_t)pr.detour - (uintptr_t)pr.addr - 5);
                VirtualProtect(pr.addr, 5, oldp, &oldp);
                FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);
            }
        } else {
            if (memcmp(pr.addr, pr.original, 5) == 0) return;
            DWORD oldp = 0;
            if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &oldp)) {
                memcpy(pr.addr, pr.original, 5);
                VirtualProtect(pr.addr, 5, oldp, &oldp);
                FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}
static volatile LONG g_shutdown_all           = 0;
static volatile LONG g_emergency_done         = 0;

static bool is_shutdown_bypass() {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return true;
    if (InterlockedCompareExchange(&g_emergency_done, 0, 0)) return true;
    return false;
}

static void quit_flush() {
    if (g_quit_flushed) return;
    g_quit_flushed = true;

    int feats = 0, d3d = 0, netc = 0;
    for (int i = 0; i < g_patch_count; ++i) {
        PatchRecord& pr = g_patches[i];
        if (patch_in_netc((uint32_t)(uintptr_t)pr.addr)) { ++netc; continue; }
        if (patch_is_feature(pr)) { patch_set(pr, false); ++feats; }
    }
    for (int i = 0; i < g_patch_count; ++i) {
        PatchRecord& pr = g_patches[i];
        if (patch_in_netc((uint32_t)(uintptr_t)pr.addr)) continue;
        if (!patch_is_feature(pr)) { patch_set(pr, false); ++d3d; }
    }
    InterlockedExchange(&g_session_live, 0);
    InterlockedExchange(&g_silent_send_ok, 0);
    mta_logf("quit", "flush: %d features + %d d3d pausados, %d netc INTOCADOS",
             feats, d3d, netc);
}

static void quit_unflush() {
    if (!g_quit_flushed) return;
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;

    g_quit_flushed = false;
    int feats = 0, d3d = 0;
    for (int i = 0; i < g_patch_count; ++i) {
        PatchRecord& pr = g_patches[i];
        if (patch_in_netc((uint32_t)(uintptr_t)pr.addr)) continue;
        if (patch_is_feature(pr)) { patch_set(pr, true); ++feats; }
    }
    for (int i = 0; i < g_patch_count; ++i) {
        PatchRecord& pr = g_patches[i];
        if (patch_in_netc((uint32_t)(uintptr_t)pr.addr)) continue;
        if (!patch_is_feature(pr)) { patch_set(pr, true); ++d3d; }
    }
    mta_logf("quit", "flush revertido: %d features + %d d3d religados (netc sempre ativo)",
             feats, d3d);
}

static uint32_t netc_image_size(HMODULE mod) {
    if (!mod) return 0;
    __try {
        uint8_t* b = (uint8_t*)mod;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)b;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        return (uint32_t)nt->OptionalHeader.SizeOfImage;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static void netc_retire_stale_patches(uint32_t new_base, uint32_t new_size) {
    (void)new_base; (void)new_size;

}

static void install_all();

static PatchRecord   g_park_netc[96]       = {};
static int           g_park_netc_count     = 0;
static uint32_t      g_park_netc_base      = 0;

static void park_netc_hooks() {

}

static void unpark_netc_hooks() {

}

static void arm_switch_park(uint32_t now) {
    uint32_t t = now ? now : 1;
    reconnect_note(t);

}

static void netc_rebase_patches(uint32_t new_base, uint32_t new_size) {
    (void)new_base; (void)new_size;

}

static bool g_cursor_hidden = false;
static bool g_menu_prev     = false;

static void menu_cursor_sync(bool open) {
    if (open) {
        CURSORINFO ci = {};
        ci.cbSize = sizeof(ci);
        if (GetCursorInfo(&ci) && !(ci.flags & CURSOR_SHOWING)) ShowCursor(TRUE);
        ClipCursor(nullptr);
        g_cursor_hidden = true;
        return;
    }
    if (g_cursor_hidden) {
        ShowCursor(FALSE);
        g_cursor_hidden = false;
    }
    ClipCursor(nullptr);
}
#define MTA_LOG_PATH       "C:\\mta.log"
#define MTA_LOG_PATH_OLD   "C:\\mta.log.old"
#define MTA_LOG_MAX_BYTES  (512 * 1024)
static volatile LONG g_log_busy    = 0;
static char          g_log_path[MAX_PATH] = { 0 };

static const char* mta_log_path() {
    if (g_log_path[0]) return g_log_path;
    FILE* f = nullptr;
    if (fopen_s(&f, MTA_LOG_PATH, "ab") == 0 && f) {
        long sz = 0;
        FILE* r = nullptr;
        if (fopen_s(&r, MTA_LOG_PATH, "rb") == 0 && r) {
            fseek(r, 0, SEEK_END); sz = ftell(r); fclose(r);
        }
        fclose(f);
        if (sz > MTA_LOG_MAX_BYTES) {
            remove(MTA_LOG_PATH_OLD);
            rename(MTA_LOG_PATH, MTA_LOG_PATH_OLD);
        }
        _snprintf_s(g_log_path, sizeof(g_log_path), _TRUNCATE, "%s", MTA_LOG_PATH);
    } else {
        char tmp[MAX_PATH] = { 0 };
        if (GetTempPathA(MAX_PATH, tmp) > 0)
            _snprintf_s(g_log_path, sizeof(g_log_path), _TRUNCATE, "%smta.log", tmp);
        else
            _snprintf_s(g_log_path, sizeof(g_log_path), _TRUNCATE, ".\\mta.log");
    }
    return g_log_path;
}

static bool mta_log_tick(int ch, DWORD ms) {
    static DWORD last[8] = { 0 };
    if (ch < 0 || ch >= 8) return true;
    DWORD now = GetTickCount();
    if (last[ch] && (now - last[ch]) < ms) return false;
    last[ch] = now ? now : 1;
    return true;
}

static void mta_logf(const char* tag, const char* fmt, ...) {
    if (InterlockedCompareExchange(&g_log_busy, 1, 0) != 0) return;
    char msg[768];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char line[1024];
    int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02u:%02u:%02u.%03u][p%u/t%u][%10u][%s] %s\n",
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
        (unsigned)st.wMilliseconds,
        (unsigned)GetCurrentProcessId(), (unsigned)GetCurrentThreadId(),
        (unsigned)GetTickCount(), tag ? tag : "log", msg);
    if (n < 0) line[sizeof(line) - 1] = '\0';
    OutputDebugStringA(line);
    FILE* f = nullptr;
    if (fopen_s(&f, mta_log_path(), "a") == 0 && f) { fputs(line, f); fclose(f); }
    InterlockedExchange(&g_log_busy, 0);
}

static const ImVec4 SCHEME_V        = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
static const ImVec4 SCHEME_HOVER_V  = ImVec4(222 / 255.f, 222 / 255.f, 222 / 255.f, 1.0f);
static const ImVec4 SCHEME_ACTIVE_V = ImVec4(190 / 255.f, 190 / 255.f, 190 / 255.f, 1.0f);
static const ImVec4 WARN_V          = ImVec4(255 / 255.f, 131 / 255.f, 17 / 255.f, 1.0f);
static const ImU32 COL_SCHEME       = IM_COL32(255, 255, 255, 255);
static const ImU32 COL_SCHEME_HOVER = IM_COL32(222, 222, 222, 255);
static const ImU32 COL_SCHEME_ACT   = IM_COL32(190, 190, 190, 255);
static const ImU32 COL_ACCENT       = COL_SCHEME;
static const ImU32 COL_ACCENT_DIM   = IM_COL32(255, 255, 255, 60);
static const ImU32 COL_ACCENT_SOFT  = IM_COL32(235, 235, 235, 255);

static const ImU32 COL_BG_PANEL     = IM_COL32(0, 0, 0, 255);
static const ImU32 COL_BG_HEADER    = IM_COL32(0, 0, 0, 255);
static const ImU32 COL_BG_SIDEBAR   = IM_COL32(0, 0, 0, 0);
static const ImU32 COL_BG_CARD      = IM_COL32(0, 0, 0, 0);
static const ImU32 COL_CARD_STROKE  = IM_COL32(255, 255, 255, 120);
static const ImU32 COL_BTN_STROKE   = IM_COL32(255, 255, 255, 150);
static const ImU32 COL_BTN_STROKE_HI= IM_COL32(255, 255, 255, 230);
static const ImU32 COL_FRAME_BG     = IM_COL32(0, 0, 0, 255);
static const ImU32 COL_FRAME_HOVER  = IM_COL32(26, 26, 28, 255);
static const ImU32 COL_FRAME_ACTIVE = IM_COL32(48, 48, 52, 255);
static const ImU32 COL_TOGGLE_OFF   = IM_COL32(52, 52, 56, 255);
static const ImU32 COL_TOGGLE_KNOB  = IM_COL32(150, 151, 156, 255);
static const ImU32 COL_BORDER       = IM_COL32(255, 255, 255, 8);
static const ImU32 COL_TEXT         = IM_COL32(205, 205, 208, 255);
static const ImU32 COL_TEXT_DIM     = IM_COL32(128, 129, 134, 255);
static const float UI_ANIM_SPEED    = 0.12f;

enum MenuTab {
    TAB_COMBAT = 0,
    TAB_VISUALS,
    TAB_MISC,
    TAB_TROLL,
    TAB_COUNT
};

static bool  g_menu_open       = true;
static bool  g_prev_insert     = false;
static bool  g_prev_menu_open  = false;

static int   g_current_tab     = TAB_VISUALS;
static int   g_next_tab        = TAB_VISUALS;
static float g_content_anim      = 1.0f;
static float g_content_anim_dest = 1.0f;

static ImVec2 g_menu_pos       = ImVec2(0, 0);
static ImVec2 g_menu_size      = ImVec2(640, 420);

static bool  g_esp_local_enable  = false;
static bool  g_esp_local_box     = false;
static bool  g_esp_local_box_filled = false;
static bool  g_esp_local_box_corner = false;
static bool  g_esp_local_box_rounded = false;
static bool  g_esp_local_lines   = false;
static bool  g_esp_local_names   = false;
static bool  g_esp_local_health  = false;
static bool  g_esp_local_health_dynamic = false;
static bool  g_esp_local_armor   = false;
static bool  g_esp_local_skeleton= false;
static bool  g_esp_local_distance = true;

static float g_col_local_box[4]      = { 1.0f, 1.0f, 1.0f, 1.0f };
static float g_col_local_lines[3]    = { 1.0f, 1.0f, 1.0f };
static float g_col_local_names[3]    = { 1.0f, 1.0f, 1.0f };
static float g_col_local_health[3]   = { 0.0f, 1.0f, 0.0f };
static float g_col_local_armor[3]    = { 0.0f, 0.63f, 1.0f };
static float g_col_local_skeleton[3] = { 1.0f, 1.0f, 1.0f };
static float g_col_local_distance[3] = { 1.0f, 1.0f, 1.0f };

static bool  g_esp_players_enable  = false;
static bool  g_esp_players_box     = false;
static bool  g_esp_players_box_filled = false;
static bool  g_esp_players_box_corner = false;
static bool  g_esp_players_box_rounded = false;
static bool  g_esp_players_lines   = false;
static bool  g_esp_players_names   = false;
static bool  g_esp_players_health  = false;
static bool  g_esp_players_health_dynamic = false;
static bool  g_esp_players_armor   = false;
static bool  g_esp_players_skeleton= false;
static bool  g_esp_players_distance = true;

static float g_col_players_box[4]      = { 1.0f, 1.0f, 1.0f, 1.0f };
static float g_col_players_lines[3]    = { 1.0f, 1.0f, 1.0f };
static float g_col_players_names[3]    = { 1.0f, 1.0f, 1.0f };
static float g_col_players_health[3]   = { 0.0f, 1.0f, 0.0f };
static float g_col_players_armor[3]    = { 0.0f, 0.63f, 1.0f };
static float g_col_players_skeleton[3] = { 1.0f, 1.0f, 1.0f };
static float g_col_players_distance[3] = { 1.0f, 1.0f, 1.0f };

#define ESP_NAME_FONT_SIZE   13.0f

#define ESP_TEXT_STROKE        1.0f
#define ESP_TEXT_STROKE_ALPHA  200

#define ESP_SHOW_UNRESOLVED_NAME 0

#define ESP_SKELETON_THICKNESS  1.0f

static bool session_live() {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return false;
    if (!InterlockedCompareExchange(&g_session_live, 0, 0)) return false;
    uint32_t t = g_session_live_tick;
    if (!t || GetTickCount() - t > SESSION_HEARTBEAT_MS) return false;
    return true;
}
static bool          g_emergency_logged  = false;

static int      g_menu_key_vk        = VK_INSERT;
static char     g_menu_key_name[32] = "Insert";
static bool     g_menu_key_latch     = false;
static uint32_t g_menu_toggle_tick   = 0;
static volatile LONG g_menu_toggle_pending = 0;
static int      g_fly_key_vk         = VK_F8;
static char     g_fly_key_name[32]  = "F8";
static bool     g_fly_key_prev       = false;
static bool     g_fly_key_held       = false;
static int      g_bind_capture       = 0;
static uint32_t g_bind_capture_tick  = 0;

#define FLY_MODE_HOLD      0
#define FLY_MODE_TOGGLE    1
#ifndef VK_SHIFT
#define VK_SHIFT 0x10
#endif
static bool  g_fly_enable       = false;
static bool  g_fly_active       = false;
static float g_fly_speed        = 8.0f;
static int   g_fly_mode         = FLY_MODE_HOLD;
static float g_fly_pitch_base   = 0.0f;
static bool  g_fly_pitch_init   = false;
static int   g_fly_pitch_axis   = -1;
static bool  g_fly_toggle_on    = false;
static bool  g_fly_key_edge     = false;
static bool  g_fly_hover_valid  = false;
static float g_fly_hover_pos[3] = { 0.0f, 0.0f, 0.0f };
static bool  g_fly_phys_saved    = false;
static uint32_t g_fly_phys_flags  = 0;
static uint32_t g_fly_phys_ped    = 0;
static float g_fly_hp_saved       = 100.0f;
static float g_fly_armor_saved    = 0.0f;
static int   g_fly_axis_idx       = -1;
static bool  g_infinite_ammo      = false;
static bool  g_ammo_logged        = false;
static bool  g_fly_veh_logged     = false;

static uint64_t      g_us_wait         = 0;

#define WDA_NONE_VALUE            0x00000000
#define WDA_MONITOR_VALUE         0x00000001
#define WDA_EXCLUDEFROMCAPTURE_V  0x00000011

static bool     g_stream_proof         = false;
static bool     g_game_focused         = true;
static bool     g_stream_proof_ok      = true;
static bool     g_stream_proof_ready   = false;
static DWORD    g_stream_proof_applied = WDA_NONE_VALUE;
static HWND     g_stream_proof_hwnd    = nullptr;
static uint32_t g_stream_proof_last_try = 0;

#define CFG_NAME_MAX   32
#define CFG_MAX_FILES  64
static char  g_cfg_dir[MAX_PATH]                  = {};
static char  g_cfg_input[CFG_NAME_MAX + 1]        = {};
static char  g_cfg_names[CFG_MAX_FILES][CFG_NAME_MAX + 1] = {};
static int   g_cfg_count       = 0;
static int   g_cfg_selected    = -1;
static char  g_cfg_status[160] = "Nenhuma config carregada.";
static bool  g_cfg_status_ok   = true;
static bool  g_cfg_pending_overwrite = false;
static bool  g_cfg_pending_delete    = false;

static void notify_push(const char*, const char*, bool, const char*, ...);

static void cfg_status(bool ok, const char* fmt, ...) {
    g_cfg_status_ok = ok;
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(g_cfg_status, sizeof(g_cfg_status), _TRUNCATE, fmt, ap);
    va_end(ap);
    mta_logf(ok ? "cfg" : "cfg!", "%s", g_cfg_status);
    notify_push("Config", ICON_FA_COG, ok, "%s", g_cfg_status);
}

static const char* cfg_get_dir() {
    if (g_cfg_dir[0]) return g_cfg_dir;
    char app[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableA("APPDATA", app, MAX_PATH);
    if (!n || n >= MAX_PATH) {
        if (!GetTempPathA(MAX_PATH, app) || !app[0]) return nullptr;
    }
    _snprintf_s(g_cfg_dir, sizeof(g_cfg_dir), _TRUNCATE, "%s\\Hijacking", app);
    CreateDirectoryA(g_cfg_dir, nullptr);
    return g_cfg_dir;
}

static int cfg_ieq(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

static bool cfg_valid_name(const char* s, char* why, size_t why_sz) {
    if (!s || !s[0]) { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Digite um nome para salvar."); return false; }
    size_t n = strlen(s);
    if (n > CFG_NAME_MAX) { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Maximo de %d caracteres.", CFG_NAME_MAX); return false; }
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ' ';
        if (!ok) { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Use apenas letras, numeros, _ - e espaco."); return false; }
    }
    if (s[0] == ' ' || s[n - 1] == ' ') { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Sem espaco no inicio/fim."); return false; }
    static const char* reserved[] = { "CON","PRN","AUX","NUL","CLOCK$",
        "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
        "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9", nullptr };
    for (int i = 0; reserved[i]; ++i)
        if (cfg_ieq(s, reserved[i])) { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Nome reservado pelo Windows."); return false; }
    return true;
}

static bool cfg_make_path(const char* name, char* out, size_t out_sz) {
    const char* d = cfg_get_dir();
    if (!d) return false;
    int n = _snprintf_s(out, out_sz, _TRUNCATE, "%s\\%s.hcfg", d, name);
    return n > 0;
}

static bool cfg_exists(const char* name) {
    char path[MAX_PATH];
    if (!cfg_make_path(name, path, sizeof(path))) return false;
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void cfg_scan(bool force = false) {
    static uint32_t last_scan = 0;
    uint32_t now = GetTickCount();
    if (!force && last_scan && now - last_scan < 2000) return;
    last_scan = now ? now : 1;
    g_cfg_count = 0;
    const char* d = cfg_get_dir();
    if (!d) return;
    char pat[MAX_PATH];
    _snprintf_s(pat, sizeof(pat), _TRUNCATE, "%s\\*.hcfg", d);
    WIN32_FIND_DATAA fd = {};
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) { g_cfg_selected = -1; return; }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const char* dot = strrchr(fd.cFileName, '.');
        if (!dot || strcmp(dot, ".hcfg") != 0) continue;
        size_t n = (size_t)(dot - fd.cFileName);
        if (n == 0 || n > CFG_NAME_MAX || g_cfg_count >= CFG_MAX_FILES) continue;
        memcpy(g_cfg_names[g_cfg_count], fd.cFileName, n);
        g_cfg_names[g_cfg_count][n] = '\0';
        ++g_cfg_count;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (g_cfg_selected >= g_cfg_count) g_cfg_selected = g_cfg_count ? 0 : -1;
}

static bool cfg_name_combo(const char** items, int count) {
    static char joined[CFG_MAX_FILES * (CFG_NAME_MAX + 2)] = {};
    joined[0] = '\0';
    size_t at = 0;
    for (int i = 0; i < count && i < CFG_MAX_FILES; ++i) {
        size_t l = strlen(g_cfg_names[i]);
        if (at + l + 1 >= sizeof(joined)) break;
        memcpy(joined + at, g_cfg_names[i], l);
        at += l; joined[at++] = '\0';
    }
    joined[at] = '\0';
    *items = joined;
    return true;
}

static void bind_format_key(int vk, char* out, size_t sz) {
    const char* fixed = nullptr;
    switch (vk) {
    case VK_LBUTTON: fixed = "Mouse1"; break;
    case VK_RBUTTON: fixed = "Mouse2"; break;
    case VK_MBUTTON: fixed = "Mouse3"; break;
    case VK_XBUTTON1: fixed = "Mouse4"; break;
    case VK_XBUTTON2: fixed = "Mouse5"; break;
    case VK_INSERT: fixed = "Insert"; break;
    case VK_DELETE: fixed = "Delete"; break;
    case VK_HOME: fixed = "Home"; break;
    case VK_SHIFT: fixed = "Shift"; break;
    case VK_CONTROL: fixed = "Ctrl"; break;
    case VK_MENU: fixed = "Alt"; break;
    case VK_SPACE: fixed = "Space"; break;
    case VK_RETURN: fixed = "Enter"; break;
    case VK_BACK: fixed = "Back"; break;
    case VK_TAB: fixed = "Tab"; break;
    case VK_CAPITAL: fixed = "Caps"; break;
    case VK_ESCAPE: fixed = "Esc"; break;
    }
    if (fixed) { _snprintf_s(out, sz, _TRUNCATE, "%s", fixed); return; }
    if (vk >= VK_F1 && vk <= VK_F12) { _snprintf_s(out, sz, _TRUNCATE, "F%d", vk - VK_F1 + 1); return; }
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) { _snprintf_s(out, sz, _TRUNCATE, "Num%d", vk - VK_NUMPAD0); return; }
    UINT scan = MapVirtualKeyA((UINT)vk, MAPVK_VK_TO_VSC);
    char nm[64] = {};
    int n = GetKeyNameTextA((LONG)(scan << 16), nm, (int)sizeof(nm) - 1);
    if (n > 0 && nm[0] && nm[0] != ' ') _snprintf_s(out, sz, _TRUNCATE, "%s", nm);
    else if ((vk >= 'A' && vk <= 'Z') || (vk >= '0' && vk <= '9')) _snprintf_s(out, sz, _TRUNCATE, "%c", (char)vk);
    else _snprintf_s(out, sz, _TRUNCATE, "VK %02X", (unsigned)vk);
}

static void bind_set_key(int which, int vk) {
    if (vk <= 0 || vk > 255) return;
    if      (which == 2) { g_menu_key_vk = vk; bind_format_key(vk, g_menu_key_name, sizeof(g_menu_key_name)); }
    else if (which == 3) { g_fly_key_vk = vk; bind_format_key(vk, g_fly_key_name, sizeof(g_fly_key_name)); }
    g_fly_toggle_on = false;
    g_fly_key_edge = false;
    g_fly_hover_valid = false;
    g_bind_capture = 0;
    g_bind_capture_tick = 0;
    g_menu_key_latch = (GetAsyncKeyState(g_menu_key_vk) & 0x8000) != 0;
    g_fly_key_prev = false;
    mta_logf("bind", "which=%d vk=%02X nome=%s", which, (unsigned)vk,
             which == 2 ? g_menu_key_name : g_fly_key_name);
}

static bool bind_is_down(int vk) {
    if (vk <= 0 || vk > 255) return false;
    return (GetAsyncKeyState(vk) & 0x8000) != 0;
}

typedef BOOL (WINAPI* SetWindowDisplayAffinityFn)(HWND, DWORD);
static bool set_display_affinity(HWND hwnd, DWORD aff) {
    if (!hwnd) return false;
    HMODULE u = GetModuleHandleA("user32.dll");
    if (!u) return false;
    SetWindowDisplayAffinityFn fn =
        (SetWindowDisplayAffinityFn)(void*)GetProcAddress(u, "SetWindowDisplayAffinity");
    if (!fn) return false;
    return fn(hwnd, aff) != FALSE;
}

static char  g_local_nick[64]  = "Local Player";

static bool  g_aimbot_enable     = false;
static bool  g_aimbot_show_fov   = false;
static float g_aimbot_fov_col[3] = { 1.0f, 1.0f, 1.0f };
static float g_aimbot_fov_size   = 120.0f;
static float g_aimbot_smooth     = 10.0f;
static int   g_aimbot_bone       = 0;
static bool  g_aimbot_center_dot = false;
static bool  g_aimbot_show_target= true;
static const char AIMBOT_BONE_ITEMS[] =
    "Head\0Neck\0Chest\0Right Arm\0Left Arm\0Left Leg\0Right Leg\0";

#define AIMBOT_KEY_HOLD_MODE       1
#define AIMBOT_AIM_MODE            0
#define AIMBOT_MOUSE_SENS          1.0f
#define AIMBOT_SNAP_MAX_PIXELS  1600.0f
#define AIMBOT_CAM_YAW_SIGN        1.0f
#define AIMBOT_CAM_PITCH_SIGN      1.0f
#define AIMBOT_ONLY_REAL_PLAYERS   0
#define AIMBOT_CENTER_DOT_RADIUS   1.2f

#define SILENT_FIRE_INSTANT_HIT   0x73FB10
#define NETC_GRACE_MS             2500
#define MTA_FIRE_MID_POS          0x740B89
#define MTA_FIRE_MID_END          0x10
#define MTA_FIRE_MID_START        0x38
#define MTA_SNIPER_MID_POS        0x73AE31
#define MTA_SNIPER_MID_END        0x3C
#define MTA_PACKET_BULLETSYNC     98

static bool  g_silent_enable       = false;
static bool  g_silent_show_fov     = true;
static float g_silent_fov_col[3]   = { 1.0f, 0.0f, 0.0f };
static float g_silent_fov_size     = 70.0f;
static int   g_silent_bone         = 0;
static bool  g_silent_center_dot   = false;
static bool  g_silent_show_target  = true;
static int   g_silent_key_vk       = VK_XBUTTON2;
static char  g_silent_key_name[32] = "Mouse5";
static bool  g_silent_capturing    = false;
static bool  g_silent_aim_on       = false;
static bool  g_silent_has_target   = false;
static float g_silent_target_sx    = 0.0f;
static float g_silent_target_sy    = 0.0f;
static volatile float g_silent_aim_point[3] = {};
static void* g_o_FireInstantHit    = nullptr;
static bool  g_silent_hook_ok      = false;
static void* g_o_mta_fire_mid      = nullptr;
static void* g_o_mta_sniper_mid    = nullptr;
static bool  g_silent_mid_ok        = false;
static bool  g_silent_sniper_ok     = false;
static bool  g_silent_mid_logged    = false;
static bool  g_silent_sniper_logged = false;
static bool  g_silent_ignore_walls = false;
static bool  g_los_logged          = false;
static uint32_t g_conn_grace       = 0;
static bool  g_conn_prev_active    = false;

static bool conn_handshake_active() {
    uint32_t t = g_conn_grace;
    if (!t) return false;
    if (GetTickCount() - t < NETC_GRACE_MS) return true;
    g_conn_grace = 0;
    return false;
}

#ifdef ICON_FA_KEYBOARD
#define AIMBOT_ICON_KEYBOARD  ICON_FA_KEYBOARD
#else
#define AIMBOT_ICON_KEYBOARD  "\xEF\x84\x9C"
#endif
#define TROLL_ICON_GLYPH "\xEF\x96\x88"

#define TROLL_ICON_USER    "\xEF\x80\x87"
#define TROLL_ICON_USERS   "\xEF\x83\x80"
#define TROLL_ICON_HEART   "\xEF\x80\x84"
#define TROLL_ICON_SHIELD  "\xEF\x8F\xAD"
#define TROLL_ICON_PLACE   "\xEF\x8F\x85"
#define TROLL_ICON_FIRE    "\xEF\x81\xAD"
#define TROLL_ICON_BOMB    "\xEF\x87\xA2"
#define TROLL_ICON_EYE     "\xEF\x81\xAE"
#define TROLL_ICON_BACK    "\xEF\x81\x80"
#define TROLL_ICON_STAR    "\xEF\x80\x85"

#define ADDR_EXPLOSION_ADD      0x736A50u
#define ADDR_FIRE_MANAGER       0xB71F80u
#define FIRE_SLOT_SIZE          40u
#define FIRE_MAX_SLOTS          60u
#define ADDR_FIRE_START_ONPED   0x53A050u
#define ADDR_FIRE_IGNITE_FX     0x539360u
#define ADDR_FIRE_EXTINGUISH    0x5393F0u
#define PED_OFF_FIRE_ONPED      0x730u
#define PED_OFF_FIRE_DAMAGEMULT 0x734u
#define ADDR_CTIMER_TICK        0xB7CB84u
#define ADDR_CCAMERA            0xB6F028u
#define ADDR_CAMERA_TAKE_CONTROL 0x50C7C0u
#define ADDR_CAMERA_RESTORE_JC1 0x50BD40u
#define ADDR_CAMERA_RESTORE_JC2 0x50BAB0u
#define CAM_OFF_TARGET_ENTITY   0x958u
#define CAM_MODE_NONE           0u
#define CAM_MODE_FOLLOWPED      4u
#define CAM_STYLE_SMOOTH        1u
#define CAM_STYLE_CUT           2u

#define EXPLOSION_GRENADE       0
#define EXPLOSION_MOLOTOV       1
#define EXPLOSION_ROCKET        2
#define EXPLOSION_CAR           4
#define EXPLOSION_MINE          8
#define EXPLOSION_TANK_GRENADE  10
#define EXPLOSION_SMALL         11

#define TROLL_EXPLODE_SHAKE     (-1.0f)
#define TROLL_FIRE_SIZE         1.8f
#define TROLL_FIRE_BURN_MS      15000u
#define TROLL_TICK_MS           400u
#define TROLL_FIRE_TICK_MS      500u
#define TROLL_FIRE_MAX_REARMS   6u
#define TROLL_SPECTATE_MAX_ARM  8u
#define TROLL_SPECTATE_ARM_MS   1200u

#ifdef ICON_FA_CROSSHAIRS
#define CARD_ICON_CROSSHAIR ICON_FA_CROSSHAIRS
#else
#define CARD_ICON_CROSSHAIR "\xEF\x81\x9B"
#endif
#ifdef ICON_FA_GHOST
#define CARD_ICON_GHOST     ICON_FA_GHOST
#else
#define CARD_ICON_GHOST     "\xEF\x9B\xA2"
#endif
#ifdef ICON_FA_EYE
#define CARD_ICON_EYE       ICON_FA_EYE
#else
#define CARD_ICON_EYE       "\xEF\x81\xAE"
#endif
#ifdef ICON_FA_COG
#define CARD_ICON_COG       ICON_FA_COG
#else
#define CARD_ICON_COG       "\xEF\x80\x93"
#endif
#ifdef ICON_FA_BOLT
#define CARD_ICON_BOLT      ICON_FA_BOLT
#else
#define CARD_ICON_BOLT      "\xEF\x83\xA7"
#endif

static int      g_aimbot_key_vk       = VK_XBUTTON1;
static char     g_aimbot_key_name[32] = "Mouse4";
static bool     g_aimbot_key_is_mouse = true;
static bool     g_aimbot_capturing    = false;
static uint32_t g_aimbot_capture_tick = 0;
static bool     g_aimbot_key_held     = false;
static uint32_t g_aimbot_held_tick    = 0;
static bool     g_aimbot_aim_on       = false;
static bool     g_aimbot_has_target   = false;
static float    g_aimbot_target_sx    = 0.0f;
static float    g_aimbot_target_sy    = 0.0f;

static void session_fail_closed(uint32_t reason) {
    uint32_t now = GetTickCount();
    InterlockedExchange(&g_session_live, 0);
    g_session_live_tick = 0;
    InterlockedExchange(&g_silent_send_ok, 0);
    g_silent_aim_on = g_silent_has_target = false;
    g_aimbot_aim_on = g_aimbot_has_target = false;
    if (!g_fail_clean_done) {
        g_fail_clean_done = true;
        fly_physics_end();
    }
    if ((!g_session_fail_logged || g_session_fail_reason != reason) &&
        (!g_fail_log_tick || now - g_fail_log_tick > 1000)) {
        g_session_fail_logged = true;
        g_session_fail_reason = reason;
        g_fail_log_tick = now ? now : 1;
        mta_logf("safe", "fail-closed motivo=%u: trajetoria, mira e packet desligados",
                 (unsigned)reason);
    }
}

static void reconnect_note(uint32_t now) {
    uint32_t t = now ? now : 1;
    if (g_quarantine_until &&
        (t - g_quarantine_until < RECONNECT_QUARANTINE_MS))
        return;
    if (!g_reconnect_window ||
        t - g_reconnect_window > RECONNECT_BURST_WINDOW_MS) {
        g_reconnect_window = t;
        g_reconnect_count = 0;
    }
    ++g_reconnect_count;
    if (g_reconnect_count >= RECONNECT_BURST_COUNT) {
        g_quarantine_until = t;
        g_reconnect_count = 0;
        mta_logf("safe", "quarentena %ums: %u trocas de servidor em %ums",
                 (unsigned)RECONNECT_QUARANTINE_MS,
                 (unsigned)RECONNECT_BURST_COUNT,
                 (unsigned)RECONNECT_BURST_WINDOW_MS);
    }
}

static void aimbot_set_key(int vk) {
    g_aimbot_key_vk = vk;
    g_aimbot_key_is_mouse =
        (vk == VK_LBUTTON || vk == VK_RBUTTON || vk == VK_MBUTTON ||
         vk == VK_XBUTTON1 || vk == VK_XBUTTON2);

    const char* fixed = nullptr;
    switch (vk) {
    case VK_LBUTTON:  fixed = "Mouse1"; break;
    case VK_RBUTTON:  fixed = "Mouse2"; break;
    case VK_MBUTTON:  fixed = "Mouse3"; break;
    case VK_XBUTTON1: fixed = "Mouse4"; break;
    case VK_XBUTTON2: fixed = "Mouse5"; break;
    case VK_SHIFT:    fixed = "Shift";  break;
    case VK_CONTROL:  fixed = "Ctrl";   break;
    case VK_MENU:     fixed = "Alt";    break;
    case VK_SPACE:    fixed = "Space";  break;
    case VK_RETURN:   fixed = "Enter";  break;
    case VK_BACK:     fixed = "Back";   break;
    case VK_TAB:      fixed = "Tab";    break;
    case VK_CAPITAL:  fixed = "Caps";   break;
    case VK_ESCAPE:   fixed = "Esc";    break;
    }
    if (fixed) {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "%s", fixed);
        return;
    }
    if (vk >= VK_F1 && vk <= VK_F12) {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "F%d", vk - VK_F1 + 1);
        return;
    }
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "Num%d", vk - VK_NUMPAD0);
        return;
    }
    UINT scan = MapVirtualKeyA((UINT)vk, MAPVK_VK_TO_VSC);
    char nm[64] = {};
    int n = GetKeyNameTextA((LONG)(scan << 16), nm, (int)sizeof(nm) - 1);
    if (n > 0 && nm[0] && nm[0] != ' ') {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "%s", nm);
    } else if ((vk >= 'A' && vk <= 'Z') || (vk >= '0' && vk <= '9')) {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "%c", (char)vk);
    } else {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "VK %02X", (unsigned)vk);
    }
}

static void aimbot_stop_capture() {
    g_aimbot_capturing    = false;
    g_aimbot_capture_tick = 0;
    g_aimbot_key_held     = false;
    g_aimbot_aim_on       = false;
}

static void aimbot_poll_capture() {
    if (!g_aimbot_capturing) return;

    static bool     armed = false;
    static bool     was_down[256] = {};
    static uint32_t start = 0;

    if (g_aimbot_capture_tick == 0) {
        g_aimbot_capture_tick = GetTickCount();
        start = g_aimbot_capture_tick;
        armed = false;
        return;
    }
    if (GetTickCount() - start > 8000) { aimbot_stop_capture(); return; }

    if (!armed) {
        for (int i = 0; i < 256; ++i)
            was_down[i] = (GetAsyncKeyState(i) & 0x8000) != 0;
        if ((GetAsyncKeyState(VK_LBUTTON) & 0x8000) == 0) {
            armed = true;
            was_down[VK_LBUTTON] = false;
        }
        return;
    }

    if ((GetAsyncKeyState(VK_ESCAPE) & 0x8000) != 0 && !was_down[VK_ESCAPE]) {
        aimbot_stop_capture();
        return;
    }
    for (int vk = 1; vk < 256; ++vk) {
        if (vk == VK_ESCAPE || was_down[vk]) continue;
        if ((GetAsyncKeyState(vk) & 0x8000) != 0) {
            aimbot_set_key(vk);
            aimbot_stop_capture();
            return;
        }
    }
}

static bool aimbot_is_key_down() {
    const bool async = (GetAsyncKeyState(g_aimbot_key_vk) & 0x8000) != 0;
    if (async) return true;
    if (!g_aimbot_key_held) return false;
    if (GetTickCount() - g_aimbot_held_tick > 4000) {
        g_aimbot_key_held = false;
        return false;
    }
    return g_aimbot_key_is_mouse;
}

static void aimbot_update_key() {
    const bool held = aimbot_is_key_down() && !g_aimbot_capturing;
#if AIMBOT_KEY_HOLD_MODE
    g_aimbot_aim_on = held;
#else
    static bool prev = false;
    if (held && !prev) g_aimbot_aim_on = !g_aimbot_aim_on;
    prev = held;
#endif
    if (!g_aimbot_enable) g_aimbot_aim_on = false;
}

static ImFont* g_font_regular   = nullptr;
static ImFont* g_font_tabs      = nullptr;
static ImFont* g_font_header    = nullptr;
static ImFont* g_font_esp_name  = nullptr;
static ImFont* g_font_icons     = nullptr;
static float   g_icon_font_size = 16.0f;
static std::unordered_map<ImGuiID, float> g_check_anim;

enum { CFG_BOOL = 0, CFG_FLOAT = 1, CFG_INT = 2, CFG_COL3 = 3, CFG_COL4 = 4 };
struct CfgEntry { const char* key; void* ptr; int type; };
static const CfgEntry CFG_ENTRIES[] = {
    { "esp.local.enable",     &g_esp_local_enable,     CFG_BOOL  },
    { "esp.local.box",        &g_esp_local_box,        CFG_BOOL  },
    { "esp.local.filled",     &g_esp_local_box_filled, CFG_BOOL  },
    { "esp.local.corner",     &g_esp_local_box_corner, CFG_BOOL  },
    { "esp.local.rounded",    &g_esp_local_box_rounded,CFG_BOOL  },
    { "esp.local.lines",      &g_esp_local_lines,      CFG_BOOL  },
    { "esp.local.names",      &g_esp_local_names,      CFG_BOOL  },
    { "esp.local.health",     &g_esp_local_health,     CFG_BOOL  },
    { "esp.local.healthdyn",  &g_esp_local_health_dynamic, CFG_BOOL },
    { "esp.local.armor",      &g_esp_local_armor,      CFG_BOOL  },
    { "esp.local.skeleton",   &g_esp_local_skeleton,   CFG_BOOL  },
    { "esp.local.distance",   &g_esp_local_distance,   CFG_BOOL  },
    { "esp.local.colbox",     g_col_local_box,         CFG_COL4  },
    { "esp.local.collines",   g_col_local_lines,       CFG_COL3  },
    { "esp.local.colnames",   g_col_local_names,       CFG_COL3  },
    { "esp.local.colhealth",  g_col_local_health,      CFG_COL3  },
    { "esp.local.colarmor",   g_col_local_armor,       CFG_COL3  },
    { "esp.local.colskel",    g_col_local_skeleton,    CFG_COL3  },
    { "esp.local.coldist",    g_col_local_distance,    CFG_COL3  },
    { "esp.players.enable",   &g_esp_players_enable,   CFG_BOOL  },
    { "esp.players.box",      &g_esp_players_box,      CFG_BOOL  },
    { "esp.players.filled",   &g_esp_players_box_filled, CFG_BOOL },
    { "esp.players.corner",   &g_esp_players_box_corner, CFG_BOOL },
    { "esp.players.rounded",  &g_esp_players_box_rounded,CFG_BOOL },
    { "esp.players.lines",    &g_esp_players_lines,    CFG_BOOL  },
    { "esp.players.names",    &g_esp_players_names,    CFG_BOOL  },
    { "esp.players.health",   &g_esp_players_health,   CFG_BOOL  },
    { "esp.players.healthdyn",&g_esp_players_health_dynamic, CFG_BOOL },
    { "esp.players.armor",    &g_esp_players_armor,    CFG_BOOL  },
    { "esp.players.skeleton", &g_esp_players_skeleton, CFG_BOOL  },
    { "esp.players.distance", &g_esp_players_distance, CFG_BOOL  },
    { "esp.players.colbox",   g_col_players_box,       CFG_COL4  },
    { "esp.players.collines", g_col_players_lines,     CFG_COL3  },
    { "esp.players.colnames", g_col_players_names,     CFG_COL3  },
    { "esp.players.colhealth",g_col_players_health,    CFG_COL3  },
    { "esp.players.colarmor", g_col_players_armor,     CFG_COL3  },
    { "esp.players.colskel",  g_col_players_skeleton,  CFG_COL3  },
    { "esp.players.coldist",  g_col_players_distance,  CFG_COL3  },
    { "aim.enable",           &g_aimbot_enable,        CFG_BOOL  },
    { "aim.showfov",          &g_aimbot_show_fov,      CFG_BOOL  },
    { "aim.centerdot",        &g_aimbot_center_dot,    CFG_BOOL  },
    { "aim.showtarget",       &g_aimbot_show_target,   CFG_BOOL  },
    { "aim.fovsize",          &g_aimbot_fov_size,      CFG_FLOAT },
    { "aim.smooth",           &g_aimbot_smooth,        CFG_FLOAT },
    { "aim.bone",             &g_aimbot_bone,          CFG_INT   },
    { "aim.fovcol",           g_aimbot_fov_col,        CFG_COL3  },
    { "aim.key",              &g_aimbot_key_vk,        CFG_INT   },
    { "sil.enable",           &g_silent_enable,        CFG_BOOL  },
    { "sil.showfov",          &g_silent_show_fov,      CFG_BOOL  },
    { "sil.centerdot",        &g_silent_center_dot,    CFG_BOOL  },
    { "sil.showtarget",       &g_silent_show_target,   CFG_BOOL  },
    { "sil.fovsize",          &g_silent_fov_size,      CFG_FLOAT },
    { "sil.bone",             &g_silent_bone,          CFG_INT   },
    { "sil.fovcol",           g_silent_fov_col,        CFG_COL3  },
    { "sil.key",              &g_silent_key_vk,        CFG_INT   },
    { "sil.ignorewalls",       &g_silent_ignore_walls,  CFG_BOOL  },
    { "misc.menukey",         &g_menu_key_vk,          CFG_INT   },
    { "misc.flyenable",       &g_fly_enable,           CFG_BOOL  },
    { "misc.flykey",          &g_fly_key_vk,           CFG_INT   },
    { "misc.flyspeed",        &g_fly_speed,            CFG_FLOAT },
    { "misc.flymode",         &g_fly_mode,            CFG_INT   },
    { "misc.streamproof",     &g_stream_proof,         CFG_BOOL  },
    // FIX: entra no snapshot/restore. Antes ficava ON permanentemente
    // (não era tocado por sess_disable_all) e a escrita por frame em
    // weapon+slot continuava mesmo após disconnect. Sintoma reportado:
    // "as coisas não" quando o usuário reentra — na verdade era a ammo
    // sendo reescrita sem a sessão viva.
    { "troll.ammo",           &g_infinite_ammo,        CFG_BOOL  },
};
static const int CFG_ENTRY_COUNT = (int)(sizeof(CFG_ENTRIES) / sizeof(CFG_ENTRIES[0]));

static float cfg_clampf(float v, float lo, float hi) { return v < lo ? lo : (v > hi ? hi : v); }

static bool cfg_save(const char* name) {
    char why[128];
    if (!cfg_valid_name(name, why, sizeof(why))) { cfg_status(false, "%s", why); return false; }
    if (cfg_exists(name) && !g_cfg_pending_overwrite) {
        g_cfg_pending_overwrite = true;
        cfg_status(false, "'%s' ja existe. Clique Salvar novamente para sobrescrever.", name);
        return false;
    }
    char path[MAX_PATH];
    if (!cfg_make_path(name, path, sizeof(path))) { cfg_status(false, "Sem pasta para salvar."); return false; }
    FILE* f = nullptr;
    if (fopen_s(&f, path, "w") != 0 || !f) { cfg_status(false, "Falha ao abrir arquivo."); return false; }
    fprintf(f, "HJCfg1\n");
    for (int i = 0; i < CFG_ENTRY_COUNT; ++i) {
        const CfgEntry& e = CFG_ENTRIES[i];
        switch (e.type) {
        case CFG_BOOL:  fprintf(f, "%s=%d\n", e.key, *(bool*)e.ptr ? 1 : 0); break;
        case CFG_INT:   fprintf(f, "%s=%d\n", e.key, *(int*)e.ptr); break;
        case CFG_FLOAT: fprintf(f, "%s=%.4f\n", e.key, *(float*)e.ptr); break;
        case CFG_COL3: {
            float* c = (float*)e.ptr;
            fprintf(f, "%s=%.4f,%.4f,%.4f\n", e.key, c[0], c[1], c[2]); break;
        }
        case CFG_COL4: {
            float* c = (float*)e.ptr;
            fprintf(f, "%s=%.4f,%.4f,%.4f,%.4f\n", e.key, c[0], c[1], c[2], c[3]); break;
        }
        }
    }
    fclose(f);
    g_cfg_pending_overwrite = false;
    cfg_scan(true);
    for (int i = 0; i < g_cfg_count; ++i)
        if (strcmp(g_cfg_names[i], name) == 0) { g_cfg_selected = i; break; }
    cfg_status(true, "Config '%s' foi salva.", name);
    return true;
}

static bool cfg_load(const char* name) {
    char why[128];
    if (!cfg_valid_name(name, why, sizeof(why))) { cfg_status(false, "%s", why); return false; }
    char path[MAX_PATH];
    if (!cfg_make_path(name, path, sizeof(path)) || !cfg_exists(name)) {
        cfg_status(false, "Arquivo nao encontrado."); return false;
    }
    FILE* f = nullptr;
    if (fopen_s(&f, path, "r") != 0 || !f) { cfg_status(false, "Falha ao ler arquivo."); return false; }
    char line[256];
    if (!fgets(line, sizeof(line), f) || strncmp(line, "HJCfg1", 6) != 0) {
        fclose(f); cfg_status(false, "Arquivo invalido (nao e uma config)."); return false;
    }
    int applied = 0;
    while (fgets(line, sizeof(line), f)) {
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char* key = line;
        char* val = eq + 1;
        for (int i = 0; i < CFG_ENTRY_COUNT; ++i) {
            const CfgEntry& e = CFG_ENTRIES[i];
            if (strcmp(key, e.key) != 0) continue;
            switch (e.type) {
            case CFG_BOOL:  *(bool*)e.ptr = (atoi(val) != 0); break;
            case CFG_INT: {
                int v = atoi(val);
                if (v >= 0 && v <= 255) *(int*)e.ptr = v;
                break;
            }
            case CFG_FLOAT: *(float*)e.ptr = cfg_clampf((float)atof(val), -1000.0f, 1000.0f); break;
            case CFG_COL3: case CFG_COL4: {
                float* c = (float*)e.ptr;
                int n = (e.type == CFG_COL3) ? 3 : 4;
                char* p = val;
                for (int k = 0; k < n; ++k) {
                    while (*p == ' ' || *p == ',') ++p;
                    if (!*p || *p == '\n' || *p == '\r') break;
                    c[k] = cfg_clampf((float)strtod(p, &p), 0.0f, 1.0f);
                }
                break;
            }
            }
            ++applied;
            break;
        }
    }
    fclose(f);
    if (applied == 0) { cfg_status(false, "Nenhuma opcao valida no arquivo."); return false; }
    g_aimbot_fov_size = cfg_clampf(g_aimbot_fov_size, 1.0f, 900.0f);
    g_aimbot_smooth   = cfg_clampf(g_aimbot_smooth, 0.0f, 100.0f);
    g_aimbot_bone     = g_aimbot_bone < 0 ? 0 : (g_aimbot_bone > 6 ? 6 : g_aimbot_bone);
    g_silent_fov_size = cfg_clampf(g_silent_fov_size, 1.0f, 900.0f);
    g_silent_bone     = g_silent_bone < 0 ? 0 : (g_silent_bone > 6 ? 6 : g_silent_bone);
    if (g_silent_key_vk <= 0 || g_silent_key_vk > 255) g_silent_key_vk = VK_XBUTTON2;
    bind_format_key(g_silent_key_vk, g_silent_key_name, sizeof(g_silent_key_name));
    g_fly_speed       = cfg_clampf(g_fly_speed, 0.5f, 100.0f);
    if (g_menu_key_vk <= 0 || g_menu_key_vk > 255) g_menu_key_vk = VK_INSERT;
    if (g_fly_key_vk  <= 0 || g_fly_key_vk  > 255) g_fly_key_vk  = VK_F8;
    g_fly_mode = (g_fly_mode == FLY_MODE_TOGGLE) ? FLY_MODE_TOGGLE : FLY_MODE_HOLD;
    if (g_aimbot_key_vk <= 0 || g_aimbot_key_vk > 255) g_aimbot_key_vk = VK_XBUTTON1;
    bind_format_key(g_menu_key_vk, g_menu_key_name, sizeof(g_menu_key_name));
    bind_format_key(g_fly_key_vk,  g_fly_key_name,  sizeof(g_fly_key_name));
    aimbot_set_key(g_aimbot_key_vk);
    g_fly_toggle_on = false; g_fly_key_edge = false;
    g_fly_hover_valid = false;
    g_stream_proof_applied = WDA_NONE_VALUE;
    cfg_status(true, "Config '%s' foi carregada.", name);
    return true;
}

static bool cfg_delete(const char* name) {
    char why[128];
    if (!cfg_valid_name(name, why, sizeof(why))) { cfg_status(false, "%s", why); return false; }
    if (!g_cfg_pending_delete) {
        g_cfg_pending_delete = true;
        cfg_status(false, "Clique Excluir novamente para apagar '%s'.", name);
        return false;
    }
    char path[MAX_PATH];
    if (!cfg_make_path(name, path, sizeof(path))) { cfg_status(false, "Sem pasta."); return false; }
    bool ok = DeleteFileA(path) != FALSE;
    g_cfg_pending_delete = false;
    cfg_scan(true);
    cfg_status(ok, ok ? "Config '%s' foi deletada." : "Falha ao excluir: %s", name);
    return ok;
}

static char     g_notify_title[64]  = {};
static char     g_notify_text[160] = {};
static const char* g_notify_icon   = nullptr;
static bool     g_notify_ok        = true;
static uint32_t g_notify_tick      = 0;
static float    g_notify_anim      = 0.0f;
static std::unordered_map<ImGuiID, float> g_sub_h;
static char     g_troll_names[64][48] = {};
static int      g_troll_count      = 0;
static char     g_troll_selected_name[48] = {};
static char     g_troll_submenu_name[48]  = {};
static bool     g_troll_submenu_open      = false;
static uint32_t g_troll_submenu_ped       = 0;
static bool     g_spectate_active         = false;
static uint32_t g_spectate_ped            = 0;
static uint32_t g_spectate_last_apply     = 0;
static uint32_t g_fire_slot               = 0;
static uint32_t g_fire_ped                = 0;
static uint32_t g_fire_last_tick          = 0;
static uint32_t g_fire_diag               = 0;
static uint32_t g_fire_rearms             = 0;
static uint32_t g_spectate_ped_idx        = 0xFFFFFFFFu;
static uint32_t g_spectate_arms           = 0;
static uint32_t g_cam_off_state           = 1;
static uint32_t g_spectate_reapply_ms     = TROLL_SPECTATE_ARM_MS;
static std::unordered_map<ImGuiID, float> g_sub_anim;
static std::unordered_map<ImGuiID, float> g_slider_anim;
static std::unordered_map<ImGuiID, float> g_btn_anim;

static float ui_anim(const char* label, int seed, bool state, float lo, float hi, float speed) {
    static std::unordered_map<ImGuiID, float> values;
    ImGuiID id = ImHashStr(label, 0, (ImU32)seed);
    if (values.find(id) == values.end()) values[id] = lo;
    float& v = values[id];
    float step = speed * (1.0f - ImGui::GetIO().DeltaTime);
    if (step < 0.0f) step = 0.0f;
    if (step > 1.0f) step = 1.0f;
    v = ImLerp(v, state ? hi : lo, step);
    return v;
}

static ImU32 ui_color_lerp(ImU32 from, ImU32 to, float t) {
    if (t <= 0.0f) return from;
    if (t >= 1.0f) return to;
    return ImGui::GetColorU32(ImLerp(ImGui::ColorConvertU32ToFloat4(from),
                                     ImGui::ColorConvertU32ToFloat4(to), t));
}

static ImU32 ui_col_a(ImU32 col, float a) {
    ImVec4 v = ImGui::ColorConvertU32ToFloat4(col);
    v.w *= ImClamp(a, 0.0f, 1.0f);
    return ImGui::GetColorU32(v);
}

static const char* ui_combo_item(const char* items, int idx) {
    if (!items || idx < 0) return "";
    const char* p = items;
    for (int i = 0; i < idx; ++i) {
        while (*p) ++p;
        ++p;
        if (!*p) return "";
    }
    return p;
}

static void ui_tooltip(const char* text) {
    if (!text || !text[0]) return;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 8));
    ImGui::SetTooltip("%s", text);
    ImGui::PopStyleVar();
}

static void notify_push(const char* title, const char* icon, bool ok,
                        const char* fmt, ...) {
    snprintf(g_notify_title, sizeof(g_notify_title), "%s", title);
    g_notify_icon = icon;
    g_notify_ok = ok;
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(g_notify_text, sizeof(g_notify_text), _TRUNCATE, fmt, ap);
    va_end(ap);
    uint32_t t = GetTickCount();
    g_notify_tick = t ? t : 1;
    g_notify_anim = 0.0f;
}

static void draw_check_v(ImDrawList* dl, const ImRect& b, float t, float reveal = 1.0f);

static void notify_draw() {
    if (!g_notify_tick || InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    ImGuiIO& io = ImGui::GetIO();
    uint32_t age = GetTickCount() - g_notify_tick;
    float target = (age < 3200) ? 1.0f : 0.0f;
    g_notify_anim += (target - g_notify_anim) * ImMin(1.0f, 10.0f * io.DeltaTime);
    if (target == 0.0f && g_notify_anim < 0.003f) { g_notify_tick = 0; g_notify_anim = 0.0f; return; }
    float a = ImClamp(g_notify_anim, 0.0f, 1.0f);

    float reveal = ImClamp((float)age / 240.0f, 0.0f, 1.0f);
    const float h = 50.0f;

    float txt_w = ImMax(ImGui::CalcTextSize(g_notify_title).x,
                        ImGui::CalcTextSize(g_notify_text).x);
    float w = ImMax(280.0f, 64.0f + txt_w + 20.0f);
    ImVec2 pos(io.DisplaySize.x - (w + 18.0f), 30.0f - (1.0f - a) * 24.0f);
    ImGui::SetNextWindowPos(pos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(w, h), ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, a);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, ImGui::GetStyle().FrameRounding);
    ImGui::Begin("##notify", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBackground |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMouseInputs);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetWindowPos();
    ImVec2 p1(p0.x + w, p0.y + h);
    float rr = ImGui::GetStyle().FrameRounding;
    dl->AddRectFilled(p0, p1, ui_col_a(COL_FRAME_BG, a), rr);
    ImVec4 st = g_notify_ok ? SCHEME_V : WARN_V;
    st.w = a;
    dl->AddRectFilled(p0, ImVec2(p0.x + 50.0f, p1.y), ImGui::GetColorU32(st), rr,
                      ImDrawFlags_RoundCornersLeft);
    if (g_notify_ok) {
        ImRect mk(ImVec2(p0.x + 12.0f, p0.y + 12.0f), ImVec2(p0.x + 38.0f, p0.y + 38.0f));
        draw_check_v(dl, mk, a, reveal);
    } else {
        ImVec2 c(p0.x + 25.0f, p0.y + 25.0f);
        ImU32 wc = ui_col_a(IM_COL32(255, 255, 255, 255), a);
        dl->AddLine(ImVec2(c.x - 6.0f, c.y - 6.0f), ImVec2(c.x + 6.0f, c.y + 6.0f), wc, 2.0f);
        dl->AddLine(ImVec2(c.x + 6.0f, c.y - 6.0f), ImVec2(c.x - 6.0f, c.y + 6.0f), wc, 2.0f);
    }
    dl->AddText(ImVec2(p0.x + 64.0f, p0.y + 9.0f),
                ui_col_a(IM_COL32(255, 255, 255, 255), a), g_notify_title);
    dl->AddText(ImVec2(p0.x + 64.0f, p0.y + 28.0f), ui_col_a(COL_TEXT, a), g_notify_text);
    ImGui::End();
    ImGui::PopStyleVar(4);
}

static void draw_check_v(ImDrawList* dl, const ImRect& b, float t, float reveal) {
    float alpha = ImClamp(t, 0.0f, 1.0f);
    if (alpha <= 0.01f) return;
    const float th = ImMax(2.0f, b.GetHeight() * 0.115f);
    ImVec2 p1(b.Min.x + b.GetWidth() * 0.19f, b.Min.y + b.GetHeight() * 0.50f);
    ImVec2 p2(b.Min.x + b.GetWidth() * 0.40f, b.Min.y + b.GetHeight() * 0.79f);
    ImVec2 p3(b.Min.x + b.GetWidth() * 0.85f, b.Min.y + b.GetHeight() * 0.22f);
    ImU32 col = IM_COL32(250, 250, 252, (int)(alpha * 255));
    float rv = ImClamp(reveal, 0.0f, 1.0f);
    float r1 = ImClamp(rv / 0.38f, 0.0f, 1.0f);
    float r2 = ImClamp((rv - 0.34f) / 0.42f, 0.0f, 1.0f);

    dl->AddLine(p1, ImVec2(p1.x + (p2.x - p1.x) * r1, p1.y + (p2.y - p1.y) * r1), col, th);
    if (r2 > 0.0f)
        dl->AddLine(p2, ImVec2(p2.x + (p3.x - p2.x) * r2, p2.y + (p3.y - p2.y) * r2), col, th);

    if (r1 >= 0.995f) {
        dl->AddCircleFilled(p1, th * 0.5f, col);
        dl->AddCircleFilled(p2, th * 0.5f, col);
    }
    if (r2 >= 0.995f)
        dl->AddCircleFilled(p3, th * 0.5f, col);
}

static void draw_toggle(ImDrawList* dl, const ImRect& bb, float anim, bool hovered, bool held) {
    const float r = bb.GetHeight() * 0.5f;
    ImU32 track = ui_color_lerp(hovered ? COL_FRAME_ACTIVE : COL_TOGGLE_OFF, COL_SCHEME, anim);
    dl->AddRectFilled(bb.Min, bb.Max, track, r);
    if (held)
        dl->AddRect(bb.Min, bb.Max, ui_col_a(COL_SCHEME, 0.65f), r, 0, 1.0f);
    float kx = bb.Min.x + r + anim * (bb.GetWidth() - bb.GetHeight());
    ImVec2 cen(kx, bb.GetCenter().y);
    dl->AddCircleFilled(cen, r - 2.0f,
                        ui_color_lerp(COL_TOGGLE_KNOB, IM_COL32(255, 255, 255, 255), anim));
}

static bool accent_checkbox(const char* label, bool* v) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(v);
    ImGui::PushID(label);
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID("##cb");
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);
    const float box_size = 36.0f;
    const float box_h    = 18.0f;
    const float height = ImMax(box_h, label_size.y);
    const float total_w = box_size + (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f);
    ImVec2 pos = window->DC.CursorPos;
    ImRect total_bb(pos, ImVec2(pos.x + total_w, pos.y + height));
    ImGui::ItemSize(total_bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(total_bb, id)) { ImGui::PopID(); ImGui::PopID(); return false; }
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(total_bb, id, &hovered, &held);
    if (pressed) { *v = !*v; ImGui::MarkItemEdited(id); }
    float& anim = g_check_anim[id];
    anim += ((*v ? 1.0f : 0.0f) - anim) * ImMin(1.0f, 14.0f * g.IO.DeltaTime);
    if (anim < 0.001f) anim = 0.0f;
    if (anim > 0.999f) anim = 1.0f;
    ImRect box_bb(ImVec2(pos.x, pos.y + (height - box_h) * 0.5f),
                  ImVec2(pos.x + box_size, pos.y + (height + box_h) * 0.5f));
    draw_toggle(window->DrawList, box_bb, anim, hovered, held);
    if (label_size.x > 0.0f)
        ImGui::RenderText(ImVec2(box_bb.Max.x + style.ItemInnerSpacing.x,
                                 pos.y + (height - label_size.y) * 0.5f), label);
    ImGui::PopID();
    ImGui::PopID();
    return pressed;
}

static int ui_hex_parse(const char* s, unsigned* out, int n) {
    int k = 0;
    unsigned cur = 0;
    int digits = 0;
    for (const char* p = s; *p && k < n; ++p) {
        unsigned d;
        char c = *p;
        if (c >= '0' && c <= '9')      d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
        else continue;
        cur = cur * 16u + d;
        if (++digits == 2) { out[k++] = cur; cur = 0; digits = 0; }
    }
    return k;
}

static void ui_color_picker(float* col, int comps, float w) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    const ImGuiStyle& style = ImGui::GetStyle();
    ImGuiIO& io = ImGui::GetIO();
    ImDrawList* dl = window->DrawList;
    const float alpha8 = style.Alpha;
    bool changed = false;

    float h = 0.0f, s = 0.0f, v = 0.0f;
    ImGui::ColorConvertRGBtoHSV(col[0], col[1], col[2], h, s, v);
    h = ImClamp(h, 0.0f, 1.0f);
    s = ImClamp(s, 0.0f, 1.0f);
    v = ImClamp(v, 0.0f, 1.0f);

    ImVec4 hue_v(1.0f, 1.0f, 1.0f, alpha8);
    ImGui::ColorConvertHSVtoRGB(h, 1.0f, 1.0f, hue_v.x, hue_v.y, hue_v.z);
    ImU32 hue32 = ImGui::GetColorU32(hue_v);
    ImU32 white = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, alpha8));
    ImU32 black = ImGui::GetColorU32(ImVec4(0.0f, 0.0f, 0.0f, alpha8));

    ImVec2 sp = window->DC.CursorPos;
    float sq_h = ImMax(20.0f, w * 0.5f);
    ImRect sq(sp, ImVec2(sp.x + w, sp.y + sq_h));
    dl->AddRectFilledMultiColor(sq.Min, sq.Max, white, hue32, hue32, white);
    dl->AddRectFilledMultiColor(sq.Min, sq.Max, 0, 0, black, black);
    ImVec2 cur(ImClamp(IM_ROUND(sq.Min.x + ImSaturate(s) * sq.GetWidth()), sq.Min.x + 2.0f, sq.Max.x - 2.0f),
               ImClamp(IM_ROUND(sq.Min.y + ImSaturate(1.0f - v) * sq.GetHeight()), sq.Min.y + 2.0f, sq.Max.y - 2.0f));
    dl->AddCircleFilled(cur, 4.5f, ImGui::GetColorU32(ImVec4(col[0], col[1], col[2], 1.0f)));
    dl->AddCircle(cur, 4.5f, white, 0, 1.6f);
    dl->AddCircle(cur, 5.9f, ImGui::GetColorU32(ImVec4(0.0f, 0.0f, 0.0f, 0.5f * alpha8)), 0, 1.0f);
    ImGui::InvisibleButton("##sv", sq.GetSize());
    if (ImGui::IsItemActive()) {
        s = ImSaturate((io.MousePos.x - sq.Min.x) / ImMax(1.0f, sq.GetWidth() - 1.0f));
        v = 1.0f - ImSaturate((io.MousePos.y - sq.Min.y) / ImMax(1.0f, sq.GetHeight() - 1.0f));
        if (s <= 0.0f) s = 0.01f;
        if (v <= 0.0f) v = 0.01f;
        changed = true;
    }
    ImGui::Dummy(ImVec2(0, 4));

    const ImU32 hues[7] = {
        IM_COL32(255, 0, 0, 255), IM_COL32(255, 255, 0, 255), IM_COL32(0, 255, 0, 255),
        IM_COL32(0, 255, 255, 255), IM_COL32(0, 0, 255, 255), IM_COL32(255, 0, 255, 255),
        IM_COL32(255, 0, 0, 255)
    };
    ImVec2 hp = window->DC.CursorPos;
    ImRect hb(hp, ImVec2(hp.x + w, hp.y + 8.0f));
    for (int i = 0; i < 6; ++i)
        dl->AddRectFilledMultiColor(ImVec2(hb.Min.x + (float)i * (w / 6.0f), hb.Min.y),
                                    ImVec2(hb.Min.x + (float)(i + 1) * (w / 6.0f), hb.Max.y),
                                    ui_col_a(hues[i], alpha8), ui_col_a(hues[i + 1], alpha8),
                                    ui_col_a(hues[i + 1], alpha8), ui_col_a(hues[i], alpha8));
    dl->AddCircleFilled(ImVec2(hb.Min.x + 4.0f, hb.GetCenter().y), 4.0f, ui_col_a(hues[0], alpha8));
    dl->AddCircleFilled(ImVec2(hb.Max.x - 4.0f, hb.GetCenter().y), 4.0f, ui_col_a(hues[6], alpha8));
    float hmx = hb.Min.x + 4.0f + (w - 8.0f) * ImSaturate(h);
    dl->AddRectFilled(ImVec2(hmx - 3.0f, hb.Min.y - 3.0f), ImVec2(hmx + 3.0f, hb.Max.y + 3.0f),
                      white, 2.0f);
    dl->AddRectFilled(ImVec2(hmx - 1.5f, hb.Min.y - 1.5f), ImVec2(hmx + 1.5f, hb.Max.y + 1.5f),
                      hue32, 1.0f);
    ImGui::InvisibleButton("##hue", ImVec2(w, 14.0f));
    if (ImGui::IsItemActive()) {
        h = ImSaturate((io.MousePos.x - hb.Min.x) / ImMax(1.0f, hb.GetWidth()));
        changed = true;
    }

    if (comps >= 4) {
        ImGui::Dummy(ImVec2(0, 4));
        ImVec2 ap = window->DC.CursorPos;
        ImRect ab(ap, ImVec2(ap.x + w, ap.y + 8.0f));
        const float cs = 4.0f;
        const ImU32 c1 = IM_COL32(64, 64, 64, 255);
        const ImU32 c2 = IM_COL32(38, 38, 38, 255);
        int ky = 0;
        for (float yy = ab.Min.y; yy < ab.Max.y; yy += cs, ++ky) {
            int kx = 0;
            for (float xx = ab.Min.x; xx < ab.Max.x; xx += cs, ++kx)
                dl->AddRectFilled(ImVec2(xx, yy),
                                  ImVec2(ImMin(xx + cs, ab.Max.x), ImMin(yy + cs, ab.Max.y)),
                                  ((kx + ky) & 1) ? c2 : c1);
        }
        ImColor l0(col[0], col[1], col[2], 0.0f);
        ImColor l1(col[0], col[1], col[2], alpha8);
        dl->AddRectFilledMultiColor(ab.Min, ab.Max, l0, l1, l1, l0);
        ImU32 am_col = ui_color_lerp(white, ImGui::GetColorU32(ImVec4(col[0], col[1], col[2], 1.0f)),
                                     ImClamp(col[3], 0.0f, 1.0f));
        float amx = ab.Min.x + 4.0f + (w - 8.0f) * ImClamp(col[3], 0.0f, 1.0f);
        dl->AddRectFilled(ImVec2(amx - 3.0f, ab.Min.y - 3.0f), ImVec2(amx + 3.0f, ab.Max.y + 3.0f),
                          white, 2.0f);
        dl->AddRectFilled(ImVec2(amx - 1.5f, ab.Min.y - 1.5f), ImVec2(amx + 1.5f, ab.Max.y + 1.5f),
                          am_col, 1.0f);
        ImGui::InvisibleButton("##alpha", ImVec2(w, 14.0f));
        if (ImGui::IsItemActive()) {
            col[3] = ImSaturate((io.MousePos.x - ab.Min.x) / ImMax(1.0f, ab.GetWidth()));
            changed = true;
        }
    }

    if (changed) {
        ImGui::ColorConvertHSVtoRGB(h, s, v, col[0], col[1], col[2]);
        ImGui::MarkItemEdited(window->GetID("##picker"));
    }
}

static bool color_swatch(const char* str_id, const float* col, int comps, bool selected) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    const ImGuiStyle& style = ImGui::GetStyle();
    ImVec2 pos = window->DC.CursorPos;
    float hh = ImMax(20.0f, ImGui::GetTextLineHeight());
    const ImGuiID sid = window->GetID(str_id);
    bool pressed = ImGui::InvisibleButton(str_id, ImVec2(20.0f, hh));
    bool hovered = ImGui::IsItemHovered();
    float& anim = g_check_anim[sid];
    anim += (((selected || hovered) ? 1.0f : 0.0f) - anim) * ImMin(1.0f, 14.0f * ImGui::GetIO().DeltaTime);
    if (anim < 0.001f) anim = 0.0f;
    if (anim > 0.999f) anim = 1.0f;
    int a = (comps >= 4) ? (int)(ImClamp(col[3], 0.0f, 1.0f) * 255.0f) : 255;
    ImU32 c = IM_COL32((int)(ImClamp(col[0], 0.0f, 1.0f) * 255.0f),
                       (int)(ImClamp(col[1], 0.0f, 1.0f) * 255.0f),
                       (int)(ImClamp(col[2], 0.0f, 1.0f) * 255.0f),
                       (int)((float)a * style.Alpha));
    ImVec2 cen(pos.x + 10.0f, pos.y + hh * 0.5f);
    window->DrawList->AddCircleFilled(cen, 8.0f, c);
    window->DrawList->AddCircle(cen, 9.5f,
                                ui_col_a(IM_COL32(255, 255, 255, 255), anim), 0, 1.5f);
    return pressed;
}

static bool accent_checkbox_color(const char* label, bool* v, float* col, int comps, const char* popup_id) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(label);
    ImGui::PushID(popup_id);
    const ImGuiStyle& style = ImGui::GetStyle();
    const ImGuiID id = window->GetID("##cbc");
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);
    const float swatch_size = 20.0f;
    const float box_size    = 36.0f;
    const float box_h       = 18.0f;
    const float gap_sw      = 8.0f;
    const float gap_cb      = 8.0f;
    const float height = ImMax(ImMax(swatch_size, box_h), label_size.y);
    const float total_w = swatch_size + gap_sw + box_size +
                          (label_size.x > 0.0f ? gap_cb + label_size.x : 0.0f);
    ImVec2 pos = window->DC.CursorPos;
    ImRect total_bb(pos, ImVec2(pos.x + total_w, pos.y + height));
    ImGui::ItemSize(total_bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(total_bb, id)) { ImGui::PopID(); ImGui::PopID(); return false; }

    ImGui::SetCursorScreenPos(pos);
    if (color_swatch("##swatch", col, comps, *v)) ImGui::OpenPopup("##picker_popup");
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 16));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10, 8));
    if (ImGui::BeginPopup("##picker_popup")) {
        ui_color_picker(col, comps, 228.0f);
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(2);

    ImVec2 cb_pos(pos.x + swatch_size + gap_sw, pos.y + (height - box_h) * 0.5f);
    ImRect cb_bb(cb_pos, ImVec2(cb_pos.x + box_size, cb_pos.y + box_h));
    ImGui::SetCursorScreenPos(cb_pos);
    bool cb_clicked = ImGui::InvisibleButton("##chkbox", ImVec2(box_size, box_size));
    bool cb_hovered = ImGui::IsItemHovered();
    bool cb_held    = ImGui::IsItemActive();
    if (cb_clicked) { *v = !*v; ImGui::MarkItemEdited(id); }
    float& anim = g_check_anim[id];
    anim += ((*v ? 1.0f : 0.0f) - anim) * ImMin(1.0f, 14.0f * ImGui::GetIO().DeltaTime);
    if (anim < 0.001f) anim = 0.0f;
    if (anim > 0.999f) anim = 1.0f;
    draw_toggle(window->DrawList, cb_bb, anim, cb_hovered, cb_held);
    if (label_size.x > 0.0f)
        ImGui::RenderText(ImVec2(cb_bb.Max.x + gap_cb, pos.y + (height - label_size.y) * 0.5f), label);
    ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y + height));
    ImGui::Dummy(ImVec2(0, 0));
    ImGui::PopID();
    ImGui::PopID();
    return cb_clicked;
}

static bool smooth_slider(const char* label, float* v, float lo, float hi,
                          const char* fmt, const char* lo_tag = nullptr,
                          const char* hi_tag = nullptr) {
    *v = ImClamp(*v, lo, hi);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(label);
    const ImGuiID id = window->GetID("##s");
    const ImGuiID track_id = window->GetID("##track");
    ImGuiIO& io = ImGui::GetIO();
    const ImGuiStyle& style = ImGui::GetStyle();
    float avail = ImGui::GetContentRegionAvail().x;
    float label_w = ImGui::CalcTextSize(label).x;
    char valbuf[32] = {};
    snprintf(valbuf, sizeof(valbuf), fmt, *v);
    float val_w = ImGui::CalcTextSize(valbuf).x;
    float track_w = avail - label_w - val_w - 30.0f;
    if (track_w < 40.0f) track_w = 40.0f;
    float h = ImMax(20.0f, ImGui::GetFrameHeight() - 10.0f);
    ImVec2 pos = window->DC.CursorPos;
    float tx = pos.x + label_w + 10.0f;
    ImGui::SetCursorScreenPos(ImVec2(tx, pos.y));
    ImGui::InvisibleButton("##track", ImVec2(track_w, h));
    bool hovered = ImGui::IsItemHovered();
    bool active  = ImGui::IsItemActive();
    bool changed = false;
    if (active) {
        float f = (io.MousePos.x - tx) / track_w;
        f = ImClamp(f, 0.0f, 1.0f);
        float nv = lo + f * (hi - lo);
        if (fabsf(nv - *v) > 0.0001f) { *v = nv; changed = true; ImGui::MarkItemEdited(track_id); }
    }
    float frac = ImClamp((*v - lo) / ImMax(0.0001f, hi - lo), 0.0f, 1.0f);
    float& sm = g_slider_anim[id];
    sm += (frac - sm) * ImMin(1.0f, 13.0f * io.DeltaTime);
    ImDrawList* dl = window->DrawList;
    float cy = pos.y + h * 0.5f;
    float bar_h = 4.0f;
    dl->AddRectFilled(ImVec2(tx, cy - bar_h * 0.5f), ImVec2(tx + track_w, cy + bar_h * 0.5f),
                      hovered ? COL_FRAME_HOVER : COL_FRAME_BG, style.FrameRounding);
    dl->AddRectFilled(ImVec2(tx, cy - bar_h * 0.5f), ImVec2(tx + track_w * sm, cy + bar_h * 0.5f),
                      COL_SCHEME, style.FrameRounding);
    float gx = tx + track_w * sm;
    float gr = (hovered || active) ? 6.5f : 5.0f;
    dl->AddCircleFilled(ImVec2(gx, cy), gr, ImGui::GetColorU32(ImGuiCol_SliderGrab));
    dl->AddCircle(ImVec2(gx, cy), gr, ui_col_a(COL_SCHEME, 0.9f), 0, 1.0f);
    float ty = pos.y + (h - ImGui::GetTextLineHeight()) * 0.5f;
    ImGui::RenderText(ImVec2(pos.x, ty), label);
    ImGui::RenderText(ImVec2(tx + track_w + 8.0f, ty), valbuf);
    float advance = h + 4.0f;
    if (lo_tag || hi_tag) {
        ImU32 dim = ImGui::GetColorU32(ImGuiCol_TextDisabled);
        if (lo_tag) dl->AddText(ImVec2(tx, pos.y + h + 1.0f), dim, lo_tag);
        if (hi_tag) {
            float tw = ImGui::CalcTextSize(hi_tag).x;
            dl->AddText(ImVec2(tx + track_w - tw, pos.y + h + 1.0f), dim, hi_tag);
        }
        advance = h + 16.0f;
    }
    ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y + advance));
    ImGui::Dummy(ImVec2(0.0f, 0.0f));
    ImGui::PopID();
    return changed;
}

static bool ui_combo(const char* label, int* cur, const char* items, int count, float width = 0.0f) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    if (count < 1) count = 1;
    if (*cur < 0) *cur = 0;
    if (*cur >= count) *cur = count - 1;
    ImGui::PushID(label);
    const ImGuiID id = window->GetID("##combo");
    const ImGuiStyle& style = ImGui::GetStyle();
    float avail = (width > 0.0f) ? width : ImGui::GetContentRegionAvail().x;
    float h = ImMax(20.0f, ImGui::GetFrameHeight() - 10.0f);
    ImVec2 pos = window->DC.CursorPos;
    ImRect bb(pos, ImVec2(pos.x + avail, pos.y + h));
    ImGui::ItemSize(bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, id)) { ImGui::PopID(); return false; }
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);
    if (pressed) ImGui::OpenPopup("##popup");
    ImDrawList* dl = window->DrawList;
    ImU32 bg = held ? COL_FRAME_ACTIVE : (hovered ? COL_FRAME_HOVER : COL_FRAME_BG);
    dl->AddRectFilled(bb.Min, bb.Max, bg, style.FrameRounding);
    float ty = bb.GetCenter().y - ImGui::GetTextLineHeight() * 0.5f;
    dl->AddText(ImVec2(bb.Min.x + 10.0f, ty), ImGui::GetColorU32(ImGuiCol_Text), label);
    const char* cur_item = ui_combo_item(items, *cur);
    ImVec2 vs = ImGui::CalcTextSize(cur_item);
    float ax = bb.Max.x - 12.0f;
    dl->AddText(ImVec2(ax - 10.0f - vs.x, bb.GetCenter().y - vs.y * 0.5f),
                ImGui::GetColorU32(ImGuiCol_TextDisabled), cur_item);
    ImVec2 c(ax - 3.0f, bb.GetCenter().y - 1.0f);
    dl->AddTriangleFilled(ImVec2(c.x - 3.5f, c.y - 2.0f), ImVec2(c.x + 3.5f, c.y - 2.0f),
                          ImVec2(c.x, c.y + 3.0f), ImGui::GetColorU32(ImGuiCol_TextDisabled));
    bool changed = false;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 8));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 4));
    if (ImGui::BeginPopup("##popup")) {
        for (int i = 0; i < count; ++i) {
            const char* it = ui_combo_item(items, i);
            if (ImGui::Selectable(it, i == *cur, ImGuiSelectableFlags_None,
                                  ImVec2(ImMax(60.0f, avail - 16.0f), 22.0f))) {
                *cur = i;
                changed = true;
                ImGui::MarkItemEdited(id);
            }
        }
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(2);
    ImGui::PopID();
    return changed;
}

static bool ui_button(const char* label, float w, float h, bool primary) {
    w = ImMax(1.0f, w);
    h = ImMax(1.0f, h);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(label);
    const ImGuiStyle& style = ImGui::GetStyle();
    const ImGuiID id = window->GetID("##b");
    ImVec2 pos = window->DC.CursorPos;
    ImRect bb(pos, ImVec2(pos.x + w, pos.y + h));
    ImGui::ItemSize(bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, id)) { ImGui::PopID(); return false; }
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);
    float& anim = g_btn_anim[id];
    anim += ((hovered ? 1.0f : 0.0f) - anim) * ImMin(1.0f, 14.0f * ImGui::GetIO().DeltaTime);
    ImDrawList* dl = window->DrawList;
    ImU32 bg;
    bg = held ? IM_COL32(255, 255, 255, 26) : (hovered ? IM_COL32(255, 255, 255, 14) : IM_COL32(0, 0, 0, 255));
    dl->AddRectFilled(bb.Min, bb.Max, bg, style.FrameRounding);
    dl->AddRect(bb.Min, bb.Max, hovered ? COL_BTN_STROKE_HI : COL_BTN_STROKE, style.FrameRounding, 0, 1.0f);
    ImVec2 ts = ImGui::CalcTextSize(label);
    dl->AddText(ImVec2(bb.Min.x + (w - ts.x) * 0.5f, bb.Min.y + (h - ts.y) * 0.5f),
                primary ? IM_COL32(255, 255, 255, 255) : ImGui::GetColorU32(ImGuiCol_Text), label);
    ImGui::PopID();
    return pressed;
}

static void num_pt(char* out, size_t n, float v, int dec) {
    char tmp[40];
    if (dec <= 0)      snprintf(tmp, sizeof(tmp), "%.0f",  (double)v);
    else if (dec == 1) snprintf(tmp, sizeof(tmp), "%.1f",  (double)v);
    else               snprintf(tmp, sizeof(tmp), "%.2f",  (double)v);
    for (char* c = tmp; *c; ++c) if (*c == '.') *c = ',';
    snprintf(out, n, "%s", tmp);
}

static bool ui_button_ghost(const char* label, const char* icon,
                             float w, float h, bool active) {
    w = ImMax(1.0f, w);
    h = ImMax(1.0f, h);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(label);
    const ImGuiStyle& style = ImGui::GetStyle();
    const ImGuiID id = window->GetID("##gb");
    ImVec2 pos = window->DC.CursorPos;
    ImRect bb(pos, ImVec2(pos.x + w, pos.y + h));
    ImGui::ItemSize(bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, id)) { ImGui::PopID(); return false; }
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);
    float& anim = g_btn_anim[id];
    anim += ((hovered ? 1.0f : 0.0f) - anim) * ImMin(1.0f, 14.0f * ImGui::GetIO().DeltaTime);
    ImDrawList* dl = window->DrawList;

    ImU32 fill;
    fill = held ? IM_COL32(255, 255, 255, 26) : (active ? IM_COL32(255, 255, 255, 16) : IM_COL32(0, 0, 0, 255));
    dl->AddRectFilled(bb.Min, bb.Max, fill, style.FrameRounding);
    dl->AddRect(bb.Min, bb.Max, (active || hovered) ? COL_BTN_STROKE_HI : COL_BTN_STROKE,
                style.FrameRounding, 0, 1.0f);

    ImFont* fnt  = (icon && icon[0] && g_font_icons) ? g_font_icons : nullptr;
    const float fs = g_icon_font_size * 0.60f;
    ImVec2 isz = fnt ? fnt->CalcTextSizeA(fs, FLT_MAX, 0.0f, icon) : ImVec2(0.0f, 0.0f);
    ImVec2 ts = ImGui::CalcTextSize(label);
    float tw = ts.x + (isz.x > 0.0f ? isz.x + 6.0f : 0.0f);
    float tx = bb.Min.x + ImMax(6.0f, (w - tw) * 0.5f);
    float ty = bb.Min.y + (h - ts.y) * 0.5f;
    if (isz.x > 0.0f) {
        dl->AddText(fnt, fs, ImVec2(tx, bb.Min.y + (h - isz.y) * 0.5f),
                    active ? IM_COL32(255, 255, 255, 255) : COL_SCHEME, icon);
        tx += isz.x + 6.0f;
    }
    dl->AddText(ImVec2(tx, ty), active ? IM_COL32(255, 255, 255, 255) : COL_ACCENT_SOFT, label);
    ImGui::PopID();
    return pressed;
}

static bool ui_info_row(const char* icon, const char* text, float w, float h, bool* hovered_out) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    const ImGuiStyle& style = ImGui::GetStyle();
    const ImGuiID id = window->GetID(text);
    ImVec2 pos = window->DC.CursorPos;
    ImRect bb(pos, ImVec2(pos.x + ImMax(1.0f, w), pos.y + h));
    ImGui::ItemSize(bb, 0.0f);
    if (!ImGui::ItemAdd(bb, id)) return false;
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);
    if (hovered_out) *hovered_out = hovered;
    ImDrawList* dl = window->DrawList;
    dl->AddRectFilled(bb.Min, bb.Max,
                      hovered ? IM_COL32(255, 255, 255, 14) : IM_COL32(0, 0, 0, 255),
                      style.FrameRounding);
    dl->AddRect(bb.Min, bb.Max, hovered ? COL_BTN_STROKE_HI : COL_BTN_STROKE,
                style.FrameRounding, 0, 1.0f);
    float x = bb.Min.x + 9.0f;
    ImFont* fnt = (icon && icon[0] && g_font_icons) ? g_font_icons : nullptr;
    if (fnt) {
        const float fs = g_icon_font_size * 0.55f;
        ImVec2 isz = fnt->CalcTextSizeA(fs, FLT_MAX, 0.0f, icon);
        dl->AddText(fnt, fs, ImVec2(x, bb.Min.y + (h - isz.y) * 0.5f), COL_SCHEME, icon);
        x += isz.x + 7.0f;
    }
    ImVec2 ts = ImGui::CalcTextSize(text);
    dl->AddText(ImVec2(x, bb.Min.y + (h - ts.y) * 0.5f), COL_TEXT, text);
    return pressed;
}

struct SubCardState { ImVec2 pos; float w; float h; };
typedef void (*SubCardFn)(void*);

static void draw_sub_card(const char* id, bool open, float full_h,
                          SubCardFn fn, void* ctx, float parent_x) {
    (void)full_h;
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return;
    ImGui::PushID(id);
    const ImGuiID aid = window->GetID("##anim");
    float& a = g_sub_anim[aid];
    float target = open ? 1.0f : 0.0f;
    a += (target - a) * ImMin(1.0f, 11.0f * ImGui::GetIO().DeltaTime);
    if (target == 1.0f && a > 0.998f) a = 1.0f;
    if (target == 0.0f && a < 0.002f) a = 0.0f;
    if (a < 0.02f) { ImGui::PopID(); return; }
    float indent = ImMax(0.0f, parent_x);
    ImVec2 pos = window->DC.CursorPos;
    float bar_x = pos.x + indent;
    float prev_h = g_sub_h[aid];
    if (prev_h > 2.0f)
        window->DrawList->AddRectFilled(ImVec2(bar_x - 12.0f, pos.y - 2.0f),
                                        ImVec2(bar_x - 10.0f, pos.y - 2.0f + prev_h),
                                        ui_col_a(COL_SCHEME, 0.85f * a), 1.0f);
    ImGui::SetCursorScreenPos(ImVec2(bar_x, pos.y));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(14, 10));
    ImGui::BeginGroup();
    if (fn) fn(ctx);
    ImGui::EndGroup();
    ImGui::PopStyleVar();
    ImVec2 gmax = ImGui::GetItemRectMax();
    g_sub_h[aid] = ImMax(0.0f, gmax.y - pos.y + 4.0f);
    ImGui::SetCursorScreenPos(ImVec2(pos.x, gmax.y + 2.0f));
    ImGui::Dummy(ImVec2(0.0f, 0.0f));
    ImGui::PopID();
}

struct SubFilledCtx { bool* filled; float* col; bool* corner; bool* rounded; };
struct SubDynCtx    { bool* dyn; };

static void ui_tooltip(const char* text);

static void sub_filled_fn(void* p) {
    SubFilledCtx* c = (SubFilledCtx*)p;
    bool was = *c->filled;
    if (accent_checkbox("Filled", c->filled) && *c->filled && !was) {
        c->col[0] = 0.0f; c->col[1] = 0.0f; c->col[2] = 0.0f; c->col[3] = 0.30f;
    }
    if (accent_checkbox("Corner Box", c->corner) && *c->corner)
        *c->rounded = false;
    if (ImGui::IsItemHovered())
        ui_tooltip("Quinas apenas. Exclusivo com Rounded Box.");
    if (accent_checkbox("Rounded Box", c->rounded) && *c->rounded)
        *c->corner = false;
    if (ImGui::IsItemHovered())
        ui_tooltip("Caixa arredondada. Exclusiva com Corner Box.");
}

static void sub_dyn_fn(void* p) {
    accent_checkbox("Dynamic Health", ((SubDynCtx*)p)->dyn);
}

#define CARD_SIDE_SHRINK 30.0f
#define CARD_BOTTOM_GAP  50.0f

static void card_begin(const char* id, const char* title, float w, const char* icon = nullptr, float shrink = CARD_SIDE_SHRINK) {
    char oid[96] = {};
    char iid[96] = {};
    snprintf(oid, sizeof(oid), "%s_main", id);
    snprintf(iid, sizeof(iid), "%s_body", id);
    float cw = (w > 0.0f)
        ? w
        : ImMax(60.0f, ImGui::GetWindowWidth() * 0.5f - ImGui::GetStyle().ItemSpacing.x * 0.5f - 20.0f);

    cw = ImMax(60.0f, cw - shrink);
    ImGui::BeginChild(oid, ImVec2(cw, -CARD_BOTTOM_GAP), false);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 ws = ImGui::GetWindowSize();
    const float hdr = 44.0f;
    float tx = wp.x + 24.0f;
    if (icon && icon[0] && g_font_icons) {
        const float fs = g_icon_font_size * 0.7f;
        ImVec2 isz = g_font_icons->CalcTextSizeA(fs, FLT_MAX, 0.0f, icon);
        dl->AddText(g_font_icons, fs, ImVec2(tx, wp.y + hdr * 0.5f - isz.y * 0.5f),
                    COL_SCHEME, icon);
        tx += isz.x + 10.0f;
    }
    ImVec2 ts = ImGui::CalcTextSize(title, nullptr, true);
    dl->AddText(ImVec2(tx, wp.y + hdr * 0.5f - ts.y * 0.5f),
                ImGui::GetColorU32(ImGuiCol_Text), title, ImGui::FindRenderedTextEnd(title));
    dl->AddRectFilled(ImVec2(wp.x, wp.y + hdr - 1.0f), ImVec2(wp.x + ws.x, wp.y + hdr),
                      ImGui::GetColorU32(ImGuiCol_Border));

    dl->AddRect(wp, ImVec2(wp.x + ws.x, wp.y + ws.y), COL_CARD_STROKE,
                ImGui::GetStyle().ChildRounding, 0, 1.0f);
    ImGui::SetCursorPos(ImVec2(24.0f, hdr + 24.0f));
    ImGui::BeginChild(iid, ImVec2(-24.0f, -24.0f), false, ImGuiWindowFlags_NoBackground);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(18, 14));
}

static void card_end() {
    ImGui::PopStyleVar();
    ImGui::EndChild();
    ImGui::EndChild();
}

static void draw_esp_card(const char* card_id, const char* title, float card_w,
                          bool* enable,
                          bool* box,   float col_box[4],   const char* pop_box,
                          bool* box_filled,
                          bool* box_corner,
                          bool* box_rounded,
                          bool* lines, float col_lines[3], const char* pop_lines,
                          bool* names, float col_names[3], const char* pop_names,
                          bool* health,float col_health[3],const char* pop_health,
                          bool* health_dynamic,
                          bool* armor, float col_armor[3], const char* pop_armor,
                          bool* skel,  float col_skel[3],  const char* pop_skel,
                          bool* distance, float col_distance[3],
                          const char* pop_distance) {
    card_begin(card_id, title, card_w, CARD_ICON_EYE);
    accent_checkbox("Enable", enable);
    if (*enable) {
        accent_checkbox_color("Show Box", box, col_box, 4, pop_box);
        SubFilledCtx fc = { box_filled, col_box, box_corner, box_rounded };
        draw_sub_card("##sub_filled", *box, 74.0f, sub_filled_fn, &fc, 30.0f);
        accent_checkbox_color("Show Lines",    lines, col_lines, 3, pop_lines);
        accent_checkbox_color("Show Names",    names, col_names, 3, pop_names);
        accent_checkbox_color("Show Distance", distance, col_distance, 3, pop_distance);
        accent_checkbox_color("Show Health",   health, col_health, 3, pop_health);
        SubDynCtx dc = { health_dynamic };
        draw_sub_card("##sub_dyn", *health, 34.0f, sub_dyn_fn, &dc, 30.0f);
        accent_checkbox_color("Show Armor",    armor, col_armor, 3, pop_armor);
        accent_checkbox_color("Show Skeleton", skel,  col_skel,  3, pop_skel);
    }
    card_end();
}

static void draw_visuals_page() {
    float avail_w = ImGui::GetContentRegionAvail().x;
    float gap     = 20.0f;
    float col_w   = ImMax(1.0f, (avail_w - gap) * 0.5f);
    draw_esp_card("##esp_local_card", "ESP LOCAL", col_w,
        &g_esp_local_enable,
        &g_esp_local_box,    g_col_local_box,    "##cp_l_box",
        &g_esp_local_box_filled,
        &g_esp_local_box_corner,
        &g_esp_local_box_rounded,
        &g_esp_local_lines,  g_col_local_lines,  "##cp_l_lines",
        &g_esp_local_names,  g_col_local_names,  "##cp_l_names",
        &g_esp_local_health, g_col_local_health, "##cp_l_health",
        &g_esp_local_health_dynamic,
        &g_esp_local_armor,  g_col_local_armor,  "##cp_l_armor",
        &g_esp_local_skeleton,g_col_local_skeleton,"##cp_l_skel",
        &g_esp_local_distance, g_col_local_distance, "##cp_l_dist");
    ImGui::SameLine(0.0f, gap);
    draw_esp_card("##esp_players_card", "ESP PLAYERS", col_w,
        &g_esp_players_enable,
        &g_esp_players_box,    g_col_players_box,    "##cp_p_box",
        &g_esp_players_box_filled,
        &g_esp_players_box_corner,
        &g_esp_players_box_rounded,
        &g_esp_players_lines,  g_col_players_lines,  "##cp_p_lines",
        &g_esp_players_names,  g_col_players_names,  "##cp_p_names",
        &g_esp_players_health, g_col_players_health, "##cp_p_health",
        &g_esp_players_health_dynamic,
        &g_esp_players_armor,  g_col_players_armor,  "##cp_p_armor",
        &g_esp_players_skeleton,g_col_players_skeleton,"##cp_p_skel",
        &g_esp_players_distance, g_col_players_distance, "##cp_p_dist");
}

static void draw_placeholder_page(const char* title) { (void)title; }

static float aimbot_icon_w() {
    if (!g_font_icons) return 0.0f;
    ImVec2 s = g_font_icons->CalcTextSizeA(g_icon_font_size * 0.8f, FLT_MAX,
                                           0.0f, AIMBOT_ICON_KEYBOARD);
    return s.x;
}

static bool keybind_button(const char* id, float width, const char* text,
                           bool capturing, bool active) {
    width = ImMax(1.0f, width);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(id);
    const ImGuiID bid = window->GetID("##btn");
    const ImGuiStyle& style = ImGui::GetStyle();
    const float   h   = ImMax(20.0f, ImGui::GetFrameHeight() - 10.0f);
    const ImVec2  pos = window->DC.CursorPos;
    const ImRect  bb(pos, ImVec2(pos.x + width, pos.y + h));
    ImGui::ItemSize(bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, bid)) { ImGui::PopID(); return false; }
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(bb, bid, &hovered, &held);
    ImU32 bg = (capturing || active) ? IM_COL32(255, 255, 255, 26) : (hovered ? IM_COL32(255, 255, 255, 14) : IM_COL32(0, 0, 0, 255));
    ImDrawList* dl = window->DrawList;
    dl->AddRectFilled(bb.Min, bb.Max, bg, style.FrameRounding);
    dl->AddRect(bb.Min, bb.Max, (capturing || active) ? COL_BTN_STROKE_HI : COL_BTN_STROKE, style.FrameRounding, 0, 1.0f);
    const ImVec2 tsz = ImGui::CalcTextSize(text);
    const float  iw  = aimbot_icon_w();
    const float  gap = (iw > 0.0f) ? 6.0f : 0.0f;
    const float  total = iw + gap + tsz.x;
    float x0 = bb.Min.x + (width - total) * 0.5f;
    if (x0 < bb.Min.x + 6.0f) x0 = bb.Min.x + 6.0f;
    const ImU32 col = (capturing || active) ? IM_COL32(255, 255, 255, 255)
                                            : ImGui::GetColorU32(ImGuiCol_Text);
    if (g_font_icons) {
        const float fs = g_icon_font_size * 0.65f;
        ImVec2 isz = g_font_icons->CalcTextSizeA(fs, FLT_MAX, 0.0f, AIMBOT_ICON_KEYBOARD);
        dl->AddText(g_font_icons, fs,
            ImVec2(x0, bb.Min.y + (h - isz.y) * 0.5f), col, AIMBOT_ICON_KEYBOARD);
    }
    dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
        ImVec2(x0 + iw + gap, bb.Min.y + (h - tsz.y) * 0.5f), col, text);
    ImGui::PopID();
    return pressed;
}

static bool keybind_row(const char* label, const char* id, const char* key_name,
                        bool capturing, bool active) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    float avail = ImGui::GetContentRegionAvail().x;
    float label_w = ImGui::CalcTextSize(label).x;
    float pill_w = ImMax(80.0f, ImMin(avail * 0.5f, avail - label_w - 20.0f));
    float h = ImMax(20.0f, ImGui::GetFrameHeight() - 10.0f);
    ImVec2 pos = window->DC.CursorPos;
    window->DrawList->AddText(ImVec2(pos.x, pos.y + (h - ImGui::GetTextLineHeight()) * 0.5f),
                              ImGui::GetColorU32(ImGuiCol_Text), label);
    ImGui::SetCursorScreenPos(ImVec2(pos.x + avail - pill_w, pos.y));
    return keybind_button(id, pill_w, capturing ? "Pressione..." : key_name, capturing, active);
}

static bool aimbot_keybind_button() {
    char label[64] = {};
    snprintf(label, sizeof(label), "%s%s", g_aimbot_key_name, g_aimbot_aim_on ? " (ON)" : "");
    return keybind_row("Keybind", "##aimbot_keybind", label, g_aimbot_capturing, g_aimbot_aim_on);
}

static void misc_bind_start(int which) {
    g_bind_capture = which;
    g_bind_capture_tick = 0;
    g_menu_key_latch = (GetAsyncKeyState(g_menu_key_vk) & 0x8000) != 0;
    g_fly_key_prev = false;
    g_fly_key_edge = bind_is_down(g_fly_key_vk);
}

static void draw_bind_button(const char* label, const char* key_name, int which) {
    ImGui::PushID(which);
    ImGui::PushID(label);
    bool capturing = (g_bind_capture == which);
    if (keybind_row(label, "##bind", key_name, capturing, false)) misc_bind_start(which);
    ImGui::PopID();
    ImGui::PopID();
}

static void sub_fly_fn(void*) {
    draw_bind_button("Bind Key", g_fly_key_name, 3);
    smooth_slider("Velocity", &g_fly_speed, 0.5f, 100.0f, "%.1f", "0.5", "100");
    if (g_fly_mode != FLY_MODE_TOGGLE) g_fly_mode = FLY_MODE_HOLD;
    ui_combo("Modo", &g_fly_mode, "Hold\0Toggle\0\0", 2);
}

static void draw_aimbot_card(float w) {
    card_begin("##aimbot_card", "AIMBOT", w, CARD_ICON_CROSSHAIR);
    accent_checkbox("Enable Aimbot", &g_aimbot_enable);
    if (g_aimbot_enable) {
        accent_checkbox_color("Show Fov", &g_aimbot_show_fov, g_aimbot_fov_col, 3, "##cp_aimbot_fov");
        smooth_slider("Fov Size", &g_aimbot_fov_size, 1.0f, 900.0f, "%.0f");
        smooth_slider("Smooth", &g_aimbot_smooth, 0.0f, 100.0f, "%.1f");
        accent_checkbox("Center Dot", &g_aimbot_center_dot);
        accent_checkbox("Show Target", &g_aimbot_show_target);
        if (g_aimbot_bone < 0 || g_aimbot_bone > 6) g_aimbot_bone = 0;
        ui_combo("Target Bone", &g_aimbot_bone, AIMBOT_BONE_ITEMS, 7);
        if (aimbot_keybind_button()) {
            g_aimbot_capturing     = true;
            g_aimbot_capture_tick  = 0;
            g_aimbot_key_held      = false;
            ImGui::ClearActiveID();
        }
        if (ImGui::IsItemHovered())
            ui_tooltip("Clique e aperte qualquer tecla ou botao do mouse.\nESC cancela. Padrao: Mouse4.");
    }
    card_end();
}

static bool silent_keybind_button() {
    char label[64] = {};
    snprintf(label, sizeof(label), "%s%s", g_silent_key_name, g_silent_aim_on ? " (ON)" : "");
    return keybind_row("Keybind", "##silent_keybind", label, g_silent_capturing, g_silent_aim_on);
}

static void draw_silent_card(float w) {
    card_begin("##silent_card", "SILENT AIM", w, CARD_ICON_GHOST);
    if (accent_checkbox("Enable Silent Aim", &g_silent_enable) && g_silent_enable) {

        silent_install_hook();
        silent_install_mid_hooks();
    }
    if (g_silent_enable) {
        accent_checkbox_color("Show Fov", &g_silent_show_fov, g_silent_fov_col, 3, "##cp_silent_fov");
        smooth_slider("Fov Size", &g_silent_fov_size, 1.0f, 900.0f, "%.0f");
        accent_checkbox("Center Dot", &g_silent_center_dot);
        accent_checkbox("Show Target", &g_silent_show_target);
        accent_checkbox("Ignore Walls", &g_silent_ignore_walls);
        if (ImGui::IsItemHovered())
            ui_tooltip("Desligado: verifica parede, veiculo e objeto antes do packet.\nLigado: ignora obstrucoes.");
        if (g_silent_bone < 0 || g_silent_bone > 6) g_silent_bone = 0;
        ui_combo("Target Bone", &g_silent_bone, AIMBOT_BONE_ITEMS, 7);
        if (silent_keybind_button()) {
            g_silent_capturing = true;
            ImGui::ClearActiveID();
        }
        if (ImGui::IsItemHovered())
            ui_tooltip("Clique e aperte qualquer tecla ou botao do mouse.\nESC cancela. Padrao: Mouse5.");
    }
    card_end();
}


static inline bool is_valid_ptr(uint32_t p);
static uint32_t resolve_troll_ped();
static void troll_explode(uint32_t ped);
static void troll_fire(uint32_t ped);
static void troll_spectate(uint32_t ped);
static void troll_spectate_stop();
static void troll_fire_stop();
static void troll_spectate_update();
static void troll_fire_update();
static bool troll_target_stats(uint32_t ped, float* hp, float* maxhp, float* armor,
                               float* x, float* y, float* z, float* dist);

#if 0
static uint32_t find_ped_by_name(const char* name) {
    if (!name || !name[0]) return 0;
    uint32_t local_ped = get_local_ped();
    uint32_t found = 0;
    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (is_valid_ptr(pool)) {
            uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
            uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
            uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
            if (is_valid_ptr(objects) && is_valid_ptr(flags) && size > 0) {
                if (size > 256) size = 256;
                for (uint32_t i = 0; i < size; ++i) {
                    uint8_t flag = *(uint8_t*)(flags + i);
                    if (flag & 0x80) continue;
                    uint32_t ped = objects + i * PED_STRIDE;
                    if (!is_valid_ptr(ped) || ped == local_ped) continue;
                    char nick[64] = {};
                    if (get_ped_nickname((int)i, ped, false, nick, sizeof(nick)) &&
                        mta_stricmp(nick, name) == 0) {
                        found = ped;
                        break;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return found;
}

static uint32_t resolve_troll_ped() {
    if (is_valid_ptr(g_troll_submenu_ped)) {
        char nick[64] = {};
        if (get_ped_nickname(-1, g_troll_submenu_ped, false, nick, sizeof(nick)) &&
            mta_stricmp(nick, g_troll_submenu_name) == 0)
            return g_troll_submenu_ped;
    }
    g_troll_submenu_ped = find_ped_by_name(g_troll_submenu_name);
    return g_troll_submenu_ped;
}

#endif

static char g_friend_names[16][40] = {};
#define FRIEND_BLUE_IM   IM_COL32(30, 64, 175, 255)
static const float FRIEND_BLUE[3] = { 30.0f / 255.0f, 64.0f / 255.0f, 175.0f / 255.0f };

static bool friend_name_eq(const char* a, const char* b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (ca != cb) return false;
        ++a; ++b;
    }
    return *a == '\0' && *b == '\0';
}
static bool esp_is_friend(const char* name) {
    if (!name || !name[0]) return false;
    for (int i = 0; i < 16; ++i)
        if (g_friend_names[i][0] && friend_name_eq(g_friend_names[i], name)) return true;
    return false;
}

static bool friend_toggle(const char* name) {
    if (!name || !name[0]) return false;
    for (int i = 0; i < 16; ++i) {
        if (g_friend_names[i][0] && friend_name_eq(g_friend_names[i], name)) {
            g_friend_names[i][0] = '\0';
            return false;
        }
    }
    for (int i = 0; i < 16; ++i) {
        if (!g_friend_names[i][0]) {
            snprintf(g_friend_names[i], sizeof(g_friend_names[i]), "%s", name);
            return true;
        }
    }
    return false;
}

static void draw_troll_info_panel(uint32_t ped) {
    static const char* ROW_ICON[4]   = { TROLL_ICON_USER, TROLL_ICON_HEART,
                                         TROLL_ICON_SHIELD, TROLL_ICON_PLACE };
    static const char* ROW_TITLE[4]  = { "Alvo", "Vida", "Colete", "Posicao" };

    char txt[4][112];
    char ntf[4][160];
    float hp = 0.0f, maxhp = 100.0f, armor = 0.0f;
    float x = 0.0f, y = 0.0f, z = 0.0f, dist = -1.0f;
    bool  have = troll_target_stats(ped, &hp, &maxhp, &armor, &x, &y, &z, &dist);

    snprintf(txt[0], sizeof(txt[0]), "%s",
             g_troll_submenu_name[0] ? g_troll_submenu_name : "???");
    snprintf(ntf[0], sizeof(ntf[0]), "Alvo selecionado: %s", txt[0]);

    if (have) {
        char s1[24], s2[24], s3[24], s4[24], s5[24], s6[24], s7[24];
        num_pt(s1, sizeof(s1), hp, 0);
        num_pt(s2, sizeof(s2), maxhp, 0);
        num_pt(s3, sizeof(s3), armor, 0);
        num_pt(s4, sizeof(s4), x, 1);
        num_pt(s5, sizeof(s5), y, 1);
        num_pt(s6, sizeof(s6), z, 2);
        int pct = (maxhp > 0.0f) ? (int)((hp / maxhp) * 100.0f) : 0;
        if (pct < 0) pct = 0;
        if (pct > 999) pct = 999;

        snprintf(txt[1], sizeof(txt[1]), "Vida: %s/%s (%d%%)", s1, s2, pct);
        snprintf(ntf[1], sizeof(ntf[1]), "%s esta com %s de vida (%d%%)", txt[0], s1, pct);
        snprintf(txt[2], sizeof(txt[2]), "Colete: %s", s3);
        snprintf(ntf[2], sizeof(ntf[2]), "%s esta com %s de colete", txt[0], s3);

        num_pt(s7, sizeof(s7), dist, 1);
        num_pt(s6, sizeof(s6), z, 1);

        if (dist >= 0.0f) {
            snprintf(txt[3], sizeof(txt[3]), "%s / %s / %s  -  %s m", s4, s5, s6, s7);
            snprintf(ntf[3], sizeof(ntf[3]), "%s em X%s Y%s Z%s (a %s m)",
                     txt[0], s4, s5, s6, s7);
        } else {
            snprintf(txt[3], sizeof(txt[3]), "%s / %s / %s", s4, s5, s6);
            snprintf(ntf[3], sizeof(ntf[3]), "%s em X%s Y%s Z%s", txt[0], s4, s5, s6);
        }
    } else {
        snprintf(txt[1], sizeof(txt[1]), "Vida: --- (ped nao lido)");
        snprintf(ntf[1], sizeof(ntf[1]), "Nao consegui ler a vida de %s", txt[0]);
        snprintf(txt[2], sizeof(txt[2]), "Colete: ---");
        snprintf(ntf[2], sizeof(ntf[2]), "Nao consegui ler o colete de %s", txt[0]);
        snprintf(txt[3], sizeof(txt[3]), "sem posicao (fora de alcance)");
        snprintf(ntf[3], sizeof(ntf[3]), "%s nao esta streamado; sem posicao", txt[0]);
    }

    const float row_h = 22.0f;
    float rw = ImMax(1.0f, ImGui::GetContentRegionAvail().x);
    float half = ImMax(1.0f, (rw - 4.0f) * 0.5f);
    const float ROWS_X[4] = { rw, half, half, rw };
    for (int i = 0; i < 4; ++i) {
        if (i == 2) ImGui::SameLine(0.0f, 4.0f);
        bool hov = false;
        ImGui::PushID(i);
        bool clicked = ui_info_row(ROW_ICON[i], txt[i], ROWS_X[i], row_h, &hov);
        ImGui::PopID();
        if (clicked) {
            notify_push(ROW_TITLE[i], ROW_ICON[i], have, "%s", ntf[i]);
            if (g_troll_submenu_name[0]) ImGui::SetClipboardText(txt[i]);
        }
        if (i == 0 || i == 2) ImGui::Dummy(ImVec2(0, 2.0f));
    }
}

static void draw_troll_submenu() {
    float avail = ImGui::GetContentRegionAvail().x;
    const float bh  = 32.0f;
    const float gap = 8.0f;

    uint32_t ped = resolve_troll_ped();
    bool can_act = is_valid_ptr(ped);

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
    ImGui::AlignTextToFramePadding();
    ImGui::Text("%s", g_troll_submenu_name[0] ? g_troll_submenu_name : "Alvo");
    ImGui::PopStyleColor();

    const float back_w = 92.0f, back_h = 24.0f;
    ImGui::SameLine(ImMax(0.0f, avail - back_w));
    if (ui_button_ghost("Voltar", TROLL_ICON_BACK, back_w, back_h, false)) {
        g_troll_submenu_open = false;
        g_troll_submenu_name[0] = '\0';
        g_troll_submenu_ped = 0;
        return;
    }
    ImGui::Dummy(ImVec2(0, 6));

    draw_troll_info_panel(ped);
    ImGui::Dummy(ImVec2(0, 6));

    bool fr = esp_is_friend(g_troll_submenu_name);

    if (!can_act) {

        if (ui_button_ghost(fr ? "Remove Friend" : "Add Friend", TROLL_ICON_STAR,
                            ImMin(avail, 170.0f), 26.0f, fr)) {
            fr = friend_toggle(g_troll_submenu_name);
            notify_push("Friends", TROLL_ICON_STAR, fr,
                        fr ? "%s agora e amigo" : "%s saiu dos amigos", g_troll_submenu_name);
        }
        ImGui::Dummy(ImVec2(0, 4));
        ImGui::PushStyleColor(ImGuiCol_Text,
            ImVec4(255 / 255.f, 131 / 255.f, 17 / 255.f, 1.0f));
        ImGui::TextWrapped("Alvo fora de alcance (nao streamado) - acoes desativadas.");
        ImGui::PopStyleColor();
        return;
    }

    const float bw = ImMax(52.0f, (avail - gap * 3.0f) / 4.0f);
    bool spec_on = g_spectate_active;
    bool fire_on = (g_fire_slot != 0 && g_fire_ped == ped);

    if (ui_button_ghost(spec_on ? "Stop Spectate" : "Spectate", TROLL_ICON_EYE,
                        bw, bh, spec_on)) {
        if (spec_on) troll_spectate_stop();
        else         troll_spectate(ped);
    }
    ImGui::SameLine(0.0f, gap);
    if (ui_button_ghost("Explode", TROLL_ICON_BOMB, bw, bh, false))
        troll_explode(ped);
    ImGui::SameLine(0.0f, gap);
    if (ui_button_ghost(fire_on ? "Stop Fire" : "Fire", TROLL_ICON_FIRE,
                        bw, bh, fire_on))
        troll_fire(ped);
    ImGui::SameLine(0.0f, gap);
    if (ui_button_ghost(fr ? "Remove Friend" : "Add Friend", TROLL_ICON_STAR,
                        bw, bh, fr)) {
        fr = friend_toggle(g_troll_submenu_name);
        notify_push("Friends", TROLL_ICON_STAR, fr,
                    fr ? "%s agora e amigo (aimbot/silent ignoram)" : "%s saiu dos amigos",
                    g_troll_submenu_name);
    }
}

static void draw_players_card(float w) {
    if (g_troll_submenu_open) {
        card_begin("##troll_players_card", "JOGADORES", w, TROLL_ICON_USERS, 6.0f);
        draw_troll_submenu();
        card_end();
        return;
    }
    card_begin("##troll_players_card", "JOGADORES", w, TROLL_ICON_USERS);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 4));
    ImGui::BeginChild("##troll_player_list", ImVec2(0, 0), false,
                      ImGuiWindowFlags_NoScrollbar);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float row_h = 22.0f;
    for (int i = 0; i < g_troll_count; ++i) {
        if (!g_troll_names[i][0]) continue;
        ImGui::PushID(i);
        ImVec2 p = ImGui::GetCursorScreenPos();
        float row_w = ImMax(1.0f, ImGui::GetContentRegionAvail().x);
        bool clicked = ImGui::InvisibleButton("##row", ImVec2(row_w, row_h));
        bool hovered = ImGui::IsItemHovered();
        if (clicked) {
            snprintf(g_troll_selected_name, sizeof(g_troll_selected_name), "%s", g_troll_names[i]);
            snprintf(g_troll_submenu_name, sizeof(g_troll_submenu_name), "%s", g_troll_names[i]);
            g_troll_submenu_ped = 0;
            g_troll_submenu_open = true;
        }
        bool sel = (strcmp(g_troll_selected_name, g_troll_names[i]) == 0);
        if (sel)
            dl->AddRectFilled(p, ImVec2(p.x + row_w, p.y + row_h), ui_col_a(COL_SCHEME, 0.18f), 3.0f);
        else if (hovered)
            dl->AddRectFilled(p, ImVec2(p.x + row_w, p.y + row_h), COL_FRAME_HOVER, 3.0f);
        else
            dl->AddRectFilled(p, ImVec2(p.x + row_w, p.y + row_h), COL_FRAME_BG, 3.0f);
        if (sel)
            dl->AddRectFilled(p, ImVec2(p.x + 2.0f, p.y + row_h), COL_SCHEME, 1.0f);
        ImVec2 ts = ImGui::CalcTextSize(g_troll_names[i]);
        float name_x = p.x + 10.0f;
        if (g_font_icons) {
            const float ifs = g_icon_font_size * 0.5f;
            ImVec2 isz = g_font_icons->CalcTextSizeA(ifs, FLT_MAX, 0.0f, TROLL_ICON_USER);
            dl->AddText(g_font_icons, ifs, ImVec2(p.x + 8.0f, p.y + (row_h - isz.y) * 0.5f),
                        sel ? IM_COL32(255, 255, 255, 255) : COL_SCHEME, TROLL_ICON_USER);
            name_x = p.x + 8.0f + isz.x + 8.0f;
        }
        bool fr = esp_is_friend(g_troll_names[i]);
        dl->AddText(ImVec2(name_x, p.y + (row_h - ts.y) * 0.5f),
                    fr ? FRIEND_BLUE_IM
                       : (sel ? IM_COL32(255, 255, 255, 255) : ImGui::GetColorU32(ImGuiCol_Text)),
                    g_troll_names[i]);
        if (fr && g_font_icons) {
            const float sfs = g_icon_font_size * 0.45f;
            ImVec2 ssz = g_font_icons->CalcTextSizeA(sfs, FLT_MAX, 0.0f, TROLL_ICON_STAR);
            dl->AddText(g_font_icons, sfs, ImVec2(p.x + row_w - ssz.x - 8.0f,
                        p.y + (row_h - ssz.y) * 0.5f), FRIEND_BLUE_IM, TROLL_ICON_STAR);
        }
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    card_end();
}

static void draw_troll_card(float w) {
    card_begin("##troll_card", "TROLL", w, CARD_ICON_BOLT);
    if (accent_checkbox("Fly", &g_fly_enable))
        notify_push("Fly", TROLL_ICON_GLYPH, true,
                    g_fly_enable ? "Fly ON" : "Fly OFF");
    if (ImGui::IsItemHovered())
        ui_tooltip("W/S/A/D voam no plano horizontal da camera; Espaco sobe, Ctrl\ndesce, Shift da boost. Hold = segura o bind; Toggle = um toque liga.");
    draw_sub_card("##sub_fly", g_fly_enable, 122.0f, sub_fly_fn, nullptr, 8.0f);
    if (accent_checkbox("Infinite Ammo", &g_infinite_ammo))
        notify_push("Ammo", TROLL_ICON_GLYPH, true,
                    g_infinite_ammo ? "Municao infinita ON" : "Municao infinita OFF");
    if (ImGui::IsItemHovered())
        ui_tooltip("Recarrega o clip e o total da arma atual do teu ped a cada frame.\nSomente no teu ped; valida slot (0-12) e tipo (0-46) antes de escrever.");
    card_end();
}

static void draw_options_card(float w) {
    card_begin("##options_card", "OPTIONS", w, CARD_ICON_COG);
    accent_checkbox("Stream Proof", &g_stream_proof);
    if (ImGui::IsItemHovered())
        ui_tooltip("Esconde a janela do menu/overlay de capturas (OBS, Discord).\nSo aplica com o jogo em foco; limpa na hora se perder o foco.");
    card_end();
}

static void draw_config_card(float w) {
    card_begin("##config_card", "CONFIG", w, CARD_ICON_COG);
    draw_bind_button("Menu Key", g_menu_key_name, 2);
    ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x);
    if (ImGui::InputText("##cfg_name", g_cfg_input, sizeof(g_cfg_input),
                         ImGuiInputTextFlags_CharsNoBlank)) {
        g_cfg_pending_overwrite = false;
        g_cfg_pending_delete = false;
    }
    ImGui::PopItemWidth();
    float bw = ImGui::GetContentRegionAvail().x;
    float bh = 28.0f;
    if (ui_button("Save", bw, bh, true)) {
        g_cfg_pending_delete = false;
        cfg_save(g_cfg_input);
    }
    if (ui_button("Load", bw, bh, false)) {
        g_cfg_pending_overwrite = false;
        g_cfg_pending_delete = false;
        cfg_scan(true);
        if (g_cfg_selected >= 0 && g_cfg_selected < g_cfg_count)
            cfg_load(g_cfg_names[g_cfg_selected]);
        else
            cfg_status(false, "Nenhuma config selecionada.");
    }
    if (ui_button("Del", bw, bh, false)) {
        g_cfg_pending_overwrite = false;
        if (g_cfg_selected >= 0 && g_cfg_selected < g_cfg_count)
            cfg_delete(g_cfg_names[g_cfg_selected]);
        else
            cfg_status(false, "Nenhuma config selecionada.");
    }
    cfg_scan();
    const char* joined = "";
    cfg_name_combo(&joined, g_cfg_count);
    if (g_cfg_count > 0) {
        if (g_cfg_selected < 0 || g_cfg_selected >= g_cfg_count) g_cfg_selected = 0;
        ui_combo("Configs", &g_cfg_selected, joined, g_cfg_count);
    }
    card_end();
}

static void draw_options_page() {
    float avail_w = ImGui::GetContentRegionAvail().x;
    float gap     = 20.0f;
    float col_w   = ImMax(1.0f, (avail_w - gap) * 0.5f);
    draw_options_card(col_w);
    ImGui::SameLine(0.0f, gap);
    draw_config_card(col_w);
}

static void draw_troll_page() {
    float avail_w = ImGui::GetContentRegionAvail().x;
    float gap     = 20.0f;
    float col_w   = ImMax(1.0f, (avail_w - gap) * 0.5f);
    draw_troll_card(col_w);
    ImGui::SameLine(0.0f, gap);
    draw_players_card(col_w);
}

static void draw_combat_page() {
    float gap = 20.0f;
    float w = ImMax(1.0f, (ImGui::GetContentRegionAvail().x - gap) * 0.5f);
    draw_aimbot_card(w);
    ImGui::SameLine(0.0f, gap);
    draw_silent_card(w);
}

static const char* TAB_LABELS[TAB_COUNT] = {
    "COMBAT", "VISUALS", "OPTIONS", "TROLL"
};
static const char* TAB_ICONS[TAB_COUNT] = {
    CARD_ICON_CROSSHAIR, CARD_ICON_EYE, CARD_ICON_COG, CARD_ICON_BOLT
};

static void draw_tab_icon(ImDrawList* dl, int num, ImVec2 cen, float sz, ImU32 col) {
    const float r = sz * 0.5f;
    if (num == TAB_COMBAT) {
        dl->AddCircle(cen, r * 0.62f, col, 0, 1.6f);
        dl->AddLine(ImVec2(cen.x, cen.y - r), ImVec2(cen.x, cen.y - r * 0.34f), col, 1.6f);
        dl->AddLine(ImVec2(cen.x, cen.y + r * 0.34f), ImVec2(cen.x, cen.y + r), col, 1.6f);
        dl->AddLine(ImVec2(cen.x - r, cen.y), ImVec2(cen.x - r * 0.34f, cen.y), col, 1.6f);
        dl->AddLine(ImVec2(cen.x + r * 0.34f, cen.y), ImVec2(cen.x + r, cen.y), col, 1.6f);
        dl->AddCircleFilled(cen, 1.6f, col);
    } else if (num == TAB_VISUALS) {
        dl->PathClear();
        dl->PathLineTo(ImVec2(cen.x - r, cen.y));
        dl->PathBezierQuadraticCurveTo(ImVec2(cen.x, cen.y - r * 1.15f), ImVec2(cen.x + r, cen.y));
        dl->PathBezierQuadraticCurveTo(ImVec2(cen.x, cen.y + r * 1.15f), ImVec2(cen.x - r, cen.y));
        dl->PathStroke(col, 0, 1.6f);
        dl->AddCircleFilled(cen, r * 0.34f, col);
    } else if (num == TAB_MISC) {
        dl->AddCircle(cen, r * 0.52f, col, 0, 1.6f);
        for (int i = 0; i < 6; ++i) {
            float a = (float)i * 3.14159265f / 3.0f;
            ImVec2 d(cosf(a), sinf(a));
            ImVec2 pp(-sinf(a), cosf(a));
            ImVec2 c2(cen.x + d.x * r * 0.78f, cen.y + d.y * r * 0.78f);
            dl->PathClear();
            dl->PathLineTo(ImVec2(c2.x + pp.x * r * 0.30f - d.x * r * 0.28f,
                                  c2.y + pp.y * r * 0.30f - d.y * r * 0.28f));
            dl->PathLineTo(ImVec2(c2.x + pp.x * r * 0.30f + d.x * r * 0.28f,
                                  c2.y + pp.y * r * 0.30f + d.y * r * 0.28f));
            dl->PathLineTo(ImVec2(c2.x - pp.x * r * 0.30f + d.x * r * 0.28f,
                                  c2.y - pp.y * r * 0.30f + d.y * r * 0.28f));
            dl->PathLineTo(ImVec2(c2.x - pp.x * r * 0.30f - d.x * r * 0.28f,
                                  c2.y - pp.y * r * 0.30f - d.y * r * 0.28f));
            dl->PathFillConvex(col);
        }
        dl->AddCircleFilled(cen, r * 0.20f, col);
    } else {
        dl->PathClear();
        dl->PathLineTo(ImVec2(cen.x + r * 0.28f, cen.y - r));
        dl->PathLineTo(ImVec2(cen.x - r * 0.62f, cen.y + r * 0.12f));
        dl->PathLineTo(ImVec2(cen.x - r * 0.06f, cen.y + r * 0.12f));
        dl->PathLineTo(ImVec2(cen.x - r * 0.28f, cen.y + r));
        dl->PathLineTo(ImVec2(cen.x + r * 0.62f, cen.y - r * 0.12f));
        dl->PathLineTo(ImVec2(cen.x + r * 0.06f, cen.y - r * 0.12f));
        dl->PathFillConvex(col);
    }
}

static bool tab_widget(int num, float w) {

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    const char* label = TAB_LABELS[num];
    ImGuiID id = window->GetID(label);
    bool selected = (num == g_next_tab);
    float selected_anim = ui_anim(label, 0, selected, 0.0f, 1.0f, UI_ANIM_SPEED);
    const char* icon = TAB_ICONS[num];
    const float tfs = 12.0f;
    ImVec2 lsz = g_font_tabs
        ? g_font_tabs->CalcTextSizeA(tfs, FLT_MAX, 0.0f, label)
        : ImGui::CalcTextSize(label, nullptr, true);
    const float iszf = g_font_icons ? g_icon_font_size * 0.62f : 13.0f;
    ImVec2 isz = g_font_icons
        ? g_font_icons->CalcTextSizeA(iszf, FLT_MAX, 0.0f, icon)
        : ImVec2(13.0f, 13.0f);

    ImVec2 size(w, 32.0f);
    ImVec2 p = window->DC.CursorPos;
    ImRect bb(p, ImVec2(p.x + size.x, p.y + size.y));
    ImGui::ItemSize(bb);
    if (!ImGui::ItemAdd(bb, id)) return false;

    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);
    if (pressed && !selected) {
        g_content_anim_dest = 0.0f;
        g_next_tab = num;
    }
    float hover_anim = ui_anim(label, 1, hovered && !selected, 0.0f, 1.0f, UI_ANIM_SPEED);
    ImDrawList* dl = window->DrawList;
    if (selected_anim > 0.001f) {
        dl->AddRectFilled(bb.Min, bb.Max, ui_col_a(COL_SCHEME, selected_anim * 0.26f), 4.0f);
        dl->AddRectFilled(ImVec2(bb.Min.x, bb.Min.y + 5.0f),
                          ImVec2(bb.Min.x + 3.0f, bb.Max.y - 5.0f),
                          ui_col_a(COL_SCHEME, selected_anim), 1.5f);
    }
    ImU32 icon_col = ui_color_lerp(ImGui::GetColorU32(ImGuiCol_TextDisabled),
                                   IM_COL32(255, 255, 255, 255),
                                   ImMax(selected_anim, hover_anim));
    float ix = bb.Min.x + 10.0f;
    if (g_font_icons)
        dl->AddText(g_font_icons, iszf, ImVec2(ix, bb.GetCenter().y - isz.y * 0.5f), icon_col, icon);
    else
        draw_tab_icon(dl, num, ImVec2(ix + 7.0f, bb.GetCenter().y), 12.0f, icon_col);
    ImU32 text_col = ui_col_a(IM_COL32(255, 255, 255, 255),
                             0.75f + 0.25f * ImMax(selected_anim, hover_anim));
    float lx = ix + (isz.x > 0.0f ? isz.x + 8.0f : 16.0f);
    if (g_font_tabs)
        dl->AddText(g_font_tabs, tfs, ImVec2(lx, bb.GetCenter().y - lsz.y * 0.5f), text_col, label, ImGui::FindRenderedTextEnd(label));
    else
        dl->AddText(ImVec2(lx, bb.GetCenter().y - lsz.y * 0.5f), text_col, label, ImGui::FindRenderedTextEnd(label));
    return pressed;
}

static void render_page() {
    switch (g_current_tab) {
    case TAB_COMBAT:   draw_combat_page();   break;
    case TAB_VISUALS:  draw_visuals_page();  break;
    case TAB_MISC:     draw_options_page();  break;
    case TAB_TROLL:    draw_troll_page();    break;
    default:                                 break;
    }
}

static void handle_alpha_anim() {
    g_content_anim = ImLerp(g_content_anim, g_content_anim_dest, UI_ANIM_SPEED * 2.5f);
    if (g_content_anim < 0.001f) {
        g_content_anim_dest = 1.0f;
        g_current_tab = g_next_tab;
    }
}

static void draw_menu_cursor() {
}

static void draw_menu() {
    ImGuiIO& io = ImGui::GetIO();
    const ImVec2 win_size(650.0f, 440.0f);
    g_menu_size = win_size;
    ImGui::SetNextWindowSize(win_size, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2((io.DisplaySize.x - win_size.x) * 0.5f,
                                   (io.DisplaySize.y - win_size.y) * 0.5f),
                            ImGuiCond_FirstUseEver);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##main_menu", &g_menu_open,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings);
    g_menu_pos = ImGui::GetWindowPos();

    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, ImGui::GetStyle().WindowRounding);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));

    const float sb_w = 152.0f;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 0.0f));
    ImGui::BeginChild("##sidebar", ImVec2(sb_w, 0), false, ImGuiWindowFlags_NoBackground);
    {
        ImDrawList* sdl = ImGui::GetWindowDrawList();
        ImVec2 sp = ImGui::GetWindowPos();
        ImVec2 ss = ImGui::GetWindowSize();
        sdl->AddLine(ImVec2(sp.x + ss.x - 0.5f, sp.y + 10.0f),
                     ImVec2(sp.x + ss.x - 0.5f, sp.y + ss.y - 10.0f),
                     ui_col_a(COL_SCHEME, 0.34f), 1.0f);
        const float hfs = 15.0f;
        ImVec2 s1 = g_font_header ? g_font_header->CalcTextSizeA(hfs, FLT_MAX, 0.0f, "Hijacking")
                                  : ImGui::CalcTextSize("Hijacking");
        float ty = sp.y + 14.0f;
        if (g_font_header) {
            sdl->AddText(g_font_header, hfs, ImVec2(sp.x + 12.0f, ty), IM_COL32(255, 255, 255, 255), "Hijacking");
            sdl->AddText(g_font_header, hfs, ImVec2(sp.x + 12.0f + s1.x + 5.0f, ty), IM_COL32(255, 255, 255, 255), "Menu");
        } else {
            sdl->AddText(ImVec2(sp.x + 12.0f, ty), IM_COL32(255, 255, 255, 255), "Hijacking Menu");
        }
        ImGui::SetCursorPos(ImVec2(0.0f, 0.0f));
        ImGui::InvisibleButton("##drag_bar", ImVec2(ss.x, 40.0f));
        if (ImGui::IsItemHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            ImGuiWindow* mw = ImGui::FindWindowByName("##main_menu");
            if (mw) {
                ImVec2 np(mw->Pos.x + io.MouseDelta.x, mw->Pos.y + io.MouseDelta.y);
                np.x = ImClamp(np.x, 80.0f - mw->Size.x, io.DisplaySize.x - 80.0f);
                np.y = ImClamp(np.y, 0.0f, ImMax(0.0f, io.DisplaySize.y - 40.0f));
                ImGui::SetWindowPos(mw, np);
            }
        }
        ImGui::SetCursorPos(ImVec2(0.0f, 44.0f));
        for (int i = 0; i < TAB_COUNT; ++i) {
            tab_widget(i, sb_w - 24.0f);
            ImGui::Dummy(ImVec2(0, 2.0f));
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();

    ImGui::SameLine(0.0f, 0.0f);
    ImGui::PopStyleVar(2);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, g_content_anim);
    ImGui::BeginChild("##content", ImVec2(0, 0), false, ImGuiWindowFlags_NoBackground);
    ImGui::SetCursorPos(ImVec2(14.0f, 10.0f));
    render_page();
    ImGui::EndChild();
    ImGui::PopStyleVar();

    ImGui::End();
    ImGui::PopStyleVar();
    draw_menu_cursor();
    handle_alpha_anim();
}

using fn_EndScene     = HRESULT(__stdcall*)(IDirect3DDevice9*);
using fn_Reset        = HRESULT(__stdcall*)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);
using fn_Present      = HRESULT(__stdcall*)(IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*);
using fn_SetTransform = HRESULT(__stdcall*)(IDirect3DDevice9*, D3DTRANSFORMSTATETYPE, const D3DMATRIX*);

static fn_EndScene     g_o_EndScene     = nullptr;
static fn_Reset        g_o_Reset        = nullptr;
static fn_Present      g_o_Present      = nullptr;
static fn_SetTransform g_o_SetTransform = nullptr;
static bool            g_imgui_init     = false;
static volatile LONG   g_imgui_invalidated = 0;

static D3DMATRIX g_current_view = {};
static D3DMATRIX g_3d_view      = {};
static D3DMATRIX g_3d_proj      = {};
static bool      g_have_3d      = false;

static HWND    g_game_hwnd = nullptr;
static WNDPROC g_o_wndproc = nullptr;

static void stream_proof_apply() {
    if (!g_game_hwnd || !IsWindow(g_game_hwnd)) {
        g_stream_proof_ready = false;
        g_stream_proof_hwnd  = nullptr;
        return;
    }
    g_stream_proof_ready = true;

    DWORD desired = g_stream_proof ? WDA_EXCLUDEFROMCAPTURE_V : WDA_NONE_VALUE;

    if (g_stream_proof_applied == desired && g_stream_proof_hwnd == g_game_hwnd)
        return;

    if (desired == WDA_NONE_VALUE) {
        if (set_display_affinity(g_game_hwnd, WDA_NONE_VALUE)) {
            g_stream_proof_applied = WDA_NONE_VALUE;
            g_stream_proof_hwnd    = g_game_hwnd;
            g_stream_proof_ok      = true;
            mta_logf("wda", "stream proof OFF (WDA_NONE): render d3d9 intacto");
        }
        return;
    }

    uint32_t now = GetTickCount();
    if (g_stream_proof_last_try && (now - g_stream_proof_last_try) < 2000)
        return;
    g_stream_proof_last_try = now ? now : 1;

    if (set_display_affinity(g_game_hwnd, WDA_EXCLUDEFROMCAPTURE_V)) {
        if (g_stream_proof_applied != WDA_EXCLUDEFROMCAPTURE_V)
            mta_logf("wda", "stream proof ON: WDA_EXCLUDEFROMCAPTURE (0x%X) aplicado",
                     (unsigned)WDA_EXCLUDEFROMCAPTURE_V);
        g_stream_proof_applied = WDA_EXCLUDEFROMCAPTURE_V;
        g_stream_proof_hwnd    = g_game_hwnd;
        g_stream_proof_ok      = true;
        return;
    }

    static bool wda_unsup_logged = false;
    if (!wda_unsup_logged) {
        wda_unsup_logged = true;
        g_stream_proof_ok = false;
        mta_logf("wda", "stream proof INDISPONIVEL: WDA_EXCLUDEFROMCAPTURE falhou (Win<1903 ou DWM off); WDA_MONITOR nao sera usado (apaga a tela do proprio usuario)");
    }

    if (g_stream_proof_ok || mta_log_tick(7, 5000))
        mta_logf("wda!", "stream proof falhou: EXCLUDEFROMCAPTURE e MONITOR rejeitados "
                         "(exclusive fullscreen? use borderless)");
    g_stream_proof_applied = WDA_NONE_VALUE;
    g_stream_proof_hwnd    = g_game_hwnd;
    g_stream_proof_ok      = false;
}

#ifndef SC_CLOSE_V
#define SC_CLOSE_V 0xF060
#endif
static PatchRecord g_quit_patches[96] = {};
static int         g_quit_patch_count = 0;

static void quit_hard_restore() {
    InterlockedExchange(&g_watchdog_stop, 1);
    g_quit_flushed = true;
    InterlockedExchange(&g_session_live, 0);
    g_session_live_tick = 0;
    InterlockedExchange(&g_silent_send_ok, 0);

    int n = g_patch_count;
    if (n > 96) n = 96;
    if (n < 0) n = 0;
    int feats = 0, d3d = 0, netc = 0;
    g_quit_patch_count = 0;
    for (int i = 0; i < n; ++i) {
        PatchRecord& pr = g_patches[i];
        if (!pr.addr) continue;
        if (g_quit_patch_count < 96) g_quit_patches[g_quit_patch_count++] = pr;
        if (patch_in_netc((uint32_t)(uintptr_t)pr.addr)) { ++netc; continue; }
        if (patch_is_feature(pr)) { patch_set(pr, false); ++feats; }
    }
    for (int i = 0; i < n; ++i) {
        PatchRecord& pr = g_patches[i];
        if (!pr.addr || patch_in_netc((uint32_t)(uintptr_t)pr.addr)) continue;
        if (!patch_is_feature(pr)) { patch_set(pr, false); ++d3d; }
    }
    mta_logf("quit", "hard restore: %d features + %d d3d pausados, %d netc INTOCADOS (por design)",
             feats, d3d, netc);
}

static void emergency_disable_all() {
    if (InterlockedExchange(&g_emergency_done, 1) != 0) return;
    InterlockedExchange(&g_shutdown_all, 1);
    session_fail_closed(4);
    DWORD t0 = GetTickCount();
    InterlockedExchange(&g_watchdog_stop, 1);
    quit_hard_restore();
    fly_physics_end();
    menu_cursor_sync(false);

    HANDLE wh = g_watchdog_handle;
    g_watchdog_handle = nullptr;
    if (wh) {
        WaitForSingleObject(wh, 0);
        CloseHandle(wh);
    }

    g_esp_local_enable = g_esp_local_box = g_esp_local_box_filled = false;
    g_esp_local_box_corner = g_esp_local_box_rounded = false;
    g_esp_local_lines = g_esp_local_names = g_esp_local_health = false;
    g_esp_local_health_dynamic = g_esp_local_armor = g_esp_local_skeleton = false;
    g_esp_local_distance = false;
    g_esp_players_enable = g_esp_players_box = g_esp_players_box_filled = false;
    g_esp_players_box_corner = g_esp_players_box_rounded = false;
    g_esp_players_lines = g_esp_players_names = g_esp_players_health = false;
    g_esp_players_health_dynamic = g_esp_players_armor = g_esp_players_skeleton = false;
    g_esp_players_distance = false;
    g_aimbot_enable = g_aimbot_show_fov = g_aimbot_center_dot = false;
    g_silent_enable = g_silent_show_fov = g_silent_center_dot = false;
    g_silent_aim_on = g_silent_has_target = false;
    g_silent_capturing = false;
    InterlockedExchange(&g_silent_send_ok, 0);
    g_aimbot_show_target = false;
    g_aimbot_aim_on = g_aimbot_has_target = false;
    g_aimbot_capturing = g_aimbot_key_held = false;
    g_bind_capture = 0; g_bind_capture_tick = 0;
    g_menu_key_latch = (GetAsyncKeyState(g_menu_key_vk) & 0x8000) != 0;
    InterlockedExchange(&g_menu_toggle_pending, 0);
    g_fly_key_prev = g_fly_key_held = false;
    g_fly_enable = g_fly_active = false;
    g_fly_toggle_on = false; g_fly_key_edge = false;
    g_fly_hover_valid = false;
    g_stream_proof = false;
    g_menu_open = false; g_prev_insert = false; g_prev_menu_open = false;
    g_cfg_pending_overwrite = false; g_cfg_pending_delete = false;
    g_troll_submenu_open = false;
    g_troll_submenu_name[0] = '\0';
    g_troll_submenu_ped = 0;
    troll_spectate_stop();
    troll_fire_stop();

    if (g_game_hwnd) set_display_affinity(g_game_hwnd, WDA_NONE_VALUE);
    g_stream_proof_ready   = false;
    g_stream_proof_applied = WDA_NONE_VALUE;
    g_stream_proof_hwnd    = nullptr;

    ClipCursor(nullptr);

    WNDPROC orig = g_o_wndproc;
    if (orig && g_game_hwnd) {
        SetWindowLongPtrA(g_game_hwnd, GWLP_WNDPROC, (LONG_PTR)orig);
        g_o_wndproc = nullptr;
    }

    silent_retire_hooks();
    quit_hard_restore();
    if (!g_emergency_logged) {
        g_emergency_logged = true;
        mta_logf("quit", "kill switch %ums: %d hooks restaurados ANTES do disconnect, watchdog parado, WDA_NONE",
                 (unsigned)(GetTickCount() - t0), g_quit_patch_count);
    }
}

static void misc_bind_poll_capture() {
    int which = g_bind_capture;
    if (!which) return;
    static bool     armed = false;
    static bool     was_down[256] = {};
    static uint32_t start = 0;

    if (g_bind_capture_tick == 0) {
        g_bind_capture_tick = GetTickCount();
        start = g_bind_capture_tick;
        armed = false;
        for (int i = 0; i < 256; ++i) was_down[i] = bind_is_down(i);
        return;
    }
    if (GetTickCount() - start > 8000) { bind_set_key(which, 0); g_bind_capture = 0; return; }
    if (bind_is_down(VK_ESCAPE)) {
        g_bind_capture = 0; g_bind_capture_tick = 0; armed = false;
        return;
    }
    for (int vk = 1; vk < 256; ++vk) {
        bool down = bind_is_down(vk);
        bool edge = down && !was_down[vk];
        was_down[vk] = down;
        if (!edge) continue;
        if (!armed) { armed = true; continue; }
        if (vk == VK_ESCAPE) { g_bind_capture = 0; g_bind_capture_tick = 0; return; }
        bind_set_key(which, vk);
        return;
    }
}

static bool is_perspective(const D3DMATRIX* m) {
    return m->m[3][2] != 0.0f && m->m[3][3] == 0.0f;
}

static LRESULT CALLBACK hk_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    WNDPROC orig_at_entry = g_o_wndproc;
    if (msg == WM_SHOWWINDOW) {
        if (!wParam && !IsIconic(hwnd)) quit_flush();
        else if (wParam) quit_unflush();
    } else if (msg == WM_WINDOWPOSCHANGED && lParam) {
        __try {
            WINDOWPOS* wp = (WINDOWPOS*)lParam;
            if ((wp->flags & SWP_HIDEWINDOW) && !IsIconic(hwnd)) quit_flush();
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    if (msg == WM_CLOSE || msg == WM_DESTROY || msg == WM_NCDESTROY ||
        msg == WM_QUIT || msg == WM_ENDSESSION || msg == WM_QUERYENDSESSION ||
        (msg == WM_SYSCOMMAND && (wParam & 0xFFF0) == SC_CLOSE_V)) {

        quit_flush();
        emergency_disable_all();
        static bool quit_msg_logged = false;
        if (!quit_msg_logged) {
            quit_msg_logged = true;
            mta_logf("quit", "sinal 0x%04X: features+d3d retirados, netc intocado, disconnect OK",
                     (unsigned)msg);
        }
        return orig_at_entry
            ? CallWindowProc(orig_at_entry, hwnd, msg, wParam, lParam)
            : DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) {
        return orig_at_entry
            ? CallWindowProc(orig_at_entry, hwnd, msg, wParam, lParam)
            : DefWindowProcA(hwnd, msg, wParam, lParam);
    }

    if ((msg == WM_ACTIVATEAPP && wParam) || msg == WM_SETFOCUS) g_game_focused = true;
    if ((msg == WM_ACTIVATEAPP && !wParam) || msg == WM_KILLFOCUS) {
        g_game_focused = false;
        InterlockedExchange(&g_silent_send_ok, 0);
        g_silent_aim_on = g_silent_has_target = false;
    }

    if (g_silent_capturing) {
        int cap = 0;
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) cap = (int)(wParam & 0xFF);
        else if (msg == WM_LBUTTONDOWN) cap = VK_LBUTTON;
        else if (msg == WM_RBUTTONDOWN) cap = VK_RBUTTON;
        else if (msg == WM_MBUTTONDOWN) cap = VK_MBUTTON;
        else if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONDBLCLK)
            cap = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        if (cap == VK_ESCAPE) { g_silent_capturing = false; return 1; }
        if (cap) {
            g_silent_key_vk = cap;
            bind_format_key(cap, g_silent_key_name, sizeof(g_silent_key_name));
            g_silent_capturing = false;
            return 1;
        }
    }

    if (g_bind_capture) {
        int cap = 0;
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) cap = (int)(wParam & 0xFF);
        else if (msg == WM_LBUTTONDOWN) cap = VK_LBUTTON;
        else if (msg == WM_RBUTTONDOWN) cap = VK_RBUTTON;
        else if (msg == WM_MBUTTONDOWN) cap = VK_MBUTTON;
        else if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONDBLCLK)
            cap = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        if (cap == VK_ESCAPE) { g_bind_capture = 0; g_bind_capture_tick = 0; return 1; }
        if (cap) { bind_set_key(g_bind_capture, cap); return 1; }
    }

    if (g_aimbot_capturing) {
        int cap = 0;
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) cap = (int)(wParam & 0xFF);
        else if (msg == WM_LBUTTONDOWN) cap = VK_LBUTTON;
        else if (msg == WM_RBUTTONDOWN) cap = VK_RBUTTON;
        else if (msg == WM_MBUTTONDOWN) cap = VK_MBUTTON;
        else if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONDBLCLK)
            cap = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        if (cap == VK_ESCAPE) { aimbot_stop_capture(); return 1; }
        if (cap) { aimbot_set_key(cap); aimbot_stop_capture(); return 1; }
    }
    {
        int dvk = 0, uvk = 0;
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) dvk = (int)(wParam & 0xFF);
        else if (msg == WM_KEYUP || msg == WM_SYSKEYUP) uvk = (int)(wParam & 0xFF);
        else if (msg == WM_LBUTTONDOWN) dvk = VK_LBUTTON;
        else if (msg == WM_LBUTTONUP)   uvk = VK_LBUTTON;
        else if (msg == WM_RBUTTONDOWN) dvk = VK_RBUTTON;
        else if (msg == WM_RBUTTONUP)   uvk = VK_RBUTTON;
        else if (msg == WM_MBUTTONDOWN) dvk = VK_MBUTTON;
        else if (msg == WM_MBUTTONUP)   uvk = VK_MBUTTON;
        else if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONDBLCLK)
            dvk = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        else if (msg == WM_XBUTTONUP)
            uvk = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        if (dvk && dvk == g_aimbot_key_vk) {
            g_aimbot_key_held  = true;
            g_aimbot_held_tick = GetTickCount();
        }
        if (uvk && uvk == g_aimbot_key_vk) g_aimbot_key_held = false;
    }
    if (msg == WM_KILLFOCUS) g_aimbot_key_held = false;

    if ((msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) &&
        !(lParam & 0x40000000) &&
        (int)(wParam & 0xFF) == g_menu_key_vk &&
        !g_bind_capture && !g_aimbot_capturing) {
        InterlockedExchange(&g_menu_toggle_pending, 1);
    }

    if (g_imgui_init) {
        if (msg == WM_SETCURSOR && g_menu_open) return 1;
        ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam);
        ImGuiIO& io = ImGui::GetIO();

        if ((msg == WM_ACTIVATE && LOWORD(wParam) == WA_INACTIVE) ||
            (msg == WM_ACTIVATEAPP && wParam == FALSE) ||
            msg == WM_KILLFOCUS) {
            io.MouseDown[0] = io.MouseDown[1] = io.MouseDown[2] = false;
            io.MouseWheel   = 0.0f;
            io.MouseWheelH  = 0.0f;
            ImGui::ClearActiveID();
            ClipCursor(nullptr);
        }
        if (g_menu_open && io.WantCaptureMouse) {
            switch (msg) {
                case WM_LBUTTONDOWN: case WM_LBUTTONUP:
                case WM_RBUTTONDOWN: case WM_RBUTTONUP:
                case WM_MBUTTONDOWN: case WM_MBUTTONUP:
                case WM_MOUSEWHEEL:  case WM_MOUSEMOVE:
                    return 1;
            }
        }
        if (g_menu_open && io.WantCaptureKeyboard) {
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

static void apply_theme() {
    ImGuiStyle& s = ImGui::GetStyle();
    ImVec4* c = s.Colors;

    c[ImGuiCol_Text]                  = ImVec4(205 / 255.f, 205 / 255.f, 208 / 255.f, 1.0f);
    c[ImGuiCol_TextDisabled]          = ImVec4(128 / 255.f, 129 / 255.f, 134 / 255.f, 1.0f);
    c[ImGuiCol_WindowBg]              = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);

    c[ImGuiCol_ChildBg]               = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_PopupBg]               = ImVec4(0.0f, 0.0f, 0.0f, 0.96f);
    c[ImGuiCol_Border]                = ImVec4(1.0f, 1.0f, 1.0f, 40 / 255.f);
    c[ImGuiCol_BorderShadow]          = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);

    c[ImGuiCol_FrameBg]               = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
    c[ImGuiCol_FrameBgHovered]        = ImVec4(26 / 255.f, 26 / 255.f, 28 / 255.f, 1.0f);
    c[ImGuiCol_FrameBgActive]         = ImVec4(48 / 255.f, 48 / 255.f, 52 / 255.f, 1.0f);

    c[ImGuiCol_TitleBg]               = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
    c[ImGuiCol_TitleBgActive]         = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
    c[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
    c[ImGuiCol_MenuBarBg]             = ImVec4(26 / 255.f, 26 / 255.f, 28 / 255.f, 1.0f);

    c[ImGuiCol_ScrollbarBg]           = ImVec4(0.02f, 0.02f, 0.02f, 0.0f);
    c[ImGuiCol_ScrollbarGrab]         = SCHEME_V;
    c[ImGuiCol_ScrollbarGrabHovered]  = SCHEME_V;
    c[ImGuiCol_ScrollbarGrabActive]   = SCHEME_V;

    c[ImGuiCol_CheckMark]             = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    c[ImGuiCol_SliderGrab]            = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    c[ImGuiCol_SliderGrabActive]      = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);

    c[ImGuiCol_Button]                = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
    c[ImGuiCol_ButtonHovered]         = ImVec4(1.0f, 1.0f, 1.0f, 0.10f);
    c[ImGuiCol_ButtonActive]          = ImVec4(1.0f, 1.0f, 1.0f, 0.18f);

    c[ImGuiCol_Header]                = ImVec4(35 / 255.f, 35 / 255.f, 38 / 255.f, 1.0f);
    c[ImGuiCol_HeaderHovered]         = ImVec4(1.0f, 1.0f, 1.0f, 0.12f);
    c[ImGuiCol_HeaderActive]          = ImVec4(1.0f, 1.0f, 1.0f, 0.20f);

    c[ImGuiCol_Separator]             = ImVec4(1.0f, 1.0f, 1.0f, 10 / 255.f);
    c[ImGuiCol_SeparatorHovered]      = SCHEME_V;
    c[ImGuiCol_SeparatorActive]       = SCHEME_V;

    c[ImGuiCol_ResizeGrip]            = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_ResizeGripHovered]     = SCHEME_V;
    c[ImGuiCol_ResizeGripActive]      = SCHEME_V;

    c[ImGuiCol_Tab]                   = ImVec4(40 / 255.f, 41 / 255.f, 43 / 255.f, 1.0f);
    c[ImGuiCol_TabHovered]            = SCHEME_V;
    c[ImGuiCol_TabActive]             = SCHEME_HOVER_V;

    c[ImGuiCol_PlotLines]             = SCHEME_V;
    c[ImGuiCol_PlotLinesHovered]      = SCHEME_HOVER_V;
    c[ImGuiCol_PlotHistogram]         = SCHEME_V;
    c[ImGuiCol_PlotHistogramHovered]  = SCHEME_HOVER_V;

    c[ImGuiCol_TextSelectedBg]        = ImVec4(1.0f, 1.0f, 1.0f, 40 / 255.f);
    c[ImGuiCol_NavHighlight]          = SCHEME_V;

    s.WindowRounding    = 0.0f;
    s.WindowPadding     = ImVec2(0, 0);
    s.WindowBorderSize  = 0.0f;
    s.ChildRounding     = 4.0f;
    s.ChildBorderSize   = 0.0f;
    s.FrameRounding     = 3.0f;

    s.FramePadding      = ImVec2(12, 10);
    s.FrameBorderSize   = 0.0f;
    s.PopupRounding     = 3.0f;
    s.PopupBorderSize   = 0.0f;

    s.ItemSpacing       = ImVec2(16, 12);
    s.ItemInnerSpacing  = ImVec2(8, 8);
    s.ScrollbarRounding = 4.0f;
    s.ScrollbarSize     = 4.0f;
    s.GrabRounding      = 3.0f;
    s.GrabMinSize       = 8.0f;
    s.IndentSpacing     = 14.0f;
    s.TabRounding       = 3.0f;

    s.AntiAliasedLines  = true;
    s.AntiAliasedFill   = true;
}
static ImFont* SafeLoadFont(const char* Path, float Size, const ImFontConfig* Cfg = nullptr, const ImWchar* Ranges = nullptr) {
    if (!Path) return nullptr;
    DWORD Attr = GetFileAttributesA(Path);
    if (Attr == INVALID_FILE_ATTRIBUTES) return nullptr;
    if (Attr & FILE_ATTRIBUTE_DIRECTORY) return nullptr;
    return ImGui::GetIO().Fonts->AddFontFromFileTTF(Path, Size, Cfg, Ranges);
}

static void init_imgui(IDirect3DDevice9* pDevice) {
    D3DDEVICE_CREATION_PARAMETERS cp = {};
    pDevice->GetCreationParameters(&cp);

    HWND hwnd = cp.hFocusWindow;
    if (!hwnd) {
        __try { hwnd = *(HWND*)0x00C97C1C; } __except (EXCEPTION_EXECUTE_HANDLER) { hwnd = nullptr; }
    }
    if (!hwnd) hwnd = FindWindowA("Grand theft auto San Andreas", nullptr);
    if (!hwnd || !IsWindow(hwnd)) return;
    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != GetCurrentProcessId()) return;
    g_game_hwnd = hwnd;
    g_stream_proof_ready = true;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;

    char win_dir[MAX_PATH] = { 0 };
    GetWindowsDirectoryA(win_dir, MAX_PATH);
    char arial_r[MAX_PATH], arial_b[MAX_PATH];
    snprintf(arial_r, sizeof(arial_r), "%s\\Fonts\\arial.ttf",   win_dir);
    snprintf(arial_b, sizeof(arial_b), "%s\\Fonts\\arialbd.ttf", win_dir);

    g_font_regular = SafeLoadFont(arial_r, 14.0f);
    if (!g_font_regular) g_font_regular = io.Fonts->AddFontDefault();
    g_font_header  = SafeLoadFont(arial_b, 18.0f);
    if (!g_font_header)  g_font_header  = g_font_regular;
    g_font_tabs    = SafeLoadFont(arial_b, 12.0f);
    if (!g_font_tabs)    g_font_tabs    = g_font_regular;

    g_font_esp_name = SafeLoadFont(arial_b, ESP_NAME_FONT_SIZE);
    if (!g_font_esp_name)
        g_font_esp_name = g_font_header ? g_font_header : g_font_regular;

    ImFontConfig icon_cfg;
    static const ImWchar icon_ranges[] = { 0xf000, 0xf8ff, 0 };
    icon_cfg.GlyphRanges = icon_ranges;
    icon_cfg.PixelSnapH  = true;

    g_font_icons = io.Fonts->AddFontFromMemoryCompressedTTF(
        (const void*)FA_solid_900_data,
        (int)FA_solid_900_size,
        16.0f,
        &icon_cfg,
        icon_ranges);

    if (!g_font_icons) {
        g_font_icons = io.Fonts->AddFontFromMemoryCompressedTTF(
            (const void*)FA_regular_400_data,
            (int)FA_regular_400_size,
            16.0f,
            &icon_cfg,
            icon_ranges);
    }
    if (!g_font_icons) g_font_icons = g_font_regular;
    g_icon_font_size = 16.0f;

    ImGui_ImplWin32_Init(hwnd);

    ImGui_ImplDX9_Init(pDevice);

    ImGui::StyleColorsDark();
    apply_theme();

    ImGui::GetStyle().ScaleAllSizes(0.86f);

    g_o_wndproc = (WNDPROC)SetWindowLongPtrA(hwnd, GWLP_WNDPROC, (LONG_PTR)hk_wndproc);
    g_imgui_init = true;
    mta_logf("ui", "ImGui pronto: hwnd=%p regular=%p header=%p tabs=%p esp=%p icons=%p",
             (void*)g_game_hwnd, (void*)g_font_regular, (void*)g_font_header,
             (void*)g_font_tabs, (void*)g_font_esp_name, (void*)g_font_icons);
}

struct Vec3 { float x, y, z; };

#define ADDR_LOCAL_PLAYER_PRIMARY   0xB6F5F0
#define ADDR_LOCAL_PLAYER_FALLBACK  0xB7CD98
#define PED_OFF_MATRIX       0x14
#define PED_OFF_HEALTH       0x540
#define PED_OFF_MAX_HEALTH   0x544
#define PED_OFF_ARMOR        0x548
#define PED_OFF_PHYS_FLAGS   0x40
#define PED_OFF_MOVE_SPEED   0x44
#define PED_OFF_TURN_SPEED   0x50
#define PED_OFF_WEAPONS      0x5A0
#define PED_WEAPON_STRIDE    0x1C
#define PED_OFF_WEAPON_SLOT  0x718
#define PED_OFF_VEHICLE      0x58C
#define W_OFF_TYPE           0x0
#define W_OFF_CLIP           0x8
#define W_OFF_TOTAL          0xC
#define INFINITE_AMMO_VALUE  9999
#define CMTX_OFF_POS         0x30

using CPed_GetBonePosition_t = Vec3* (__thiscall*)(void* thisptr, Vec3* out, int boneId, bool includeAnim);
static const CPed_GetBonePosition_t CPed_GetBonePosition = (CPed_GetBonePosition_t)0x5E4280;

static inline bool is_valid_ptr(uint32_t p) {
    return p >= 0x10000 && p <= 0x7FFFFFFF;
}

static uint32_t get_local_ped() {
    auto validate = [](uint32_t p) -> bool {
        if (!is_valid_ptr(p)) return false;
        __try {
            uint32_t matrix = *(uint32_t*)(p + PED_OFF_MATRIX);
            if (!is_valid_ptr(matrix)) return false;
            float hp = *(float*)(p + PED_OFF_HEALTH);
            if (hp < 0.0f || hp > 10000.0f) return false;
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    };

    __try {
        uint32_t p = *(uint32_t*)ADDR_LOCAL_PLAYER_FALLBACK;
        if (validate(p)) return p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try {
        uint32_t p = *(uint32_t*)ADDR_LOCAL_PLAYER_PRIMARY;
        if (validate(p)) return p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    return 0;
}

static void fly_physics_end() {
    if (!g_fly_phys_saved) return;
    g_fly_phys_saved = false;
    g_fly_hover_valid = false;
    uint32_t ped = get_local_ped();
    if (!is_valid_ptr(ped) || ped != g_fly_phys_ped) {
        g_fly_hover_valid = false;
        return;
    }
    __try {
        uint32_t* flags = (uint32_t*)(uintptr_t)(ped + PED_OFF_PHYS_FLAGS);
        float* mv = (float*)(uintptr_t)(ped + PED_OFF_MOVE_SPEED);
        float* tv = (float*)(uintptr_t)(ped + PED_OFF_TURN_SPEED);
        uint32_t f = *flags;
        *flags = (f & ~0x00000006u) | (g_fly_phys_flags & 0x00000006u);
        mv[0] = mv[1] = mv[2] = 0.0f;
        tv[0] = tv[1] = tv[2] = 0.0f;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void fly_physics_apply(uint32_t ped, float fdx, float fdy, float fdz, float dt) {
    if (!is_valid_ptr(ped)) return;
    __try {
        uint32_t* flags = (uint32_t*)(uintptr_t)(ped + PED_OFF_PHYS_FLAGS);
        float* mv = (float*)(uintptr_t)(ped + PED_OFF_MOVE_SPEED);
        float* tv = (float*)(uintptr_t)(ped + PED_OFF_TURN_SPEED);
        float* hp = (float*)(uintptr_t)(ped + PED_OFF_HEALTH);
        float* ar = (float*)(uintptr_t)(ped + PED_OFF_ARMOR);
        uint32_t f = *flags;
        if (g_fly_phys_saved && g_fly_phys_ped != ped) g_fly_phys_saved = false;
        if (!g_fly_phys_saved) {
            g_fly_phys_ped     = ped;
            g_fly_phys_flags   = f & 0x00000006u;
            g_fly_hp_saved     = *hp;
            g_fly_armor_saved  = *ar;
            if (!(g_fly_hp_saved > 0.0f && g_fly_hp_saved < 10000.0f)) g_fly_hp_saved = 100.0f;
            if (!(g_fly_armor_saved >= 0.0f && g_fly_armor_saved < 1000.0f)) g_fly_armor_saved = 0.0f;
            g_fly_phys_saved = true;
            mta_logf("fly", "fisica OFF flags=%08X hp=%.0f armor=%.0f",
                     (unsigned)f, g_fly_hp_saved, g_fly_armor_saved);
        }
        *flags = (f & ~0x00000002u) | 0x00000004u;

        float vmag = sqrtf(fdx*fdx + fdy*fdy + fdz*fdz);
        if (vmag > 0.0001f && dt > 0.0001f) {
            float v = vmag / dt;

            if (v > 160.0f) v = 160.0f;
            mv[0] = fdx / vmag * v;
            mv[1] = fdy / vmag * v;
            mv[2] = fdz / vmag * v;
        } else {
            mv[0] = mv[1] = mv[2] = 0.0f;
        }
        tv[0] = tv[1] = tv[2] = 0.0f;
        if (*hp < g_fly_hp_saved && *hp > -1000.0f) *hp = g_fly_hp_saved;
        if (*ar < g_fly_armor_saved && *ar > -1000.0f) *ar = g_fly_armor_saved;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void fly_camera_axes(const float* pos, float* fwd, float* right, bool& ok) {
    ok = false;
    if (!g_have_3d) return;
    const D3DMATRIX& v = g_3d_view;
    D3DMATRIX m = {};
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            m.m[i][j] = v.m[i][0]*g_3d_proj.m[0][j] + v.m[i][1]*g_3d_proj.m[1][j]
                      + v.m[i][2]*g_3d_proj.m[2][j] + v.m[i][3]*g_3d_proj.m[3][j];
    float cand[4][3] = {
        {  v.m[0][2],  v.m[1][2],  v.m[2][2] },
        { -v.m[0][2], -v.m[1][2], -v.m[2][2] },
        {  v.m[2][0],  v.m[2][1],  v.m[2][2] },
        { -v.m[2][0], -v.m[2][1], -v.m[2][2] }
    };
    float best = 1.0e30f;
    int bi = -1;
    for (int k = 0; k < 4; ++k) {
        float d[3] = { cand[k][0], cand[k][1], cand[k][2] };
        float l = sqrtf(d[0]*d[0] + d[1]*d[1] + d[2]*d[2]);
        if (l < 0.0001f) continue;
        d[0] /= l; d[1] /= l; d[2] /= l;
        float qx = pos[0] + d[0]*64.0f;
        float qy = pos[1] + d[1]*64.0f;
        float qz = pos[2] + d[2]*64.0f;
        float cx = qx*m.m[0][0] + qy*m.m[1][0] + qz*m.m[2][0] + m.m[3][0];
        float cy = qx*m.m[0][1] + qy*m.m[1][1] + qz*m.m[2][1] + m.m[3][1];
        float cw = qx*m.m[0][3] + qy*m.m[1][3] + qz*m.m[2][3] + m.m[3][3];
        if (cw < 0.05f) continue;
        float nx = cx / cw, ny = cy / cw;
        float score = nx*nx + ny*ny;
        if (score < best) { best = score; bi = k; }
    }
    if (bi < 0 || best > 25.0f) bi = 0;
    if (bi != g_fly_axis_idx) {
        g_fly_axis_idx = bi;
        mta_logf("fly", "eixo camera conv=%d sign=%d score=%.2f",
                 bi < 2 ? 0 : 1, (bi % 2) ? -1 : 1, best);
    }
    float sg = (bi % 2) ? -1.0f : 1.0f;
    if (bi < 2) {
        fwd[0]   = sg*v.m[0][2]; fwd[1]   = sg*v.m[1][2]; fwd[2]   = sg*v.m[2][2];
        right[0] =    v.m[0][0]; right[1] =    v.m[1][0]; right[2] =    v.m[2][0];
    } else {
        fwd[0]   = sg*v.m[2][0]; fwd[1]   = sg*v.m[2][1]; fwd[2]   = sg*v.m[2][2];
        right[0] =    v.m[0][0]; right[1] =    v.m[0][1]; right[2] =    v.m[0][2];
    }
    float lf = sqrtf(fwd[0]*fwd[0] + fwd[1]*fwd[1] + fwd[2]*fwd[2]);
    if (lf < 0.0001f) return;
    fwd[0] /= lf; fwd[1] /= lf; fwd[2] /= lf;
    float dot = right[0]*fwd[0] + right[1]*fwd[1] + right[2]*fwd[2];
    right[0] -= fwd[0]*dot; right[1] -= fwd[1]*dot; right[2] -= fwd[2]*dot;
    float lr = sqrtf(right[0]*right[0] + right[1]*right[1] + right[2]*right[2]);
    if (lr < 0.0001f) return;
    right[0] /= lr; right[1] /= lr; right[2] /= lr;
    ok = true;
}

static float fly_camera_pitch() {
    __try {
        uint8_t active = *(uint8_t*)0xB6F081u;
        if (active >= 3) return 1000.0f;
        uint32_t cam = 0xB6F19Cu + (uint32_t)active * 0x238u;
        volatile float* pitch = (volatile float*)(cam + 0xACu);
        float cp = *pitch;
        if (cp > -20.0f && cp < 20.0f) return cp;
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
    return 1000.0f;
}

static bool get_ped_world_pos(uint32_t ped, Vec3& out) {
    if (!is_valid_ptr(ped)) return false;
    __try {
        uint32_t matrix = *(uint32_t*)(ped + PED_OFF_MATRIX);
        float* pos = is_valid_ptr(matrix) ? (float*)(matrix + CMTX_OFF_POS)
                                          : (float*)(ped + 0x04);
        float x = pos[0], y = pos[1], z = pos[2];
        if (x == 0.0f && y == 0.0f && z == 0.0f) {
            if (is_valid_ptr(matrix)) {
                float* fallback_pos = (float*)(ped + 0x04);
                x = fallback_pos[0]; y = fallback_pos[1]; z = fallback_pos[2];
            }
            if (x == 0.0f && y == 0.0f && z == 0.0f) return false;
        }
        if (!(x > -16000.0f && x < 16000.0f)) return false;
        if (!(y > -16000.0f && y < 16000.0f)) return false;
        if (!(z > -5000.0f  && z < 10000.0f)) return false;
        out.x = x; out.y = y; out.z = z;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool get_local_player_pos(Vec3& out, float& hp, float& max_hp, float& armor) {
    __try {
        uint32_t ped = get_local_ped();
        if (!is_valid_ptr(ped)) return false;
        if (!get_ped_world_pos(ped, out)) return false;
        hp     = *(float*)(ped + PED_OFF_HEALTH);
        max_hp = *(float*)(ped + PED_OFF_MAX_HEALTH);
        if (max_hp < 1.0f || max_hp > 10000.0f) max_hp = 100.0f;
        if (hp < 0.0f || hp > max_hp * 2.0f) hp = max_hp;
        armor = *(float*)(ped + PED_OFF_ARMOR);
        if (armor < 0.0f || armor > 500.0f) armor = 0.0f;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool get_bone_pos(uint32_t ped, int bone_id, Vec3& out) {
    __try {
        uint32_t rw_obj = *(uint32_t*)(ped + 0x18);
        if (!is_valid_ptr(rw_obj)) return false;
        Vec3 tmp = {};
        Vec3* ret = CPed_GetBonePosition((void*)ped, &tmp, bone_id, true);
        if (!ret) return false;
        if (!(tmp.x > -16000.0f && tmp.x < 16000.0f &&
              tmp.y > -16000.0f && tmp.y < 16000.0f &&
              tmp.z > -5000.0f  && tmp.z < 10000.0f)) return false;
        out = tmp;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool world_to_screen(IDirect3DDevice9* dev, const Vec3& w, float& sx, float& sy) {
    D3DVIEWPORT9 vp;
    if (FAILED(dev->GetViewport(&vp)) || vp.Width == 0 || vp.Height == 0) return false;

    __try {
        const float* cm = (const float*)0xB6FA2C;
        float m11 = cm[0],  m12 = cm[1],  m13 = cm[2];
        float m21 = cm[4],  m22 = cm[5],  m23 = cm[6];
        float m31 = cm[8],  m32 = cm[9],  m33 = cm[10];
        float m41 = cm[12], m42 = cm[13], m43 = cm[14];

        if (m11 != 0.0f || m22 != 0.0f || m33 != 0.0f) {
            float rx = w.z * m31 + w.y * m21 + w.x * m11 + m41;
            float ry = w.z * m32 + w.y * m22 + w.x * m12 + m42;
            float rz = w.z * m33 + w.y * m23 + w.x * m13 + m43;
            if (rz < 0.05f) return false;

            float inv = 1.0f / rz;
            sx = rx * inv * (float)vp.Width  + (float)vp.X;
            sy = ry * inv * (float)vp.Height + (float)vp.Y;
            return (sx > -1.0e6f && sx < 1.0e6f && sy > -1.0e6f && sy < 1.0e6f);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    D3DMATRIX view, proj;
    if (g_have_3d) { view = g_3d_view; proj = g_3d_proj; }
    else {
        if (FAILED(dev->GetTransform(D3DTS_VIEW, &view))) return false;
        if (FAILED(dev->GetTransform(D3DTS_PROJECTION, &proj))) return false;
    }
    D3DMATRIX m;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            m.m[i][j] = view.m[i][0]*proj.m[0][j] + view.m[i][1]*proj.m[1][j]
                      + view.m[i][2]*proj.m[2][j] + view.m[i][3]*proj.m[3][j];
    float cx = w.x*m.m[0][0] + w.y*m.m[1][0] + w.z*m.m[2][0] + m.m[3][0];
    float cy = w.x*m.m[0][1] + w.y*m.m[1][1] + w.z*m.m[2][1] + m.m[3][1];
    float cw = w.x*m.m[0][3] + w.y*m.m[1][3] + w.z*m.m[2][3] + m.m[3][3];
    if (cw < 0.05f) return false;
    float inv = 1.0f / cw;
    sx = (cx * inv * 0.5f + 0.5f) * vp.Width  + vp.X;
    sy = (-cy * inv * 0.5f + 0.5f) * vp.Height + vp.Y;
    return (sx > -1.0e6f && sx < 1.0e6f && sy > -1.0e6f && sy < 1.0e6f);
}

struct BonePair { int a; int b; };
static const BonePair SKELETON_PAIRS[] = {
    { 4, 5 }, { 5, 6 },
    { 4, 21 }, { 21, 22 }, { 22, 23 }, { 23, 24 }, { 24, 25 },
    { 4, 31 }, { 31, 32 }, { 32, 33 }, { 33, 34 }, { 34, 35 },
    { 2, 3 }, { 3, 4 },
    { 2, 41 }, { 41, 42 }, { 42, 43 }, { 43, 44 },
    { 2, 51 }, { 51, 52 }, { 52, 53 }, { 53, 54 },
};

static ImU32 health_color_dynamic(float hp_pct) {
    if (hp_pct >= 0.65f) return IM_COL32(  0, 255,   0, 230);
    if (hp_pct >= 0.40f) return IM_COL32(255, 255,   0, 230);
    if (hp_pct >= 0.20f) return IM_COL32(255, 165,   0, 230);
    return                     IM_COL32(255,   0,   0, 230);
}

static void infinite_ammo_update() {
    if (!g_infinite_ammo) return;
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    if (!session_live()) return;
    uint32_t ped = get_local_ped();
    if (!is_valid_ptr(ped)) return;
    __try {
        uint8_t slot = *(uint8_t*)(ped + PED_OFF_WEAPON_SLOT);
        if (slot > 12) return;
        uint32_t w = ped + PED_OFF_WEAPONS + (uint32_t)slot * PED_WEAPON_STRIDE;
        uint32_t type = *(uint32_t*)(w + W_OFF_TYPE);
        if (type > 46) return;
        uint32_t* clip  = (uint32_t*)(w + W_OFF_CLIP);
        uint32_t* total = (uint32_t*)(w + W_OFF_TOTAL);
        if (*clip  < INFINITE_AMMO_VALUE) *clip  = INFINITE_AMMO_VALUE;
        if (*total < INFINITE_AMMO_VALUE) *total = INFINITE_AMMO_VALUE;
        if (!g_ammo_logged) {
            g_ammo_logged = true;
            mta_logf("ammo", "infinite ammo ON: ped=%08X slot=%u type=%u -> clip/total=%d",
                     (unsigned)ped, (unsigned)slot, (unsigned)type, (int)INFINITE_AMMO_VALUE);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}
static void fly_update(float dt) {
    g_fly_active = false;
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) { fly_physics_end(); return; }
    if (!session_live()) return;
    if (!g_fly_enable) {
        g_fly_toggle_on = false;
        g_fly_key_edge = false;
        g_fly_pitch_init = false;
        g_fly_pitch_axis = -1;
        fly_physics_end();
        return;
    }
    if (g_fly_mode != FLY_MODE_TOGGLE) g_fly_mode = FLY_MODE_HOLD;

    bool down = bind_is_down(g_fly_key_vk);
    bool flying;
    if (g_fly_mode == FLY_MODE_TOGGLE) {
        if (down && !g_fly_key_edge) {
            g_fly_toggle_on = !g_fly_toggle_on;
            g_fly_hover_valid = false;
            if (mta_log_tick(5, 300))
                mta_logf("fly", "toggle %s", g_fly_toggle_on ? "ON" : "OFF");
            notify_push("Fly", TROLL_ICON_GLYPH, true,
                        g_fly_toggle_on ? "Fly Habilitado" : "Fly Desabilitado");
        }
        g_fly_key_edge = down;
        flying = g_fly_toggle_on;
    } else {
        g_fly_toggle_on = false;
        g_fly_key_edge = down;
        flying = down;
    }
    if (!flying) {
        g_fly_veh_logged = false;
        g_fly_pitch_init = false;
        g_fly_pitch_axis = -1;
        fly_physics_end();
        return;
    }
    g_fly_active = true;

    float f = 0.0f, s = 0.0f, u = 0.0f;
    if (bind_is_down('W')) f += 1.0f;
    if (bind_is_down('S')) f -= 1.0f;
    if (bind_is_down('D')) s += 1.0f;
    if (bind_is_down('A')) s -= 1.0f;
    if (bind_is_down(VK_SPACE))   u += 1.0f;
    if (bind_is_down(VK_CONTROL)) u -= 1.0f;
    bool has_input = (f != 0.0f || s != 0.0f || u != 0.0f);
    float boost = bind_is_down(VK_SHIFT) ? 1.6f : 1.0f;

    if (dt <= 0.0f || dt > 0.1f) dt = 1.0f / 60.0f;
    uint32_t ped = get_local_ped();
    if (!is_valid_ptr(ped)) { fly_physics_end(); return; }
    uint32_t in_veh = 0;
    __try { in_veh = *(uint32_t*)(ped + PED_OFF_VEHICLE); } __except (EXCEPTION_EXECUTE_HANDLER) { in_veh = 0; }
    if (is_valid_ptr(in_veh)) {
        if (!g_fly_veh_logged) {
            g_fly_veh_logged = true;
            mta_logf("fly", "dentro do veiculo %08X: o fly do ped nao move o carro", (unsigned)in_veh);
        }
        g_fly_active = false;
        fly_physics_end();
        return;
    }
    g_fly_veh_logged = false;
    __try {
        uint32_t matrix = *(uint32_t*)(uintptr_t)(ped + PED_OFF_MATRIX);
        bool has_mtx = is_valid_ptr(matrix);
        float* pos = has_mtx ? (float*)(uintptr_t)(matrix + CMTX_OFF_POS)
                             : (float*)(uintptr_t)(ped + 0x04);
        if (!pos[0] && !pos[1] && !pos[2]) return;
        if (!(pos[0] > -16000.0f && pos[0] < 16000.0f &&
              pos[1] > -16000.0f && pos[1] < 16000.0f &&
              pos[2] > -5000.0f  && pos[2] < 10000.0f)) return;

        float ddx = pos[0] - g_fly_hover_pos[0];
        float ddy = pos[1] - g_fly_hover_pos[1];
        float ddz = pos[2] - g_fly_hover_pos[2];
        if (!g_fly_hover_valid || (ddx*ddx + ddy*ddy + ddz*ddz) > 160000.0f) {
            g_fly_hover_pos[0] = pos[0];
            g_fly_hover_pos[1] = pos[1];
            g_fly_hover_pos[2] = pos[2];
            g_fly_hover_valid = true;
        }

        float fwd[3]   = { 0.0f, 1.0f, 0.0f };
        float right[3] = { 1.0f, 0.0f, 0.0f };
        bool cam_ok = false;
        fly_camera_axes(g_fly_hover_pos, fwd, right, cam_ok);
        if (!cam_ok && has_mtx) {
            float* rv = (float*)(uintptr_t)(matrix + 0x00);
            float* fv = (float*)(uintptr_t)(matrix + 0x10);
            fwd[0] = fv[0]; fwd[1] = fv[1]; fwd[2] = fv[2];
            right[0] = rv[0]; right[1] = rv[1]; right[2] = rv[2];
            float lf = sqrtf(fwd[0]*fwd[0] + fwd[1]*fwd[1] + fwd[2]*fwd[2]);
            if (lf > 0.0001f) {
                fwd[0] /= lf; fwd[1] /= lf; fwd[2] /= lf;
                cam_ok = true;
            }
        }
        if (!cam_ok && has_input && mta_log_tick(6, 3000))
            mta_logf("fly", "sem view matrix: direcao pela matriz do ped");

        if (cam_ok) {
            float lh = sqrtf(fwd[0]*fwd[0] + fwd[1]*fwd[1]);
            if (lh > 0.0001f) { fwd[0] /= lh; fwd[1] /= lh; }
            else               { fwd[0] = 0.0f; fwd[1] = 1.0f; }
            fwd[2] = 0.0f;
            float lr = sqrtf(right[0]*right[0] + right[1]*right[1]);
            if (lr > 0.0001f) { right[0] /= lr; right[1] /= lr; }
            else              { right[0] = 1.0f; right[1] = 0.0f; }
            right[2] = 0.0f;
        }
        if (has_input) {
            float dx, dy, dz;
            if (cam_ok) {
                dx = fwd[0]*f + right[0]*s;
                dy = fwd[1]*f + right[1]*s;
                dz = u;
            } else {
                dx = right[0]*s;
                dy = f;
                dz = u;
            }
            float len = sqrtf(dx*dx + dy*dy + dz*dz);
            if (len >= 0.0001f) {
                dx /= len; dy /= len; dz /= len;
                float step = g_fly_speed * boost * dt;
                g_fly_hover_pos[0] += dx * step;
                g_fly_hover_pos[1] += dy * step;
                g_fly_hover_pos[2] += dz * step;
            }
        }

        {

            float ddx = g_fly_hover_pos[0] - pos[0];
            float ddy = g_fly_hover_pos[1] - pos[1];
            float ddz = g_fly_hover_pos[2] - pos[2];
            if (ddx*ddx + ddy*ddy + ddz*ddz > 160000.0f) {
                g_fly_hover_pos[0] = pos[0];
                g_fly_hover_pos[1] = pos[1];
                g_fly_hover_pos[2] = pos[2];
            }

            pos[0] = g_fly_hover_pos[0];
            pos[1] = g_fly_hover_pos[1];
            pos[2] = g_fly_hover_pos[2];
            fly_physics_apply(ped, 0.0f, 0.0f, 0.0f, dt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { g_fly_active = false; }
}

#define ADDR_PED_POOL        0xB74490
#define POOL_OBJ_OFF         0x00
#define POOL_FLAG_OFF        0x04
#define POOL_SIZE_OFF        0x08
#define PED_STRIDE           0x7C4

#define MTA_MAX_VEHICLES       110
#define MTA_MAX_PEDS           140
#define MTA_MAX_OBJECTS        1200
#define MTA_SCLIENT_SIZE       8
#define MTA_SPOOL_DATA(n)      ((n) * MTA_SCLIENT_SIZE + 4)
#define MTA_VPTR_SIZE          4
#define MTA_PED_ARRAY_OFF      (MTA_VPTR_SIZE + MTA_SPOOL_DATA(MTA_MAX_VEHICLES))
#define MTA_POOL_PTRS_OFF      (MTA_PED_ARRAY_OFF + MTA_SPOOL_DATA(MTA_MAX_PEDS) + \
                                MTA_SPOOL_DATA(MTA_MAX_OBJECTS))
#define MTA_PED_STRIDE         1988
#define MTA_CLASS_CPOOL_OBJECT  0xB7449C
#define MTA_CLASS_CPOOL_VEHICLE 0xB74494
#define MTA_VT_GETPLAYERNAMES  10
#define MTA_SSTRING_SIZE       24
#define MTA_MAX_NAMES          256
#define MTA_NICK_SCAN_END      0x1000

static uint32_t g_mta_client_obj    = 0;
static uint32_t g_mta_client_vt     = 0;
static uint32_t g_mta_pools_ptr     = 0;
static uint32_t g_mta_nick_off      = 0;
static bool     g_mta_type_relaxed = false;
static int      g_mta_calib_ents   = 0;
static uint32_t g_mta_last_refresh  = 0;
static uint32_t g_mta_last_calib    = 0;
static uint32_t g_mta_pool_sig_off   = 0;
static uint32_t g_mta_pools_fail_tick = 0;
static bool     g_mta_official_disable = false;

#define NICK_CACHE_SIZE   256
#define NICK_CACHE_TTL    400
struct MtaNickEntry { uint32_t ped; uint32_t tick; char nick[48]; bool valid; };
static MtaNickEntry g_mta_nick_ttl[NICK_CACHE_SIZE] = {};

struct MtaNameVector { uint32_t first, last, end; };
static uint8_t       g_mta_name_storage[MTA_MAX_NAMES * 32];
static MtaNameVector g_mta_name_vec = {};
static bool          g_mta_name_vec_inited = false;
static char          g_mta_official_names[MTA_MAX_NAMES][48];
static int           g_mta_official_count = 0;

static uint32_t rd32(uint32_t addr) {
    if (!is_valid_ptr(addr)) return 0;
    __try { return *(uint32_t*)(uintptr_t)addr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static bool get_module_bounds(const char* mod_name, uint32_t& base_out, uint32_t& end_out) {
    HMODULE hMod = GetModuleHandleA(mod_name);
    if (!hMod) return false;
    __try {
        uint32_t base = (uint32_t)(uintptr_t)hMod;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        base_out = base;
        end_out  = base + nt->OptionalHeader.SizeOfImage;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void mta_writable_range(uint32_t base, uint32_t end, uint32_t& s_out, uint32_t& e_out) {
    s_out = e_out = 0;
    __try {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
            if ((sec[s].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sec[s].Characteristics & IMAGE_SCN_MEM_READ)) {
                uint32_t a = base + sec[s].VirtualAddress;
                uint32_t b = a + sec[s].Misc.VirtualSize;
                if (b > end) b = end;
                if (b > a) { s_out = a; e_out = b; return; }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static bool read_msvc_string(uint32_t addr, char* out, uint32_t out_max,
                             uint32_t min_len = 1, uint32_t max_len = 63) {
    if (!is_valid_ptr(addr) || !out || out_max < 2) return false;
    __try {
        uint32_t size = *(uint32_t*)(uintptr_t)(addr + 0x10);
        uint32_t cap  = *(uint32_t*)(uintptr_t)(addr + 0x14);
        if (size < min_len || size > max_len || size >= out_max) return false;
        if (cap < 15 || cap > 255 || size > cap) return false;
        const char* str_ptr;
        if (cap == 15) {
            str_ptr = (const char*)(uintptr_t)addr;
        } else {
            uint32_t heap_ptr = *(uint32_t*)(uintptr_t)addr;
            if (!is_valid_ptr(heap_ptr)) return false;
            str_ptr = (const char*)(uintptr_t)heap_ptr;
        }
        if (str_ptr[size] != '\0') return false;
        for (uint32_t i = 0; i < size; ++i) {
            uint8_t ch = (uint8_t)str_ptr[i];
            if (ch < 0x20 || ch == 0x7F) return false;
        }
        memcpy(out, str_ptr, size);
        out[size] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool is_placeholder_nick(const char* s) {
    if (!s || !s[0]) return true;
    return strcmp(s, "Default") == 0 || strcmp(s, "player") == 0 ||
           strcmp(s, "Player")  == 0 || strcmp(s, "PLAYER") == 0 ||
           strcmp(s, "ped")     == 0 || strcmp(s, "Local")  == 0;
}

static int mta_stricmp(const char* a, const char* b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (int)ca - (int)cb;
        ++a; ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static const char* mta_strip_color(const char* s) {
    while (s[0] == '#') {
        bool ok = true;
        for (int k = 1; k <= 6; ++k) {
            char c = s[k];
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) { ok = false; break; }
        }
        if (!ok) break;
        s += 7;
    }
    return s;
}

static uint32_t mta_client_base() {
    if (g_mta_client_obj) return g_mta_client_obj;
    uint32_t cb = 0, ce = 0;
    if (!get_module_bounds("client.dll", cb, ce)) return 0;
    uint8_t* exp = (uint8_t*)GetProcAddress((HMODULE)(uintptr_t)cb, "InitClient");
    if (!exp) return 0;
    uint32_t ds = 0, de = 0;
    mta_writable_range(cb, ce, ds, de);
    if (!ds) return 0;
    for (int i = 0; i < 192; ++i) {
        uint32_t cand = rd32((uint32_t)(uintptr_t)(exp + i));
        if (cand < ds || cand + 4 > de) continue;
        uint32_t obj = rd32(cand);
        if (!is_valid_ptr(obj)) continue;
        uint32_t vt = rd32(obj);
        if (vt < cb || vt + (MTA_VT_GETPLAYERNAMES + 1) * 4 > ce) continue;
        uint32_t fn = rd32(vt + MTA_VT_GETPLAYERNAMES * 4);
        if (fn < cb || fn >= ce) continue;
        g_mta_client_obj = obj;
        g_mta_client_vt  = vt;
        return obj;
    }
    return 0;
}

static int mta_refresh_player_names() {
    uint32_t base = mta_client_base();
    uint32_t cb = 0, ce = 0;
    if (!base || !get_module_bounds("client.dll", cb, ce)) return 0;
    if (g_mta_official_disable) return 0;
    uint32_t vt = rd32(base);
    if (vt < cb || vt >= ce) return 0;
    uint32_t fn = rd32(vt + MTA_VT_GETPLAYERNAMES * 4);
    if (fn < cb || fn >= ce) return 0;

    if (!g_mta_name_vec_inited) {
        g_mta_name_vec.first = (uint32_t)(uintptr_t)g_mta_name_storage;
        g_mta_name_vec.end   = g_mta_name_vec.first + sizeof(g_mta_name_storage);
        g_mta_name_vec_inited = true;
    }
    // FIX OOM: resetar .last SEMPRE. Sem isso, GetPlayerNames appenda em .last
    // cumulativamente → .last > .end → escrita fora de g_mta_name_storage
    // (8 KB) → corrupção de heap adjacente (aparece como "out of memory").
    g_mta_name_vec.last = g_mta_name_vec.first;

    typedef void (__thiscall* MtaGetNamesFn)(void*, void*);
    __try {
        ((MtaGetNamesFn)(uintptr_t)fn)((void*)(uintptr_t)base, &g_mta_name_vec);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    uint32_t first = g_mta_name_vec.first, last = g_mta_name_vec.last;
    if (last < first || last > g_mta_name_vec.end) { g_mta_official_disable = true; mta_logf("nick!", "layout SString divergente: lista oficial desligada"); return 0; }
    uint32_t used = last - first;
    if (used % MTA_SSTRING_SIZE != 0) {
        g_mta_official_disable = true;
        return 0;
    }
    int count = (int)(used / MTA_SSTRING_SIZE);
    if (count > MTA_MAX_NAMES) count = MTA_MAX_NAMES;

    g_mta_official_count = 0;
    for (int i = 0; i < count; ++i) {
        char raw[64] = {};
        g_mta_official_names[i][0] = '\0';
        if (!read_msvc_string(first + (uint32_t)i * MTA_SSTRING_SIZE,
                              raw, sizeof(raw), 1, 63)) continue;
        const char* s = mta_strip_color(raw);
        if (!s[0] || is_placeholder_nick(s)) continue;
        size_t len = strlen(s);
        if (len >= sizeof(g_mta_official_names[i])) len = sizeof(g_mta_official_names[i]) - 1;
        memcpy(g_mta_official_names[i], s, len);
        g_mta_official_names[i][len] = '\0';
        ++g_mta_official_count;
    }
    return g_mta_official_count;
}

static void troll_player_list_refresh() {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    static uint32_t last = 0;
    uint32_t now = GetTickCount();
    if (now - last < 1000) return;
    last = now ? now : 1;
    mta_refresh_player_names();
    int n = 0;
    for (int i = 0; i < g_mta_official_count && n < 64; ++i) {
        if (!g_mta_official_names[i][0]) continue;
        snprintf(g_troll_names[n], sizeof(g_troll_names[n]), "%s", g_mta_official_names[i]);
        ++n;
    }
    for (int i = n; i < 64; ++i) g_troll_names[i][0] = '\0';
    g_troll_count = n;
    bool found = false;
    for (int i = 0; i < g_troll_count; ++i)
        if (strcmp(g_troll_selected_name, g_troll_names[i]) == 0) { found = true; break; }
    if (!found) g_troll_selected_name[0] = '\0';
}

static bool mta_name_in_official_list(const char* s) {
    for (int i = 0; i < MTA_MAX_NAMES; ++i) {
        if (g_mta_official_names[i][0] && mta_stricmp(g_mta_official_names[i], s) == 0)
            return true;
    }
    return false;
}

static bool mta_sig_at(uint32_t pools, uint32_t off) {
    uint32_t a = pools + off;
    return rd32(a)     == ADDR_PED_POOL &&
           rd32(a + 4) == MTA_CLASS_CPOOL_OBJECT &&
           rd32(a + 8) == MTA_CLASS_CPOOL_VEHICLE;
}

static bool mta_cpools_valid(uint32_t pools, uint32_t gb, uint32_t ge) {
    if (!is_valid_ptr(pools)) return false;
    uint32_t vt = rd32(pools);
    if (vt < gb || vt >= ge) return false;
    if (g_mta_pool_sig_off) {
        if (mta_sig_at(pools, g_mta_pool_sig_off)) return true;
        g_mta_pool_sig_off = 0;
    }

    for (int32_t d = -0x1000; d <= 0x1000; d += 4) {
        uint32_t off = MTA_POOL_PTRS_OFF + (uint32_t)d;
        if (mta_sig_at(pools, off)) { g_mta_pool_sig_off = off; return true; }
    }
    for (uint32_t off = 0x400; off <= 0x8000; off += 4) {
        if (mta_sig_at(pools, off)) { g_mta_pool_sig_off = off; return true; }
    }
    return false;
}

static uint32_t mta_find_pools(uint32_t gb, uint32_t ge) {
    if (g_mta_pools_ptr && mta_cpools_valid(g_mta_pools_ptr, gb, ge)) return g_mta_pools_ptr;

    uint32_t now = GetTickCount();
    if (g_mta_pools_fail_tick && (now - g_mta_pools_fail_tick) < 3000) return 0;

    uint32_t ds = 0, de = 0;
    mta_writable_range(gb, ge, ds, de);

    uint32_t pGame = 0;
    uint8_t* exp = (uint8_t*)GetProcAddress((HMODULE)(uintptr_t)gb, "GetGameInterface");
    if (exp && ds) {
        for (int i = 0; i < 192 && !pGame; ++i) {
            uint32_t cand = rd32((uint32_t)(uintptr_t)(exp + i));
            if (cand < ds || cand + 4 > de) continue;
            uint32_t val = rd32(cand);
            if (!is_valid_ptr(val)) continue;
            uint32_t vt = rd32(val);
            if (vt >= gb && vt < ge) pGame = val;
        }
    }

    if (pGame) {
        for (uint32_t off = 4; off <= 0x800; off += 4) {
            uint32_t cand = rd32(pGame + off);
            if (!is_valid_ptr(cand)) continue;
            uint32_t vt = rd32(cand);
            if (vt < gb || vt >= ge) continue;
            if (mta_cpools_valid(cand, gb, ge)) {
                g_mta_pools_ptr = cand;
                mta_logf("pools", "CPoolsSA=%08X sigOff=%04X game_sa=%08X..%08X",
                         cand, g_mta_pool_sig_off, gb, ge);
                return cand;
            }
        }
    }

    if (ds && de) {
        uint32_t lim = de;
        if (lim > ds + 0x20000) lim = ds + 0x20000;
        for (uint32_t a = ds; a + 4 <= lim; a += 4) {
            uint32_t cand = rd32(a);
            if (!is_valid_ptr(cand)) continue;
            uint32_t vt = rd32(cand);
            if (vt < gb || vt >= ge) continue;
            if (mta_cpools_valid(cand, gb, ge)) {
                g_mta_pools_ptr = cand;
                mta_logf("pools", "CPoolsSA=%08X sigOff=%04X game_sa=%08X..%08X",
                         cand, g_mta_pool_sig_off, gb, ge);
                return cand;
            }
        }
    }
    g_mta_pools_fail_tick = now ? now : 1;
    if (mta_log_tick(3, 3000))
        mta_logf("pools!", "CPoolsSA nao encontrado; proxima tentativa em 3s");
    return 0;
}

static bool mta_is_client_player(uint32_t ent, uint32_t cb, uint32_t ce) {
    if (!is_valid_ptr(ent)) return false;
    uint32_t vt = rd32(ent);
    if (vt < cb || vt + 8 > ce) return false;
    if (g_mta_type_relaxed) return true;
    uint32_t fn = rd32(vt + 4);
    if (fn < cb || fn + 8 > ce) return false;
    uint32_t w0 = rd32(fn), w1 = rd32(fn + 4);
    uint8_t b[8];
    memcpy(b, &w0, 4); memcpy(b + 4, &w1, 4);
    bool mov1 = (b[0] == 0xB8 && b[1] == 0x01 && b[2] == 0 && b[3] == 0 && b[4] == 0);
    if (mov1 && (b[5] == 0xC3 || (b[5] == 0xC2 && b[6] == 0 && b[7] == 0))) return true;
    if (b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0x40 && b[3] == 0xC3) return true;
    return false;
}

static uint32_t mta_slot_client_entity(uint32_t slot_addr, uint32_t gb, uint32_t ge,
                                       uint32_t cb, uint32_t ce) {
    (void)gb; (void)ge;
    uint32_t pEntity       = rd32(slot_addr);
    uint32_t pClientEntity = rd32(slot_addr + 4);
    if (!pEntity || !pClientEntity) return 0;
    if (!mta_is_client_player(pClientEntity, cb, ce)) return 0;
    return pClientEntity;
}

static bool mta_ped_context(uint32_t ped, uint32_t& slot_out) {
    uint32_t gb = 0, ge = 0, cb = 0, ce = 0;
    if (!get_module_bounds("game_sa.dll", gb, ge)) return false;
    if (!get_module_bounds("client.dll",  cb, ce)) return false;
    uint32_t pools = mta_find_pools(gb, ge);
    if (!pools) return false;
    uint32_t pool = rd32(ADDR_PED_POOL);
    if (!is_valid_ptr(pool)) return false;
    uint32_t objects = rd32(pool + POOL_OBJ_OFF);
    if (!is_valid_ptr(objects) || ped < objects) return false;
    uint32_t idx = (ped - objects) / MTA_PED_STRIDE;
    if (idx >= MTA_MAX_PEDS) return false;
    slot_out = pools + MTA_PED_ARRAY_OFF + idx * MTA_SCLIENT_SIZE;
    return true;
}

static uint32_t mta_client_entity_for_ped(uint32_t ped) {
    uint32_t slot = 0;
    if (!mta_ped_context(ped, slot)) return 0;
    uint32_t gb = 0, ge = 0, cb = 0, ce = 0;
    if (!get_module_bounds("game_sa.dll", gb, ge)) return 0;
    if (!get_module_bounds("client.dll",  cb, ce)) return 0;
    return mta_slot_client_entity(slot, gb, ge, cb, ce);
}

static int mta_collect_player_entities(uint32_t* out, int cap) {
    if (!out || cap <= 0) return 0;
    uint32_t gb = 0, ge = 0, cb = 0, ce = 0;
    if (!get_module_bounds("game_sa.dll", gb, ge)) return 0;
    if (!get_module_bounds("client.dll",  cb, ce)) return 0;
    uint32_t pools = mta_find_pools(gb, ge);
    if (!pools) return 0;
    for (int pass = 0; pass < 2; ++pass) {
        int n = 0;
        for (uint32_t i = 0; i < MTA_MAX_PEDS && n < cap; ++i) {
            uint32_t slot = pools + MTA_PED_ARRAY_OFF + i * MTA_SCLIENT_SIZE;
            uint32_t e = mta_slot_client_entity(slot, gb, ge, cb, ce);
            if (!e) continue;
            bool dup = false;
            for (int j = 0; j < n; ++j) if (out[j] == e) { dup = true; break; }
            if (!dup) out[n++] = e;
        }
        if (n >= 2) { g_mta_calib_ents = n; return n; }
        if (pass == 0) g_mta_type_relaxed = true;
    }
    g_mta_calib_ents = 0;
    return 0;
}

static bool mta_calibrate_nick_off() {
    uint32_t ents[64];
    int n = mta_collect_player_entities(ents, 64);
    if (n < 1) return false;
    if (n > 10) n = 10;
    bool single = (n < 2);
    if (single && g_mta_official_count < 1) return false;

    uint32_t best_off = 0;
    int      best_score = 0;
    for (uint32_t off = 0x40; off <= MTA_NICK_SCAN_END; off += 4) {
        char vals[10][40];
        int valid = 0, distinct = 0, official = 0;
        for (int j = 0; j < n; ++j) {
            vals[j][0] = '\0';
            if (read_msvc_string(ents[j] + off, vals[j], sizeof(vals[j]), 1, 32) &&
                !is_placeholder_nick(vals[j])) ++valid;
            else vals[j][0] = '\0';
        }
        if (single) {
            if (valid < 1 || !vals[0][0]) continue;
            if (!mta_name_in_official_list(vals[0])) continue;
            int score = 100 + valid;
            if (score > best_score) { best_score = score; best_off = off; }
            continue;
        }
        if (valid < 2) continue;
        for (int j = 0; j < n; ++j) {
            if (!vals[j][0]) continue;
            bool seen = false;
            for (int k = 0; k < j; ++k)
                if (vals[k][0] && mta_stricmp(vals[k], vals[j]) == 0) { seen = true; break; }
            if (!seen) ++distinct;
        }
        if (distinct < 2) continue;
        for (int j = 0; j < n; ++j)
            if (vals[j][0] && mta_name_in_official_list(vals[j])) ++official;
        int score = valid + distinct * 3 + official * 8;
        if (g_mta_official_count > 0 && official == 0) score -= 12;
        if (score > best_score) { best_score = score; best_off = off; }
    }
    if (!best_off) return false;
    g_mta_nick_off = best_off;
    mta_logf("nick", "calibrado: off=%04X score=%d ents=%d nomes=%d",
             best_off, best_score, g_mta_calib_ents, g_mta_official_count);
    return true;
}

static bool nick_cache_lookup(uint32_t ped, char* out, uint32_t sz, bool& hit) {
    hit = false;
    MtaNickEntry& c = g_mta_nick_ttl[(ped >> 4) & (NICK_CACHE_SIZE - 1)];
    if (c.tick == 0 || c.ped != ped) return false;
    if (GetTickCount() - c.tick > NICK_CACHE_TTL) return false;
    hit = true;
    if (!c.valid || !c.nick[0]) return false;
    size_t n = strlen(c.nick);
    if (n >= sz) n = sz - 1;
    memcpy(out, c.nick, n);
    out[n] = '\0';
    return true;
}

static void nick_cache_store(uint32_t ped, const char* nick, bool valid) {
    MtaNickEntry& c = g_mta_nick_ttl[(ped >> 4) & (NICK_CACHE_SIZE - 1)];
    if (c.ped != ped || c.tick == 0) c.nick[0] = '\0';
    c.ped   = ped;
    c.tick  = GetTickCount(); if (!c.tick) c.tick = 1;
    c.valid = valid;
    if (c.ped != ped || c.tick == 0) c.nick[0] = '\0';
    if (valid && nick && nick[0]) {
        size_t n = strlen(nick);
        if (n >= sizeof(c.nick)) n = sizeof(c.nick) - 1;
        memcpy(c.nick, nick, n);
        c.nick[n] = '\0';
    }
}

static bool nick_cache_last(uint32_t ped, char* out, uint32_t sz) {
    MtaNickEntry& c = g_mta_nick_ttl[(ped >> 4) & (NICK_CACHE_SIZE - 1)];
    if (c.tick == 0 || c.ped != ped || !c.nick[0]) return false;
    size_t n = strlen(c.nick);
    if (n >= sz) n = sz - 1;
    memcpy(out, c.nick, n);
    out[n] = '\0';
    return true;
}

static bool get_ped_nickname(int pool_idx, uint32_t ped_interface, bool is_local,
                             char* out_nick, uint32_t out_max) {
    (void)pool_idx; (void)is_local;
    if (!out_nick || out_max < 2) return false;
    out_nick[0] = '\0';
    if (!is_valid_ptr(ped_interface)) return false;
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return false;

    bool hit = false;
    if (nick_cache_lookup(ped_interface, out_nick, out_max, hit)) return true;
    if (hit) return nick_cache_last(ped_interface, out_nick, out_max);

    bool result = false;
    uint32_t now = GetTickCount();
    if (!g_mta_last_refresh || now - g_mta_last_refresh > 1000) {
        g_mta_last_refresh = now;
        mta_refresh_player_names();
    }

    if (!g_mta_nick_off) {
        if (!g_mta_last_calib || now - g_mta_last_calib > 2000) {
            g_mta_last_calib = now;
            if (!mta_calibrate_nick_off()) {
                if (nick_cache_last(ped_interface, out_nick, out_max)) return true;
                nick_cache_store(ped_interface, "", false);
                return false;
            }
        } else {
            if (nick_cache_last(ped_interface, out_nick, out_max)) return true;
            nick_cache_store(ped_interface, "", false);
            return false;
        }
    }

    uint32_t ent = mta_client_entity_for_ped(ped_interface);
    if (ent) {
        if (read_msvc_string(ent + g_mta_nick_off, out_nick, out_max, 1, 32) &&
            !is_placeholder_nick(out_nick)) {
            result = true;
        }
    }
    if (!result) {
        if (nick_cache_last(ped_interface, out_nick, out_max)) return true;
        out_nick[0] = '\0';
    }

    if (mta_log_tick(0, 8000))
        mta_logf("nick", "ped=%08X pools=%08X off=%04X ents=%d nomes=%d ent=%08X ok=%d",
                 ped_interface, g_mta_pools_ptr, g_mta_nick_off, g_mta_calib_ents,
                 g_mta_official_count, ent, result ? 1 : 0);
    nick_cache_store(ped_interface, out_nick, result);
    return result;
}

static uint32_t find_ped_by_name(const char* name) {
    if (!name || !name[0]) return 0;
    uint32_t local_ped = get_local_ped();
    uint32_t found = 0;
    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (is_valid_ptr(pool)) {
            uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
            uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
            uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
            if (is_valid_ptr(objects) && is_valid_ptr(flags) && size > 0) {
                if (size > 256) size = 256;
                for (uint32_t i = 0; i < size; ++i) {
                    uint8_t flag = *(uint8_t*)(flags + i);
                    if (flag & 0x80) continue;
                    uint32_t ped = objects + i * PED_STRIDE;
                    if (!is_valid_ptr(ped) || ped == local_ped) continue;
                    char nick[64] = {};
                    if (get_ped_nickname((int)i, ped, false, nick, sizeof(nick)) &&
                        mta_stricmp(nick, name) == 0) {
                        found = ped;
                        break;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return found;
}

static uint32_t resolve_troll_ped() {
    if (is_valid_ptr(g_troll_submenu_ped)) {
        char nick[64] = {};
        if (get_ped_nickname(-1, g_troll_submenu_ped, false, nick, sizeof(nick)) &&
            mta_stricmp(nick, g_troll_submenu_name) == 0)
            return g_troll_submenu_ped;
    }
    g_troll_submenu_ped = find_ped_by_name(g_troll_submenu_name);
    return g_troll_submenu_ped;
}

static bool game_add_explosion(const Vec3& pos, int type, uint32_t owner, uint32_t exploding,
                               uint32_t delay, bool makeSound, float camShake, bool noDamage) {
    typedef void (__cdecl* fn_add_explosion)(uint32_t pExplodingEntity, uint32_t pOwner, int explosionType,
                                             float fX, float fY, float fZ, uint32_t uiActivationDelay,
                                             uint32_t bMakeSound, float fCamShake, uint32_t bNoDamage);
    bool ok = false;
    __try {
        fn_add_explosion fn = (fn_add_explosion)(uintptr_t)ADDR_EXPLOSION_ADD;
        fn(exploding, owner, type, pos.x, pos.y, pos.z, delay,
           makeSound ? 1u : 0u, camShake, noDamage ? 1u : 0u);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    return ok;
}

struct fire_slot_t {
    uint8_t  flags;
    uint8_t  pad01;
    uint16_t scriptRef;
    float    x, y, z;
    uint32_t entityTarget;
    uint32_t entityCreator;
    uint32_t nTimeToBurn;
    float    strength;
    int8_t   nGenerations;
    uint8_t  removalDist;
    uint16_t pad22;
    uint32_t fxSys;
};
static_assert(sizeof(fire_slot_t) == FIRE_SLOT_SIZE, "CFireSAInterface layout mudou");

#define FIRE_FLAG_ACTIVE          0x01
#define FIRE_FLAG_CREATED_BY_SCR  0x02
#define FIRE_FLAG_MAKES_NOISE     0x04
#define FIRE_FLAG_BEING_EXTING    0x08
#define FIRE_FLAG_FIRST_GEN       0x10

static uint32_t game_set_ped_on_fire(uint32_t ped, float size, uint32_t timeToBurnOut) {
    typedef uint32_t (__thiscall* fn_start_on_ped)(void* self, uint32_t target, uint32_t creator,
                                                   float size, int a4, uint32_t timeBurn, int nGen);
    uint32_t fire = 0;
    __try {
        const uint8_t* pro = (const uint8_t*)(uintptr_t)ADDR_FIRE_START_ONPED;

        if (*pro == 0xCC || *pro == 0xC3 || *pro == 0x90) return 0;
        fn_start_on_ped fn = (fn_start_on_ped)(uintptr_t)ADDR_FIRE_START_ONPED;
        fire = fn((void*)(uintptr_t)ADDR_FIRE_MANAGER, ped, ped, size, 0, timeToBurnOut, 0);
        uint32_t onPed = *(uint32_t*)(ped + PED_OFF_FIRE_ONPED);
        if (onPed) {
            fire = onPed;
        } else if (fire) {
            *(uint32_t*)(ped + PED_OFF_FIRE_ONPED) = fire;
            *(float*)(ped + PED_OFF_FIRE_DAMAGEMULT) = 1.0f;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return fire;
}

static void game_extinguish_fire(uint32_t fire, uint32_t ped) {
    if (!fire) return;
    typedef void (__thiscall* fn_ext)(void* self);
    __try {
        fn_ext ex = (fn_ext)(uintptr_t)ADDR_FIRE_EXTINGUISH;
        ex((void*)(uintptr_t)fire);
        fire_slot_t* f = (fire_slot_t*)(uintptr_t)fire;
        f->flags &= (uint8_t)~FIRE_FLAG_ACTIVE;
        f->entityTarget = 0;
        if (is_valid_ptr(ped) && *(uint32_t*)(ped + PED_OFF_FIRE_ONPED) == fire)
            *(uint32_t*)(ped + PED_OFF_FIRE_ONPED) = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static bool game_camera_focus(uint32_t entity, uint32_t mode, uint32_t style) {
    typedef void (__thiscall* fn_take_control)(void* pCamera, void* pEntity, uint32_t camMode,
                                                uint32_t camSwitchStyle, uint32_t unk);
    bool ok = false;
    __try {
        fn_take_control fn = (fn_take_control)(uintptr_t)ADDR_CAMERA_TAKE_CONTROL;
        fn((void*)(uintptr_t)ADDR_CCAMERA, (void*)(uintptr_t)entity, mode, style, 1);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    return ok;
}

static void game_camera_restore() {
    typedef void (__thiscall* fn_void)(void* self);
    __try {
        ((fn_void)(uintptr_t)ADDR_CAMERA_RESTORE_JC1)((void*)(uintptr_t)ADDR_CCAMERA);
        ((fn_void)(uintptr_t)ADDR_CAMERA_RESTORE_JC2)((void*)(uintptr_t)ADDR_CCAMERA);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static bool game_camera_target_is(uint32_t entity) {
    bool same = false;
    __try {
        uint32_t cur = *(uint32_t*)(uintptr_t)((uintptr_t)ADDR_CCAMERA + CAM_OFF_TARGET_ENTITY);
        same = (cur == entity);
    } __except (EXCEPTION_EXECUTE_HANDLER) { same = false; }
    return same;
}

static uint32_t troll_ped_slot_index(uint32_t ped) {
    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (!is_valid_ptr(pool)) return 0xFFFFFFFFu;
        uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
        uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
        if (!is_valid_ptr(objects) || size == 0 || ped < objects) return 0xFFFFFFFFu;
        uint32_t off = ped - objects;
        if (off % PED_STRIDE) return 0xFFFFFFFFu;
        uint32_t idx = off / PED_STRIDE;
        return (idx < size) ? idx : 0xFFFFFFFFu;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0xFFFFFFFFu; }
}

static bool troll_ped_slot_alive(uint32_t ped, uint32_t idx) {
    if (idx == 0xFFFFFFFFu) return false;
    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (!is_valid_ptr(pool)) return false;
        uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
        uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
        uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
        if (!is_valid_ptr(objects) || !is_valid_ptr(flags) || size == 0) return false;
        if (idx >= size) return false;
        if (*(uint8_t*)(flags + idx) & 0x80) return false;
        return (objects + idx * PED_STRIDE) == ped;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool troll_ped_usable(uint32_t ped) {
    if (!is_valid_ptr(ped)) return false;
    __try {
        uint32_t m = *(uint32_t*)(ped + PED_OFF_MATRIX);
        if (!is_valid_ptr(m)) return false;
        float hp = *(const float*)(ped + PED_OFF_HEALTH);
        return hp > -1000.0f && hp < 10000.0f;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void troll_explode(uint32_t ped) {
    Vec3 pos;
    if (!get_ped_world_pos(ped, pos)) {
        notify_push("Troll", TROLL_ICON_GLYPH, false, "Alvo fora do mundo");
        return;
    }
    pos.z += 0.4f;

    uint32_t me = get_local_ped();
    bool ok = game_add_explosion(pos, EXPLOSION_GRENADE, me, 0, 0, true, TROLL_EXPLODE_SHAKE, false);
    mta_logf("troll", "explode ped=%08X owner=%08X pos=%.1f,%.1f,%.1f ok=%d",
             (unsigned)ped, (unsigned)me, (double)pos.x, (double)pos.y, (double)pos.z, ok ? 1 : 0);
    notify_push("Troll", TROLL_ICON_GLYPH, ok, ok ? "Explosao em %s" : "Falha ao chamar AddExplosion", g_troll_submenu_name);
}

static void troll_fire_stop() {
    if (!g_fire_slot) return;
    uint32_t fire = g_fire_slot;
    uint32_t ped  = g_fire_ped;
    g_fire_slot = 0;
    g_fire_ped  = 0;
    g_fire_diag = 0;
    g_fire_rearms = 0;
    game_extinguish_fire(fire, ped);
}

static void troll_fire(uint32_t ped) {
    if (g_fire_slot && g_fire_ped == ped) {
        troll_fire_stop();
        notify_push("Troll", TROLL_ICON_GLYPH, true, "Fogo removido de %s", g_troll_submenu_name);
        return;
    }

    __try {
        uint32_t cur = *(uint32_t*)(ped + PED_OFF_FIRE_ONPED);
        if (cur) { game_extinguish_fire(cur, ped); g_fire_slot = 0; g_fire_ped = 0; }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    Vec3 pos;
    bool havePos = get_ped_world_pos(ped, pos);
    uint32_t tick = 0;
    __try { tick = *(uint32_t*)(uintptr_t)ADDR_CTIMER_TICK; } __except (EXCEPTION_EXECUTE_HANDLER) {}
    uint32_t fire = game_set_ped_on_fire(ped, TROLL_FIRE_SIZE, tick + TROLL_FIRE_BURN_MS);
    if (!fire) {
        mta_logf("troll", "fire: CFireManager::StartFire falhou ped=%08X", (unsigned)ped);
        notify_push("Troll", TROLL_ICON_GLYPH, false, "Falha ao acender (CFireManager)");
        return;
    }
    g_fire_slot = fire;
    g_fire_ped  = ped;
    g_fire_last_tick = GetTickCount();
    g_fire_diag = 1;
    g_fire_rearms = 0;
    if (havePos)
        mta_logf("troll", "fire slot=%08X ped=%08X pos=%.1f,%.1f,%.1f size=%.2f (StartFire onped)",
                 (unsigned)fire, (unsigned)ped,
                 (double)pos.x, (double)pos.y, (double)pos.z, (double)TROLL_FIRE_SIZE);
    else
        mta_logf("troll", "fire slot=%08X ped=%08X (StartFire onped)", (unsigned)fire, (unsigned)ped);
    notify_push("Troll", TROLL_ICON_GLYPH, true, "%s em chamas", g_troll_submenu_name);
}

static void troll_spectate(uint32_t ped) {
    if (!is_valid_ptr(ped)) return;

    uint32_t entity = ped;
    uint32_t mode   = CAM_MODE_FOLLOWPED;
    __try {
        uint32_t veh = *(uint32_t*)(ped + PED_OFF_VEHICLE);
        if (is_valid_ptr(veh)) { entity = veh; mode = 18u; }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (!game_camera_focus(entity, mode, CAM_STYLE_CUT)) {
        notify_push("Troll", TROLL_ICON_GLYPH, false, "Camera indisponivel");
        return;
    }
    g_spectate_ped        = ped;
    g_spectate_active     = true;
    g_spectate_last_apply = GetTickCount();
    g_spectate_ped_idx    = troll_ped_slot_index(ped);
    g_spectate_arms       = 0;

    g_cam_off_state     = 1;
    g_spectate_reapply_ms = 250u;
    mta_logf("troll", "spectate TakeControl ped=%08X ent=%08X mode=%u", (unsigned)ped, (unsigned)entity, (unsigned)mode);
    notify_push("Troll", TROLL_ICON_GLYPH, true, "Espectando %s", g_troll_submenu_name);
}

static void troll_spectate_stop() {
    if (g_spectate_active) game_camera_restore();
    g_spectate_active     = false;
    g_spectate_ped        = 0;
    g_spectate_ped_idx    = 0xFFFFFFFFu;
    g_spectate_arms       = 0;
    g_spectate_last_apply = 0;
    mta_logf("troll", "spectate detach (RestoreWithJumpCut)");
}

static void troll_spectate_update() {
    if (!g_spectate_active) return;

    if (!troll_ped_slot_alive(g_spectate_ped, g_spectate_ped_idx) ||
        !troll_ped_usable(g_spectate_ped)) {
        troll_spectate_stop();
        return;
    }

    uint32_t entity = g_spectate_ped;
    uint32_t mode   = CAM_MODE_FOLLOWPED;
    __try {
        uint32_t veh = *(uint32_t*)(g_spectate_ped + PED_OFF_VEHICLE);
        if (is_valid_ptr(veh)) { entity = veh; mode = 18u; }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    uint32_t t = GetTickCount();
    if (t - g_spectate_last_apply < g_spectate_reapply_ms) return;
    g_spectate_last_apply = t;

    if (g_cam_off_state == 1) {
        bool hit = game_camera_target_is(entity);
        g_cam_off_state = hit ? 2u : 0u;
        g_spectate_reapply_ms = TROLL_SPECTATE_ARM_MS;
        mta_logf("troll", "spectate: pTargetEntity %s (offset %08X)",
                 hit ? "confere" : "NAO confere - sem re-arm",
                 (unsigned)(ADDR_CCAMERA + CAM_OFF_TARGET_ENTITY));
        return;
    }
    if (g_cam_off_state == 0) return;

    if (game_camera_target_is(entity)) { g_spectate_arms = 0; return; }

    if (++g_spectate_arms > TROLL_SPECTATE_MAX_ARM) {
        mta_logf("troll", "spectate: camera nao coopera (%u re-arms), desligando",
                 (unsigned)TROLL_SPECTATE_MAX_ARM);
        troll_spectate_stop();
        return;
    }
    if (!game_camera_focus(entity, mode, CAM_STYLE_CUT)) troll_spectate_stop();
}

static void troll_fire_update() {
    if (!g_fire_slot) return;
    if (!troll_ped_usable(g_fire_ped)) { g_fire_slot = 0; g_fire_ped = 0; return; }
    uint32_t t = GetTickCount();
    if (t - g_fire_last_tick < TROLL_FIRE_TICK_MS) return;
    g_fire_last_tick = t;

    bool     alive = false;
    uint32_t slot  = g_fire_slot;
    uint32_t ped   = g_fire_ped;
    __try {
        fire_slot_t* f = (fire_slot_t*)(uintptr_t)slot;
        if (is_valid_ptr(slot) && (f->flags & FIRE_FLAG_ACTIVE) &&
            f->entityTarget == ped &&
            *(uint32_t*)(ped + PED_OFF_FIRE_ONPED) == slot) {
            alive = true;
            if (g_fire_diag) {
                mta_logf("troll", "fire dump slot=%08X flags=%02X tgt=%08X creator=%08X "
                                   "pos=%.1f,%.1f,%.1f str=%.2f fx=%08X ttb=%u now=%u gen=%d p730=%08X",
                         (unsigned)slot, (unsigned)f->flags, (unsigned)f->entityTarget,
                         (unsigned)f->entityCreator, (double)f->x, (double)f->y, (double)f->z,
                         (double)f->strength, (unsigned)f->fxSys, (unsigned)f->nTimeToBurn,
                         (unsigned)*(uint32_t*)(uintptr_t)ADDR_CTIMER_TICK, (int)f->nGenerations,
                         (unsigned)*(uint32_t*)(ped + PED_OFF_FIRE_ONPED));
            }
            if (!f->fxSys) {
                typedef void (__thiscall* fn_fire_fx)(void* self, void* vecPosition, uint32_t unk);
                fn_fire_fx pfx = (fn_fire_fx)(uintptr_t)ADDR_FIRE_IGNITE_FX;
                pfx((void*)(uintptr_t)slot, &f->x, 0);
                mta_logf("troll", "fire: fx ausente, criado -> fx=%08X", (unsigned)f->fxSys);
            }
            f->nTimeToBurn = *(uint32_t*)(uintptr_t)ADDR_CTIMER_TICK + TROLL_FIRE_BURN_MS;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { alive = false; }
    g_fire_diag = 0;
    if (alive) return;

    if (g_fire_rearms < TROLL_FIRE_MAX_REARMS) {
        ++g_fire_rearms;
        uint32_t tick = 0;
        __try { tick = *(uint32_t*)(uintptr_t)ADDR_CTIMER_TICK; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        uint32_t fire = game_set_ped_on_fire(ped, TROLL_FIRE_SIZE, tick + TROLL_FIRE_BURN_MS);
        mta_logf("troll", "fire: slot %08X morreu; reata %u -> %08X",
                 (unsigned)slot, (unsigned)g_fire_rearms, (unsigned)fire);
        if (fire) { g_fire_slot = fire; g_fire_diag = (g_fire_rearms == 1) ? 1u : 0u; return; }
    } else {
        mta_logf("troll", "fire: algo no servidor apaga o fogo (%u reatas), desistindo",
                 (unsigned)g_fire_rearms);
        notify_push("Troll", TROLL_ICON_GLYPH, false, "O servidor nao deixa fogo ficar");
    }
    g_fire_slot = 0;
    g_fire_ped  = 0;
    g_fire_rearms = 0;
}

static bool troll_target_stats(uint32_t ped, float* hp, float* maxhp, float* armor,
                               float* x, float* y, float* z, float* dist) {
    if (hp)    *hp    = 0.0f;
    if (maxhp) *maxhp = 100.0f;
    if (armor) *armor = 0.0f;
    if (x) *x = 0.0f;
    if (y) *y = 0.0f;
    if (z) *z = 0.0f;
    if (dist) *dist = -1.0f;
    if (!is_valid_ptr(ped)) return false;

    Vec3 pos;
    if (!get_ped_world_pos(ped, pos)) return false;

    float h = 0.0f, m = 100.0f, a = 0.0f;
    __try {
        h = *(const float*)(ped + PED_OFF_HEALTH);
        m = *(const float*)(ped + PED_OFF_MAX_HEALTH);
        a = *(const float*)(ped + PED_OFF_ARMOR);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

    if (m < 1.0f || m > 10000.0f) m = 100.0f;
    if (h < 0.0f || h > m * 2.0f) h = m;
    if (a < 0.0f || a > 500.0f)   a = 0.0f;

    float d = -1.0f;
    uint32_t me = get_local_ped();
    Vec3 mpos;
    if (is_valid_ptr(me) && get_ped_world_pos(me, mpos)) {
        float dx = pos.x - mpos.x, dy = pos.y - mpos.y, dz = pos.z - mpos.z;
        d = sqrtf(dx * dx + dy * dy + dz * dz);
    }

    if (hp)    *hp    = h;
    if (maxhp) *maxhp = m;
    if (armor) *armor = a;
    if (x) *x = pos.x;
    if (y) *y = pos.y;
    if (z) *z = pos.z;
    if (dist) *dist = d;
    return true;
}

static void esp_draw_text_outlined(ImDrawList* dl, ImFont* font, float size,
                                   const ImVec2& p, ImU32 col, const char* txt) {
    if (!dl || !txt || !*txt) return;
    if (!font) font = ImGui::GetIO().FontDefault;
    if (!font) return;

    const ImU32 black = IM_COL32(0, 0, 0, ESP_TEXT_STROKE_ALPHA);
    const float o = ESP_TEXT_STROKE;
    static const float ox[4] = { -o,  o,  0,  0 };
    static const float oy[4] = {  0,  0, -o,  o };
    for (int i = 0; i < 4; ++i)
        dl->AddText(font, size, ImVec2(p.x + ox[i], p.y + oy[i]), black, txt);
    dl->AddText(font, size, p, col, txt);
}

static void draw_esp_for_ped(IDirect3DDevice9* dev, uint32_t ped, bool is_local, const char* name,
                             bool show_box, float col_box[4], bool show_box_filled,
                             bool show_box_corner, bool show_box_rounded,
                             bool show_lines, float col_lines[3],
                             bool show_names, float col_names[3],
                             bool show_health, float col_health[3], bool show_health_dynamic,
                             bool show_armor, float col_armor[3],
                             bool show_skeleton, float col_skeleton[3],
                             bool show_distance, float col_distance[3]) {
    Vec3 pos;
    float hp = 100.f, max_hp = 100.f, armor = 0.f;

    __try {
        if (!get_ped_world_pos(ped, pos)) return;

        hp     = *(float*)(ped + PED_OFF_HEALTH);
        max_hp = *(float*)(ped + PED_OFF_MAX_HEALTH);
        if (max_hp < 1.0f || max_hp > 10000.0f) max_hp = 100.0f;
        if (hp < 0.0f || hp > max_hp * 2.0f) hp = max_hp;

        armor = *(float*)(ped + PED_OFF_ARMOR);
        if (armor < 0.0f || armor > 500.0f) armor = 0.0f;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    if (hp <= 0.0f) return;

    Vec3 head_w = { pos.x, pos.y, pos.z + 0.85f };
    Vec3 foot_w = { pos.x, pos.y, pos.z - 1.00f };

    float hx, hy, fx, fy;
    bool head_ok = world_to_screen(dev, head_w, hx, hy);
    bool foot_ok = world_to_screen(dev, foot_w, fx, fy);

    if (!head_ok && !foot_ok) return;

    if (head_ok && !foot_ok) {
        float approx_h = 220.0f;
        fx = hx;
        fy = hy + approx_h;
    } else if (!head_ok && foot_ok) {
        float approx_h = 220.0f;
        hx = fx;
        hy = fy - approx_h;
    }

    ImDrawList* dl = ImGui::GetForegroundDrawList();
    ImGuiIO& io = ImGui::GetIO();

    float box_h = fy - hy;
    if (!(box_h >= 0.5f && box_h < 1.0e6f)) return;

    float bx    = (hx + fx) * 0.5f;
    float top   = hy;
    float bottom = fy;

    if (box_h < 6.0f) {
        float cy = (top + bottom) * 0.5f;
        top    = cy - 3.0f;
        bottom = cy + 3.0f;
        box_h  = 6.0f;
    }

    float box_w = box_h * 0.45f;
    if (box_w < 4.0f) box_w = 4.0f;

    float left  = bx - box_w * 0.5f;
    float right = bx + box_w * 0.5f;

    float margin = 300.0f;
    if (right  < -margin || left > io.DisplaySize.x + margin) return;
    if (bottom < -margin || top  > io.DisplaySize.y + margin) return;

    ImU32 c_box  = IM_COL32((int)(col_box[0]*255),      (int)(col_box[1]*255),      (int)(col_box[2]*255),      (int)(col_box[3]*255));
    ImU32 c_line = IM_COL32((int)(col_lines[0]*255),    (int)(col_lines[1]*255),    (int)(col_lines[2]*255),    200);
    ImU32 c_name = IM_COL32((int)(col_names[0]*255),    (int)(col_names[1]*255),    (int)(col_names[2]*255),    255);
    ImU32 c_hp   = IM_COL32((int)(col_health[0]*255),   (int)(col_health[1]*255),   (int)(col_health[2]*255),   230);
    ImU32 c_arm  = IM_COL32((int)(col_armor[0]*255),    (int)(col_armor[1]*255),    (int)(col_armor[2]*255),    230);
    ImU32 c_skel = IM_COL32((int)(col_skeleton[0]*255), (int)(col_skeleton[1]*255), (int)(col_skeleton[2]*255), 255);
    ImU32 c_dist = IM_COL32((int)(col_distance[0]*255), (int)(col_distance[1]*255), (int)(col_distance[2]*255), 255);

    if (show_box) {
        float rr = show_box_rounded ? 6.0f : 0.0f;
        if (show_box_corner) {
            float cl = ImMin(box_w, box_h) * 0.30f;
            dl->AddLine(ImVec2(left, top),  ImVec2(left + cl, top),  c_box, 1.5f);
            dl->AddLine(ImVec2(left, top),  ImVec2(left, top + cl),  c_box, 1.5f);
            dl->AddLine(ImVec2(right, top), ImVec2(right - cl, top), c_box, 1.5f);
            dl->AddLine(ImVec2(right, top), ImVec2(right, top + cl), c_box, 1.5f);
            dl->AddLine(ImVec2(left, bottom),  ImVec2(left + cl, bottom),  c_box, 1.5f);
            dl->AddLine(ImVec2(left, bottom),  ImVec2(left, bottom - cl),  c_box, 1.5f);
            dl->AddLine(ImVec2(right, bottom), ImVec2(right - cl, bottom), c_box, 1.5f);
            dl->AddLine(ImVec2(right, bottom), ImVec2(right, bottom - cl), c_box, 1.5f);
        } else if (show_box_filled) {
            dl->AddRectFilled(ImVec2(left, top), ImVec2(right, bottom), c_box, rr);
        } else {
            dl->AddRect(ImVec2(left, top), ImVec2(right, bottom), c_box, rr, 0, 1.5f);
        }
    }

    if (show_lines) {
        dl->AddLine(ImVec2(io.DisplaySize.x * 0.5f, 0.0f),
                    ImVec2(bx, top), c_line, 1.0f);
    }

    float dist_m = 0.0f;
    if (show_names || show_distance) {
        Vec3 lp;
        uint32_t lped = get_local_ped();
        if (is_valid_ptr(lped) && get_ped_world_pos(lped, lp)) {
            float ddx = pos.x - lp.x;
            float ddy = pos.y - lp.y;
            float ddz = pos.z - lp.z;
            dist_m = sqrtf(ddx * ddx + ddy * ddy + ddz * ddz);
            if (!(dist_m >= 0.0f && dist_m < 100000.0f)) dist_m = 0.0f;
        }
    }

    ImFont* esp_font = g_font_esp_name ? g_font_esp_name
                     : (g_font_regular ? g_font_regular : io.FontDefault);
    const float esp_fs = ESP_NAME_FONT_SIZE;

    if (show_names && name && name[0]) {
        char label[112] = {};
        if (show_distance)
            snprintf(label, sizeof(label), "%s [%.1fm]", name, dist_m);
        else
            snprintf(label, sizeof(label), "%s", name);
        if (esp_font) {
            ImVec2 sz = esp_font->CalcTextSizeA(esp_fs, FLT_MAX, 0.0f, label);
            ImVec2 p(bx - sz.x * 0.5f, top - sz.y - 4.0f);
            esp_draw_text_outlined(dl, esp_font, esp_fs, p, c_name, label);
        }
    }

    if (show_health && max_hp > 0.0f) {
        float f = hp / max_hp;
        if (f < 0.0f) f = 0.0f;
        if (f > 1.0f) f = 1.0f;
        float bar_w = 4.0f, pad = 3.0f, bx_l = left - bar_w - pad - 5.0f;

        ImU32 hp_fill = show_health_dynamic ? health_color_dynamic(f) : c_hp;

        dl->AddRectFilled(ImVec2(bx_l, top), ImVec2(bx_l + bar_w, bottom),
                          IM_COL32(0, 0, 0, 180));

        float h = (bottom - top) * f;
        dl->AddRectFilled(ImVec2(bx_l, bottom - h), ImVec2(bx_l + bar_w, bottom), hp_fill);

        dl->AddRect(ImVec2(bx_l - 0.5f, top - 0.5f),
                    ImVec2(bx_l + bar_w + 0.5f, bottom + 0.5f),
                    IM_COL32(0, 0, 0, 255), 0.0f, 0, 1.0f);
    }

    if (show_armor && armor > 0.0f) {
        float f = armor / 100.0f;
        if (f > 1.0f) f = 1.0f;
        float bar_w = 3.0f, pad = 3.0f, bx_r = right + pad + 5.0f;
        dl->AddRectFilled(ImVec2(bx_r, top), ImVec2(bx_r + bar_w, bottom), IM_COL32(20, 20, 20, 200));
        float h = (bottom - top) * f;
        dl->AddRectFilled(ImVec2(bx_r, bottom - h), ImVec2(bx_r + bar_w, bottom), c_arm);
    }

    if (show_skeleton) {
        Vec3 bp[64] = {}; bool ok[64] = {};
        for (const BonePair& pair : SKELETON_PAIRS) {
            if (pair.a < 64 && !ok[pair.a]) {
                if (get_bone_pos(ped, pair.a, bp[pair.a])) {
                    float dx = bp[pair.a].x - pos.x, dy = bp[pair.a].y - pos.y, dz = bp[pair.a].z - pos.z;
                    ok[pair.a] = (dx*dx + dy*dy + dz*dz < 12.25f);
                }
            }
            if (pair.b < 64 && !ok[pair.b]) {
                if (get_bone_pos(ped, pair.b, bp[pair.b])) {
                    float dx = bp[pair.b].x - pos.x, dy = bp[pair.b].y - pos.y, dz = bp[pair.b].z - pos.z;
                    ok[pair.b] = (dx*dx + dy*dy + dz*dz < 12.25f);
                }
            }
        }
        for (const BonePair& pair : SKELETON_PAIRS) {
            if (!ok[pair.a] || !ok[pair.b]) continue;
            float ax, ay, bx2, by2;
            if (!world_to_screen(dev, bp[pair.a], ax, ay)) continue;
            if (!world_to_screen(dev, bp[pair.b], bx2, by2)) continue;
            dl->AddLine(ImVec2(ax, ay), ImVec2(bx2, by2), c_skel, ESP_SKELETON_THICKNESS);
        }
    }
}

static void draw_esp_all_players(IDirect3DDevice9* dev) {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    // FIX: ESP morre IMEDIATAMENTE no disconnect. Sem isso, session_fail_closed
    // seta g_session_live=0 mas o render continua por ate 1600ms (threshold de
    // estabilidade), desenhando caixas no loading screen / browser de servidor.
    if (!session_live()) return;
    if (!g_esp_local_enable && !g_esp_players_enable) return;

    uint32_t local_ped = get_local_ped();

    auto draw_one = [&](uint32_t ped, bool is_local, const char* name) {

        bool fr = (!is_local && name && name[0] && esp_is_friend(name));
        static float s_fr_names[3], s_fr_skel[3];
        if (fr) { for (int k = 0; k < 3; ++k) { s_fr_names[k] = FRIEND_BLUE[k]; s_fr_skel[k] = FRIEND_BLUE[k]; } }
        if (is_local) {
            if (g_esp_local_enable)
                draw_esp_for_ped(dev, ped, true, name,
                    g_esp_local_box,    g_col_local_box,    g_esp_local_box_filled,
                    g_esp_local_box_corner, g_esp_local_box_rounded,
                    g_esp_local_lines,  g_col_local_lines,
                    g_esp_local_names,  g_col_local_names,
                    g_esp_local_health, g_col_local_health, g_esp_local_health_dynamic,
                    g_esp_local_armor,  g_col_local_armor,
                    g_esp_local_skeleton,g_col_local_skeleton,
                    g_esp_local_distance, g_col_local_distance);
        } else {
            if (g_esp_players_enable)
                draw_esp_for_ped(dev, ped, false, name,
                    g_esp_players_box,    g_col_players_box,    g_esp_players_box_filled,
                    g_esp_players_box_corner, g_esp_players_box_rounded,
                    g_esp_players_lines,  g_col_players_lines,
                    g_esp_players_names,  fr ? s_fr_names : g_col_players_names,
                    g_esp_players_health, g_col_players_health, g_esp_players_health_dynamic,
                    g_esp_players_armor,  g_col_players_armor,
                    g_esp_players_skeleton, fr ? s_fr_skel : g_col_players_skeleton,
                    g_esp_players_distance, g_col_players_distance);
        }
    };

    bool local_ok = false;
    if (is_valid_ptr(local_ped)) {
        char local_nick[64] = {};
        const char* disp_name = get_ped_nickname(-1, local_ped, true, local_nick, sizeof(local_nick))
                              ? local_nick : "Local";
        draw_one(local_ped, true, disp_name);
        local_ok = true;
    }

    if (!g_esp_players_enable) return;

    int drawn_players = 0;
    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (is_valid_ptr(pool)) {
            uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
            uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
            uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);

            if (is_valid_ptr(objects) && is_valid_ptr(flags) && size > 0) {
                if (size > 256) size = 256;

                for (uint32_t i = 0; i < size; ++i) {
                    uint8_t flag = *(uint8_t*)(flags + i);
                    if (flag & 0x80) continue;

                    uint32_t ped = objects + i * PED_STRIDE;
                    if (!is_valid_ptr(ped)) continue;

                    if (ped == local_ped) continue;

                    Vec3 ped_pos;
                    if (!get_ped_world_pos(ped, ped_pos)) continue;

                    char player_nick[64] = {};
                    const char* disp_name = get_ped_nickname((int)i, ped, false, player_nick, sizeof(player_nick))
                                          ? player_nick : (ESP_SHOW_UNRESOLVED_NAME ? "?" : "");
                    draw_one(ped, false, disp_name);
                    ++drawn_players;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    if (mta_log_tick(1, 10000))
        mta_logf("esp", "local=%s players=%d",
                 local_ok ? "ok" : "none", drawn_players);

}

#define AIMBOT_USE_LIVE_CROSSHAIR 0

static ImVec2 get_gta_sa_crosshair(const ImVec2& display) {
    float mx = 0.53f;
    float my = 0.40f;
    __try {
        float vx = *(float*)0xB6EC14u;
        float vy = *(float*)0xB6EC10u;
        if (vx == vx && vx > 0.25f && vx < 0.75f) mx = vx;
        if (vy == vy && vy > 0.20f && vy < 0.70f) my = vy;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

#if AIMBOT_USE_LIVE_CROSSHAIR
    __try {
        const uint32_t info = 0xB7CD98u;
        uint32_t active = *(uint32_t*)(info + 0x158);
        float nx = *(float*)(info + 0x15C);
        float ny = *(float*)(info + 0x160);
        if (active && nx == nx && ny == ny &&
            nx >= -1.0f && nx <= 1.0f && ny >= -1.0f && ny <= 1.0f) {
            float px = mx * display.x + nx * display.x * 0.5f;
            float py = my * display.y + ny * display.y * 0.5f;
            if (px >= 0.0f && px <= display.x && py >= 0.0f && py <= display.y)
                return ImVec2(px, py);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
    return ImVec2(mx * display.x, my * display.y);
}

static void draw_aimbot_fov() {
    if (!session_live()) return;  // FIX: FOV morre no disconnect (igual ESP)
    if (!g_aimbot_enable || !g_aimbot_show_fov) return;

    ImGuiIO& io = ImGui::GetIO();
    ImVec2 c = get_gta_sa_crosshair(io.DisplaySize);

    ImU32 col = IM_COL32((int)(g_aimbot_fov_col[0] * 255.0f),
                         (int)(g_aimbot_fov_col[1] * 255.0f),
                         (int)(g_aimbot_fov_col[2] * 255.0f), 255);

    float r = g_aimbot_fov_size;
    if (r < 1.0f)   r = 1.0f;
    if (r > 900.0f) r = 900.0f;

    ImDrawList* dl = ImGui::GetForegroundDrawList();
    dl->AddCircle(c, r, col, 96, 1.5f);
    if (g_aimbot_center_dot)
        dl->AddCircleFilled(c, AIMBOT_CENTER_DOT_RADIUS, col, 12);

    if (g_aimbot_show_target && g_aimbot_aim_on && g_aimbot_has_target) {
        ImVec2 t(g_aimbot_target_sx, g_aimbot_target_sy);
        dl->AddLine(c, t, IM_COL32(255, 255, 255, 90), 1.0f);
        dl->AddCircle(t, 7.0f, col, 20, 2.0f);
    }
}

static float silent_effective_fov() {
    float r = g_silent_fov_size;
    if (r < 1.0f)   r = 1.0f;
    if (r > 900.0f) r = 900.0f;
    return r;
}

static void draw_silent_fov() {
    if (!session_live()) return;  // FIX: FOV morre no disconnect (igual ESP)
    if (!g_silent_enable || !g_silent_show_fov) return;
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 c = get_gta_sa_crosshair(io.DisplaySize);
    ImU32 col = IM_COL32((int)(g_silent_fov_col[0] * 255.0f),
                         (int)(g_silent_fov_col[1] * 255.0f),
                         (int)(g_silent_fov_col[2] * 255.0f), 255);
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    dl->AddCircle(c, silent_effective_fov(), col, 64, 1.5f);
    if (g_silent_center_dot)
        dl->AddCircleFilled(c, AIMBOT_CENTER_DOT_RADIUS, col, 12);
    if (g_silent_show_target && g_silent_aim_on && g_silent_has_target) {
        ImVec2 t(g_silent_target_sx, g_silent_target_sy);
        dl->AddLine(c, t, IM_COL32(255, 60, 60, 90), 1.0f);
        dl->AddCircle(t, 5.0f, col, 16, 2.0f);
    }
}

static const int AIMBOT_BONE_IDS[7] = {
    5,
    4,
    3,
    22,
    32,
    42,
    52
};

typedef bool (__cdecl *fn_world_los)(const Vec3*, const Vec3*,
    int, int, int, int, int, int, int);

static bool los_available() {
    uint32_t now = GetTickCount();
    if (g_los_avail_tick && now - g_los_avail_tick < 2000) return g_los_avail;
    g_los_avail_tick = now ? now : 1;
    g_los_avail = false;
    __try {
        MEMORY_BASIC_INFORMATION mbi = {};
        void* fn = (void*)(uintptr_t)FUNC_WORLD_IS_LOS_CLEAR;
        if (VirtualQuery(fn, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            uint8_t b = *(uint8_t*)fn;
            g_los_avail = b != 0xE9 && b != 0xE8 && b != 0x00 && b != 0xCC;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { g_los_avail = false; }
    return g_los_avail;
}

static bool los_same_target(const Vec3& a, const Vec3& b) {
    return g_los_have_cache &&
        fabsf(g_los_cache_a[0] - a.x) < 0.25f &&
        fabsf(g_los_cache_a[1] - a.y) < 0.25f &&
        fabsf(g_los_cache_a[2] - a.z) < 0.25f &&
        fabsf(g_los_cache_b[0] - b.x) < 0.25f &&
        fabsf(g_los_cache_b[1] - b.y) < 0.25f &&
        fabsf(g_los_cache_b[2] - b.z) < 0.25f;
}

static bool los_clear(const Vec3& a, const Vec3& b) {
    if (!los_available()) {
        if (!g_los_logged) {
            g_los_logged = true;
            mta_logf("los", "LOS %08X indisponivel: fail-open, parede NAO bloqueia o silent",
                     (unsigned)FUNC_WORLD_IS_LOS_CLEAR);
        }
        g_los_have_cache = false;
        return true;
    }
    uint32_t now = GetTickCount();
    if (los_same_target(a, b) && g_los_tick &&
        now - g_los_tick < LOS_RECHECK_MS) return g_los_cached;
    g_los_cached = false;
    __try {
        fn_world_los f = (fn_world_los)(uintptr_t)FUNC_WORLD_IS_LOS_CLEAR;
        g_los_cached = f(&a, &b, 1, 1, 0, 0, 0, 1, 0) ? true : false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_los_cached = true;
        if (!g_los_logged) {
            g_los_logged = true;
            mta_logf("los", "LOS %08X lancou excecao: fail-open, parede NAO bloqueia o silent",
                     (unsigned)FUNC_WORLD_IS_LOS_CLEAR);
        }
    }
    g_los_tick = now ? now : 1;
    g_los_cache_a[0] = a.x; g_los_cache_a[1] = a.y; g_los_cache_a[2] = a.z;
    g_los_cache_b[0] = b.x; g_los_cache_b[1] = b.y; g_los_cache_b[2] = b.z;
    g_los_have_cache = true;
    return g_los_cached;
}

static void silent_update(IDirect3DDevice9* dev) {
    g_silent_has_target = false;
    InterlockedExchange(&g_silent_send_ok, 0);
    if (!session_live()) { g_silent_aim_on = false; return; }

    g_silent_aim_on = g_silent_enable &&
        ((GetAsyncKeyState(g_silent_key_vk) & 0x8000) != 0);
    if (!g_silent_enable || !g_silent_aim_on || g_menu_open ||
        g_silent_capturing || !dev) return;
    HWND fg = GetForegroundWindow();
    HWND game_root = GetAncestor(g_game_hwnd, GA_ROOT);
    if (!fg || !game_root || GetAncestor(fg, GA_ROOT) != game_root) return;

    ImGuiIO& io = ImGui::GetIO();
    const ImVec2 cross = get_gta_sa_crosshair(io.DisplaySize);
    const float radius = silent_effective_fov();
    const int bone = AIMBOT_BONE_IDS[
        (g_silent_bone >= 0 && g_silent_bone < 7) ? g_silent_bone : 0];
    const uint32_t local_ped = get_local_ped();
    float best_d2 = radius * radius;
    bool found = false;
    uint32_t best_ped = 0;
    const int sel_bone = (g_silent_bone >= 0 && g_silent_bone < 7) ? g_silent_bone : 0;

    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (is_valid_ptr(pool)) {
            uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
            uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
            uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
            if (is_valid_ptr(objects) && is_valid_ptr(flags) && size > 0) {
                if (size > 256) size = 256;
                for (uint32_t i = 0; i < size; ++i) {
                    uint8_t flag = *(uint8_t*)(flags + i);
                    if (flag & 0x80) continue;
                    uint32_t ped = objects + i * PED_STRIDE;
                    if (!is_valid_ptr(ped) || ped == local_ped) continue;
                    float hp = *(float*)(ped + PED_OFF_HEALTH);
                    if (!(hp > 0.0f && hp < 10000.0f)) continue;
                    char fnick[64] = {};
                    if (get_ped_nickname((int)i, ped, false, fnick, sizeof(fnick)) &&
                        esp_is_friend(fnick)) continue;
                    Vec3 pos;
                    if (!get_ped_world_pos(ped, pos)) continue;
                    Vec3 aim;
                    if (!get_bone_pos(ped, bone, aim)) {
                        aim = pos;
                        aim.z += 1.0f;
                    }
                    float sx = 0.0f, sy = 0.0f;
                    if (!world_to_screen(dev, aim, sx, sy)) continue;
                    float ddx = sx - cross.x, ddy = sy - cross.y;
                    float d2 = ddx * ddx + ddy * ddy;
                    if (d2 < best_d2) {
                        best_d2 = d2;
                        best_ped = ped;
                        g_silent_target_sx = sx;
                        g_silent_target_sy = sy;
                        g_silent_aim_point[0] = aim.x;
                        g_silent_aim_point[1] = aim.y;
                        g_silent_aim_point[2] = aim.z;
                        found = true;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (found && g_silent_ignore_walls) {
        g_los_have_cache = false;
    } else if (found && best_ped) {
        Vec3 src;
        Vec3 dst;
        dst.x = g_silent_aim_point[0];
        dst.y = g_silent_aim_point[1];
        dst.z = g_silent_aim_point[2];
        if (!get_ped_world_pos(local_ped, src)) {
            found = false;
        } else {
            src.z += 1.0f;
            int used = -1;
            if (los_clear(src, dst)) {
                used = sel_bone;
            } else {
                for (int k = 1; k < 7 && used < 0; ++k) {
                    int bi = (sel_bone + k) % 7;
                    Vec3 alt;
                    if (!get_bone_pos(best_ped, AIMBOT_BONE_IDS[bi], alt)) continue;
                    if (!los_clear(src, alt)) continue;
                    g_silent_aim_point[0] = alt.x;
                    g_silent_aim_point[1] = alt.y;
                    g_silent_aim_point[2] = alt.z;
                    used = bi;
                }
            }
            if (used < 0) found = false;
        }
    }
    g_silent_has_target = found;
    InterlockedExchange(&g_silent_send_ok,
        (found && session_live() && !conn_handshake_active() && !g_menu_open &&
         !InterlockedCompareExchange(&g_shutdown_all, 0, 0)) ? 1 : 0);
    if (mta_log_tick(4, 5000))
        mta_logf("silent", "upd enable=%d on=%d found=%d ok=%d live=%d menu=%d hs=%d",
                 g_silent_enable ? 1 : 0, g_silent_aim_on ? 1 : 0,
                 found ? 1 : 0, (int)g_silent_send_ok,
                 session_live() ? 1 : 0, g_menu_open ? 1 : 0,
                 conn_handshake_active() ? 1 : 0);
}

static __declspec(naked) void hk_mta_fire_mid() {
    __asm {
        cmp dword ptr [g_session_live], 0
        je  short pass_fire_mid
        cmp dword ptr [g_silent_send_ok], 0
        je  short pass_fire_mid
        mov eax, offset g_silent_aim_point
        mov ecx, dword ptr [eax]
        mov edx, dword ptr [eax + 4]
        mov eax, dword ptr [eax + 8]
        mov dword ptr [esp + 10h], ecx
        mov dword ptr [esp + 14h], edx
        mov dword ptr [esp + 18h], eax
      pass_fire_mid:
        jmp dword ptr [g_o_mta_fire_mid]
    }
}

static __declspec(naked) void hk_mta_sniper_mid() {
    __asm {
        cmp dword ptr [g_session_live], 0
        je  short pass_sniper_mid
        cmp dword ptr [g_silent_send_ok], 0
        je  short pass_sniper_mid
        mov eax, offset g_silent_aim_point
        mov ecx, dword ptr [eax]
        mov edx, dword ptr [eax + 4]
        mov eax, dword ptr [eax + 8]
        mov dword ptr [esp + 3Ch], ecx
        mov dword ptr [esp + 40h], edx
        mov dword ptr [esp + 44h], eax
      pass_sniper_mid:
        jmp dword ptr [g_o_mta_sniper_mid]
    }
}

static bool silent_patch_mid(uint32_t pos, void* detour, void** mta_hook) {
    uint8_t* p = (uint8_t*)(uintptr_t)pos;
    __try {
        if (p[0] != 0xE9) return false;
        int32_t rel = *(int32_t*)(p + 1);
        uint32_t dest = pos + 5 + (uint32_t)rel;
        if (dest < 0x10000u || dest > 0x7FFFFFFFu) return false;
        *mta_hook = (void*)(uintptr_t)dest;
        if (g_patch_count >= 92) return false;
        DWORD oldp = 0;
        if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &oldp)) return false;
        PatchRecord& pr = g_patches[g_patch_count];
        pr.addr = p;
        memcpy(pr.original, p, 5);
        pr.detour = detour;
        p[0] = 0xE9;
        *(int32_t*)(p + 1) = (int32_t)((uintptr_t)detour - pos - 5);
        VirtualProtect(p, 5, oldp, &oldp);
        FlushInstructionCache(GetCurrentProcess(), p, 5);
        ++g_patch_count;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void silent_install_mid_hooks() {
    if (!g_silent_mid_ok) {
        uint8_t b0 = 0;
        __try { b0 = *(uint8_t*)(uintptr_t)MTA_FIRE_MID_POS; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        mta_logf("silent", "mid %08X byte0=%02X (E9 esperado)", (unsigned)MTA_FIRE_MID_POS, (unsigned)b0);
        void* det = (void*)(uintptr_t)&hk_mta_fire_mid;
        if (silent_patch_mid(MTA_FIRE_MID_POS, det, &g_o_mta_fire_mid)) {
            g_silent_mid_ok = true;
            mta_logf("silent", "bulletsync instanthit %08X -> MTA %08X: end=esp+%02X start intacto",
                     (unsigned)MTA_FIRE_MID_POS,
                     (unsigned)(uintptr_t)g_o_mta_fire_mid,
                     (unsigned)MTA_FIRE_MID_END);
        } else if (!g_silent_mid_logged) {
            g_silent_mid_logged = true;
            mta_logf("silent", "mid %08X sem JMP do MTA: bulletsync nao redirecionado",
                     (unsigned)MTA_FIRE_MID_POS);
        }
    }
    if (!g_silent_sniper_ok) {
        void* det = (void*)(uintptr_t)&hk_mta_sniper_mid;
        if (silent_patch_mid(MTA_SNIPER_MID_POS, det, &g_o_mta_sniper_mid)) {
            g_silent_sniper_ok = true;
            mta_logf("silent", "bulletsync sniper %08X -> MTA %08X: end=esp+%02X",
                     (unsigned)MTA_SNIPER_MID_POS,
                     (unsigned)(uintptr_t)g_o_mta_sniper_mid,
                     (unsigned)MTA_SNIPER_MID_END);
        } else if (!g_silent_sniper_logged) {
            g_silent_sniper_logged = true;
            mta_logf("silent", "mid %08X sem JMP do MTA: sniper nao redirecionado",
                     (unsigned)MTA_SNIPER_MID_POS);
        }
    }
}

using fn_fire_instant_hit = void (__fastcall *)(void*, void*);

static __declspec(naked) void hk_fire_instant_hit() {
    __asm {
        pushad
        cmp dword ptr [g_session_live], 0
        je  short pass_silent
        cmp dword ptr [g_silent_send_ok], 0
        je  short pass_silent
        cmp byte ptr [g_silent_enable], 0
        je  short pass_silent
        cmp byte ptr [g_silent_aim_on], 0
        je  short pass_silent
        cmp byte ptr [g_silent_has_target], 0
        je  short pass_silent
        cmp dword ptr [g_shutdown_all], 0
        jne short pass_silent
        mov eax, offset g_silent_aim_point
        mov dword ptr [esp + 34h], eax
      pass_silent:
        popad
        jmp dword ptr [g_o_FireInstantHit]
    }
}

static void silent_retire_hooks() {
    int w = 0;
    for (int i = 0; i < g_patch_count && i < 96; ++i) {
        PatchRecord pr = g_patches[i];
        uint32_t a = (uint32_t)(uintptr_t)pr.addr;
        if (a != SILENT_FIRE_INSTANT_HIT && a != MTA_FIRE_MID_POS &&
            a != MTA_SNIPER_MID_POS) {
            if (w != i) g_patches[w] = pr;
            ++w;
            continue;
        }
        __try {
            DWORD oldp = 0;
            if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &oldp)) {
                memcpy(pr.addr, pr.original, 5);
                VirtualProtect(pr.addr, 5, oldp, &oldp);
                FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    g_patch_count = w;
    // FIX OOM: NÃO zerar g_o_FireInstantHit. O trampolim aponta para código
    // original válido (5 bytes copiados no install inicial) — pode ser reusado
    // indefinidamente. Zerar forçava reinstalação a cada retire(), que alocava
    // um novo trampolim VirtualAlloc(4KB) → leak massivo com packet 33 (sync).
    g_o_mta_fire_mid = nullptr;
    g_o_mta_sniper_mid = nullptr;
    g_silent_hook_ok = false;
    g_silent_mid_ok = false;
    g_silent_sniper_ok = false;
    g_silent_mid_logged = false;
    g_silent_sniper_logged = false;
}

static void silent_install_hook() {
    if (g_silent_hook_ok) return;
    if (g_patch_count >= 92) return;
    uint8_t* p = (uint8_t*)(uintptr_t)SILENT_FIRE_INSTANT_HIT;
    __try {
        uint8_t b = p[0];
        uint8_t q[5] = { p[0], p[1], p[2], p[3], p[4] };
        mta_logf("silent", "FireInstantHit prologo %02X %02X %02X %02X %02X",
                 (unsigned)q[0], (unsigned)q[1], (unsigned)q[2],
                 (unsigned)q[3], (unsigned)q[4]);
        if (b == 0xE9 || b == 0xE8 || b == 0xEB || b == 0x00 || b == 0xCC) {
            mta_logf("silent", "FireInstantHit ja modificado (byte=%02X): hook nao instalado", (unsigned)b);
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    // FIX OOM: se já temos trampolim cacheado (g_o_FireInstantHit != nullptr),
    // reinstala o JMP SEM alocar outro trampolim. Só atualiza o slice do patch.
    if (g_o_FireInstantHit) {
        uint8_t saved[5] = {};
        DWORD old = 0;
        __try {
            memcpy(saved, p, 5);
            if (VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) {
                PatchRecord& pr = g_patches[g_patch_count];
                pr.addr = p;
                memcpy(pr.original, saved, 5);
                pr.detour = (void*)(uintptr_t)&hk_fire_instant_hit;
                ++g_patch_count;

                p[0] = 0xE9;
                *(int32_t*)(p + 1) = (int32_t)((uintptr_t)&hk_fire_instant_hit - (uintptr_t)p - 5);
                VirtualProtect(p, 5, old, &old);
                FlushInstructionCache(GetCurrentProcess(), p, 5);

                g_silent_hook_ok = true;
                mta_logf("silent", "trajetoria local RE-instalada (trampoline cacheado, sem alloc)");
                return;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        mta_logf("silent", "falha ao reusar trampolim; caindo para fresh install");
    }

    // Fresh install (só ocorre no boot ou se o cache foi zerado)
    fn_fire_instant_hit tramp = nullptr;
    if (patch_jmp((void*)(uintptr_t)SILENT_FIRE_INSTANT_HIT,
                  reinterpret_cast<fn_fire_instant_hit>(&hk_fire_instant_hit), tramp)) {
        g_o_FireInstantHit = (void*)(uintptr_t)tramp;
        g_silent_hook_ok = true;
        mta_logf("silent", "trajetoria local instalada em %08X; pacote via mid %08X (id=%d)",
                 (unsigned)SILENT_FIRE_INSTANT_HIT,
                 (unsigned)MTA_FIRE_MID_POS, (int)MTA_PACKET_BULLETSYNC);
    } else {
        mta_logf("silent", "falha ao instalar redirecionamento de trajetoria");
    }
}

static void aimbot_run(IDirect3DDevice9* dev) {
    g_aimbot_has_target = false;
    if (!session_live()) return;
    if (!g_aimbot_enable || !g_aimbot_aim_on ||
        g_menu_open || g_aimbot_capturing || !dev) return;

    HWND fg = GetForegroundWindow();
    HWND game_root = GetAncestor(g_game_hwnd, GA_ROOT);
    if (!fg || !game_root || GetAncestor(fg, GA_ROOT) != game_root) return;

    ImGuiIO& io = ImGui::GetIO();
    const ImVec2 cross = get_gta_sa_crosshair(io.DisplaySize);

    float radius = g_aimbot_fov_size;
    if (radius < 1.0f)   radius = 1.0f;
    if (radius > 900.0f) radius = 900.0f;

    const int bone = AIMBOT_BONE_IDS[
        (g_aimbot_bone >= 0 && g_aimbot_bone < 7) ? g_aimbot_bone : 0];

    const uint32_t local_ped = get_local_ped();
    float best_d2 = radius * radius;
    float best_sx = 0.0f, best_sy = 0.0f;
    bool  found   = false;

    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (is_valid_ptr(pool)) {
            uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
            uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
            uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
            if (is_valid_ptr(objects) && is_valid_ptr(flags) && size > 0) {
                if (size > 256) size = 256;
                for (uint32_t i = 0; i < size; ++i) {
                    uint8_t flag = *(uint8_t*)(flags + i);
                    if (flag & 0x80) continue;

                    uint32_t ped = objects + i * PED_STRIDE;
                    if (!is_valid_ptr(ped) || ped == local_ped) continue;

                    float hp = *(float*)(ped + PED_OFF_HEALTH);
                    if (!(hp > 0.0f && hp < 10000.0f)) continue;

                    Vec3 pos;
                    if (!get_ped_world_pos(ped, pos)) continue;

                    char nick[64] = {};
                    bool nick_ok = get_ped_nickname((int)i, ped, false, nick, sizeof(nick));
#if AIMBOT_ONLY_REAL_PLAYERS
                    if (!nick_ok) continue;
#endif
                    if (nick_ok && esp_is_friend(nick)) continue;
                    Vec3 aim;
                    if (!get_bone_pos(ped, bone, aim)) {
                        aim = pos;
                        aim.z += 1.0f;
                    }

                    float sx = 0.0f, sy = 0.0f;
                    if (!world_to_screen(dev, aim, sx, sy)) continue;

                    float ddx = sx - cross.x;
                    float ddy = sy - cross.y;
                    float d2  = ddx * ddx + ddy * ddy;
                    if (d2 < best_d2) {
                        best_d2 = d2;
                        best_sx = sx;
                        best_sy = sy;
                        found = true;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    if (!found) return;
    g_aimbot_has_target = true;
    g_aimbot_target_sx  = best_sx;
    g_aimbot_target_sy  = best_sy;

    const float sm = g_aimbot_smooth;
    const bool  snap = (sm <= 0.001f);
    const float step = snap ? 1.0f : 1.0f / (1.0f + sm * 0.1f);
    const float cap  = snap ? AIMBOT_SNAP_MAX_PIXELS : 600.0f;
    float dx = (best_sx - cross.x) * step * AIMBOT_MOUSE_SENS;
    float dy = (best_sy - cross.y) * step * AIMBOT_MOUSE_SENS;
    if (dx >  cap) dx =  cap;
    if (dx < -cap) dx = -cap;
    if (dy >  cap) dy =  cap;
    if (dy < -cap) dy = -cap;

#if AIMBOT_AIM_MODE == 0
    static float acc_x = 0.0f, acc_y = 0.0f;
    if (snap) {
        acc_x = 0.0f;
        acc_y = 0.0f;
        float rx = dx, ry = dy;
        if (rx == rx && ry == ry) {
            for (int guard = 0; guard < 16; ++guard) {
                int ix = (int)rx;
                int iy = (int)ry;
                if (ix >  300) ix =  300;
                if (ix < -300) ix = -300;
                if (iy >  300) iy =  300;
                if (iy < -300) iy = -300;
                if (!ix && !iy) break;
                mouse_event(MOUSEEVENTF_MOVE, (DWORD)(LONG)ix, (DWORD)(LONG)iy, 0, 0);
                rx -= (float)ix;
                ry -= (float)iy;
            }
        }
    } else {
        acc_x += dx;
        acc_y += dy;
        int ix = (int)acc_x;
        int iy = (int)acc_y;
        acc_x -= (float)ix;
        acc_y -= (float)iy;
        if (ix >  300) ix =  300;
        if (ix < -300) ix = -300;
        if (iy >  300) iy =  300;
        if (iy < -300) iy = -300;
        if (ix || iy)
            mouse_event(MOUSEEVENTF_MOVE, (DWORD)(LONG)ix, (DWORD)(LONG)iy, 0, 0);
    }
#else
    __try {
        uint8_t active = *(uint8_t*)0xB6F081u;
        if (active < 3) {
            uint32_t cam = 0xB6F19Cu + (uint32_t)active * 0x238u;
            volatile float* yaw   = (volatile float*)(cam + 0xBCu);
            volatile float* pitch = (volatile float*)(cam + 0xACu);
            const float cy = *yaw;
            const float cp = *pitch;
            if (cy > -20.0f && cy < 20.0f && cp > -20.0f && cp < 20.0f &&
                io.DisplaySize.x > 0.0f && io.DisplaySize.y > 0.0f) {
                const float fov_rad = 70.0f * 3.14159265f / 180.0f;
                *yaw   = cy - dx * (fov_rad / io.DisplaySize.x) * AIMBOT_CAM_YAW_SIGN;
                *pitch = cp + dy * (fov_rad / io.DisplaySize.y) * AIMBOT_CAM_PITCH_SIGN;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
}

static volatile LONG g_render_faults     = 0;
static volatile LONG g_d3d_reset_count   = 0;
static volatile LONG g_reset_storm       = 0;
static uint32_t      g_reset_window_tick = 0;
static int           g_reset_window_n    = 0;
static uint32_t      g_ammo_last_tick    = 0;
static uint32_t      g_frame_idx         = 0;
static uint64_t      g_us_gameplay = 0;
static uint64_t      g_us_ui       = 0;
static uint64_t      g_us_present  = 0;
static uint32_t      g_us_frames   = 0;
static uint64_t      g_qpc_freq    = 0;

static uint64_t now_us() {
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    if (!g_qpc_freq) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        g_qpc_freq = f.QuadPart ? (uint64_t)f.QuadPart : 1ull;
    }
    return (uint64_t)c.QuadPart * 1000000ull / g_qpc_freq;
}

static HRESULT __stdcall hk_Reset(IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* pParams) {
    g_have_3d = false;
    uint32_t rnow = GetTickCount();
    if (rnow - g_reset_window_tick > 5000) {
        g_reset_window_tick = rnow ? rnow : 1;
        g_reset_window_n    = 0;
        InterlockedExchange(&g_reset_storm, 0);
    }
    g_reset_window_n++;
    InterlockedIncrement(&g_d3d_reset_count);
    bool storm = (g_reset_window_n > 30);
    if (storm && InterlockedCompareExchange(&g_reset_storm, 1, 0) == 0)
        mta_logf("d3d", "RESET STORM: %d resets em 5s; atlas nao sera recriado ate acalmar",
                 g_reset_window_n);
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

    uint64_t w0 = now_us();
    HRESULT hr = g_o_Present(pDevice, pSrc, pDst, hWnd, pDirty);
    g_us_wait += now_us() - w0;
    return hr;
}

static HRESULT __stdcall hk_SetTransform(IDirect3DDevice9* dev, D3DTRANSFORMSTATETYPE state, const D3DMATRIX* m) {

    if (m) {
        if (state == D3DTS_VIEW) {
            g_current_view = *m;
        } else if (state == D3DTS_PROJECTION) {
            if (is_perspective(m)) {
                g_3d_view = g_current_view;
                g_3d_proj = *m;
                g_have_3d = true;
            }
        }
    }
    return g_o_SetTransform(dev, state, m);
}

static int      g_sess_state     = 0;
static int      g_sess_stable    = 0;
static bool     g_sess_last_raw  = false;
static uint32_t g_sess_tick      = 0;
static uint32_t g_sess_lost      = 0;
static bool     g_sess_saved     = false;
static bool     g_sess_menu_open = false;
static bool     g_sess_prev_menu = false;
static bool     g_sess_prev_ins  = false;
static unsigned char g_sess_snap[CFG_ENTRY_COUNT][16] = {};

static size_t sess_entry_size(int type) {
    if (type == CFG_BOOL)  return sizeof(bool);
    if (type == CFG_INT)   return sizeof(int);
    if (type == CFG_FLOAT) return sizeof(float);
    if (type == CFG_COL3)  return 3 * sizeof(float);
    if (type == CFG_COL4)  return 4 * sizeof(float);
    return 0;
}

static bool sess_probe() {
    uint32_t ped = get_local_ped();
    if (!is_valid_ptr(ped)) return false;
    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (!is_valid_ptr(pool)) return false;
        uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
        uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
        if (size == 0 || size > 512 || !is_valid_ptr(objects)) return false;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void sess_disable_all() {
    if (g_sess_saved) return;
    fly_physics_end();
    // FIX: encerra troll (camera spectate no ped do servidor antigo e fogo ativo
    // sao invalidos no novo server; antes ficavam grudados ate o proximo WM_CLOSE).
    troll_spectate_stop();
    troll_fire_stop();
    // FIX: g_infinite_ammo tambem precisa desligar no disconnect. Antes ficava
    // ON permanentemente (nao estava em CFG_ENTRIES, logo sess_disable_all
    // nao o tocava, e a escrita por frame em weapon+slot continuava).
    g_infinite_ammo = false;
    g_ammo_logged = false;
    g_silent_aim_on = g_silent_has_target = false;
    g_silent_capturing = false;
    InterlockedExchange(&g_silent_send_ok, 0);
    for (int i = 0; i < CFG_ENTRY_COUNT; ++i) {
        if (strcmp(CFG_ENTRIES[i].key, "misc.streamproof") == 0) continue;
        size_t n = sess_entry_size(CFG_ENTRIES[i].type);
        if (n && n <= 16) memcpy(g_sess_snap[i], CFG_ENTRIES[i].ptr, n);
    }
    g_sess_menu_open = g_menu_open;
    g_sess_prev_menu = g_prev_menu_open;
    g_sess_prev_ins  = g_prev_insert;
    g_sess_saved = true;

    for (int i = 0; i < CFG_ENTRY_COUNT; ++i)
        if (CFG_ENTRIES[i].type == CFG_BOOL &&
            strcmp(CFG_ENTRIES[i].key, "misc.streamproof") != 0)
            *(bool*)CFG_ENTRIES[i].ptr = false;

    g_aimbot_aim_on = g_aimbot_has_target = false;
    g_aimbot_capturing = g_aimbot_key_held = false;
    g_bind_capture = 0; g_bind_capture_tick = 0;
    g_menu_key_latch = (GetAsyncKeyState(g_menu_key_vk) & 0x8000) != 0;
    InterlockedExchange(&g_menu_toggle_pending, 0);
    g_fly_key_prev = g_fly_key_held = false;
    g_fly_active = false;
    g_fly_toggle_on = false; g_fly_key_edge = false;
    g_fly_hover_valid = false;
    g_menu_open = false; g_prev_menu_open = false; g_prev_insert = false;
    g_cfg_pending_overwrite = false; g_cfg_pending_delete = false;

    session_fail_closed(5);

    silent_retire_hooks();
    ClipCursor(nullptr);
    mta_logf("conn", "desconectado/main menu: %d opcoes desligadas (snapshot salvo)", CFG_ENTRY_COUNT);
}

static void sess_restore_all() {
    if (!g_sess_saved) return;
    for (int i = 0; i < CFG_ENTRY_COUNT; ++i) {
        if (strcmp(CFG_ENTRIES[i].key, "misc.streamproof") == 0) continue;
        size_t n = sess_entry_size(CFG_ENTRIES[i].type);
        if (n && n <= 16) memcpy(CFG_ENTRIES[i].ptr, g_sess_snap[i], n);
    }
    g_menu_open = g_sess_menu_open;
    g_prev_menu_open = g_sess_prev_menu;
    g_prev_insert = g_sess_prev_ins;
    g_sess_saved = false;

    if (g_menu_key_vk <= 0 || g_menu_key_vk > 255) g_menu_key_vk = VK_INSERT;
    if (g_fly_key_vk  <= 0 || g_fly_key_vk  > 255) g_fly_key_vk  = VK_F8;
    if (g_aimbot_key_vk <= 0 || g_aimbot_key_vk > 255) g_aimbot_key_vk = VK_XBUTTON1;
    if (g_silent_key_vk <= 0 || g_silent_key_vk > 255) g_silent_key_vk = VK_XBUTTON2;
    g_silent_fov_size = cfg_clampf(g_silent_fov_size, 1.0f, 900.0f);
    g_silent_bone = g_silent_bone < 0 ? 0 : (g_silent_bone > 6 ? 6 : g_silent_bone);
    g_fly_mode = (g_fly_mode == FLY_MODE_TOGGLE) ? FLY_MODE_TOGGLE : FLY_MODE_HOLD;
    g_fly_speed = cfg_clampf(g_fly_speed, 0.5f, 100.0f);
    bind_format_key(g_menu_key_vk, g_menu_key_name, sizeof(g_menu_key_name));
    bind_format_key(g_fly_key_vk,  g_fly_key_name,  sizeof(g_fly_key_name));
    bind_format_key(g_silent_key_vk, g_silent_key_name, sizeof(g_silent_key_name));
    aimbot_set_key(g_aimbot_key_vk);
    g_silent_aim_on = g_silent_has_target = false;
    g_silent_capturing = false;
    InterlockedExchange(&g_silent_send_ok, 0);
    session_fail_closed(10);
    g_fly_toggle_on = false; g_fly_key_edge = false;
    g_fly_hover_valid = false;
    mta_logf("conn", "conectado: %d opcoes restauradas do snapshot", CFG_ENTRY_COUNT);
}

static void reconnect_guard() {
    HMODULE cur = GetModuleHandleA("netc.dll");
    uint32_t base = (uint32_t)(uintptr_t)cur;
    uint32_t size = netc_image_size(cur);
    uint32_t old_base = g_netc_base;
    if (!g_netc_base && base) {
        g_netc_base = base;
        g_netc_size = size;
        return;
    }

    if (old_base && !base) {
        if (!g_netc_unload_logged) {
            g_netc_unload_logged = true;
            mta_logf("conn!", "netc VANISHED past PIN — refusing park/reinstall, "
                              "%d patches held stale", (int)g_patch_count);
        }
    } else if (old_base && base && base != old_base) {
        if (!g_netc_rebase_logged) {
            g_netc_rebase_logged = true;
            mta_logf("conn!", "netc REBASED past PIN %08X -> %08X — refusing reinstall, "
                              "patches on old map will miss",
                     (unsigned)old_base, (unsigned)base);
        }
    }
    if (g_conn_grace && !conn_handshake_active())
        mta_logf("conn", "handshake concluido: recursos liberados sem tocar no send_packet");
}

static void session_monitor() {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    uint32_t now = GetTickCount();
    if (now - g_sess_tick < 200) return;
    g_sess_tick = now ? now : 1;
    bool active = sess_probe();

    // FIX: além do ped local, exigir tráfego recente de pacotes. O ped local
    // sobrevive 1-2s após disconnect (MTA destrói de forma assíncrona), mas
    // os packets param no mesmo frame da desconexão. Sem este check,
    // active=true durante a transição → ESP/FOV renderizam contra mundo morto.
    // 1500ms é folgado o suficiente para sobreviver a lag spikes.
    if (active) {
        uint32_t lp = (uint32_t)InterlockedCompareExchange(&g_last_pkt_tick, 0, 0);
        if (lp && (now - lp) > 1500) active = false;
    }

    reconnect_guard();
    g_server_kick_seen = 0;
    bool quarantined = g_quarantine_until &&
        (now - g_quarantine_until < RECONNECT_QUARANTINE_MS);

    // FIX: era >=8 (1.6s). sess_restore_all já roda em >=2, mas session_live()
    // só ficava true em >=8 — janela de 1.2s onde ImGui mostrava ON mas nada
    // renderizava. >=2 (400ms) filtra glitch de 1 amostra e ativa quase junto
    // com o restore. O gate real contra detecção AC continua sendo
    // conn_handshake_active() (2.5s de silêncio pós-conexão).
    bool live = active && !conn_handshake_active() && !quarantined &&
        !g_sess_saved && g_netc_base && g_sess_stable >= 2 &&
        !InterlockedCompareExchange(&g_emergency_done, 0, 0);
    if (live) {
        InterlockedExchange(&g_session_live, 1);
        g_session_live_tick = now ? now : 1;
        g_fail_clean_done = false;

        if (!g_silent_hook_ok) silent_install_hook();
        if (!g_silent_mid_ok || !g_silent_sniper_ok) silent_install_mid_hooks();
    } else {
        session_fail_closed(active ? 8u : 9u);
    }
    if (active && !g_conn_prev_active) {
        g_conn_grace = now ? now : 1;
        g_sess_stable = 0;
        mta_logf("conn", "conectado: janela de handshake iniciada");
    } else if (!active && g_conn_prev_active) {
        g_conn_grace = 0;
        fly_physics_end();
        session_fail_closed(3);

        silent_retire_hooks();
        g_silent_capturing = false;

        // FIX: desligar features JÁ no frame de transição. Antes, esperava
        // g_sess_stable>=2 (~400ms) para sess_disable_all rodar — nesse
        // intervalo ESP/FOV continuavam renderizando, e o snapshot podia
        // capturar estado incorreto se o usuário tocasse em toggles.
        // Snapshot agora reflete o estado REAL in-game (antes do disable).
        if (!g_sess_saved) sess_disable_all();

        mta_logf("conn", "desconectado: features OFF imediato, silent hooks restaurados");
    }
    g_conn_prev_active = active;
    if (active == g_sess_last_raw) {
        if (g_sess_stable < 100) ++g_sess_stable;
    } else {
        g_sess_stable = 0;
        g_sess_last_raw = active;
    }
    if (g_game_hwnd && !IsWindow(g_game_hwnd)) {
        if (!g_sess_lost) g_sess_lost = now ? now : 1;
        else if (!active && (now - g_sess_lost) > 3000) {
            emergency_disable_all();
            return;
        }
    } else g_sess_lost = 0;
    // FIX: era 8 probes (1600ms). Isso deixava features visiveis por 1.6s apos
    // o disconnect e fazia trocas rapidas de servidor (< 1.6s sem ped) nao
    // dispararem sess_disable_all (log 19:30:24 mostra ped trocando sem
    // disconnect registrado). 2 probes = 400ms: filtra falso-positivo de 1
    // sample (hiccup de rede) mas e praticamente instantaneo pro usuario.
    if (g_sess_stable < 2) return;
    int want = active ? 1 : 2; 	
    g_sess_state = want;
    if (want == 2 && !g_sess_saved) sess_disable_all();
    else if (want == 1 && g_sess_saved && !conn_handshake_active() &&
             !quarantined) sess_restore_all();
}

static void quit_early_probe() {
}


static bool     g_focus_skip     = false;
static int      g_focus_no_draw  = 0;

static void focus_set_skip(bool v) {
    if (g_focus_skip == v) return;
    g_focus_skip = v;
    if (v) mta_logf("foco", "sem foco: frames da DLL suspensos");
    else { g_focus_no_draw = 0; mta_logf("foco", "em foco: retomado"); }
}

static bool render_frame_ok() {
    if (!g_game_hwnd || !IsWindow(g_game_hwnd)) { focus_set_skip(false); return true; }
    if (IsIconic(g_game_hwnd)) { focus_set_skip(true); return false; }
    HWND fg   = GetForegroundWindow();
    HWND root = GetAncestor(g_game_hwnd, GA_ROOT);
    if (!fg || !root || GetAncestor(fg, GA_ROOT) == root) { focus_set_skip(false); return true; }
    if (++g_focus_no_draw < 3) return true;
    focus_set_skip(true);
    return false;
}

static HRESULT __stdcall hk_EndScene(IDirect3DDevice9* pDevice) {
    quit_early_probe();
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0))
        return g_o_EndScene(pDevice);

    HRESULT coop = pDevice->TestCooperativeLevel();
    if (coop != D3D_OK) {
        g_have_3d = false;
        InterlockedExchange(&g_silent_send_ok, 0);
        return g_o_EndScene(pDevice);
    }

    session_monitor();

    if (!g_game_focused) {
        g_have_3d = false;
        InterlockedExchange(&g_silent_send_ok, 0);
        return g_o_EndScene(pDevice);
    }

    if (!render_frame_ok()) {
        g_have_3d = false;
        InterlockedExchange(&g_silent_send_ok, 0);
        return g_o_EndScene(pDevice);
    }

    if (!g_imgui_init) {
        init_imgui(pDevice);
        if (!g_imgui_init) return g_o_EndScene(pDevice);
    }

    {
        HWND fg = GetForegroundWindow();
        HWND game_root = GetAncestor(g_game_hwnd, GA_ROOT);
        bool game_focused = (fg != nullptr) && (game_root != nullptr)
                            && (GetAncestor(fg, GA_ROOT) == game_root);
        uint32_t now = GetTickCount();
        bool pending = InterlockedExchange(&g_menu_toggle_pending, 0) != 0;
        bool key_down = game_focused && bind_is_down(g_menu_key_vk);
        bool edge = key_down && !g_menu_key_latch;
        if ((pending || edge) && now - g_menu_toggle_tick > 180) {
            g_menu_open = !g_menu_open;
            g_menu_toggle_tick = now ? now : 1;
            g_menu_key_latch = true;
        }
        if (!key_down) g_menu_key_latch = false;
    }

    menu_cursor_sync(g_menu_open);
    if (g_menu_prev != g_menu_open) {
        g_menu_prev = g_menu_open;
        mta_logf("menu", "%s fps=%.1f size=%.0fx%.0f",
                 g_menu_open ? "aberto" : "fechado",
                 (double)ImGui::GetIO().Framerate,
                 (double)ImGui::GetIO().DisplaySize.x,
                 (double)ImGui::GetIO().DisplaySize.y);
    }

    stream_proof_apply();
    g_frame_idx++;
    if (InterlockedCompareExchange(&g_reset_storm, 0, 0)) {
        static uint32_t s_lost_last = 0;
        uint32_t lt = GetTickCount();
        float ldt = ImClamp((float)(lt - s_lost_last) * 0.001f, 0.0f, 0.1f);
        s_lost_last = lt ? lt : 1;
        __try {
            fly_update(ldt);
            uint32_t at0 = GetTickCount();
            if (at0 - g_ammo_last_tick >= 150) {
                g_ammo_last_tick = at0 ? at0 : 1;
                infinite_ammo_update();
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement(&g_render_faults);
        }
        return g_o_EndScene(pDevice);
    }

    if (InterlockedCompareExchange(&g_imgui_invalidated, 0, 0)) {
        bool ok = false;
        __try {
            ImGui_ImplDX9_CreateDeviceObjects();
            ok = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement(&g_render_faults);
        }
        if (ok) {
            InterlockedExchange(&g_imgui_invalidated, 0);
            mta_logf("d3d", "device objects recriados no primeiro frame com coop ok");
        }
    }

    ImGui::GetIO().MouseDrawCursor = false;
    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();

    if (ImGui::GetIO().DisplaySize.x < 64.0f || ImGui::GetIO().DisplaySize.y < 64.0f)
        return g_o_EndScene(pDevice);
    if (ImGui::GetIO().DeltaTime > 0.1f) ImGui::GetIO().DeltaTime = 0.1f;
    ImGui::NewFrame();
    if (mta_log_tick(2, 5000)) {
        ImGuiIO& io = ImGui::GetIO();
        double fdiv = g_us_frames ? (double)g_us_frames : 1.0;
        mta_logf("fps", "fps=%.1f dt=%.1fms gp=%.2fms ui=%.2fms rd=%.2fms wait=%.2fms patches=%d repatch=%d menu=%d faults=%d resets=%d storm=%d shutdown=%d",
                 (double)io.Framerate, (double)(io.DeltaTime * 1000.0f),
                 (double)((double)g_us_gameplay / fdiv / 1000.0),
                 (double)((double)g_us_ui / fdiv / 1000.0),
                 (double)((double)g_us_present / fdiv / 1000.0),
                 (double)((double)g_us_wait / fdiv / 1000.0),
                 (int)g_patch_count,
                 (int)InterlockedCompareExchange(&g_watchdog_repatch_count, 0, 0),
                 g_menu_open ? 1 : 0,
                 (int)InterlockedExchange(&g_render_faults, 0),
                 (int)InterlockedExchange(&g_d3d_reset_count, 0),
                 (int)InterlockedCompareExchange(&g_reset_storm, 0, 0),
                 (int)InterlockedCompareExchange(&g_shutdown_all, 0, 0));
        g_us_gameplay = 0;
        g_us_ui       = 0;
        g_us_present  = 0;
        g_us_wait     = 0;
        g_us_frames   = 0;
    }

    const bool handshake = conn_handshake_active();
    uint64_t t0 = now_us();
    bool heavy = (ImGui::GetIO().Framerate >= 45.0f) || ((g_frame_idx & 1u) == 0u);
    if (!handshake) {
        __try {
            if (heavy) draw_esp_all_players(pDevice);
            fly_update(ImGui::GetIO().DeltaTime);
            uint32_t at1 = GetTickCount();
            if (at1 - g_ammo_last_tick >= 150) {
                g_ammo_last_tick = at1 ? at1 : 1;
                infinite_ammo_update();
            }
            if (heavy) {
                aimbot_run(pDevice);
                silent_update(pDevice);
            }
            troll_spectate_update();
            troll_fire_update();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement(&g_render_faults);
        }
    } else {
        g_silent_aim_on = g_silent_has_target = false;
        g_aimbot_aim_on = g_aimbot_has_target = false;
        InterlockedExchange(&g_silent_send_ok, 0);
    }
    uint64_t t1 = now_us();
    g_us_gameplay += t1 - t0;
    bool frame_begun = true;
    __try {
        aimbot_update_key();
        aimbot_poll_capture();
        misc_bind_poll_capture();
        draw_aimbot_fov();
        draw_silent_fov();
        if (g_menu_open && g_current_tab == TAB_TROLL) troll_player_list_refresh();
        if (g_menu_open) draw_menu();
        notify_draw();
        uint64_t t2 = now_us();
        g_us_ui += t2 - t1;
        ImGui::EndFrame();
        frame_begun = false;
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
        g_us_present += now_us() - t2;
        g_us_frames++;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_render_faults);
        if (frame_begun) {
            __try { ImGui::EndFrame(); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

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
    if (b[0] == 0x68) return false;
    if (b[0] == 0x00 || b[0] == 0xCC) return false;
    return true;
}

static void install_d3d9_hooks() {
    HWND hwnd = CreateWindowExA(0, "STATIC", "dummy",
        WS_POPUP, 0, 0, 1, 1, NULL, NULL, NULL, NULL);
    if (!hwnd) return;

    IDirect3D9* d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) { DestroyWindow(hwnd); return; }

    D3DPRESENT_PARAMETERS pp = {};
    pp.Windowed         = TRUE;
    pp.SwapEffect       = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow    = hwnd;
    pp.BackBufferFormat = D3DFMT_UNKNOWN;

    IDirect3DDevice9* dev = nullptr;
    HRESULT hr = d3d->CreateDevice(
        D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);

    if (FAILED(hr)) {
        d3d->Release();
        DestroyWindow(hwnd);
        return;
    }

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
        if (busy[i])
            mta_logf("d3d9", "%s ja esta hookada por outro modulo (overlay?) - hook NAO instalado",
                     sites[i].name);
    }
    if (busy[0]) {
        mta_logf("d3d9", "ENDSCENE ocupada: ImGui nao sera desenhado. Feche RivaTuner/"
                         "Afterburner (ou qualquer overlay) e reinicie o jogo.");
        return;
    }

    for (int i = 0; i < 4; ++i) {
        if (busy[i]) continue;
        bool ok = false;
        switch (i) {
            case 0: ok = patch_jmp(sites[0].addr, &hk_EndScene,     g_o_EndScene);     break;
            case 1: ok = patch_jmp(sites[1].addr, &hk_Reset,        g_o_Reset);         break;
            case 2: ok = patch_jmp(sites[2].addr, &hk_Present,      g_o_Present);       break;
            default: ok = patch_jmp(sites[3].addr, &hk_SetTransform, g_o_SetTransform); break;
        }
        if (!ok) mta_logf("d3d9", "patch_jmp falhou em %s", sites[i].name);
    }
}

static HMODULE find_mod() { return GetModuleHandleA("netc.dll"); }

static HMODULE g_netc_pin = nullptr;

static bool pin_netc() {
    if (g_netc_pin) return true;
    HMODULE h = nullptr;
    for (int i = 0; i < 240; ++i) {
        if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return false;
        if (GetModuleHandleExA(0x00000001 ,
                               "netc.dll", &h) && h) {
            g_netc_pin = h;
            uint32_t size = 0;
            __try {
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)h;
                IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((uint8_t*)h + dos->e_lfanew);
                size = nt->OptionalHeader.SizeOfImage;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            mta_logf("pin", "netc.dll PINNED at %p (image=%uKB) — cannot unload",
                     (void*)h, (unsigned)(size / 1024));
            return true;
        }
        Sleep(250);
    }
    mta_logf("pin!", "netc.dll not found after 60s — pin failed");
    return false;
}

static unsigned g_ok = 0, g_miss = 0, g_fail = 0;

template<typename T>
static bool try_install_global(const char* name, const char* pat, const char* msk, unsigned occ,
                               T detour, T& original_out) {
    if (g_patch_count >= 92) { ++g_fail; return false; }
    void* addr = scan_mask(find_mod(), pat, msk, occ);
    if (!addr) { ++g_miss; return false; }

    if (!patch_jmp(addr, detour, original_out)) {
        ++g_fail;
        return false;
    }
    ++g_ok;
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
    if (addr < 0x10000u || addr + 5 > 0x7FFFFFFFu) { ++g_miss; return false; }
    if (addr + 5 > g_netc_base + g_netc_size) { ++g_miss; return false; }

    void* a = (void*)(uintptr_t)addr;
    __try {
        volatile uint8_t b = *(uint8_t*)a;
        (void)b;
    } __except (EXCEPTION_EXECUTE_HANDLER) { ++g_miss; return false; }

    if (*(uint8_t*)a == 0xE9) {
        int32_t rel = *(int32_t*)((uint8_t*)a + 1);
        uint32_t dest = addr + 5 + (uint32_t)rel;
        if (dest == (uint32_t)(uintptr_t)detour) {
            mta_logf("rva", "%s rva=%05X addr=%08X ja hookado", name, rva, addr);
            return true;
        }
    }

    T tramp = nullptr;
    if (!patch_jmp(a, detour, tramp)) {
        ++g_fail;
        mta_logf("rva!", "%s rva=%05X addr=%08X: falhou", name, rva, addr);
        return false;
    }
    ++g_ok;
    mta_logf("rva", "%s rva=%05X addr=%08X", name, rva, addr);
    return true;
}

static void __fastcall w_send_client_kick(int a, int b, unsigned int c,
                                          int d, DWORD* e, int f) {
    d_send_client_kick(a, b, c, d, e, f);
}

static void __fastcall w_send_client_local_kick(int a, char b) {
    d_send_client_local_kick(a, b);
}

static void __fastcall w_send_client_ban(int a, int b, int* c, int* d,
                                        char e, int f) {
    d_send_client_ban(a, b, c, d, e, f);
}

static void install_all() {
    if (g_install_done_generation == g_install_generation) return;
    HMODULE mod = nullptr;
    for (int i = 0; i < 60; ++i) {
        mod = find_mod();
        if (mod) break;
        Sleep(500);
    }
    if (!mod) return;
    g_install_done_generation = g_install_generation;
    ++g_install_count;
    mta_logf("safe", "install_all geracao=%u tentativa=%u patches=%d: trampolins por geracao",
             (unsigned)g_install_generation, (unsigned)g_install_count,
             (int)g_patch_count);
    g_netc_base = (uint32_t)(uintptr_t)mod;
    g_netc_size = netc_image_size(mod);
    memset(g_stale_patch_sink, 0xE9, sizeof(g_stale_patch_sink));

    try_install<bool(__cdecl*)(int,int,int,DWORD*,int*,DWORD*)>(
        "advanced_memory_validator",
        PAT_ADVANCED_MEMORY_VALIDATOR, MSK_ADVANCED_MEMORY_VALIDATOR, 1,
        &d_advanced_memory_validator);

    try_install<int(__fastcall*)(DWORD*,void*,int,unsigned __int8,unsigned __int16)>(
        "network_packet_state_validator",
        PAT_NETWORK_PACKET_STATE_VALIDATOR, MSK_NETWORK_PACKET_STATE_VALIDATOR, 1,
        &d_network_packet_state_validator);

    try_install<char(__stdcall*)(int*)>(
        "animation_packet_validator",
        PAT_ANIMATION_PACKET_VALIDATOR, MSK_ANIMATION_PACKET_VALIDATOR, 1,
        &d_animation_packet_validator);

    try_install_global<fn_send_packet>(
        "send_packet",
        PAT_SEND_PACKET, MSK_SEND_PACKET, 1,
        &d_send_packet, g_o_send_packet);

    try_install<int(__cdecl*)(char,void*,int,int,int)>(
        "send_report",
        PAT_SEND_REPORT, MSK_SEND_REPORT, 1,
        &d_send_report);

    try_install<HANDLE(__stdcall*)(LPCWSTR,ACCESS_MASK,DWORD,LPSECURITY_ATTRIBUTES,ULONG,ULONG)>(
        "send_driver_report",
        PAT_SEND_DRIVER_REPORT, MSK_SEND_DRIVER_REPORT, 1,
        &d_send_driver_report);

    try_install<void(__fastcall*)(int,int,unsigned int,int,DWORD*,int)>(
        "send_client_kick",
        PAT_SEND_CLIENT_KICK, MSK_SEND_CLIENT_KICK, 1,
        &w_send_client_kick);

    try_install<void(__fastcall*)(int,char)>(
        "send_client_local_kick",
        PAT_SEND_CLIENT_LOCAL_KICK, MSK_SEND_CLIENT_LOCAL_KICK, 1,
        &w_send_client_local_kick);

    try_install<void(__fastcall*)(int,int,int*,int*,char,int)>(
        "send_client_ban",
        PAT_SEND_CLIENT_BAN, MSK_SEND_CLIENT_BAN, 1,
        &w_send_client_ban);

    try_install_global<fn_send_lua_check>(
        "send_lua_check",
        PAT_SEND_LUA_CHECK, MSK_SEND_LUA_CHECK, 1,
        &d_send_lua_check, g_o_send_lua_check);

    try_install<void(__fastcall*)(void*,void*)>(
        "sub_10056A50",
        PAT_SUB_10056A50, MSK_SUB_10056A50, 1,
        &d_sub_10056A50);

    try_install<unsigned int(__fastcall*)(void*,void*,int)>(
        "sub_10293EC0",
        PAT_SUB_10293EC0, MSK_SUB_10293EC0, 1,
        &d_sub_10293EC0);

    try_install<int(__fastcall*)(void*,void*)>(
        "sub_10159D50",
        PAT_SUB_10159D50, MSK_SUB_10159D50, 1,
        &d_sub_10159D50);

    try_install<int(__cdecl*)(void*)>(
        "sub_10141000",
        PAT_SUB_10141000, MSK_SUB_10141000, 1,
        &d_sub_10141000);

    try_install<int(__fastcall*)(void*,void*,int,void*,int,const char*,const char*)>(
        "sub_101731D0",
        PAT_SUB_101731D0, MSK_SUB_101731D0, 1,
        &d_sub_101731D0);

    try_install<bool(__cdecl*)()>(
        "sub_1028CB90",
        PAT_SUB_1028CB90, MSK_SUB_1028CB90, 2,
        &d_sub_1028CB90);

    try_install<bool(__cdecl*)(char*)>(
        "detect_hook_new2",
        PAT_DETECT_HOOK_NEW2, MSK_DETECT_HOOK_NEW2, 1,
        &d_detect_hook_new2);

    try_install<bool(__cdecl*)(char*)>(
        "detect_hook_new",
        PAT_DETECT_HOOK_NEW, MSK_DETECT_HOOK_NEW, 1,
        &d_detect_hook_new);

    try_install<char(__cdecl*)(char*)>(
        "detect_hook",
        PAT_DETECT_HOOK, MSK_DETECT_HOOK, 1,
        &d_detect_hook);

    try_install<void(__cdecl*)(const char*)>(
        "sub_1006CC80",
        PAT_SUB_1006CC80, MSK_SUB_1006CC80, 1,
        &d_sub_1006CC80);

    try_install<char(__fastcall*)(void*,void*,int,int)>(
        "bypassnew",
        PAT_BYPASSNEW, MSK_BYPASSNEW, 1,
        &d_bypassnew);

    try_install<int(__fastcall*)(void*,void*,int,int)>(
        "bypass",
        PAT_BYPASS, MSK_BYPASS, 1,
        &d_bypass);

    try_install<int(__fastcall*)(unsigned int,void*,int)>(
        "sub_new",
        PAT_SUB_NEW, MSK_SUB_NEW, 2,
        &d_sub_new);

    try_install<int(__stdcall*)(int)>(
        "send_crash_hook",
        PAT_SEND_CRASH_HOOK, MSK_SEND_CRASH_HOOK, 1,
        &d_send_crash_hook);

    try_install_global<fn_sub_102BDFDE>(
        "sub_102BDFDE",
        PAT_SUB_102BDFDE, MSK_SUB_102BDFDE, 1,
        &d_sub_102BDFDE, g_o_sub_102BDFDE);

    try_install<unsigned int(__fastcall*)(int,int,unsigned int)>(
        "sub_100D57B0",
        PAT_SUB_100D57B0, MSK_SUB_100D57B0, 1,
        &d_sub_100D57B0);

    try_install_rva<fn_ac_check_hooking_function>(
        "ac_check_hooking_function", 0x6BC90, &d_ac_check_hooking_function);
    try_install_rva<LONG(__stdcall*)(void*)>(
        "ac_veh_stack", 0x11E9C0, &d_veh_stack);
    try_install_rva<fn_ac_send_client_kick>(
        "ac_send_client_kick", 0x1CCF40, &d_ac_send_client_kick);
    try_install_rva<fn_add_ac_log_path_hook>(
        "add_ac_log_path_hook", 0x29910, &d_add_ac_log_path_hook);
    try_install_rva<fn_ac_watchdog>(
        "ac_watchdog", 0x2A8930, &d_ac_watchdog);
       try_install_rva<DWORD(__stdcall*)(void*)>(
        "ac_start_watchdog", 0x2A8AD0, &d_ac_start_watchdog);

}

static DWORD WINAPI thread(LPVOID) {
    g_boot_tick = GetTickCount();
    HANDLE sh = CreateThread(nullptr, 0, session_heartbeat_thread, nullptr, 0, nullptr);
    if (sh) CloseHandle(sh);
    pin_netc();
    install_all();
    silent_install_hook();
    mta_logf("hook", "install_all: ok=%u miss=%u fail=%u patches=%d",
             g_ok, g_miss, g_fail, (int)g_patch_count);
    install_d3d9_hooks();
    mta_logf("d3d9", "EndScene=%p Reset=%p Present=%p SetTransform=%p",
             (void*)(uintptr_t)g_o_EndScene, (void*)(uintptr_t)g_o_Reset,
             (void*)(uintptr_t)g_o_Present, (void*)(uintptr_t)g_o_SetTransform);

    InterlockedExchange(&g_watchdog_stop, 0);
    g_watchdog_handle = CreateThread(nullptr, 0, watchdog_thread, nullptr, 0, nullptr);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        mta_logf("boot", "DLL_PROCESS_ATTACH | rev=R55 | build %s %s | log=%s",
                 __DATE__, __TIME__, mta_log_path());
        if (InterlockedCompareExchange(&g_init_top, 1, 0) == 0) {
            HANDLE t = CreateThread(nullptr, 0, thread, nullptr, 0, nullptr);
            if (t) CloseHandle(t);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (lpReserved != nullptr) {

            quit_flush();
            quit_hard_restore();
            return TRUE;
        }

        quit_flush();
        emergency_disable_all();
        unpatch_all();
        if (g_imgui_init) {
            ImGui_ImplDX9_Shutdown();
            ImGui_ImplWin32_Shutdown();
            ImGui::DestroyContext();
            g_imgui_init = false;
        }
    }
    return TRUE;
}
