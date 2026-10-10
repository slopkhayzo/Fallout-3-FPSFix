#define DIRECTINPUT_VERSION 0x0800
#include <windows.h>
#include <dinput.h>

#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>

namespace {

constexpr char kPatchVersion[] = "1.0.0";
constexpr uintptr_t kImageBase = 0x00400000;
constexpr uintptr_t kTimerCall = 0x006E43C7;
constexpr uintptr_t kTimerUpdate = 0x0086C280;
constexpr uintptr_t kHavokScheduleCall = 0x006E43F5;
constexpr uintptr_t kHavokSchedule = 0x008D3C10;
constexpr uintptr_t kOuterFrameCall = 0x006EEC86;
constexpr uintptr_t kGameFrame = 0x006EDBE0;
constexpr uintptr_t kSceneDrawCall = 0x006EC8B8;
constexpr uintptr_t kSceneDraw = 0x006EB5E0;
constexpr uintptr_t kRenderFinalizeCall = 0x006EDB8B;
constexpr uintptr_t kRenderDispatch = 0x006ECBA0;
constexpr uintptr_t kRenderFinalize = 0x00AEEAC0;
constexpr uintptr_t kBindImageSpacePassResource = 0x00B228D0;
constexpr uintptr_t kImageSpacePassDraw = 0x00B86390;
constexpr uintptr_t kHUDMainMenuTimerUpdate = 0x0086C280;
constexpr uintptr_t kHUDTargetTimerCall = 0x0064476A;
constexpr wchar_t kCaptureActiveEventName[] = L"Local\\Fallout3HFRCaptureActive";

constexpr uintptr_t kGlobalFrameCounter = 0x00F6DD80;
constexpr uintptr_t kDetectedProcessorCount = 0x0106CD30;
constexpr uintptr_t kPlayerSingleton = 0x0107A104;
constexpr uintptr_t kSaveLoadSingleton = 0x01079858;
constexpr uintptr_t kCalendarSingleton = 0x01079F68;
constexpr uintptr_t kProcessManager = 0x0107C0A0;
constexpr uintptr_t kAudioManager = 0x011791D8;
constexpr uintptr_t kSceneGraphSingleton = 0x0107A224;
constexpr uintptr_t kRendererSingleton = 0x0108F048;
constexpr uintptr_t kGlobalFrameDelta = 0x01090BAC;
constexpr uintptr_t kGlobalTimeMultiplier = 0x00F7544C;
constexpr uintptr_t kHavokRemainder = 0x010F2A70;
constexpr uintptr_t kHavokSubstepCount = 0x010F2A74;
constexpr uintptr_t kHavokPhysicsDelta = 0x010F2A6C;
constexpr uintptr_t kHavokMaxTime = 0x010F2BE8;
// TESMain singleton; it is the `this` of the monolithic frame (ECX at
// 006EEC80). +6 is the fly-cam flag and +7 the freeze-time flag written by
// the `tfc` toggle at 0076D870. The frame function itself gates its
// world/process/worker calls on +7 and on the menu-mode byte below.
constexpr uintptr_t kTESMainSingleton = 0x0107A0D4;
constexpr uintptr_t kMenuModeFlag = 0x0107A0F3;
// OSInputGlobals: the key query FUN_00BE8410 compares the current keyboard
// buffer at +0x18F8 with the previous one at +0x19F8; the mouse query
// FUN_00BE81C0 uses buttons at +0x1B30 (previous +0x1B44) and wheel +0x1B2C.
constexpr uintptr_t kOSInputGlobals = 0x011795C4;

enum class DispatchCounter : uint32_t {
    AudioPlay,
    ScriptRun,
    AnimationNote,
    InputPoll,
    Present,
    GeometryDispatch,
};

struct DispatchProbeSite {
    uintptr_t address;
    DispatchCounter counter;
    uint8_t overwriteLength;
    std::array<uint8_t, 12> expected;
    const char *name;
    uint32_t markerId;
    bool incrementCounter;
};

// Function-entry probes established from FOSE symbols and Ghidra control-flow
// analysis. Markers 401/402 bracket the indirect device Present call, while
// 501/502 bracket the state-1 BeginScene/default-target wrapper, and marker
// 503 observes each state-2 pass after BeginScene/target activation. Markers
// 1301-1304 trace the target-close/presentation-queue lifecycle, 1310
// snapshots the retained geometry accumulator before its reverse traversal,
// 1320/1321 bracket the image-space graph that opens the final state-1
// default-target pass, 1330 records each concrete image-space pass entry, and
// 1340 records the enclosing graph executor call and arguments, and 1350
// snapshots the fully bound final leaf immediately before its virtual draw;
// 1360 observes the retained resource after stock stack-wrapper release.
// Marker 1400 is the generic NiControllerSequence note fan-out, 1401/1402 are
// the normal/alternate player-control handler entries, and 1403/1404 mark the
// corresponding returns to the early-frame caller. Marker 1410 observes the
// HighProcess AttackCallback that accumulates the attack count. The temporary
// 1420/1421 producer and 1430/1431 clear probes were retired after validation.
// Markers 1801-1806 bracket the three function-pointer-only render-worker
// callback bodies adjacent to FUN_00724350/FUN_007243B0. Markers 1810/1811
// split callback A's internal DAT_0107AFF8 wait. Markers 1842-1845 refine the
// first pre-wait call group and its conditional ReleaseSemaphore path. Markers
// 1850/1851 bracket XInputGetState inside the input/controller update reached
// through FUN_00619230. Markers 1852-1859 subdivide the post-XInput path,
// including an exact bracket around FUN_0069F8D0. Markers 1860-1864 refine
// the late 00BFB870-to-0061E200 interval. Markers 1870-1872 count and split
// the effect-list lookup/virtual-callback loop. Markers 1880/1881 bracket the
// HUDMainMenu timer call inside the fifth callback. Marker 1813 precedes each
// populated worker-record wait inside FUN_007243B0, while marker 1814 observes
// the common iteration-advance block reached after a populated record is
// decremented or an empty record is skipped. Marker 1812 is installed in the
// frame-call table at the exact FUN_007244B0(0) release call. Together they
// identify the actual executing threads and overlap without changing any
// semaphore operation or the stock join.
// Markers 1950-1953 form a read-only digital-action path ledger inside the
// normal player-control handler. 1950 observes action 7 (tap reload / hold
// ready-holster) in a pressed/held state. 1951 is reached only by the timed
// ready-holster branch and is not an ordinary tap-reload acceptance marker.
// 1952 observes action 4 (attack) active, and 1953 identifies the attack
// gate's common fall-through path; it is not by itself proof of rejection.
// The input-poll counter in each snapshot associates these consumers with the
// sampled device state.
// Every overwritten instruction is position-independent on x86.
constexpr std::array<DispatchProbeSite, 56> kDispatchProbeSites = {{
    {0x00BD00C0, DispatchCounter::AudioPlay, 5,
     {0x8B, 0x01, 0x83, 0xF8, 0xFF}, "BSSoundHandle_Play", 0, true},
    {0x00540C50, DispatchCounter::ScriptRun, 7,
     {0x6A, 0xFF, 0x68, 0xBB, 0x76, 0xC3, 0x00}, "ScriptRunner_Run_timed", 0, true},
    {0x00540F60, DispatchCounter::ScriptRun, 7,
     {0x6A, 0xFF, 0x68, 0xFB, 0x76, 0xC3, 0x00}, "ScriptRunner_Run_compact", 0, true},
    {0x008BB4B0, DispatchCounter::AnimationNote, 6,
     {0x56, 0x57, 0x8B, 0xF9, 0x33, 0xF6}, "NiControllerSequence_NoteFanout", 1400, true},
    {0x00BE8FD0, DispatchCounter::InputPoll, 5,
     {0xA1, 0xA0, 0x95, 0x17, 0x01}, "OSInput_PollDevices", 0, true},
    {0x00788350, DispatchCounter::InputPoll, 6,
     {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0}, "PlayerControl_Normal_Entry", 1401, false},
    {0x00786770, DispatchCounter::InputPoll, 7,
     {0x6A, 0xFF, 0x68, 0xF8, 0xE8, 0xC6, 0x00}, "PlayerControl_Alternate_Entry", 1402, false},
    {0x006E47A5, DispatchCounter::InputPoll, 7,
     {0x80, 0x05, 0x58, 0xBA, 0x07, 0x01, 0xFF}, "PlayerControl_Normal_Return", 1403, false},
    {0x006E4751, DispatchCounter::InputPoll, 5,
     {0x5E, 0x83, 0xC4, 0x10, 0xC3}, "PlayerControl_Alternate_Return", 1404, false},
    {0x0073B980, DispatchCounter::AnimationNote, 5,
     {0x66, 0x8B, 0x44, 0x24, 0x04}, "HighProcess_AttackCallback", 1410, false},
    {0x00788D47, DispatchCounter::InputPoll, 7,
     {0xF6, 0x83, 0xDC, 0x05, 0x00, 0x00, 0x08}, "ReloadHolster_QueryActive", 1950, false},
    {0x00788E03, DispatchCounter::InputPoll, 7,
     {0xC6, 0x05, 0xC1, 0xBF, 0x07, 0x01, 0x01}, "ReadyHolster_HoldPath", 1951, false},
    {0x00789AD3, DispatchCounter::InputPoll, 7,
     {0x80, 0x3D, 0x5A, 0xBA, 0x07, 0x01, 0x00}, "Attack_QueryActive", 1952, false},
    {0x00789AF8, DispatchCounter::InputPoll, 5,
     {0x8B, 0x4B, 0x60, 0x8B, 0x11}, "Attack_CommonFallthrough", 1953, false},
    {0x00724550, DispatchCounter::Present, 6,
     {0x8B, 0x0D, 0xD4, 0xA0, 0x07, 0x01}, "RenderWorkerCallbackA_Entry", 1801, false},
    {0x00724699, DispatchCounter::Present, 10,
     {0xC7, 0x05, 0xC4, 0xAF, 0x07, 0x01, 0x07, 0x00, 0x00, 0x00},
     "RenderWorkerCallbackA_Exit", 1802, false},
    {0x00724641, DispatchCounter::Present, 6,
     {0x8B, 0x15, 0xF8, 0xAF, 0x07, 0x01}, "RenderWorkerCallbackA_WaitBegin", 1810, false},
    {0x0072465A, DispatchCounter::Present, 5,
     {0x68, 0xF4, 0xAF, 0x07, 0x01}, "RenderWorkerCallbackA_WaitEnd", 1811, false},
    {0x00619250, DispatchCounter::Present, 6,
     {0x8B, 0x0D, 0x24, 0x5B, 0x07, 0x01}, "RenderWorkerPreWait_00619250_Entry", 1842, false},
    {0x00627696, DispatchCounter::Present, 5,
     {0x85, 0xC0, 0x0F, 0x94, 0xC0}, "WorkerInputUpdate_XInputEnd", 1851, false},
    {0x006278C6, DispatchCounter::Present, 9,
     {0x8B, 0x46, 0x0C, 0x39, 0x05, 0xAC, 0xA5, 0xF6, 0x00},
     "WorkerInputUpdate_0069F8D0_End", 1854, false},
    {0x00628DFB, DispatchCounter::Present, 6,
     {0x8B, 0x0D, 0x1C, 0xA8, 0x07, 0x01}, "WorkerInputUpdate_00BFB870_End", 1860, false},
    {0x00628E1F, DispatchCounter::Present, 9,
     {0x84, 0xC0, 0xC6, 0x05, 0x29, 0x5B, 0x07, 0x01, 0x00},
     "WorkerInputUpdate_PreEffectList", 1861, false},
    {0x00628E9A, DispatchCounter::Present, 5,
     {0xBF, 0x03, 0x00, 0x00, 0x00}, "WorkerInputUpdate_PostEffectList", 1862, false},
    {0x00628F79, DispatchCounter::Present, 6,
     {0x8B, 0x5C, 0x24, 0x28, 0x6A, 0x01}, "WorkerInputUpdate_PostModeState", 1863, false},
    {0x00629003, DispatchCounter::Present, 7,
     {0x83, 0xBE, 0xBC, 0x04, 0x00, 0x00, 0x00}, "WorkerInputUpdate_ShortcutDispatch", 1864, false},
    {0x00628E37, DispatchCounter::Present, 7,
     {0x80, 0x3D, 0x29, 0x5B, 0x07, 0x01, 0x00}, "WorkerEffectList_Iteration", 1870, false},
    {0x00628E55, DispatchCounter::Present, 7,
     {0x8B, 0x10, 0x8B, 0xC8, 0x8B, 0x42, 0x2C}, "WorkerEffectList_CallbackBegin", 1872, false},
    {0x0065202F, DispatchCounter::Present, 6,
     {0x8B, 0x46, 0x3C, 0x8B, 0x4E, 0x38}, "HUDMainMenu_TimerEnd", 1881, false},
    {0x0072455B, DispatchCounter::Present, 7,
     {0x83, 0x3D, 0xB4, 0xAF, 0x07, 0x01, 0x00}, "RenderWorkerPreWait_FirstGroupExit", 1843, false},
    {0x00724564, DispatchCounter::Present, 5,
     {0xA1, 0xD0, 0xAF, 0x07, 0x01}, "RenderWorkerPreWait_ReleaseBegin", 1844, false},
    {0x00724574, DispatchCounter::Present, 5,
     {0x68, 0xCC, 0xAF, 0x07, 0x01}, "RenderWorkerPreWait_ReleaseEnd", 1845, false},
    {0x007246B0, DispatchCounter::Present, 6,
     {0x8B, 0x0D, 0xD4, 0xA0, 0x07, 0x01}, "RenderWorkerCallbackB_Entry", 1803, false},
    {0x007248C3, DispatchCounter::Present, 5,
     {0x5F, 0x5E, 0xC3, 0xCC, 0xCC}, "RenderWorkerCallbackB_Exit", 1804, false},
    {0x007248D0, DispatchCounter::Present, 6,
     {0x56, 0x57, 0x6A, 0x01, 0x6A, 0x00}, "RenderWorkerCallbackC_Entry", 1805, false},
    {0x00724A6E, DispatchCounter::Present, 5,
     {0x5F, 0x5E, 0xC3, 0xCC, 0xCC}, "RenderWorkerCallbackC_Exit", 1806, false},
    {0x007243D8, DispatchCounter::Present, 5,
     {0x6A, 0xFF, 0x51, 0xFF, 0xD3}, "RenderWorkerJoin_WaitBegin", 1813, false},
    {0x007243E0, DispatchCounter::Present, 6,
     {0x83, 0xC7, 0x01, 0x83, 0xFF, 0x02}, "RenderWorkerJoin_IterationAdvance", 1814, false},
    {0x008827A0, DispatchCounter::Present, 5,
     {0x8B, 0x41, 0x58, 0x8B, 0x08}, "D3D9Device_PresentEntry", 401, true},
    {0x008827B3, DispatchCounter::Present, 7,
     {0x33, 0xC9, 0x85, 0xC0, 0x0F, 0x9D, 0xC1}, "D3D9Device_PresentExit", 402, false},
    {0x00AEEC20, DispatchCounter::Present, 6,
     {0x8B, 0x0D, 0x48, 0xF0, 0x08, 0x01}, "FinalPassBegin_Entry", 501, false},
    {0x00AEEC59, DispatchCounter::Present, 5,
     {0x83, 0xC4, 0x08, 0x5E, 0xC3}, "FinalPassBegin_Exit", 502, false},
    {0x00AEEC99, DispatchCounter::Present, 5,
     {0x83, 0xC4, 0x08, 0x5E, 0xC3}, "State2PassBegin_Exit", 503, false},
    {0x006E5E90, DispatchCounter::Present, 7,
     {0x6A, 0xFF, 0x68, 0xB0, 0xB8, 0xC6, 0x00}, "MainTargetOwner_Entry", 504, false},
    {0x00AEEA50, DispatchCounter::Present, 5,
     {0xA1, 0xA8, 0xFD, 0x16, 0x01}, "TargetStackClose_Entry", 1301, false},
    {0x00AEE6A3, DispatchCounter::Present, 6,
     {0x8B, 0x86, 0x00, 0x02, 0x00, 0x00}, "ActiveTargetClose_AfterPrologue", 1302, false},
    {0x00879CB0, DispatchCounter::Present, 6,
     {0x83, 0xEC, 0x0C, 0x55, 0x8B, 0xE9}, "PresentQueueEnqueue_Entry", 1303, false},
    {0x00879EF0, DispatchCounter::Present, 8,
     {0x51, 0x80, 0xB9, 0xFC, 0x06, 0x00, 0x00, 0x00}, "PresentQueueDrain_Entry", 1304, false},
    {0x00AE7CA0, DispatchCounter::Present, 6,
     {0x53, 0x55, 0x56, 0x57, 0x8B, 0xF1}, "GeometryAccumulatorDrain_Entry", 1310, false},
    {0x00B0F230, DispatchCounter::GeometryDispatch, 5,
     {0x56, 0x8B, 0x74, 0x24, 0x08}, "GeometryDrawDispatch_Entry", 0, true},
    {0x00ADBEC0, DispatchCounter::Present, 5,
     {0x8B, 0x54, 0x24, 0x04, 0x56}, "FinalCompositeGraph_Entry", 1320, false},
    {0x00ADBEDB, DispatchCounter::Present, 5,
     {0x33, 0xF6, 0x8D, 0x49, 0x00}, "FinalCompositeGraph_AfterPasses", 1321, false},
    {0x00B86390, DispatchCounter::Present, 7,
     {0x6A, 0xFF, 0x68, 0xE0, 0xD2, 0xC7, 0x00}, "ImageSpacePass_Entry", 1330, false},
    {0x00B1D860, DispatchCounter::Present, 7,
     {0x6A, 0xFF, 0x68, 0x28, 0x02, 0xC8, 0x00}, "ImageSpacePassExecutor_Entry", 1340, false},
    {0x00B3063B, DispatchCounter::Present, 7,
     {0x8B, 0x8C, 0x24, 0x84, 0x00, 0x00, 0x00}, "FinalCompositeLeaf_Ready", 1350, false},
    {0x00B306C3, DispatchCounter::Present, 5,
     {0xB9, 0x24, 0x63, 0x17, 0x01}, "FinalCompositeLeaf_AfterRelease", 1360, false},
}};

struct ProbeSite {
    uintptr_t callAddress;
    uintptr_t originalTarget;
    uint32_t id;
    std::array<uint8_t, 5> expected;
    const char *name;
};

// Calls spanning the monolithic frame. IDs 1-16 are the coarse boundaries,
// IDs 101-111 refine the late-frame tail, ID 201 follows the D3D9 EndScene
// call, IDs 301-307 subdivide post-render cleanup, IDs 701-717 cover the live
// render branch, IDs 801-802 guard the exact main EndScene close, and IDs
// 901-915 divide the live scene routine into phases, 1501-1527 split every
// direct call between coarse markers 10 and 14, 1701-1716 split every
// additional direct call between coarse markers 7 and 10, 1820-1835 split
// the direct calls in callback A's variable pre-wait phase, 1840/1841 split
// the first group's nested calls, 1850 brackets its XInputGetState call with
// dispatch marker 1851, 1852-1864 subdivide the post-XInput update, 1870-1872
// split its effect-list loop, 1880/1881 bracket the HUDMainMenu timer call,
// 1890-1945 ledger every remaining direct call in FUN_006ED560, and
// 1960-1978 split the direct calls inside final-sync FUN_006E4510. IDs
// 1980-1986 trace the accepted weapon-fire path through both FUN_0071E150
// callers, its two shot-descriptor builders, the hitscan branch, hit
// resolution, and the descriptor's final free. The descriptor is transient
// hit data, not a persistent projectile object. IDs 1990-1999 are broad,
// read-only milestones inside the normal PlayerCharacter control handler used
// to isolate the sub-block that commits player rotation and camera state. IDs
// 2000-2003 bracket the mouse-look dispatcher and its yaw/pitch commit calls.
// IDs 2010-2017 ledger every direct call between the camera-parameter and
// reference-sync milestones so camera transform publication can be isolated.
// IDs 2020/2021 bracket the scene-hierarchy update inside FUN_0077D670.
// ID 306 is
// conditional on the multicore path used by the target system. Durations are
// derived from the observed event sequence rather than installation order.
constexpr std::array<ProbeSite, 247> kProbeSites = {{
    {0x006EDC90, 0x006E46E0,  1, {0xE8, 0x4B, 0x6A, 0xFF, 0xFF}, "early_player_scene"},
    {0x006EDCAD, 0x006EA9B0,  2, {0xE8, 0xFE, 0xCC, 0xFF, 0xFF}, "queued_work"},
    {0x006EDD2A, 0x006D6200,  3, {0xE8, 0xD1, 0x84, 0xFE, 0xFF}, "pre_timer"},
    {0x006EDD72, 0x006E4430,  4, {0xE8, 0xB9, 0x66, 0xFF, 0xFF}, "post_timer"},
    {0x006EDDBE, 0x006E42C0,  5, {0xE8, 0xFD, 0x64, 0xFF, 0xFF}, "gameplay_begin"},
    {0x006EDE8C, 0x0078E270,  6, {0xE8, 0xDF, 0x03, 0x0A, 0x00}, "world_phase_a"},
    {0x006EDF1D, 0x0078C030,  7, {0xE8, 0x0E, 0xE1, 0x09, 0x00}, "world_phase_b"},
    {0x006EDF85, 0x0046B690,  8, {0xE8, 0x06, 0xD7, 0xD7, 0xFF}, "scene_prepare"},
    {0x006EE01A, 0x00436B40,  9, {0xE8, 0x21, 0x8B, 0xD4, 0xFF}, "render_cluster"},
    {0x006EE087, 0x006E5830, 10, {0xE8, 0xA4, 0x77, 0xFF, 0xFF}, "post_render_sync"},
    {0x006EE0CE, 0x005C89C0, 11, {0xE8, 0xED, 0xA8, 0xED, 0xFF}, "late_gameplay"},
    {0x006EE151, 0x004EF9B0, 12, {0xE8, 0x5A, 0x18, 0xE0, 0xFF}, "ui_begin"},
    {0x006EE16F, 0x006F3F70, 13, {0xE8, 0xFC, 0x5D, 0x00, 0x00}, "cursor_input"},
    {0x006EE261, 0x006ED560, 14, {0xE8, 0xFA, 0xF2, 0xFF, 0xFF}, "ui_render_finalize"},
    {0x006EE2C3, 0x006E4510, 15, {0xE8, 0x48, 0x62, 0xFF, 0xFF}, "final_sync"},
    {0x006EE2E5, 0x00C24B70, 16, {0xE8, 0x86, 0x68, 0x53, 0x00}, "frame_cleanup"},
    {0x006EE098, 0x00619210, 1501, {0xE8, 0x73, 0xB1, 0xF2, 0xFF}, "m10_call_00619210"},
    {0x006EE09D, 0x00619230, 1502, {0xE8, 0x8E, 0xB1, 0xF2, 0xFF}, "m10_call_00619230"},
    {0x006EE0A2, 0x00619250, 1503, {0xE8, 0xA9, 0xB1, 0xF2, 0xFF}, "m10_call_00619250"},
    {0x006EE0A7, 0x00619160, 1504, {0xE8, 0xB4, 0xB0, 0xF2, 0xFF}, "m10_call_00619160"},
    {0x006EE0B0, 0x00619E30, 1505, {0xE8, 0x7B, 0xBD, 0xF2, 0xFF}, "m10_call_00619E30"},
    {0x006EE0BC, 0x0044F4B0, 1506, {0xE8, 0xEF, 0x13, 0xD6, 0xFF}, "m10_call_0044F4B0"},
    {0x006EE0C3, 0x00608BD0, 1507, {0xE8, 0x08, 0xAB, 0xF1, 0xFF}, "m10_call_00608BD0"},
    {0x006EE0E4, 0x005E9AD0, 1508, {0xE8, 0xE7, 0xB9, 0xEF, 0xFF}, "m11_call_005E9AD0"},
    {0x006EE0EB, 0x005E8FD0, 1509, {0xE8, 0xE0, 0xAE, 0xEF, 0xFF}, "m11_call_005E8FD0"},
    {0x006EE118, 0x007A74A0, 1510, {0xE8, 0x83, 0x93, 0x0B, 0x00}, "m11_call_007A74A0"},
    {0x006EE130, 0x0084C170, 1511, {0xE8, 0x3B, 0xE0, 0x15, 0x00}, "m11_call_0084C170"},
    {0x006EE135, 0x006191A0, 1512, {0xE8, 0x66, 0xB0, 0xF2, 0xFF}, "m11_call_006191A0"},
    {0x006EE141, 0x00619D10, 1513, {0xE8, 0xCA, 0xBB, 0xF2, 0xFF}, "m11_call_00619D10"},
    {0x006EE14C, 0x006ECC50, 1514, {0xE8, 0xFF, 0xEA, 0xFF, 0xFF}, "m11_call_006ECC50"},
    {0x006EE156, 0x00AE6870, 1515, {0xE8, 0x15, 0x87, 0x3F, 0x00}, "m12_call_00AE6870"},
    {0x006EE164, 0x0061F260, 1516, {0xE8, 0xF7, 0x10, 0xF3, 0xFF}, "m12_call_0061F260"},
    {0x006EE187, 0x006F37D0, 1517, {0xE8, 0x44, 0x56, 0x00, 0x00}, "m13_call_006F37D0"},
    {0x006EE1A0, 0x00BE82B0, 1518, {0xE8, 0x0B, 0xA1, 0x4F, 0x00}, "m13_call_00BE82B0_hide"},
    {0x006EE1DB, 0x00BE82B0, 1519, {0xE8, 0xD0, 0xA0, 0x4F, 0x00}, "m13_call_00BE82B0_show"},
    {0x006EE1E0, 0x00BE78D0, 1520, {0xE8, 0xEB, 0x96, 0x4F, 0x00}, "m13_call_00BE78D0_a"},
    {0x006EE1E9, 0x00BE7890, 1521, {0xE8, 0xA2, 0x96, 0x4F, 0x00}, "m13_call_00BE7890"},
    {0x006EE1F4, 0x006F4CD0, 1522, {0xE8, 0xD7, 0x6A, 0x00, 0x00}, "m13_call_006F4CD0"},
    {0x006EE1FC, 0x00BE78D0, 1523, {0xE8, 0xCF, 0x96, 0x4F, 0x00}, "m13_call_00BE78D0_b"},
    {0x006EE229, 0x0044F380, 1524, {0xE8, 0x52, 0x11, 0xD6, 0xFF}, "m13_call_0044F380"},
    {0x006EE242, 0x00BE78D0, 1525, {0xE8, 0x89, 0x96, 0x4F, 0x00}, "m13_call_00BE78D0_c"},
    {0x006EE253, 0x00BE78D0, 1526, {0xE8, 0x78, 0x96, 0x4F, 0x00}, "m13_call_00BE78D0_d"},
    {0x006EE25A, 0x00BE7820, 1527, {0xE8, 0xC1, 0x95, 0x4F, 0x00}, "m13_call_00BE7820"},
    {0x006EDF2B, 0x008294A0, 1701, {0xE8, 0x70, 0xB5, 0x13, 0x00}, "m7_call_008294A0"},
    {0x006EDF30, 0x006E3640, 1702, {0xE8, 0x0B, 0x57, 0xFF, 0xFF}, "m7_call_006E3640"},
    {0x006EDF35, 0x006E3970, 1703, {0xE8, 0x36, 0x5A, 0xFF, 0xFF}, "m7_call_006E3970"},
    {0x006EDF5F, 0x0059BD60, 1704, {0xE8, 0xFC, 0xDD, 0xEA, 0xFF}, "m7_call_0059BD60"},
    {0x006EDF69, 0x006E4890, 1705, {0xE8, 0x22, 0x69, 0xFF, 0xFF}, "m7_call_006E4890"},
    {0x006EDF76, 0x00619210, 1706, {0xE8, 0x95, 0xB2, 0xF2, 0xFF}, "m7_call_00619210"},
    {0x006EDF7B, 0x00619230, 1707, {0xE8, 0xB0, 0xB2, 0xF2, 0xFF}, "m7_call_00619230"},
    {0x006EDF80, 0x00619250, 1708, {0xE8, 0xCB, 0xB2, 0xF2, 0xFF}, "m7_call_00619250"},
    {0x006EDF8C, 0x0046C070, 1709, {0xE8, 0xDF, 0xE0, 0xD7, 0xFF}, "m8_call_0046C070"},
    {0x006EDFE8, 0x00AAEAF0, 1710, {0xE8, 0x03, 0x0B, 0x3C, 0x00}, "m8_call_00AAEAF0"},
    {0x006EDFFE, 0x00ADA410, 1711, {0xE8, 0x0D, 0xC4, 0x3E, 0x00}, "m8_call_00ADA410"},
    {0x006EE026, 0x00AE1630, 1712, {0xE8, 0x05, 0x36, 0x3F, 0x00}, "m9_call_00AE1630"},
    {0x006EE032, 0x00437DC0, 1713, {0xE8, 0x89, 0x9D, 0xD4, 0xFF}, "m9_call_00437DC0"},
    {0x006EE063, 0x007244B0, 1714, {0xE8, 0x48, 0x64, 0x03, 0x00}, "m9_call_007244B0"},
    {0x006EE070, 0x00724350, 1715, {0xE8, 0xDB, 0x62, 0x03, 0x00}, "m9_call_00724350"},
    {0x006EE080, 0x00725A00, 1716, {0xE8, 0x7B, 0x79, 0x03, 0x00}, "m9_call_00725A00"},
    {0x006ED61D, 0x00C24B70, 101, {0xE8, 0x4E, 0x75, 0x53, 0x00}, "r14_pre_lock"},
    {0x006ED63E, 0x00B0D030, 102, {0xE8, 0xED, 0xF9, 0x41, 0x00}, "r14_locked_begin"},
    {0x006ED86E, 0x00ADBE10, 103, {0xE8, 0x9D, 0xE5, 0x3E, 0x00}, "r14_post_render_branch"},
    {0x006ED873, 0x0061AA70, 104, {0xE8, 0xF8, 0xD1, 0xF2, 0xFF}, "r14_finalize_a"},
    {0x006ED87F, 0x006192A0, 105, {0xE8, 0x1C, 0xBA, 0xF2, 0xFF}, "r14_finalize_b"},
    {0x006ED88C, 0x00B0D0A0, 106, {0xE8, 0x0F, 0xF8, 0x41, 0x00}, "r14_finalize_c"},
    {0x006ED998, 0x00AAADC0, 107, {0xE8, 0x23, 0xD4, 0x3B, 0x00}, "r14_renderer_state_begin"},
    {0x006EDB8B, 0x00AEEAC0, 108, {0xE8, 0x30, 0x0F, 0x40, 0x00}, "r14_renderer_state_end"},
    {0x006EDB96, 0x00AAEF70, 109, {0xE8, 0xD5, 0x13, 0x3C, 0x00}, "r14_pre_unlock"},
    {0x006EDBB0, 0x007244B0, 1812, {0xE8, 0xFB, 0x68, 0x03, 0x00}, "render_worker_gate_release"},
    {0x006E48F0, 0x00619210, 1840, {0xE8, 0x1B, 0x49, 0xF3, 0xFF}, "worker_first_group_call_00619210"},
    {0x006E48F5, 0x00619230, 1841, {0xE8, 0x36, 0x49, 0xF3, 0xFF}, "worker_first_group_call_00619230"},
    {0x00627691, 0x007F3746, 1850, {0xE8, 0xB0, 0xC0, 0x1C, 0x00}, "worker_input_update_xinput_begin"},
    {0x006278B6, 0x006970F0, 1852, {0xE8, 0x35, 0xF8, 0x06, 0x00}, "worker_input_update_call_006970F0"},
    {0x006278C1, 0x0069F8D0, 1853, {0xE8, 0x0A, 0x80, 0x07, 0x00}, "worker_input_update_call_0069F8D0"},
    {0x00627BE1, 0x0061F8C0, 1855, {0xE8, 0xDA, 0x7C, 0xFF, 0xFF}, "worker_input_update_call_0061F8C0"},
    {0x00628832, 0x006E4EB0, 1856, {0xE8, 0x79, 0xC6, 0x0B, 0x00}, "worker_input_update_call_006E4EB0_late"},
    {0x006289DF, 0x006301B0, 1857, {0xE8, 0xCC, 0x77, 0x00, 0x00}, "worker_input_update_call_006301B0"},
    {0x00628DF6, 0x00BFB870, 1858, {0xE8, 0x75, 0x2A, 0x5D, 0x00}, "worker_input_update_call_00BFB870"},
    {0x0062909B, 0x0061E200, 1859, {0xE8, 0x60, 0x51, 0xFF, 0xFF}, "worker_input_update_call_0061E200_tail"},
    {0x00628E4C, 0x00BEAB90, 1871, {0xE8, 0x3F, 0x1D, 0x5C, 0x00}, "worker_effect_list_lookup"},
    {0x0065202A, 0x0086C280, 1880, {0xE8, 0x51, 0xA2, 0x21, 0x00}, "hud_main_menu_timer_begin"},
    {0x006ED59A, 0x0076FF40, 1890, {0xE8, 0xA1, 0x29, 0x08, 0x00}, "r14_call_0076FF40"},
    {0x006ED5AE, 0x0076FF40, 1891, {0xE8, 0x8D, 0x29, 0x08, 0x00}, "r14_call_0076FF40"},
    {0x006ED5C3, 0x0076FF40, 1892, {0xE8, 0x78, 0x29, 0x08, 0x00}, "r14_call_0076FF40"},
    {0x006ED5D2, 0x0076FF40, 1893, {0xE8, 0x69, 0x29, 0x08, 0x00}, "r14_call_0076FF40"},
    {0x006ED5DC, 0x006ECC50, 1894, {0xE8, 0x6F, 0xF6, 0xFF, 0xFF}, "r14_call_006ECC50"},
    {0x006ED5E8, 0x0076FF40, 1895, {0xE8, 0x53, 0x29, 0x08, 0x00}, "r14_call_0076FF40"},
    {0x006ED604, 0x0076FF40, 1896, {0xE8, 0x37, 0x29, 0x08, 0x00}, "r14_call_0076FF40"},
    {0x006ED64C, 0x0048FDF0, 1897, {0xE8, 0x9F, 0x27, 0xDA, 0xFF}, "r14_call_0048FDF0"},
    {0x006ED65D, 0x00617BE0, 1898, {0xE8, 0x7E, 0xA5, 0xF2, 0xFF}, "r14_call_00617BE0"},
    {0x006ED66E, 0x00617BE0, 1899, {0xE8, 0x6D, 0xA5, 0xF2, 0xFF}, "r14_call_00617BE0"},
    {0x006ED697, 0x00433A30, 1900, {0xE8, 0x94, 0x63, 0xD4, 0xFF}, "r14_call_00433A30"},
    {0x006ED6A1, 0x0078C6D0, 1901, {0xE8, 0x2A, 0xF0, 0x09, 0x00}, "r14_call_0078C6D0"},
    {0x006ED6EC, 0x00617FD0, 1902, {0xE8, 0xDF, 0xA8, 0xF2, 0xFF}, "r14_call_00617FD0"},
    {0x006ED6FA, 0x00617FD0, 1903, {0xE8, 0xD1, 0xA8, 0xF2, 0xFF}, "r14_call_00617FD0"},
    {0x006ED701, 0x006E82D0, 1904, {0xE8, 0xCA, 0xAB, 0xFF, 0xFF}, "r14_call_006E82D0"},
    {0x006ED740, 0x00617BA0, 1905, {0xE8, 0x5B, 0xA4, 0xF2, 0xFF}, "r14_call_00617BA0"},
    {0x006ED754, 0x00B35640, 1906, {0xE8, 0xE7, 0x7E, 0x44, 0x00}, "r14_call_00B35640"},
    {0x006ED77F, 0x0047BC90, 1907, {0xE8, 0x0C, 0xE5, 0xD8, 0xFF}, "r14_call_0047BC90"},
    {0x006ED789, 0x006ECBA0, 1908, {0xE8, 0x12, 0xF4, 0xFF, 0xFF}, "r14_call_006ECBA0"},
    {0x006ED793, 0x0061BCC0, 1909, {0xE8, 0x28, 0xE5, 0xF2, 0xFF}, "r14_call_0061BCC0"},
    {0x006ED79C, 0x00619160, 1910, {0xE8, 0xBF, 0xB9, 0xF2, 0xFF}, "r14_call_00619160"},
    {0x006ED7AB, 0x0061AC60, 1911, {0xE8, 0xB0, 0xD4, 0xF2, 0xFF}, "r14_call_0061AC60"},
    {0x006ED7D0, 0x0061BCC0, 1912, {0xE8, 0xEB, 0xE4, 0xF2, 0xFF}, "r14_call_0061BCC0"},
    {0x006ED7D9, 0x006ECBA0, 1913, {0xE8, 0xC2, 0xF3, 0xFF, 0xFF}, "r14_call_006ECBA0"},
    {0x006ED7EA, 0x00B0D1F0, 1914, {0xE8, 0x01, 0xFA, 0x41, 0x00}, "r14_call_00B0D1F0"},
    {0x006ED7F7, 0x00B0D230, 1915, {0xE8, 0x34, 0xFA, 0x41, 0x00}, "r14_call_00B0D230"},
    {0x006ED806, 0x006E5910, 1916, {0xE8, 0x05, 0x81, 0xFF, 0xFF}, "r14_call_006E5910"},
    {0x006ED811, 0x0061AC60, 1917, {0xE8, 0x4A, 0xD4, 0xF2, 0xFF}, "r14_call_0061AC60"},
    {0x006ED823, 0x0061AC60, 1918, {0xE8, 0x38, 0xD4, 0xF2, 0xFF}, "r14_call_0061AC60"},
    {0x006ED835, 0x0061AC60, 1919, {0xE8, 0x26, 0xD4, 0xF2, 0xFF}, "r14_call_0061AC60"},
    {0x006ED85F, 0x006E6580, 1920, {0xE8, 0x1C, 0x8D, 0xFF, 0xFF}, "r14_call_006E6580"},
    {0x006ED869, 0x006E9530, 1921, {0xE8, 0xC2, 0xBC, 0xFF, 0xFF}, "r14_call_006E9530"},
    {0x006ED8A1, 0x00AF0DE0, 1922, {0xE8, 0x3A, 0x35, 0x40, 0x00}, "r14_call_00AF0DE0"},
    {0x006ED8D8, 0x00BE97A0, 1923, {0xE8, 0xC3, 0xBE, 0x4F, 0x00}, "r14_call_00BE97A0"},
    {0x006ED8F1, 0x00BE8410, 1924, {0xE8, 0x1A, 0xAB, 0x4F, 0x00}, "r14_call_00BE8410"},
    {0x006ED904, 0x006EFBE0, 1925, {0xE8, 0xD7, 0x22, 0x00, 0x00}, "r14_call_006EFBE0"},
    {0x006ED949, 0x00403230, 1926, {0xE8, 0xE2, 0x58, 0xD1, 0xFF}, "r14_call_00403230"},
    {0x006EDA53, 0x007F374C, 1927, {0xE8, 0xF4, 0x5C, 0x10, 0x00}, "r14_call_007F374C"},
    {0x006EDAEE, 0x00B0DA30, 1928, {0xE8, 0x3D, 0xFF, 0x41, 0x00}, "r14_call_00B0DA30"},
    {0x006EDAF6, 0x00B0DA80, 1929, {0xE8, 0x85, 0xFF, 0x41, 0x00}, "r14_call_00B0DA80"},
    {0x006EDAFE, 0x00B0DAD0, 1930, {0xE8, 0xCD, 0xFF, 0x41, 0x00}, "r14_call_00B0DAD0"},
    {0x006EDB05, 0x00B0DB20, 1931, {0xE8, 0x16, 0x00, 0x42, 0x00}, "r14_call_00B0DB20"},
    {0x006EDB0D, 0x00B0DB70, 1932, {0xE8, 0x5E, 0x00, 0x42, 0x00}, "r14_call_00B0DB70"},
    {0x006EDB14, 0x00B0DBF0, 1933, {0xE8, 0xD7, 0x00, 0x42, 0x00}, "r14_call_00B0DBF0"},
    {0x006EDB1D, 0x00B0DC40, 1934, {0xE8, 0x1E, 0x01, 0x42, 0x00}, "r14_call_00B0DC40"},
    {0x006EDB28, 0x00B0DFD0, 1935, {0xE8, 0xA3, 0x04, 0x42, 0x00}, "r14_call_00B0DFD0"},
    {0x006EDB2F, 0x00B0DCC0, 1936, {0xE8, 0x8C, 0x01, 0x42, 0x00}, "r14_call_00B0DCC0"},
    {0x006EDB38, 0x00B0DD10, 1937, {0xE8, 0xD3, 0x01, 0x42, 0x00}, "r14_call_00B0DD10"},
    {0x006EDB45, 0x00B0DDD0, 1938, {0xE8, 0x86, 0x02, 0x42, 0x00}, "r14_call_00B0DDD0"},
    {0x006EDB50, 0x00B0DE80, 1939, {0xE8, 0x2B, 0x03, 0x42, 0x00}, "r14_call_00B0DE80"},
    {0x006EDB57, 0x00B0E140, 1940, {0xE8, 0xE4, 0x05, 0x42, 0x00}, "r14_call_00B0E140"},
    {0x006EDB66, 0x00B0DED0, 1941, {0xE8, 0x65, 0x03, 0x42, 0x00}, "r14_call_00B0DED0"},
    {0x006EDB75, 0x00B0DF70, 1942, {0xE8, 0xF6, 0x03, 0x42, 0x00}, "r14_call_00B0DF70"},
    {0x006EDB7C, 0x00B0E0D0, 1943, {0xE8, 0x4F, 0x05, 0x42, 0x00}, "r14_call_00B0E0D0"},
    {0x006EDB83, 0x00B0E190, 1944, {0xE8, 0x08, 0x06, 0x42, 0x00}, "r14_call_00B0E190"},
    {0x006EDBC5, 0x00C0018C, 1945, {0xE8, 0xC2, 0x25, 0x51, 0x00}, "r14_call_00C0018C"},
    {0x00724556, 0x006E48F0, 1820, {0xE8, 0x95, 0x03, 0xFC, 0xFF}, "worker_pre_wait_call_006E48F0"},
    {0x00724585, 0x006F0C10, 1821, {0xE8, 0x86, 0xC6, 0xFC, 0xFF}, "worker_pre_wait_call_006F0C10"},
    {0x00724598, 0x007A74A0, 1822, {0xE8, 0x03, 0x2F, 0x08, 0x00}, "worker_pre_wait_call_007A74A0"},
    {0x007245A2, 0x0078C640, 1823, {0xE8, 0x99, 0x80, 0x06, 0x00}, "worker_pre_wait_call_0078C640"},
    {0x007245AC, 0x00794370, 1824, {0xE8, 0xBF, 0xFD, 0x06, 0x00}, "worker_pre_wait_call_00794370"},
    {0x007245B7, 0x004338D0, 1825, {0xE8, 0x14, 0xF3, 0xD0, 0xFF}, "worker_pre_wait_call_004338D0"},
    {0x007245C1, 0x0078E230, 1826, {0xE8, 0x6A, 0x9C, 0x06, 0x00}, "worker_pre_wait_call_0078E230"},
    {0x007245CC, 0x007A7CF0, 1827, {0xE8, 0x1F, 0x37, 0x08, 0x00}, "worker_pre_wait_call_007A7CF0"},
    {0x007245DE, 0x00792C80, 1828, {0xE8, 0x9D, 0xE6, 0x06, 0x00}, "worker_pre_wait_call_00792C80"},
    {0x007245E8, 0x0078C170, 1829, {0xE8, 0x83, 0x7B, 0x06, 0x00}, "worker_pre_wait_call_0078C170"},
    {0x007245FC, 0x0078C710, 1830, {0xE8, 0x0F, 0x81, 0x06, 0x00}, "worker_pre_wait_call_0078C710"},
    {0x0072460E, 0x00634F80, 1831, {0xE8, 0x6D, 0x09, 0xF1, 0xFF}, "worker_pre_wait_call_00634F80"},
    {0x00724618, 0x0078C4B0, 1832, {0xE8, 0x93, 0x7E, 0x06, 0x00}, "worker_pre_wait_call_0078C4B0"},
    {0x00724622, 0x0078C590, 1833, {0xE8, 0x69, 0x7F, 0x06, 0x00}, "worker_pre_wait_call_0078C590"},
    {0x00724627, 0x0044B540, 1834, {0xE8, 0x14, 0x6F, 0xD2, 0xFF}, "worker_pre_wait_call_0044B540"},
    {0x0072463C, 0x00437290, 1835, {0xE8, 0x4F, 0x2C, 0xD1, 0xFF}, "worker_pre_wait_call_00437290"},
    {0x006EE268, 0x006E4900, 110, {0xE8, 0x93, 0x66, 0xFF, 0xFF}, "post_r14_cleanup"},
    {0x006EE2B0, 0x007243B0, 111, {0xE8, 0xFB, 0x60, 0x03, 0x00}, "render_thread_handoff"},
    {0x0086E78B, 0x00884F40, 201, {0xE8, 0xB0, 0x67, 0x01, 0x00}, "post_d3d9_endscene"},
    {0x006E490B, 0x00BCFE20, 301, {0xE8, 0x10, 0xB5, 0x4E, 0x00}, "cleanup_begin"},
    {0x006E4910, 0x006BF3A0, 302, {0xE8, 0x8B, 0xAA, 0xFD, 0xFF}, "cleanup_phase_b"},
    {0x006E4915, 0x006BDE30, 303, {0xE8, 0x16, 0x95, 0xFD, 0xFF}, "cleanup_phase_c"},
    {0x006E491C, 0x006C41F0, 304, {0xE8, 0xCF, 0xF8, 0xFD, 0xFF}, "cleanup_phase_d"},
    {0x006E4926, 0x006E4660, 305, {0xE8, 0x35, 0xFD, 0xFF, 0xFF}, "cleanup_phase_e"},
    {0x006E4935, 0x004E1CE0, 306, {0xE8, 0xA6, 0xD3, 0xDF, 0xFF}, "cleanup_multicore"},
    {0x006E494F, 0x00512BA0, 307, {0xE8, 0x4C, 0xE2, 0xE2, 0xFF}, "cleanup_tail"},
    {0x006EC724, 0x006E6510, 701, {0xE8, 0xE7, 0x9D, 0xFF, 0xFF}, "live_post_target"},
    {0x006EC796, 0x0061AB20, 702, {0xE8, 0x85, 0xE3, 0xF2, 0xFF}, "live_scene_prepare"},
    {0x006EC81B, 0x0061A680, 703, {0xE8, 0x60, 0xDE, 0xF2, 0xFF}, "live_scene_state"},
    {0x006EC89D, 0x00AD5A10, 704, {0xE8, 0x6E, 0x91, 0x3E, 0x00}, "live_scene_setup"},
    {0x006EC8B8, 0x006EB5E0, 705, {0xE8, 0x23, 0xED, 0xFF, 0xFF}, "live_scene_draw"},
    {0x006EC900, 0x00B11B50, 706, {0xE8, 0x4B, 0x52, 0x42, 0x00}, "live_post_scene"},
    {0x006EC93A, 0x006E6190, 707, {0xE8, 0x51, 0x98, 0xFF, 0xFF}, "live_overlay_begin"},
    {0x006EC978, 0x00AE7350, 708, {0xE8, 0xD3, 0xA9, 0x3F, 0x00}, "live_overlay_state"},
    {0x006EC98B, 0x006E63D0, 709, {0xE8, 0x40, 0x9A, 0xFF, 0xFF}, "live_overlay_prepare"},
    {0x006EC999, 0x006E65F0, 710, {0xE8, 0x52, 0x9C, 0xFF, 0xFF}, "live_overlay_draw_a"},
    {0x006EC9DF, 0x006E6A40, 711, {0xE8, 0x5C, 0xA0, 0xFF, 0xFF}, "live_overlay_draw_b"},
    {0x006ECA17, 0x006EAD80, 712, {0xE8, 0x64, 0xE3, 0xFF, 0xFF}, "live_post_overlay"},
    {0x006ECAE9, 0x006E73F0, 713, {0xE8, 0x02, 0xA9, 0xFF, 0xFF}, "live_tail_a"},
    {0x006ECB12, 0x006E7D70, 714, {0xE8, 0x59, 0xB2, 0xFF, 0xFF}, "live_tail_b"},
    {0x006ECB20, 0x00AEEB20, 715, {0xE8, 0xFB, 0x1F, 0x40, 0x00}, "live_target_finalize"},
    {0x006ECB2C, 0x00ADA4E0, 716, {0xE8, 0xAF, 0xD9, 0x3E, 0x00}, "live_tail_c"},
    {0x006ECB3B, 0x006E7BE0, 717, {0xE8, 0xA0, 0xB0, 0xFF, 0xFF}, "live_finalize"},
    {0x006E7452, 0x00AEEB20, 801, {0xE8, 0xC9, 0x76, 0x40, 0x00}, "endscene_owner_target_finalize"},
    {0x006E7457, 0x0061B960, 802, {0xE8, 0x04, 0x45, 0xF3, 0xFF}, "endscene_owner_mode"},
    {0x006EB718, 0x008338B0, 901, {0xE8, 0x93, 0x81, 0x14, 0x00}, "scene_phase_setup"},
    {0x006EC0AA, 0x00AE5870, 902, {0xE8, 0xC1, 0x97, 0x3F, 0x00}, "scene_phase_post_traversal"},
    {0x006EC0E2, 0x00ADAEC0, 903, {0xE8, 0xD9, 0xED, 0x3E, 0x00}, "scene_phase_camera"},
    {0x006EC158, 0x00B0D4A0, 904, {0xE8, 0x43, 0x13, 0x42, 0x00}, "scene_phase_draw_setup"},
    {0x006EC165, 0x00B0D1F0, 905, {0xE8, 0x86, 0x10, 0x42, 0x00}, "scene_phase_group_begin"},
    {0x006EC179, 0x00833810, 906, {0xE8, 0x92, 0x76, 0x14, 0x00}, "scene_phase_culling_begin"},
    {0x006EC1E7, 0x00AEF360, 907, {0xE8, 0x74, 0x31, 0x40, 0x00}, "scene_phase_submit_a"},
    {0x006EC1FE, 0x00AEF360, 908, {0xE8, 0x5D, 0x31, 0x40, 0x00}, "scene_phase_submit_b"},
    {0x006EC20F, 0x00B0D230, 909, {0xE8, 0x1C, 0x10, 0x42, 0x00}, "scene_phase_group_end"},
    {0x006EC285, 0x00AEEDB0, 910, {0xE8, 0x26, 0x2B, 0x40, 0x00}, "scene_phase_render_a"},
    {0x006EC2D8, 0x00AEECC0, 911, {0xE8, 0xE3, 0x29, 0x40, 0x00}, "scene_phase_render_b"},
    {0x006EC36F, 0x00B02B90, 912, {0xE8, 0x1C, 0x68, 0x41, 0x00}, "scene_phase_secondary_setup"},
    {0x006EC3CD, 0x00AEF280, 913, {0xE8, 0xAE, 0x2E, 0x40, 0x00}, "scene_phase_secondary_render"},
    {0x006EC3E1, 0x00AEF470, 914, {0xE8, 0x8A, 0x30, 0x40, 0x00}, "scene_phase_secondary_finish"},
    {0x006EC48E, 0x0076FF40, 915, {0xE8, 0xAD, 0x3A, 0x08, 0x00}, "scene_phase_cleanup"},
    {0x006E4513, 0x00619B80, 1960, {0xE8, 0x68, 0x56, 0xF3, 0xFF}, "final_sync_call_00619B80"},
    {0x006E451C, 0x00619620, 1961, {0xE8, 0xFF, 0x50, 0xF3, 0xFF}, "final_sync_call_00619620"},
    {0x006E4538, 0x0063D270, 1962, {0xE8, 0x33, 0x8D, 0xF5, 0xFF}, "final_sync_call_0063D270"},
    {0x006E4571, 0x0078C0F0, 1963, {0xE8, 0x7A, 0x7B, 0x0A, 0x00}, "final_sync_call_0078C0F0"},
    {0x006E4584, 0x00794210, 1964, {0xE8, 0x87, 0xFC, 0x0A, 0x00}, "final_sync_call_00794210"},
    {0x006E458B, 0x0078C510, 1965, {0xE8, 0x80, 0x7F, 0x0A, 0x00}, "final_sync_call_0078C510"},
    {0x006E4595, 0x0078C460, 1966, {0xE8, 0xC6, 0x7E, 0x0A, 0x00}, "final_sync_call_0078C460"},
    {0x006E45A9, 0x00794040, 1967, {0xE8, 0x92, 0xFA, 0x0A, 0x00}, "final_sync_call_00794040"},
    {0x006E45AE, 0x00619E90, 1968, {0xE8, 0xDD, 0x58, 0xF3, 0xFF}, "final_sync_call_00619E90"},
    {0x006E45BE, 0x006975F0, 1969, {0xE8, 0x2D, 0x30, 0xFB, 0xFF}, "final_sync_call_006975F0"},
    {0x006E45CC, 0x004E24E0, 1970, {0xE8, 0x0F, 0xDF, 0xDF, 0xFF}, "final_sync_call_004E24E0"},
    {0x006E45D7, 0x006F0C30, 1971, {0xE8, 0x54, 0xC6, 0x00, 0x00}, "final_sync_call_006F0C30"},
    {0x006E45E2, 0x006F0C90, 1972, {0xE8, 0xA9, 0xC6, 0x00, 0x00}, "final_sync_call_006F0C90"},
    {0x006E45E7, 0x004E1CE0, 1973, {0xE8, 0xF4, 0xD6, 0xDF, 0xFF}, "final_sync_call_004E1CE0"},
    {0x006E45FE, 0x006F0C10, 1974, {0xE8, 0x0D, 0xC6, 0x00, 0x00}, "final_sync_call_006F0C10"},
    {0x006E4609, 0x006194D0, 1975, {0xE8, 0xC2, 0x4E, 0xF3, 0xFF}, "final_sync_call_006194D0"},
    {0x006E4611, 0x006194B0, 1976, {0xE8, 0x9A, 0x4E, 0xF3, 0xFF}, "final_sync_call_006194B0"},
    {0x006E4637, 0x007A9280, 1977, {0xE8, 0x44, 0x4C, 0x0C, 0x00}, "final_sync_call_007A9280_a"},
    {0x006E464A, 0x007A9280, 1978, {0xE8, 0x31, 0x4C, 0x0C, 0x00}, "final_sync_call_007A9280_b"},
    {0x0071EBE3, 0x0071E150, 1980, {0xE8, 0x68, 0xF5, 0xFF, 0xFF}, "weapon_fire_primary_dispatch"},
    {0x007C78CE, 0x0071E150, 1981, {0xE8, 0x7D, 0x68, 0xF5, 0xFF}, "weapon_fire_alternate_dispatch"},
    {0x0071E330, 0x007C4300, 1982, {0xE8, 0xCB, 0x5F, 0x0A, 0x00}, "shot_descriptor_builder_cached"},
    {0x0071E4B2, 0x007C4300, 1983, {0xE8, 0x49, 0x5E, 0x0A, 0x00}, "shot_descriptor_builder_normal"},
    {0x0071E694, 0x006C4EB0, 1984, {0xE8, 0x17, 0x68, 0xFA, 0xFF}, "shot_hitscan_branch"},
    {0x0071E78B, 0x0071C930, 1985, {0xE8, 0xA0, 0xE1, 0xFF, 0xFF}, "shot_hit_resolution"},
    {0x0071E7AF, 0x0086BA60, 1986, {0xE8, 0xAC, 0xD2, 0x14, 0x00}, "shot_descriptor_final_free"},
    {0x007884A0, 0x006E4EB0, 1990, {0xE8, 0x0B, 0xCA, 0xF5, 0xFF}, "player_control_after_initial_state"},
    {0x00788551, 0x00778A00, 1991, {0xE8, 0xAA, 0x04, 0xFF, 0xFF}, "player_control_after_process_setup"},
    {0x0078917E, 0x00778920, 1992, {0xE8, 0x9D, 0xF7, 0xFE, 0xFF}, "player_control_before_movement_input"},
    {0x00789AA7, 0x007755E0, 1993, {0xE8, 0x34, 0xBB, 0xFE, 0xFF}, "player_control_after_mover_update"},
    {0x0078A0E4, 0x0071F3C0, 1994, {0xE8, 0xD7, 0x52, 0xF9, 0xFF}, "player_control_action_dispatch"},
    {0x0078A8E9, 0x004EE000, 1995, {0xE8, 0x12, 0x37, 0xD6, 0xFF}, "player_control_late_action_state"},
    {0x0078AB14, 0x00788130, 1996, {0xE8, 0x17, 0xD6, 0xFF, 0xFF}, "player_control_dialogue_boundary"},
    {0x0078AC17, 0x00777DB0, 1997, {0xE8, 0x94, 0xD1, 0xFE, 0xFF}, "player_control_camera_parameter_update"},
    {0x0078ACC7, 0x004E1370, 1998, {0xE8, 0xA4, 0x66, 0xD5, 0xFF}, "player_control_reference_sync"},
    {0x0078AD57, 0x004DD7D0, 1999, {0xE8, 0x74, 0x2A, 0xD5, 0xFF}, "player_control_tail"},
    {0x007889D3, 0x0077B3A0, 2000, {0xE8, 0xC8, 0x29, 0xFF, 0xFF}, "player_look_dispatch_begin"},
    {0x0077C617, 0x00765400, 2001, {0xE8, 0xE4, 0x8D, 0xFE, 0xFF}, "player_look_yaw_commit"},
    {0x0077C642, 0x007654D0, 2002, {0xE8, 0x89, 0x8E, 0xFE, 0xFF}, "player_look_pitch_commit"},
    {0x00788A0C, 0x007392E0, 2003, {0xE8, 0xCF, 0x08, 0xFB, 0xFF}, "player_look_dispatch_return"},
    {0x0078AC35, 0x00729160, 2010, {0xE8, 0x26, 0xE5, 0xF9, 0xFF}, "player_camera_tail_call_00729160_a"},
    {0x0078AC4D, 0x006F8F30, 2011, {0xE8, 0xDE, 0xE2, 0xF6, 0xFF}, "player_camera_tail_call_006F8F30_a"},
    {0x0078AC5C, 0x0070D7D0, 2012, {0xE8, 0x6F, 0x2B, 0xF8, 0xFF}, "player_camera_tail_call_0070D7D0_a"},
    {0x0078AC7A, 0x00729160, 2013, {0xE8, 0xE1, 0xE4, 0xF9, 0xFF}, "player_camera_tail_call_00729160_b"},
    {0x0078AC92, 0x006F8F30, 2014, {0xE8, 0x99, 0xE2, 0xF6, 0xFF}, "player_camera_tail_call_006F8F30_b"},
    {0x0078ACA1, 0x0070D7D0, 2015, {0xE8, 0x2A, 0x2B, 0xF8, 0xFF}, "player_camera_tail_call_0070D7D0_b"},
    {0x0078ACA8, 0x0071ED50, 2016, {0xE8, 0xA3, 0x40, 0xF9, 0xFF}, "player_camera_tail_call_0071ED50"},
    {0x0078ACBA, 0x0077D670, 2017, {0xE8, 0xB1, 0x29, 0xFF, 0xFF}, "player_camera_tail_call_0077D670"},
    {0x0077E538, 0x008264C0, 2020, {0xE8, 0x83, 0x7F, 0x0A, 0x00}, "camera_scene_hierarchy_update"},
    {0x0077E55C, 0x00BCF510, 2021, {0xE8, 0xAF, 0x0F, 0x45, 0x00}, "camera_scene_hierarchy_update_return"},
}};

// The build this was developed against (GOG 1.7.0.3). Reported in the log for
// comparison only; nothing is refused because of it.
constexpr DWORD kReferencePeTimestamp = 0x4A40F18B;

// What decides whether the patch may be installed is the executable's layout,
// not its identity: every hook site is checked against the exact call bytes
// expected there (which also fixes the address of the function it calls), and
// the fixed data addresses the patch reads are checked here, each through
// two instructions of the game that reference it. Any executable in which all
// of these hold has the code and data where the patch expects them, whichever
// storefront it came from.
struct LayoutAnchor {
    uintptr_t address;
    uint8_t length;
    uint8_t bytes[6];
    const char *what;
};
constexpr LayoutAnchor kLayoutAnchors[] = {
    {0x00403D91, 6, {0x8B, 0x15, 0x04, 0xA1, 0x07, 0x01}, "player singleton"},
    {0x00403EB3, 6, {0x8B, 0x0D, 0x04, 0xA1, 0x07, 0x01}, "player singleton"},
    {0x0042913D, 6, {0x8B, 0x0D, 0xD4, 0xA0, 0x07, 0x01}, "TESMain singleton"},
    {0x00429E27, 6, {0x8B, 0x0D, 0xD4, 0xA0, 0x07, 0x01}, "TESMain singleton"},
    {0x00424300, 6, {0x80, 0x3D, 0xF3, 0xA0, 0x07, 0x01}, "menu-mode flag"},
    {0x0042D067, 6, {0x80, 0x3D, 0xF3, 0xA0, 0x07, 0x01}, "menu-mode flag"},
    {0x0067A559, 5, {0xA1, 0xC4, 0x95, 0x17, 0x01, 0x00}, "input globals"},
    {0x0067BD1E, 6, {0x8B, 0x0D, 0xC4, 0x95, 0x17, 0x01}, "input globals"},
    {0x004334B5, 6, {0xD8, 0x0D, 0xAC, 0x0B, 0x09, 0x01}, "global frame delta"},
    {0x004373DB, 6, {0xD8, 0x0D, 0xAC, 0x0B, 0x09, 0x01}, "global frame delta"},
    {0x00618108, 6, {0xD8, 0x35, 0x4C, 0x54, 0xF7, 0x00}, "global time multiplier"},
    {0x006181B0, 6, {0xD8, 0x35, 0x4C, 0x54, 0xF7, 0x00}, "global time multiplier"},
    {0x008D3CF4, 6, {0xD9, 0x05, 0xE8, 0x2B, 0x0F, 0x01}, "Havok maximum step"},
    {0x008D3E34, 6, {0xD8, 0x35, 0xE8, 0x2B, 0x0F, 0x01}, "Havok maximum step"},
    {0x00425B3F, 5, {0xA1, 0x48, 0xF0, 0x08, 0x01, 0x00}, "renderer singleton"},
    {0x00469878, 6, {0x8B, 0x0D, 0x48, 0xF0, 0x08, 0x01}, "renderer singleton"},
    {0x0048FD1F, 6, {0x8B, 0x0D, 0x24, 0xA2, 0x07, 0x01}, "scene graph singleton"},
    {0x00497BA5, 6, {0x8B, 0x0D, 0x24, 0xA2, 0x07, 0x01}, "scene graph singleton"},
    {0x0043C255, 5, {0xA1, 0x90, 0x2F, 0x07, 0x01, 0x00}, "sky singleton"},
    {0x0043C2B0, 5, {0xA3, 0x90, 0x2F, 0x07, 0x01, 0x00}, "sky singleton"},
    {0x004267D5, 6, {0x8B, 0x0D, 0xD8, 0xA0, 0x07, 0x01}, "TES object pointer"},
    {0x00426A52, 6, {0x8B, 0x0D, 0xD8, 0xA0, 0x07, 0x01}, "TES object pointer"},
    {0x004185A6, 5, {0xB9, 0xA0, 0xC0, 0x07, 0x01, 0x00}, "process manager"},
    {0x0041E706, 5, {0xB9, 0xA0, 0xC0, 0x07, 0x01, 0x00}, "process manager"},
    {0x00621F6C, 6, {0x39, 0x35, 0x78, 0xBA, 0x07, 0x01}, "first-person camera node"},
    {0x006E680C, 5, {0xA1, 0x78, 0xBA, 0x07, 0x01, 0x00}, "first-person camera node"},
};

constexpr uint32_t kRingCapacity = 1u << 15;
constexpr uint32_t kRingMask = kRingCapacity - 1;

struct BSTimer {
    uint8_t disableCounter;
    uint8_t padding01[3];
    float clampMs;
    float clampRemainderMs;
    float deltaSeconds;
    uint32_t lastTimeMs;
    uint32_t firstTimeMs;
    bool changeTimeMultSlowly;
    bool sameFrameDelta;
    uint8_t padding1A[2];
};
static_assert(sizeof(BSTimer) == 0x1C);

enum class EventKind : uint32_t { Timer = 1, Havok = 2 };

enum StateValidity : uint32_t {
    kStatePlayer = 1u << 0,
    kStatePlayerProcess = 1u << 1,
    kStateCalendar = 1u << 2,
    kStateSaveManager = 1u << 3,
    kStateProcessManager = 1u << 4,
    kStateAudioManager = 1u << 5,
    kStateDispatchCounters = 1u << 6,
    kStateRenderer = 1u << 7,
    kStateSceneCamera = 1u << 8,
    kStateRenderAccumulator = 1u << 9,
    kStateFirstPersonAnimation = 1u << 10,
    kStateSceneTransforms = 1u << 11,
    kStateReadFault = 1u << 31,
};

constexpr uint32_t kAuthoritativeValidityMask =
    kStatePlayer | kStatePlayerProcess | kStateCalendar | kStateSaveManager |
    kStateProcessManager | kStateAudioManager | kStateDispatchCounters |
    kStateReadFault;

// Explicit fields only: never hash whole engine objects because their padding,
// pointers, and renderer-owned caches would create meaningless differences.
struct StateSnapshot {
    uint32_t validMask;
    uint64_t authoritativeHash;
    uint64_t eventQueueHash;
    uint32_t playerRefId;
    uint32_t cellRefId;
    uint32_t packageRefId;
    float playerPosition[3];
    float playerRotation[3];
    float playerScale;
    uint32_t processLevel;
    uint32_t lifeState;
    uint32_t sitSleepState;
    uint32_t playerStateFlags;
    uint32_t disabledControlFlags;
    uint32_t playerViewFlags;
    uint32_t firstPersonAnimDataPtr;
    uint32_t weaponAnimGroupId;
    int32_t weaponSequenceState1;
    int32_t weaponSequenceState2;
    uint32_t weaponSequencePtr;
    uint32_t weaponSequenceAnimGroupPtr;
    uint32_t weaponSequenceAnimGroupIndex;
    uint32_t packageProcedure;
    float packageStartTime;
    float processTime;
    float processSystemTime;
    float gameHour;
    float gameDaysPassed;
    uint32_t changedForms;
    uint32_t changedFormsVtable;
    uint32_t changedFormsDataPtr;
    uint32_t changedFormsAlloc;
    uint32_t audioRequestA;
    uint32_t audioRequestB;
    uint32_t audioRequestC;
    uint32_t playingSounds;
    uint32_t audioPlayCalls;
    uint32_t scriptRunCalls;
    uint32_t animationNoteCalls;
    uint32_t inputPollCalls;
    uint32_t presentCalls;
    uint32_t scriptDuringPresentCalls;
    uint32_t scriptDuringPresentSameThreadCalls;
    uint32_t scriptDuringPresentOtherThreadCalls;
    uint32_t lastScriptDuringPresentThreadId;
    uint32_t scriptDuringState2PassCalls;
    uint32_t scriptDuringState2PassSameThreadCalls;
    uint32_t scriptDuringState2PassOtherThreadCalls;
    uint32_t lastScriptDuringState2PassThreadId;
    uint32_t changedFormsClearCalls;
    uint32_t lastChangedFormsClearReturnAddress;
    uint32_t changedFormsFreeCalls;
    uint32_t lastChangedFormsFreeReturnAddress;
    uint32_t state2PassReturnAddress;
    uint32_t state2OwnerReturnAddress;
    uint32_t rendererPtr;
    uint32_t rendererDevicePtr;
    uint32_t rendererFrameState;
    uint32_t rendererFrameId;
    uint32_t rendererTargetActive;
    uint32_t rendererDefaultTargetPtr;
    uint32_t rendererCurrentTargetPtr;
    uint32_t rendererSecondaryTargetPtr;
    uint32_t rendererTargetColorBufferCount;
    uint32_t rendererTargetColorBuffer0Ptr;
    uint32_t rendererTargetDepthBufferPtr;
    uint32_t rendererTargetColorWidth;
    uint32_t rendererTargetColorHeight;
    uint32_t rendererTargetDepthWidth;
    uint32_t rendererTargetDepthHeight;
    uint32_t rendererTargetColorDataPtr;
    uint32_t rendererTargetDepthDataPtr;
    uint32_t rendererPresentQueueHeadPtr;
    uint32_t rendererPresentQueueTailPtr;
    uint32_t rendererPresentQueueCount;
    uint32_t rendererPresentQueueObjectPtr;
    uint32_t rendererPresentQueueObjectVtable;
    uint32_t rendererPresentQueueSwapChainPtr;
    uint32_t geometryDispatchCalls;
    uint32_t renderAccumulatorPtr;
    uint32_t renderAccumulatorCount;
    uint32_t renderAccumulatorArrayPtr;
    uint32_t renderAccumulatorCursor;
    uint32_t renderAccumulatorCurrentGeometryPtr;
    uint32_t renderAccumulatorPassId;
    uint32_t renderAccumulatorReverseGeometryPtr;
    uint32_t renderAccumulatorReversePropertyPtr;
    uint32_t compositePassOrdinal;
    uint32_t compositePassThisPtr;
    uint32_t compositePassBasePtr;
    uint32_t compositePassVtable;
    uint32_t compositePassTargetSlotPtr;
    uint32_t compositePassTargetBindingPtr;
    uint32_t compositePassTargetPtr;
    uint32_t compositePassTargetVtable;
    uint32_t compositePassTargetRefCount;
    uint32_t compositePassReturnAddress;
    uint32_t compositePassArg0;
    uint32_t compositePassArg1;
    uint32_t compositePassArg2;
    uint32_t compositePassArg3;
    uint32_t compositeExecutorGraphPtr;
    uint32_t compositeExecutorReturnAddress;
    uint32_t compositeExecutorIndex;
    uint32_t compositeExecutorArg1;
    uint32_t compositeExecutorArg2;
    uint32_t compositeExecutorArg3;
    uint32_t compositeExecutorArg4;
    uint32_t compositeExecutorArg5;
    uint32_t compositeLeafPassPtr;
    uint32_t compositeLeafRootPtr;
    uint32_t compositeLeafCaller;
    uint32_t compositeLeafArg0;
    uint32_t compositeLeafArg1;
    uint32_t compositeLeafArg2;
    uint32_t compositeLeafBindingArrayPtr;
    uint32_t compositeLeafBinding0Ptr;
    uint32_t compositeLeafBinding1Ptr;
    uint32_t compositeLeafBinding2Ptr;
    uint32_t compositeLeafBinding3Ptr;
    uint32_t compositeLeafBinding1Flags;
    uint32_t compositeLeafBinding1ResourcePtr;
    uint32_t compositeLeafBinding1Metadata;
    uint32_t compositeLeafBinding1Aux;
    uint32_t compositeLeafBinding1ResourceVtable;
    uint32_t compositeLeafBinding1ResourceRefCount;
    uint32_t compositeLeafBinding1PostReleaseRefCount;
    uint32_t compositeLeafBinding0Flags;
    uint32_t compositeLeafBinding0ResourcePtr;
    uint32_t compositeLeafBinding0Metadata;
    uint32_t compositeLeafBinding0Aux;
    uint32_t compositeLeafBinding0ResourceVtable;
    uint32_t compositeLeafBinding0ResourceRefCount;
    uint32_t compositeLeafBinding2Flags;
    uint32_t compositeLeafBinding2ResourcePtr;
    uint32_t compositeLeafBinding2Metadata;
    uint32_t compositeLeafBinding2Aux;
    uint32_t compositeLeafBinding2ResourceVtable;
    uint32_t compositeLeafBinding2ResourceRefCount;
    uint32_t compositeLeafBinding3Flags;
    uint32_t compositeLeafBinding3ResourcePtr;
    uint32_t compositeLeafBinding3Metadata;
    uint32_t compositeLeafBinding3Aux;
    uint32_t compositeLeafBinding3ResourceVtable;
    uint32_t compositeLeafBinding3ResourceRefCount;
    uint32_t retentionAcquireCalls;
    uint32_t retentionReleaseCalls;
    uint32_t retentionRejectCalls;
    uint32_t retentionForcedReleaseCalls;
    uint32_t retentionActive;
    uint32_t retentionSlot1AcquireRefCount;
    uint32_t retentionSlot2AcquireRefCount;
    uint32_t retentionSlot3AcquireRefCount;
    uint32_t retentionSlot1ReleaseRefCount;
    uint32_t retentionSlot2ReleaseRefCount;
    uint32_t retentionSlot3ReleaseRefCount;
    uint32_t retentionRejectMask;
    uint32_t retentionObservedSlot1RefCount;
    uint32_t retentionObservedSlot2RefCount;
    uint32_t retentionObservedSlot3RefCount;
    uint32_t leafLifetimeSampleCalls;
    uint32_t leafLifetimeCheckCalls;
    uint32_t leafLifetimeBaselineFaultMask;
    uint32_t leafLifetimePostPresentFaultMask;
    uint32_t leafLifetimeChangeMask;
    uint32_t leafLifetimeBaselineHash;
    uint32_t leafLifetimePostPresentHash;
    uint32_t leafReplayAttemptCalls;
    uint32_t leafReplayDrawCalls;
    uint32_t leafReplayFinalizeCalls;
    uint32_t leafReplayRejectCalls;
    uint32_t leafReplayRejectMask;
    uint32_t leafReplayActive;
    uint32_t sceneGraphPtr;
    uint32_t cameraPtr;
    uint64_t cameraLocalRotationHash;
    uint64_t cameraWorldRotationHash;
    uint32_t sceneUpdateRootPtr;
    uint64_t sceneUpdateRootLocalRotationHash;
    uint64_t sceneUpdateRootWorldRotationHash;
    uint32_t cameraParentPtr[4];
    uint64_t cameraParentLocalRotationHash[4];
    uint64_t cameraParentWorldRotationHash[4];
    float cameraWorldPosition[3];
    float cameraWorldScale;
    float cameraFrustum[6];
    uint32_t cameraOrthographic;
    uint32_t transformNodePtr[4];
    uint32_t transformNodeParentPtr[4];
    uint32_t transformNodeFlags[4];
    uint64_t transformNodeLocalRotationHash[4];
    uint64_t transformNodeWorldRotationHash[4];
    float transformNodeLocalPosition[4][3];
    float transformNodeWorldPosition[4][3];
    float transformNodeLocalScale[4];
    float transformNodeWorldScale[4];
};

struct TelemetryEvent {
    std::atomic<uint32_t> sequence;
    uint32_t kind;
    uint32_t probeId;
    uint32_t threadId;
    int64_t qpc;
    uint32_t frame;
    uint32_t pulse;
    double wallDeltaMs;
    double accumulatorMs;
    uint32_t timerInputMs;
    float timerClampMs;
    float timerClampRemainderMs;
    float frameDeltaSeconds;
    float timeMultiplier;
    float havokMaxTime;
    float havokPhysicsDelta;
    float havokRemainder;
    uint32_t havokSubsteps;
    StateSnapshot state;
};

std::array<TelemetryEvent, kRingCapacity> g_ring{};
// Producers reserve unique sequence numbers with compare-exchange.  The log
// thread may observe the reservation ceiling before a producer commits its
// slot, so it also waits for the per-slot release sequence below.
std::atomic<uint32_t> g_writeIndex{0};
std::atomic<uint32_t> g_readIndex{0};
std::atomic<uint32_t> g_dropped{0};
std::atomic<bool> g_stop{false};

HMODULE g_self = nullptr;
HMODULE g_realDinput = nullptr;
HANDLE g_logThread = nullptr;
LARGE_INTEGER g_qpcFrequency{};
LARGE_INTEGER g_lastQpc{};
double g_accumulatorMs = 0.0;
double g_simulationStepMs = 1000.0 / 60.0;
double g_maxWallDeltaMs = 250.0;
bool g_telemetryEnabled = true;
bool g_quantizedDeltaEnabled = false;
bool g_frameRegionTelemetryEnabled = false;
bool g_authoritativeStateTelemetryEnabled = false;
bool g_eventDispatchTelemetryEnabled = false;
bool g_sceneTransformTelemetryEnabled = false;
bool g_singleCoreFrameEnabled = false;
bool g_sceneDrawReplayEnabled = false;
bool g_postPresentReplayEnabled = false;
bool g_postPresentSameFrameIdEnabled = false;
bool g_leafResourceRetentionEnabled = false;
bool g_postPresentLeafReplayEnabled = false;
bool g_hudTimerNoSleepEnabled = false;
bool g_renderCameraPositionInterpolationEnabled = false;
bool g_renderCameraPositionInterpolationFaulted = false;
bool g_renderTranslationInterpolationEnabled = false;
bool g_renderTranslationInterpolationFaulted = false;
bool g_freezeRenderFramesEnabled = false;
// Normal-play configuration: experiments are armed from process start without
// the launcher's named event, and no per-frame telemetry rows or input ledger
// lines are produced (the periodic status line still is).
bool g_armAtStartup = false;
bool g_quietTelemetry = false;
// Diagnostic: a hardware write breakpoint on one finger bone, to find the
// code that stretches the hand ("spider hands").
bool g_debugHandWriteTrace = false;
// Puts finger and thumb bones of the player's third-person skeleton back to
// the length they had when the skeleton was first seen.
bool g_fingerLengthFixEnabled = false;
bool g_alignHavokStepEnabled = false;
// -1: the frame hook made no decision; the timer hook accumulates as before.
int g_framePulseDecision = -1;
// Frames that cannot be frozen (menu mode, which includes conversations, and
// the first frames after it) are not quantised any more. Measured: on such
// frames, with a full tick on some and almost no time on the others, actor
// poses arrive two to four draws after the tick and several times per tick,
// which no single blend phase fits. The engine is a variable-step engine, so
// on these frames it is simply given the real frame time, every frame, and
// animates at the display rate by itself.
//
// Off by default, at the user's request: it steps the engine at the display
// rate on those frames (about a quarter of all frames in a session with
// menus), and this game is known to be unstable when stepped well above
// 60 Hz. With it off those frames are quantised as before, at 60 ticks a
// second, and actors turning at the start and end of a conversation step.
bool g_nativeStepUnfrozenEnabled = false;
bool g_frameNativeStep = false;
double g_frameNativeDeltaMs = 0.0;
constexpr int kFreezeWarmUpFrames = 30;
volatile LONG g_freezeStatNative = 0;
LARGE_INTEGER g_frameLastQpc{};
uint32_t g_freezeEligibleFrames = 0;
float g_havokMaxTimeOriginal = 0.0f;
bool g_havokMaxTimeOverridden = false;
volatile LONG g_freezeStatFrames = 0;
volatile LONG g_freezeStatPulses = 0;
volatile LONG g_freezeStatFrozen = 0;
volatile LONG g_freezeStatIneligible = 0;
bool g_latchInputEdgesEnabled = false;
// Digital input as last shown to a tick-frame player handler.
struct InputEdgeLatch {
    std::array<uint8_t, 256> keys{};
    std::array<uint8_t, 8> buttons{};
    std::array<uint8_t, 256> pendingKeys{};
    std::array<uint8_t, 8> pendingButtons{};
    std::array<uint8_t, 256> rawKeys{};
    std::array<uint8_t, 8> rawButtons{};
    bool valid = false;
};
// Raw and delivered digital-input changes, drained to the status log by the
// log thread so presses can be matched against what the game did with them.
struct InputLedgerEntry {
    int64_t qpc;
    uint32_t frame;
    uint16_t index;     // DirectInput scan code, or 0x100 + mouse button
    uint8_t down;
    uint8_t kind;       // 0 = raw change seen in a poll, 1 = shown to the handler
    uint8_t tick;
    // Gates read by the handler's attack (FUN_0077C690) and reload paths.
    int32_t weaponAction;   // player process vtable +0x3E0; -1 = none
    uint8_t attackBlocked;  // 0107BA59
    uint8_t attackArmed;    // 0107BA5A
    uint32_t attackCounter; // 0107BA5C
    uint8_t holsterLatched; // 0107BFC1
    float reloadHoldTimer;  // 0107BA8C
    float frameDelta;       // 01090BAC as the handler will read it
};
std::array<InputLedgerEntry, 1024> g_inputLedger{};
std::atomic<uint32_t> g_inputLedgerWrite{0};
uint32_t g_inputLedgerRead = 0;

template <typename T>
T ReadEngineValue(uintptr_t address);

void RecordInputLedger(uint16_t index, bool down, uint8_t kind, bool tick) {
    if (g_quietTelemetry) return;
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    const uint32_t write = g_inputLedgerWrite.load(std::memory_order_relaxed);
    InputLedgerEntry &entry = g_inputLedger[write % g_inputLedger.size()];
    entry.qpc = now.QuadPart;
    entry.frame = *reinterpret_cast<volatile uint32_t *>(kGlobalFrameCounter) + 1;
    entry.index = index;
    entry.down = down ? 1 : 0;
    entry.kind = kind;
    entry.tick = tick ? 1 : 0;
    entry.weaponAction = -2;
    __try {
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        const uintptr_t process =
            player >= 0x10000 ? ReadEngineValue<uintptr_t>(player + 0x60) : 0;
        if (process >= 0x10000) {
            // Same getter the handler uses through FUN_006F7370.
            using ActionFn = int32_t(__thiscall *)(void *);
            const auto getAction = ReadEngineValue<ActionFn>(
                ReadEngineValue<uintptr_t>(process) + 0x3E0);
            entry.weaponAction = getAction(reinterpret_cast<void *>(process));
        }
        entry.attackBlocked = ReadEngineValue<uint8_t>(0x0107BA59);
        entry.attackArmed = ReadEngineValue<uint8_t>(0x0107BA5A);
        entry.attackCounter = ReadEngineValue<uint32_t>(0x0107BA5C);
        entry.holsterLatched = ReadEngineValue<uint8_t>(0x0107BFC1);
        entry.reloadHoldTimer = ReadEngineValue<float>(0x0107BA8C);
        entry.frameDelta = ReadEngineValue<float>(kGlobalFrameDelta);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        entry.weaponAction = -3;
    }
    g_inputLedgerWrite.store(write + 1, std::memory_order_release);
}
InputEdgeLatch g_inputEdgeLatch{};
volatile LONG g_latchStatEdgesDelivered = 0;
volatile LONG g_translationStatApplied = 0;
volatile LONG g_translationStatIdentityResets = 0;
volatile LONG g_translationStatEyeSteps = 0;
volatile LONG g_translationStatThirdPersonDraws = 0;
struct EyeHeightHistory {
    float from = 0.0f;
    float to = 0.0f;
    uint8_t score = 0;      // +4 per off-tick change, -1 per draw
    bool valid = false;
};
EyeHeightHistory g_eyeHeightHistory{};
// Diagnostic trace of view height against the first-person model, one row per
// frame for 90 frames after the camera's height above the player changes
// (crouching, standing up). Written by the render thread, drained by the log
// thread.
struct CrouchTraceRow {
    uint32_t frame = 0;
    uint8_t tick = 0;
    uint8_t fpPass = 0;
    float alpha = 0.0f;
    float playerZ = 0.0f;
    float cameraWorldZ = 0.0f;      // engine value, before any correction
    float cameraLocalZ = 0.0f;
    float moveCorrectionZ = 0.0f;
    float eyeCorrection = 0.0f;
    float fpCameraWorldZ = 0.0f;    // scene camera when the first-person pass starts
    float rootLocalZ = 0.0f;
    float rootWorldZBefore = 0.0f;
    float camera1stLocalZ = 0.0f;   // engine values, before blending
    float handLocalZ = 0.0f;
    float rootWorldZ = 0.0f;        // after the pass: what was drawn
    float camera1stWorldZ = 0.0f;
    float handWorldZ = 0.0f;
};
std::array<CrouchTraceRow, 4096> g_crouchTrace{};
std::atomic<uint32_t> g_crouchTraceWrite{0};
uint32_t g_crouchTraceRead = 0;
CrouchTraceRow g_crouchTracePending{};
bool g_crouchTracePendingValid = false;
uint32_t g_crouchTraceHot = 0;
float g_crouchTraceLastEye = 0.0f;
// FUN_006E65F0 places the first-person camera at the world position of the
// node held in this global minus the root's, and reads it before it updates
// the tree from the local transforms. So the position it reads is the one
// left by the previous update: the engine's on a tick frame, the previous
// frame's blend otherwise. The node's world translation is therefore worked
// out here from the blended locals, walking up to the root.
constexpr uintptr_t kFirstPersonCameraNode = 0x0107BA78;
volatile LONG g_fpStatCameraNodeWrites = 0;
volatile LONG g_fpStatCameraNodeMisses = 0;
uintptr_t g_crouchTraceRoot = 0;
uintptr_t g_crouchTraceCamera1st = 0;
uintptr_t g_crouchTraceHand = 0;
volatile LONG g_translationStatIneligibleResets = 0;
volatile LONG g_translationStatCellChanges = 0;
volatile LONG g_translationStatParentChanges = 0;
bool g_actorTranslationInterpolationEnabled = false;
bool g_actorTranslationInterpolationFaulted = false;
// Diagnostic: extra height added to every tracked actor during the draw, to
// show on screen whether the draw uses the shifted transforms at all.
float g_debugActorOffsetZ = 0.0f;
float g_debugFirstPersonOffsetZ = 0.0f;
volatile LONG g_actorStatTracked = 0;       // actors seen in the last draw
volatile LONG g_actorStatApplied = 0;       // node poses written, cumulative
volatile LONG g_actorStatNodesMax = 0;      // most nodes written in one draw
volatile LONG g_actorStatSnaps = 0;
volatile LONG g_actorStatOverflow = 0;
volatile LONG g_actorStatOffTickChanges = 0;
volatile LONG g_actorStatTableResets = 0;
volatile LONG g_actorStatDuplicates = 0;
volatile LONG g_actorStatRestoreConflicts = 0;
// Diagnostic: track and classify, never write.
bool g_debugActorObserveOnly = false;
// Off-tick world-transform changes by largest component difference:
// [0] < 1e-4, [1] < 0.05, [2] larger; second index 1 = frame ran frozen.
volatile LONG g_actorStatOffTickClass[3][2] = {};
volatile LONG g_actorStatNodeDraws[2] = {};       // node visits, by frozen
volatile LONG g_actorStatOffTickMaxMilli = 0;     // largest difference * 1000
volatile LONG g_translationStatPoses = 0;
volatile LONG g_translationStatSnaps = 0;
volatile LONG g_translationStatRootMismatch = 0;
volatile LONG g_latchStatEdgesDeferred = 0;
volatile LONG g_latchStatTapsRecovered = 0;
void *g_probeStubAllocation = nullptr;
size_t g_installedProbeCount = 0;
void *g_dispatchStubAllocation = nullptr;
size_t g_installedDispatchProbeCount = 0;
void *g_sceneDrawReplayStub = nullptr;
bool g_sceneDrawReplayInstalled = false;
bool g_sceneDrawReplayPatchedDirectly = false;
void *g_postPresentReplayStub = nullptr;
bool g_postPresentReplayInstalled = false;
bool g_postPresentReplayPatchedDirectly = false;
HANDLE g_captureActiveEvent = nullptr;
volatile LONG g_audioPlayCalls = 0;
volatile LONG g_scriptRunCalls = 0;
volatile LONG g_animationNoteCalls = 0;
volatile LONG g_inputPollCalls = 0;
volatile LONG g_presentCalls = 0;
volatile LONG g_geometryDispatchCalls = 0;
volatile LONG g_presentObservationActive = 0;
volatile LONG g_presentObservationThreadId = 0;
volatile LONG g_scriptDuringPresentCalls = 0;
volatile LONG g_scriptDuringPresentSameThreadCalls = 0;
volatile LONG g_scriptDuringPresentOtherThreadCalls = 0;
volatile LONG g_lastScriptDuringPresentThreadId = 0;
volatile LONG g_state2PassObservationActive = 0;
volatile LONG g_state2PassObservationThreadId = 0;
volatile LONG g_scriptDuringState2PassCalls = 0;
volatile LONG g_scriptDuringState2PassSameThreadCalls = 0;
volatile LONG g_scriptDuringState2PassOtherThreadCalls = 0;
volatile LONG g_lastScriptDuringState2PassThreadId = 0;
volatile LONG g_changedFormsClearCalls = 0;
volatile LONG g_lastChangedFormsClearReturnAddress = 0;
volatile LONG g_changedFormsFreeCalls = 0;
volatile LONG g_lastChangedFormsFreeReturnAddress = 0;
volatile LONG g_state2PassReturnAddress = 0;
volatile LONG g_state2OwnerReturnAddress = 0;
volatile LONG g_renderAccumulatorPtr = 0;
volatile LONG g_renderAccumulatorCount = 0;
volatile LONG g_renderAccumulatorArrayPtr = 0;
volatile LONG g_renderAccumulatorCursor = 0;
volatile LONG g_renderAccumulatorCurrentGeometryPtr = 0;
volatile LONG g_renderAccumulatorPassId = 0;
volatile LONG g_renderAccumulatorReverseGeometryPtr = 0;
volatile LONG g_renderAccumulatorReversePropertyPtr = 0;
volatile LONG g_compositePassOrdinal = 0;
volatile LONG g_compositePassThisPtr = 0;
volatile LONG g_compositePassBasePtr = 0;
volatile LONG g_compositePassVtable = 0;
volatile LONG g_compositePassTargetSlotPtr = 0;
volatile LONG g_compositePassTargetBindingPtr = 0;
volatile LONG g_compositePassTargetPtr = 0;
volatile LONG g_compositePassTargetVtable = 0;
volatile LONG g_compositePassTargetRefCount = 0;
volatile LONG g_compositePassReturnAddress = 0;
volatile LONG g_compositePassArg0 = 0;
volatile LONG g_compositePassArg1 = 0;
volatile LONG g_compositePassArg2 = 0;
volatile LONG g_compositePassArg3 = 0;
volatile LONG g_compositeExecutorGraphPtr = 0;
volatile LONG g_compositeExecutorReturnAddress = 0;
volatile LONG g_compositeExecutorIndex = 0;
volatile LONG g_compositeExecutorArg1 = 0;
volatile LONG g_compositeExecutorArg2 = 0;
volatile LONG g_compositeExecutorArg3 = 0;
volatile LONG g_compositeExecutorArg4 = 0;
volatile LONG g_compositeExecutorArg5 = 0;
volatile LONG g_compositeLeafPassPtr = 0;
volatile LONG g_compositeLeafRootPtr = 0;
volatile LONG g_compositeLeafCaller = 0;
volatile LONG g_compositeLeafArg0 = 0;
volatile LONG g_compositeLeafArg1 = 0;
volatile LONG g_compositeLeafArg2 = 0;
volatile LONG g_compositeLeafBindingArrayPtr = 0;
volatile LONG g_compositeLeafBinding0Ptr = 0;
volatile LONG g_compositeLeafBinding1Ptr = 0;
volatile LONG g_compositeLeafBinding2Ptr = 0;
volatile LONG g_compositeLeafBinding3Ptr = 0;
volatile LONG g_compositeLeafBinding1Flags = 0;
volatile LONG g_compositeLeafBinding1ResourcePtr = 0;
volatile LONG g_compositeLeafBinding1Metadata = 0;
volatile LONG g_compositeLeafBinding1Aux = 0;
volatile LONG g_compositeLeafBinding1ResourceVtable = 0;
volatile LONG g_compositeLeafBinding1ResourceRefCount = 0;
volatile LONG g_compositeLeafBinding1PostReleaseRefCount = 0;
volatile LONG g_compositeLeafBinding0Flags = 0;
volatile LONG g_compositeLeafBinding0ResourcePtr = 0;
volatile LONG g_compositeLeafBinding0Metadata = 0;
volatile LONG g_compositeLeafBinding0Aux = 0;
volatile LONG g_compositeLeafBinding0ResourceVtable = 0;
volatile LONG g_compositeLeafBinding0ResourceRefCount = 0;
volatile LONG g_compositeLeafBinding2Flags = 0;
volatile LONG g_compositeLeafBinding2ResourcePtr = 0;
volatile LONG g_compositeLeafBinding2Metadata = 0;
volatile LONG g_compositeLeafBinding2Aux = 0;
volatile LONG g_compositeLeafBinding2ResourceVtable = 0;
volatile LONG g_compositeLeafBinding2ResourceRefCount = 0;
volatile LONG g_compositeLeafBinding3Flags = 0;
volatile LONG g_compositeLeafBinding3ResourcePtr = 0;
volatile LONG g_compositeLeafBinding3Metadata = 0;
volatile LONG g_compositeLeafBinding3Aux = 0;
volatile LONG g_compositeLeafBinding3ResourceVtable = 0;
volatile LONG g_compositeLeafBinding3ResourceRefCount = 0;
volatile LONG g_compositeGraphActive = 0;
volatile LONG g_compositeGraphStartGeometryDispatchCalls = 0;
volatile LONG g_compositeGraphLeafCount = 0;
volatile LONG g_compositeGraphPostReleaseCount = 0;
volatile LONG g_compositeGraphState1Count = 0;
volatile LONG g_compositeGraphState2Count = 0;
volatile LONG g_compositeGraphAccumulatorDrainCount = 0;
volatile LONG g_retentionAcquireCalls = 0;
volatile LONG g_retentionReleaseCalls = 0;
volatile LONG g_retentionRejectCalls = 0;
volatile LONG g_retentionForcedReleaseCalls = 0;
volatile LONG g_retentionActive = 0;
volatile LONG g_retentionSlot1AcquireRefCount = 0;
volatile LONG g_retentionSlot2AcquireRefCount = 0;
volatile LONG g_retentionSlot3AcquireRefCount = 0;
volatile LONG g_retentionSlot1ReleaseRefCount = 0;
volatile LONG g_retentionSlot2ReleaseRefCount = 0;
volatile LONG g_retentionSlot3ReleaseRefCount = 0;
volatile LONG g_retentionRejectMask = 0;
volatile LONG g_retentionObservedSlot1RefCount = 0;
volatile LONG g_retentionObservedSlot2RefCount = 0;
volatile LONG g_retentionObservedSlot3RefCount = 0;
volatile LONG g_leafLifetimeSampleCalls = 0;
volatile LONG g_leafLifetimeCheckCalls = 0;
volatile LONG g_leafLifetimeBaselineFaultMask = 0;
volatile LONG g_leafLifetimePostPresentFaultMask = 0;
volatile LONG g_leafLifetimeChangeMask = 0;
volatile LONG g_leafLifetimeBaselineHash = 0;
volatile LONG g_leafLifetimePostPresentHash = 0;
volatile LONG g_leafReplayAttemptCalls = 0;
volatile LONG g_leafReplayDrawCalls = 0;
volatile LONG g_leafReplayFinalizeCalls = 0;
volatile LONG g_leafReplayRejectCalls = 0;
volatile LONG g_leafReplayRejectMask = 0;
volatile LONG g_leafReplayActive = 0;
volatile LONG g_leafReplayEligibleFrames = 0;
volatile LONG g_leafReplayCell = 0;
volatile LONG g_sceneDrawReplayEligibleFrames = 0;
volatile LONG g_sceneDrawReplayCell = 0;
volatile LONG g_postPresentReplayEligibleFrames = 0;
volatile LONG g_postPresentReplayCell = 0;
std::atomic<uint32_t> g_currentPulse{0};
std::atomic<double> g_currentWallDeltaMs{0.0};
std::atomic<uint32_t> g_currentTimerInputMs{0};
std::atomic<float> g_currentTimerClampMs{0.0f};
std::atomic<float> g_currentTimerClampRemainderMs{0.0f};

struct CameraPositionSample {
    std::array<float, 3> position{};
    uintptr_t camera = 0;
    uintptr_t root = 0;
    uintptr_t cell = 0;
    bool valid = false;
};

CameraPositionSample g_previousFixedCameraPosition{};
CameraPositionSample g_currentFixedCameraPosition{};
uint32_t g_renderCameraPositionEligibleFrames = 0;

struct TranslationPublicationSample {
    std::array<float, 3> playerPosition{};
    std::array<std::array<float, 3>, 4> nodeWorldPositions{};
    uintptr_t player = 0;
    uintptr_t cell = 0;
    uintptr_t renderer = 0;
    uintptr_t sceneGraph = 0;
    uintptr_t camera = 0;
    uintptr_t cameraParent = 0;
    std::array<uintptr_t, 4> nodes{};
    std::array<uintptr_t, 4> parents{};
    uint32_t frame = 0;
    bool valid = false;
};

struct TranslationInterpolationPair {
    std::array<float, 3> from{};
    std::array<float, 3> to{};
    uintptr_t player = 0;
    uintptr_t cell = 0;
    uintptr_t renderer = 0;
    uintptr_t sceneGraph = 0;
    uintptr_t camera = 0;
    uintptr_t cameraParent = 0;
    std::array<uintptr_t, 4> nodes{};
    std::array<uintptr_t, 4> parents{};
    bool valid = false;
};

TranslationPublicationSample g_futureTranslationPublication{};
TranslationInterpolationPair g_translationInterpolationPair{};
uint32_t g_renderTranslationEligibleFrames = 0;
uintptr_t g_renderTranslationPlayer = 0;
uintptr_t g_renderTranslationCell = 0;
uintptr_t g_renderTranslationRenderer = 0;
uintptr_t g_renderTranslationSceneGraph = 0;
uintptr_t g_renderTranslationCamera = 0;
uintptr_t g_renderTranslationCameraParent = 0;
std::array<uintptr_t, 4> g_renderTranslationNodes{};
std::array<uintptr_t, 4> g_renderTranslationParents{};

struct RetainedResourceBinding {
    uint32_t flags;
    uint32_t resource;
    uint32_t metadata;
    uint32_t auxiliary;
};
static_assert(sizeof(RetainedResourceBinding) == 0x10);

std::array<RetainedResourceBinding, 3> g_retainedLeafBindings{};
RetainedResourceBinding g_retainedLeafEmptyBinding{0x00000100, 0, 0, 0};

struct LeafArgumentLifetimeSample {
    // Pointer/value pairs needed by the final leaf virtual call. The first
    // sample is taken after the stock leaf has returned and released its
    // transient wrappers, so comparison with post-Present does not confuse
    // mutations performed by the stock leaf itself with lifetime changes.
    std::array<uint32_t, 12> values{};
    uint32_t faultMask = 0;
    bool valid = false;
};

LeafArgumentLifetimeSample g_leafArgumentLifetimeBaseline{};

using DirectInput8CreateFn = HRESULT(WINAPI *)(HINSTANCE, DWORD, REFIID, LPVOID *, LPUNKNOWN);
using TimerUpdateFn = void(__thiscall *)(BSTimer *, uint32_t);
using HavokScheduleFn = void(__cdecl *)(float, uint8_t, uint8_t);
using GameFrameFn = void(__fastcall *)(void *);

DirectInput8CreateFn g_realDirectInput8Create = nullptr;
TimerUpdateFn g_timerUpdate = reinterpret_cast<TimerUpdateFn>(kTimerUpdate);
HavokScheduleFn g_havokSchedule = reinterpret_cast<HavokScheduleFn>(kHavokSchedule);
GameFrameFn g_gameFrame = reinterpret_cast<GameFrameFn>(kGameFrame);

INIT_ONCE g_proxyInitOnce = INIT_ONCE_STATIC_INIT;
INIT_ONCE g_patchInitOnce = INIT_ONCE_STATIC_INIT;

std::wstring ModuleDirectory(HMODULE module) {
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return L".";
    wchar_t *slash = wcsrchr(path, L'\\');
    if (slash != nullptr) *slash = L'\0';
    return path;
}

void AppendStatus(const char *format, ...) {
    const std::wstring path = ModuleDirectory(g_self) + L"\\Fallout3HFR.log";
    HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    char buffer[4096]{};
    va_list args;
    va_start(args, format);
    const int length = vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    if (length > 0) {
        DWORD written = 0;
        WriteFile(file, buffer, static_cast<DWORD>(length), &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
    }
    CloseHandle(file);
}

bool MatchesBytes(uintptr_t address, const uint8_t *expected, size_t count) {
    return std::memcmp(reinterpret_cast<const void *>(address), expected, count) == 0;
}

// True if the running executable is a 32-bit image at the expected base whose
// data references are where the patch expects them. The hook sites are
// checked separately, where they are patched.
bool VerifyTargetLayout() {
    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (base != kImageBase) {
        AppendStatus("unsupported executable: loaded at %08X, expected %08X",
                     static_cast<unsigned>(base), static_cast<unsigned>(kImageBase));
        return false;
    }
    __try {
        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        const auto *nt =
            reinterpret_cast<const IMAGE_NT_HEADERS32 *>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            AppendStatus("unsupported executable: not a 32-bit x86 image");
            return false;
        }
        const uintptr_t imageEnd = base + nt->OptionalHeader.SizeOfImage;
        AppendStatus("executable timestamp=%08lX image_size=%08lX (reference build timestamp=%08lX: %s)",
                     static_cast<unsigned long>(nt->FileHeader.TimeDateStamp),
                     static_cast<unsigned long>(nt->OptionalHeader.SizeOfImage),
                     static_cast<unsigned long>(kReferencePeTimestamp),
                     nt->FileHeader.TimeDateStamp == kReferencePeTimestamp
                         ? "same" : "different, layout checks decide");
        int failures = 0;
        for (const LayoutAnchor &anchor : kLayoutAnchors) {
            if (anchor.address < base || anchor.address + anchor.length > imageEnd ||
                !MatchesBytes(anchor.address, anchor.bytes, anchor.length)) {
                if (failures < 8) {
                    AppendStatus("layout check failed at %08X (%s)",
                                 static_cast<unsigned>(anchor.address), anchor.what);
                }
                ++failures;
            }
        }
        if (failures != 0) {
            AppendStatus("unsupported executable: %d of %d layout checks failed",
                         failures, static_cast<int>(std::size(kLayoutAnchors)));
            return false;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        AppendStatus("unsupported executable: layout checks faulted");
        return false;
    }
}

bool PatchRelativeCall(uintptr_t address, const void *target, const uint8_t expected[5]) {
    if (!MatchesBytes(address, expected, 5)) {
        AppendStatus("hook signature mismatch at %08X", static_cast<unsigned>(address));
        return false;
    }
    DWORD oldProtection = 0;
    if (!VirtualProtect(reinterpret_cast<void *>(address), 5, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        AppendStatus("VirtualProtect failed at %08X", static_cast<unsigned>(address));
        return false;
    }
    uint8_t patch[5]{0xE8};
    const auto displacement = static_cast<int32_t>(reinterpret_cast<uintptr_t>(target) - (address + 5));
    std::memcpy(patch + 1, &displacement, sizeof(displacement));
    std::memcpy(reinterpret_cast<void *>(address), patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(address), sizeof(patch));
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void *>(address), 5, oldProtection, &ignored);
    return true;
}

bool RestoreBytes(uintptr_t address, const uint8_t bytes[5]) {
    DWORD oldProtection = 0;
    if (!VirtualProtect(reinterpret_cast<void *>(address), 5, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        return false;
    }
    std::memcpy(reinterpret_cast<void *>(address), bytes, 5);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(address), 5);
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void *>(address), 5, oldProtection, &ignored);
    return true;
}

bool PatchRelativeJump(uintptr_t address, const void *target, const uint8_t *expected,
                       size_t count) {
    if (count < 5 || count > 12 || !MatchesBytes(address, expected, count)) {
        AppendStatus("dispatch probe signature mismatch at %08X", static_cast<unsigned>(address));
        return false;
    }
    DWORD oldProtection = 0;
    if (!VirtualProtect(reinterpret_cast<void *>(address), count, PAGE_EXECUTE_READWRITE,
                        &oldProtection)) {
        AppendStatus("VirtualProtect failed at %08X", static_cast<unsigned>(address));
        return false;
    }
    uint8_t patch[12]{};
    std::memset(patch, 0x90, count);
    patch[0] = 0xE9;
    const auto displacement = static_cast<int32_t>(
        reinterpret_cast<uintptr_t>(target) - (address + 5));
    std::memcpy(patch + 1, &displacement, sizeof(displacement));
    std::memcpy(reinterpret_cast<void *>(address), patch, count);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(address), count);
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void *>(address), count, oldProtection, &ignored);
    return true;
}

bool RestoreBytes(uintptr_t address, const uint8_t *bytes, size_t count) {
    DWORD oldProtection = 0;
    if (!VirtualProtect(reinterpret_cast<void *>(address), count, PAGE_EXECUTE_READWRITE,
                        &oldProtection)) {
        return false;
    }
    std::memcpy(reinterpret_cast<void *>(address), bytes, count);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(address), count);
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void *>(address), count, oldProtection, &ignored);
    return true;
}

volatile LONG *DispatchCounterAddress(DispatchCounter counter) {
    switch (counter) {
    case DispatchCounter::AudioPlay: return &g_audioPlayCalls;
    case DispatchCounter::ScriptRun: return &g_scriptRunCalls;
    case DispatchCounter::AnimationNote: return &g_animationNoteCalls;
    case DispatchCounter::InputPoll: return &g_inputPollCalls;
    case DispatchCounter::Present: return &g_presentCalls;
    case DispatchCounter::GeometryDispatch: return &g_geometryDispatchCalls;
    }
    return nullptr;
}

uint32_t ReadDispatchCounter(volatile LONG *counter) {
    return static_cast<uint32_t>(InterlockedCompareExchange(counter, 0, 0));
}

void __cdecl RecordScriptDuringPresent() {
    const DWORD threadId = GetCurrentThreadId();
    if (InterlockedCompareExchange(&g_presentObservationActive, 0, 0) != 0) {
        InterlockedIncrement(&g_scriptDuringPresentCalls);
        InterlockedExchange(&g_lastScriptDuringPresentThreadId, static_cast<LONG>(threadId));
        const DWORD presentThreadId = static_cast<DWORD>(
            InterlockedCompareExchange(&g_presentObservationThreadId, 0, 0));
        if (threadId == presentThreadId) {
            InterlockedIncrement(&g_scriptDuringPresentSameThreadCalls);
        } else {
            InterlockedIncrement(&g_scriptDuringPresentOtherThreadCalls);
        }
    }
    if (InterlockedCompareExchange(&g_state2PassObservationActive, 0, 0) != 0) {
        InterlockedIncrement(&g_scriptDuringState2PassCalls);
        InterlockedExchange(&g_lastScriptDuringState2PassThreadId,
                            static_cast<LONG>(threadId));
        const DWORD passThreadId = static_cast<DWORD>(
            InterlockedCompareExchange(&g_state2PassObservationThreadId, 0, 0));
        if (threadId == passThreadId) {
            InterlockedIncrement(&g_scriptDuringState2PassSameThreadCalls);
        } else {
            InterlockedIncrement(&g_scriptDuringState2PassOtherThreadCalls);
        }
    }
}

void BeginPresentObservation() {
    InterlockedExchange(&g_presentObservationThreadId,
                        static_cast<LONG>(GetCurrentThreadId()));
    InterlockedExchange(&g_presentObservationActive, 1);
}

void EndPresentObservation() {
    InterlockedExchange(&g_presentObservationActive, 0);
}

void BeginState2PassObservation() {
    InterlockedExchange(&g_state2PassObservationThreadId,
                        static_cast<LONG>(GetCurrentThreadId()));
    InterlockedExchange(&g_state2PassObservationActive, 1);
}

void EndState2PassObservation() {
    InterlockedExchange(&g_state2PassObservationActive, 0);
    InterlockedExchange(&g_state2PassObservationThreadId, 0);
}

void __cdecl RecordState2PassReturnAddress(uint32_t returnAddress) {
    InterlockedExchange(&g_state2PassReturnAddress,
                        static_cast<LONG>(returnAddress));
    if (returnAddress != 0x006E60F8) {
        InterlockedExchange(&g_state2OwnerReturnAddress, 0);
    }
}

void __cdecl RecordState2OwnerReturnAddress(uint32_t returnAddress) {
    InterlockedExchange(&g_state2OwnerReturnAddress,
                        static_cast<LONG>(returnAddress));
}

uint64_t HashBytes(uint64_t hash, const void *data, size_t size) {
    constexpr uint64_t kFnvPrime = 1099511628211ull;
    const auto *bytes = static_cast<const uint8_t *>(data);
    for (size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= kFnvPrime;
    }
    return hash;
}

template <typename T>
uint64_t HashValue(uint64_t hash, const T &value) {
    return HashBytes(hash, &value, sizeof(value));
}

template <typename T>
T ReadEngineValue(uintptr_t address) {
    return *reinterpret_cast<volatile const T *>(address);
}

void __cdecl RecordRenderAccumulator(uint32_t accumulatorValue) {
    uint32_t count = 0;
    uint32_t array = 0;
    uint32_t cursor = 0;
    uint32_t currentGeometry = 0;
    uint32_t passId = 0;
    uint32_t reverseGeometry = 0;
    uint32_t reverseProperty = 0;
    const uintptr_t accumulator = accumulatorValue;

    __try {
        if (accumulator >= 0x10000) {
            count = ReadEngineValue<uint32_t>(accumulator + 0x1C);
            array = ReadEngineValue<uint32_t>(accumulator + 0x24);
            cursor = ReadEngineValue<uint32_t>(accumulator + 0x2C);
            currentGeometry = ReadEngineValue<uint32_t>(accumulator + 0x1A4);
            passId = ReadEngineValue<uint16_t>(accumulator + 0x1A8);
            if (count != 0 && count < 0x100000 && array >= 0x10000) {
                reverseGeometry = ReadEngineValue<uint32_t>(
                    static_cast<uintptr_t>(array) + (count - 1) * sizeof(uint32_t));
                if (reverseGeometry >= 0x10000) {
                    reverseProperty = ReadEngineValue<uint32_t>(
                        static_cast<uintptr_t>(reverseGeometry) + 0xB8);
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        accumulatorValue = 0;
        count = 0;
        array = 0;
        cursor = 0;
        currentGeometry = 0;
        passId = 0;
        reverseGeometry = 0;
        reverseProperty = 0;
    }

    InterlockedExchange(&g_renderAccumulatorPtr, static_cast<LONG>(accumulatorValue));
    InterlockedExchange(&g_renderAccumulatorCount, static_cast<LONG>(count));
    InterlockedExchange(&g_renderAccumulatorArrayPtr, static_cast<LONG>(array));
    InterlockedExchange(&g_renderAccumulatorCursor, static_cast<LONG>(cursor));
    InterlockedExchange(&g_renderAccumulatorCurrentGeometryPtr,
                        static_cast<LONG>(currentGeometry));
    InterlockedExchange(&g_renderAccumulatorPassId, static_cast<LONG>(passId));
    InterlockedExchange(&g_renderAccumulatorReverseGeometryPtr,
                        static_cast<LONG>(reverseGeometry));
    InterlockedExchange(&g_renderAccumulatorReversePropertyPtr,
                        static_cast<LONG>(reverseProperty));
}

void __cdecl RecordCompositePassEntry(const uint32_t *savedContext) {
    uint32_t thisPtr = 0;
    uint32_t basePtr = 0;
    uint32_t vtable = 0;
    uint32_t targetSlot = 0;
    uint32_t targetBinding = 0;
    uint32_t target = 0;
    uint32_t targetVtable = 0;
    uint32_t targetRefCount = 0;
    uint32_t returnAddress = 0;
    uint32_t args[4]{};

    __try {
        if (savedContext != nullptr) {
            // pushfd/pushad saves EDI, ESI, EBP, pre-pushad ESP, EBX, EDX,
            // ECX, EAX, EFLAGS, then the untouched function-entry stack.
            thisPtr = savedContext[6];
            returnAddress = savedContext[9];
            for (size_t index = 0; index < 4; ++index) {
                args[index] = savedContext[10 + index];
            }
        }
        if (thisPtr >= 0x10000) {
            basePtr = thisPtr - 0x6C;
            vtable = ReadEngineValue<uint32_t>(thisPtr);
            targetSlot = ReadEngineValue<uint32_t>(thisPtr + 0x2C);
            if (targetSlot >= 0x10000) {
                targetBinding = ReadEngineValue<uint32_t>(targetSlot);
                if (targetBinding >= 0x10000 &&
                    ReadEngineValue<uint8_t>(targetBinding + 1) != 0) {
                    target = ReadEngineValue<uint32_t>(targetBinding + 4);
                }
            }
            if (target >= 0x10000) {
                targetVtable = ReadEngineValue<uint32_t>(target);
                targetRefCount = ReadEngineValue<uint32_t>(target + 4);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        thisPtr = 0;
        basePtr = 0;
        vtable = 0;
        targetSlot = 0;
        targetBinding = 0;
        target = 0;
        targetVtable = 0;
        targetRefCount = 0;
        returnAddress = 0;
        std::memset(args, 0, sizeof(args));
    }

    InterlockedIncrement(&g_compositePassOrdinal);
    InterlockedExchange(&g_compositePassThisPtr, static_cast<LONG>(thisPtr));
    InterlockedExchange(&g_compositePassBasePtr, static_cast<LONG>(basePtr));
    InterlockedExchange(&g_compositePassVtable, static_cast<LONG>(vtable));
    InterlockedExchange(&g_compositePassTargetSlotPtr, static_cast<LONG>(targetSlot));
    InterlockedExchange(&g_compositePassTargetBindingPtr, static_cast<LONG>(targetBinding));
    InterlockedExchange(&g_compositePassTargetPtr, static_cast<LONG>(target));
    InterlockedExchange(&g_compositePassTargetVtable, static_cast<LONG>(targetVtable));
    InterlockedExchange(&g_compositePassTargetRefCount, static_cast<LONG>(targetRefCount));
    InterlockedExchange(&g_compositePassReturnAddress, static_cast<LONG>(returnAddress));
    InterlockedExchange(&g_compositePassArg0, static_cast<LONG>(args[0]));
    InterlockedExchange(&g_compositePassArg1, static_cast<LONG>(args[1]));
    InterlockedExchange(&g_compositePassArg2, static_cast<LONG>(args[2]));
    InterlockedExchange(&g_compositePassArg3, static_cast<LONG>(args[3]));
}

void __cdecl RecordCompositeExecutorEntry(const uint32_t *savedContext) {
    uint32_t graph = 0;
    uint32_t returnAddress = 0;
    uint32_t args[6]{};

    __try {
        if (savedContext != nullptr) {
            graph = savedContext[6];
            returnAddress = savedContext[9];
            for (size_t index = 0; index < 6; ++index) {
                args[index] = savedContext[10 + index];
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        graph = 0;
        returnAddress = 0;
        std::memset(args, 0, sizeof(args));
    }

    InterlockedExchange(&g_compositeExecutorGraphPtr, static_cast<LONG>(graph));
    InterlockedExchange(&g_compositeExecutorReturnAddress,
                        static_cast<LONG>(returnAddress));
    InterlockedExchange(&g_compositeExecutorIndex, static_cast<LONG>(args[0]));
    InterlockedExchange(&g_compositeExecutorArg1, static_cast<LONG>(args[1]));
    InterlockedExchange(&g_compositeExecutorArg2, static_cast<LONG>(args[2]));
    InterlockedExchange(&g_compositeExecutorArg3, static_cast<LONG>(args[3]));
    InterlockedExchange(&g_compositeExecutorArg4, static_cast<LONG>(args[4]));
    InterlockedExchange(&g_compositeExecutorArg5, static_cast<LONG>(args[5]));
}

void __cdecl RecordCompositeLeafReady(const uint32_t *savedContext) {
    uint32_t pass = 0;
    uint32_t root = 0;
    uint32_t caller = 0;
    uint32_t args[3]{};
    uint32_t bindingArray = 0;
    uint32_t bindings[4]{};
    uint32_t bindingFlags[4]{};
    uint32_t bindingResources[4]{};
    uint32_t bindingMetadata[4]{};
    uint32_t bindingAux[4]{};
    uint32_t bindingResourceVtables[4]{};
    uint32_t bindingResourceRefCounts[4]{};

    __try {
        if (savedContext != nullptr) {
            // At 00B3063B the final pass is fully bound. pushfd precedes
            // pushad, so savedContext[3] is four bytes below the engine ESP.
            const uintptr_t engineEsp =
                static_cast<uintptr_t>(savedContext[3]) + sizeof(uint32_t);
            pass = savedContext[0]; // original EDI
            root = savedContext[1]; // original ESI
            args[1] = savedContext[2]; // original EBP
            args[2] = savedContext[4]; // original EBX
            if (engineEsp >= 0x10000) {
                caller = ReadEngineValue<uint32_t>(engineEsp + 0x80);
                args[0] = ReadEngineValue<uint32_t>(engineEsp + 0x84);
            }
        }
        if (pass >= 0x10000) {
            bindingArray = ReadEngineValue<uint32_t>(pass + 0x2C);
            if (bindingArray >= 0x10000) {
                for (size_t index = 0; index < 4; ++index) {
                    bindings[index] = ReadEngineValue<uint32_t>(
                        static_cast<uintptr_t>(bindingArray) +
                        index * sizeof(uint32_t));
                }
            }
        }
        for (size_t index = 0; index < 4; ++index) {
            if (bindings[index] >= 0x10000) {
                bindingFlags[index] = ReadEngineValue<uint32_t>(bindings[index]);
                bindingResources[index] =
                    ReadEngineValue<uint32_t>(bindings[index] + 4);
                bindingMetadata[index] =
                    ReadEngineValue<uint32_t>(bindings[index] + 8);
                bindingAux[index] =
                    ReadEngineValue<uint32_t>(bindings[index] + 0x0C);
            }
            if (bindingResources[index] >= 0x10000) {
                bindingResourceVtables[index] =
                    ReadEngineValue<uint32_t>(bindingResources[index]);
                bindingResourceRefCounts[index] =
                    ReadEngineValue<uint32_t>(bindingResources[index] + 4);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        pass = 0;
        root = 0;
        caller = 0;
        std::memset(args, 0, sizeof(args));
        bindingArray = 0;
        std::memset(bindings, 0, sizeof(bindings));
        std::memset(bindingFlags, 0, sizeof(bindingFlags));
        std::memset(bindingResources, 0, sizeof(bindingResources));
        std::memset(bindingMetadata, 0, sizeof(bindingMetadata));
        std::memset(bindingAux, 0, sizeof(bindingAux));
        std::memset(bindingResourceVtables, 0, sizeof(bindingResourceVtables));
        std::memset(bindingResourceRefCounts, 0, sizeof(bindingResourceRefCounts));
    }

    InterlockedExchange(&g_compositeLeafPassPtr, static_cast<LONG>(pass));
    InterlockedExchange(&g_compositeLeafRootPtr, static_cast<LONG>(root));
    InterlockedExchange(&g_compositeLeafCaller, static_cast<LONG>(caller));
    InterlockedExchange(&g_compositeLeafArg0, static_cast<LONG>(args[0]));
    InterlockedExchange(&g_compositeLeafArg1, static_cast<LONG>(args[1]));
    InterlockedExchange(&g_compositeLeafArg2, static_cast<LONG>(args[2]));
    InterlockedExchange(&g_compositeLeafBindingArrayPtr,
                        static_cast<LONG>(bindingArray));
    InterlockedExchange(&g_compositeLeafBinding0Ptr,
                        static_cast<LONG>(bindings[0]));
    InterlockedExchange(&g_compositeLeafBinding1Ptr,
                        static_cast<LONG>(bindings[1]));
    InterlockedExchange(&g_compositeLeafBinding2Ptr,
                        static_cast<LONG>(bindings[2]));
    InterlockedExchange(&g_compositeLeafBinding3Ptr,
                        static_cast<LONG>(bindings[3]));
    InterlockedExchange(&g_compositeLeafBinding1Flags,
                        static_cast<LONG>(bindingFlags[1]));
    InterlockedExchange(&g_compositeLeafBinding1ResourcePtr,
                        static_cast<LONG>(bindingResources[1]));
    InterlockedExchange(&g_compositeLeafBinding1Metadata,
                        static_cast<LONG>(bindingMetadata[1]));
    InterlockedExchange(&g_compositeLeafBinding1Aux,
                        static_cast<LONG>(bindingAux[1]));
    InterlockedExchange(&g_compositeLeafBinding1ResourceVtable,
                        static_cast<LONG>(bindingResourceVtables[1]));
    InterlockedExchange(&g_compositeLeafBinding1ResourceRefCount,
                        static_cast<LONG>(bindingResourceRefCounts[1]));
    InterlockedExchange(&g_compositeLeafBinding1PostReleaseRefCount, 0);
    InterlockedExchange(&g_compositeLeafBinding0Flags,
                        static_cast<LONG>(bindingFlags[0]));
    InterlockedExchange(&g_compositeLeafBinding0ResourcePtr,
                        static_cast<LONG>(bindingResources[0]));
    InterlockedExchange(&g_compositeLeafBinding0Metadata,
                        static_cast<LONG>(bindingMetadata[0]));
    InterlockedExchange(&g_compositeLeafBinding0Aux,
                        static_cast<LONG>(bindingAux[0]));
    InterlockedExchange(&g_compositeLeafBinding0ResourceVtable,
                        static_cast<LONG>(bindingResourceVtables[0]));
    InterlockedExchange(&g_compositeLeafBinding0ResourceRefCount,
                        static_cast<LONG>(bindingResourceRefCounts[0]));
    InterlockedExchange(&g_compositeLeafBinding2Flags,
                        static_cast<LONG>(bindingFlags[2]));
    InterlockedExchange(&g_compositeLeafBinding2ResourcePtr,
                        static_cast<LONG>(bindingResources[2]));
    InterlockedExchange(&g_compositeLeafBinding2Metadata,
                        static_cast<LONG>(bindingMetadata[2]));
    InterlockedExchange(&g_compositeLeafBinding2Aux,
                        static_cast<LONG>(bindingAux[2]));
    InterlockedExchange(&g_compositeLeafBinding2ResourceVtable,
                        static_cast<LONG>(bindingResourceVtables[2]));
    InterlockedExchange(&g_compositeLeafBinding2ResourceRefCount,
                        static_cast<LONG>(bindingResourceRefCounts[2]));
    InterlockedExchange(&g_compositeLeafBinding3Flags,
                        static_cast<LONG>(bindingFlags[3]));
    InterlockedExchange(&g_compositeLeafBinding3ResourcePtr,
                        static_cast<LONG>(bindingResources[3]));
    InterlockedExchange(&g_compositeLeafBinding3Metadata,
                        static_cast<LONG>(bindingMetadata[3]));
    InterlockedExchange(&g_compositeLeafBinding3Aux,
                        static_cast<LONG>(bindingAux[3]));
    InterlockedExchange(&g_compositeLeafBinding3ResourceVtable,
                        static_cast<LONG>(bindingResourceVtables[3]));
    InterlockedExchange(&g_compositeLeafBinding3ResourceRefCount,
                        static_cast<LONG>(bindingResourceRefCounts[3]));
}

void RecordCompositeLeafPostRelease() {
    uint32_t refCount = 0;
    __try {
        const uint32_t resource =
            ReadDispatchCounter(&g_compositeLeafBinding1ResourcePtr);
        if (resource >= 0x10000) {
            refCount = ReadEngineValue<uint32_t>(resource + 4);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        refCount = 0;
    }
    InterlockedExchange(&g_compositeLeafBinding1PostReleaseRefCount,
                        static_cast<LONG>(refCount));
}

uint32_t FoldLeafLifetimeHash(const LeafArgumentLifetimeSample &sample) {
    uint64_t hash = 1469598103934665603ull;
    hash = HashBytes(hash, sample.values.data(),
                     sample.values.size() * sizeof(sample.values[0]));
    hash = HashValue(hash, sample.faultMask);
    return static_cast<uint32_t>(hash ^ (hash >> 32));
}

bool CaptureGateIsActive();

LeafArgumentLifetimeSample CaptureLeafArgumentLifetime(
    const LeafArgumentLifetimeSample *identity) {
    LeafArgumentLifetimeSample sample{};
    sample.values[0] = identity != nullptr
        ? identity->values[0]
        : ReadDispatchCounter(&g_compositeLeafPassPtr);
    sample.values[3] = identity != nullptr
        ? identity->values[3]
        : ReadDispatchCounter(&g_compositeLeafArg0);
    sample.values[6] = identity != nullptr
        ? identity->values[6]
        : ReadDispatchCounter(&g_compositeLeafArg1);
    sample.values[8] = identity != nullptr
        ? identity->values[8]
        : ReadDispatchCounter(&g_compositeLeafArg2);

    __try {
        if (sample.values[0] < 0x10000) {
            sample.faultMask |= 1u << 0;
        } else {
            sample.values[1] = ReadEngineValue<uint32_t>(sample.values[0]);
            sample.values[2] = ReadEngineValue<uint32_t>(sample.values[0] + 0x2C);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sample.faultMask |= 1u << 0;
    }

    __try {
        if (sample.values[3] < 0x10000) {
            sample.faultMask |= 1u << 1;
        } else {
            sample.values[4] = ReadEngineValue<uint32_t>(sample.values[3]);
            sample.values[5] = ReadEngineValue<uint32_t>(sample.values[3] + 0xC0);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sample.faultMask |= 1u << 1;
    }

    __try {
        sample.values[7] = ReadEngineValue<uint32_t>(kRendererSingleton);
        if (sample.values[6] < 0x10000 || sample.values[7] < 0x10000 ||
            sample.values[6] != sample.values[7]) {
            sample.faultMask |= 1u << 2;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sample.faultMask |= 1u << 2;
    }

    __try {
        if (sample.values[8] < 0x10000) {
            sample.faultMask |= 1u << 3;
        } else {
            sample.values[9] = ReadEngineValue<uint32_t>(sample.values[8]);
            sample.values[10] = ReadEngineValue<uint32_t>(sample.values[8] + 0x28);
            sample.values[11] = ReadEngineValue<uint32_t>(sample.values[8] + 0x2C);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sample.faultMask |= 1u << 3;
    }

    sample.valid = true;
    return sample;
}

void RecordLeafArgumentLifetimeBaseline() {
    if (!g_leafResourceRetentionEnabled || !CaptureGateIsActive()) return;

    g_leafArgumentLifetimeBaseline = CaptureLeafArgumentLifetime(nullptr);
    InterlockedExchange(&g_leafLifetimeBaselineFaultMask,
                        static_cast<LONG>(g_leafArgumentLifetimeBaseline.faultMask));
    InterlockedExchange(&g_leafLifetimeBaselineHash,
                        static_cast<LONG>(FoldLeafLifetimeHash(
                            g_leafArgumentLifetimeBaseline)));
    InterlockedExchange(&g_leafLifetimePostPresentFaultMask, 0);
    InterlockedExchange(&g_leafLifetimeChangeMask, 0);
    InterlockedExchange(&g_leafLifetimePostPresentHash, 0);
    InterlockedIncrement(&g_leafLifetimeSampleCalls);
}

void RecordLeafArgumentLifetimePostPresent() {
    if (!g_leafResourceRetentionEnabled ||
        InterlockedCompareExchange(&g_retentionActive, 0, 0) == 0 ||
        !g_leafArgumentLifetimeBaseline.valid) {
        return;
    }

    const LeafArgumentLifetimeSample post =
        CaptureLeafArgumentLifetime(&g_leafArgumentLifetimeBaseline);
    uint32_t changeMask = 0;
    for (size_t index = 0; index < post.values.size(); ++index) {
        if (post.values[index] != g_leafArgumentLifetimeBaseline.values[index]) {
            changeMask |= 1u << index;
        }
    }
    InterlockedExchange(&g_leafLifetimePostPresentFaultMask,
                        static_cast<LONG>(post.faultMask));
    InterlockedExchange(&g_leafLifetimeChangeMask,
                        static_cast<LONG>(changeMask));
    InterlockedExchange(&g_leafLifetimePostPresentHash,
                        static_cast<LONG>(FoldLeafLifetimeHash(post)));
    InterlockedIncrement(&g_leafLifetimeCheckCalls);
}

uint32_t ReleaseResourceReference(uint32_t resource) {
    uint32_t refCount = 0;
    __try {
        if (resource >= 0x10000) {
            refCount = static_cast<uint32_t>(InterlockedDecrement(
                reinterpret_cast<volatile LONG *>(
                    static_cast<uintptr_t>(resource) + sizeof(uint32_t))));
            if (refCount == 0) {
                const uintptr_t vtable = ReadEngineValue<uintptr_t>(resource);
                const uintptr_t release = ReadEngineValue<uintptr_t>(
                    vtable + sizeof(uint32_t));
                using ReleaseFn = void(__thiscall *)(void *);
                reinterpret_cast<ReleaseFn>(release)(
                    reinterpret_cast<void *>(static_cast<uintptr_t>(resource)));
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        refCount = 0;
    }
    return refCount;
}

void ReleaseRetainedLeafResources(bool forced) {
    if (InterlockedExchange(&g_retentionActive, 0) == 0) return;

    uint32_t releaseCounts[3]{};
    for (size_t index = 0; index < g_retainedLeafBindings.size(); ++index) {
        const uint32_t resource = g_retainedLeafBindings[index].resource;
        g_retainedLeafBindings[index].resource = 0;
        releaseCounts[index] = ReleaseResourceReference(resource);
    }
    InterlockedExchange(&g_retentionSlot1ReleaseRefCount,
                        static_cast<LONG>(releaseCounts[0]));
    InterlockedExchange(&g_retentionSlot2ReleaseRefCount,
                        static_cast<LONG>(releaseCounts[1]));
    InterlockedExchange(&g_retentionSlot3ReleaseRefCount,
                        static_cast<LONG>(releaseCounts[2]));
    InterlockedIncrement(&g_retentionReleaseCalls);
    if (forced) InterlockedIncrement(&g_retentionForcedReleaseCalls);
}

void BeginCompositeGraphObservation() {
    if (g_leafResourceRetentionEnabled) {
        ReleaseRetainedLeafResources(true);
    }
    g_leafArgumentLifetimeBaseline.valid = false;
    InterlockedExchange(&g_compositePassOrdinal, 0);
    InterlockedExchange(&g_compositeGraphStartGeometryDispatchCalls,
                        static_cast<LONG>(ReadDispatchCounter(&g_geometryDispatchCalls)));
    InterlockedExchange(&g_compositeGraphLeafCount, 0);
    InterlockedExchange(&g_compositeGraphPostReleaseCount, 0);
    InterlockedExchange(&g_compositeGraphState1Count, 0);
    InterlockedExchange(&g_compositeGraphState2Count, 0);
    InterlockedExchange(&g_compositeGraphAccumulatorDrainCount, 0);
    InterlockedExchange(&g_compositeGraphActive, 1);
}

bool CaptureGateIsActive() {
    if (g_armAtStartup) return true;
    return g_captureActiveEvent != nullptr &&
        WaitForSingleObject(g_captureActiveEvent, 0) == WAIT_OBJECT_0;
}

bool ResolvePlayerTranslationNodes(
    uintptr_t player, std::array<uintptr_t, 4> &nodes,
    std::array<uintptr_t, 4> &parents) {
    if (player < 0x10000) return false;
    const uintptr_t loadedData = ReadEngineValue<uintptr_t>(player + 0x5C);
    const uintptr_t thirdPersonBiped =
        ReadEngineValue<uintptr_t>(player + 0x1A0);
    const uintptr_t firstPersonBiped =
        ReadEngineValue<uintptr_t>(player + 0x5E8);
    nodes[0] = loadedData >= 0x10000
        ? ReadEngineValue<uintptr_t>(loadedData + 0x14) : 0;
    nodes[1] = thirdPersonBiped >= 0x10000
        ? ReadEngineValue<uintptr_t>(thirdPersonBiped) : 0;
    nodes[2] = firstPersonBiped >= 0x10000
        ? ReadEngineValue<uintptr_t>(firstPersonBiped) : 0;
    nodes[3] = ReadEngineValue<uintptr_t>(player + 0x5F0);
    for (size_t index = 0; index < nodes.size(); ++index) {
        if (nodes[index] < 0x10000) return false;
        parents[index] = ReadEngineValue<uintptr_t>(nodes[index] + 0x18);
        if (parents[index] < 0x10000) return false;
        for (size_t previous = 0; previous < index; ++previous) {
            if (nodes[index] == nodes[previous]) return false;
        }
    }
    return true;
}

bool PositionsNear(
    const std::array<float, 3> &left,
    const std::array<float, 3> &right,
    float toleranceSquared = 0.0001f) {
    float distanceSquared = 0.0f;
    for (size_t axis = 0; axis < left.size(); ++axis) {
        const float delta = left[axis] - right[axis];
        distanceSquared += delta * delta;
    }
    return std::isfinite(distanceSquared) && distanceSquared <= toleranceSquared;
}

void ResetRenderTranslationInterpolation() {
    g_futureTranslationPublication = {};
    g_translationInterpolationPair = {};
    g_renderTranslationEligibleFrames = 0;
    g_renderTranslationPlayer = 0;
    g_renderTranslationCell = 0;
    g_renderTranslationRenderer = 0;
    g_renderTranslationSceneGraph = 0;
    g_renderTranslationCamera = 0;
    g_renderTranslationCameraParent = 0;
    g_renderTranslationNodes = {};
    g_renderTranslationParents = {};
}

void RecordFutureTranslationPublication() {
    if (!g_renderTranslationInterpolationEnabled ||
        !g_quantizedDeltaEnabled || !CaptureGateIsActive()) {
        g_futureTranslationPublication = {};
        return;
    }

    TranslationPublicationSample sample{};
    __try {
        sample.player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        sample.cell = sample.player >= 0x10000
            ? ReadEngineValue<uintptr_t>(sample.player + 0x3C) : 0;
        sample.renderer = ReadEngineValue<uintptr_t>(kRendererSingleton);
        sample.sceneGraph = ReadEngineValue<uintptr_t>(kSceneGraphSingleton);
        sample.camera = sample.sceneGraph >= 0x10000
            ? ReadEngineValue<uintptr_t>(sample.sceneGraph + 0xAC) : 0;
        sample.cameraParent = sample.camera >= 0x10000
            ? ReadEngineValue<uintptr_t>(sample.camera + 0x18) : 0;
        const bool firstPerson = sample.player >= 0x10000 &&
            ReadEngineValue<uint8_t>(sample.player + 0x5A8) == 0 &&
            ReadEngineValue<uint8_t>(sample.player + 0x5A9) == 0;
        if (!firstPerson || sample.cell < 0x10000 ||
            sample.renderer < 0x10000 || sample.sceneGraph < 0x10000 ||
            sample.camera < 0x10000 || sample.cameraParent < 0x10000 ||
            !ResolvePlayerTranslationNodes(sample.player, sample.nodes, sample.parents)) {
            g_futureTranslationPublication = {};
            return;
        }
        for (size_t axis = 0; axis < sample.playerPosition.size(); ++axis) {
            sample.playerPosition[axis] =
                ReadEngineValue<float>(sample.player + 0x2C + axis * 4);
        }
        bool positionsMatch = true;
        for (size_t index = 0; index < sample.nodes.size(); ++index) {
            for (size_t axis = 0; axis < sample.playerPosition.size(); ++axis) {
                sample.nodeWorldPositions[index][axis] =
                    ReadEngineValue<float>(sample.nodes[index] + 0x8C + axis * 4);
            }
            positionsMatch = positionsMatch &&
                PositionsNear(sample.nodeWorldPositions[index], sample.playerPosition);
        }
        sample.frame = ReadEngineValue<uint32_t>(kGlobalFrameCounter);
        sample.valid = positionsMatch;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sample = {};
    }
    g_futureTranslationPublication = sample;
}

void TryAcquireRetainedLeafResources() {
    if (!g_leafResourceRetentionEnabled || !CaptureGateIsActive()) return;

    bool eligible = false;
    uint32_t resources[3]{};
    uint32_t metadata[3]{};
    uint32_t auxiliary[3]{};
    uint32_t liveRefCounts[3]{};
    uint32_t rejectMask = 0x80000000u;
    __try {
        const uint32_t geometryDelta =
            ReadDispatchCounter(&g_geometryDispatchCalls) -
            ReadDispatchCounter(&g_compositeGraphStartGeometryDispatchCalls);
        const uintptr_t renderer = ReadEngineValue<uintptr_t>(kRendererSingleton);
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        const uintptr_t cell = player >= 0x10000
            ? ReadEngineValue<uintptr_t>(player + 0x3C) : 0;

        resources[0] = ReadDispatchCounter(&g_compositeLeafBinding1ResourcePtr);
        resources[1] = ReadDispatchCounter(&g_compositeLeafBinding2ResourcePtr);
        resources[2] = ReadDispatchCounter(&g_compositeLeafBinding3ResourcePtr);
        metadata[0] = ReadDispatchCounter(&g_compositeLeafBinding1Metadata);
        metadata[1] = ReadDispatchCounter(&g_compositeLeafBinding2Metadata);
        metadata[2] = ReadDispatchCounter(&g_compositeLeafBinding3Metadata);
        auxiliary[0] = ReadDispatchCounter(&g_compositeLeafBinding1Aux);
        auxiliary[1] = ReadDispatchCounter(&g_compositeLeafBinding2Aux);
        auxiliary[2] = ReadDispatchCounter(&g_compositeLeafBinding3Aux);

        bool resourceSignaturesMatch = true;
        for (size_t index = 0; index < 3; ++index) {
            resourceSignaturesMatch = resourceSignaturesMatch &&
                resources[index] >= 0x10000 &&
                ReadEngineValue<uint32_t>(resources[index]) == 0x00E95038;
            liveRefCounts[index] = ReadEngineValue<uint32_t>(
                static_cast<uintptr_t>(resources[index]) + sizeof(uint32_t));
        }

        const uint32_t passVtable = ReadDispatchCounter(&g_compositePassVtable);
        const bool bindingFlagsMatch =
            (ReadDispatchCounter(&g_compositeLeafBinding1Flags) & 0xFFFFu) == 0x0100u &&
            (ReadDispatchCounter(&g_compositeLeafBinding2Flags) & 0xFFFFu) == 0x0100u &&
            (ReadDispatchCounter(&g_compositeLeafBinding3Flags) & 0xFFFFu) == 0x0100u;
        const bool rendererMatches = renderer >= 0x10000 &&
            ReadEngineValue<uint32_t>(renderer + 0x200) == 1 &&
            ReadEngineValue<uint8_t>(renderer + 0x208) == 1 &&
            ReadEngineValue<uintptr_t>(renderer + 0x884) >= 0x10000 &&
            ReadEngineValue<uintptr_t>(renderer + 0x888) ==
                ReadEngineValue<uintptr_t>(renderer + 0x884);

        rejectMask = 0;
        if (InterlockedCompareExchange(&g_compositeGraphActive, 0, 0) == 0) {
            rejectMask |= 1u << 0;
        }
        if (ReadDispatchCounter(&g_compositePassOrdinal) != 8) {
            rejectMask |= 1u << 1;
        }
        if (ReadDispatchCounter(&g_compositeGraphLeafCount) != 1 ||
            ReadDispatchCounter(&g_compositeGraphPostReleaseCount) != 1) {
            rejectMask |= 1u << 2;
        }
        if (ReadDispatchCounter(&g_compositeGraphState1Count) != 1 ||
            ReadDispatchCounter(&g_compositeGraphState2Count) != 7) {
            rejectMask |= 1u << 3;
        }
        if (ReadDispatchCounter(&g_compositeGraphAccumulatorDrainCount) != 0) {
            rejectMask |= 1u << 4;
        }
        if (geometryDelta != 8) rejectMask |= 1u << 5;
        if (player < 0x10000 || cell < 0x10000) rejectMask |= 1u << 6;
        if (!rendererMatches) rejectMask |= 1u << 7;
        if (!resourceSignaturesMatch) rejectMask |= 1u << 8;
        if (!bindingFlagsMatch) rejectMask |= 1u << 9;
        if (ReadDispatchCounter(&g_compositeLeafPassPtr) !=
                ReadDispatchCounter(&g_compositePassThisPtr) ||
            ReadDispatchCounter(&g_compositeLeafCaller) != 0x00B1CC47 ||
            ReadDispatchCounter(&g_compositePassReturnAddress) != 0x00B30650 ||
            (passVtable != 0x00E9A160 && passVtable != 0x00E9A30C)) {
            rejectMask |= 1u << 10;
        }
        if (ReadDispatchCounter(&g_compositeLeafBinding0ResourcePtr) != 0 ||
            ReadDispatchCounter(&g_compositeLeafBinding3Ptr) != 0x01176324) {
            rejectMask |= 1u << 11;
        }
        if (ReadDispatchCounter(&g_compositeLeafBinding1ResourceRefCount) != 2 ||
            ReadDispatchCounter(&g_compositeLeafBinding2ResourceRefCount) != 2 ||
            ReadDispatchCounter(&g_compositeLeafBinding3ResourceRefCount) != 3) {
            rejectMask |= 1u << 12;
        }
        if (ReadDispatchCounter(&g_compositeLeafBinding1PostReleaseRefCount) != 1) {
            rejectMask |= 1u << 13;
        }
        if (liveRefCounts[0] != 1 || liveRefCounts[1] != 1 ||
            liveRefCounts[2] != 2) {
            rejectMask |= 1u << 14;
        }
        if (resources[0] == resources[1] || resources[0] == resources[2] ||
            resources[1] == resources[2]) {
            rejectMask |= 1u << 15;
        }
        if (metadata[0] != 1 || metadata[1] != 0 || metadata[2] != 0 ||
            auxiliary[0] != 0 || auxiliary[1] != 0 || auxiliary[2] != 0) {
            rejectMask |= 1u << 16;
        }
        eligible = rejectMask == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        eligible = false;
    }

    InterlockedExchange(&g_retentionRejectMask, static_cast<LONG>(rejectMask));
    InterlockedExchange(&g_retentionObservedSlot1RefCount,
                        static_cast<LONG>(liveRefCounts[0]));
    InterlockedExchange(&g_retentionObservedSlot2RefCount,
                        static_cast<LONG>(liveRefCounts[1]));
    InterlockedExchange(&g_retentionObservedSlot3RefCount,
                        static_cast<LONG>(liveRefCounts[2]));

    InterlockedExchange(&g_compositeGraphActive, 0);
    if (!eligible) {
        InterlockedIncrement(&g_retentionRejectCalls);
        return;
    }

    for (size_t index = 0; index < g_retainedLeafBindings.size(); ++index) {
        g_retainedLeafBindings[index].flags = 0x00000100;
        g_retainedLeafBindings[index].resource = resources[index];
        g_retainedLeafBindings[index].metadata = metadata[index];
        g_retainedLeafBindings[index].auxiliary = auxiliary[index];
    }

    size_t acquiredCount = 0;
    uint32_t acquireCounts[3]{};
    bool acquired = true;
    __try {
        for (; acquiredCount < g_retainedLeafBindings.size(); ++acquiredCount) {
            acquireCounts[acquiredCount] = static_cast<uint32_t>(InterlockedIncrement(
                reinterpret_cast<volatile LONG *>(
                    static_cast<uintptr_t>(resources[acquiredCount]) +
                    sizeof(uint32_t))));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        acquired = false;
    }
    if (!acquired) {
        while (acquiredCount != 0) {
            --acquiredCount;
            ReleaseResourceReference(resources[acquiredCount]);
        }
        for (auto &binding : g_retainedLeafBindings) binding.resource = 0;
        InterlockedIncrement(&g_retentionRejectCalls);
        return;
    }

    InterlockedExchange(&g_retentionSlot1AcquireRefCount,
                        static_cast<LONG>(acquireCounts[0]));
    InterlockedExchange(&g_retentionSlot2AcquireRefCount,
                        static_cast<LONG>(acquireCounts[1]));
    InterlockedExchange(&g_retentionSlot3AcquireRefCount,
                        static_cast<LONG>(acquireCounts[2]));
    InterlockedExchange(&g_retentionSlot1ReleaseRefCount, 0);
    InterlockedExchange(&g_retentionSlot2ReleaseRefCount, 0);
    InterlockedExchange(&g_retentionSlot3ReleaseRefCount, 0);
    InterlockedExchange(&g_retentionActive, 1);
    InterlockedIncrement(&g_retentionAcquireCalls);
}

void PublishProbe(uint32_t probeId);
void __cdecl PublishWorkerEffectCallbackTarget(uint32_t objectPtr);

void __cdecl RunPostPresentLeafReplay() {
    if (!g_postPresentLeafReplayEnabled) return;
    if (InterlockedCompareExchange(&g_retentionActive, 0, 0) == 0) {
        if (!CaptureGateIsActive()) {
            InterlockedExchange(&g_leafReplayEligibleFrames, 0);
            InterlockedExchange(&g_leafReplayCell, 0);
        }
        return;
    }

    InterlockedIncrement(&g_leafReplayAttemptCalls);
    uint32_t rejectMask = 0;
    uintptr_t pass = 0;
    uintptr_t arg0 = 0;
    uintptr_t arg1 = 0;
    uintptr_t arg2 = 0;
    uintptr_t draw = 0;
    uintptr_t cell = 0;

    __try {
        if (!CaptureGateIsActive()) rejectMask |= 1u << 0;
        if (!g_leafArgumentLifetimeBaseline.valid ||
            ReadDispatchCounter(&g_leafLifetimeBaselineFaultMask) != 0 ||
            ReadDispatchCounter(&g_leafLifetimePostPresentFaultMask) != 0 ||
            ReadDispatchCounter(&g_leafLifetimeChangeMask) != 0 ||
            ReadDispatchCounter(&g_leafLifetimeBaselineHash) !=
                ReadDispatchCounter(&g_leafLifetimePostPresentHash)) {
            rejectMask |= 1u << 1;
        }

        const uintptr_t renderer = ReadEngineValue<uintptr_t>(kRendererSingleton);
        if (renderer < 0x10000 ||
            ReadEngineValue<uint32_t>(renderer + 0x200) != 0 ||
            ReadEngineValue<uint8_t>(renderer + 0x208) != 0 ||
            ReadEngineValue<uintptr_t>(renderer + 0x888) != 0) {
            rejectMask |= 1u << 2;
        }
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        cell = player >= 0x10000
            ? ReadEngineValue<uintptr_t>(player + 0x3C) : 0;
        if (player < 0x10000 || cell < 0x10000) rejectMask |= 1u << 3;

        pass = ReadDispatchCounter(&g_compositeLeafPassPtr);
        arg0 = ReadDispatchCounter(&g_compositeLeafArg0);
        arg1 = ReadDispatchCounter(&g_compositeLeafArg1);
        arg2 = ReadDispatchCounter(&g_compositeLeafArg2);
        const uintptr_t passVtable = pass >= 0x10000
            ? ReadEngineValue<uintptr_t>(pass) : 0;
        draw = passVtable >= 0x10000
            ? ReadEngineValue<uintptr_t>(passVtable + sizeof(uint32_t)) : 0;
        if (pass < 0x10000 ||
            (passVtable != 0x00E9A160 && passVtable != 0x00E9A30C) ||
            draw != kImageSpacePassDraw) {
            rejectMask |= 1u << 4;
        }
        if (arg0 < 0x10000 || arg1 != renderer || arg2 < 0x10000) {
            rejectMask |= 1u << 5;
        }

        bool bindingsMatch = true;
        bindingsMatch = g_retainedLeafEmptyBinding.flags == 0x00000100 &&
            g_retainedLeafEmptyBinding.resource == 0 &&
            g_retainedLeafEmptyBinding.metadata == 0 &&
            g_retainedLeafEmptyBinding.auxiliary == 0;
        const uint32_t expectedMetadata[3] = {1, 0, 0};
        const uint32_t expectedRefCounts[3] = {2, 2, 3};
        for (size_t index = 0; index < g_retainedLeafBindings.size(); ++index) {
            const RetainedResourceBinding &binding = g_retainedLeafBindings[index];
            bindingsMatch = bindingsMatch && binding.flags == 0x00000100 &&
                binding.resource >= 0x10000 &&
                binding.metadata == expectedMetadata[index] &&
                binding.auxiliary == 0 &&
                ReadEngineValue<uint32_t>(binding.resource) == 0x00E95038 &&
                ReadEngineValue<uint32_t>(binding.resource + sizeof(uint32_t)) ==
                    expectedRefCounts[index];
        }
        if (!bindingsMatch) rejectMask |= 1u << 6;

        const LeafArgumentLifetimeSample current =
            CaptureLeafArgumentLifetime(&g_leafArgumentLifetimeBaseline);
        uint32_t changed = current.faultMask;
        for (size_t index = 0; index < current.values.size(); ++index) {
            if (current.values[index] !=
                g_leafArgumentLifetimeBaseline.values[index]) {
                changed |= 1u << (index + 4);
            }
        }
        if (changed != 0) rejectMask |= 1u << 7;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        rejectMask |= 1u << 31;
    }

    InterlockedExchange(&g_leafReplayRejectMask, static_cast<LONG>(rejectMask));
    if (rejectMask != 0) {
        InterlockedExchange(&g_leafReplayEligibleFrames, 0);
        InterlockedExchange(&g_leafReplayCell, 0);
        InterlockedIncrement(&g_leafReplayRejectCalls);
        PublishProbe(1374);
        ReleaseRetainedLeafResources(false);
        PublishProbe(1373);
        return;
    }

    const LONG cellValue = static_cast<LONG>(cell);
    if (InterlockedExchange(&g_leafReplayCell, cellValue) != cellValue) {
        InterlockedExchange(&g_leafReplayEligibleFrames, 0);
    }
    if (InterlockedIncrement(&g_leafReplayEligibleFrames) <= 240) {
        ReleaseRetainedLeafResources(false);
        PublishProbe(1375);
        return;
    }

    InterlockedExchange(&g_leafReplayActive, 1);
    PublishProbe(1370);

    using BindFn = void(__thiscall *)(void *, uint32_t, void *, uint32_t);
    const auto bind = reinterpret_cast<BindFn>(kBindImageSpacePassResource);
    bind(reinterpret_cast<void *>(pass), 0, &g_retainedLeafEmptyBinding, 0);
    bind(reinterpret_cast<void *>(pass), 1, &g_retainedLeafBindings[0], 1);
    bind(reinterpret_cast<void *>(pass), 2, &g_retainedLeafBindings[1], 0);
    bind(reinterpret_cast<void *>(pass), 3, &g_retainedLeafBindings[2], 0);

    using DrawFn = void(__thiscall *)(void *, void *, void *, void *, uint32_t);
    reinterpret_cast<DrawFn>(draw)(
        reinterpret_cast<void *>(pass), reinterpret_cast<void *>(arg0),
        reinterpret_cast<void *>(arg1), reinterpret_cast<void *>(arg2), 1);
    InterlockedIncrement(&g_leafReplayDrawCalls);
    PublishProbe(1371);

    using FinalizeFn = void(__cdecl *)();
    reinterpret_cast<FinalizeFn>(kRenderFinalize)();
    InterlockedIncrement(&g_leafReplayFinalizeCalls);
    PublishProbe(1372);

    ReleaseRetainedLeafResources(false);
    InterlockedExchange(&g_leafReplayActive, 0);
    PublishProbe(1373);
}

uint32_t ReadFormId(uintptr_t form) {
    return form >= 0x10000 ? ReadEngineValue<uint32_t>(form + 0x0C) : 0;
}

void CaptureTransformNode(StateSnapshot &snapshot, size_t index, uintptr_t node) {
    if (index >= 4 || node < 0x10000) return;
    snapshot.transformNodePtr[index] = static_cast<uint32_t>(node);
    snapshot.transformNodeParentPtr[index] =
        ReadEngineValue<uint32_t>(node + 0x18);
    snapshot.transformNodeFlags[index] =
        ReadEngineValue<uint32_t>(node + 0x30);
    float localRotation[9]{};
    float worldRotation[9]{};
    for (size_t i = 0; i < 9; ++i) {
        localRotation[i] = ReadEngineValue<float>(node + 0x34 + i * 4);
        worldRotation[i] = ReadEngineValue<float>(node + 0x68 + i * 4);
    }
    snapshot.transformNodeLocalRotationHash[index] =
        HashBytes(14695981039346656037ull, localRotation,
                  sizeof(localRotation));
    snapshot.transformNodeWorldRotationHash[index] =
        HashBytes(14695981039346656037ull, worldRotation,
                  sizeof(worldRotation));
    for (size_t axis = 0; axis < 3; ++axis) {
        snapshot.transformNodeLocalPosition[index][axis] =
            ReadEngineValue<float>(node + 0x58 + axis * 4);
        snapshot.transformNodeWorldPosition[index][axis] =
            ReadEngineValue<float>(node + 0x8C + axis * 4);
    }
    snapshot.transformNodeLocalScale[index] =
        ReadEngineValue<float>(node + 0x64);
    snapshot.transformNodeWorldScale[index] =
        ReadEngineValue<float>(node + 0x98);
}

StateSnapshot CaptureStateSnapshot() {
    StateSnapshot snapshot{};
    __try {
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        if (player >= 0x10000) {
            snapshot.validMask |= kStatePlayer;
            snapshot.playerRefId = ReadFormId(player);
            const uintptr_t cell = ReadEngineValue<uintptr_t>(player + 0x3C);
            snapshot.cellRefId = ReadFormId(cell);
            for (size_t i = 0; i < 3; ++i) {
                snapshot.playerRotation[i] = ReadEngineValue<float>(player + 0x20 + i * 4);
                snapshot.playerPosition[i] = ReadEngineValue<float>(player + 0x2C + i * 4);
            }
            snapshot.playerScale = ReadEngineValue<float>(player + 0x38);
            snapshot.lifeState = ReadEngineValue<uint32_t>(player + 0xFC);
            snapshot.sitSleepState = ReadEngineValue<uint32_t>(player + 0x19C);
            snapshot.playerStateFlags =
                (static_cast<uint32_t>(ReadEngineValue<uint8_t>(player + 0xF8)) << 0) |
                (static_cast<uint32_t>(ReadEngineValue<uint8_t>(player + 0x140)) << 8) |
                (static_cast<uint32_t>(ReadEngineValue<uint8_t>(player + 0x141)) << 16) |
                (static_cast<uint32_t>(ReadEngineValue<uint8_t>(player + 0x9A4)) << 24);
            snapshot.disabledControlFlags = ReadEngineValue<uint32_t>(player + 0x5DC);

            // ButcherPeteFOSE's Fallout 3 layouts identify PlayerCharacter's
            // first-person AnimData at +0x5EC and the weapon sequence at
            // AnimData index 4. Read it only; do not call engine animation
            // methods from telemetry sites that may run on non-game threads.
            const uint8_t isThirdPerson = ReadEngineValue<uint8_t>(player + 0x5A8);
            const uint8_t thirdPersonCamera = ReadEngineValue<uint8_t>(player + 0x5A9);
            snapshot.playerViewFlags =
                static_cast<uint32_t>(isThirdPerson) |
                (static_cast<uint32_t>(thirdPersonCamera) << 8);
            const uintptr_t firstPersonAnimData =
                ReadEngineValue<uintptr_t>(player + 0x5EC);
            if (firstPersonAnimData >= 0x10000) {
                snapshot.validMask |= kStateFirstPersonAnimation;
                snapshot.firstPersonAnimDataPtr =
                    static_cast<uint32_t>(firstPersonAnimData);
                snapshot.weaponAnimGroupId =
                    ReadEngineValue<uint16_t>(firstPersonAnimData + 0x4C + 4 * 2);
                snapshot.weaponSequenceState1 =
                    ReadEngineValue<int32_t>(firstPersonAnimData + 0x5C + 4 * 4);
                snapshot.weaponSequenceState2 =
                    ReadEngineValue<int32_t>(firstPersonAnimData + 0x7C + 4 * 4);
                snapshot.weaponSequencePtr =
                    ReadEngineValue<uint32_t>(firstPersonAnimData + 0xE0 + 4 * 4);
                const uintptr_t weaponSequence = snapshot.weaponSequencePtr;
                if (weaponSequence >= 0x10000) {
                    const uintptr_t animGroup =
                        ReadEngineValue<uintptr_t>(weaponSequence + 0x74);
                    if (animGroup >= 0x10000) {
                        snapshot.weaponSequenceAnimGroupPtr =
                            static_cast<uint32_t>(animGroup);
                        snapshot.weaponSequenceAnimGroupIndex =
                            ReadEngineValue<uint8_t>(animGroup + 0x10);
                    }
                }
            }

            const uintptr_t process = ReadEngineValue<uintptr_t>(player + 0x60);
            if (process >= 0x10000) {
                snapshot.validMask |= kStatePlayerProcess;
                const uintptr_t package = ReadEngineValue<uintptr_t>(process + 0x04);
                snapshot.packageRefId = ReadFormId(package);
                snapshot.packageProcedure = ReadEngineValue<uint32_t>(process + 0x10);
                snapshot.packageStartTime = ReadEngineValue<float>(process + 0x14);
                snapshot.processSystemTime = ReadEngineValue<float>(process + 0x1C);
                snapshot.processLevel = ReadEngineValue<uint32_t>(process + 0x28);
            }

            if (g_sceneTransformTelemetryEnabled) {
                const uintptr_t loadedData =
                    ReadEngineValue<uintptr_t>(player + 0x5C);
                const uintptr_t playerRoot = loadedData >= 0x10000
                    ? ReadEngineValue<uintptr_t>(loadedData + 0x14) : 0;
                const uintptr_t thirdPersonBiped =
                    ReadEngineValue<uintptr_t>(player + 0x1A0);
                const uintptr_t thirdPersonRoot = thirdPersonBiped >= 0x10000
                    ? ReadEngineValue<uintptr_t>(thirdPersonBiped) : 0;
                const uintptr_t firstPersonBiped =
                    ReadEngineValue<uintptr_t>(player + 0x5E8);
                const uintptr_t firstPersonRoot = firstPersonBiped >= 0x10000
                    ? ReadEngineValue<uintptr_t>(firstPersonBiped) : 0;
                const uintptr_t firstPersonNode =
                    ReadEngineValue<uintptr_t>(player + 0x5F0);
                CaptureTransformNode(snapshot, 0, playerRoot);
                CaptureTransformNode(snapshot, 1, thirdPersonRoot);
                CaptureTransformNode(snapshot, 2, firstPersonRoot);
                CaptureTransformNode(snapshot, 3, firstPersonNode);
                if (snapshot.transformNodePtr[0] != 0 ||
                    snapshot.transformNodePtr[1] != 0 ||
                    snapshot.transformNodePtr[2] != 0 ||
                    snapshot.transformNodePtr[3] != 0) {
                    snapshot.validMask |= kStateSceneTransforms;
                }
            }
        }

        const uintptr_t gameHour = ReadEngineValue<uintptr_t>(kCalendarSingleton + 0x0C);
        const uintptr_t gameDaysPassed = ReadEngineValue<uintptr_t>(kCalendarSingleton + 0x10);
        if (gameHour >= 0x10000 && gameDaysPassed >= 0x10000) {
            snapshot.validMask |= kStateCalendar;
            snapshot.gameHour = ReadEngineValue<float>(gameHour + 0x24);
            snapshot.gameDaysPassed = ReadEngineValue<float>(gameDaysPassed + 0x24);
        }

        snapshot.validMask |= kStateProcessManager;
        snapshot.processTime = ReadEngineValue<float>(kProcessManager);

        const uintptr_t saveManager = ReadEngineValue<uintptr_t>(kSaveLoadSingleton);
        if (saveManager >= 0x10000) {
            snapshot.validMask |= kStateSaveManager;
            snapshot.changedFormsVtable = ReadEngineValue<uint32_t>(saveManager + 0x24);
            snapshot.changedFormsDataPtr = ReadEngineValue<uint32_t>(saveManager + 0x28);
            snapshot.changedForms = ReadEngineValue<uint32_t>(saveManager + 0x2C);
            snapshot.changedFormsAlloc = ReadEngineValue<uint32_t>(saveManager + 0x30);
        }

        snapshot.validMask |= kStateAudioManager;
        snapshot.audioRequestA = ReadEngineValue<uint32_t>(kAudioManager + 0x24);
        snapshot.audioRequestB = ReadEngineValue<uint32_t>(kAudioManager + 0x34);
        snapshot.audioRequestC = ReadEngineValue<uint32_t>(kAudioManager + 0x44);
        snapshot.playingSounds = ReadEngineValue<uint32_t>(kAudioManager + 0x60);

        if (g_eventDispatchTelemetryEnabled) {
            snapshot.validMask |= kStateDispatchCounters;
            snapshot.audioPlayCalls = ReadDispatchCounter(&g_audioPlayCalls);
            snapshot.scriptRunCalls = ReadDispatchCounter(&g_scriptRunCalls);
            snapshot.animationNoteCalls = ReadDispatchCounter(&g_animationNoteCalls);
            snapshot.inputPollCalls = ReadDispatchCounter(&g_inputPollCalls);
            snapshot.presentCalls = ReadDispatchCounter(&g_presentCalls);
            snapshot.geometryDispatchCalls =
                ReadDispatchCounter(&g_geometryDispatchCalls);
            snapshot.scriptDuringPresentCalls =
                ReadDispatchCounter(&g_scriptDuringPresentCalls);
            snapshot.scriptDuringPresentSameThreadCalls =
                ReadDispatchCounter(&g_scriptDuringPresentSameThreadCalls);
            snapshot.scriptDuringPresentOtherThreadCalls =
                ReadDispatchCounter(&g_scriptDuringPresentOtherThreadCalls);
            snapshot.lastScriptDuringPresentThreadId =
                ReadDispatchCounter(&g_lastScriptDuringPresentThreadId);
            snapshot.scriptDuringState2PassCalls =
                ReadDispatchCounter(&g_scriptDuringState2PassCalls);
            snapshot.scriptDuringState2PassSameThreadCalls =
                ReadDispatchCounter(&g_scriptDuringState2PassSameThreadCalls);
            snapshot.scriptDuringState2PassOtherThreadCalls =
                ReadDispatchCounter(&g_scriptDuringState2PassOtherThreadCalls);
            snapshot.lastScriptDuringState2PassThreadId =
                ReadDispatchCounter(&g_lastScriptDuringState2PassThreadId);
            snapshot.changedFormsClearCalls =
                ReadDispatchCounter(&g_changedFormsClearCalls);
            snapshot.lastChangedFormsClearReturnAddress =
                ReadDispatchCounter(&g_lastChangedFormsClearReturnAddress);
            snapshot.changedFormsFreeCalls =
                ReadDispatchCounter(&g_changedFormsFreeCalls);
            snapshot.lastChangedFormsFreeReturnAddress =
                ReadDispatchCounter(&g_lastChangedFormsFreeReturnAddress);
            snapshot.state2PassReturnAddress =
                ReadDispatchCounter(&g_state2PassReturnAddress);
            snapshot.state2OwnerReturnAddress =
                ReadDispatchCounter(&g_state2OwnerReturnAddress);
            snapshot.renderAccumulatorPtr =
                ReadDispatchCounter(&g_renderAccumulatorPtr);
            snapshot.renderAccumulatorCount =
                ReadDispatchCounter(&g_renderAccumulatorCount);
            snapshot.renderAccumulatorArrayPtr =
                ReadDispatchCounter(&g_renderAccumulatorArrayPtr);
            snapshot.renderAccumulatorCursor =
                ReadDispatchCounter(&g_renderAccumulatorCursor);
            snapshot.renderAccumulatorCurrentGeometryPtr =
                ReadDispatchCounter(&g_renderAccumulatorCurrentGeometryPtr);
            snapshot.renderAccumulatorPassId =
                ReadDispatchCounter(&g_renderAccumulatorPassId);
            snapshot.renderAccumulatorReverseGeometryPtr =
                ReadDispatchCounter(&g_renderAccumulatorReverseGeometryPtr);
            snapshot.renderAccumulatorReversePropertyPtr =
                ReadDispatchCounter(&g_renderAccumulatorReversePropertyPtr);
            snapshot.compositePassOrdinal =
                ReadDispatchCounter(&g_compositePassOrdinal);
            snapshot.compositePassThisPtr =
                ReadDispatchCounter(&g_compositePassThisPtr);
            snapshot.compositePassBasePtr =
                ReadDispatchCounter(&g_compositePassBasePtr);
            snapshot.compositePassVtable =
                ReadDispatchCounter(&g_compositePassVtable);
            snapshot.compositePassTargetSlotPtr =
                ReadDispatchCounter(&g_compositePassTargetSlotPtr);
            snapshot.compositePassTargetBindingPtr =
                ReadDispatchCounter(&g_compositePassTargetBindingPtr);
            snapshot.compositePassTargetPtr =
                ReadDispatchCounter(&g_compositePassTargetPtr);
            snapshot.compositePassTargetVtable =
                ReadDispatchCounter(&g_compositePassTargetVtable);
            snapshot.compositePassTargetRefCount =
                ReadDispatchCounter(&g_compositePassTargetRefCount);
            snapshot.compositePassReturnAddress =
                ReadDispatchCounter(&g_compositePassReturnAddress);
            snapshot.compositePassArg0 = ReadDispatchCounter(&g_compositePassArg0);
            snapshot.compositePassArg1 = ReadDispatchCounter(&g_compositePassArg1);
            snapshot.compositePassArg2 = ReadDispatchCounter(&g_compositePassArg2);
            snapshot.compositePassArg3 = ReadDispatchCounter(&g_compositePassArg3);
            snapshot.compositeExecutorGraphPtr =
                ReadDispatchCounter(&g_compositeExecutorGraphPtr);
            snapshot.compositeExecutorReturnAddress =
                ReadDispatchCounter(&g_compositeExecutorReturnAddress);
            snapshot.compositeExecutorIndex =
                ReadDispatchCounter(&g_compositeExecutorIndex);
            snapshot.compositeExecutorArg1 =
                ReadDispatchCounter(&g_compositeExecutorArg1);
            snapshot.compositeExecutorArg2 =
                ReadDispatchCounter(&g_compositeExecutorArg2);
            snapshot.compositeExecutorArg3 =
                ReadDispatchCounter(&g_compositeExecutorArg3);
            snapshot.compositeExecutorArg4 =
                ReadDispatchCounter(&g_compositeExecutorArg4);
            snapshot.compositeExecutorArg5 =
                ReadDispatchCounter(&g_compositeExecutorArg5);
            snapshot.compositeLeafPassPtr =
                ReadDispatchCounter(&g_compositeLeafPassPtr);
            snapshot.compositeLeafRootPtr =
                ReadDispatchCounter(&g_compositeLeafRootPtr);
            snapshot.compositeLeafCaller =
                ReadDispatchCounter(&g_compositeLeafCaller);
            snapshot.compositeLeafArg0 = ReadDispatchCounter(&g_compositeLeafArg0);
            snapshot.compositeLeafArg1 = ReadDispatchCounter(&g_compositeLeafArg1);
            snapshot.compositeLeafArg2 = ReadDispatchCounter(&g_compositeLeafArg2);
            snapshot.compositeLeafBindingArrayPtr =
                ReadDispatchCounter(&g_compositeLeafBindingArrayPtr);
            snapshot.compositeLeafBinding0Ptr =
                ReadDispatchCounter(&g_compositeLeafBinding0Ptr);
            snapshot.compositeLeafBinding1Ptr =
                ReadDispatchCounter(&g_compositeLeafBinding1Ptr);
            snapshot.compositeLeafBinding2Ptr =
                ReadDispatchCounter(&g_compositeLeafBinding2Ptr);
            snapshot.compositeLeafBinding3Ptr =
                ReadDispatchCounter(&g_compositeLeafBinding3Ptr);
            snapshot.compositeLeafBinding1Flags =
                ReadDispatchCounter(&g_compositeLeafBinding1Flags);
            snapshot.compositeLeafBinding1ResourcePtr =
                ReadDispatchCounter(&g_compositeLeafBinding1ResourcePtr);
            snapshot.compositeLeafBinding1Metadata =
                ReadDispatchCounter(&g_compositeLeafBinding1Metadata);
            snapshot.compositeLeafBinding1Aux =
                ReadDispatchCounter(&g_compositeLeafBinding1Aux);
            snapshot.compositeLeafBinding1ResourceVtable =
                ReadDispatchCounter(&g_compositeLeafBinding1ResourceVtable);
            snapshot.compositeLeafBinding1ResourceRefCount =
                ReadDispatchCounter(&g_compositeLeafBinding1ResourceRefCount);
            snapshot.compositeLeafBinding1PostReleaseRefCount =
                ReadDispatchCounter(&g_compositeLeafBinding1PostReleaseRefCount);
            snapshot.compositeLeafBinding0Flags =
                ReadDispatchCounter(&g_compositeLeafBinding0Flags);
            snapshot.compositeLeafBinding0ResourcePtr =
                ReadDispatchCounter(&g_compositeLeafBinding0ResourcePtr);
            snapshot.compositeLeafBinding0Metadata =
                ReadDispatchCounter(&g_compositeLeafBinding0Metadata);
            snapshot.compositeLeafBinding0Aux =
                ReadDispatchCounter(&g_compositeLeafBinding0Aux);
            snapshot.compositeLeafBinding0ResourceVtable =
                ReadDispatchCounter(&g_compositeLeafBinding0ResourceVtable);
            snapshot.compositeLeafBinding0ResourceRefCount =
                ReadDispatchCounter(&g_compositeLeafBinding0ResourceRefCount);
            snapshot.compositeLeafBinding2Flags =
                ReadDispatchCounter(&g_compositeLeafBinding2Flags);
            snapshot.compositeLeafBinding2ResourcePtr =
                ReadDispatchCounter(&g_compositeLeafBinding2ResourcePtr);
            snapshot.compositeLeafBinding2Metadata =
                ReadDispatchCounter(&g_compositeLeafBinding2Metadata);
            snapshot.compositeLeafBinding2Aux =
                ReadDispatchCounter(&g_compositeLeafBinding2Aux);
            snapshot.compositeLeafBinding2ResourceVtable =
                ReadDispatchCounter(&g_compositeLeafBinding2ResourceVtable);
            snapshot.compositeLeafBinding2ResourceRefCount =
                ReadDispatchCounter(&g_compositeLeafBinding2ResourceRefCount);
            snapshot.compositeLeafBinding3Flags =
                ReadDispatchCounter(&g_compositeLeafBinding3Flags);
            snapshot.compositeLeafBinding3ResourcePtr =
                ReadDispatchCounter(&g_compositeLeafBinding3ResourcePtr);
            snapshot.compositeLeafBinding3Metadata =
                ReadDispatchCounter(&g_compositeLeafBinding3Metadata);
            snapshot.compositeLeafBinding3Aux =
                ReadDispatchCounter(&g_compositeLeafBinding3Aux);
            snapshot.compositeLeafBinding3ResourceVtable =
                ReadDispatchCounter(&g_compositeLeafBinding3ResourceVtable);
            snapshot.compositeLeafBinding3ResourceRefCount =
                ReadDispatchCounter(&g_compositeLeafBinding3ResourceRefCount);
            snapshot.retentionAcquireCalls =
                ReadDispatchCounter(&g_retentionAcquireCalls);
            snapshot.retentionReleaseCalls =
                ReadDispatchCounter(&g_retentionReleaseCalls);
            snapshot.retentionRejectCalls =
                ReadDispatchCounter(&g_retentionRejectCalls);
            snapshot.retentionForcedReleaseCalls =
                ReadDispatchCounter(&g_retentionForcedReleaseCalls);
            snapshot.retentionActive = ReadDispatchCounter(&g_retentionActive);
            snapshot.retentionSlot1AcquireRefCount =
                ReadDispatchCounter(&g_retentionSlot1AcquireRefCount);
            snapshot.retentionSlot2AcquireRefCount =
                ReadDispatchCounter(&g_retentionSlot2AcquireRefCount);
            snapshot.retentionSlot3AcquireRefCount =
                ReadDispatchCounter(&g_retentionSlot3AcquireRefCount);
            snapshot.retentionSlot1ReleaseRefCount =
                ReadDispatchCounter(&g_retentionSlot1ReleaseRefCount);
            snapshot.retentionSlot2ReleaseRefCount =
                ReadDispatchCounter(&g_retentionSlot2ReleaseRefCount);
            snapshot.retentionSlot3ReleaseRefCount =
                ReadDispatchCounter(&g_retentionSlot3ReleaseRefCount);
            snapshot.retentionRejectMask =
                ReadDispatchCounter(&g_retentionRejectMask);
            snapshot.retentionObservedSlot1RefCount =
                ReadDispatchCounter(&g_retentionObservedSlot1RefCount);
            snapshot.retentionObservedSlot2RefCount =
                ReadDispatchCounter(&g_retentionObservedSlot2RefCount);
            snapshot.retentionObservedSlot3RefCount =
                ReadDispatchCounter(&g_retentionObservedSlot3RefCount);
            snapshot.leafLifetimeSampleCalls =
                ReadDispatchCounter(&g_leafLifetimeSampleCalls);
            snapshot.leafLifetimeCheckCalls =
                ReadDispatchCounter(&g_leafLifetimeCheckCalls);
            snapshot.leafLifetimeBaselineFaultMask =
                ReadDispatchCounter(&g_leafLifetimeBaselineFaultMask);
            snapshot.leafLifetimePostPresentFaultMask =
                ReadDispatchCounter(&g_leafLifetimePostPresentFaultMask);
            snapshot.leafLifetimeChangeMask =
                ReadDispatchCounter(&g_leafLifetimeChangeMask);
            snapshot.leafLifetimeBaselineHash =
                ReadDispatchCounter(&g_leafLifetimeBaselineHash);
            snapshot.leafLifetimePostPresentHash =
                ReadDispatchCounter(&g_leafLifetimePostPresentHash);
            snapshot.leafReplayAttemptCalls =
                ReadDispatchCounter(&g_leafReplayAttemptCalls);
            snapshot.leafReplayDrawCalls =
                ReadDispatchCounter(&g_leafReplayDrawCalls);
            snapshot.leafReplayFinalizeCalls =
                ReadDispatchCounter(&g_leafReplayFinalizeCalls);
            snapshot.leafReplayRejectCalls =
                ReadDispatchCounter(&g_leafReplayRejectCalls);
            snapshot.leafReplayRejectMask =
                ReadDispatchCounter(&g_leafReplayRejectMask);
            snapshot.leafReplayActive =
                ReadDispatchCounter(&g_leafReplayActive);
            if (snapshot.renderAccumulatorPtr >= 0x10000) {
                snapshot.validMask |= kStateRenderAccumulator;
            }
        }

        const uintptr_t renderer = ReadEngineValue<uintptr_t>(kRendererSingleton);
        if (renderer >= 0x10000) {
            snapshot.validMask |= kStateRenderer;
            snapshot.rendererPtr = static_cast<uint32_t>(renderer);
            snapshot.rendererDevicePtr = ReadEngineValue<uint32_t>(renderer + 0x288);
            snapshot.rendererFrameState = ReadEngineValue<uint32_t>(renderer + 0x200);
            snapshot.rendererFrameId = ReadEngineValue<uint32_t>(renderer + 0x204);
            snapshot.rendererTargetActive = ReadEngineValue<uint8_t>(renderer + 0x208);
            snapshot.rendererDefaultTargetPtr = ReadEngineValue<uint32_t>(renderer + 0x884);
            snapshot.rendererCurrentTargetPtr = ReadEngineValue<uint32_t>(renderer + 0x888);
            snapshot.rendererSecondaryTargetPtr = ReadEngineValue<uint32_t>(renderer + 0x88C);
            const uintptr_t target = snapshot.rendererCurrentTargetPtr;
            if (target >= 0x10000) {
                snapshot.rendererTargetColorBufferCount =
                    ReadEngineValue<uint32_t>(target + 0x1C);
                snapshot.rendererTargetColorBuffer0Ptr =
                    ReadEngineValue<uint32_t>(target + 0x0C);
                snapshot.rendererTargetDepthBufferPtr =
                    ReadEngineValue<uint32_t>(target + 0x20);
                const uintptr_t colorBuffer = snapshot.rendererTargetColorBuffer0Ptr;
                if (colorBuffer >= 0x10000) {
                    snapshot.rendererTargetColorWidth =
                        ReadEngineValue<uint32_t>(colorBuffer + 0x08);
                    snapshot.rendererTargetColorHeight =
                        ReadEngineValue<uint32_t>(colorBuffer + 0x0C);
                    snapshot.rendererTargetColorDataPtr =
                        ReadEngineValue<uint32_t>(colorBuffer + 0x10);
                }
                const uintptr_t depthBuffer = snapshot.rendererTargetDepthBufferPtr;
                if (depthBuffer >= 0x10000) {
                    snapshot.rendererTargetDepthWidth =
                        ReadEngineValue<uint32_t>(depthBuffer + 0x08);
                    snapshot.rendererTargetDepthHeight =
                        ReadEngineValue<uint32_t>(depthBuffer + 0x0C);
                    snapshot.rendererTargetDepthDataPtr =
                        ReadEngineValue<uint32_t>(depthBuffer + 0x10);
                }
            }
            snapshot.rendererPresentQueueHeadPtr =
                ReadEngineValue<uint32_t>(renderer + 0x900);
            snapshot.rendererPresentQueueTailPtr =
                ReadEngineValue<uint32_t>(renderer + 0x904);
            snapshot.rendererPresentQueueCount =
                ReadEngineValue<uint32_t>(renderer + 0x908);
            const uintptr_t queueHead = snapshot.rendererPresentQueueHeadPtr;
            if (queueHead >= 0x10000) {
                snapshot.rendererPresentQueueObjectPtr =
                    ReadEngineValue<uint32_t>(queueHead + 0x08);
                const uintptr_t queueObject = snapshot.rendererPresentQueueObjectPtr;
                if (queueObject >= 0x10000) {
                    snapshot.rendererPresentQueueObjectVtable =
                        ReadEngineValue<uint32_t>(queueObject);
                    snapshot.rendererPresentQueueSwapChainPtr =
                        ReadEngineValue<uint32_t>(queueObject + 0x58);
                }
            }
        }

        const uintptr_t sceneGraph = ReadEngineValue<uintptr_t>(kSceneGraphSingleton);
        if (sceneGraph >= 0x10000) {
            snapshot.validMask |= kStateSceneCamera;
            snapshot.sceneGraphPtr = static_cast<uint32_t>(sceneGraph);
            const uintptr_t sceneChildren =
                ReadEngineValue<uintptr_t>(sceneGraph + 0xA0);
            if (sceneChildren >= 0x10000) {
                const uintptr_t sceneUpdateRoot =
                    ReadEngineValue<uintptr_t>(sceneChildren);
                if (sceneUpdateRoot >= 0x10000) {
                    snapshot.sceneUpdateRootPtr =
                        static_cast<uint32_t>(sceneUpdateRoot);
                    float rootLocalRotation[9]{};
                    float rootWorldRotation[9]{};
                    for (size_t i = 0; i < 9; ++i) {
                        rootLocalRotation[i] =
                            ReadEngineValue<float>(sceneUpdateRoot + 0x34 + i * 4);
                        rootWorldRotation[i] =
                            ReadEngineValue<float>(sceneUpdateRoot + 0x68 + i * 4);
                    }
                    snapshot.sceneUpdateRootLocalRotationHash =
                        HashBytes(14695981039346656037ull, rootLocalRotation,
                                  sizeof(rootLocalRotation));
                    snapshot.sceneUpdateRootWorldRotationHash =
                        HashBytes(14695981039346656037ull, rootWorldRotation,
                                  sizeof(rootWorldRotation));
                }
            }
            const uintptr_t camera = ReadEngineValue<uintptr_t>(sceneGraph + 0xAC);
            if (camera >= 0x10000) {
                snapshot.cameraPtr = static_cast<uint32_t>(camera);
                float cameraLocalRotation[9]{};
                float cameraWorldRotation[9]{};
                for (size_t i = 0; i < 9; ++i) {
                    cameraLocalRotation[i] =
                        ReadEngineValue<float>(camera + 0x34 + i * 4);
                    cameraWorldRotation[i] =
                        ReadEngineValue<float>(camera + 0x68 + i * 4);
                }
                snapshot.cameraLocalRotationHash =
                    HashBytes(14695981039346656037ull, cameraLocalRotation,
                              sizeof(cameraLocalRotation));
                snapshot.cameraWorldRotationHash =
                    HashBytes(14695981039346656037ull, cameraWorldRotation,
                              sizeof(cameraWorldRotation));
                uintptr_t cameraAncestor = camera;
                for (size_t level = 0; level < 4; ++level) {
                    cameraAncestor =
                        ReadEngineValue<uintptr_t>(cameraAncestor + 0x18);
                    if (cameraAncestor < 0x10000) break;
                    snapshot.cameraParentPtr[level] =
                        static_cast<uint32_t>(cameraAncestor);
                    float parentLocalRotation[9]{};
                    float parentWorldRotation[9]{};
                    for (size_t i = 0; i < 9; ++i) {
                        parentLocalRotation[i] =
                            ReadEngineValue<float>(cameraAncestor + 0x34 + i * 4);
                        parentWorldRotation[i] =
                            ReadEngineValue<float>(cameraAncestor + 0x68 + i * 4);
                    }
                    snapshot.cameraParentLocalRotationHash[level] =
                        HashBytes(14695981039346656037ull, parentLocalRotation,
                                  sizeof(parentLocalRotation));
                    snapshot.cameraParentWorldRotationHash[level] =
                        HashBytes(14695981039346656037ull, parentWorldRotation,
                                  sizeof(parentWorldRotation));
                }
                for (size_t i = 0; i < 3; ++i) {
                    snapshot.cameraWorldPosition[i] =
                        ReadEngineValue<float>(camera + 0x8C + i * 4);
                }
                snapshot.cameraWorldScale = ReadEngineValue<float>(camera + 0x98);
                for (size_t i = 0; i < 6; ++i) {
                    snapshot.cameraFrustum[i] =
                        ReadEngineValue<float>(camera + 0xDC + i * 4);
                }
                snapshot.cameraOrthographic = ReadEngineValue<uint8_t>(camera + 0xF4);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snapshot.validMask |= kStateReadFault;
    }

    constexpr uint64_t kFnvOffset = 14695981039346656037ull;
    uint64_t authoritative = kFnvOffset;
    const uint32_t authoritativeValidity =
        snapshot.validMask & kAuthoritativeValidityMask;
    authoritative = HashValue(authoritative, authoritativeValidity);
    authoritative = HashValue(authoritative, snapshot.playerRefId);
    authoritative = HashValue(authoritative, snapshot.cellRefId);
    authoritative = HashValue(authoritative, snapshot.packageRefId);
    authoritative = HashBytes(authoritative, snapshot.playerPosition, sizeof(snapshot.playerPosition));
    authoritative = HashBytes(authoritative, snapshot.playerRotation, sizeof(snapshot.playerRotation));
    authoritative = HashValue(authoritative, snapshot.playerScale);
    authoritative = HashValue(authoritative, snapshot.processLevel);
    authoritative = HashValue(authoritative, snapshot.lifeState);
    authoritative = HashValue(authoritative, snapshot.sitSleepState);
    authoritative = HashValue(authoritative, snapshot.playerStateFlags);
    authoritative = HashValue(authoritative, snapshot.disabledControlFlags);
    authoritative = HashValue(authoritative, snapshot.packageProcedure);
    authoritative = HashValue(authoritative, snapshot.packageStartTime);
    authoritative = HashValue(authoritative, snapshot.processTime);
    authoritative = HashValue(authoritative, snapshot.processSystemTime);
    authoritative = HashValue(authoritative, snapshot.gameHour);
    authoritative = HashValue(authoritative, snapshot.gameDaysPassed);
    authoritative = HashValue(authoritative, snapshot.changedForms);
    const float havokPhysicsDelta = ReadEngineValue<float>(kHavokPhysicsDelta);
    const float havokRemainder = ReadEngineValue<float>(kHavokRemainder);
    const uint32_t havokSubsteps = ReadEngineValue<uint32_t>(kHavokSubstepCount);
    authoritative = HashValue(authoritative, havokPhysicsDelta);
    authoritative = HashValue(authoritative, havokRemainder);
    authoritative = HashValue(authoritative, havokSubsteps);
    snapshot.authoritativeHash = authoritative;

    uint64_t eventQueues = kFnvOffset;
    eventQueues = HashValue(eventQueues, authoritativeValidity);
    eventQueues = HashValue(eventQueues, snapshot.changedForms);
    eventQueues = HashValue(eventQueues, snapshot.audioRequestA);
    eventQueues = HashValue(eventQueues, snapshot.audioRequestB);
    eventQueues = HashValue(eventQueues, snapshot.audioRequestC);
    eventQueues = HashValue(eventQueues, snapshot.playingSounds);
    eventQueues = HashValue(eventQueues, snapshot.audioPlayCalls);
    eventQueues = HashValue(eventQueues, snapshot.scriptRunCalls);
    eventQueues = HashValue(eventQueues, snapshot.animationNoteCalls);
    eventQueues = HashValue(eventQueues, snapshot.inputPollCalls);
    snapshot.eventQueueHash = eventQueues;
    return snapshot;
}

void Publish(EventKind kind, int64_t qpc, double wallDeltaMs, double accumulatorMs,
             uint32_t timerInputMs, float timerClampMs, float timerClampRemainderMs,
             float frameDeltaSeconds, uint32_t pulse) {
    if (!g_telemetryEnabled || g_quietTelemetry) return;
    uint32_t write = g_writeIndex.load(std::memory_order_relaxed);
    for (;;) {
        const uint32_t read = g_readIndex.load(std::memory_order_acquire);
        if (write - read >= kRingCapacity) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (g_writeIndex.compare_exchange_weak(
                write, write + 1, std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            break;
        }
    }
    TelemetryEvent &event = g_ring[write & kRingMask];
    event.kind = static_cast<uint32_t>(kind);
    event.probeId = 0;
    event.threadId = GetCurrentThreadId();
    event.qpc = qpc;
    event.frame = *reinterpret_cast<volatile uint32_t *>(kGlobalFrameCounter);
    event.pulse = pulse;
    event.wallDeltaMs = wallDeltaMs;
    event.accumulatorMs = accumulatorMs;
    event.timerInputMs = timerInputMs;
    event.timerClampMs = timerClampMs;
    event.timerClampRemainderMs = timerClampRemainderMs;
    event.frameDeltaSeconds = frameDeltaSeconds;
    event.timeMultiplier = *reinterpret_cast<volatile float *>(kGlobalTimeMultiplier);
    event.havokMaxTime = *reinterpret_cast<volatile float *>(kHavokMaxTime);
    event.havokPhysicsDelta = *reinterpret_cast<volatile float *>(kHavokPhysicsDelta);
    event.havokRemainder = *reinterpret_cast<volatile float *>(kHavokRemainder);
    event.havokSubsteps = *reinterpret_cast<volatile uint32_t *>(kHavokSubstepCount);
    event.state = {};
    event.sequence.store(write + 1, std::memory_order_release);
}

void PublishProbe(uint32_t probeId) {
    if (probeId == 2020) RecordFutureTranslationPublication();
    if (probeId == 1320) BeginCompositeGraphObservation();
    const bool compositeActive =
        InterlockedCompareExchange(&g_compositeGraphActive, 0, 0) != 0;
    if (compositeActive) {
        if (probeId == 501) InterlockedIncrement(&g_compositeGraphState1Count);
        if (probeId == 503) InterlockedIncrement(&g_compositeGraphState2Count);
        if (probeId == 1310) {
            InterlockedIncrement(&g_compositeGraphAccumulatorDrainCount);
        }
        if (probeId == 1350) InterlockedIncrement(&g_compositeGraphLeafCount);
        if (probeId == 1360) {
            RecordCompositeLeafPostRelease();
            InterlockedIncrement(&g_compositeGraphPostReleaseCount);
        }
    } else if (probeId == 1360) {
        RecordCompositeLeafPostRelease();
    }
    if (probeId == 1360) RecordLeafArgumentLifetimeBaseline();
    if (probeId == 1321) TryAcquireRetainedLeafResources();
    if (probeId == 402) {
        if (InterlockedCompareExchange(&g_leafReplayActive, 0, 0) == 0) {
            RecordLeafArgumentLifetimePostPresent();
        }
        if (g_leafResourceRetentionEnabled && !g_postPresentLeafReplayEnabled) {
            ReleaseRetainedLeafResources(false);
        }
        EndPresentObservation();
    }
    if (!g_telemetryEnabled || g_quietTelemetry ||
        (!g_frameRegionTelemetryEnabled && !g_authoritativeStateTelemetryEnabled &&
         !g_eventDispatchTelemetryEnabled && !g_sceneTransformTelemetryEnabled)) {
        if (probeId == 401) BeginPresentObservation();
        if (probeId == 503) BeginState2PassObservation();
        if (probeId == 201) EndState2PassObservation();
        return;
    }
    if (g_sceneTransformTelemetryEnabled &&
        !g_frameRegionTelemetryEnabled && !g_authoritativeStateTelemetryEnabled &&
        !g_eventDispatchTelemetryEnabled &&
        probeId != 2020 && probeId != 2021 && probeId != 705 && probeId != 706 &&
        probeId != 2040 && probeId != 2041 && probeId != 2042 && probeId != 2043 &&
        probeId != 2100) {
        return;
    }
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);

    uint32_t write = g_writeIndex.load(std::memory_order_relaxed);
    for (;;) {
        const uint32_t read = g_readIndex.load(std::memory_order_acquire);
        if (write - read >= kRingCapacity) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            if (probeId == 401) BeginPresentObservation();
            if (probeId == 503) BeginState2PassObservation();
            if (probeId == 201) EndState2PassObservation();
            return;
        }
        if (g_writeIndex.compare_exchange_weak(
                write, write + 1, std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            break;
        }
    }

    TelemetryEvent &event = g_ring[write & kRingMask];
    event.kind = 3;
    event.probeId = probeId;
    event.threadId = GetCurrentThreadId();
    event.qpc = now.QuadPart;
    event.frame = *reinterpret_cast<volatile uint32_t *>(kGlobalFrameCounter);
    event.pulse = g_currentPulse.load(std::memory_order_relaxed);
    event.wallDeltaMs = g_currentWallDeltaMs.load(std::memory_order_relaxed);
    event.accumulatorMs = g_accumulatorMs;
    event.timerInputMs = g_currentTimerInputMs.load(std::memory_order_relaxed);
    event.timerClampMs = g_currentTimerClampMs.load(std::memory_order_relaxed);
    event.timerClampRemainderMs = g_currentTimerClampRemainderMs.load(std::memory_order_relaxed);
    event.frameDeltaSeconds = *reinterpret_cast<volatile float *>(kGlobalFrameDelta);
    event.timeMultiplier = *reinterpret_cast<volatile float *>(kGlobalTimeMultiplier);
    event.havokMaxTime = *reinterpret_cast<volatile float *>(kHavokMaxTime);
    event.havokPhysicsDelta = *reinterpret_cast<volatile float *>(kHavokPhysicsDelta);
    event.havokRemainder = *reinterpret_cast<volatile float *>(kHavokRemainder);
    event.havokSubsteps = *reinterpret_cast<volatile uint32_t *>(kHavokSubstepCount);
    event.state = (g_authoritativeStateTelemetryEnabled || g_eventDispatchTelemetryEnabled ||
                   g_sceneTransformTelemetryEnabled)
        ? CaptureStateSnapshot() : StateSnapshot{};
    event.sequence.store(write + 1, std::memory_order_release);
    if (probeId == 401) BeginPresentObservation();
    if (probeId == 503) BeginState2PassObservation();
    if (probeId == 201) EndState2PassObservation();
}

void __cdecl PublishWorkerEffectCallbackTarget(uint32_t objectPtr) {
    // Marker 1872 runs after FUN_00BEAB90 returned its callback object in EAX,
    // but before MOV EDX,[EAX] / CALL [EDX+2C]. Publish the resolved virtual
    // target as a compact synthetic marker so no CSV schema change is needed.
    // Fallout 3 code addresses fit below 0x02000000; that bit distinguishes
    // target tags from ordinary probe IDs. A zero payload records a bad read.
    uint32_t target = 0;
    __try {
        if (objectPtr >= 0x10000) {
            const uint32_t vtable = ReadEngineValue<uint32_t>(objectPtr);
            if (vtable >= 0x10000) {
                target = ReadEngineValue<uint32_t>(vtable + 0x2C);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        target = 0;
    }
    PublishProbe(0x02000000u | (target & 0x01FFFFFFu));
}

// HUDMainMenu's timer (this+0x1F4) is updated a second time in the same frame
// by FUN_006446A0 (call at 0064476A) whenever the HUD has a target reference
// to show, for example the crosshair resting on a damaged enemy. Almost no
// time has passed since the first update, so the stock routine takes its
// "elapsed is zero" path and sleeps about 9 ms on every such frame. Here the
// second update is skipped when less than 2 ms have passed, leaving the delta
// from the frame's first update in place.
volatile LONG g_hudTargetTimerSkips = 0;
void __fastcall UpdateHUDTargetTimerNoSleep(uint8_t *timer, void *, uint32_t now) {
    using HUDTimerUpdateFn = void(__thiscall *)(void *, uint32_t);
    const auto stock = reinterpret_cast<HUDTimerUpdateFn>(kHUDMainMenuTimerUpdate);
    bool skip = false;
    if (g_hudTimerNoSleepEnabled && CaptureGateIsActive() && timer != nullptr) {
        __try {
            const uint8_t pauseDepth = ReadEngineValue<uint8_t>(
                reinterpret_cast<uintptr_t>(timer));
            const float fixedStepMs = ReadEngineValue<float>(
                reinterpret_cast<uintptr_t>(timer) + 0x04);
            const uint32_t epoch = ReadEngineValue<uint32_t>(
                reinterpret_cast<uintptr_t>(timer) + 0x14);
            const uint32_t previous = ReadEngineValue<uint32_t>(
                reinterpret_cast<uintptr_t>(timer) + 0x10);
            skip = pauseDepth == 0 && fixedStepMs == 0.0f &&
                (now - epoch) - previous < 2;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            skip = false;
        }
    }
    if (skip) {
        InterlockedIncrement(&g_hudTargetTimerSkips);
        return;
    }
    stock(timer, now);
}

void __fastcall UpdateHUDMainMenuTimerNoSleep(
    uint8_t *timer, void *, uint32_t now) {
    using HUDTimerUpdateFn = void(__thiscall *)(void *, uint32_t);
    const auto stock = reinterpret_cast<HUDTimerUpdateFn>(kHUDMainMenuTimerUpdate);
    if (!g_hudTimerNoSleepEnabled || !CaptureGateIsActive() || timer == nullptr) {
        stock(timer, now);
        return;
    }

    bool useStock = false;
    __try {
        const uint8_t pauseDepth = ReadEngineValue<uint8_t>(
            reinterpret_cast<uintptr_t>(timer));
        const float fixedStepMs = ReadEngineValue<float>(
            reinterpret_cast<uintptr_t>(timer) + 0x04);
        if (pauseDepth != 0 || fixedStepMs != 0.0f) {
            useStock = true;
        } else {
            const uint32_t epoch = ReadEngineValue<uint32_t>(
                reinterpret_cast<uintptr_t>(timer) + 0x14);
            const uint32_t current = now - epoch;
            const uint32_t previous = ReadEngineValue<uint32_t>(
                reinterpret_cast<uintptr_t>(timer) + 0x10);
            uint32_t elapsed = current - previous;
            if (elapsed == 0) elapsed = 1;
            if (elapsed > 166) elapsed = 166;

            *reinterpret_cast<volatile uint8_t *>(timer + 0x19) = 0;
            *reinterpret_cast<volatile uint32_t *>(timer + 0x10) = current;
            *reinterpret_cast<volatile float *>(timer + 0x0C) =
                static_cast<float>(elapsed) * 0.001f *
                ReadEngineValue<float>(kGlobalTimeMultiplier);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        useStock = true;
    }

    if (useStock) {
        stock(timer, now);
        return;
    }
    PublishProbe(1882);
}

void ResetRenderCameraPositionInterpolation() {
    g_previousFixedCameraPosition = {};
    g_currentFixedCameraPosition = {};
    g_renderCameraPositionEligibleFrames = 0;
}

void __fastcall RenderCameraPositionInterpolationHook(
    void *renderContext, void *, uint32_t arg0, uint32_t arg1,
    uint32_t arg2, uint32_t arg3) {
    using SceneDrawFn = void(__thiscall *)(
        void *, uint32_t, uint32_t, uint32_t, uint32_t);
    const auto stock = reinterpret_cast<SceneDrawFn>(kSceneDraw);

    uintptr_t camera = 0;
    uintptr_t root = 0;
    uintptr_t sceneGraph = 0;
    uintptr_t cell = 0;
    std::array<float, 3> originalPosition{};
    bool apply = false;

    if (g_renderCameraPositionInterpolationEnabled &&
        !g_renderCameraPositionInterpolationFaulted &&
        g_quantizedDeltaEnabled && CaptureGateIsActive()) {
        __try {
            const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
            cell = player >= 0x10000
                ? ReadEngineValue<uintptr_t>(player + 0x3C) : 0;
            const bool firstPerson = player >= 0x10000 &&
                ReadEngineValue<uint8_t>(player + 0x5A8) == 0 &&
                ReadEngineValue<uint8_t>(player + 0x5A9) == 0;
            const uintptr_t renderer = ReadEngineValue<uintptr_t>(kRendererSingleton);
            sceneGraph = ReadEngineValue<uintptr_t>(kSceneGraphSingleton);
            const uintptr_t children = sceneGraph >= 0x10000
                ? ReadEngineValue<uintptr_t>(sceneGraph + 0xA0) : 0;
            root = children >= 0x10000
                ? ReadEngineValue<uintptr_t>(children) : 0;
            camera = sceneGraph >= 0x10000
                ? ReadEngineValue<uintptr_t>(sceneGraph + 0xAC) : 0;
            const uintptr_t cameraParent = camera >= 0x10000
                ? ReadEngineValue<uintptr_t>(camera + 0x18) : 0;
            const bool eligible = firstPerson && cell >= 0x10000 &&
                renderer >= 0x10000 && sceneGraph >= 0x10000 &&
                root >= 0x10000 && camera >= 0x10000 &&
                cameraParent == root &&
                ReadEngineValue<uint32_t>(renderer + 0x200) == 2 &&
                ReadEngineValue<uint8_t>(renderer + 0x208) != 0 &&
                ReadEngineValue<uintptr_t>(renderer + 0x888) >= 0x10000;

            if (!eligible) {
                ResetRenderCameraPositionInterpolation();
            } else {
                for (size_t axis = 0; axis < originalPosition.size(); ++axis) {
                    originalPosition[axis] =
                        ReadEngineValue<float>(camera + 0x8C + axis * sizeof(float));
                }

                const bool identityChanged =
                    (g_currentFixedCameraPosition.valid &&
                     (g_currentFixedCameraPosition.camera != camera ||
                      g_currentFixedCameraPosition.root != root ||
                      g_currentFixedCameraPosition.cell != cell));
                if (identityChanged) ResetRenderCameraPositionInterpolation();
                ++g_renderCameraPositionEligibleFrames;

                CameraPositionSample observed{};
                observed.position = originalPosition;
                observed.camera = camera;
                observed.root = root;
                observed.cell = cell;
                observed.valid = true;

                const uint32_t pulse =
                    g_currentPulse.load(std::memory_order_relaxed);
                if (pulse != 0) {
                    if (g_currentFixedCameraPosition.valid) {
                        g_previousFixedCameraPosition =
                            g_currentFixedCameraPosition;
                    }
                    g_currentFixedCameraPosition = observed;
                }

                if (g_previousFixedCameraPosition.valid &&
                    g_currentFixedCameraPosition.valid &&
                    g_renderCameraPositionEligibleFrames > 240) {
                    float fixedDistanceSquared = 0.0f;
                    for (size_t axis = 0; axis < originalPosition.size(); ++axis) {
                        const float delta =
                            g_currentFixedCameraPosition.position[axis] -
                            g_previousFixedCameraPosition.position[axis];
                        fixedDistanceSquared += delta * delta;
                    }

                    // Teleports, camera-mode transitions, and discontinuous
                    // animation changes fail closed instead of being smeared.
                    if (std::isfinite(fixedDistanceSquared) &&
                        fixedDistanceSquared <= 100.0f) {
                        double alpha = g_accumulatorMs / g_simulationStepMs;
                        if (alpha < 0.0) alpha = 0.0;
                        if (alpha > 1.0) alpha = 1.0;
                        std::array<float, 3> predicted = originalPosition;
                        float correctionSquared = 0.0f;
                        bool predictedFinite = true;
                        for (size_t axis = 0; axis < predicted.size(); ++axis) {
                            const double interpolated =
                                static_cast<double>(g_previousFixedCameraPosition.position[axis]) +
                                (static_cast<double>(g_currentFixedCameraPosition.position[axis]) -
                                 static_cast<double>(g_previousFixedCameraPosition.position[axis])) *
                                    alpha;
                            const float correction = static_cast<float>(
                                interpolated -
                                static_cast<double>(g_currentFixedCameraPosition.position[axis]));
                            predicted[axis] += correction;
                            correctionSquared += correction * correction;
                            if (!std::isfinite(predicted[axis])) predictedFinite = false;
                        }
                        apply = predictedFinite && std::isfinite(correctionSquared) &&
                            correctionSquared <= 100.0f;
                        if (apply) {
                            std::memcpy(reinterpret_cast<void *>(camera + 0x8C),
                                        predicted.data(), sizeof(predicted));
                        }
                    } else {
                        g_previousFixedCameraPosition =
                            g_currentFixedCameraPosition;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ResetRenderCameraPositionInterpolation();
            apply = false;
        }
    } else if (!CaptureGateIsActive()) {
        ResetRenderCameraPositionInterpolation();
    }

    if (!apply) {
        stock(renderContext, arg0, arg1, arg2, arg3);
        return;
    }

    // Marker 705 contains the stock camera, 2030 the temporary render view,
    // 2031 the state immediately after the stock draw, and 2032 the restored
    // engine state. Marker 706 follows after this hook returns.
    PublishProbe(2030);
    stock(renderContext, arg0, arg1, arg2, arg3);
    PublishProbe(2031);

    bool restored = false;
    __try {
        std::memcpy(reinterpret_cast<void *>(camera + 0x8C),
                    originalPosition.data(), sizeof(originalPosition));
        const uintptr_t currentSceneGraph =
            ReadEngineValue<uintptr_t>(kSceneGraphSingleton);
        const uintptr_t currentCamera = currentSceneGraph == sceneGraph
            ? ReadEngineValue<uintptr_t>(currentSceneGraph + 0xAC) : 0;
        const uintptr_t currentParent = currentCamera == camera
            ? ReadEngineValue<uintptr_t>(currentCamera + 0x18) : 0;
        restored = currentCamera == camera && currentParent == root &&
            std::memcmp(reinterpret_cast<const void *>(camera + 0x8C),
                        originalPosition.data(), sizeof(originalPosition)) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        restored = false;
    }

    if (restored) {
        PublishProbe(2032);
    } else {
        g_renderCameraPositionInterpolationFaulted = true;
        PublishProbe(2033);
    }
}

// --- Actor pose interpolation ---------------------------------------------------
// Every node below the 3D root of each actor in the process manager's high
// list (ProcessManager 0107C0A0: object array data at +0x08, high-process
// range [+0x14, +0x24)) gets a from/to history of its complete world
// transform (NiAVObject +0x68: 3x3 rotation, translation, scale; 52 bytes).
// World transforms only change on tick frames, so the history advances on the
// scene draw of each tick frame. For the draw, every node is given
// blend(from, to, accumulator / tick) and afterwards its exact bytes are put
// back. Local transforms, bounds and the references are not touched.
constexpr size_t kPoseFloats = 13;
constexpr uintptr_t kNodeWorldTransform = 0x68;
constexpr uintptr_t kNodeLocalTransform = 0x34;
struct NodePose {
    std::array<float, kPoseFloats> value;
};
struct NodePoseHistory {
    uintptr_t node = 0;
    uint32_t lastSeen = 0;
    // Which tick period the from/to pair belongs to, and how many draws
    // after the tick draw the change arrived. Measured: 1 on frozen frames
    // (ordinary play), 2 in menu mode and in the unfrozen frames after it,
    // sometimes 0.
    uint32_t changePeriod = 0;
    uint8_t lagDraws = 1;
    uint8_t changesInPeriod = 0;    // large changes seen in changePeriod
    uint32_t perFrameUntil = 0;     // tick period up to which it is shown as is
    NodePose from{};
    NodePose to{};
    NodePose periodFrom{};          // `to` as it was before changePeriod began
};
// Diagnostic rows for two open cases: the first-person skeleton while a
// weapon is being reloaded ('R'), and the actor pass around menu mode, which
// includes conversations ('M'). One row per draw; the integer and float
// columns are named where the rows are printed.
struct TimingTraceRow {
    char tag = 0;
    uint32_t serial = 0;
    uint8_t kind = 0;       // 0 tick, 1 after a tick, 2 both, 3 neither
    int32_t state = 0;      // weapon action, or the menu-mode byte
    uint16_t counts[8] = {};
    float values[4] = {};
};
std::array<TimingTraceRow, 8192> g_timingTrace{};
std::atomic<uint32_t> g_timingTraceWrite{0};
uint32_t g_timingTraceRead = 0;

void PushTimingTraceRow(const TimingTraceRow &row) {
    const uint32_t write = g_timingTraceWrite.load(std::memory_order_relaxed);
    g_timingTrace[write % g_timingTrace.size()] = row;
    g_timingTraceWrite.store(write + 1, std::memory_order_release);
}

// Per-draw tallies of the actor and object pass.
uint16_t g_actorTraceCounts[8] = {};
float g_actorTraceLargestAsIs = 0.0f;
uint32_t g_actorTraceHot = 0;
uint8_t g_actorTraceLastMenu = 0;

// Set by ApplyActorTranslations for the draw in progress.
bool g_poseFrameIsTick = false;
double g_poseFrameAlpha = 0.0;
uint32_t g_poseTickCount = 1;
uint32_t g_poseTicksBefore = 1;
// Draws since the last tick draw (0 on a tick draw), and the alpha and tick
// period of the last eight draws, indexed by draw serial.
uint32_t g_poseDrawsSinceTick = 0;
double g_poseAlphaRing[8] = {};
uint32_t g_posePeriodRing[8] = {};
constexpr uint32_t kMaxLagDraws = 3;
volatile LONG g_actorStatTickDrawBlends = 0;
struct SavedNodePose {
    uintptr_t node;
    NodePose pose;      // the engine's bytes
    NodePose written;   // what was put there for the draw
};
constexpr size_t kPoseTableSize = 65536;    // power of two
std::array<NodePoseHistory, kPoseTableSize> g_poseTable{};
size_t g_poseTableUsed = 0;
uint32_t g_poseDrawSerial = 1;
int g_poseDrawFrozen = 0;
// Actor poses computed on a tick frame are first seen by the scene draw of the
// following frame, so the history advances, and the blend phase runs, one
// draw behind the tick decision.
bool g_posePreviousDrawWasTick = false;
double g_posePreviousDrawAlpha = 0.0;
std::array<SavedNodePose, 16384> g_actorSavedNodes{};
size_t g_actorSavedNodeCount = 0;

void ResetActorTranslationInterpolation() {
    if (g_poseTableUsed == 0) return;
    for (NodePoseHistory &entry : g_poseTable) entry.node = 0;
    g_poseTableUsed = 0;
}

NodePoseHistory *FindPoseHistory(uintptr_t node) {
    size_t slot = (node >> 4) & (kPoseTableSize - 1);
    for (size_t probe = 0; probe < 64; ++probe) {
        NodePoseHistory &entry = g_poseTable[slot];
        if (entry.node == node) return &entry;
        if (entry.node == 0) {
            entry.node = node;
            entry.lastSeen = 0;
            ++g_poseTableUsed;
            return &entry;
        }
        slot = (slot + 1) & (kPoseTableSize - 1);
    }
    return nullptr;
}

// NiObject vtable slot 3 (IsNiNode) is `mov eax, ecx; ret` for nodes and
// `xor eax, eax; ret` for everything else. Reading the body avoids calling it.
bool IsSceneNode(uintptr_t object) {
    const uintptr_t vtable = ReadEngineValue<uintptr_t>(object);
    if (vtable < kImageBase || vtable >= kImageBase + 0x01000000) return false;
    const uintptr_t isNode = ReadEngineValue<uintptr_t>(vtable + 0x0C);
    if (isNode < kImageBase || isNode >= kImageBase + 0x01000000) return false;
    const auto *code = reinterpret_cast<const uint8_t *>(isNode);
    return code[0] == 0x8B && code[1] == 0xC1 && code[2] == 0xC3;
}

void MatrixToQuaternion(const float *m, double q[4]) {
    const double trace = static_cast<double>(m[0]) + m[4] + m[8];
    if (trace > 0.0) {
        const double s = std::sqrt(trace + 1.0) * 2.0;
        q[0] = 0.25 * s;
        q[1] = (m[7] - m[5]) / s;
        q[2] = (m[2] - m[6]) / s;
        q[3] = (m[3] - m[1]) / s;
    } else if (m[0] > m[4] && m[0] > m[8]) {
        const double s = std::sqrt(1.0 + m[0] - m[4] - m[8]) * 2.0;
        q[0] = (m[7] - m[5]) / s;
        q[1] = 0.25 * s;
        q[2] = (m[1] + m[3]) / s;
        q[3] = (m[2] + m[6]) / s;
    } else if (m[4] > m[8]) {
        const double s = std::sqrt(1.0 + m[4] - m[0] - m[8]) * 2.0;
        q[0] = (m[2] - m[6]) / s;
        q[1] = (m[1] + m[3]) / s;
        q[2] = 0.25 * s;
        q[3] = (m[5] + m[7]) / s;
    } else {
        const double s = std::sqrt(1.0 + m[8] - m[0] - m[4]) * 2.0;
        q[0] = (m[3] - m[1]) / s;
        q[1] = (m[2] + m[6]) / s;
        q[2] = (m[5] + m[7]) / s;
        q[3] = 0.25 * s;
    }
}

void QuaternionToMatrix(const double q[4], float *m) {
    const double w = q[0], x = q[1], y = q[2], z = q[3];
    m[0] = static_cast<float>(1.0 - 2.0 * (y * y + z * z));
    m[1] = static_cast<float>(2.0 * (x * y - z * w));
    m[2] = static_cast<float>(2.0 * (x * z + y * w));
    m[3] = static_cast<float>(2.0 * (x * y + z * w));
    m[4] = static_cast<float>(1.0 - 2.0 * (x * x + z * z));
    m[5] = static_cast<float>(2.0 * (y * z - x * w));
    m[6] = static_cast<float>(2.0 * (x * z - y * w));
    m[7] = static_cast<float>(2.0 * (y * z + x * w));
    m[8] = static_cast<float>(1.0 - 2.0 * (x * x + y * y));
}

// Returns false when the result is not usable (non-finite or degenerate).
bool BlendPose(const NodePose &from, const NodePose &to, double alpha, NodePose &out) {
    out = to;
    if (std::memcmp(from.value.data(), to.value.data(), 9 * sizeof(float)) != 0) {
        double a[4], b[4];
        MatrixToQuaternion(from.value.data(), a);
        MatrixToQuaternion(to.value.data(), b);
        double dot = a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3];
        const double sign = dot < 0.0 ? -1.0 : 1.0;
        double q[4];
        double length = 0.0;
        for (size_t index = 0; index < 4; ++index) {
            q[index] = a[index] + (sign * b[index] - a[index]) * alpha;
            length += q[index] * q[index];
        }
        if (!std::isfinite(length) || length < 1e-12) return false;
        length = std::sqrt(length);
        for (double &component : q) component /= length;
        QuaternionToMatrix(q, out.value.data());
    }
    for (size_t index = 9; index < kPoseFloats; ++index) {
        out.value[index] = static_cast<float>(
            static_cast<double>(from.value[index]) +
            (static_cast<double>(to.value[index]) - from.value[index]) * alpha);
    }
    for (const float component : out.value) {
        if (!std::isfinite(component)) return false;
    }
    return true;
}

void InterpolateSubtree(uintptr_t object, bool tick, bool interpolate, double alpha,
                        uint32_t depth) {
    if (object < 0x10000 || depth > 48) return;
    NodePose current{};
    std::memcpy(current.value.data(),
                reinterpret_cast<const void *>(object + kNodeWorldTransform),
                sizeof(current.value));
    NodePoseHistory *history = FindPoseHistory(object);
    if (history != nullptr && history->lastSeen == g_poseDrawSerial) {
        // Reached a second time in the same draw (shared between parents or
        // actors). It has already been handled; its current bytes are the
        // blended pose, not the engine's.
        InterlockedIncrement(&g_actorStatDuplicates);
        return;
    }
    if (history != nullptr) {
        const bool continuous = history->lastSeen + 1 == g_poseDrawSerial;
        if (!continuous) {
            history->from = current;
            history->to = current;
            history->periodFrom = current;
            history->changePeriod = 0;
            history->changesInPeriod = 0;
        } else if (std::memcmp(history->to.value.data(), current.value.data(),
                               sizeof(current.value)) != 0) {
            if (g_actorTraceCounts[0] != 0xFFFF) ++g_actorTraceCounts[0];
            float rotationStep = 0.0f;
            float translationStep = 0.0f;
            for (size_t component = 0; component < kPoseFloats; ++component) {
                const float difference = std::fabs(
                    current.value[component] - history->to.value[component]);
                float &largest = (component >= 9 && component < 12)
                    ? translationStep : rotationStep;
                if (!(difference <= largest)) largest = difference;
            }
            const float largest =
                rotationStep > translationStep ? rotationStep : translationStep;
            // How many draws back the tick draw is that this pose belongs
            // to. A pose seen on the draw after a tick draw belongs to that
            // tick even when this draw is a tick draw too (frame rates near
            // the tick rate), as it always has here.
            const uint32_t lagDraws = tick ? 1 : g_poseDrawsSinceTick;
            const bool nearTick = lagDraws <= kMaxLagDraws;
            const uint32_t posePeriod = nearTick
                ? g_posePeriodRing[(g_poseDrawSerial - lagDraws) & 7] : 0;
            const bool newPeriod = history->changePeriod != posePeriod;
            const bool perFrame = history->perFrameUntil > g_poseTickCount;
            // After a pose has been taken for this tick, later small changes
            // (seen on unfrozen frames, under 0.06) are let through: the
            // blend carries on and the next tick's pose includes them.
            const bool minor = !newPeriod && rotationStep <= 0.02f &&
                translationStep <= 0.2f;
            if (minor) {
                if (g_actorTraceCounts[6] != 0xFFFF) ++g_actorTraceCounts[6];
            } else if (nearTick && !perFrame) {
                // This tick's pose: the first change within three draws of
                // the tick draw, or a later one replacing it (a node written
                // twice per tick ends on its second value).
                if (newPeriod) {
                    history->periodFrom = history->to;
                    history->changesInPeriod = 0;
                }
                if (history->changesInPeriod != 0xFF) ++history->changesInPeriod;
                history->from = history->periodFrom;
                history->to = current;
                history->changePeriod = posePeriod;
                history->lagDraws = static_cast<uint8_t>(lagDraws);
                if (history->changesInPeriod >= 3) {
                    // Three large changes in one tick: driven every frame.
                    history->perFrameUntil = g_poseTickCount + 30;
                    history->from = current;
                    history->changePeriod = 0;
                }
                uint16_t &tally = g_actorTraceCounts[lagDraws == 0 ? 2 : 1];
                if (tally != 0xFFFF) ++tally;
                if (lagDraws != 1) {
                    InterlockedIncrement(&g_actorStatTickDrawBlends);
                }
            } else {
                // Moved away from a tick, or driven every frame: as it is.
                const int magnitude = largest < 0.0001f ? 0 : (largest < 0.05f ? 1 : 2);
                InterlockedIncrement(&g_actorStatOffTickClass[magnitude][g_poseDrawFrozen]);
                const LONG milli = largest < 1000000.0f
                    ? static_cast<LONG>(largest * 1000.0f) : 1000000000;
                if (milli > InterlockedCompareExchange(&g_actorStatOffTickMaxMilli, 0, 0)) {
                    InterlockedExchange(&g_actorStatOffTickMaxMilli, milli);
                }
                history->from = current;
                history->to = current;
                history->changePeriod = 0;
                if (g_actorTraceCounts[3] != 0xFFFF) ++g_actorTraceCounts[3];
                if (largest > g_actorTraceLargestAsIs) g_actorTraceLargestAsIs = largest;
                InterlockedIncrement(&g_actorStatOffTickChanges);
            }
        }
        history->lastSeen = g_poseDrawSerial;
        if (!tick) InterlockedIncrement(&g_actorStatNodeDraws[g_poseDrawFrozen]);

        float stepSquared = 0.0f;
        for (size_t axis = 9; axis < 12; ++axis) {
            const float delta = history->to.value[axis] - history->from.value[axis];
            stepSquared += delta * delta;
        }
        if (!(stepSquared <= 900.0f)) {
            // More than 30 units in one tick (teleport, fast fall): no blend.
            history->from = history->to;
            history->changePeriod = 0;
            InterlockedIncrement(&g_actorStatSnaps);
        }

        // The pair is shown with the alpha of the draw `lagDraws` back, for
        // as long as that draw belongs to the pair's tick period: from the
        // draw the pose arrived on until the next one arrives.
        const uint32_t laggedDraw = (g_poseDrawSerial - history->lagDraws) & 7;
        const bool active = history->changePeriod != 0 &&
            history->changePeriod == g_posePeriodRing[laggedDraw];
        NodePose shown{};
        bool write = false;
        if (interpolate && active &&
            std::memcmp(history->from.value.data(), history->to.value.data(),
                        sizeof(current.value)) != 0) {
            write = BlendPose(history->from, history->to, g_poseAlphaRing[laggedDraw],
                              shown);
            uint16_t &tally = g_actorTraceCounts[history->lagDraws != 0 ? 4 : 5];
            if (tally != 0xFFFF) ++tally;
        } else if (interpolate && g_debugActorOffsetZ != 0.0f) {
            shown = current;
            write = true;
        }
        if (write) {
            shown.value[11] += g_debugActorOffsetZ;
            if (g_actorSavedNodeCount >= g_actorSavedNodes.size()) {
                InterlockedIncrement(&g_actorStatOverflow);
            } else {
                SavedNodePose &saved = g_actorSavedNodes[g_actorSavedNodeCount++];
                saved.node = object;
                saved.pose = current;
                saved.written = shown;
                std::memcpy(reinterpret_cast<void *>(object + kNodeWorldTransform),
                            shown.value.data(), sizeof(shown.value));
            }
        }
    }
    if (!IsSceneNode(object)) return;
    const uintptr_t children = ReadEngineValue<uintptr_t>(object + 0xA0);
    const uint32_t count = ReadEngineValue<uint16_t>(object + 0xA6);
    if (children < 0x10000 || count > 1024) return;
    for (uint32_t index = 0; index < count; ++index) {
        InterpolateSubtree(ReadEngineValue<uintptr_t>(children + index * 4), tick,
                           interpolate, alpha, depth + 1);
    }
}

void RestoreActorTranslations() {
    __try {
        // Newest first, so a node saved twice ends with its first-saved bytes.
        for (size_t index = g_actorSavedNodeCount; index-- > 0;) {
            const SavedNodePose &saved = g_actorSavedNodes[index];
            auto *live = reinterpret_cast<void *>(saved.node + kNodeWorldTransform);
            if (std::memcmp(live, saved.written.value.data(),
                            sizeof(saved.written.value)) != 0) {
                // Something else wrote this node during the draw. Its value
                // is newer than the saved one; leave it.
                InterlockedIncrement(&g_actorStatRestoreConflicts);
                continue;
            }
            std::memcpy(live, saved.pose.value.data(), sizeof(saved.pose.value));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_actorTranslationInterpolationFaulted = true;
    }
    g_actorSavedNodeCount = 0;
}

// --- Cell objects ----------------------------------------------------------------
// Objects that are not high-process actors (physics bodies, doors, carried
// and dropped items, projectiles, other actors). This part writes nothing: it
// finds the reference list of the player's cell, and for every reference with
// a 3D root records on which kind of draw the root's world transform changes.
// Measured: the changes arrive on the draw after a tick, as for actors. A
// reference whose root moved stays "active" for 300 draws, and the actor pass
// blends the subtrees of the active ones with the same lagged phase.
//
// The list's offset inside the cell is not taken on trust: every candidate
// offset is read as a singly linked list of {item, next}, and accepted only
// if every item is a reference whose parent cell (+0x3C) is this cell.
struct ObservedObject {
    uintptr_t root = 0;
    uint32_t lastSeen = 0;
    uint32_t refId = 0;
    uint32_t baseId = 0;
    uint8_t baseType = 0;
    NodePose pose{};
    uint32_t changes[4] = {};   // tick, after a tick, both, neither
    uint32_t reported = 0;
    float largestStep = 0.0f;
    uint32_t activeUntil = 0;
};
std::array<ObservedObject, 65536> g_observedObjects{};
std::array<uintptr_t, 2048> g_objectActiveRoots{};
size_t g_objectActiveCount = 0;
volatile LONG g_objectStatActiveMax = 0;
volatile LONG g_objectStatControlled = 0;
volatile LONG g_objectStatSubtrees = 0;
uint32_t g_objectSerial = 1;
uintptr_t g_objectCell = 0;
uint32_t g_objectListOffset = 0;
bool g_objectPreviousDrawWasTick = false;
volatile LONG g_objectStatListOffset = 0;
volatile LONG g_objectStatReferences = 0;
volatile LONG g_objectStatWithRoot = 0;
volatile LONG g_objectStatChanges[4] = {};
volatile LONG g_objectStatMovingMax = 0;
volatile LONG g_objectStatCellScans = 0;

int CountCellListReferences(uintptr_t cell, uint32_t offset) {
    __try {
        uintptr_t node = cell + offset;
        int count = 0;
        for (int guard = 0; guard < 16384 && node >= 0x10000; ++guard) {
            const uintptr_t item = ReadEngineValue<uintptr_t>(node);
            if (item != 0) {
                if (item < 0x10000) return -1;
                if (ReadEngineValue<uintptr_t>(item + 0x3C) != cell) return -1;
                ++count;
            }
            node = ReadEngineValue<uintptr_t>(node + 4);
        }
        return node == 0 ? count : -1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

// --- Loaded exterior cells ----------------------------------------------------
// Outdoors the engine keeps a square grid of cells loaded around the player.
// Nothing about its layout is assumed beyond the class names: the vtables of
// TES, GridCellArray and TESObjectCELL are found through the executable's own
// RTTI records, the TES object by its vtable among the pointers in the
// executable's writable data, the grid among TES's fields, and the cell array
// among the grid's fields. A candidate array is accepted only if every entry
// is null or an object with the cell vtable and the player's cell is in it.
struct ReadableRegion {
    uintptr_t low = 0;
    uintptr_t high = 0;
};
ReadableRegion g_readableRegion{};

bool IsReadableAddress(uintptr_t address, size_t size) {
    if (address < 0x10000 || address + size < address) return false;
    if (address >= g_readableRegion.low && address + size <= g_readableRegion.high) {
        return true;
    }
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void *>(address), &info, sizeof(info)) == 0) {
        return false;
    }
    if (info.State != MEM_COMMIT || info.Protect == 0 ||
        (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
    g_readableRegion.low = reinterpret_cast<uintptr_t>(info.BaseAddress);
    g_readableRegion.high = g_readableRegion.low + info.RegionSize;
    return address + size <= g_readableRegion.high;
}

bool ExecutableImageRange(uintptr_t &base, uintptr_t &end) {
    base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (base == 0) return false;
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS32 *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    end = base + nt->OptionalHeader.SizeOfImage;
    return true;
}

// First match at or after `from`, at addresses that are multiples of
// `alignment`; 0 if none.
uintptr_t ScanExecutableImage(const void *pattern, size_t length, size_t alignment,
                              uintptr_t from) {
    uintptr_t base = 0;
    uintptr_t end = 0;
    if (!ExecutableImageRange(base, end)) return 0;
    uintptr_t address = from > base ? from : base;
    __try {
        while (address + length <= end) {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(reinterpret_cast<const void *>(address), &info,
                             sizeof(info)) == 0) return 0;
            const uintptr_t regionEnd =
                reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
            const bool readable = info.State == MEM_COMMIT && info.Protect != 0 &&
                (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
            if (readable) {
                const uintptr_t limit = regionEnd < end ? regionEnd : end;
                address = (address + alignment - 1) / alignment * alignment;
                for (; address + length <= limit; address += alignment) {
                    if (std::memcmp(reinterpret_cast<const void *>(address), pattern,
                                    length) == 0) return address;
                }
            }
            address = regionEnd;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return 0;
}

// `decoratedName` as the compiler stores it, for example ".?AVTES@@".
uintptr_t FindVtableByTypeName(const char *decoratedName) {
    const uintptr_t nameAddress =
        ScanExecutableImage(decoratedName, std::strlen(decoratedName) + 1, 1, 0);
    if (nameAddress == 0) return 0;
    const uint32_t typeDescriptor = static_cast<uint32_t>(nameAddress - 8);
    __try {
        for (uintptr_t reference = ScanExecutableImage(&typeDescriptor, 4, 4, 0);
             reference != 0;
             reference = ScanExecutableImage(&typeDescriptor, 4, 4, reference + 4)) {
            // Complete object locator: signature, offset, constructor
            // displacement offset, type descriptor. All three are 0 for the
            // primary vtable of a class.
            const uintptr_t locator = reference - 12;
            if (ReadEngineValue<uint32_t>(locator) != 0 ||
                ReadEngineValue<uint32_t>(locator + 4) != 0 ||
                ReadEngineValue<uint32_t>(locator + 8) != 0) continue;
            const uint32_t locatorValue = static_cast<uint32_t>(locator);
            const uintptr_t slot = ScanExecutableImage(&locatorValue, 4, 4, 0);
            if (slot != 0) return slot + 4;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return 0;
}

// A pointer stored in the executable's writable data to an object whose first
// word is `vtable`; 0 if none.
uintptr_t FindObjectByVtable(uintptr_t vtable) {
    uintptr_t base = 0;
    uintptr_t end = 0;
    if (!ExecutableImageRange(base, end)) return 0;
    __try {
        uintptr_t address = base;
        while (address + 4 <= end) {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(reinterpret_cast<const void *>(address), &info,
                             sizeof(info)) == 0) return 0;
            const uintptr_t regionEnd =
                reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
            const DWORD protect = info.Protect & 0xFF;
            const bool writable = info.State == MEM_COMMIT &&
                (protect == PAGE_READWRITE || protect == PAGE_WRITECOPY ||
                 protect == PAGE_EXECUTE_READWRITE ||
                 protect == PAGE_EXECUTE_WRITECOPY) &&
                (info.Protect & PAGE_GUARD) == 0;
            if (writable) {
                const uintptr_t limit = regionEnd < end ? regionEnd : end;
                address = (address + 3) & ~static_cast<uintptr_t>(3);
                for (; address + 4 <= limit; address += 4) {
                    const uintptr_t value = *reinterpret_cast<const uintptr_t *>(address);
                    if (value < 0x10000 || (value & 3) != 0) continue;
                    if (!IsReadableAddress(value, 4)) continue;
                    if (*reinterpret_cast<const uintptr_t *>(value) == vtable) return value;
                }
            }
            address = regionEnd;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return 0;
}

struct WorldGrid {
    bool lookedUp = false;      // the one-time class lookup was done
    bool scanned = false;       // the one-time scan for the TES object was done
    uintptr_t tesVtable = 0;
    uintptr_t gridVtable = 0;
    uintptr_t cellVtable = 0;
    uintptr_t tes = 0;
    uintptr_t grid = 0;
    uint32_t arrayOffset = 0;   // within the grid object
    uint32_t stride = 0;        // bytes per entry
    uint32_t cellOffset = 0;    // of the cell pointer within an entry
    uint32_t count = 0;         // entries
    bool valid = false;
    uint32_t retryAt = 0;       // object serial of the next layout attempt
};
WorldGrid g_worldGrid{};
volatile LONG g_gridStatState = 0;      // 0 not tried, 1 no classes, 2 no TES,
                                        // 3 no grid, 4 no array yet, 5 found,
                                        // 6 player cell has another vtable,
                                        // 7 the lookup faulted
volatile LONG g_gridStatCount = 0;
volatile LONG g_gridStatStride = 0;
volatile LONG g_gridStatArrayOffset = 0;
volatile LONG g_gridStatCells = 0;
volatile LONG g_gridStatInvalidations = 0;
// What the lookup saw, for the status line: the three vtables, the stored TES
// pointer, its first word, and whether that address was readable.
volatile LONG g_gridDiagnostics[6] = {};

bool GridArrayHolds(uintptr_t array, uint32_t stride, uint32_t cellOffset,
                    uint32_t count, uintptr_t cellVtable, uintptr_t playerCell) {
    bool found = false;
    for (uint32_t index = 0; index < count; ++index) {
        const uintptr_t slot = array + index * stride + cellOffset;
        if (!IsReadableAddress(slot, 4)) return false;
        const uintptr_t cell = *reinterpret_cast<const uintptr_t *>(slot);
        if (cell == 0) continue;
        if (!IsReadableAddress(cell, 4) ||
            *reinterpret_cast<const uintptr_t *>(cell) != cellVtable) return false;
        if (cell == playerCell) found = true;
    }
    return found;
}

void DiscoverWorldGrid(uintptr_t playerCell) {
    WorldGrid &world = g_worldGrid;
    g_readableRegion = {};
    __try {
        if (!world.lookedUp) {
            world.lookedUp = true;
            world.tesVtable = FindVtableByTypeName(".?AVTES@@");
            world.gridVtable = FindVtableByTypeName(".?AVGridCellArray@@");
            world.cellVtable = FindVtableByTypeName(".?AVTESObjectCELL@@");
            if (world.tesVtable == 0 || world.gridVtable == 0 || world.cellVtable == 0) {
                InterlockedExchange(&g_gridStatState, 1);
                return;
            }
        }
        if (world.tesVtable == 0 || world.gridVtable == 0 || world.cellVtable == 0) return;
        if (world.tes == 0) {
            // The pointer stored at 006EB28C after the constructor 00438510;
            // accepted only if it carries the TES vtable.
            constexpr uintptr_t kTESObjectPointer = 0x0107A0D8;
            const uintptr_t stored = ReadEngineValue<uintptr_t>(kTESObjectPointer);
            const bool storedReadable = IsReadableAddress(stored, 4);
            InterlockedExchange(&g_gridDiagnostics[0], static_cast<LONG>(world.tesVtable));
            InterlockedExchange(&g_gridDiagnostics[1], static_cast<LONG>(world.gridVtable));
            InterlockedExchange(&g_gridDiagnostics[2], static_cast<LONG>(world.cellVtable));
            InterlockedExchange(&g_gridDiagnostics[3], static_cast<LONG>(stored));
            InterlockedExchange(&g_gridDiagnostics[4], storedReadable
                ? static_cast<LONG>(ReadEngineValue<uintptr_t>(stored)) : 0);
            InterlockedExchange(&g_gridDiagnostics[5], storedReadable ? 1 : 0);
            // Measured: the object behind this pointer does not start with
            // the TES vtable (its first word read as 0). It is therefore
            // taken as it is, and what proves it right is the next step:
            // one of its fields must point at a GridCellArray.
            if (storedReadable && IsReadableAddress(stored, 0x104)) {
                world.tes = stored;
            } else if (!world.scanned) {
                world.scanned = true;
                world.tes = FindObjectByVtable(world.tesVtable);
            }
            if (world.tes == 0) {
                InterlockedExchange(&g_gridStatState, 2);
                return;
            }
        }
        if (ReadEngineValue<uintptr_t>(playerCell) != world.cellVtable) {
            InterlockedExchange(&g_gridStatState, 6);
            InterlockedExchange(&g_gridDiagnostics[4],
                                static_cast<LONG>(ReadEngineValue<uintptr_t>(playerCell)));
            return;
        }
        world.grid = 0;
        for (uint32_t offset = 4; offset <= 0x100 && world.grid == 0; offset += 4) {
            const uintptr_t candidate = ReadEngineValue<uintptr_t>(world.tes + offset);
            if (IsReadableAddress(candidate, 4) &&
                ReadEngineValue<uintptr_t>(candidate) == world.gridVtable) {
                world.grid = candidate;
            }
        }
        if (world.grid == 0) {
            InterlockedExchange(&g_gridStatState, 3);
            world.tes = 0;      // look the object up again on the next attempt
            return;
        }
        static const uint32_t kCounts[] = {121, 81, 49, 25, 9};
        static const uint32_t kLayouts[][2] = {{4, 0}, {8, 0}, {8, 4}};
        for (uint32_t offset = 4; offset <= 0x40; offset += 4) {
            const uintptr_t array = ReadEngineValue<uintptr_t>(world.grid + offset);
            if (!IsReadableAddress(array, 4)) continue;
            for (const auto &layout : kLayouts) {
                for (const uint32_t count : kCounts) {
                    if (!GridArrayHolds(array, layout[0], layout[1], count,
                                        world.cellVtable, playerCell)) continue;
                    world.arrayOffset = offset;
                    world.stride = layout[0];
                    world.cellOffset = layout[1];
                    world.count = count;
                    world.valid = true;
                    InterlockedExchange(&g_gridStatState, 5);
                    InterlockedExchange(&g_gridStatCount, static_cast<LONG>(count));
                    InterlockedExchange(&g_gridStatStride, static_cast<LONG>(layout[0]));
                    InterlockedExchange(&g_gridStatArrayOffset, static_cast<LONG>(offset));
                    return;
                }
            }
        }
        // Normal indoors: the player's cell is not part of the grid.
        InterlockedExchange(&g_gridStatState, 4);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        world.valid = false;
        InterlockedExchange(&g_gridStatState, 7);
    }
}

// Fills `cells` with the player's cell first and, when it is part of the
// loaded grid, the grid's other cells. Returns how many.
size_t CollectLoadedCells(uintptr_t playerCell, uintptr_t *cells, size_t capacity) {
    size_t count = 0;
    cells[count++] = playerCell;
    WorldGrid &world = g_worldGrid;
    if (!world.valid) {
        if (g_objectSerial >= world.retryAt) {
            world.retryAt = g_objectSerial + 600;
            DiscoverWorldGrid(playerCell);
        }
        if (!world.valid) return count;
    }
    __try {
        const uintptr_t array = ReadEngineValue<uintptr_t>(world.grid + world.arrayOffset);
        if (ReadEngineValue<uintptr_t>(world.grid) != world.gridVtable ||
            array < 0x10000) {
            world.valid = false;
            InterlockedIncrement(&g_gridStatInvalidations);
            return 1;
        }
        bool playerInGrid = false;
        for (uint32_t index = 0; index < world.count && count < capacity; ++index) {
            const uintptr_t cell = ReadEngineValue<uintptr_t>(
                array + index * world.stride + world.cellOffset);
            if (cell == 0) continue;
            if (cell < 0x10000 || ReadEngineValue<uintptr_t>(cell) != world.cellVtable) {
                world.valid = false;
                InterlockedIncrement(&g_gridStatInvalidations);
                return 1;
            }
            if (cell == playerCell) {
                playerInGrid = true;
                continue;
            }
            cells[count++] = cell;
        }
        // Indoors the grid may still list exterior cells; they are not drawn.
        if (!playerInGrid) return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        world.valid = false;
        InterlockedIncrement(&g_gridStatInvalidations);
        return 1;
    }
    return count;
}

ObservedObject *FindObservedObject(uintptr_t root, bool &existing) {
    ObservedObject *reusable = nullptr;
    size_t slot = (root >> 4) & (g_observedObjects.size() - 1);
    for (size_t probe = 0; probe < 32; ++probe) {
        ObservedObject &entry = g_observedObjects[slot];
        if (entry.root == root) {
            existing = true;
            return &entry;
        }
        if (entry.root == 0) {
            if (reusable == nullptr) reusable = &entry;
            break;
        }
        // Not seen for 600 walks: the object is gone, the slot can be reused.
        if (reusable == nullptr && entry.lastSeen + 600 < g_objectSerial) {
            reusable = &entry;
        }
        slot = (slot + 1) & (g_observedObjects.size() - 1);
    }
    existing = false;
    return reusable;
}

uint32_t g_objectLastEligibleFrame = 0;
// Neighbouring cells are not all read on every walk. A cell is "hot" while it
// holds an active object (one that moved recently, or a controller-animated
// one near the player) and is then read on every walk, like the player's own
// cell; the active list is rebuilt from those, so every root in it was seen
// on this walk. A cold cell is read on one walk in six, only to notice that
// something in it has started to move.
struct CellHeat {
    uintptr_t cell = 0;
    uint32_t hotUntil = 0;
};
std::array<CellHeat, 64> g_cellHeat{};
constexpr uint32_t kColdCellPeriod = 6;
volatile LONG g_objectStatCellsRead = 0;
volatile LONG g_objectStatHotCells = 0;
volatile LONG64 g_perfObjectWalkTicks = 0;
int64_t PerfNow();

CellHeat &FindCellHeat(uintptr_t cell) {
    // The table is small: look at all of it for the cell before taking a
    // slot, so that a hot cell is never mistaken for a new one.
    CellHeat *reusable = nullptr;
    for (CellHeat &entry : g_cellHeat) {
        if (entry.cell == cell) return entry;
        // Empty, or a cell that has not been hot for a long time.
        if (reusable == nullptr &&
            (entry.cell == 0 || entry.hotUntil + 2000 < g_objectSerial)) {
            reusable = &entry;
        }
    }
    if (reusable == nullptr) reusable = &g_cellHeat[(cell >> 4) & (g_cellHeat.size() - 1)];
    reusable->cell = cell;
    reusable->hotUntil = 0;
    return *reusable;
}

volatile LONG g_objectStatWalks = 0;
volatile LONG g_objectStatTableFull = 0;

void ObserveCellObjects(uintptr_t player, bool frameIsTick) {
    const bool previousWasTick = g_objectPreviousDrawWasTick;
    g_objectPreviousDrawWasTick = frameIsTick;
    const int frameKind = frameIsTick ? (previousWasTick ? 2 : 0)
                                      : (previousWasTick ? 1 : 3);
    // Roots change on tick draws and the draws right after them. On any other
    // draw nothing has been simulated since the last walk, so the list of
    // active roots from that walk is still right and the cells are not walked
    // again. That only holds if this draw directly follows the last one seen.
    const uint32_t eligibleFrame =
        static_cast<uint32_t>(g_renderTranslationEligibleFrames);
    const bool consecutive = eligibleFrame == g_objectLastEligibleFrame + 1;
    g_objectLastEligibleFrame = eligibleFrame;
    if (frameKind == 3 && consecutive) return;

    ++g_objectSerial;
    g_objectActiveCount = 0;
    InterlockedIncrement(&g_objectStatWalks);
    __try {
        const uintptr_t playerCell = ReadEngineValue<uintptr_t>(player + 0x3C);
        if (playerCell < 0x10000) return;
        if (playerCell != g_objectCell) {
            g_objectCell = playerCell;
            uint32_t bestOffset = 0;
            int best = 2;
            for (uint32_t offset = 0x40; offset <= 0x120; offset += 4) {
                const int count = CountCellListReferences(playerCell, offset);
                if (count > best) {
                    best = count;
                    bestOffset = offset;
                }
            }
            // A nearly empty cell cannot confirm the offset; keep the last one.
            if (bestOffset != 0) g_objectListOffset = bestOffset;
            InterlockedIncrement(&g_objectStatCellScans);
            InterlockedExchange(&g_objectStatListOffset,
                                static_cast<LONG>(g_objectListOffset));
        }
        if (g_objectListOffset == 0) return;

        float playerPosition[3];
        std::memcpy(playerPosition, reinterpret_cast<const void *>(player + 0x2C),
                    sizeof(playerPosition));
        uintptr_t cells[128];
        const size_t cellCount = CollectLoadedCells(playerCell, cells, 128);
        InterlockedExchange(&g_gridStatCells, static_cast<LONG>(cellCount));

        LONG references = 0;
        LONG withRoot = 0;
        LONG moving = 0;
        LONG controlledCount = 0;
        LONG cellsRead = 0;
        LONG hotCells = 0;
        for (size_t cellIndex = 0; cellIndex < cellCount; ++cellIndex) {
            const uintptr_t cell = cells[cellIndex];
            CellHeat &heat = FindCellHeat(cell);
            const bool hot = cellIndex == 0 || heat.hotUntil > g_objectSerial;
            if (hot) ++hotCells;
            if (!hot && (cellIndex + g_objectSerial) % kColdCellPeriod != 0) continue;
            ++cellsRead;
            bool cellHasActive = false;
            uintptr_t node = cell + g_objectListOffset;
            for (int guard = 0; guard < 16384 && node >= 0x10000; ++guard) {
                const uintptr_t reference = ReadEngineValue<uintptr_t>(node);
                node = ReadEngineValue<uintptr_t>(node + 4);
                if (reference == 0) continue;
                // Not a reference of this cell: the list is not what it was
                // taken for, leave the rest of this cell alone.
                if (reference < 0x10000 ||
                    ReadEngineValue<uintptr_t>(reference + 0x3C) != cell) break;
                if (reference == player) continue;
                ++references;
                const uintptr_t renderState = ReadEngineValue<uintptr_t>(reference + 0x5C);
                const uintptr_t root = renderState >= 0x10000
                    ? ReadEngineValue<uintptr_t>(renderState + 0x14) : 0;
                if (root < 0x10000) continue;
                ++withRoot;
                NodePose current{};
                std::memcpy(current.value.data(),
                            reinterpret_cast<const void *>(root + kNodeWorldTransform),
                            sizeof(current.value));
                // A door swings its leaves under a root that stays where it
                // is, so the root never shows a change. Such objects are
                // animated by a controller attached to the root (NiObjectNET
                // +0x0C); a root with one is always treated as active while
                // it is within 6,000 units of the player.
                bool controlled = ReadEngineValue<uintptr_t>(root + 0x0C) >= 0x10000;
                if (controlled) {
                    float distanceSquared = 0.0f;
                    for (int axis = 0; axis < 3; ++axis) {
                        const float delta = current.value[9 + axis] - playerPosition[axis];
                        distanceSquared += delta * delta;
                    }
                    controlled = distanceSquared <= 6000.0f * 6000.0f;
                }
                if (controlled) ++controlledCount;
                bool existing = false;
                ObservedObject *entry = FindObservedObject(root, existing);
                if (entry == nullptr) {
                    InterlockedIncrement(&g_objectStatTableFull);
                    continue;
                }
                // Seen on the last walk, or for a cold cell within its
                // reading period (with some slack).
                if (existing && entry->lastSeen + 2 * kColdCellPeriod >= g_objectSerial) {
                    float largest = 0.0f;
                    for (size_t component = 0; component < kPoseFloats; ++component) {
                        const float difference = std::fabs(
                            current.value[component] - entry->pose.value[component]);
                        if (difference > largest) largest = difference;
                    }
                    if (largest > 0.001f) {
                        ++entry->changes[frameKind];
                        if (largest > entry->largestStep) entry->largestStep = largest;
                        InterlockedIncrement(&g_objectStatChanges[frameKind]);
                        ++moving;
                        // About 2.5 s of walks at two walks per tick.
                        entry->activeUntil = g_objectSerial + 300;
                    }
                    if (controlled || entry->activeUntil > g_objectSerial) {
                        cellHasActive = true;
                        // Only a cell read on every walk feeds the list:
                        // an object found by a cold read becomes drawable
                        // from the next walk on, once its cell is hot.
                        if (hot && g_objectActiveCount < g_objectActiveRoots.size()) {
                            g_objectActiveRoots[g_objectActiveCount++] = root;
                        }
                    }
                } else {
                    entry->root = root;
                    entry->activeUntil = 0;
                    entry->changes[0] = entry->changes[1] = 0;
                    entry->changes[2] = entry->changes[3] = 0;
                    entry->reported = 0;
                    entry->largestStep = 0.0f;
                    entry->refId = ReadEngineValue<uint32_t>(reference + 0x0C);
                    const uintptr_t base = ReadEngineValue<uintptr_t>(reference + 0x1C);
                    entry->baseId = base >= 0x10000
                        ? ReadEngineValue<uint32_t>(base + 0x0C) : 0;
                    entry->baseType = base >= 0x10000
                        ? ReadEngineValue<uint8_t>(base + 0x04) : 0;
                }
                entry->lastSeen = g_objectSerial;
                entry->pose = current;
            }
            if (cellHasActive) heat.hotUntil = g_objectSerial + 2;
        }
        InterlockedExchange(&g_objectStatCellsRead, cellsRead);
        InterlockedExchange(&g_objectStatHotCells, hotCells);
        InterlockedExchange(&g_objectStatReferences, references);
        InterlockedExchange(&g_objectStatWithRoot, withRoot);
        InterlockedExchange(&g_objectStatControlled, controlledCount);
        if (moving > InterlockedCompareExchange(&g_objectStatMovingMax, 0, 0)) {
            InterlockedExchange(&g_objectStatMovingMax, moving);
        }
        if (static_cast<LONG>(g_objectActiveCount) >
            InterlockedCompareExchange(&g_objectStatActiveMax, 0, 0)) {
            InterlockedExchange(&g_objectStatActiveMax,
                                static_cast<LONG>(g_objectActiveCount));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_objectCell = 0;
        g_objectActiveCount = 0;
    }
}

// Returns true when at least one node was changed and must be restored.
bool ApplyActorTranslations(uintptr_t player, bool interpolate, bool includePlayer) {
    g_actorSavedNodeCount = 0;
    if (!g_actorTranslationInterpolationEnabled ||
        g_actorTranslationInterpolationFaulted) return false;
    __try {
        constexpr uintptr_t kProcessManagerObject = 0x0107C0A0;
        const uintptr_t data = ReadEngineValue<uintptr_t>(kProcessManagerObject + 0x08);
        const uint32_t firstFree = ReadEngineValue<uint16_t>(kProcessManagerObject + 0x0E);
        const uint32_t begin = ReadEngineValue<uint32_t>(kProcessManagerObject + 0x14);
        const uint32_t end = ReadEngineValue<uint32_t>(kProcessManagerObject + 0x24);
        if (data < 0x10000 || begin > end || end > firstFree || end - begin > 512) {
            ResetActorTranslationInterpolation();
            return false;
        }
        if (g_poseTableUsed > kPoseTableSize / 2) {
            // Stale entries are never removed one by one; start over instead.
            ResetActorTranslationInterpolation();
            InterlockedIncrement(&g_actorStatTableResets);
        }
        const bool frameIsTick = g_currentPulse.load(std::memory_order_relaxed) != 0;
        double frameAlpha = g_accumulatorMs / g_simulationStepMs;
        if (frameAlpha < 0.0) frameAlpha = 0.0;
        if (frameAlpha > 1.0) frameAlpha = 1.0;
        const bool tick = g_posePreviousDrawWasTick;
        const double alpha = g_posePreviousDrawAlpha;
        g_posePreviousDrawWasTick = frameIsTick;
        g_posePreviousDrawAlpha = frameAlpha;
        g_poseFrameIsTick = frameIsTick;
        g_poseFrameAlpha = frameAlpha;
        for (uint16_t &tally : g_actorTraceCounts) tally = 0;
        g_actorTraceLargestAsIs = 0.0f;
        g_poseTicksBefore = g_poseTickCount;
        if (frameIsTick) {
            ++g_poseTickCount;
            g_poseDrawsSinceTick = 0;
        } else if (g_poseDrawsSinceTick < 1000) {
            ++g_poseDrawsSinceTick;
        }
        ++g_poseDrawSerial;
        g_poseAlphaRing[g_poseDrawSerial & 7] = frameAlpha;
        g_posePeriodRing[g_poseDrawSerial & 7] = g_poseTickCount;
        const uintptr_t tesMain = ReadEngineValue<uintptr_t>(kTESMainSingleton);
        g_poseDrawFrozen =
            tesMain >= 0x10000 && ReadEngineValue<uint8_t>(tesMain + 7) != 0 ? 1 : 0;
        if (g_debugActorObserveOnly) interpolate = false;
        if (player >= 0x10000) {
            const int64_t walkStart = PerfNow();
            ObserveCellObjects(player, frameIsTick);
            InterlockedExchangeAdd64(&g_perfObjectWalkTicks, PerfNow() - walkStart);
        }

        LONG tracked = 0;
        for (uint32_t index = begin; index < end; ++index) {
            const uintptr_t reference = ReadEngineValue<uintptr_t>(data + index * 4);
            if (reference < 0x10000 || reference == player) continue;
            const uintptr_t renderState = ReadEngineValue<uintptr_t>(reference + 0x5C);
            const uintptr_t root = renderState >= 0x10000
                ? ReadEngineValue<uintptr_t>(renderState + 0x14) : 0;
            if (root < 0x10000) continue;
            ++tracked;
            InterpolateSubtree(root, tick, interpolate, alpha, 0);
        }
        if (includePlayer && player >= 0x10000) {
            // Third person: the player's own body is drawn and is posed on
            // ticks like any other actor.
            const uintptr_t renderState = ReadEngineValue<uintptr_t>(player + 0x5C);
            const uintptr_t root = renderState >= 0x10000
                ? ReadEngineValue<uintptr_t>(renderState + 0x14) : 0;
            // Unlike other actors, the player's root is already at the new
            // position on the tick draw itself (it is what the camera
            // history is keyed on), so the un-lagged phase is used here.
            if (root >= 0x10000) {
                InterpolateSubtree(root, frameIsTick, interpolate, frameAlpha, 0);
            }
        }
        // Active cell objects, after the actors so that an actor found in
        // both lists is handled once, by the loop above.
        for (size_t index = 0; index < g_objectActiveCount; ++index) {
            const uintptr_t root = g_objectActiveRoots[index];
            const NodePoseHistory *seen = FindPoseHistory(root);
            if (seen != nullptr && seen->lastSeen == g_poseDrawSerial) continue;
            InterlockedIncrement(&g_objectStatSubtrees);
            InterpolateSubtree(root, tick, interpolate, alpha, 0);
        }
        {
            // 400 draws from the moment menu mode starts, and 400 from the
            // moment it ends.
            const uint8_t menu = ReadEngineValue<uint8_t>(kMenuModeFlag);
            if ((menu != 0) != (g_actorTraceLastMenu != 0)) g_actorTraceHot = 400;
            g_actorTraceLastMenu = menu;
            if (g_actorTraceHot != 0) {
                --g_actorTraceHot;
                TimingTraceRow row{};
                row.tag = 'M';
                row.serial = g_poseDrawSerial;
                row.kind = static_cast<uint8_t>(
                    frameIsTick ? (tick ? 2 : 0) : (tick ? 1 : 3));
                row.state = menu;
                std::memcpy(row.counts, g_actorTraceCounts, sizeof(row.counts));
                row.counts[7] = static_cast<uint16_t>(tracked > 0xFFFF ? 0xFFFF : tracked);
                row.values[3] = static_cast<float>(g_poseDrawFrozen * 100 +
                                                   (g_poseDrawsSinceTick > 9
                                                        ? 9 : g_poseDrawsSinceTick));
                row.values[0] = static_cast<float>(frameAlpha);
                row.values[1] = static_cast<float>(alpha);
                row.values[2] = g_actorTraceLargestAsIs;
                PushTimingTraceRow(row);
            }
        }
        InterlockedExchange(&g_actorStatTracked, tracked);
        InterlockedExchangeAdd(&g_actorStatApplied,
                               static_cast<LONG>(g_actorSavedNodeCount));
        if (static_cast<LONG>(g_actorSavedNodeCount) >
            InterlockedCompareExchange(&g_actorStatNodesMax, 0, 0)) {
            InterlockedExchange(&g_actorStatNodesMax,
                                static_cast<LONG>(g_actorSavedNodeCount));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // What was changed is still restored by the caller; stop afterwards.
        g_actorTranslationInterpolationFaulted = true;
    }
    return g_actorSavedNodeCount != 0;
}

// --- First-person model observer (read-only) -----------------------------------
// The first-person tree follows the camera every frame, so its world
// transforms cannot be interpolated directly. This measures, for every node
// below PlayerCharacter+0x5F0, its transform relative to that root, and
// reports on which kind of draw those relative transforms change.
struct RelativePoseEntry {
    uintptr_t node = 0;
    uint32_t lastSeen = 0;
    NodePose relative{};
};
std::array<RelativePoseEntry, 2048> g_firstPersonTable{};
uint32_t g_firstPersonSerial = 1;
volatile LONG g_fpStatNodes = 0;
// Draws on which at least one relative transform changed by more than 1e-3:
// [0] this frame is a tick, previous was not; [1] previous was a tick, this
// is not; [2] both; [3] neither.
volatile LONG g_fpStatChangeDraws[4] = {};
volatile LONG g_fpStatDraws = 0;
volatile LONG g_fpStatRootMovedFrozen = 0;
volatile LONG g_fpStatMaxMilli = 0;
bool g_fpPreviousDrawWasTick = false;
NodePose g_fpPreviousRoot{};

void RelativePose(const NodePose &root, const NodePose &node, NodePose &out) {
    const float *r = root.value.data();
    const float *n = node.value.data();
    const float scale = r[12] != 0.0f ? r[12] : 1.0f;
    for (size_t row = 0; row < 3; ++row) {
        for (size_t column = 0; column < 3; ++column) {
            // transpose(rootRotation) * nodeRotation
            out.value[row * 3 + column] = r[0 + row] * n[0 + column] +
                r[3 + row] * n[3 + column] + r[6 + row] * n[6 + column];
        }
        const float dx = n[9] - r[9], dy = n[10] - r[10], dz = n[11] - r[11];
        out.value[9 + row] = (r[0 + row] * dx + r[3 + row] * dy + r[6 + row] * dz) / scale;
    }
    out.value[12] = n[12] / scale;
}

float ObserveFirstPersonSubtree(uintptr_t object, const NodePose &root, uint32_t depth,
                                LONG &count) {
    if (object < 0x10000 || depth > 48) return 0.0f;
    NodePose world{};
    std::memcpy(world.value.data(),
                reinterpret_cast<const void *>(object + kNodeWorldTransform),
                sizeof(world.value));
    NodePose relative{};
    RelativePose(root, world, relative);
    float largest = 0.0f;
    size_t slot = (object >> 4) & (g_firstPersonTable.size() - 1);
    for (size_t probe = 0; probe < 32; ++probe) {
        RelativePoseEntry &entry = g_firstPersonTable[slot];
        if (entry.node == object || entry.node == 0) {
            if (entry.node == object && entry.lastSeen + 1 == g_firstPersonSerial) {
                for (size_t component = 0; component < kPoseFloats; ++component) {
                    const float difference = std::fabs(
                        relative.value[component] - entry.relative.value[component]);
                    if (difference > largest) largest = difference;
                }
            }
            entry.node = object;
            entry.lastSeen = g_firstPersonSerial;
            entry.relative = relative;
            break;
        }
        slot = (slot + 1) & (g_firstPersonTable.size() - 1);
    }
    ++count;
    if (!IsSceneNode(object)) return largest;
    const uintptr_t children = ReadEngineValue<uintptr_t>(object + 0xA0);
    const uint32_t childCount = ReadEngineValue<uint16_t>(object + 0xA6);
    if (children < 0x10000 || childCount > 1024) return largest;
    for (uint32_t index = 0; index < childCount; ++index) {
        const float child = ObserveFirstPersonSubtree(
            ReadEngineValue<uintptr_t>(children + index * 4), root, depth + 1, count);
        if (child > largest) largest = child;
    }
    return largest;
}

void ObserveFirstPersonModel() {
    __try {
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        if (player < 0x10000) return;
        const uintptr_t rootNode = ReadEngineValue<uintptr_t>(player + 0x5F0);
        if (rootNode < 0x10000) return;
        NodePose root{};
        std::memcpy(root.value.data(),
                    reinterpret_cast<const void *>(rootNode + kNodeWorldTransform),
                    sizeof(root.value));
        const bool tick = g_currentPulse.load(std::memory_order_relaxed) != 0;
        const uintptr_t tesMain = ReadEngineValue<uintptr_t>(kTESMainSingleton);
        const bool frozen =
            tesMain >= 0x10000 && ReadEngineValue<uint8_t>(tesMain + 7) != 0;
        ++g_firstPersonSerial;
        LONG count = 0;
        const float largest = ObserveFirstPersonSubtree(rootNode, root, 0, count);
        InterlockedExchange(&g_fpStatNodes, count);
        InterlockedIncrement(&g_fpStatDraws);
        if (largest > 0.001f) {
            const int kind = tick
                ? (g_fpPreviousDrawWasTick ? 2 : 0)
                : (g_fpPreviousDrawWasTick ? 1 : 3);
            InterlockedIncrement(&g_fpStatChangeDraws[kind]);
            const LONG milli = largest < 1000000.0f
                ? static_cast<LONG>(largest * 1000.0f) : 1000000000;
            if (milli > InterlockedCompareExchange(&g_fpStatMaxMilli, 0, 0)) {
                InterlockedExchange(&g_fpStatMaxMilli, milli);
            }
        }
        if (frozen && std::memcmp(root.value.data(), g_fpPreviousRoot.value.data(),
                                  sizeof(root.value)) != 0) {
            InterlockedIncrement(&g_fpStatRootMovedFrozen);
        }
        g_fpPreviousRoot = root;
        g_fpPreviousDrawWasTick = tick;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// --- First-person pass ----------------------------------------------------------
// The first-person arms and weapon are not drawn by the main scene draw. In
// FUN_006EC680 they have their own pass right after it: FUN_006E6190 (call at
// 006EC93A, sets the first-person field of view), FUN_006E63D0 (006EC98B),
// the draws FUN_006E65F0 (006EC999) and FUN_006E6A40 (006EC9DF), then
// FUN_006EAD80 (006ECA17). Every one of those calls is conditional, so the
// tree is prepared at whichever of the three middle calls comes first and put
// back at FUN_006E73F0 (006ECAE9), which every frame reaches.
std::array<SavedNodePose, 512> g_firstPersonSaved{};
size_t g_firstPersonSavedCount = 0;
bool g_firstPersonPassPrepared = false;
volatile LONG g_fpStatPasses = 0;
volatile LONG g_fpStatLateRestores = 0;
volatile LONG g_fpStatRestoreConflicts = 0;

void RestoreFirstPersonPass() {
    __try {
        for (size_t index = g_firstPersonSavedCount; index-- > 0;) {
            const SavedNodePose &saved = g_firstPersonSaved[index];
            auto *live = reinterpret_cast<void *>(saved.node + kNodeLocalTransform);
            if (std::memcmp(live, saved.written.value.data(),
                            sizeof(saved.written.value)) != 0) {
                InterlockedIncrement(&g_fpStatRestoreConflicts);
                continue;
            }
            std::memcpy(live, saved.pose.value.data(), sizeof(saved.pose.value));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    g_firstPersonSavedCount = 0;
}

// First-person local-transform interpolation. The pass recomputes every world
// transform of the tree from the local ones (a world write made before it is
// simply overwritten), so the blend is applied to local transforms
// (NiAVObject +0x34: rotation, translation, scale; 52 bytes) of every node
// below the root just before the pass, and the engine's bytes are put back at
// the finish point. The root itself follows the camera and is left alone.
struct FirstPersonLocalHistory {
    uintptr_t node = 0;
    uint32_t lastSeen = 0;
    uint32_t lastChange = 0;    // pass serial of the last change
    uint8_t offTickScore = 0;   // +4 per off-tick change, -1 per pass
    bool lastChangeLagged = false;  // the previous change came a draw after its tick
    // Diagnostics, read by the log thread.
    char name[32] = {};
    uint32_t statChanges[4] = {};   // tick, after a tick, both, neither
    uint32_t statBlends = 0;
    uint32_t statPerFrame = 0;
    uint32_t statReportedOffTick = 0;
    uint32_t changePeriod = 0;  // tick period the last change belongs to
    bool lag = false;           // change first seen on the frame after its tick
    NodePose from{};
    NodePose to{};
};
std::array<FirstPersonLocalHistory, 2048> g_firstPersonLocal{};
uint32_t g_fpPassSerial = 1;
uint32_t g_fpTickCount = 0;
bool g_fpPreviousFrameWasTick = false;
double g_fpPreviousFrameAlpha = 0.0;
// Node-level local changes by frame kind: tick, after a tick, both, neither.
volatile LONG g_fpStatLocalChanges[4] = {};
volatile LONG g_fpStatLocalBlends = 0;
volatile LONG g_fpStatLocalPerFrame = 0;
volatile LONG g_fpStatLateBlends = 0;

// Blended local transforms worked out for this frame and not yet written:
// node, the engine's local transform, and the one to show. The histories are
// advanced once per frame, at the main scene draw (which needs the blended
// camera bone) or at the first-person pass, whichever comes first.
std::array<SavedNodePose, 512> g_fpPending{};
size_t g_fpPendingCount = 0;
bool g_fpAdvanced = false;

uint32_t g_fpTraceHot = 0;
// The first-person pass copies its camera's rotation from the scene camera
// (FUN_006E65F0, +0x68), after the main scene draw has had the engine's
// rotation put back. The arms are drawn with the blended pose, so with the
// engine's rotation the weapon shifts against the view by up to one tick of
// camera-bone rotation, 60 times a second, whenever an animation turns the
// camera (reloads). The blended rotation of this frame is therefore written
// again when the pass is prepared and put back at its finish point.
struct PassCameraRotation {
    bool pending = false;       // a blended rotation exists for this frame
    bool written = false;
    uintptr_t camera = 0;
    float original[9] = {};
    float blended[9] = {};
};
PassCameraRotation g_passCameraRotation{};
volatile LONG g_cameraStatPassWrites = 0;
volatile LONG g_cameraStatPassConflicts = 0;
void FirstPersonAdvance() {
    if (g_fpAdvanced) return;
    if (!g_actorTranslationInterpolationEnabled || !g_quantizedDeltaEnabled ||
        !CaptureGateIsActive() || g_renderTranslationEligibleFrames <= 60) return;
    g_fpAdvanced = true;
    g_fpPendingCount = 0;
    __try {
        const bool frameIsTick = g_currentPulse.load(std::memory_order_relaxed) != 0;
        double frameAlpha = g_accumulatorMs / g_simulationStepMs;
        if (frameAlpha < 0.0) frameAlpha = 0.0;
        if (frameAlpha > 1.0) frameAlpha = 1.0;
        const uint32_t ticksBefore = g_fpTickCount;
        if (frameIsTick) ++g_fpTickCount;
        const bool previousWasTick = g_fpPreviousFrameWasTick;
        const double previousAlpha = g_fpPreviousFrameAlpha;
        g_fpPreviousFrameWasTick = frameIsTick;
        g_fpPreviousFrameAlpha = frameAlpha;
        ++g_fpPassSerial;
        const int frameKind = frameIsTick ? (previousWasTick ? 2 : 0)
                                          : (previousWasTick ? 1 : 3);
        // Tallies for the reload trace: changed, accepted on the tick draw,
        // accepted late, shown as is (off tick, per frame, first late pose),
        // blends in progress on tick phase and on late phase.
        uint16_t fpTrace[8] = {};
        float fpTraceHand[2] = {0.0f, 0.0f};
        int fpTraceHandDecision = -1;

        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        const uintptr_t rootNode =
            player >= 0x10000 ? ReadEngineValue<uintptr_t>(player + 0x5F0) : 0;
        if (rootNode < 0x10000) return;
        const bool tracing = g_crouchTracePendingValid;
        if (tracing) {
            g_crouchTracePending.fpPass = 1;
            g_crouchTraceRoot = rootNode;
            g_crouchTracePending.rootLocalZ = ReadEngineValue<float>(rootNode + 0x60);
            g_crouchTracePending.rootWorldZBefore = ReadEngineValue<float>(rootNode + 0x94);
            const uintptr_t sceneGraph = ReadEngineValue<uintptr_t>(kSceneGraphSingleton);
            const uintptr_t sceneCamera = sceneGraph >= 0x10000
                ? ReadEngineValue<uintptr_t>(sceneGraph + 0xAC) : 0;
            if (sceneCamera >= 0x10000) {
                g_crouchTracePending.fpCameraWorldZ =
                    ReadEngineValue<float>(sceneCamera + 0x94);
            }
        }
        uintptr_t stack[512];
        size_t top = 0;
        stack[top++] = rootNode;
        while (top != 0) {
            const uintptr_t object = stack[--top];
            if (object < 0x10000) continue;
            if (IsSceneNode(object)) {
                const uintptr_t children = ReadEngineValue<uintptr_t>(object + 0xA0);
                const uint32_t count = ReadEngineValue<uint16_t>(object + 0xA6);
                if (children >= 0x10000 && count <= 1024) {
                    for (uint32_t index = 0; index < count && top < 512; ++index) {
                        stack[top++] = ReadEngineValue<uintptr_t>(children + index * 4);
                    }
                }
            }
            if (object == rootNode) continue;

            NodePose current{};
            std::memcpy(current.value.data(),
                        reinterpret_cast<const void *>(object + kNodeLocalTransform),
                        sizeof(current.value));
            FirstPersonLocalHistory *history = nullptr;
            size_t slot = (object >> 4) & (g_firstPersonLocal.size() - 1);
            for (size_t probe = 0; probe < 32; ++probe) {
                FirstPersonLocalHistory &entry = g_firstPersonLocal[slot];
                if (entry.node == object || entry.node == 0) {
                    history = &entry;
                    break;
                }
                slot = (slot + 1) & (g_firstPersonLocal.size() - 1);
            }
            if (history == nullptr) continue;
            const bool known =
                history->node == object && history->lastSeen + 1 == g_fpPassSerial;
            history->node = object;
            history->lastSeen = g_fpPassSerial;
            if (!known) {
                history->from = current;
                history->to = current;
                history->lastChange = 0;
                history->offTickScore = 0;
                history->statChanges[0] = history->statChanges[1] = 0;
                history->statChanges[2] = history->statChanges[3] = 0;
                history->statBlends = history->statPerFrame = 0;
                history->statReportedOffTick = 0;
                history->name[0] = '\0';
                const uintptr_t nameAddress = ReadEngineValue<uintptr_t>(object + 0x08);
                if (nameAddress >= 0x10000) {
                    const auto *text = reinterpret_cast<const char *>(nameAddress);
                    size_t length = 0;
                    while (length + 1 < sizeof(history->name) && text[length] != '\0') {
                        const char c = text[length];
                        history->name[length] = (c >= 0x20 && c < 0x7F && c != ',') ? c : '?';
                        ++length;
                    }
                    history->name[length] = '\0';
                }
                continue;
            }
            if (tracing) {
                if (std::strcmp(history->name, "Camera1st") == 0) {
                    g_crouchTraceCamera1st = object;
                } else if (std::strcmp(history->name, "Bip01 R Hand") == 0) {
                    g_crouchTraceHand = object;
                }
            }
            const bool traceNode = std::strcmp(history->name, "Bip01 R Hand") == 0;
            if (traceNode) {
                fpTraceHand[0] = current.value[1];
                fpTraceHand[1] = current.value[1];
                fpTraceHandDecision = 0;
            }
            if (history->offTickScore != 0) --history->offTickScore;
            if (std::memcmp(history->to.value.data(), current.value.data(),
                            sizeof(current.value)) != 0) {
                ++fpTrace[0];
                InterlockedIncrement(&g_fpStatLocalChanges[frameKind]);
                ++history->statChanges[frameKind];
                const bool changedLastPass = history->lastChange + 1 == g_fpPassSerial;
                history->lastChange = g_fpPassSerial;
                // Animation moves a node on tick frames only. A node that
                // keeps changing on other frames as well is being driven every
                // frame (the pitch-following nodes while the mouse moves);
                // blending it would make it trail the view on tick frames. A
                // single off-tick change (an animation starting) is shown as
                // it is without reclassifying the node, so a skeleton is not
                // left half blended and half stepped.
                //
                // Measured over a long session: for stretches of some
                // animations (part of a rifle reload) the whole skeleton's
                // poses arrive on the draw after the tick instead. A change
                // on that draw, with none on the tick draw before it, is such
                // a late pose and not a sign of per-frame driving; the first
                // one is shown as it is, and from the second in a row the
                // node is blended with the previous draw's phase.
                const bool latePose = frameKind == 1 && !changedLastPass;
                const bool offTick = (frameKind == 1 && !latePose) || frameKind == 3;
                const bool blendLate = latePose && history->lastChangeLagged;
                history->lastChangeLagged = latePose;
                if (offTick) {
                    history->offTickScore = static_cast<uint8_t>(
                        history->offTickScore > 12 ? 16 : history->offTickScore + 4);
                }
                const bool perFrame = history->offTickScore >= 8;
                if (blendLate && !perFrame) InterlockedIncrement(&g_fpStatLateBlends);
                if (offTick || perFrame || (latePose && !blendLate)) {
                    // 3 off a tick, 4 driven every frame, 5 first late pose.
                    const int reason = offTick ? 3 : (perFrame ? 4 : 5);
                    ++fpTrace[reason];
                    if (traceNode) fpTraceHandDecision = reason;
                    InterlockedIncrement(&g_fpStatLocalPerFrame);
                    ++history->statPerFrame;
                    history->from = current;
                    history->to = current;
                    history->changePeriod = 0;
                    continue;
                }
                history->from = history->to;
                history->to = current;
                history->lag = !frameIsTick;
                history->changePeriod = history->lag ? ticksBefore : g_fpTickCount;
                ++fpTrace[history->lag ? 2 : 1];
                if (traceNode) fpTraceHandDecision = history->lag ? 2 : 1;
            }
            const uint32_t period = history->lag ? ticksBefore : g_fpTickCount;
            if (history->changePeriod == 0 || history->changePeriod != period) continue;
            float stepSquared = 0.0f;
            for (size_t axis = 9; axis < 12; ++axis) {
                const float delta = history->to.value[axis] - history->from.value[axis];
                stepSquared += delta * delta;
            }
            if (!(stepSquared <= 900.0f)) continue;
            NodePose shown{};
            if (!BlendPose(history->from, history->to,
                           history->lag ? previousAlpha : frameAlpha, shown)) continue;
            if (g_fpPendingCount >= g_fpPending.size()) continue;
            SavedNodePose &pending = g_fpPending[g_fpPendingCount++];
            pending.node = object;
            pending.pose = current;
            pending.written = shown;
            ++fpTrace[history->lag ? 7 : 6];
            if (traceNode) fpTraceHand[1] = shown.value[1];
            InterlockedIncrement(&g_fpStatLocalBlends);
            ++history->statBlends;
        }

        {
            // While a weapon action is in progress (reloading is 9) and for
            // 40 passes after it.
            int32_t action = -2;
            const uintptr_t process = ReadEngineValue<uintptr_t>(player + 0x60);
            if (process >= 0x10000) {
                using ActionFn = int32_t(__thiscall *)(void *);
                const auto getAction = ReadEngineValue<ActionFn>(
                    ReadEngineValue<uintptr_t>(process) + 0x3E0);
                action = getAction(reinterpret_cast<void *>(process));
            }
            if (action == 9) g_fpTraceHot = 40;
            if (g_fpTraceHot != 0) {
                --g_fpTraceHot;
                TimingTraceRow row{};
                row.tag = 'R';
                row.serial = g_fpPassSerial;
                row.kind = static_cast<uint8_t>(frameKind);
                row.state = action;
                std::memcpy(row.counts, fpTrace, sizeof(row.counts));
                row.values[0] = static_cast<float>(frameAlpha);
                row.values[1] = fpTraceHand[0];
                row.values[2] = fpTraceHand[1];
                row.values[3] = static_cast<float>(fpTraceHandDecision);
                PushTimingTraceRow(row);
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void __cdecl FirstPersonPassPrepare() {
    if (g_firstPersonPassPrepared) return;
    FirstPersonAdvance();
    if (!g_fpAdvanced) return;
    g_firstPersonPassPrepared = true;
    InterlockedIncrement(&g_fpStatPasses);
    __try {
        for (size_t index = 0; index < g_fpPendingCount; ++index) {
            const SavedNodePose &pending = g_fpPending[index];
            auto *live = reinterpret_cast<void *>(pending.node + kNodeLocalTransform);
            // Written only if the engine's transform is still the one the
            // blend was worked out from.
            if (std::memcmp(live, pending.pose.value.data(),
                            sizeof(pending.pose.value)) != 0) continue;
            if (g_firstPersonSavedCount >= g_firstPersonSaved.size()) break;
            g_firstPersonSaved[g_firstPersonSavedCount++] = pending;
            std::memcpy(live, pending.written.value.data(),
                        sizeof(pending.written.value));
        }
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        const uintptr_t rootNode =
            player >= 0x10000 ? ReadEngineValue<uintptr_t>(player + 0x5F0) : 0;
        if (rootNode < 0x10000) return;
        const bool tracing = g_crouchTracePendingValid;

        const uintptr_t cameraNode = ReadEngineValue<uintptr_t>(kFirstPersonCameraNode);
        bool cameraNodeWritten = false;
        if (cameraNode >= 0x10000 && cameraNode != rootNode) {
            float position[3];
            std::memcpy(position, reinterpret_cast<const void *>(cameraNode + 0x58),
                        sizeof(position));
            uintptr_t ancestor = ReadEngineValue<uintptr_t>(cameraNode + 0x18);
            bool reachedRoot = false;
            for (int depth = 0; depth < 32 && ancestor >= 0x10000; ++depth) {
                const bool isRoot = ancestor == rootNode;
                // The root contributes its world transform, the others their
                // local one: rotation, translation, scale.
                const uintptr_t base = ancestor + (isRoot ? kNodeWorldTransform
                                                          : kNodeLocalTransform);
                float transform[13];
                std::memcpy(transform, reinterpret_cast<const void *>(base),
                            sizeof(transform));
                float moved[3];
                for (int row = 0; row < 3; ++row) {
                    moved[row] = (transform[row * 3 + 0] * position[0] +
                                  transform[row * 3 + 1] * position[1] +
                                  transform[row * 3 + 2] * position[2]) *
                                     transform[12] + transform[9 + row];
                }
                std::memcpy(position, moved, sizeof(position));
                if (isRoot) {
                    reachedRoot = true;
                    break;
                }
                ancestor = ReadEngineValue<uintptr_t>(ancestor + 0x18);
            }
            if (reachedRoot && std::isfinite(position[0]) &&
                std::isfinite(position[1]) && std::isfinite(position[2])) {
                if (tracing) {
                    g_crouchTracePending.camera1stLocalZ =
                        ReadEngineValue<float>(cameraNode + 0x94);
                    g_crouchTracePending.handLocalZ = position[2];
                }
                std::memcpy(reinterpret_cast<void *>(cameraNode + 0x8C), position,
                            sizeof(position));
                cameraNodeWritten = true;
                InterlockedIncrement(&g_fpStatCameraNodeWrites);
            }
        }
        if (!cameraNodeWritten) InterlockedIncrement(&g_fpStatCameraNodeMisses);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// The scene camera takes its orientation from the same camera bone of the
// first-person skeleton (reload and landing animations turn it), so that part
// of the view moved at tick rate. For the main scene draw the camera's world
// rotation is multiplied by the difference between the bone's world rotation
// with the blended locals and with the engine's locals, both worked out by
// walking from the bone up to the root. Mouse look reaches the camera every
// frame through locals that are not blended, so it cancels out of the
// difference.
struct SavedCameraRotation {
    uintptr_t camera = 0;
    float original[9] = {};
    float written[9] = {};
};
SavedCameraRotation g_cameraRotationSaved{};
float g_cameraBoneRelation[9] = {};
bool g_cameraBoneRelationValid = false;
volatile LONG g_cameraStatRotationWrites = 0;
volatile LONG g_cameraStatRelationChanges = 0;
volatile LONG g_cameraStatRotationConflicts = 0;

void MultiplyRotation(const float *left, const float *right, float *out) {
    float result[9];
    for (int row = 0; row < 3; ++row) {
        for (int column = 0; column < 3; ++column) {
            result[row * 3 + column] =
                left[row * 3 + 0] * right[0 * 3 + column] +
                left[row * 3 + 1] * right[1 * 3 + column] +
                left[row * 3 + 2] * right[2 * 3 + column];
        }
    }
    std::memcpy(out, result, sizeof(result));
}

void TransposeRotation(const float *in, float *out) {
    float result[9];
    for (int row = 0; row < 3; ++row) {
        for (int column = 0; column < 3; ++column) {
            result[row * 3 + column] = in[column * 3 + row];
        }
    }
    std::memcpy(out, result, sizeof(result));
}

bool ApplyCameraAnimationRotation(uintptr_t player, uintptr_t camera) {
    g_cameraRotationSaved.camera = 0;
    FirstPersonAdvance();
    if (!g_fpAdvanced) return false;
    __try {
        const uintptr_t rootNode = ReadEngineValue<uintptr_t>(player + 0x5F0);
        const uintptr_t cameraNode = ReadEngineValue<uintptr_t>(kFirstPersonCameraNode);
        if (rootNode < 0x10000 || cameraNode < 0x10000 || cameraNode == rootNode) {
            return false;
        }
        float engineChain[9] = {1, 0, 0, 0, 1, 0, 0, 0, 1};
        float blendedChain[9] = {1, 0, 0, 0, 1, 0, 0, 0, 1};
        bool anyBlended = false;
        bool reachedRoot = false;
        uintptr_t node = cameraNode;
        for (int depth = 0; depth < 32 && node >= 0x10000; ++depth) {
            if (node == rootNode) {
                reachedRoot = true;
                break;
            }
            float engineLocal[9];
            std::memcpy(engineLocal,
                        reinterpret_cast<const void *>(node + kNodeLocalTransform),
                        sizeof(engineLocal));
            const float *blendedLocal = engineLocal;
            for (size_t index = 0; index < g_fpPendingCount; ++index) {
                if (g_fpPending[index].node != node) continue;
                if (std::memcmp(engineLocal, g_fpPending[index].pose.value.data(),
                                sizeof(engineLocal)) == 0) {
                    blendedLocal = g_fpPending[index].written.value.data();
                    anyBlended = true;
                }
                break;
            }
            MultiplyRotation(engineLocal, engineChain, engineChain);
            MultiplyRotation(blendedLocal, blendedChain, blendedChain);
            node = ReadEngineValue<uintptr_t>(node + 0x18);
        }
        if (!reachedRoot) return false;

        float rootRotation[9];
        std::memcpy(rootRotation,
                    reinterpret_cast<const void *>(rootNode + kNodeWorldTransform),
                    sizeof(rootRotation));
        float engineWorld[9];
        float blendedWorld[9];
        MultiplyRotation(rootRotation, engineChain, engineWorld);
        MultiplyRotation(rootRotation, blendedChain, blendedWorld);
        float engineWorldInverse[9];
        TransposeRotation(engineWorld, engineWorldInverse);

        SavedCameraRotation &saved = g_cameraRotationSaved;
        std::memcpy(saved.original, reinterpret_cast<const void *>(camera + 0x68),
                    sizeof(saved.original));
        // The camera is expected to be the bone's rotation times a constant.
        // If that relation moves, the camera is not following the bone (or
        // not yet), and nothing is written on this frame.
        float relation[9];
        MultiplyRotation(engineWorldInverse, saved.original, relation);
        float deviation = 0.0f;
        for (int index = 0; index < 9; ++index) {
            if (!std::isfinite(relation[index])) return false;
            const float difference =
                std::fabs(relation[index] - g_cameraBoneRelation[index]);
            if (difference > deviation) deviation = difference;
        }
        if (!g_cameraBoneRelationValid || deviation > 0.002f) {
            if (g_cameraBoneRelationValid) {
                InterlockedIncrement(&g_cameraStatRelationChanges);
            }
            std::memcpy(g_cameraBoneRelation, relation, sizeof(relation));
            g_cameraBoneRelationValid = true;
            return false;
        }
        if (!anyBlended) return false;

        float difference[9];
        MultiplyRotation(blendedWorld, engineWorldInverse, difference);
        MultiplyRotation(difference, saved.original, saved.written);
        for (int index = 0; index < 9; ++index) {
            if (!std::isfinite(saved.written[index])) return false;
        }
        if (std::memcmp(saved.written, saved.original, sizeof(saved.written)) == 0) {
            return false;
        }
        std::memcpy(reinterpret_cast<void *>(camera + 0x68), saved.written,
                    sizeof(saved.written));
        saved.camera = camera;
        g_passCameraRotation.pending = true;
        g_passCameraRotation.written = false;
        g_passCameraRotation.camera = camera;
        std::memcpy(g_passCameraRotation.original, saved.original,
                    sizeof(saved.original));
        std::memcpy(g_passCameraRotation.blended, saved.written, sizeof(saved.written));
        InterlockedIncrement(&g_cameraStatRotationWrites);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_cameraRotationSaved.camera = 0;
        return false;
    }
}

void RestoreCameraAnimationRotation() {
    SavedCameraRotation &saved = g_cameraRotationSaved;
    if (saved.camera == 0) return;
    __try {
        auto *live = reinterpret_cast<void *>(saved.camera + 0x68);
        if (std::memcmp(live, saved.written, sizeof(saved.written)) == 0) {
            std::memcpy(live, saved.original, sizeof(saved.original));
        } else {
            InterlockedIncrement(&g_cameraStatRotationConflicts);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    saved.camera = 0;
}

// Entry of FUN_006E65F0 (call at 006EC999), the function that copies the scene
// camera's rotation to the first-person camera: prepare the pass if no
// earlier call did, then put the blended rotation on the scene camera, here
// and not earlier, since something rewrites it between the calls (12,857 of
// 12,996 earlier writes had been replaced by the finish point).
volatile LONG g_cameraStatPassSkips = 0;
void __cdecl FirstPersonPassPrepare710() {
    FirstPersonPassPrepare();
    PassCameraRotation &pass = g_passCameraRotation;
    if (!pass.pending || pass.camera < 0x10000) return;
    __try {
        auto *live = reinterpret_cast<void *>(pass.camera + 0x68);
        // Only over the engine's own rotation.
        if (std::memcmp(live, pass.original, sizeof(pass.original)) == 0) {
            std::memcpy(live, pass.blended, sizeof(pass.blended));
            pass.written = true;
            InterlockedIncrement(&g_cameraStatPassWrites);
        } else if (std::memcmp(live, pass.blended, sizeof(pass.blended)) != 0) {
            InterlockedIncrement(&g_cameraStatPassSkips);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void __cdecl FirstPersonPassFinish() {
    if (g_crouchTracePendingValid && g_crouchTracePending.fpPass != 0) {
        __try {
            if (g_crouchTraceRoot >= 0x10000) {
                g_crouchTracePending.rootWorldZ =
                    ReadEngineValue<float>(g_crouchTraceRoot + 0x94);
            }
            if (g_crouchTraceCamera1st >= 0x10000) {
                g_crouchTracePending.camera1stWorldZ =
                    ReadEngineValue<float>(g_crouchTraceCamera1st + 0x94);
            }
            if (g_crouchTraceHand >= 0x10000) {
                g_crouchTracePending.handWorldZ =
                    ReadEngineValue<float>(g_crouchTraceHand + 0x94);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    g_crouchTraceRoot = g_crouchTraceCamera1st = g_crouchTraceHand = 0;
    if (g_firstPersonSavedCount != 0) RestoreFirstPersonPass();
    g_firstPersonPassPrepared = false;
    g_fpAdvanced = false;
    g_fpPendingCount = 0;
    if (g_passCameraRotation.written) {
        __try {
            PassCameraRotation &pass = g_passCameraRotation;
            auto *live = reinterpret_cast<void *>(pass.camera + 0x68);
            if (std::memcmp(live, pass.blended, sizeof(pass.blended)) == 0) {
                std::memcpy(live, pass.original, sizeof(pass.original));
            } else {
                InterlockedIncrement(&g_cameraStatPassConflicts);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    g_passCameraRotation.pending = false;
    g_passCameraRotation.written = false;
}

// The probed call sites are redirected here instead of to their stock targets.
// Registers, flags and the stack are exactly as the caller left them when the
// stock function is entered.
#define FIRST_PERSON_THUNK(name, worker, stockAddress) \
    __declspec(naked) void name() {                    \
        __asm pushfd                                   \
        __asm pushad                                   \
        __asm call worker                              \
        __asm popad                                    \
        __asm popfd                                    \
        __asm push stockAddress                        \
        __asm ret                                      \
    }
FIRST_PERSON_THUNK(FirstPersonPrepareThunk709, FirstPersonPassPrepare, 0x006E63D0)
FIRST_PERSON_THUNK(FirstPersonPrepareThunk710, FirstPersonPassPrepare710, 0x006E65F0)
FIRST_PERSON_THUNK(FirstPersonPrepareThunk711, FirstPersonPassPrepare, 0x006E6A40)
FIRST_PERSON_THUNK(FirstPersonFinishThunk713, FirstPersonPassFinish, 0x006E73F0)
#undef FIRST_PERSON_THUNK

// The sky (dome, stars, sun, moon, clouds) is kept centred on the camera by the
// engine, at the camera's position as of the last tick. The main scene draw
// is made from the interpolated camera position, so the sky has to be moved
// by the same amount or it shifts against the view by up to one tick of
// movement. Sky singleton pointer at 0x01072F90 (stored at 0043C2B0 from the
// constructor 0057AFC0); its two NiNode roots are at +0x04 and +0x08.
constexpr uintptr_t kSkySingleton = 0x01072F90;
struct SavedSkyTranslation {
    uintptr_t node = 0;
    float original[3] = {};
    float written[3] = {};
};
std::array<SavedSkyTranslation, 256> g_skySaved{};
size_t g_skySavedCount = 0;
volatile LONG g_skyStatNodesWritten = 0;
volatile LONG g_skyStatRestoreConflicts = 0;

void ShiftSkyForDraw(const float delta[3]) {
    g_skySavedCount = 0;
    __try {
        const uintptr_t sky = ReadEngineValue<uintptr_t>(kSkySingleton);
        if (sky < 0x10000) return;
        const uintptr_t roots[2] = {ReadEngineValue<uintptr_t>(sky + 0x04),
                                    ReadEngineValue<uintptr_t>(sky + 0x08)};
        uintptr_t stack[256];
        size_t top = 0;
        if (roots[0] >= 0x10000) stack[top++] = roots[0];
        if (roots[1] >= 0x10000 && roots[1] != roots[0]) {
            // Skip the second root if it already hangs below the first.
            bool below = false;
            uintptr_t ancestor = ReadEngineValue<uintptr_t>(roots[1] + 0x18);
            for (int depth = 0; depth < 16 && ancestor >= 0x10000; ++depth) {
                if (ancestor == roots[0]) {
                    below = true;
                    break;
                }
                ancestor = ReadEngineValue<uintptr_t>(ancestor + 0x18);
            }
            if (!below) stack[top++] = roots[1];
        }
        while (top != 0 && g_skySavedCount < g_skySaved.size()) {
            const uintptr_t object = stack[--top];
            if (object < 0x10000) continue;
            if (IsSceneNode(object)) {
                const uintptr_t children = ReadEngineValue<uintptr_t>(object + 0xA0);
                const uint32_t count = ReadEngineValue<uint16_t>(object + 0xA6);
                if (children >= 0x10000 && count <= 256) {
                    for (uint32_t index = 0; index < count && top < 256; ++index) {
                        stack[top++] = ReadEngineValue<uintptr_t>(children + index * 4);
                    }
                }
            }
            SavedSkyTranslation &saved = g_skySaved[g_skySavedCount];
            saved.node = object;
            std::memcpy(saved.original, reinterpret_cast<const void *>(object + 0x8C),
                        sizeof(saved.original));
            bool finite = true;
            for (int axis = 0; axis < 3; ++axis) {
                saved.written[axis] = saved.original[axis] + delta[axis];
                finite = finite && std::isfinite(saved.written[axis]);
            }
            if (!finite) continue;
            std::memcpy(reinterpret_cast<void *>(object + 0x8C), saved.written,
                        sizeof(saved.written));
            ++g_skySavedCount;
            InterlockedIncrement(&g_skyStatNodesWritten);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void RestoreSkyAfterDraw() {
    __try {
        for (size_t index = g_skySavedCount; index-- > 0;) {
            const SavedSkyTranslation &saved = g_skySaved[index];
            auto *live = reinterpret_cast<void *>(saved.node + 0x8C);
            if (std::memcmp(live, saved.written, sizeof(saved.written)) != 0) {
                InterlockedIncrement(&g_skyStatRestoreConflicts);
                continue;
            }
            std::memcpy(live, saved.original, sizeof(saved.original));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    g_skySavedCount = 0;
}

// --- Left hand watch (read-only diagnostic) ----------------------------------------------
// The player's left hand has been seen enlarged with stretched fingers in
// third person, lasting until the game is restarted. To find out when and in
// which values that happens, every 16th main scene draw the third-person
// skeleton's left hand, finger and forearm nodes are compared with what they
// were when first seen: local scale, world scale, the length of the local
// translation (a bone's length; animation turns bones but does not stretch
// them) and how far the local rotation is from a pure rotation. A departure
// is logged once per node and value, with the frame and state it appeared in.
struct HandWatchEntry {
    uintptr_t node = 0;
    char name[32] = {};
    float localScale = 0.0f;
    float worldScale = 0.0f;
    float boneLength = 0.0f;
    uint8_t reported = 0;       // bit per value
    // For the finger length fix: the length is trusted only after it has
    // read the same on eight checks in a row (a blend in progress changes it
    // every frame), and only if the same bone of the other hand agrees.
    float steadyLength = 0.0f;
    uint8_t steadyCount = 0;
    int8_t otherHand = -1;      // index of the mirrored bone, -2 if none
};
struct HandWatchEvent {
    char name[32];
    uint32_t frame;
    uint8_t value;              // 0 local scale, 1 world scale, 2 length, 3 rotation
    uint8_t firstPerson;
    uint8_t tick;
    uint8_t frozen;
    float before;
    float after;
};
std::array<HandWatchEntry, 96> g_handWatch{};
std::array<HandWatchEvent, 64> g_handEvents{};
std::atomic<uint32_t> g_handEventCount{0};
uint32_t g_handEventsLogged = 0;
uint32_t g_handWatchCounter = 0;
uintptr_t g_handWatchRoot = 0;
volatile LONG g_handStatNodes = 0;
volatile LONG g_handStatChecks = 0;

// Write trace. Measured with the watch above: all fifteen left finger bones
// had their local translation multiplied by the same 1.0894 at once. To find
// the code that does it, the x component of one finger bone's local
// translation gets a hardware write breakpoint on the thread that renders
// (set from the log thread, since a thread cannot reliably set its own debug
// registers). The exception handler looks at the value just written; when it
// differs from the last one by more than 2 % it records the address after
// the writing instruction and the return addresses found on the stack.
struct HandWriteEvent {
    uint32_t instruction;
    uint32_t returns[12];
    float before;
    float after;
    uint32_t frame;
    uint8_t tick;
    uint8_t frozen;
};
std::array<HandWriteEvent, 48> g_handWriteEvents{};
std::atomic<uint32_t> g_handWriteEventCount{0};
uint32_t g_handWriteEventsLogged = 0;
std::atomic<uintptr_t> g_handTraceWanted{0};    // address to watch
std::atomic<uintptr_t> g_handTraceArmed{0};     // address the breakpoint is on
std::atomic<uint32_t> g_handTraceThreadId{0};
std::atomic<uint32_t> g_handTraceLastBits{0};
volatile LONG g_handTraceHits = 0;
volatile LONG g_handTraceArmings = 0;
float g_handRatio = 1.0f;       // finger bone length now / when first seen

LONG CALLBACK HandWriteTraceHandler(EXCEPTION_POINTERS *info) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    CONTEXT *context = info->ContextRecord;
    if ((context->Dr6 & 1) == 0) return EXCEPTION_CONTINUE_SEARCH;
    context->Dr6 &= ~static_cast<DWORD>(0xF);
    const uintptr_t address = g_handTraceArmed.load(std::memory_order_relaxed);
    if (address == 0 || context->Dr0 != address) return EXCEPTION_CONTINUE_EXECUTION;
    InterlockedIncrement(&g_handTraceHits);
    const uint32_t bits = *reinterpret_cast<volatile const uint32_t *>(address);
    const uint32_t previousBits = g_handTraceLastBits.exchange(bits, std::memory_order_relaxed);
    float before = 0.0f;
    float after = 0.0f;
    std::memcpy(&before, &previousBits, sizeof(before));
    std::memcpy(&after, &bits, sizeof(after));
    if (previousBits == 0 || !(std::fabs(before) > 0.5f)) return EXCEPTION_CONTINUE_EXECUTION;
    if (std::fabs(after - before) <= std::fabs(before) * 0.02f) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    const uint32_t index = g_handWriteEventCount.load(std::memory_order_relaxed);
    if (index >= g_handWriteEvents.size()) return EXCEPTION_CONTINUE_EXECUTION;
    HandWriteEvent &event = g_handWriteEvents[index];
    event = {};
    event.instruction = context->Eip;
    event.before = before;
    event.after = after;
    event.frame = static_cast<uint32_t>(g_renderTranslationEligibleFrames);
    event.tick = g_currentPulse.load(std::memory_order_relaxed) != 0 ? 1 : 0;
    const uintptr_t tesMain = *reinterpret_cast<volatile const uintptr_t *>(kTESMainSingleton);
    event.frozen = tesMain >= 0x10000 &&
        *reinterpret_cast<volatile const uint8_t *>(tesMain + 7) != 0 ? 1 : 0;
    // Return addresses: stack words that point into the executable's code
    // just after a call instruction.
    const uintptr_t stackBase = __readfsdword(0x04);
    size_t found = 0;
    for (uintptr_t slot = context->Esp;
         slot + 4 <= stackBase && slot < context->Esp + 0x600 && found < 12; slot += 4) {
        const uint32_t value = *reinterpret_cast<const uint32_t *>(slot);
        if (value < 0x00401006 || value >= 0x00D9A000) continue;
        const auto *code = reinterpret_cast<const uint8_t *>(value);
        if (code[-5] == 0xE8 || code[-2] == 0xFF || code[-3] == 0xFF || code[-6] == 0xFF) {
            event.returns[found++] = value;
        }
    }
    g_handWriteEventCount.store(index + 1, std::memory_order_release);
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Log thread: puts the breakpoint where the watch asked for it.
void ServiceHandWriteTrace() {
    const uintptr_t wanted = g_handTraceWanted.load(std::memory_order_acquire);
    const uint32_t threadId = g_handTraceThreadId.load(std::memory_order_acquire);
    if (wanted == g_handTraceArmed.load(std::memory_order_relaxed) || threadId == 0) return;
    HANDLE thread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
    if (thread == nullptr) return;
    if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &context)) {
            context.Dr0 = wanted;
            // Local enable 0; break on write; four bytes.
            context.Dr7 &= ~static_cast<DWORD>(0x000F0003);
            if (wanted != 0) context.Dr7 |= 0x000D0001;
            context.Dr6 = 0;
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (SetThreadContext(thread, &context)) {
                g_handTraceLastBits.store(0, std::memory_order_relaxed);
                g_handTraceArmed.store(wanted, std::memory_order_release);
                InterlockedIncrement(&g_handTraceArmings);
            }
        }
        ResumeThread(thread);
    }
    CloseHandle(thread);
}

void RecordHandEvent(const HandWatchEntry &entry, uint8_t value, float before, float after,
                     bool firstPerson) {
    const uint32_t index = g_handEventCount.load(std::memory_order_relaxed);
    if (index >= g_handEvents.size()) return;
    HandWatchEvent &event = g_handEvents[index];
    std::memcpy(event.name, entry.name, sizeof(event.name));
    event.frame = static_cast<uint32_t>(g_renderTranslationEligibleFrames);
    event.value = value;
    event.firstPerson = firstPerson ? 1 : 0;
    event.tick = g_currentPulse.load(std::memory_order_relaxed) != 0 ? 1 : 0;
    const uintptr_t tesMain = ReadEngineValue<uintptr_t>(kTESMainSingleton);
    event.frozen = tesMain >= 0x10000 && ReadEngineValue<uint8_t>(tesMain + 7) != 0 ? 1 : 0;
    event.before = before;
    event.after = after;
    g_handEventCount.store(index + 1, std::memory_order_release);
}

void WatchLeftHand(uintptr_t player, bool firstPerson) {
    if ((++g_handWatchCounter & 15) != 0) return;
    __try {
        const uintptr_t renderState = ReadEngineValue<uintptr_t>(player + 0x5C);
        const uintptr_t rootNode = renderState >= 0x10000
            ? ReadEngineValue<uintptr_t>(renderState + 0x14) : 0;
        if (rootNode < 0x10000) return;
        if (rootNode != g_handWatchRoot) {
            // A new skeleton: start again from what it looks like now.
            g_handWatchRoot = rootNode;
            for (HandWatchEntry &entry : g_handWatch) entry = {};
        }
        InterlockedIncrement(&g_handStatChecks);
        LONG nodes = 0;
        uintptr_t stack[512];
        size_t top = 0;
        stack[top++] = rootNode;
        while (top != 0) {
            const uintptr_t object = stack[--top];
            if (object < 0x10000) continue;
            if (IsSceneNode(object)) {
                const uintptr_t children = ReadEngineValue<uintptr_t>(object + 0xA0);
                const uint32_t count = ReadEngineValue<uint16_t>(object + 0xA6);
                if (children >= 0x10000 && count <= 1024) {
                    for (uint32_t index = 0; index < count && top < 512; ++index) {
                        stack[top++] = ReadEngineValue<uintptr_t>(children + index * 4);
                    }
                }
            }
            const uintptr_t nameAddress = ReadEngineValue<uintptr_t>(object + 0x08);
            if (nameAddress < 0x10000) continue;
            const auto *text = reinterpret_cast<const char *>(nameAddress);
            char name[32] = {};
            size_t length = 0;
            while (length + 1 < sizeof(name) && text[length] != '\0') {
                const char c = text[length];
                name[length] = (c >= 0x20 && c < 0x7F && c != ',') ? c : '?';
                ++length;
            }
            const bool left = std::strstr(name, " L ") != nullptr ||
                std::strstr(name, "PipBoy") != nullptr ||
                std::strstr(name, "Pipboy") != nullptr;
            const bool part = std::strstr(name, "Hand") != nullptr ||
                std::strstr(name, "Finger") != nullptr ||
                std::strstr(name, "Thumb") != nullptr ||
                std::strstr(name, "Forearm") != nullptr ||
                std::strstr(name, "ForeTwist") != nullptr ||
                std::strstr(name, "Pip") != nullptr;
            const bool finger = std::strstr(name, "Finger") != nullptr ||
                std::strstr(name, "Thumb") != nullptr;
            if (!finger && (!left || !part)) continue;
            ++nodes;

            float local[13];
            std::memcpy(local, reinterpret_cast<const void *>(object + kNodeLocalTransform),
                        sizeof(local));
            const float worldScale =
                ReadEngineValue<float>(object + kNodeWorldTransform + 48);
            const float boneLength = std::sqrt(local[9] * local[9] + local[10] * local[10] +
                                               local[11] * local[11]);
            // Largest departure of the rotation's rows from unit length.
            float rotationError = 0.0f;
            for (int row = 0; row < 3; ++row) {
                const float norm = local[row * 3] * local[row * 3] +
                    local[row * 3 + 1] * local[row * 3 + 1] +
                    local[row * 3 + 2] * local[row * 3 + 2];
                const float error = std::fabs(norm - 1.0f);
                if (!(error <= rotationError)) rotationError = error;
            }

            HandWatchEntry *entry = nullptr;
            for (HandWatchEntry &candidate : g_handWatch) {
                if (candidate.node == object || candidate.node == 0) {
                    entry = &candidate;
                    break;
                }
            }
            if (entry == nullptr) continue;
            if (entry->node == object && entry->steadyCount < 8) {
                if (entry->steadyLength > 0.0f &&
                    std::fabs(boneLength - entry->steadyLength) <=
                        entry->steadyLength * 0.001f) {
                    ++entry->steadyCount;
                } else {
                    entry->steadyLength = boneLength;
                    entry->steadyCount = 0;
                }
            }
            if (std::strcmp(name, "Bip01 L Finger1") == 0) {
                if (entry->node == object && entry->boneLength > 0.0f) {
                    g_handRatio = boneLength / entry->boneLength;
                }
                if (g_debugHandWriteTrace) {
                    g_handTraceThreadId.store(GetCurrentThreadId(),
                                              std::memory_order_release);
                    g_handTraceWanted.store(object + kNodeLocalTransform + 36,
                                            std::memory_order_release);
                }
            }
            if (entry->node == 0) {
                entry->node = object;
                std::memcpy(entry->name, name, sizeof(entry->name));
                entry->localScale = local[12];
                entry->worldScale = worldScale;
                entry->boneLength = boneLength;
                entry->reported = 0;
                // Already wrong when first seen is worth knowing too.
                if (rotationError > 0.02f) {
                    entry->reported |= 8;
                    RecordHandEvent(*entry, 3, 0.0f, rotationError, firstPerson);
                }
                continue;
            }
            const auto departs = [](float before, float after, float relative,
                                    float absolute) {
                return !(std::fabs(after - before) <=
                         std::fabs(before) * relative + absolute);
            };
            if ((entry->reported & 1) == 0 &&
                departs(entry->localScale, local[12], 0.02f, 0.0f)) {
                entry->reported |= 1;
                RecordHandEvent(*entry, 0, entry->localScale, local[12], firstPerson);
            }
            if ((entry->reported & 2) == 0 &&
                departs(entry->worldScale, worldScale, 0.02f, 0.0f)) {
                entry->reported |= 2;
                RecordHandEvent(*entry, 1, entry->worldScale, worldScale, firstPerson);
            }
            if ((entry->reported & 4) == 0 &&
                departs(entry->boneLength, boneLength, 0.05f, 0.05f)) {
                entry->reported |= 4;
                RecordHandEvent(*entry, 2, entry->boneLength, boneLength, firstPerson);
            }
            if ((entry->reported & 8) == 0 && rotationError > 0.02f) {
                entry->reported |= 8;
                RecordHandEvent(*entry, 3, 0.0f, rotationError, firstPerson);
            }
        }
        InterlockedExchange(&g_handStatNodes, nodes);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// --- Finger length fix ("spider hands") -------------------------------------------------
// Measured with the write trace: the finger bones' local translations are
// written by the multi-target transform controller update at 0049DB10
// (reached from the frame function through 006E47A5, 0078AC61, 0070D81F,
// 0045CE67, 0049DE70) with whatever its blend interpolator returns, and while
// animations are being blended that value is the bone's translation times a
// factor that is not 1 and changes from frame to frame (0.81 to 1.21 seen
// between consecutive frames). When the blend ends on such a value and the
// bone is not written again, the hand stays stretched or shrunk.
//
// A finger bone does not change length, so this puts the translation of every
// finger and thumb bone of the player's third-person skeleton back to the
// length recorded when the skeleton was first seen, keeping its direction.
// Unlike everything else here this changes a value the engine keeps: the
// local translation is not restored afterwards. It runs before the main
// scene draw, on bones already found by the watch above.
volatile LONG g_fingerStatFixes = 0;
volatile LONG g_fingerStatBones = 0;

volatile LONG g_fingerStatHandsDisagree = 0;

void FixFingerLengths(uintptr_t player) {
    __try {
        const uintptr_t renderState = ReadEngineValue<uintptr_t>(player + 0x5C);
        const uintptr_t rootNode = renderState >= 0x10000
            ? ReadEngineValue<uintptr_t>(renderState + 0x14) : 0;
        // The watch owns the list; it is only valid for the skeleton it
        // was built from.
        if (rootNode < 0x10000 || rootNode != g_handWatchRoot) return;
        LONG bones = 0;
        LONG disagree = 0;
        for (size_t index = 0; index < g_handWatch.size(); ++index) {
            HandWatchEntry &entry = g_handWatch[index];
            if (entry.node == 0) break;
            if (std::strstr(entry.name, "Finger") == nullptr &&
                std::strstr(entry.name, "Thumb") == nullptr) continue;
            if (entry.steadyCount < 8 || !(entry.steadyLength > 0.05f)) continue;
            if (entry.otherHand == -1) {
                // "Bip01 L Finger1" <-> "Bip01 R Finger1".
                entry.otherHand = -2;
                char mirrored[32];
                std::memcpy(mirrored, entry.name, sizeof(mirrored));
                char *side = std::strstr(mirrored, " L ");
                if (side != nullptr) {
                    side[1] = 'R';
                } else if ((side = std::strstr(mirrored, " R ")) != nullptr) {
                    side[1] = 'L';
                }
                for (size_t other = 0; side != nullptr && other < g_handWatch.size();
                     ++other) {
                    if (g_handWatch[other].node == 0) break;
                    if (std::strcmp(g_handWatch[other].name, mirrored) == 0) {
                        entry.otherHand = static_cast<int8_t>(other);
                        break;
                    }
                }
                // Not found yet: look again once the list has grown.
                if (entry.otherHand == -2 && side != nullptr) entry.otherHand = -1;
            }
            if (entry.otherHand < 0) continue;
            const HandWatchEntry &mirror = g_handWatch[entry.otherHand];
            if (mirror.steadyCount < 8) continue;
            if (std::fabs(mirror.steadyLength - entry.steadyLength) >
                entry.steadyLength * 0.01f) {
                // One of the two was already wrong when recorded; there is
                // no telling which, so neither is touched.
                ++disagree;
                continue;
            }
            ++bones;
            auto *translation =
                reinterpret_cast<float *>(entry.node + kNodeLocalTransform + 36);
            const float x = translation[0];
            const float y = translation[1];
            const float z = translation[2];
            const float length = std::sqrt(x * x + y * y + z * z);
            if (!(length > 0.01f) || !std::isfinite(length)) continue;
            if (std::fabs(length - entry.steadyLength) <= entry.steadyLength * 0.005f) {
                continue;
            }
            const float factor = entry.steadyLength / length;
            translation[0] = x * factor;
            translation[1] = y * factor;
            translation[2] = z * factor;
            InterlockedIncrement(&g_fingerStatFixes);
        }
        InterlockedExchange(&g_fingerStatBones, bones);
        InterlockedExchange(&g_fingerStatHandsDisagree, disagree);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// --- Cost of the pre-draw work ---------------------------------------------------------
// Time spent in the main scene draw hook before the stock draw, and in two of
// its parts, summed in performance-counter ticks.
volatile LONG64 g_perfPreDrawTicks = 0;
volatile LONG64 g_perfActorPassTicks = 0;
volatile LONG64 g_perfBodyPassTicks = 0;
volatile LONG g_perfDraws = 0;

int64_t PerfNow() {
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    return now.QuadPart;
}

// --- First person: camera position from the camera bone --------------------------------
// In first person the scene camera sits at the world position of the camera
// bone of the first-person skeleton (measured: equal to 0.001). Crouching,
// standing up and view animations move that bone on ticks; looking up or down
// moves it every frame through nodes that are not blended. The camera's
// correction is the bone's position worked out with the blended locals minus
// the same with the engine's locals, so the per-frame part cancels and only
// the tick-driven part is interpolated. This replaces the eye-height pair,
// which had to stop blending whenever the view pitch moved during a crouch.
volatile LONG g_cameraBoneStatApplied = 0;
volatile LONG g_cameraBoneStatMismatch = 0;

bool ComputeCameraBoneDelta(uintptr_t player, const float *cameraPosition, float *delta) {
    delta[0] = delta[1] = delta[2] = 0.0f;
    FirstPersonAdvance();
    if (!g_fpAdvanced || g_fpPendingCount == 0) return false;
    __try {
        const uintptr_t rootNode = ReadEngineValue<uintptr_t>(player + 0x5F0);
        const uintptr_t cameraNode = ReadEngineValue<uintptr_t>(kFirstPersonCameraNode);
        if (rootNode < 0x10000 || cameraNode < 0x10000 || cameraNode == rootNode) {
            return false;
        }
        float enginePosition[3] = {0.0f, 0.0f, 0.0f};
        float blendedPosition[3] = {0.0f, 0.0f, 0.0f};
        bool anyBlended = false;
        bool reachedRoot = false;
        bool first = true;
        uintptr_t node = cameraNode;
        for (int depth = 0; depth < 32 && node >= 0x10000; ++depth) {
            if (node == rootNode) {
                reachedRoot = true;
                break;
            }
            float engineLocal[13];
            std::memcpy(engineLocal,
                        reinterpret_cast<const void *>(node + kNodeLocalTransform),
                        sizeof(engineLocal));
            const float *blendedLocal = engineLocal;
            for (size_t index = 0; index < g_fpPendingCount; ++index) {
                if (g_fpPending[index].node != node) continue;
                if (std::memcmp(engineLocal, g_fpPending[index].pose.value.data(),
                                sizeof(engineLocal)) == 0) {
                    blendedLocal = g_fpPending[index].written.value.data();
                    anyBlended = true;
                }
                break;
            }
            if (first) {
                // The bone's own position in its parent's frame.
                for (int axis = 0; axis < 3; ++axis) {
                    enginePosition[axis] = engineLocal[9 + axis];
                    blendedPosition[axis] = blendedLocal[9 + axis];
                }
                first = false;
            } else {
                float moved[3];
                for (int row = 0; row < 3; ++row) {
                    moved[row] = (engineLocal[row * 3 + 0] * enginePosition[0] +
                                  engineLocal[row * 3 + 1] * enginePosition[1] +
                                  engineLocal[row * 3 + 2] * enginePosition[2]) *
                                     engineLocal[12] + engineLocal[9 + row];
                }
                std::memcpy(enginePosition, moved, sizeof(moved));
                for (int row = 0; row < 3; ++row) {
                    moved[row] = (blendedLocal[row * 3 + 0] * blendedPosition[0] +
                                  blendedLocal[row * 3 + 1] * blendedPosition[1] +
                                  blendedLocal[row * 3 + 2] * blendedPosition[2]) *
                                     blendedLocal[12] + blendedLocal[9 + row];
                }
                std::memcpy(blendedPosition, moved, sizeof(moved));
            }
            node = ReadEngineValue<uintptr_t>(node + 0x18);
        }
        if (!reachedRoot || !anyBlended) return false;

        float root[13];
        std::memcpy(root, reinterpret_cast<const void *>(rootNode + kNodeWorldTransform),
                    sizeof(root));
        float result[3];
        for (int row = 0; row < 3; ++row) {
            const float engineWorld = (root[row * 3 + 0] * enginePosition[0] +
                                       root[row * 3 + 1] * enginePosition[1] +
                                       root[row * 3 + 2] * enginePosition[2]) *
                                          root[12] + root[9 + row];
            // The camera has to be where the engine's bone is, or it is not
            // following the bone on this frame.
            if (!(std::fabs(engineWorld - cameraPosition[row]) <= 0.05f)) {
                InterlockedIncrement(&g_cameraBoneStatMismatch);
                return false;
            }
            result[row] = (root[row * 3 + 0] * (blendedPosition[0] - enginePosition[0]) +
                           root[row * 3 + 1] * (blendedPosition[1] - enginePosition[1]) +
                           root[row * 3 + 2] * (blendedPosition[2] - enginePosition[2])) *
                              root[12];
            if (!(std::fabs(result[row]) <= 30.0f)) return false;
        }
        if (std::fabs(result[0]) <= 0.0001f && std::fabs(result[1]) <= 0.0001f &&
            std::fabs(result[2]) <= 0.0001f) return false;
        std::memcpy(delta, result, sizeof(result));
        InterlockedIncrement(&g_cameraBoneStatApplied);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        delta[0] = delta[1] = delta[2] = 0.0f;
        return false;
    }
}

// --- Third person: the player's body ------------------------------------------------
// The body turns with the mouse on every frame, so its nodes' world transforms
// change on every frame and the per-node world blend used for other actors
// sees nothing but off-tick moves. Here each node's pose is taken relative to
// its parent, computed from the two world transforms (not from the engine's
// local-transform fields). A node driven every frame is recognised and shown
// as it is; every other relative pose changes on ticks only (animation) and
// is blended. The world poses are rebuilt from the root down, the root
// carrying the camera's translation correction. Written before the main
// scene draw, put back after it.
struct BodyPoseHistory {
    uintptr_t node = 0;
    uint32_t lastSeen = 0;
    uint32_t changePeriod = 0;
    uint8_t offTickScore = 0;   // +4 per off-tick change, -1 per draw
    bool lag = false;           // the last change arrived on the draw after its tick
    uint32_t lastChange = 0;    // draw serial of the last change
    NodePose from{};
    NodePose to{};
};
std::array<BodyPoseHistory, 2048> g_bodyHistory{};
bool g_bodyPreviousDrawWasTick = false;
double g_bodyPreviousDrawAlpha = 0.0;
// Relative-pose changes by draw kind: tick, after a tick, both, neither.
volatile LONG g_bodyStatChanges[4] = {};
// Off-tick changes too small to act on (see ApplyPlayerBodyPose).
volatile LONG g_bodyStatMinor = 0;
std::array<SavedNodePose, 1024> g_bodySaved{};
size_t g_bodySavedCount = 0;
uint32_t g_bodySerial = 1;
uint32_t g_bodyTickCount = 0;
volatile LONG g_bodyStatNodesWritten = 0;
volatile LONG g_bodyStatBlends = 0;
volatile LONG g_bodyStatOffTick = 0;
volatile LONG g_bodyStatRestoreConflicts = 0;

void ComposePose(const NodePose &root, const NodePose &relative, NodePose &out) {
    const float *r = root.value.data();
    const float *l = relative.value.data();
    for (size_t row = 0; row < 3; ++row) {
        for (size_t column = 0; column < 3; ++column) {
            out.value[row * 3 + column] = r[row * 3 + 0] * l[0 + column] +
                r[row * 3 + 1] * l[3 + column] + r[row * 3 + 2] * l[6 + column];
        }
        out.value[9 + row] = (r[row * 3 + 0] * l[9] + r[row * 3 + 1] * l[10] +
                              r[row * 3 + 2] * l[11]) * r[12] + r[9 + row];
    }
    out.value[12] = r[12] * l[12];
}

// Relative poses are recomputed from world transforms every draw, so they
// carry rounding noise; only a real change counts.
bool RelativePoseDiffers(const NodePose &left, const NodePose &right) {
    for (size_t index = 0; index < kPoseFloats; ++index) {
        const float tolerance = (index >= 9 && index < 12) ? 0.005f : 0.0001f;
        if (!(std::fabs(left.value[index] - right.value[index]) <= tolerance)) return true;
    }
    return false;
}

void RestorePlayerBodyPose() {
    __try {
        for (size_t index = g_bodySavedCount; index-- > 0;) {
            const SavedNodePose &saved = g_bodySaved[index];
            auto *live = reinterpret_cast<void *>(saved.node + kNodeWorldTransform);
            if (std::memcmp(live, saved.written.value.data(),
                            sizeof(saved.written.value)) != 0) {
                InterlockedIncrement(&g_bodyStatRestoreConflicts);
                continue;
            }
            std::memcpy(live, saved.pose.value.data(), sizeof(saved.pose.value));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    g_bodySavedCount = 0;
}

bool ApplyPlayerBodyPose(uintptr_t player, const std::array<float, 3> &correction,
                         bool interpolate) {
    g_bodySavedCount = 0;
    __try {
        const bool frameIsTick = g_currentPulse.load(std::memory_order_relaxed) != 0;
        double frameAlpha = g_accumulatorMs / g_simulationStepMs;
        if (frameAlpha < 0.0) frameAlpha = 0.0;
        if (frameAlpha > 1.0) frameAlpha = 1.0;
        const uint32_t ticksBefore = g_bodyTickCount;
        if (frameIsTick) ++g_bodyTickCount;
        ++g_bodySerial;
        const bool previousWasTick = g_bodyPreviousDrawWasTick;
        const double previousAlpha = g_bodyPreviousDrawAlpha;
        g_bodyPreviousDrawWasTick = frameIsTick;
        g_bodyPreviousDrawAlpha = frameAlpha;
        const int frameKind = frameIsTick ? (previousWasTick ? 2 : 0)
                                          : (previousWasTick ? 1 : 3);
        const uintptr_t renderState = ReadEngineValue<uintptr_t>(player + 0x5C);
        const uintptr_t rootNode = renderState >= 0x10000
            ? ReadEngineValue<uintptr_t>(renderState + 0x14) : 0;
        if (rootNode < 0x10000) return false;
        NodePose rootEngine{};
        std::memcpy(rootEngine.value.data(),
                    reinterpret_cast<const void *>(rootNode + kNodeWorldTransform),
                    sizeof(rootEngine.value));
        NodePose rootShown = rootEngine;
        const bool corrected = correction[0] != 0.0f || correction[1] != 0.0f ||
            correction[2] != 0.0f;
        for (size_t axis = 0; axis < 3; ++axis) rootShown.value[9 + axis] += correction[axis];

        // Each node is taken relative to its parent, and the world pose is
        // rebuilt from the top down. A node that is driven every frame (the
        // one that carries the turning, wherever in the tree it sits) is then
        // the only one shown as it is; the nodes below it still blend.
        static uintptr_t stackNode[512];
        static NodePose stackParentEngine[512];
        static NodePose stackParentShown[512];
        static bool stackParentMoved[512];
        size_t top = 0;
        stackNode[top] = rootNode;
        stackParentEngine[top] = rootEngine;
        stackParentShown[top] = rootShown;
        stackParentMoved[top] = false;
        ++top;
        while (top != 0) {
            --top;
            const uintptr_t object = stackNode[top];
            const NodePose parentEngine = stackParentEngine[top];
            const NodePose parentShown = stackParentShown[top];
            const bool parentMoved = stackParentMoved[top];
            if (object < 0x10000) continue;
            NodePose engine{};
            std::memcpy(engine.value.data(),
                        reinterpret_cast<const void *>(object + kNodeWorldTransform),
                        sizeof(engine.value));
            NodePose shown = rootShown;
            bool blended = false;
            if (object != rootNode) {
                NodePose relative{};
                RelativePose(parentEngine, engine, relative);
                NodePose shownRelative = relative;
                BodyPoseHistory *history = nullptr;
                size_t slot = (object >> 4) & (g_bodyHistory.size() - 1);
                for (size_t probe = 0; probe < 32; ++probe) {
                    BodyPoseHistory &entry = g_bodyHistory[slot];
                    if (entry.node == object) {
                        history = &entry;
                        break;
                    }
                    if (entry.node == 0) {
                        if (history == nullptr) history = &entry;
                        break;
                    }
                    if (history == nullptr && entry.lastSeen + 600 < g_bodySerial) {
                        history = &entry;
                    }
                    slot = (slot + 1) & (g_bodyHistory.size() - 1);
                }
                if (history != nullptr) {
                    const bool known = history->node == object &&
                        history->lastSeen + 1 == g_bodySerial;
                    history->node = object;
                    history->lastSeen = g_bodySerial;
                    if (!known) {
                        history->from = relative;
                        history->to = relative;
                        history->changePeriod = 0;
                        history->offTickScore = 0;
                    } else {
                        if (history->offTickScore != 0) --history->offTickScore;
                        if (RelativePoseDiffers(relative, history->to)) {
                            InterlockedIncrement(&g_bodyStatChanges[frameKind]);
                            // A pose arrives either on the tick draw or on
                            // the draw after it (standing and crouched
                            // animation were seen to differ). A change on
                            // the draw after a tick counts as that tick's,
                            // unless the node also changed on the tick draw
                            // itself, which means it moves every frame.
                            const bool changedLastDraw =
                                history->lastChange + 1 == g_bodySerial;
                            history->lastChange = g_bodySerial;
                            const bool lagged = frameKind == 1 && !changedLastDraw;
                            bool offTick = !frameIsTick && !lagged;
                            if (offTick) {
                                // Foot placement re-solves the legs whenever
                                // the body turns, between ticks as well, by
                                // small amounts. Treating that as "driven
                                // every frame" left the legs un-blended. A
                                // small off-tick change is let through: the
                                // tick-to-tick blend carries on, and the
                                // adjustment is picked up at the next tick.
                                float rotationStep = 0.0f;
                                float translationStep = 0.0f;
                                for (size_t index = 0; index < kPoseFloats; ++index) {
                                    const float difference = std::fabs(
                                        relative.value[index] - history->to.value[index]);
                                    float &largest = (index >= 9 && index < 12)
                                        ? translationStep : rotationStep;
                                    if (!(difference <= largest)) largest = difference;
                                }
                                if (rotationStep <= 0.03f && translationStep <= 0.5f) {
                                    InterlockedIncrement(&g_bodyStatMinor);
                                    history->lastChange = g_bodySerial - 1;
                                    offTick = false;
                                    goto minorChangeDone;
                                }
                            }
                            if (offTick) {
                                history->offTickScore = static_cast<uint8_t>(
                                    history->offTickScore > 12 ? 16
                                                               : history->offTickScore + 4);
                                InterlockedIncrement(&g_bodyStatOffTick);
                            }
                            if (offTick || history->offTickScore >= 8) {
                                history->from = relative;
                                history->to = relative;
                                history->changePeriod = 0;
                            } else {
                                history->from = history->to;
                                history->to = relative;
                                history->lag = lagged;
                                history->changePeriod =
                                    lagged ? ticksBefore : g_bodyTickCount;
                            }
                        }
                    minorChangeDone:
                        const uint32_t period =
                            history->lag ? ticksBefore : g_bodyTickCount;
                        if (history->changePeriod != 0 &&
                            history->changePeriod == period) {
                            float stepSquared = 0.0f;
                            for (size_t axis = 9; axis < 12; ++axis) {
                                const float delta =
                                    history->to.value[axis] - history->from.value[axis];
                                stepSquared += delta * delta;
                            }
                            if (stepSquared <= 900.0f &&
                                BlendPose(history->from, history->to,
                                          history->lag ? previousAlpha : frameAlpha,
                                          shownRelative)) {
                                blended = true;
                                InterlockedIncrement(&g_bodyStatBlends);
                            } else {
                                shownRelative = relative;
                            }
                        }
                    }
                }
                ComposePose(parentShown, shownRelative, shown);
            }
            const bool moved = parentMoved || blended;
            if (IsSceneNode(object)) {
                const uintptr_t children = ReadEngineValue<uintptr_t>(object + 0xA0);
                const uint32_t count = ReadEngineValue<uint16_t>(object + 0xA6);
                if (children >= 0x10000 && count <= 1024) {
                    for (uint32_t index = 0; index < count && top < 512; ++index) {
                        stackNode[top] = ReadEngineValue<uintptr_t>(children + index * 4);
                        stackParentEngine[top] = engine;
                        stackParentShown[top] = shown;
                        stackParentMoved[top] = moved;
                        ++top;
                    }
                }
            }
            // Rebuilding a pose that is neither moved nor blended would only
            // write rounding noise.
            if (!interpolate || (!corrected && !moved)) continue;
            bool finite = true;
            for (size_t index = 0; index < kPoseFloats; ++index) {
                finite = finite && std::isfinite(shown.value[index]);
            }
            if (!finite || g_bodySavedCount >= g_bodySaved.size()) continue;
            SavedNodePose &saved = g_bodySaved[g_bodySavedCount++];
            saved.node = object;
            saved.pose = engine;
            saved.written = shown;
            std::memcpy(reinterpret_cast<void *>(object + kNodeWorldTransform),
                        shown.value.data(), sizeof(shown.value));
            InterlockedIncrement(&g_bodyStatNodesWritten);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return g_bodySavedCount != 0;
}

// --- Third person: the camera ---------------------------------------------------------
// The camera's position relative to the player is written as
// height * up + back * forward + side * right, with `forward` the camera's
// view direction and `right` horizontal. Turning the camera with the mouse
// changes the directions every frame but not the three numbers; crouching,
// zooming and the engine's own smoothing change the numbers, on ticks. Each
// number therefore gets a tick-aligned from/to pair, like the first-person
// eye height, and stops being blended for a while if it is seen to change
// off a tick (which would mean this description does not fit).
struct TickTrack {
    float from = 0.0f;
    float to = 0.0f;
    uint8_t score = 0;
    bool valid = false;
};
TickTrack g_thirdPersonTracks[3]{};
volatile LONG g_thirdPersonStatSteps = 0;
volatile LONG g_thirdPersonStatOffTick = 0;

float AdvanceTickTrack(TickTrack &track, float value, bool tick, double alpha,
                       float tolerance) {
    if (track.score != 0) --track.score;
    if (!track.valid || !std::isfinite(value)) {
        track.from = track.to = value;
        track.valid = std::isfinite(value);
        track.score = 0;
        return value;
    }
    const float step = std::fabs(value - track.to);
    if (step > tolerance) {
        if (!tick) {
            track.score = static_cast<uint8_t>(track.score > 12 ? 16 : track.score + 4);
            track.from = value;
            InterlockedIncrement(&g_thirdPersonStatOffTick);
        } else if (track.score >= 8 || step > 40.0f) {
            track.from = value;
        } else {
            track.from = track.to;
            InterlockedIncrement(&g_thirdPersonStatSteps);
        }
        track.to = value;
    } else if (tick) {
        track.from = track.to;
    }
    return static_cast<float>(track.from +
                              (static_cast<double>(track.to) - track.from) * alpha);
}

// --- Field of view ----------------------------------------------------------------
// Aiming changes two fields of the player on ticks: the world field of view
// (+0x5D0) and the first-person one (+0x5D4). The frame function (call at
// 006EDFE8) and the render passes hand them to FUN_00AAEAF0 (scene graph,
// field of view, three more arguments), which sets the camera frustum. Those
// calls are redirected here, and a value equal to one of the two fields is
// replaced by its interpolated value. The fields themselves are not touched.
constexpr uintptr_t kSetCameraFov = 0x00AAEAF0;
struct FovTrack {
    float from = 0.0f;
    float to = 0.0f;
    float shown = 0.0f;
    bool valid = false;
    bool lag = false;           // change first seen on the frame after its tick
    uint32_t changePeriod = 0;
};
FovTrack g_fovTracks[2]{};
// Diagnostic: one row per main scene draw for 40 draws after either field of
// view steps, to see what still moves at tick rate while aiming.
struct AimTraceRow {
    uint32_t frame = 0;
    uint8_t tick = 0;
    uint8_t firstPerson = 0;
    float alpha = 0.0f;
    float engineFov[2] = {};
    float shownFov[2] = {};
    float frustum[5] = {};          // scene camera +0xDC..+0xEC at the draw:
                                    // left, right, top, bottom, near
    float cameraOffset[3] = {};     // engine camera position minus player position
    float cameraForward[3] = {};    // first column of the camera's world rotation
};
std::array<AimTraceRow, 4096> g_aimTrace{};
std::atomic<uint32_t> g_aimTraceWrite{0};
uint32_t g_aimTraceRead = 0;
uint32_t g_aimTraceHot = 0;
uint32_t g_fovFrameSerial = 1;      // advanced at the start of every frame
uint32_t g_fovUpdatedFrame = 0;
uint32_t g_fovTickCount = 0;
bool g_fovPreviousFrameWasTick = false;
double g_fovPreviousFrameAlpha = 0.0;
volatile LONG g_fovStatSteps = 0;
volatile LONG g_fovStatSubstitutions = 0;
volatile LONG g_fovStatSites = 0;

void UpdateFovTracks(uintptr_t player) {
    const bool frameIsTick = g_currentPulse.load(std::memory_order_relaxed) != 0;
    double frameAlpha = g_accumulatorMs / g_simulationStepMs;
    if (frameAlpha < 0.0) frameAlpha = 0.0;
    if (frameAlpha > 1.0) frameAlpha = 1.0;
    const uint32_t ticksBefore = g_fovTickCount;
    if (frameIsTick) ++g_fovTickCount;
    const bool previousWasTick = g_fovPreviousFrameWasTick;
    const double previousAlpha = g_fovPreviousFrameAlpha;
    g_fovPreviousFrameWasTick = frameIsTick;
    g_fovPreviousFrameAlpha = frameAlpha;
    for (int index = 0; index < 2; ++index) {
        FovTrack &track = g_fovTracks[index];
        const float engine = ReadEngineValue<float>(player + 0x5D0 + index * 4);
        if (!track.valid || !std::isfinite(engine)) {
            track.from = track.to = track.shown = engine;
            track.valid = std::isfinite(engine);
            track.changePeriod = 0;
            continue;
        }
        if (engine != track.to) {
            const float step = std::fabs(engine - track.to);
            if ((!frameIsTick && !previousWasTick) || step > 30.0f) {
                // Changed away from a tick, or jumped: show it as it is.
                track.from = track.to = engine;
                track.changePeriod = 0;
            } else {
                track.from = track.to;
                track.to = engine;
                track.lag = !frameIsTick;
                track.changePeriod = track.lag ? ticksBefore : g_fovTickCount;
                InterlockedIncrement(&g_fovStatSteps);
                g_aimTraceHot = 0;      // aim trace retired; set to 40 to use it
            }
        }
        const uint32_t period = track.lag ? ticksBefore : g_fovTickCount;
        if (track.changePeriod != 0 && track.changePeriod == period) {
            const double alpha = track.lag ? previousAlpha : frameAlpha;
            track.shown = static_cast<float>(
                track.from + (static_cast<double>(track.to) - track.from) * alpha);
        } else {
            track.shown = track.to;
        }
    }
}

void __fastcall SetCameraFovHook(void *sceneGraph, void *, float fieldOfView,
                                 uint32_t arg1, uint32_t arg2, uint32_t arg3) {
    using SetCameraFovFn = void(__thiscall *)(void *, float, uint32_t, uint32_t, uint32_t);
    const auto stock = reinterpret_cast<SetCameraFovFn>(kSetCameraFov);
    float shown = fieldOfView;
    if (g_renderTranslationInterpolationEnabled && g_quantizedDeltaEnabled &&
        CaptureGateIsActive() && g_framePulseDecision >= 0) {
        __try {
            const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
            if (player >= 0x10000) {
                if (g_fovUpdatedFrame != g_fovFrameSerial) {
                    g_fovUpdatedFrame = g_fovFrameSerial;
                    UpdateFovTracks(player);
                }
                for (int index = 0; index < 2; ++index) {
                    const FovTrack &track = g_fovTracks[index];
                    if (!track.valid) continue;
                    const float engine =
                        ReadEngineValue<float>(player + 0x5D0 + index * 4);
                    if (std::memcmp(&engine, &fieldOfView, sizeof(engine)) != 0) continue;
                    if (track.shown != engine && std::isfinite(track.shown)) {
                        shown = track.shown;
                        InterlockedIncrement(&g_fovStatSubstitutions);
                    }
                    break;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            shown = fieldOfView;
        }
    }
    stock(sceneGraph, shown, arg1, arg2, arg3);
}

void __fastcall RenderTranslationInterpolationHook(
    void *renderContext, void *, uint32_t arg0, uint32_t arg1,
    uint32_t arg2, uint32_t arg3) {
    using SceneDrawFn = void(__thiscall *)(
        void *, uint32_t, uint32_t, uint32_t, uint32_t);
    const auto stock = reinterpret_cast<SceneDrawFn>(kSceneDraw);

    uintptr_t player = 0;
    uintptr_t cell = 0;
    uintptr_t renderer = 0;
    uintptr_t sceneGraph = 0;
    uintptr_t camera = 0;
    uintptr_t cameraParent = 0;
    std::array<uintptr_t, 4> nodes{};
    std::array<uintptr_t, 4> parents{};
    std::array<uintptr_t, 5> targets{};
    std::array<std::array<float, 3>, 5> originalPositions{};
    std::array<float, 3> currentPlayerPosition{};
    // False in third person: the camera and sky still follow the interpolated
    // player position, the four player roots are left to the pose pass (which
    // then includes the player's body), and nothing that depends on the
    // first-person skeleton is applied.
    bool firstPersonView = false;
    std::array<float, 3> playerCorrection{};
    const int64_t perfStart = PerfNow();
    bool apply = false;

    if (g_renderTranslationInterpolationEnabled &&
        !g_renderTranslationInterpolationFaulted &&
        g_quantizedDeltaEnabled && CaptureGateIsActive()) {
        __try {
            player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
            cell = player >= 0x10000
                ? ReadEngineValue<uintptr_t>(player + 0x3C) : 0;
            const bool firstPerson = player >= 0x10000 &&
                ReadEngineValue<uint8_t>(player + 0x5A8) == 0 &&
                ReadEngineValue<uint8_t>(player + 0x5A9) == 0;
            renderer = ReadEngineValue<uintptr_t>(kRendererSingleton);
            sceneGraph = ReadEngineValue<uintptr_t>(kSceneGraphSingleton);
            camera = sceneGraph >= 0x10000
                ? ReadEngineValue<uintptr_t>(sceneGraph + 0xAC) : 0;
            cameraParent = camera >= 0x10000
                ? ReadEngineValue<uintptr_t>(camera + 0x18) : 0;
            firstPersonView = firstPerson;
            if (!firstPersonView) InterlockedIncrement(&g_translationStatThirdPersonDraws);
            const bool nodesValid = player >= 0x10000 && cell >= 0x10000 &&
                ResolvePlayerTranslationNodes(player, nodes, parents);
            const bool eligible = nodesValid && renderer >= 0x10000 &&
                sceneGraph >= 0x10000 && camera >= 0x10000 &&
                cameraParent >= 0x10000 &&
                ReadEngineValue<uint32_t>(renderer + 0x200) == 2 &&
                ReadEngineValue<uint8_t>(renderer + 0x208) != 0 &&
                ReadEngineValue<uintptr_t>(renderer + 0x888) >= 0x10000;

            if (!eligible) {
                if (g_renderTranslationEligibleFrames != 0) {
                    InterlockedIncrement(&g_translationStatIneligibleResets);
                }
                ResetRenderTranslationInterpolation();
            } else {
                // The objects whose positions are tracked must stay the same.
                // Where they hang in the scene graph may change freely: the
                // engine re-parents the player and camera between cells and
                // between the rooms of an interior (for example at a doorway),
                // and their world positions stay continuous across that.
                const bool tracking = g_renderTranslationEligibleFrames != 0;
                const bool identityChanged = tracking &&
                    (g_renderTranslationPlayer != player ||
                     g_renderTranslationRenderer != renderer ||
                     g_renderTranslationSceneGraph != sceneGraph ||
                     g_renderTranslationCamera != camera ||
                     g_renderTranslationNodes != nodes);
                if (tracking && g_renderTranslationCell != cell) {
                    InterlockedIncrement(&g_translationStatCellChanges);
                }
                if (tracking && (g_renderTranslationCameraParent != cameraParent ||
                                 g_renderTranslationParents != parents)) {
                    InterlockedIncrement(&g_translationStatParentChanges);
                }
                if (identityChanged) {
                    InterlockedIncrement(&g_translationStatIdentityResets);
                    ResetRenderTranslationInterpolation();
                }
                g_renderTranslationPlayer = player;
                g_renderTranslationCell = cell;
                g_renderTranslationRenderer = renderer;
                g_renderTranslationSceneGraph = sceneGraph;
                g_renderTranslationCamera = camera;
                g_renderTranslationCameraParent = cameraParent;
                g_renderTranslationNodes = nodes;
                g_renderTranslationParents = parents;
                ++g_renderTranslationEligibleFrames;
                for (size_t axis = 0; axis < currentPlayerPosition.size(); ++axis) {
                    currentPlayerPosition[axis] =
                        ReadEngineValue<float>(player + 0x2C + axis * 4);
                }

                targets[0] = camera;
                for (size_t index = 0; index < nodes.size(); ++index) {
                    targets[index + 1] = nodes[index];
                }
                bool currentNodePositionsMatch = true;
                for (size_t index = 0; index < targets.size(); ++index) {
                    for (size_t axis = 0; axis < currentPlayerPosition.size(); ++axis) {
                        originalPositions[index][axis] =
                            ReadEngineValue<float>(targets[index] + 0x8C + axis * 4);
                    }
                    // In third person only the body's root has to agree.
                    if (index != 0 && (firstPersonView || index == 1)) {
                        currentNodePositionsMatch = currentNodePositionsMatch &&
                            PositionsNear(originalPositions[index], currentPlayerPosition);
                    }
                }

                // History of the authoritative player position as seen by the
                // scene draw: `to` is the newest pose, `from` the one before it.
                // A new pose appears on the draw of a tick frame; the picture
                // shows lerp(from, to, accumulator / tick), one tick behind.
                const uint32_t pulse =
                    g_currentPulse.load(std::memory_order_relaxed);
                TranslationInterpolationPair &history = g_translationInterpolationPair;
                if (!currentNodePositionsMatch) {
                    history = {};
                    InterlockedIncrement(&g_translationStatRootMismatch);
                } else if (!history.valid) {
                    history.from = currentPlayerPosition;
                    history.to = currentPlayerPosition;
                    history.valid = true;
                } else if (!PositionsNear(currentPlayerPosition, history.to)) {
                    // Steps above 150 units in one tick (a teleport) are shown at once.
                    if (PositionsNear(currentPlayerPosition, history.to, 22500.0f)) {
                        history.from = history.to;
                    } else {
                        history.from = currentPlayerPosition;
                        InterlockedIncrement(&g_translationStatSnaps);
                    }
                    history.to = currentPlayerPosition;
                    InterlockedIncrement(&g_translationStatPoses);
                } else if (pulse != 0) {
                    // A tick that did not move the player.
                    history.from = history.to;
                }
                // Eye height: the camera's height above the player reference
                // (crouching, standing up). It changes on ticks and is not part
                // of the player position, so it has its own from/to pair. If it
                // also changes off ticks (looking up or down moves it a little)
                // it is left alone for a while, like a per-frame weapon node.
                const float eyeHeight =
                    originalPositions[0][2] - currentPlayerPosition[2];
                EyeHeightHistory &eye = g_eyeHeightHistory;
                if (eye.score != 0) --eye.score;
                // Retired in favour of ComputeCameraBoneDelta: kept passive.
                constexpr bool kEyeHeightPairEnabled = false;
                if (!kEyeHeightPairEnabled || !eye.valid || !history.valid ||
                    !firstPersonView) {
                    eye.from = eye.to = eyeHeight;
                    eye.valid = history.valid;
                    eye.score = 0;
                } else if (std::fabs(eyeHeight - eye.to) > 0.0005f) {
                    if (pulse == 0) {
                        eye.score = static_cast<uint8_t>(eye.score > 12 ? 16 : eye.score + 4);
                        eye.from = eyeHeight;
                    } else if (eye.score >= 8 || std::fabs(eyeHeight - eye.to) > 40.0f) {
                        eye.from = eyeHeight;
                    } else {
                        eye.from = eye.to;
                        InterlockedIncrement(&g_translationStatEyeSteps);
                    }
                    eye.to = eyeHeight;
                } else if (pulse != 0) {
                    eye.from = eye.to;
                }

                if (g_crouchTracePendingValid) {
                    const uint32_t write = g_crouchTraceWrite.load(std::memory_order_relaxed);
                    g_crouchTrace[write % g_crouchTrace.size()] = g_crouchTracePending;
                    g_crouchTraceWrite.store(write + 1, std::memory_order_release);
                    g_crouchTracePendingValid = false;
                }
                // The crouch trace has served its purpose; set to true to use it.
                constexpr bool kCrouchTraceEnabled = false;
                if (kCrouchTraceEnabled &&
                    std::fabs(eyeHeight - g_crouchTraceLastEye) > 0.02f) {
                    g_crouchTraceHot = 90;
                }
                g_crouchTraceLastEye = eyeHeight;
                if (g_crouchTraceHot != 0) {
                    --g_crouchTraceHot;
                    g_crouchTracePending = {};
                    g_crouchTracePending.frame =
                        static_cast<uint32_t>(g_renderTranslationEligibleFrames);
                    g_crouchTracePending.tick = pulse != 0 ? 1 : 0;
                    g_crouchTracePending.alpha =
                        static_cast<float>(g_accumulatorMs / g_simulationStepMs);
                    g_crouchTracePending.playerZ = currentPlayerPosition[2];
                    g_crouchTracePending.cameraWorldZ = originalPositions[0][2];
                    g_crouchTracePending.cameraLocalZ =
                        ReadEngineValue<float>(camera + 0x60);
                    g_crouchTracePendingValid = true;
                }

                // Third person: tick-driven part of the camera's offset.
                float thirdPersonDelta[3] = {0.0f, 0.0f, 0.0f};
                bool thirdPersonMoves = false;
                if (!firstPersonView && history.valid) {
                    double trackAlpha = g_accumulatorMs / g_simulationStepMs;
                    if (trackAlpha < 0.0) trackAlpha = 0.0;
                    if (trackAlpha > 1.0) trackAlpha = 1.0;
                    const float forward[3] = {
                        ReadEngineValue<float>(camera + 0x68 + 0),
                        ReadEngineValue<float>(camera + 0x68 + 12),
                        ReadEngineValue<float>(camera + 0x68 + 24)};
                    // right = up x forward, horizontal; undefined when the
                    // view is straight up or down.
                    float right[3] = {-forward[1], forward[0], 0.0f};
                    const float rightLength =
                        std::sqrt(right[0] * right[0] + right[1] * right[1]);
                    const float vertical = forward[2];
                    if (rightLength > 0.15f && std::fabs(vertical) < 0.985f) {
                        right[0] /= rightLength;
                        right[1] /= rightLength;
                        float offset[3];
                        for (int axis = 0; axis < 3; ++axis) {
                            offset[axis] =
                                originalPositions[0][axis] - currentPlayerPosition[axis];
                        }
                        const float side = offset[0] * right[0] + offset[1] * right[1];
                        const float inPlane[3] = {offset[0] - side * right[0],
                                                  offset[1] - side * right[1], offset[2]};
                        const float alongForward = inPlane[0] * forward[0] +
                            inPlane[1] * forward[1] + inPlane[2] * forward[2];
                        const float back = (alongForward - vertical * inPlane[2]) /
                            (1.0f - vertical * vertical);
                        const float height = inPlane[2] - back * vertical;
                        const float engineValues[3] = {height, back, side};
                        float shownValues[3];
                        for (int index = 0; index < 3; ++index) {
                            shownValues[index] = AdvanceTickTrack(
                                g_thirdPersonTracks[index], engineValues[index],
                                pulse != 0, trackAlpha, 0.01f);
                        }
                        const float dHeight = shownValues[0] - height;
                        const float dBack = shownValues[1] - back;
                        const float dSide = shownValues[2] - side;
                        thirdPersonDelta[0] = dBack * forward[0] + dSide * right[0];
                        thirdPersonDelta[1] = dBack * forward[1] + dSide * right[1];
                        thirdPersonDelta[2] = dHeight + dBack * forward[2];
                        thirdPersonMoves =
                            std::isfinite(thirdPersonDelta[0]) &&
                            std::isfinite(thirdPersonDelta[1]) &&
                            std::isfinite(thirdPersonDelta[2]) &&
                            (std::fabs(thirdPersonDelta[0]) > 0.0001f ||
                             std::fabs(thirdPersonDelta[1]) > 0.0001f ||
                             std::fabs(thirdPersonDelta[2]) > 0.0001f);
                    } else {
                        for (TickTrack &track : g_thirdPersonTracks) track = {};
                    }
                } else {
                    for (TickTrack &track : g_thirdPersonTracks) track = {};
                }

                if (g_aimTraceHot != 0) {
                    --g_aimTraceHot;
                    AimTraceRow row{};
                    row.frame = static_cast<uint32_t>(g_renderTranslationEligibleFrames);
                    row.tick = pulse != 0 ? 1 : 0;
                    row.firstPerson = firstPersonView ? 1 : 0;
                    row.alpha = static_cast<float>(g_accumulatorMs / g_simulationStepMs);
                    for (int index = 0; index < 2; ++index) {
                        row.engineFov[index] =
                            ReadEngineValue<float>(player + 0x5D0 + index * 4);
                        row.shownFov[index] = g_fovTracks[index].shown;
                    }
                    std::memcpy(row.frustum, reinterpret_cast<const void *>(camera + 0xDC),
                                sizeof(row.frustum));
                    for (int axis = 0; axis < 3; ++axis) {
                        row.cameraOffset[axis] =
                            originalPositions[0][axis] - currentPlayerPosition[axis];
                        row.cameraForward[axis] =
                            ReadEngineValue<float>(camera + 0x68 + axis * 12);
                    }
                    const uint32_t write = g_aimTraceWrite.load(std::memory_order_relaxed);
                    g_aimTrace[write % g_aimTrace.size()] = row;
                    g_aimTraceWrite.store(write + 1, std::memory_order_release);
                }

                const TranslationInterpolationPair pair = history;
                if (pair.valid && g_renderTranslationEligibleFrames > 60) {
                    double alpha = g_accumulatorMs / g_simulationStepMs;
                    if (alpha < 0.0) alpha = 0.0;
                    if (alpha > 1.0) alpha = 1.0;
                    const float eyeCorrection = static_cast<float>(
                        static_cast<double>(eye.from) +
                        (static_cast<double>(eye.to) - eye.from) * alpha -
                        static_cast<double>(eyeHeight));
                    std::array<float, 3> correction{};
                    float correctionSquared = 0.0f;
                    bool finite = true;
                    for (size_t axis = 0; axis < correction.size(); ++axis) {
                        const double interpolated =
                            static_cast<double>(pair.from[axis]) +
                            (static_cast<double>(pair.to[axis]) -
                             static_cast<double>(pair.from[axis])) * alpha;
                        correction[axis] = static_cast<float>(
                            interpolated - static_cast<double>(currentPlayerPosition[axis]));
                        correctionSquared += correction[axis] * correction[axis];
                        finite = finite && std::isfinite(correction[axis]);
                    }
                    const bool eyeMoves = std::isfinite(eyeCorrection) &&
                        std::fabs(eyeCorrection) > 0.0001f;
                    float boneDelta[3] = {0.0f, 0.0f, 0.0f};
                    const bool boneMoves =
                        firstPersonView && g_actorTranslationInterpolationEnabled &&
                        ComputeCameraBoneDelta(player, originalPositions[0].data(),
                                               boneDelta);
                    if (g_crouchTracePendingValid) {
                        g_crouchTracePending.moveCorrectionZ = correction[2];
                        g_crouchTracePending.eyeCorrection = eyeCorrection;
                    }
                    apply = finite && std::isfinite(correctionSquared) &&
                        (correctionSquared > 0.00000001f || eyeMoves ||
                         thirdPersonMoves || boneMoves) &&
                        correctionSquared <= 22500.0f;
                    if (apply) {
                        playerCorrection = correction;
                        InterlockedIncrement(&g_translationStatApplied);
                        for (size_t index = 0; index < targets.size(); ++index) {
                            if (index != 0 && !firstPersonView) break;
                            std::array<float, 3> translated{};
                            for (size_t axis = 0; axis < translated.size(); ++axis) {
                                translated[axis] =
                                    originalPositions[index][axis] + correction[axis];
                            }
                            // Only the camera carries the eye height.
                            if (index == 0 && eyeMoves) translated[2] += eyeCorrection;
                            if (index == 0 && boneMoves) {
                                for (size_t axis = 0; axis < translated.size(); ++axis) {
                                    translated[axis] += boneDelta[axis];
                                }
                            }
                            if (index == 0 && thirdPersonMoves) {
                                for (size_t axis = 0; axis < translated.size(); ++axis) {
                                    translated[axis] += thirdPersonDelta[axis];
                                }
                            }
                            std::memcpy(
                                reinterpret_cast<void *>(targets[index] + 0x8C),
                                translated.data(), sizeof(translated));
                        }
                        // The sky follows the camera, eye height included.
                        const float skyDelta[3] = {
                            correction[0] + boneDelta[0] +
                                (thirdPersonMoves ? thirdPersonDelta[0] : 0.0f),
                            correction[1] + boneDelta[1] +
                                (thirdPersonMoves ? thirdPersonDelta[1] : 0.0f),
                            correction[2] + boneDelta[2] +
                                (eyeMoves ? eyeCorrection : 0.0f) +
                                (thirdPersonMoves ? thirdPersonDelta[2] : 0.0f)};
                        ShiftSkyForDraw(skyDelta);
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ResetRenderTranslationInterpolation();
            apply = false;
        }
    } else if (!CaptureGateIsActive()) {
        ResetRenderTranslationInterpolation();
    }

    // Actors follow the player's eligibility and warm-up. History is kept up
    // to date from the first eligible draw; offsets start with the player's.
    bool actorsMoved = false;
    if (g_renderTranslationEligibleFrames > 0) {
        const int64_t actorStart = PerfNow();
        actorsMoved = ApplyActorTranslations(
            player, g_renderTranslationEligibleFrames > 60, false);
        InterlockedExchangeAdd64(&g_perfActorPassTicks, PerfNow() - actorStart);
    } else {
        ResetActorTranslationInterpolation();
    }

    // Before anything of the player's body is written for this draw.
    if (player >= 0x10000 && g_renderTranslationEligibleFrames > 0) {
        WatchLeftHand(player, firstPersonView);
        if (g_fingerLengthFixEnabled) FixFingerLengths(player);
    }
    const int64_t bodyStart = PerfNow();
    const bool bodyMoved =
        !firstPersonView && g_actorTranslationInterpolationEnabled &&
        g_renderTranslationEligibleFrames > 0 && player >= 0x10000 &&
        ApplyPlayerBodyPose(player, playerCorrection,
                            g_renderTranslationEligibleFrames > 60);
    InterlockedExchangeAdd64(&g_perfBodyPassTicks, PerfNow() - bodyStart);
    const bool cameraRotated =
        firstPersonView && g_actorTranslationInterpolationEnabled &&
        g_renderTranslationEligibleFrames > 60 && player >= 0x10000 &&
        camera >= 0x10000 && ApplyCameraAnimationRotation(player, camera);

    InterlockedExchangeAdd64(&g_perfPreDrawTicks, PerfNow() - perfStart);
    InterlockedIncrement(&g_perfDraws);
    if (!apply) {
        stock(renderContext, arg0, arg1, arg2, arg3);
        if (cameraRotated) RestoreCameraAnimationRotation();
        if (bodyMoved) RestorePlayerBodyPose();
        if (actorsMoved) RestoreActorTranslations();
        return;
    }

    // 2040/2041/2042 record apply/draw/restore. 2043 permanently fails the
    // process closed if identity or exact-byte restoration does not survive.
    PublishProbe(2040);
    stock(renderContext, arg0, arg1, arg2, arg3);
    PublishProbe(2041);
    if (cameraRotated) RestoreCameraAnimationRotation();
    if (bodyMoved) RestorePlayerBodyPose();
    if (actorsMoved) RestoreActorTranslations();
    if (g_skySavedCount != 0) RestoreSkyAfterDraw();

    bool restored = false;
    __try {
        for (size_t index = 0; index < targets.size(); ++index) {
            std::memcpy(
                reinterpret_cast<void *>(targets[index] + 0x8C),
                originalPositions[index].data(), sizeof(originalPositions[index]));
        }
        const uintptr_t currentPlayer =
            ReadEngineValue<uintptr_t>(kPlayerSingleton);
        const uintptr_t currentRenderer =
            ReadEngineValue<uintptr_t>(kRendererSingleton);
        const uintptr_t currentCell = currentPlayer == player
            ? ReadEngineValue<uintptr_t>(currentPlayer + 0x3C) : 0;
        const uintptr_t currentSceneGraph =
            ReadEngineValue<uintptr_t>(kSceneGraphSingleton);
        const uintptr_t currentCamera = currentSceneGraph == sceneGraph
            ? ReadEngineValue<uintptr_t>(currentSceneGraph + 0xAC) : 0;
        const uintptr_t currentCameraParent = currentCamera == camera
            ? ReadEngineValue<uintptr_t>(currentCamera + 0x18) : 0;
        std::array<uintptr_t, 4> currentNodes{};
        std::array<uintptr_t, 4> currentParents{};
        const bool currentNodesValid = currentPlayer == player &&
            ResolvePlayerTranslationNodes(currentPlayer, currentNodes, currentParents);
        restored = currentCell == cell && currentRenderer == renderer &&
            currentCamera == camera &&
            currentCameraParent == cameraParent && currentNodesValid &&
            currentNodes == nodes && currentParents == parents;
        for (size_t index = 0; restored && index < targets.size(); ++index) {
            restored = std::memcmp(
                reinterpret_cast<const void *>(targets[index] + 0x8C),
                originalPositions[index].data(), sizeof(originalPositions[index])) == 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        restored = false;
    }

    if (restored) {
        PublishProbe(2042);
    } else {
        g_renderTranslationInterpolationFaulted = true;
        PublishProbe(2043);
    }
}

void __cdecl FrameRegionProbe(uint32_t probeId) {
    PublishProbe(probeId);
}

bool InstallFrameRegionProbes() {
    if (!g_frameRegionTelemetryEnabled && !g_authoritativeStateTelemetryEnabled &&
        !g_eventDispatchTelemetryEnabled && !g_sceneTransformTelemetryEnabled) return true;
    for (const ProbeSite &site : kProbeSites) {
        if (!MatchesBytes(site.callAddress, site.expected.data(), site.expected.size())) {
            AppendStatus("frame probe signature mismatch id=%u at %08X", site.id,
                         static_cast<unsigned>(site.callAddress));
            return false;
        }
    }

    constexpr size_t kStubSize = 22;
    const size_t allocationSize = kProbeSites.size() * kStubSize;
    auto *allocation = static_cast<uint8_t *>(
        VirtualAlloc(nullptr, allocationSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (allocation == nullptr) {
        AppendStatus("frame probe stub allocation failed");
        return false;
    }

    for (size_t i = 0; i < kProbeSites.size(); ++i) {
        const ProbeSite &site = kProbeSites[i];
        uint8_t *stub = allocation + i * kStubSize;
        size_t offset = 0;
        stub[offset++] = 0x9C; // pushfd
        stub[offset++] = 0x60; // pushad
        stub[offset++] = 0x68; // push imm32 probe id
        std::memcpy(stub + offset, &site.id, sizeof(site.id));
        offset += sizeof(site.id);
        stub[offset++] = 0xE8; // call FrameRegionProbe
        const int32_t probeDisplacement = static_cast<int32_t>(
            reinterpret_cast<uintptr_t>(&FrameRegionProbe) -
            reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
        std::memcpy(stub + offset, &probeDisplacement, sizeof(probeDisplacement));
        offset += sizeof(probeDisplacement);
        stub[offset++] = 0x83; // add esp, 4
        stub[offset++] = 0xC4;
        stub[offset++] = 0x04;
        stub[offset++] = 0x61; // popad
        stub[offset++] = 0x9D; // popfd
        stub[offset++] = 0xE9; // jmp original target or composed replay stub
        uintptr_t target = site.originalTarget;
        if (site.id == 705 && g_sceneDrawReplayEnabled && g_sceneDrawReplayStub != nullptr) {
            target = reinterpret_cast<uintptr_t>(g_sceneDrawReplayStub);
        } else if (site.id == 705 && g_renderTranslationInterpolationEnabled) {
            target = reinterpret_cast<uintptr_t>(
                &RenderTranslationInterpolationHook);
        } else if (site.id == 705 && g_renderCameraPositionInterpolationEnabled) {
            target = reinterpret_cast<uintptr_t>(
                &RenderCameraPositionInterpolationHook);
        } else if (site.id == 108 &&
                   (g_postPresentReplayEnabled || g_postPresentLeafReplayEnabled) &&
                   g_postPresentReplayStub != nullptr) {
            target = reinterpret_cast<uintptr_t>(g_postPresentReplayStub);
        } else if (site.id == 709 && g_actorTranslationInterpolationEnabled) {
            target = reinterpret_cast<uintptr_t>(&FirstPersonPrepareThunk709);
        } else if (site.id == 710 && g_actorTranslationInterpolationEnabled) {
            target = reinterpret_cast<uintptr_t>(&FirstPersonPrepareThunk710);
        } else if (site.id == 711 && g_actorTranslationInterpolationEnabled) {
            target = reinterpret_cast<uintptr_t>(&FirstPersonPrepareThunk711);
        } else if (site.id == 713 && g_actorTranslationInterpolationEnabled) {
            target = reinterpret_cast<uintptr_t>(&FirstPersonFinishThunk713);
        } else if (site.id == 1710 && g_renderTranslationInterpolationEnabled) {
            target = reinterpret_cast<uintptr_t>(&SetCameraFovHook);
        } else if (site.id == 1880 && g_hudTimerNoSleepEnabled) {
            target = reinterpret_cast<uintptr_t>(&UpdateHUDMainMenuTimerNoSleep);
        }
        const int32_t targetDisplacement = static_cast<int32_t>(
            target - reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
        std::memcpy(stub + offset, &targetDisplacement, sizeof(targetDisplacement));
    }

    DWORD oldProtection = 0;
    if (!VirtualProtect(allocation, allocationSize, PAGE_EXECUTE_READ, &oldProtection)) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        AppendStatus("frame probe stub protection failed");
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), allocation, allocationSize);

    for (size_t i = 0; i < kProbeSites.size(); ++i) {
        const ProbeSite &site = kProbeSites[i];
        const void *stub = allocation + i * kStubSize;
        if (!PatchRelativeCall(site.callAddress, stub, site.expected.data())) {
            for (size_t rollback = 0; rollback < i; ++rollback) {
                const ProbeSite &installed = kProbeSites[rollback];
                RestoreBytes(installed.callAddress, installed.expected.data());
            }
            VirtualFree(allocation, 0, MEM_RELEASE);
            g_installedProbeCount = 0;
            AppendStatus("frame probes rolled back after partial installation failure");
            return false;
        }
        g_installedProbeCount = i + 1;
    }
    g_probeStubAllocation = allocation;
    return true;
}

void UninstallFrameRegionProbes() {
    for (size_t i = 0; i < g_installedProbeCount; ++i) {
        RestoreBytes(kProbeSites[i].callAddress, kProbeSites[i].expected.data());
    }
    g_installedProbeCount = 0;
    if (g_probeStubAllocation != nullptr) {
        VirtualFree(g_probeStubAllocation, 0, MEM_RELEASE);
        g_probeStubAllocation = nullptr;
    }
}

void UninstallEventDispatchProbes() {
    for (size_t i = 0; i < g_installedDispatchProbeCount; ++i) {
        const DispatchProbeSite &site = kDispatchProbeSites[i];
        RestoreBytes(site.address, site.expected.data(), site.overwriteLength);
    }
    g_installedDispatchProbeCount = 0;
    if (g_dispatchStubAllocation != nullptr) {
        VirtualFree(g_dispatchStubAllocation, 0, MEM_RELEASE);
        g_dispatchStubAllocation = nullptr;
    }
}

bool InstallEventDispatchProbes() {
    if (!g_eventDispatchTelemetryEnabled) return true;
    for (const DispatchProbeSite &site : kDispatchProbeSites) {
        if (!MatchesBytes(site.address, site.expected.data(), site.overwriteLength)) {
            AppendStatus("dispatch probe signature mismatch name=%s at %08X", site.name,
                         static_cast<unsigned>(site.address));
            return false;
        }
    }

    // Optional marker: pushfd/pushad; call PublishProbe; popad/popfd.
    // Script sites conditionally call the overlap recorder while the game
    // thread is inside either D3D9 Present or a state-2 target pass.
    // Optional counter: pushfd; lock inc dword ptr [counter]; popfd.
    // Then replay whole copied instructions and jump to their continuation.
    // Script entry markers plus the existing overlap recorder need more than
    // the former 64-byte slot, so keep a bounded 80-byte slot for every stub.
    constexpr size_t kStubSize = 80;
    const size_t allocationSize = kDispatchProbeSites.size() * kStubSize;
    auto *allocation = static_cast<uint8_t *>(
        VirtualAlloc(nullptr, allocationSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (allocation == nullptr) {
        AppendStatus("dispatch probe stub allocation failed");
        return false;
    }

    for (size_t i = 0; i < kDispatchProbeSites.size(); ++i) {
        const DispatchProbeSite &site = kDispatchProbeSites[i];
        uint8_t *stub = allocation + i * kStubSize;
        size_t offset = 0;
        if (site.markerId != 0) {
            stub[offset++] = 0x9C; // pushfd
            stub[offset++] = 0x60; // pushad
            if (site.markerId == 1310) {
                // FUN_00AE7CA0 is __fastcall. Its accumulator pointer is the
                // original ECX, saved at [esp+0x18] after pushfd/pushad.
                stub[offset++] = 0xFF; // push dword ptr [esp+0x18]
                stub[offset++] = 0x74;
                stub[offset++] = 0x24;
                stub[offset++] = 0x18;
                stub[offset++] = 0xE8; // call RecordRenderAccumulator
                const int32_t accumulatorDisplacement = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(&RecordRenderAccumulator) -
                    reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
                std::memcpy(stub + offset, &accumulatorDisplacement,
                            sizeof(accumulatorDisplacement));
                offset += sizeof(accumulatorDisplacement);
                stub[offset++] = 0x83; // add esp, 4
                stub[offset++] = 0xC4;
                stub[offset++] = 0x04;
            }
            if (site.markerId == 1330) {
                // Pass the complete pushfd/pushad context. The recorder reads
                // original ECX plus the untouched return address and four
                // stack arguments without changing the engine call.
                stub[offset++] = 0x54; // push esp
                stub[offset++] = 0xE8; // call RecordCompositePassEntry
                const int32_t passDisplacement = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(&RecordCompositePassEntry) -
                    reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
                std::memcpy(stub + offset, &passDisplacement,
                            sizeof(passDisplacement));
                offset += sizeof(passDisplacement);
                stub[offset++] = 0x83; // add esp, 4
                stub[offset++] = 0xC4;
                stub[offset++] = 0x04;
            }
            if (site.markerId == 1340) {
                // FUN_00B1D860 is __thiscall with six stack arguments. Preserve
                // and pass the entry context before replaying its full
                // seven-byte two-instruction prologue.
                stub[offset++] = 0x54; // push esp
                stub[offset++] = 0xE8; // call RecordCompositeExecutorEntry
                const int32_t executorDisplacement = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(&RecordCompositeExecutorEntry) -
                    reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
                std::memcpy(stub + offset, &executorDisplacement,
                            sizeof(executorDisplacement));
                offset += sizeof(executorDisplacement);
                stub[offset++] = 0x83; // add esp, 4
                stub[offset++] = 0xC4;
                stub[offset++] = 0x04;
            }
            if (site.markerId == 1350) {
                // 00B3063B is inside FUN_00B2FD70 after all four final-leaf
                // bindings are installed. Preserve the complete register and
                // stack context before replaying MOV ECX,[ESP+84].
                stub[offset++] = 0x54; // push esp
                stub[offset++] = 0xE8; // call RecordCompositeLeafReady
                const int32_t leafDisplacement = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(&RecordCompositeLeafReady) -
                    reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
                std::memcpy(stub + offset, &leafDisplacement,
                            sizeof(leafDisplacement));
                offset += sizeof(leafDisplacement);
                stub[offset++] = 0x83; // add esp, 4
                stub[offset++] = 0xC4;
                stub[offset++] = 0x04;
            }
            if (site.markerId == 503) {
                // At the hooked epilogue, the original stack contains two
                // discarded arguments, saved ESI, then the caller's return
                // address. After pushfd/pushad it is at [esp+0x30]. Record it
                // before publishing marker 503 so the snapshot identifies
                // the actual runtime call site for this target activation.
                stub[offset++] = 0xFF; // push dword ptr [esp+0x30]
                stub[offset++] = 0x74;
                stub[offset++] = 0x24;
                stub[offset++] = 0x30;
                stub[offset++] = 0xE8; // call RecordState2PassReturnAddress
                const int32_t callerDisplacement = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(&RecordState2PassReturnAddress) -
                    reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
                std::memcpy(stub + offset, &callerDisplacement,
                            sizeof(callerDisplacement));
                offset += sizeof(callerDisplacement);
                stub[offset++] = 0x83; // add esp, 4
                stub[offset++] = 0xC4;
                stub[offset++] = 0x04;
            }
            if (site.markerId == 504) {
                // This hook is at FUN_006E5E90's entry, before its prologue.
                // Its caller return address was at the original [esp], which
                // becomes [esp+0x24] after pushfd/pushad.
                stub[offset++] = 0xFF; // push dword ptr [esp+0x24]
                stub[offset++] = 0x74;
                stub[offset++] = 0x24;
                stub[offset++] = 0x24;
                stub[offset++] = 0xE8; // call RecordState2OwnerReturnAddress
                const int32_t ownerDisplacement = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(&RecordState2OwnerReturnAddress) -
                    reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
                std::memcpy(stub + offset, &ownerDisplacement,
                            sizeof(ownerDisplacement));
                offset += sizeof(ownerDisplacement);
                stub[offset++] = 0x83; // add esp, 4
                stub[offset++] = 0xC4;
                stub[offset++] = 0x04;
            }
            if (site.markerId == 1872) {
                // The callback object returned by FUN_00BEAB90 is the original
                // EAX, saved at [esp+0x1C] after pushfd/pushad. Resolve and
                // publish its vtable+0x2C target before replaying the call setup.
                stub[offset++] = 0xFF; // push dword ptr [esp+0x1C]
                stub[offset++] = 0x74;
                stub[offset++] = 0x24;
                stub[offset++] = 0x1C;
                stub[offset++] = 0xE8; // call PublishWorkerEffectCallbackTarget
                const int32_t targetDisplacement = static_cast<int32_t>(
                    reinterpret_cast<uintptr_t>(&PublishWorkerEffectCallbackTarget) -
                    reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
                std::memcpy(stub + offset, &targetDisplacement,
                            sizeof(targetDisplacement));
                offset += sizeof(targetDisplacement);
                stub[offset++] = 0x83; // add esp, 4
                stub[offset++] = 0xC4;
                stub[offset++] = 0x04;
            }
            stub[offset++] = 0x68; // push marker ID
            std::memcpy(stub + offset, &site.markerId, sizeof(site.markerId));
            offset += sizeof(site.markerId);
            stub[offset++] = 0xE8; // call PublishProbe(uint32_t)
            const int32_t markerDisplacement = static_cast<int32_t>(
                reinterpret_cast<uintptr_t>(&PublishProbe) -
                reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
            std::memcpy(stub + offset, &markerDisplacement, sizeof(markerDisplacement));
            offset += sizeof(markerDisplacement);
            stub[offset++] = 0x83; // add esp, 4
            stub[offset++] = 0xC4;
            stub[offset++] = 0x04;
            stub[offset++] = 0x61; // popad
            stub[offset++] = 0x9D; // popfd
        }
        if (site.counter == DispatchCounter::ScriptRun && site.incrementCounter) {
            stub[offset++] = 0x9C; // pushfd
            stub[offset++] = 0x83; // cmp dword ptr [absolute active flag], 0
            stub[offset++] = 0x3D;
            const auto activeAddress = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(&g_presentObservationActive));
            std::memcpy(stub + offset, &activeAddress, sizeof(activeAddress));
            offset += sizeof(activeAddress);
            stub[offset++] = 0x00;
            stub[offset++] = 0x75; // jne recorder
            const size_t presentActiveJumpOffset = offset++;
            stub[offset++] = 0x83; // cmp dword ptr [state-2 active flag], 0
            stub[offset++] = 0x3D;
            const auto state2ActiveAddress = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(&g_state2PassObservationActive));
            std::memcpy(stub + offset, &state2ActiveAddress, sizeof(state2ActiveAddress));
            offset += sizeof(state2ActiveAddress);
            stub[offset++] = 0x00;
            stub[offset++] = 0x74; // je recorder_done
            const size_t recorderSkipOffset = offset++;
            const size_t recorderOffset = offset;
            stub[offset++] = 0x60; // pushad
            stub[offset++] = 0xE8; // call RecordScriptDuringPresent
            const int32_t recorderDisplacement = static_cast<int32_t>(
                reinterpret_cast<uintptr_t>(&RecordScriptDuringPresent) -
                reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
            std::memcpy(stub + offset, &recorderDisplacement, sizeof(recorderDisplacement));
            offset += sizeof(recorderDisplacement);
            stub[offset++] = 0x61; // popad
            stub[presentActiveJumpOffset] = static_cast<uint8_t>(
                recorderOffset - (presentActiveJumpOffset + 1));
            stub[recorderSkipOffset] = static_cast<uint8_t>(
                offset - (recorderSkipOffset + 1));
            stub[offset++] = 0x9D; // popfd
        }
        if (site.incrementCounter) {
            stub[offset++] = 0x9C; // pushfd
            stub[offset++] = 0xF0; // lock inc dword ptr [absolute counter]
            stub[offset++] = 0xFF;
            stub[offset++] = 0x05;
            const auto counterAddress = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(DispatchCounterAddress(site.counter)));
            std::memcpy(stub + offset, &counterAddress, sizeof(counterAddress));
            offset += sizeof(counterAddress);
            stub[offset++] = 0x9D; // popfd
        }
        std::memcpy(stub + offset, site.expected.data(), site.overwriteLength);
        offset += site.overwriteLength;
        stub[offset++] = 0xE9; // jmp after the overwritten function-entry instructions
        const int32_t continuationDisplacement = static_cast<int32_t>(
            site.address + site.overwriteLength -
            reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
        std::memcpy(stub + offset, &continuationDisplacement,
                    sizeof(continuationDisplacement));
    }

    DWORD oldProtection = 0;
    if (!VirtualProtect(allocation, allocationSize, PAGE_EXECUTE_READ, &oldProtection)) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        AppendStatus("dispatch probe stub protection failed");
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), allocation, allocationSize);

    g_dispatchStubAllocation = allocation;
    for (size_t i = 0; i < kDispatchProbeSites.size(); ++i) {
        const DispatchProbeSite &site = kDispatchProbeSites[i];
        const void *stub = allocation + i * kStubSize;
        if (!PatchRelativeJump(site.address, stub, site.expected.data(), site.overwriteLength)) {
            UninstallEventDispatchProbes();
            AppendStatus("dispatch probes rolled back after partial installation failure");
            return false;
        }
        g_installedDispatchProbeCount = i + 1;
    }
    return true;
}

BOOL __cdecl PrepareSceneDrawReplay() {
    bool eligible = false;
    uintptr_t cell = 0;
    __try {
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        cell = player >= 0x10000
            ? ReadEngineValue<uintptr_t>(player + 0x3C) : 0;
        const uintptr_t renderer = ReadEngineValue<uintptr_t>(kRendererSingleton);
        eligible = player >= 0x10000 && cell >= 0x10000 && renderer >= 0x10000 &&
                   ReadEngineValue<uint32_t>(renderer + 0x200) == 2 &&
                   ReadEngineValue<uint8_t>(renderer + 0x208) != 0 &&
                   ReadEngineValue<uintptr_t>(renderer + 0x888) >= 0x10000;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        eligible = false;
    }

    if (!eligible) {
        InterlockedExchange(&g_sceneDrawReplayEligibleFrames, 0);
        InterlockedExchange(&g_sceneDrawReplayCell, 0);
        return FALSE;
    }

    const LONG cellValue = static_cast<LONG>(cell);
    if (InterlockedExchange(&g_sceneDrawReplayCell, cellValue) != cellValue) {
        InterlockedExchange(&g_sceneDrawReplayEligibleFrames, 0);
        return FALSE;
    }

    // Require two seconds of stable in-world rendering at roughly 120 FPS.
    // Startup, menus, loading transitions, and the first frames after a cell
    // transition therefore execute the unmodified single-pass path.
    if (InterlockedIncrement(&g_sceneDrawReplayEligibleFrames) <= 240) return FALSE;
    PublishProbe(1102);
    return TRUE;
}

void UninstallSceneDrawReplay() {
    static constexpr uint8_t expected[5] = {0xE8, 0x23, 0xED, 0xFF, 0xFF};
    if (g_sceneDrawReplayPatchedDirectly) {
        RestoreBytes(kSceneDrawCall, expected);
        g_sceneDrawReplayPatchedDirectly = false;
    }
    if (g_sceneDrawReplayStub != nullptr) {
        VirtualFree(g_sceneDrawReplayStub, 0, MEM_RELEASE);
        g_sceneDrawReplayStub = nullptr;
    }
    g_sceneDrawReplayInstalled = false;
}

bool InstallSceneDrawReplay() {
    if (!g_sceneDrawReplayEnabled) return true;
    static constexpr uint8_t expected[5] = {0xE8, 0x23, 0xED, 0xFF, 0xFF};
    if (!MatchesBytes(kSceneDrawCall, expected, sizeof(expected))) {
        AppendStatus("scene-draw replay signature mismatch at %08X",
                     static_cast<unsigned>(kSceneDrawCall));
        return false;
    }

    constexpr size_t kStubSize = 96;
    auto *stub = static_cast<uint8_t *>(
        VirtualAlloc(nullptr, kStubSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (stub == nullptr) {
        AppendStatus("scene-draw replay stub allocation failed");
        return false;
    }

    size_t offset = 0;
    stub[offset++] = 0x56; // push esi
    stub[offset++] = 0x55; // push ebp
    stub[offset++] = 0x8B; // mov ebp, esp (stable base for original arguments)
    stub[offset++] = 0xEC;
    stub[offset++] = 0x8B; // mov esi, ecx (preserve this)
    stub[offset++] = 0xF1;

    const auto emitSceneDrawCall = [&]() {
        stub[offset++] = 0xFF; // push [ebp+0x18] (fourth argument)
        stub[offset++] = 0x75;
        stub[offset++] = 0x18;
        stub[offset++] = 0xFF; // push [ebp+0x14] (third argument)
        stub[offset++] = 0x75;
        stub[offset++] = 0x14;
        stub[offset++] = 0xFF; // push [ebp+0x10] (second argument)
        stub[offset++] = 0x75;
        stub[offset++] = 0x10;
        stub[offset++] = 0xFF; // push [ebp+0x0C] (first argument)
        stub[offset++] = 0x75;
        stub[offset++] = 0x0C;
        stub[offset++] = 0x8B; // mov ecx, esi
        stub[offset++] = 0xCE;
        stub[offset++] = 0xE8; // call FUN_006EB5E0 (callee pops 16)
        const int32_t displacement = static_cast<int32_t>(
            kSceneDraw - reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
        std::memcpy(stub + offset, &displacement, sizeof(displacement));
        offset += sizeof(displacement);
    };

    emitSceneDrawCall();
    stub[offset++] = 0xE8; // call PrepareSceneDrawReplay
    const int32_t gateDisplacement = static_cast<int32_t>(
        reinterpret_cast<uintptr_t>(&PrepareSceneDrawReplay) -
        reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
    std::memcpy(stub + offset, &gateDisplacement, sizeof(gateDisplacement));
    offset += sizeof(gateDisplacement);
    stub[offset++] = 0x84; // test al, al
    stub[offset++] = 0xC0;
    stub[offset++] = 0x74; // jz skip replay
    const size_t skipOffset = offset++;
    emitSceneDrawCall();
    stub[skipOffset] = static_cast<uint8_t>(offset - (skipOffset + 1));
    stub[offset++] = 0x5D; // pop ebp
    stub[offset++] = 0x5E; // pop esi
    stub[offset++] = 0xC2; // ret 16
    stub[offset++] = 0x10;
    stub[offset++] = 0x00;

    DWORD oldProtection = 0;
    if (!VirtualProtect(stub, kStubSize, PAGE_EXECUTE_READ, &oldProtection)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        AppendStatus("scene-draw replay stub protection failed");
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), stub, kStubSize);
    g_sceneDrawReplayStub = stub;
    g_sceneDrawReplayInstalled = true;

    const bool frameProbesEnabled = g_frameRegionTelemetryEnabled ||
        g_authoritativeStateTelemetryEnabled || g_eventDispatchTelemetryEnabled;
    if (!frameProbesEnabled) {
        if (!PatchRelativeCall(kSceneDrawCall, stub, expected)) {
            VirtualFree(stub, 0, MEM_RELEASE);
            g_sceneDrawReplayStub = nullptr;
            g_sceneDrawReplayInstalled = false;
            return false;
        }
        g_sceneDrawReplayPatchedDirectly = true;
    }
    return true;
}

BOOL __cdecl PreparePostPresentReplay() {
    if (g_captureActiveEvent == nullptr ||
        WaitForSingleObject(g_captureActiveEvent, 0) != WAIT_OBJECT_0) {
        InterlockedExchange(&g_postPresentReplayEligibleFrames, 0);
        InterlockedExchange(&g_postPresentReplayCell, 0);
        return FALSE;
    }

    bool eligible = false;
    uintptr_t cell = 0;
    uintptr_t renderer = 0;
    __try {
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        cell = player >= 0x10000
            ? ReadEngineValue<uintptr_t>(player + 0x3C) : 0;
        renderer = ReadEngineValue<uintptr_t>(kRendererSingleton);
        eligible = player >= 0x10000 && cell >= 0x10000 && renderer >= 0x10000 &&
                   ReadEngineValue<uint32_t>(renderer + 0x200) == 0 &&
                   ReadEngineValue<uint8_t>(renderer + 0x208) == 0 &&
                   ReadEngineValue<uintptr_t>(renderer + 0x888) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        eligible = false;
    }

    if (!eligible) {
        InterlockedExchange(&g_postPresentReplayEligibleFrames, 0);
        InterlockedExchange(&g_postPresentReplayCell, 0);
        return FALSE;
    }

    const LONG cellValue = static_cast<LONG>(cell);
    if (InterlockedExchange(&g_postPresentReplayCell, cellValue) != cellValue) {
        InterlockedExchange(&g_postPresentReplayEligibleFrames, 0);
        return FALSE;
    }

    // Arm only after two seconds of stable active-world finalization. The
    // normal finalizer has already returned, so the renderer must be fully
    // idle before the experimental dispatcher may open another frame.
    if (InterlockedIncrement(&g_postPresentReplayEligibleFrames) <= 240) return FALSE;
    PublishProbe(1201);
    if (g_postPresentSameFrameIdEnabled) {
        // The first successful Present has advanced renderer+0x204. Restore
        // the pre-Present identity so the replay and stock pass are one
        // logical renderer frame; the replay finalizer advances it once again.
        InterlockedDecrement(
            reinterpret_cast<volatile LONG *>(renderer + 0x204));
    }
    return TRUE;
}

void __cdecl CompletePostPresentReplay() {
    PublishProbe(1202);
}

bool InstallCaptureGate() {
    if (!g_postPresentReplayEnabled && !g_leafResourceRetentionEnabled &&
        !g_postPresentLeafReplayEnabled && !g_hudTimerNoSleepEnabled &&
        !g_renderCameraPositionInterpolationEnabled &&
        !g_renderTranslationInterpolationEnabled &&
        !g_freezeRenderFramesEnabled && !g_alignHavokStepEnabled &&
        !g_latchInputEdgesEnabled) return true;
    if (g_captureActiveEvent != nullptr) return true;
    g_captureActiveEvent = CreateEventW(nullptr, TRUE, FALSE, kCaptureActiveEventName);
    if (g_captureActiveEvent == nullptr) {
        AppendStatus("experimental capture gate creation failed");
        return false;
    }
    return true;
}

void UninstallCaptureGate() {
    if (g_captureActiveEvent != nullptr) {
        CloseHandle(g_captureActiveEvent);
        g_captureActiveEvent = nullptr;
    }
}

void UninstallPostPresentReplay() {
    static constexpr uint8_t expected[5] = {0xE8, 0x30, 0x0F, 0x40, 0x00};
    if (g_postPresentReplayPatchedDirectly) {
        RestoreBytes(kRenderFinalizeCall, expected);
        g_postPresentReplayPatchedDirectly = false;
    }
    if (g_postPresentReplayStub != nullptr) {
        VirtualFree(g_postPresentReplayStub, 0, MEM_RELEASE);
        g_postPresentReplayStub = nullptr;
    }
    g_postPresentReplayInstalled = false;
}

bool InstallPostPresentReplay() {
    if (!g_postPresentReplayEnabled && !g_postPresentLeafReplayEnabled) return true;
    static constexpr uint8_t expected[5] = {0xE8, 0x30, 0x0F, 0x40, 0x00};
    if (!MatchesBytes(kRenderFinalizeCall, expected, sizeof(expected))) {
        AppendStatus("post-Present replay signature mismatch at %08X",
                     static_cast<unsigned>(kRenderFinalizeCall));
        return false;
    }
    constexpr size_t kStubSize = 64;
    auto *stub = static_cast<uint8_t *>(
        VirtualAlloc(nullptr, kStubSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (stub == nullptr) {
        AppendStatus("post-Present replay stub allocation failed");
        return false;
    }

    size_t offset = 0;
    const auto emitCall = [&](uintptr_t target) {
        stub[offset++] = 0xE8;
        const int32_t displacement = static_cast<int32_t>(
            target - reinterpret_cast<uintptr_t>(stub + offset + sizeof(int32_t)));
        std::memcpy(stub + offset, &displacement, sizeof(displacement));
        offset += sizeof(displacement);
    };

    // Preserve the stock order: finish and Present the normal frame first.
    emitCall(kRenderFinalize);
    if (g_postPresentLeafReplayEnabled) {
        emitCall(reinterpret_cast<uintptr_t>(&RunPostPresentLeafReplay));
        stub[offset++] = 0xC3;
    } else {
    emitCall(reinterpret_cast<uintptr_t>(&PreparePostPresentReplay));
    stub[offset++] = 0x84; // test al, al
    stub[offset++] = 0xC0;
    stub[offset++] = 0x74; // jz skip experimental frame
    const size_t skipOffset = offset++;
    stub[offset++] = 0x6A; // push 0 (third stock dispatcher argument)
    stub[offset++] = 0x00;
    stub[offset++] = 0x6A; // push 0 (second stock dispatcher argument)
    stub[offset++] = 0x00;
    stub[offset++] = 0x6A; // push 0 (first stock dispatcher argument)
    stub[offset++] = 0x00;
    stub[offset++] = 0x8B; // mov ecx, ebp (preserved render-owner object)
    stub[offset++] = 0xCD;
    emitCall(kRenderDispatch); // thiscall; callee pops the three arguments
    emitCall(kRenderFinalize);
    emitCall(reinterpret_cast<uintptr_t>(&CompletePostPresentReplay));
    stub[skipOffset] = static_cast<uint8_t>(offset - (skipOffset + 1));
    stub[offset++] = 0xC3;
    }

    DWORD oldProtection = 0;
    if (!VirtualProtect(stub, kStubSize, PAGE_EXECUTE_READ, &oldProtection)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        AppendStatus("post-Present replay stub protection failed");
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), stub, kStubSize);
    g_postPresentReplayStub = stub;
    g_postPresentReplayInstalled = true;

    const bool frameProbesEnabled = g_frameRegionTelemetryEnabled ||
        g_authoritativeStateTelemetryEnabled || g_eventDispatchTelemetryEnabled;
    if (!frameProbesEnabled) {
        if (!PatchRelativeCall(kRenderFinalizeCall, stub, expected)) {
            VirtualFree(stub, 0, MEM_RELEASE);
            g_postPresentReplayStub = nullptr;
            g_postPresentReplayInstalled = false;
            return false;
        }
        g_postPresentReplayPatchedDirectly = true;
    }
    return true;
}

void __fastcall TimerUpdateHook(BSTimer *timer, void *, uint32_t timeMs) {
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    double wallDeltaMs = 0.0;
    if (g_lastQpc.QuadPart != 0) {
        wallDeltaMs = static_cast<double>(now.QuadPart - g_lastQpc.QuadPart) * 1000.0 /
                      static_cast<double>(g_qpcFrequency.QuadPart);
    }
    g_lastQpc = now;

    uint32_t pulse = 1;
    // Timing mutations are inert unless the external manual capture gate is
    // armed. This makes a stranded experimental INI fail back to stock timing.
    const bool timingActive = g_quantizedDeltaEnabled && CaptureGateIsActive();
    if (g_alignHavokStepEnabled) {
        // Havok's 16 ms step against a 16.667 ms tick leaves a remainder that
        // is retired as extra partial steps on non-tick frames. Make them equal.
        auto *havokMaxTime = reinterpret_cast<volatile float *>(kHavokMaxTime);
        if (timingActive) {
            if (!g_havokMaxTimeOverridden) {
                g_havokMaxTimeOriginal = *havokMaxTime;
                g_havokMaxTimeOverridden = true;
            }
            // On a real-time frame Havok keeps its own step.
            *havokMaxTime = g_frameNativeStep
                ? g_havokMaxTimeOriginal
                : static_cast<float>(g_simulationStepMs / 1000.0);
        } else if (g_havokMaxTimeOverridden) {
            *havokMaxTime = g_havokMaxTimeOriginal;
            g_havokMaxTimeOverridden = false;
        }
    }
    if (timingActive && g_framePulseDecision >= 0) {
        // The frame hook already advanced the accumulator for this frame.
        pulse = static_cast<uint32_t>(g_framePulseDecision);
        timer->clampMs = g_frameNativeStep
            ? static_cast<float>(g_frameNativeDeltaMs)
            : (pulse != 0 ? static_cast<float>(g_simulationStepMs) : 0.000001f);
    } else if (timingActive) {
        if (wallDeltaMs < 0.0) wallDeltaMs = 0.0;
        if (wallDeltaMs > g_maxWallDeltaMs) wallDeltaMs = g_maxWallDeltaMs;
        g_accumulatorMs += wallDeltaMs;
        if (g_accumulatorMs >= g_simulationStepMs) {
            timer->clampMs = static_cast<float>(g_simulationStepMs);
            g_accumulatorMs -= g_simulationStepMs;
            pulse = 1;
        } else {
            // Non-zero enters BSTimer's explicit-clamp path and bypasses its 10 ms Sleep.
            // This is deliberately near-zero, not claimed as a simulation-free frame.
            timer->clampMs = 0.000001f;
            pulse = 0;
        }
    }

    g_timerUpdate(timer, timeMs);
    g_currentPulse.store(pulse, std::memory_order_relaxed);
    g_currentWallDeltaMs.store(wallDeltaMs, std::memory_order_relaxed);
    g_currentTimerInputMs.store(timeMs, std::memory_order_relaxed);
    g_currentTimerClampMs.store(timer->clampMs, std::memory_order_relaxed);
    g_currentTimerClampRemainderMs.store(timer->clampRemainderMs, std::memory_order_relaxed);
    Publish(EventKind::Timer, now.QuadPart, wallDeltaMs, g_accumulatorMs,
            timeMs, timer->clampMs, timer->clampRemainderMs, timer->deltaSeconds, pulse);
}

void __cdecl HavokScheduleHook(float deltaSeconds, uint8_t flagA, uint8_t flagB) {
    g_havokSchedule(deltaSeconds, flagA, flagB);
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    Publish(EventKind::Havok, now.QuadPart,
            g_currentWallDeltaMs.load(std::memory_order_relaxed), g_accumulatorMs,
            g_currentTimerInputMs.load(std::memory_order_relaxed),
            g_currentTimerClampMs.load(std::memory_order_relaxed),
            g_currentTimerClampRemainderMs.load(std::memory_order_relaxed),
            deltaSeconds, g_currentPulse.load(std::memory_order_relaxed));
}

// The player handler at the start of a frame reads press/release edges by
// comparing the newest poll's buffers (keyboard +0x18F8, mouse buttons
// +0x1B30) with the previous poll's (+0x19F8, +0x1B44). An edge is therefore
// visible for exactly one frame, whichever frame that is. This latch samples
// digital input at ticks: on a non-tick frame both buffers are set to what the
// last tick-frame handler saw (same held state, no edges), and on a tick frame
// the previous buffers are set to that state so every change since then shows
// as an edge. Held state must be frozen too: the handler's tap/hold logic
// (e.g. action 7, reload versus holster) resets itself when it sees a key up
// without a release edge. Mouse movement is untouched. The next device poll
// rewrites all four buffers.
void ApplyInputEdgeLatch(bool tick) {
    const uintptr_t input = ReadEngineValue<uintptr_t>(kOSInputGlobals);
    if (input < 0x10000) {
        g_inputEdgeLatch.valid = false;
        return;
    }
    auto *keys = reinterpret_cast<uint8_t *>(input + 0x18F8);
    auto *previousKeys = reinterpret_cast<uint8_t *>(input + 0x19F8);
    auto *buttons = reinterpret_cast<uint8_t *>(input + 0x1B30);
    auto *previousButtons = reinterpret_cast<uint8_t *>(input + 0x1B44);
    InputEdgeLatch &latch = g_inputEdgeLatch;
    if (!latch.valid) {
        std::memcpy(latch.keys.data(), keys, latch.keys.size());
        std::memcpy(latch.buttons.data(), buttons, latch.buttons.size());
        latch.pendingKeys.fill(0);
        latch.pendingButtons.fill(0);
        latch.rawKeys = latch.keys;
        latch.rawButtons = latch.buttons;
        latch.valid = true;
        return;
    }

    const auto step = [tick](uint8_t *current, uint8_t *previous, uint8_t *shown,
                             uint8_t *pending, uint8_t *raw, size_t count,
                             uint16_t ledgerBase) {
        for (size_t index = 0; index < count; ++index) {
            const bool down = (current[index] & 0x80) != 0;
            const bool shownDown = (shown[index] & 0x80) != 0;
            const auto ledgerIndex = static_cast<uint16_t>(ledgerBase + index);
            if (down != ((raw[index] & 0x80) != 0)) {
                RecordInputLedger(ledgerIndex, down, 0, tick);
            }
            raw[index] = current[index];
            if (!tick) {
                if (down != shownDown) InterlockedIncrement(&g_latchStatEdgesDeferred);
                if (down && !shownDown) pending[index] = 1;
                current[index] = shown[index];
                previous[index] = shown[index];
                continue;
            }
            if (!down && !shownDown && pending[index] != 0) {
                // Pressed and released between two ticks: show it as down for
                // this tick so the press is not lost; the release follows on
                // the next tick.
                current[index] = 0x80;
                InterlockedIncrement(&g_latchStatTapsRecovered);
            }
            pending[index] = 0;
            if (((current[index] ^ shown[index]) & 0x80) != 0) {
                InterlockedIncrement(&g_latchStatEdgesDelivered);
                RecordInputLedger(ledgerIndex, (current[index] & 0x80) != 0, 1, tick);
            }
            previous[index] = shown[index];
            shown[index] = current[index];
        }
    };
    step(keys, previousKeys, latch.keys.data(), latch.pendingKeys.data(),
         latch.rawKeys.data(), latch.keys.size(), 0);
    step(buttons, previousButtons, latch.buttons.data(), latch.pendingButtons.data(),
         latch.rawButtons.data(), latch.buttons.size(), 0x100);
}

// Owns the accumulator and the tick decision for the frame. On non-tick
// frames it can set the engine's own freeze-time flag so the stock frame skips
// its world, process and worker calls. Returns true when this hook set it.
bool BeginGatedFrame(void *frameContext) {
    g_framePulseDecision = -1;
    g_frameNativeStep = false;
    ++g_fovFrameSerial;
    if (g_firstPersonSavedCount != 0 || g_firstPersonPassPrepared || g_fpAdvanced ||
        g_passCameraRotation.pending) {
        // The first-person pass did not reach its normal finish point.
        if (g_firstPersonSavedCount != 0) InterlockedIncrement(&g_fpStatLateRestores);
        FirstPersonPassFinish();
    }
    if (!g_quantizedDeltaEnabled || !CaptureGateIsActive()) {
        g_frameLastQpc.QuadPart = 0;
        g_freezeEligibleFrames = 0;
        g_inputEdgeLatch.valid = false;
        return false;
    }

    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    double wallDeltaMs = 0.0;
    if (g_frameLastQpc.QuadPart != 0) {
        wallDeltaMs = static_cast<double>(now.QuadPart - g_frameLastQpc.QuadPart) *
                      1000.0 / static_cast<double>(g_qpcFrequency.QuadPart);
    }
    g_frameLastQpc = now;
    if (wallDeltaMs < 0.0) wallDeltaMs = 0.0;
    if (wallDeltaMs > g_maxWallDeltaMs) wallDeltaMs = g_maxWallDeltaMs;
    g_accumulatorMs += wallDeltaMs;
    const bool pulse = g_accumulatorMs >= g_simulationStepMs;
    if (pulse) g_accumulatorMs -= g_simulationStepMs;
    g_framePulseDecision = pulse ? 1 : 0;
    InterlockedIncrement(&g_freezeStatFrames);
    if (pulse) InterlockedIncrement(&g_freezeStatPulses);

    // Only gate ordinary in-world gameplay: never a menu/loading frame, a
    // real `tfc` session, or a frame without a loaded player cell.
    bool eligible = false;
    auto *tesMain = static_cast<volatile uint8_t *>(frameContext);
    __try {
        const uintptr_t player = ReadEngineValue<uintptr_t>(kPlayerSingleton);
        eligible = tesMain != nullptr &&
            reinterpret_cast<uintptr_t>(frameContext) ==
                ReadEngineValue<uintptr_t>(kTESMainSingleton) &&
            tesMain[6] == 0 && tesMain[7] == 0 &&
            ReadEngineValue<uint8_t>(kMenuModeFlag) == 0 &&
            player >= 0x10000 &&
            ReadEngineValue<uintptr_t>(player + 0x3C) >= 0x10000;
        if (g_nativeStepUnfrozenEnabled && g_freezeRenderFramesEnabled &&
            (!eligible || g_freezeEligibleFrames < kFreezeWarmUpFrames)) {
            // Not a frame that can be followed by frozen ones: real time.
            g_frameNativeStep = true;
            g_frameNativeDeltaMs = wallDeltaMs < 0.01 ? 0.01
                : (wallDeltaMs > 100.0 ? 100.0 : wallDeltaMs);
            g_accumulatorMs = 0.0;
            g_framePulseDecision = 1;
            InterlockedIncrement(&g_freezeStatNative);
        }
        if (eligible && g_frameNativeStep) {
            *reinterpret_cast<volatile float *>(kGlobalFrameDelta) =
                static_cast<float>(g_frameNativeDeltaMs * 0.001) *
                ReadEngineValue<float>(kGlobalTimeMultiplier);
        } else if (eligible) {
            // The player handler runs before this frame's timer update and
            // reads the global delta left by the previous frame. Publish this
            // frame's delta now so handler and simulation agree on which
            // frames are ticks.
            *reinterpret_cast<volatile float *>(kGlobalFrameDelta) =
                static_cast<float>((pulse ? g_simulationStepMs : 0.000001) * 0.001) *
                ReadEngineValue<float>(kGlobalTimeMultiplier);
        }
        if (eligible && g_latchInputEdgesEnabled) {
            ApplyInputEdgeLatch(pulse || g_frameNativeStep);
        } else {
            g_inputEdgeLatch.valid = false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        eligible = false;
        g_inputEdgeLatch.valid = false;
    }
    if (!eligible) {
        g_freezeEligibleFrames = 0;
        InterlockedIncrement(&g_freezeStatIneligible);
        return false;
    }
    if (!g_freezeRenderFramesEnabled) return false;
    if (g_freezeEligibleFrames < kFreezeWarmUpFrames) {
        ++g_freezeEligibleFrames;
        return false;
    }
    if (pulse) return false;
    tesMain[7] = 1;
    InterlockedIncrement(&g_freezeStatFrozen);
    PublishProbe(2100);
    return true;
}

void __fastcall GameFrameHook(void *frameContext, void *) {
    auto *processorCount = reinterpret_cast<volatile int32_t *>(kDetectedProcessorCount);
    const int32_t detectedProcessorCount = *processorCount;
    if (g_singleCoreFrameEnabled) *processorCount = 1;
    const bool frozen = BeginGatedFrame(frameContext);
    g_gameFrame(frameContext);
    if (frozen) static_cast<volatile uint8_t *>(frameContext)[7] = 0;
    g_framePulseDecision = -1;
    if (g_singleCoreFrameEnabled) *processorCount = detectedProcessorCount;
}

DWORD WINAPI LogThread(void *) {
    const std::wstring path = ModuleDirectory(g_self) + L"\\Fallout3HFR.csv";
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 1;
    const char *header = "kind,probe_id,thread_id,qpc,qpc_frequency,frame,pulse,wall_delta_ms,accumulator_ms,"
                         "timer_input_ms,timer_clamp_ms,timer_clamp_remainder_ms,"
                         "frame_delta_s,time_multiplier,havok_max_time_s,havok_physics_delta_s,"
                         "havok_remainder_s,havok_substeps,state_valid_mask,authoritative_hash,"
                         "event_queue_hash,player_ref_id,cell_ref_id,package_ref_id,player_pos_x,"
                         "player_pos_y,player_pos_z,player_rot_x,player_rot_y,player_rot_z,player_scale,"
                         "process_level,life_state,sit_sleep_state,player_state_flags,disabled_control_flags,"
                         "player_view_flags,first_person_anim_data_ptr,weapon_anim_group_id,"
                         "weapon_sequence_state_1,weapon_sequence_state_2,weapon_sequence_ptr,"
                         "weapon_sequence_anim_group_ptr,weapon_sequence_anim_group_index,"
                         "package_procedure,package_start_time,process_time,process_system_time,game_hour,"
                         "game_days_passed,changed_forms,changed_forms_vtable,"
                         "changed_forms_data_ptr,changed_forms_alloc,"
                         "audio_request_a,audio_request_b,audio_request_c,"
                         "playing_sounds,audio_play_calls,script_run_calls,animation_note_calls,"
                         "input_poll_calls,present_calls,script_during_present_calls,"
                         "script_during_present_same_thread_calls,"
                         "script_during_present_other_thread_calls,"
                         "last_script_during_present_thread_id,"
                         "script_during_state2_pass_calls,"
                         "script_during_state2_pass_same_thread_calls,"
                         "script_during_state2_pass_other_thread_calls,"
                         "last_script_during_state2_pass_thread_id,"
                         "changed_forms_clear_calls,"
                         "last_changed_forms_clear_return_address,"
                         "changed_forms_free_calls,"
                         "last_changed_forms_free_return_address,"
                         "state2_pass_return_address,state2_owner_return_address,"
                         "renderer_ptr,renderer_device_ptr,"
                         "renderer_frame_state,renderer_frame_id,renderer_target_active,"
                         "renderer_default_target_ptr,renderer_current_target_ptr,"
                         "renderer_secondary_target_ptr,renderer_target_color_buffer_count,"
                         "renderer_target_color_buffer0_ptr,renderer_target_depth_buffer_ptr,"
                         "renderer_target_color_width,renderer_target_color_height,"
                         "renderer_target_depth_width,renderer_target_depth_height,"
                         "renderer_target_color_data_ptr,renderer_target_depth_data_ptr,"
                         "renderer_present_queue_head_ptr,renderer_present_queue_tail_ptr,"
                         "renderer_present_queue_count,renderer_present_queue_object_ptr,"
                         "renderer_present_queue_object_vtable,renderer_present_queue_swap_chain_ptr,"
                         "geometry_dispatch_calls,render_accumulator_ptr,render_accumulator_count,"
                         "render_accumulator_array_ptr,render_accumulator_cursor,"
                         "render_accumulator_current_geometry_ptr,render_accumulator_pass_id,"
                         "render_accumulator_reverse_geometry_ptr,"
                         "render_accumulator_reverse_property_ptr,"
                         "composite_pass_ordinal,composite_pass_this_ptr,"
                         "composite_pass_base_ptr,composite_pass_vtable,"
                         "composite_pass_target_slot_ptr,composite_pass_target_binding_ptr,"
                         "composite_pass_target_ptr,composite_pass_target_vtable,"
                         "composite_pass_target_ref_count,composite_pass_return_address,"
                         "composite_pass_arg0,composite_pass_arg1,"
                         "composite_pass_arg2,composite_pass_arg3,"
                         "composite_executor_graph_ptr,composite_executor_return_address,"
                         "composite_executor_index,composite_executor_arg1,"
                         "composite_executor_arg2,composite_executor_arg3,"
                         "composite_executor_arg4,composite_executor_arg5,"
                         "composite_leaf_pass_ptr,composite_leaf_root_ptr,"
                         "composite_leaf_caller,composite_leaf_arg0,"
                         "composite_leaf_arg1,composite_leaf_arg2,"
                         "composite_leaf_binding_array_ptr,"
                         "composite_leaf_binding0_ptr,composite_leaf_binding1_ptr,"
                         "composite_leaf_binding2_ptr,composite_leaf_binding3_ptr,"
                         "composite_leaf_binding1_flags,"
                         "composite_leaf_binding1_resource_ptr,"
                         "composite_leaf_binding1_metadata,composite_leaf_binding1_aux,"
                         "composite_leaf_binding1_resource_vtable,"
                         "composite_leaf_binding1_resource_ref_count,"
                         "composite_leaf_binding1_post_release_ref_count,"
                         "composite_leaf_binding0_flags,"
                         "composite_leaf_binding0_resource_ptr,"
                         "composite_leaf_binding0_metadata,composite_leaf_binding0_aux,"
                         "composite_leaf_binding0_resource_vtable,"
                         "composite_leaf_binding0_resource_ref_count,"
                         "composite_leaf_binding2_flags,"
                         "composite_leaf_binding2_resource_ptr,"
                         "composite_leaf_binding2_metadata,composite_leaf_binding2_aux,"
                         "composite_leaf_binding2_resource_vtable,"
                         "composite_leaf_binding2_resource_ref_count,"
                         "composite_leaf_binding3_flags,"
                         "composite_leaf_binding3_resource_ptr,"
                         "composite_leaf_binding3_metadata,composite_leaf_binding3_aux,"
                         "composite_leaf_binding3_resource_vtable,"
                         "composite_leaf_binding3_resource_ref_count,"
                         "retention_acquire_calls,retention_release_calls,"
                         "retention_reject_calls,retention_forced_release_calls,"
                         "retention_active,retention_slot1_acquire_ref_count,"
                         "retention_slot2_acquire_ref_count,"
                         "retention_slot3_acquire_ref_count,"
                         "retention_slot1_release_ref_count,"
                         "retention_slot2_release_ref_count,"
                         "retention_slot3_release_ref_count,"
                         "retention_reject_mask,"
                         "retention_observed_slot1_ref_count,"
                         "retention_observed_slot2_ref_count,"
                         "retention_observed_slot3_ref_count,"
                         "leaf_lifetime_sample_calls,leaf_lifetime_check_calls,"
                         "leaf_lifetime_baseline_fault_mask,"
                         "leaf_lifetime_post_present_fault_mask,"
                         "leaf_lifetime_change_mask,leaf_lifetime_baseline_hash,"
                         "leaf_lifetime_post_present_hash,"
                         "leaf_replay_attempt_calls,leaf_replay_draw_calls,"
                         "leaf_replay_finalize_calls,leaf_replay_reject_calls,"
                         "leaf_replay_reject_mask,leaf_replay_active,"
                         "scene_graph_ptr,camera_ptr,"
                         "camera_local_rotation_hash,camera_world_rotation_hash,"
                         "scene_update_root_ptr,scene_update_root_local_rotation_hash,"
                         "scene_update_root_world_rotation_hash,"
                         "camera_parent0_ptr,camera_parent0_local_rotation_hash,camera_parent0_world_rotation_hash,"
                         "camera_parent1_ptr,camera_parent1_local_rotation_hash,camera_parent1_world_rotation_hash,"
                         "camera_parent2_ptr,camera_parent2_local_rotation_hash,camera_parent2_world_rotation_hash,"
                         "camera_parent3_ptr,camera_parent3_local_rotation_hash,camera_parent3_world_rotation_hash,"
                         "camera_world_x,camera_world_y,camera_world_z,camera_world_scale,"
                         "camera_frustum_l,camera_frustum_r,camera_frustum_t,camera_frustum_b,"
                         "camera_frustum_n,camera_frustum_f,camera_orthographic,dropped,"
                         "player_root_ptr,player_root_parent_ptr,player_root_flags,"
                         "player_root_local_rotation_hash,player_root_world_rotation_hash,"
                         "player_root_local_x,player_root_local_y,player_root_local_z,"
                         "player_root_world_x,player_root_world_y,player_root_world_z,"
                         "player_root_local_scale,player_root_world_scale,"
                         "third_person_root_ptr,third_person_root_parent_ptr,third_person_root_flags,"
                         "third_person_root_local_rotation_hash,third_person_root_world_rotation_hash,"
                         "third_person_root_local_x,third_person_root_local_y,third_person_root_local_z,"
                         "third_person_root_world_x,third_person_root_world_y,third_person_root_world_z,"
                         "third_person_root_local_scale,third_person_root_world_scale,"
                         "first_person_root_ptr,first_person_root_parent_ptr,first_person_root_flags,"
                         "first_person_root_local_rotation_hash,first_person_root_world_rotation_hash,"
                         "first_person_root_local_x,first_person_root_local_y,first_person_root_local_z,"
                         "first_person_root_world_x,first_person_root_world_y,first_person_root_world_z,"
                         "first_person_root_local_scale,first_person_root_world_scale,"
                         "first_person_node_ptr,first_person_node_parent_ptr,first_person_node_flags,"
                         "first_person_node_local_rotation_hash,first_person_node_world_rotation_hash,"
                         "first_person_node_local_x,first_person_node_local_y,first_person_node_local_z,"
                         "first_person_node_world_x,first_person_node_world_y,first_person_node_world_z,"
                         "first_person_node_local_scale,first_person_node_world_scale\r\n";
    DWORD written = 0;
    WriteFile(file, header, static_cast<DWORD>(std::strlen(header)), &written, nullptr);

    char line[8192]{};
    ULONGLONG lastFreezeReport = 0;
    uint32_t lastFreezeReportFrames = 0;
    while (!g_stop.load(std::memory_order_acquire) ||
           g_readIndex.load(std::memory_order_relaxed) != g_writeIndex.load(std::memory_order_acquire)) {
        bool consumed = false;
        for (;;) {
            const uint32_t read = g_readIndex.load(std::memory_order_relaxed);
            const uint32_t write = g_writeIndex.load(std::memory_order_acquire);
            if (read == write) break;
            TelemetryEvent &event = g_ring[read & kRingMask];
            if (event.sequence.load(std::memory_order_acquire) != read + 1) break;
            const int length = _snprintf_s(
                line, sizeof(line), _TRUNCATE,
                "%u,%u,%u,%lld,%lld,%u,%u,%.6f,%.6f,%u,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%u,"
                "%08X,%016llX,%016llX,%08X,%08X,%08X,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,"
                "%u,%u,%u,%08X,%08X,%08X,%08X,%u,%d,%d,%08X,%08X,%u,%u,%.9g,%.9g,%.9g,%.9g,%.9g,"
                "%u,%08X,%08X,%u,"
                "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%08X,%u,%08X,%08X,%08X,"
                "%08X,%08X,%u,%u,%u,%08X,%08X,%08X,"
                "%u,%08X,%08X,%u,%u,%u,%u,%08X,%08X,"
                "%08X,%08X,%u,%08X,%08X,%08X,%u,%08X,%u,%08X,%u,%08X,%u,%08X,%08X,"
                "%u,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%u,%08X,%08X,%08X,%08X,%08X,"
                "%08X,%08X,%u,%08X,%08X,%08X,%08X,%08X,"
                "%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,"
                "%08X,%08X,%08X,%08X,%08X,%08X,%08X,"
                "%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,"
                "%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,"
                "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
                "%08X,%u,%u,%u,"
                "%u,%u,%08X,%08X,%08X,%08X,%08X,"
                "%u,%u,%u,%u,%08X,%u,"
                "%08X,%08X,%016llX,%016llX,"
                "%08X,%016llX,%016llX,"
                "%08X,%016llX,%016llX,%08X,%016llX,%016llX,"
                "%08X,%016llX,%016llX,%08X,%016llX,%016llX,"
                "%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%u,%u,"
                "%08X,%08X,%08X,%016llX,%016llX,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,"
                "%08X,%08X,%08X,%016llX,%016llX,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,"
                "%08X,%08X,%08X,%016llX,%016llX,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,"
                "%08X,%08X,%08X,%016llX,%016llX,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g\r\n",
                event.kind, event.probeId, event.threadId, static_cast<long long>(event.qpc),
                static_cast<long long>(g_qpcFrequency.QuadPart), event.frame, event.pulse,
                event.wallDeltaMs, event.accumulatorMs, event.timerInputMs,
                event.timerClampMs, event.timerClampRemainderMs, event.frameDeltaSeconds,
                event.timeMultiplier, event.havokMaxTime, event.havokPhysicsDelta,
                event.havokRemainder, event.havokSubsteps, event.state.validMask,
                static_cast<unsigned long long>(event.state.authoritativeHash),
                static_cast<unsigned long long>(event.state.eventQueueHash),
                event.state.playerRefId, event.state.cellRefId, event.state.packageRefId,
                event.state.playerPosition[0], event.state.playerPosition[1],
                event.state.playerPosition[2], event.state.playerRotation[0],
                event.state.playerRotation[1], event.state.playerRotation[2],
                event.state.playerScale, event.state.processLevel, event.state.lifeState,
                event.state.sitSleepState, event.state.playerStateFlags,
                event.state.disabledControlFlags, event.state.playerViewFlags,
                event.state.firstPersonAnimDataPtr, event.state.weaponAnimGroupId,
                event.state.weaponSequenceState1, event.state.weaponSequenceState2,
                event.state.weaponSequencePtr, event.state.weaponSequenceAnimGroupPtr,
                event.state.weaponSequenceAnimGroupIndex,
                event.state.packageProcedure,
                event.state.packageStartTime, event.state.processTime,
                event.state.processSystemTime, event.state.gameHour, event.state.gameDaysPassed,
                event.state.changedForms, event.state.changedFormsVtable,
                event.state.changedFormsDataPtr, event.state.changedFormsAlloc,
                event.state.audioRequestA, event.state.audioRequestB,
                event.state.audioRequestC, event.state.playingSounds,
                event.state.audioPlayCalls, event.state.scriptRunCalls,
                event.state.animationNoteCalls, event.state.inputPollCalls,
                event.state.presentCalls, event.state.scriptDuringPresentCalls,
                event.state.scriptDuringPresentSameThreadCalls,
                event.state.scriptDuringPresentOtherThreadCalls,
                event.state.lastScriptDuringPresentThreadId,
                event.state.scriptDuringState2PassCalls,
                event.state.scriptDuringState2PassSameThreadCalls,
                event.state.scriptDuringState2PassOtherThreadCalls,
                event.state.lastScriptDuringState2PassThreadId,
                event.state.changedFormsClearCalls,
                event.state.lastChangedFormsClearReturnAddress,
                event.state.changedFormsFreeCalls,
                event.state.lastChangedFormsFreeReturnAddress,
                event.state.state2PassReturnAddress,
                event.state.state2OwnerReturnAddress,
                event.state.rendererPtr, event.state.rendererDevicePtr,
                event.state.rendererFrameState, event.state.rendererFrameId,
                event.state.rendererTargetActive, event.state.rendererDefaultTargetPtr,
                event.state.rendererCurrentTargetPtr,
                event.state.rendererSecondaryTargetPtr,
                event.state.rendererTargetColorBufferCount,
                event.state.rendererTargetColorBuffer0Ptr,
                event.state.rendererTargetDepthBufferPtr,
                event.state.rendererTargetColorWidth,
                event.state.rendererTargetColorHeight,
                event.state.rendererTargetDepthWidth,
                event.state.rendererTargetDepthHeight,
                event.state.rendererTargetColorDataPtr,
                event.state.rendererTargetDepthDataPtr,
                event.state.rendererPresentQueueHeadPtr,
                event.state.rendererPresentQueueTailPtr,
                event.state.rendererPresentQueueCount,
                event.state.rendererPresentQueueObjectPtr,
                event.state.rendererPresentQueueObjectVtable,
                event.state.rendererPresentQueueSwapChainPtr,
                event.state.geometryDispatchCalls,
                event.state.renderAccumulatorPtr,
                event.state.renderAccumulatorCount,
                event.state.renderAccumulatorArrayPtr,
                event.state.renderAccumulatorCursor,
                event.state.renderAccumulatorCurrentGeometryPtr,
                event.state.renderAccumulatorPassId,
                event.state.renderAccumulatorReverseGeometryPtr,
                event.state.renderAccumulatorReversePropertyPtr,
                event.state.compositePassOrdinal,
                event.state.compositePassThisPtr,
                event.state.compositePassBasePtr,
                event.state.compositePassVtable,
                event.state.compositePassTargetSlotPtr,
                event.state.compositePassTargetBindingPtr,
                event.state.compositePassTargetPtr,
                event.state.compositePassTargetVtable,
                event.state.compositePassTargetRefCount,
                event.state.compositePassReturnAddress,
                event.state.compositePassArg0,
                event.state.compositePassArg1,
                event.state.compositePassArg2,
                event.state.compositePassArg3,
                event.state.compositeExecutorGraphPtr,
                event.state.compositeExecutorReturnAddress,
                event.state.compositeExecutorIndex,
                event.state.compositeExecutorArg1,
                event.state.compositeExecutorArg2,
                event.state.compositeExecutorArg3,
                event.state.compositeExecutorArg4,
                event.state.compositeExecutorArg5,
                event.state.compositeLeafPassPtr,
                event.state.compositeLeafRootPtr,
                event.state.compositeLeafCaller,
                event.state.compositeLeafArg0,
                event.state.compositeLeafArg1,
                event.state.compositeLeafArg2,
                event.state.compositeLeafBindingArrayPtr,
                event.state.compositeLeafBinding0Ptr,
                event.state.compositeLeafBinding1Ptr,
                event.state.compositeLeafBinding2Ptr,
                event.state.compositeLeafBinding3Ptr,
                event.state.compositeLeafBinding1Flags,
                event.state.compositeLeafBinding1ResourcePtr,
                event.state.compositeLeafBinding1Metadata,
                event.state.compositeLeafBinding1Aux,
                event.state.compositeLeafBinding1ResourceVtable,
                event.state.compositeLeafBinding1ResourceRefCount,
                event.state.compositeLeafBinding1PostReleaseRefCount,
                event.state.compositeLeafBinding0Flags,
                event.state.compositeLeafBinding0ResourcePtr,
                event.state.compositeLeafBinding0Metadata,
                event.state.compositeLeafBinding0Aux,
                event.state.compositeLeafBinding0ResourceVtable,
                event.state.compositeLeafBinding0ResourceRefCount,
                event.state.compositeLeafBinding2Flags,
                event.state.compositeLeafBinding2ResourcePtr,
                event.state.compositeLeafBinding2Metadata,
                event.state.compositeLeafBinding2Aux,
                event.state.compositeLeafBinding2ResourceVtable,
                event.state.compositeLeafBinding2ResourceRefCount,
                event.state.compositeLeafBinding3Flags,
                event.state.compositeLeafBinding3ResourcePtr,
                event.state.compositeLeafBinding3Metadata,
                event.state.compositeLeafBinding3Aux,
                event.state.compositeLeafBinding3ResourceVtable,
                event.state.compositeLeafBinding3ResourceRefCount,
                event.state.retentionAcquireCalls,
                event.state.retentionReleaseCalls,
                event.state.retentionRejectCalls,
                event.state.retentionForcedReleaseCalls,
                event.state.retentionActive,
                event.state.retentionSlot1AcquireRefCount,
                event.state.retentionSlot2AcquireRefCount,
                event.state.retentionSlot3AcquireRefCount,
                event.state.retentionSlot1ReleaseRefCount,
                event.state.retentionSlot2ReleaseRefCount,
                event.state.retentionSlot3ReleaseRefCount,
                event.state.retentionRejectMask,
                event.state.retentionObservedSlot1RefCount,
                event.state.retentionObservedSlot2RefCount,
                event.state.retentionObservedSlot3RefCount,
                event.state.leafLifetimeSampleCalls,
                event.state.leafLifetimeCheckCalls,
                event.state.leafLifetimeBaselineFaultMask,
                event.state.leafLifetimePostPresentFaultMask,
                event.state.leafLifetimeChangeMask,
                event.state.leafLifetimeBaselineHash,
                event.state.leafLifetimePostPresentHash,
                event.state.leafReplayAttemptCalls,
                event.state.leafReplayDrawCalls,
                event.state.leafReplayFinalizeCalls,
                event.state.leafReplayRejectCalls,
                event.state.leafReplayRejectMask,
                event.state.leafReplayActive,
                event.state.sceneGraphPtr,
                event.state.cameraPtr,
                static_cast<unsigned long long>(event.state.cameraLocalRotationHash),
                static_cast<unsigned long long>(event.state.cameraWorldRotationHash),
                event.state.sceneUpdateRootPtr,
                static_cast<unsigned long long>(event.state.sceneUpdateRootLocalRotationHash),
                static_cast<unsigned long long>(event.state.sceneUpdateRootWorldRotationHash),
                event.state.cameraParentPtr[0],
                static_cast<unsigned long long>(event.state.cameraParentLocalRotationHash[0]),
                static_cast<unsigned long long>(event.state.cameraParentWorldRotationHash[0]),
                event.state.cameraParentPtr[1],
                static_cast<unsigned long long>(event.state.cameraParentLocalRotationHash[1]),
                static_cast<unsigned long long>(event.state.cameraParentWorldRotationHash[1]),
                event.state.cameraParentPtr[2],
                static_cast<unsigned long long>(event.state.cameraParentLocalRotationHash[2]),
                static_cast<unsigned long long>(event.state.cameraParentWorldRotationHash[2]),
                event.state.cameraParentPtr[3],
                static_cast<unsigned long long>(event.state.cameraParentLocalRotationHash[3]),
                static_cast<unsigned long long>(event.state.cameraParentWorldRotationHash[3]),
                event.state.cameraWorldPosition[0],
                event.state.cameraWorldPosition[1], event.state.cameraWorldPosition[2],
                event.state.cameraWorldScale, event.state.cameraFrustum[0],
                event.state.cameraFrustum[1], event.state.cameraFrustum[2],
                event.state.cameraFrustum[3], event.state.cameraFrustum[4],
                event.state.cameraFrustum[5], event.state.cameraOrthographic,
                g_dropped.load(std::memory_order_relaxed),
                event.state.transformNodePtr[0], event.state.transformNodeParentPtr[0],
                event.state.transformNodeFlags[0],
                static_cast<unsigned long long>(event.state.transformNodeLocalRotationHash[0]),
                static_cast<unsigned long long>(event.state.transformNodeWorldRotationHash[0]),
                event.state.transformNodeLocalPosition[0][0],
                event.state.transformNodeLocalPosition[0][1],
                event.state.transformNodeLocalPosition[0][2],
                event.state.transformNodeWorldPosition[0][0],
                event.state.transformNodeWorldPosition[0][1],
                event.state.transformNodeWorldPosition[0][2],
                event.state.transformNodeLocalScale[0], event.state.transformNodeWorldScale[0],
                event.state.transformNodePtr[1], event.state.transformNodeParentPtr[1],
                event.state.transformNodeFlags[1],
                static_cast<unsigned long long>(event.state.transformNodeLocalRotationHash[1]),
                static_cast<unsigned long long>(event.state.transformNodeWorldRotationHash[1]),
                event.state.transformNodeLocalPosition[1][0],
                event.state.transformNodeLocalPosition[1][1],
                event.state.transformNodeLocalPosition[1][2],
                event.state.transformNodeWorldPosition[1][0],
                event.state.transformNodeWorldPosition[1][1],
                event.state.transformNodeWorldPosition[1][2],
                event.state.transformNodeLocalScale[1], event.state.transformNodeWorldScale[1],
                event.state.transformNodePtr[2], event.state.transformNodeParentPtr[2],
                event.state.transformNodeFlags[2],
                static_cast<unsigned long long>(event.state.transformNodeLocalRotationHash[2]),
                static_cast<unsigned long long>(event.state.transformNodeWorldRotationHash[2]),
                event.state.transformNodeLocalPosition[2][0],
                event.state.transformNodeLocalPosition[2][1],
                event.state.transformNodeLocalPosition[2][2],
                event.state.transformNodeWorldPosition[2][0],
                event.state.transformNodeWorldPosition[2][1],
                event.state.transformNodeWorldPosition[2][2],
                event.state.transformNodeLocalScale[2], event.state.transformNodeWorldScale[2],
                event.state.transformNodePtr[3], event.state.transformNodeParentPtr[3],
                event.state.transformNodeFlags[3],
                static_cast<unsigned long long>(event.state.transformNodeLocalRotationHash[3]),
                static_cast<unsigned long long>(event.state.transformNodeWorldRotationHash[3]),
                event.state.transformNodeLocalPosition[3][0],
                event.state.transformNodeLocalPosition[3][1],
                event.state.transformNodeLocalPosition[3][2],
                event.state.transformNodeWorldPosition[3][0],
                event.state.transformNodeWorldPosition[3][1],
                event.state.transformNodeWorldPosition[3][2],
                event.state.transformNodeLocalScale[3], event.state.transformNodeWorldScale[3]);
            if (length > 0) WriteFile(file, line, static_cast<DWORD>(length), &written, nullptr);
            event.sequence.store(0, std::memory_order_release);
            g_readIndex.store(read + 1, std::memory_order_release);
            consumed = true;
        }
        for (uint32_t ledgerWrite = g_inputLedgerWrite.load(std::memory_order_acquire);
             g_inputLedgerRead != ledgerWrite; ++g_inputLedgerRead) {
            const InputLedgerEntry entry =
                g_inputLedger[g_inputLedgerRead % g_inputLedger.size()];
            AppendStatus("input %s frame=%u qpc=%lld code=%03X down=%u tick=%u action=%d blocked=%u armed=%u counter=%u holster=%u hold=%.6f delta=%.9f",
                         entry.kind == 0 ? "raw" : "shown", entry.frame,
                         static_cast<long long>(entry.qpc), entry.index,
                         entry.down, entry.tick, entry.weaponAction,
                         entry.attackBlocked, entry.attackArmed, entry.attackCounter,
                         entry.holsterLatched, entry.reloadHoldTimer, entry.frameDelta);
        }
        if (g_quantizedDeltaEnabled) {
            const ULONGLONG tick = GetTickCount64();
            const LONG frames = ReadDispatchCounter(&g_freezeStatFrames);
            if (tick - lastFreezeReport >= 5000 &&
                static_cast<uint32_t>(frames) != lastFreezeReportFrames) {
                lastFreezeReport = tick;
                lastFreezeReportFrames = static_cast<uint32_t>(frames);
                AppendStatus("gated_frames frames=%ld ticks=%ld frozen=%ld ineligible=%ld edges_delivered=%ld edges_deferred=%ld taps_recovered=%ld interp_applied=%ld interp_poses=%ld interp_snaps=%ld interp_root_mismatch=%ld interp_faulted=%d actors=%ld actor_nodes_written=%ld actor_nodes_max=%ld actor_snaps=%ld actor_offtick=%ld actor_table_resets=%ld actor_duplicates=%ld actor_overflow=%ld actor_faulted=%d dropped=%u offtick_frozen[tiny,small,large]=%ld,%ld,%ld of %ld offtick_unfrozen=%ld,%ld,%ld of %ld offtick_max=%.3f observe_only=%d restore_conflicts=%ld first_person nodes=%ld draws=%ld change_draws[tick,after_tick,both,neither]=%ld,%ld,%ld,%ld max=%.3f root_moved_frozen=%ld passes=%ld late_restores=%ld fp_restore_conflicts=%ld fp_local_changes[tick,after_tick,both,neither]=%ld,%ld,%ld,%ld fp_local_blends=%ld fp_local_per_frame=%ld interp_identity_resets=%ld interp_ineligible_resets=%ld interp_cell_changes=%ld interp_parent_changes=%ld hud_target_timer_skips=%ld eye_height_steps=%ld fp_camera_node_writes=%ld fp_camera_node_misses=%ld sky_nodes_written=%ld sky_restore_conflicts=%ld camera_rotation_writes=%ld camera_relation_changes=%ld camera_rotation_conflicts=%ld objects list_offset=0x%lX cell_scans=%ld refs=%ld with_root=%ld root_changes[tick,after_tick,both,neither]=%ld,%ld,%ld,%ld moving_max=%ld active_max=%ld subtrees=%ld controlled=%ld walks=%ld table_full=%ld grid state=%ld count=%ld stride=%ld array_offset=0x%lX cells=%ld invalidations=%ld fov sites=%ld steps=%ld substitutions=%ld third_person_draws=%ld grid_diag tes_vt=%08lX grid_vt=%08lX cell_vt=%08lX stored=%08lX first_word=%08lX readable=%ld body nodes_written=%ld blends=%ld offtick=%ld restore_conflicts=%ld changes[tick,after_tick,both,neither]=%ld,%ld,%ld,%ld third_person_camera steps=%ld offtick=%ld camera_bone applied=%ld mismatch=%ld hand_watch nodes=%ld checks=%ld events=%lu ratio=%.4f trace armings=%ld hits=%ld body minor=%ld",
                             frames, ReadDispatchCounter(&g_freezeStatPulses),
                             ReadDispatchCounter(&g_freezeStatFrozen),
                             ReadDispatchCounter(&g_freezeStatIneligible),
                             ReadDispatchCounter(&g_latchStatEdgesDelivered),
                             ReadDispatchCounter(&g_latchStatEdgesDeferred),
                             ReadDispatchCounter(&g_latchStatTapsRecovered),
                             ReadDispatchCounter(&g_translationStatApplied),
                             ReadDispatchCounter(&g_translationStatPoses),
                             ReadDispatchCounter(&g_translationStatSnaps),
                             ReadDispatchCounter(&g_translationStatRootMismatch),
                             g_renderTranslationInterpolationFaulted ? 1 : 0,
                             ReadDispatchCounter(&g_actorStatTracked),
                             ReadDispatchCounter(&g_actorStatApplied),
                             ReadDispatchCounter(&g_actorStatNodesMax),
                             ReadDispatchCounter(&g_actorStatSnaps),
                             ReadDispatchCounter(&g_actorStatOffTickChanges),
                             ReadDispatchCounter(&g_actorStatTableResets),
                             ReadDispatchCounter(&g_actorStatDuplicates),
                             ReadDispatchCounter(&g_actorStatOverflow),
                             g_actorTranslationInterpolationFaulted ? 1 : 0,
                             g_dropped.load(std::memory_order_relaxed),
                             ReadDispatchCounter(&g_actorStatOffTickClass[0][1]),
                             ReadDispatchCounter(&g_actorStatOffTickClass[1][1]),
                             ReadDispatchCounter(&g_actorStatOffTickClass[2][1]),
                             ReadDispatchCounter(&g_actorStatNodeDraws[1]),
                             ReadDispatchCounter(&g_actorStatOffTickClass[0][0]),
                             ReadDispatchCounter(&g_actorStatOffTickClass[1][0]),
                             ReadDispatchCounter(&g_actorStatOffTickClass[2][0]),
                             ReadDispatchCounter(&g_actorStatNodeDraws[0]),
                             static_cast<double>(ReadDispatchCounter(
                                 &g_actorStatOffTickMaxMilli)) / 1000.0,
                             g_debugActorObserveOnly ? 1 : 0,
                             ReadDispatchCounter(&g_actorStatRestoreConflicts),
                             ReadDispatchCounter(&g_fpStatNodes),
                             ReadDispatchCounter(&g_fpStatDraws),
                             ReadDispatchCounter(&g_fpStatChangeDraws[0]),
                             ReadDispatchCounter(&g_fpStatChangeDraws[1]),
                             ReadDispatchCounter(&g_fpStatChangeDraws[2]),
                             ReadDispatchCounter(&g_fpStatChangeDraws[3]),
                             static_cast<double>(ReadDispatchCounter(&g_fpStatMaxMilli)) /
                                 1000.0,
                             ReadDispatchCounter(&g_fpStatRootMovedFrozen),
                             ReadDispatchCounter(&g_fpStatPasses),
                             ReadDispatchCounter(&g_fpStatLateRestores),
                             ReadDispatchCounter(&g_fpStatRestoreConflicts),
                             ReadDispatchCounter(&g_fpStatLocalChanges[0]),
                             ReadDispatchCounter(&g_fpStatLocalChanges[1]),
                             ReadDispatchCounter(&g_fpStatLocalChanges[2]),
                             ReadDispatchCounter(&g_fpStatLocalChanges[3]),
                             ReadDispatchCounter(&g_fpStatLocalBlends),
                             ReadDispatchCounter(&g_fpStatLocalPerFrame),
                             ReadDispatchCounter(&g_translationStatIdentityResets),
                             ReadDispatchCounter(&g_translationStatIneligibleResets),
                             ReadDispatchCounter(&g_translationStatCellChanges),
                             ReadDispatchCounter(&g_translationStatParentChanges),
                             ReadDispatchCounter(&g_hudTargetTimerSkips),
                             ReadDispatchCounter(&g_translationStatEyeSteps),
                             ReadDispatchCounter(&g_fpStatCameraNodeWrites),
                             ReadDispatchCounter(&g_fpStatCameraNodeMisses),
                             ReadDispatchCounter(&g_skyStatNodesWritten),
                             ReadDispatchCounter(&g_skyStatRestoreConflicts),
                             ReadDispatchCounter(&g_cameraStatRotationWrites),
                             ReadDispatchCounter(&g_cameraStatRelationChanges),
                             ReadDispatchCounter(&g_cameraStatRotationConflicts),
                             ReadDispatchCounter(&g_objectStatListOffset),
                             ReadDispatchCounter(&g_objectStatCellScans),
                             ReadDispatchCounter(&g_objectStatReferences),
                             ReadDispatchCounter(&g_objectStatWithRoot),
                             ReadDispatchCounter(&g_objectStatChanges[0]),
                             ReadDispatchCounter(&g_objectStatChanges[1]),
                             ReadDispatchCounter(&g_objectStatChanges[2]),
                             ReadDispatchCounter(&g_objectStatChanges[3]),
                             ReadDispatchCounter(&g_objectStatMovingMax),
                             ReadDispatchCounter(&g_objectStatActiveMax),
                             ReadDispatchCounter(&g_objectStatSubtrees),
                             ReadDispatchCounter(&g_objectStatControlled),
                             ReadDispatchCounter(&g_objectStatWalks),
                             ReadDispatchCounter(&g_objectStatTableFull),
                             ReadDispatchCounter(&g_gridStatState),
                             ReadDispatchCounter(&g_gridStatCount),
                             ReadDispatchCounter(&g_gridStatStride),
                             ReadDispatchCounter(&g_gridStatArrayOffset),
                             ReadDispatchCounter(&g_gridStatCells),
                             ReadDispatchCounter(&g_gridStatInvalidations),
                             ReadDispatchCounter(&g_fovStatSites),
                             ReadDispatchCounter(&g_fovStatSteps),
                             ReadDispatchCounter(&g_fovStatSubstitutions),
                             ReadDispatchCounter(&g_translationStatThirdPersonDraws),
                             ReadDispatchCounter(&g_gridDiagnostics[0]),
                             ReadDispatchCounter(&g_gridDiagnostics[1]),
                             ReadDispatchCounter(&g_gridDiagnostics[2]),
                             ReadDispatchCounter(&g_gridDiagnostics[3]),
                             ReadDispatchCounter(&g_gridDiagnostics[4]),
                             ReadDispatchCounter(&g_gridDiagnostics[5]),
                             ReadDispatchCounter(&g_bodyStatNodesWritten),
                             ReadDispatchCounter(&g_bodyStatBlends),
                             ReadDispatchCounter(&g_bodyStatOffTick),
                             ReadDispatchCounter(&g_bodyStatRestoreConflicts),
                             ReadDispatchCounter(&g_bodyStatChanges[0]),
                             ReadDispatchCounter(&g_bodyStatChanges[1]),
                             ReadDispatchCounter(&g_bodyStatChanges[2]),
                             ReadDispatchCounter(&g_bodyStatChanges[3]),
                             ReadDispatchCounter(&g_thirdPersonStatSteps),
                             ReadDispatchCounter(&g_thirdPersonStatOffTick),
                             ReadDispatchCounter(&g_cameraBoneStatApplied),
                             ReadDispatchCounter(&g_cameraBoneStatMismatch),
                             ReadDispatchCounter(&g_handStatNodes),
                             ReadDispatchCounter(&g_handStatChecks),
                             static_cast<unsigned long>(
                                 g_handEventCount.load(std::memory_order_acquire)),
                             static_cast<double>(g_handRatio),
                             ReadDispatchCounter(&g_handTraceArmings),
                             ReadDispatchCounter(&g_handTraceHits),
                             ReadDispatchCounter(&g_bodyStatMinor));
                {
                    LARGE_INTEGER frequency{};
                    QueryPerformanceFrequency(&frequency);
                    const double draws = static_cast<double>(
                        ReadDispatchCounter(&g_perfDraws));
                    const double toMicros = draws > 0.0 && frequency.QuadPart > 0
                        ? 1000000.0 / static_cast<double>(frequency.QuadPart) / draws
                        : 0.0;
                    AppendStatus("perf draws=%.0f pre_draw_us=%.1f actor_and_object_pass_us=%.1f of_which_cell_walk_us=%.1f body_pass_us=%.1f cells_read=%ld hot_cells=%ld finger bones=%ld fixes=%ld hands_disagree=%ld fp_late_blends=%ld actor_tick_draw_blends=%ld pass_camera_rotation writes=%ld conflicts=%ld skips=%ld native_frames=%ld",
                                 draws,
                                 static_cast<double>(InterlockedCompareExchange64(
                                     &g_perfPreDrawTicks, 0, 0)) * toMicros,
                                 static_cast<double>(InterlockedCompareExchange64(
                                     &g_perfActorPassTicks, 0, 0)) * toMicros,
                                 static_cast<double>(InterlockedCompareExchange64(
                                     &g_perfObjectWalkTicks, 0, 0)) * toMicros,
                                 static_cast<double>(InterlockedCompareExchange64(
                                     &g_perfBodyPassTicks, 0, 0)) * toMicros,
                                 ReadDispatchCounter(&g_objectStatCellsRead),
                                 ReadDispatchCounter(&g_objectStatHotCells),
                                 ReadDispatchCounter(&g_fingerStatBones),
                                 ReadDispatchCounter(&g_fingerStatFixes),
                                 ReadDispatchCounter(&g_fingerStatHandsDisagree),
                                 ReadDispatchCounter(&g_fpStatLateBlends),
                                 ReadDispatchCounter(&g_actorStatTickDrawBlends),
                                 ReadDispatchCounter(&g_cameraStatPassWrites),
                                 ReadDispatchCounter(&g_cameraStatPassConflicts),
                                 ReadDispatchCounter(&g_cameraStatPassSkips),
                                 ReadDispatchCounter(&g_freezeStatNative));
                }
                if (g_debugHandWriteTrace) ServiceHandWriteTrace();
                const uint32_t writeEvents =
                    g_handWriteEventCount.load(std::memory_order_acquire);
                for (; g_handWriteEventsLogged < writeEvents; ++g_handWriteEventsLogged) {
                    const HandWriteEvent &event = g_handWriteEvents[g_handWriteEventsLogged];
                    AppendStatus("hand_write after_instruction=%08X before=%.5f after=%.5f frame=%u tick=%u frozen=%u returns=%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X",
                                 event.instruction, event.before, event.after, event.frame,
                                 event.tick, event.frozen, event.returns[0], event.returns[1],
                                 event.returns[2], event.returns[3], event.returns[4],
                                 event.returns[5], event.returns[6], event.returns[7],
                                 event.returns[8], event.returns[9], event.returns[10],
                                 event.returns[11]);
                }
                const uint32_t handEvents = g_handEventCount.load(std::memory_order_acquire);
                for (; g_handEventsLogged < handEvents; ++g_handEventsLogged) {
                    const HandWatchEvent &event = g_handEvents[g_handEventsLogged];
                    static const char *const kValueNames[] = {
                        "local_scale", "world_scale", "bone_length", "rotation_error"};
                    AppendStatus("hand_watch node=%s value=%s before=%.5f after=%.5f frame=%u first_person=%u tick=%u frozen=%u",
                                 event.name, kValueNames[event.value & 3], event.before,
                                 event.after, event.frame, event.firstPerson, event.tick,
                                 event.frozen);
                }
                int objectsReported = 0;
                for (ObservedObject &entry : g_observedObjects) {
                    if (entry.root == 0 || objectsReported >= 12) continue;
                    const uint32_t total = entry.changes[0] + entry.changes[1] +
                        entry.changes[2] + entry.changes[3];
                    if (total == entry.reported) continue;
                    entry.reported = total;
                    ++objectsReported;
                    AppendStatus("object ref=%08X base=%08X type=%u changes[tick,after_tick,both,neither]=%u,%u,%u,%u largest_step=%.3f",
                                 entry.refId, entry.baseId, entry.baseType,
                                 entry.changes[0], entry.changes[1], entry.changes[2],
                                 entry.changes[3], entry.largestStep);
                }
                // First-person nodes whose off-tick change count moved since
                // the last report: these are the ones not being blended.
                int reported = 0;
                for (FirstPersonLocalHistory &entry : g_firstPersonLocal) {
                    if (entry.node == 0 || reported >= 12) continue;
                    const uint32_t offTick = entry.statChanges[1] + entry.statChanges[3];
                    if (offTick == entry.statReportedOffTick) continue;
                    entry.statReportedOffTick = offTick;
                    ++reported;
                    AppendStatus("fp_node name=%s changes[tick,after_tick,both,neither]=%u,%u,%u,%u blends=%u per_frame=%u",
                                 entry.name, entry.statChanges[0], entry.statChanges[1],
                                 entry.statChanges[2], entry.statChanges[3],
                                 entry.statBlends, entry.statPerFrame);
                }
                const uint32_t timingWrite =
                    g_timingTraceWrite.load(std::memory_order_acquire);
                if (timingWrite - g_timingTraceRead > g_timingTrace.size()) {
                    g_timingTraceRead =
                        timingWrite - static_cast<uint32_t>(g_timingTrace.size());
                }
                for (; g_timingTraceRead != timingWrite; ++g_timingTraceRead) {
                    const TimingTraceRow row =
                        g_timingTrace[g_timingTraceRead % g_timingTrace.size()];
                    if (row.tag == 'R') {
                        AppendStatus("reload pass=%u kind=%u action=%d alpha=%.3f changed=%u accept_tick=%u accept_late=%u asis_offtick=%u asis_perframe=%u asis_first_late=%u blending_tick=%u blending_late=%u hand_decision=%.0f hand_engine=%.5f hand_shown=%.5f",
                                     row.serial, row.kind, row.state, row.values[0],
                                     row.counts[0], row.counts[1], row.counts[2],
                                     row.counts[3], row.counts[4], row.counts[5],
                                     row.counts[6], row.counts[7], row.values[3],
                                     row.values[1], row.values[2]);
                    } else {
                        AppendStatus("menu draw=%u kind=%u menu=%d frozen_and_draws_since_tick=%.0f actors=%u alpha=%.3f prev_alpha=%.3f changed=%u accept_after_tick=%u accept_tick_draw=%u asis=%u largest_asis=%.4f blending_lagged=%u blending_tick=%u minor=%u",
                                     row.serial, row.kind, row.state, row.values[3],
                                     row.counts[7], row.values[0], row.values[1],
                                     row.counts[0], row.counts[1], row.counts[2],
                                     row.counts[3], row.values[2], row.counts[4],
                                     row.counts[5], row.counts[6]);
                    }
                }
                const uint32_t aimWrite = g_aimTraceWrite.load(std::memory_order_acquire);
                if (aimWrite - g_aimTraceRead > g_aimTrace.size()) {
                    g_aimTraceRead = aimWrite - static_cast<uint32_t>(g_aimTrace.size());
                }
                for (; g_aimTraceRead != aimWrite; ++g_aimTraceRead) {
                    const AimTraceRow row = g_aimTrace[g_aimTraceRead % g_aimTrace.size()];
                    AppendStatus("aim frame=%u tick=%u first_person=%u alpha=%.3f world_fov=%.4f shown=%.4f fp_fov=%.4f shown=%.4f frustum=%.5f,%.5f,%.5f,%.5f,%.5f cam_offset=%.3f,%.3f,%.3f cam_forward=%.5f,%.5f,%.5f",
                                 row.frame, row.tick, row.firstPerson, row.alpha,
                                 row.engineFov[0], row.shownFov[0], row.engineFov[1],
                                 row.shownFov[1], row.frustum[0], row.frustum[1],
                                 row.frustum[2], row.frustum[3], row.frustum[4],
                                 row.cameraOffset[0], row.cameraOffset[1],
                                 row.cameraOffset[2], row.cameraForward[0],
                                 row.cameraForward[1], row.cameraForward[2]);
                }
                const uint32_t traceWrite =
                    g_crouchTraceWrite.load(std::memory_order_acquire);
                if (traceWrite - g_crouchTraceRead > g_crouchTrace.size()) {
                    g_crouchTraceRead = traceWrite - static_cast<uint32_t>(g_crouchTrace.size());
                }
                for (; g_crouchTraceRead != traceWrite; ++g_crouchTraceRead) {
                    const CrouchTraceRow row =
                        g_crouchTrace[g_crouchTraceRead % g_crouchTrace.size()];
                    AppendStatus("crouch frame=%u tick=%u fp=%u alpha=%.3f player_z=%.3f cam_z=%.3f cam_local_z=%.3f move_corr=%.3f eye_corr=%.3f fp_cam_z=%.3f root_local_z=%.3f root_z_before=%.3f fp_node_z_before=%.3f fp_node_z_written=%.3f root_z=%.3f cam1st_z=%.3f hand_z=%.3f",
                                 row.frame, row.tick, row.fpPass, row.alpha, row.playerZ,
                                 row.cameraWorldZ, row.cameraLocalZ, row.moveCorrectionZ,
                                 row.eyeCorrection, row.fpCameraWorldZ, row.rootLocalZ,
                                 row.rootWorldZBefore, row.camera1stLocalZ, row.handLocalZ,
                                 row.rootWorldZ, row.camera1stWorldZ, row.handWorldZ);
                }
            }
        }
        if (!consumed) Sleep(10);
    }
    FlushFileBuffers(file);
    CloseHandle(file);
    return 0;
}

void ReadConfiguration() {
    const std::wstring path = ModuleDirectory(g_self) + L"\\Fallout3HFR.ini";
    g_telemetryEnabled = GetPrivateProfileIntW(L"Timing", L"bTelemetry", 1, path.c_str()) != 0;
    g_quantizedDeltaEnabled =
        GetPrivateProfileIntW(L"Timing", L"bExperimentalQuantizedDelta", 0, path.c_str()) != 0;
    g_armAtStartup =
        GetPrivateProfileIntW(L"Timing", L"bArmAtStartup", 0, path.c_str()) != 0;
    g_quietTelemetry =
        GetPrivateProfileIntW(L"Timing", L"bQuietTelemetry", 0, path.c_str()) != 0;
    g_debugHandWriteTrace =
        GetPrivateProfileIntW(L"Experiments", L"bDebugHandWriteTrace", 0, path.c_str()) != 0;
    g_fingerLengthFixEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalFingerLengthFix", 0,
                              path.c_str()) != 0;
    g_nativeStepUnfrozenEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalNativeStepUnfrozen", 0,
                              path.c_str()) != 0;
    g_frameRegionTelemetryEnabled =
        GetPrivateProfileIntW(L"Tracing", L"bFrameRegionTelemetry", 0, path.c_str()) != 0;
    g_authoritativeStateTelemetryEnabled =
        GetPrivateProfileIntW(L"Tracing", L"bAuthoritativeStateTelemetry", 0, path.c_str()) != 0;
    g_eventDispatchTelemetryEnabled =
        GetPrivateProfileIntW(L"Tracing", L"bEventDispatchTelemetry", 0, path.c_str()) != 0;
    g_sceneTransformTelemetryEnabled =
        GetPrivateProfileIntW(L"Tracing", L"bSceneTransformTelemetry", 0,
                              path.c_str()) != 0;
    g_singleCoreFrameEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalSingleCoreFrame", 0,
                              path.c_str()) != 0;
    g_sceneDrawReplayEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalSceneDrawReplay", 0,
                              path.c_str()) != 0;
    g_postPresentReplayEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalPostPresentReplay", 0,
                              path.c_str()) != 0;
    g_postPresentSameFrameIdEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalPostPresentSameFrameId", 0,
                              path.c_str()) != 0;
    g_leafResourceRetentionEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalLeafResourceRetention", 0,
                              path.c_str()) != 0;
    g_postPresentLeafReplayEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalPostPresentLeafReplay", 0,
                              path.c_str()) != 0;
    g_hudTimerNoSleepEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalHUDTimerNoSleep", 0,
                              path.c_str()) != 0;
    g_renderCameraPositionInterpolationEnabled =
        GetPrivateProfileIntW(
            L"Experiments", L"bExperimentalRenderCameraPositionInterpolation", 0,
            path.c_str()) != 0;
    g_renderTranslationInterpolationEnabled =
        GetPrivateProfileIntW(
            L"Experiments", L"bExperimentalRenderTranslationInterpolation", 0,
            path.c_str()) != 0;

    g_freezeRenderFramesEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalFreezeRenderFrames", 0,
                              path.c_str()) != 0;
    g_alignHavokStepEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalAlignHavokStep", 0,
                              path.c_str()) != 0;
    g_latchInputEdgesEnabled =
        GetPrivateProfileIntW(L"Experiments", L"bExperimentalLatchInputEdges", 0,
                              path.c_str()) != 0;
    g_actorTranslationInterpolationEnabled =
        g_renderTranslationInterpolationEnabled &&
        GetPrivateProfileIntW(L"Experiments",
                              L"bExperimentalActorTranslationInterpolation", 0,
                              path.c_str()) != 0;

    g_debugActorObserveOnly =
        GetPrivateProfileIntW(L"Experiments", L"bDebugActorObserveOnly", 0,
                              path.c_str()) != 0;
    wchar_t debugValue[64]{};
    GetPrivateProfileStringW(L"Experiments", L"fDebugActorOffsetZ", L"0", debugValue, 64,
                             path.c_str());
    const double debugOffset = wcstod(debugValue, nullptr);
    if (debugOffset >= -500.0 && debugOffset <= 500.0) {
        g_debugActorOffsetZ = static_cast<float>(debugOffset);
    }

    GetPrivateProfileStringW(L"Experiments", L"fDebugFirstPersonOffsetZ", L"0",
                             debugValue, 64, path.c_str());
    const double firstPersonOffset = wcstod(debugValue, nullptr);
    if (firstPersonOffset >= -500.0 && firstPersonOffset <= 500.0) {
        g_debugFirstPersonOffsetZ = static_cast<float>(firstPersonOffset);
    }

    wchar_t value[64]{};
    GetPrivateProfileStringW(L"Timing", L"fSimulationHz", L"60.0", value, 64, path.c_str());
    const double frequency = wcstod(value, nullptr);
    if (frequency >= 20.0 && frequency <= 240.0) g_simulationStepMs = 1000.0 / frequency;
    GetPrivateProfileStringW(L"Timing", L"fMaxWallDeltaMs", L"250.0", value, 64, path.c_str());
    const double maxDelta = wcstod(value, nullptr);
    if (maxDelta >= 16.0 && maxDelta <= 2000.0) g_maxWallDeltaMs = maxDelta;
}

#ifndef FALLOUT3HFR_ASI
BOOL CALLBACK InitializeProxy(PINIT_ONCE, PVOID, PVOID *) {
    wchar_t systemDirectory[MAX_PATH]{};
    if (GetSystemDirectoryW(systemDirectory, MAX_PATH) == 0) return FALSE;
    std::wstring path(systemDirectory);
    path += L"\\dinput8.dll";
    g_realDinput = LoadLibraryW(path.c_str());
    if (g_realDinput == nullptr) return FALSE;
    g_realDirectInput8Create = reinterpret_cast<DirectInput8CreateFn>(
        GetProcAddress(g_realDinput, "DirectInput8Create"));
    return g_realDirectInput8Create != nullptr;
}
#endif

BOOL CALLBACK InitializePatch(PINIT_ONCE, PVOID, PVOID *) {
    QueryPerformanceFrequency(&g_qpcFrequency);
    ReadConfiguration();
    #ifdef FALLOUT3HFR_ASI
    AppendStatus("Fallout3HFR %s starting (ASI plugin)", kPatchVersion);
#else
    AppendStatus("Fallout3HFR %s starting (dinput8 proxy)", kPatchVersion);
#endif
    if (!VerifyTargetLayout()) {
        AppendStatus("hooks disabled: executable layout not recognised");
        return TRUE;
    }
    if (g_sceneDrawReplayEnabled &&
        (g_postPresentReplayEnabled || g_renderCameraPositionInterpolationEnabled ||
         g_renderTranslationInterpolationEnabled)) {
        AppendStatus("hooks disabled: scene-draw replay is mutually exclusive with post-Present replay and render interpolation");
        return TRUE;
    }
    if (g_postPresentSameFrameIdEnabled && !g_postPresentReplayEnabled) {
        AppendStatus("hooks disabled: same-frame-ID mode requires post-Present replay");
        return TRUE;
    }
    if (g_postPresentLeafReplayEnabled && !g_leafResourceRetentionEnabled) {
        AppendStatus("hooks disabled: post-Present leaf replay requires leaf-resource retention");
        return TRUE;
    }
    if (g_postPresentLeafReplayEnabled &&
        (g_postPresentReplayEnabled || g_sceneDrawReplayEnabled ||
         g_renderCameraPositionInterpolationEnabled ||
         g_renderTranslationInterpolationEnabled)) {
        AppendStatus("hooks disabled: post-Present leaf replay is mutually exclusive with other replay modes");
        return TRUE;
    }
    if (g_leafResourceRetentionEnabled &&
        (g_quantizedDeltaEnabled || g_singleCoreFrameEnabled ||
         g_sceneDrawReplayEnabled || g_postPresentReplayEnabled)) {
        AppendStatus("hooks disabled: leaf-resource retention is mutually exclusive with timing, topology, and replay mutations");
        return TRUE;
    }
    if (g_leafResourceRetentionEnabled && !g_eventDispatchTelemetryEnabled) {
        AppendStatus("hooks disabled: leaf-resource retention requires event-dispatch probes");
        return TRUE;
    }
    if (g_hudTimerNoSleepEnabled &&
        (g_singleCoreFrameEnabled ||
         g_sceneDrawReplayEnabled || g_postPresentReplayEnabled ||
         g_leafResourceRetentionEnabled || g_postPresentLeafReplayEnabled)) {
        AppendStatus("hooks disabled: HUD timer no-sleep is mutually exclusive with other mutations");
        return TRUE;
    }
    if (g_hudTimerNoSleepEnabled && !g_eventDispatchTelemetryEnabled &&
        !g_sceneTransformTelemetryEnabled) {
        AppendStatus("hooks disabled: HUD timer no-sleep requires event-dispatch or scene-transform probes");
        return TRUE;
    }
    if (g_renderCameraPositionInterpolationEnabled &&
        (!g_quantizedDeltaEnabled || !g_hudTimerNoSleepEnabled ||
         !g_eventDispatchTelemetryEnabled)) {
        AppendStatus("hooks disabled: camera-position interpolation requires quantized delta, HUD no-sleep, and event-dispatch probes");
        return TRUE;
    }
    if (g_renderTranslationInterpolationEnabled &&
        (g_renderCameraPositionInterpolationEnabled || !g_quantizedDeltaEnabled ||
         !g_hudTimerNoSleepEnabled || !g_sceneTransformTelemetryEnabled)) {
        AppendStatus("hooks disabled: render-translation interpolation requires quantized delta, HUD no-sleep, targeted scene-transform telemetry, and no camera-position prototype");
        return TRUE;
    }
    if ((g_freezeRenderFramesEnabled || g_alignHavokStepEnabled ||
         g_latchInputEdgesEnabled) &&
        (!g_quantizedDeltaEnabled || g_singleCoreFrameEnabled ||
         g_sceneDrawReplayEnabled || g_postPresentReplayEnabled ||
         g_postPresentLeafReplayEnabled)) {
        AppendStatus("hooks disabled: freeze-render-frames and Havok step alignment require quantized delta and no topology/replay mutation");
        return TRUE;
    }
    const bool outerFrameHookWanted =
        g_singleCoreFrameEnabled || g_freezeRenderFramesEnabled ||
        g_latchInputEdgesEnabled;
    const uint8_t timerExpected[5] = {0xE8, 0xB4, 0x7E, 0x18, 0x00};
    const uint8_t havokExpected[5] = {0xE8, 0x16, 0xF8, 0x1E, 0x00};
    const uint8_t outerFrameExpected[5] = {0xE8, 0x55, 0xEF, 0xFF, 0xFF};
    const uint8_t sceneDrawExpected[5] = {0xE8, 0x23, 0xED, 0xFF, 0xFF};
    const uint8_t renderFinalizeExpected[5] = {0xE8, 0x30, 0x0F, 0x40, 0x00};
    if (!MatchesBytes(kTimerCall, timerExpected, 5) ||
        !MatchesBytes(kHavokScheduleCall, havokExpected, 5) ||
        (outerFrameHookWanted && !MatchesBytes(kOuterFrameCall, outerFrameExpected, 5)) ||
        (g_sceneDrawReplayEnabled &&
         !MatchesBytes(kSceneDrawCall, sceneDrawExpected, 5)) ||
        ((g_postPresentReplayEnabled || g_postPresentLeafReplayEnabled) &&
         !MatchesBytes(kRenderFinalizeCall, renderFinalizeExpected, 5))) {
        AppendStatus("hooks disabled: one or more instruction signatures are already modified");
        return TRUE;
    }

    if (g_telemetryEnabled) {
        g_logThread = CreateThread(nullptr, 0, LogThread, nullptr, 0, nullptr);
    }

    const bool timerOk = PatchRelativeCall(kTimerCall, reinterpret_cast<const void *>(&TimerUpdateHook),
                                           timerExpected);
    const bool havokOk = PatchRelativeCall(kHavokScheduleCall,
                                           reinterpret_cast<const void *>(&HavokScheduleHook),
                                           havokExpected);
    const bool captureGateOk = InstallCaptureGate();
    const bool sceneDrawReplayOk = captureGateOk && InstallSceneDrawReplay();
    const bool postPresentReplayOk = sceneDrawReplayOk && InstallPostPresentReplay();
    const bool frameProbesOk = postPresentReplayOk && InstallFrameRegionProbes();
    const bool dispatchProbesOk = frameProbesOk && InstallEventDispatchProbes();
    const bool singleCoreFrameOk = !outerFrameHookWanted ||
        PatchRelativeCall(kOuterFrameCall, reinterpret_cast<const void *>(&GameFrameHook),
                          outerFrameExpected);
    const uint8_t hudTargetExpected[5] = {0xE8, 0x11, 0x7B, 0x22, 0x00};
    const bool hudTargetOk = !g_hudTimerNoSleepEnabled ||
        PatchRelativeCall(kHUDTargetTimerCall,
                          reinterpret_cast<const void *>(&UpdateHUDTargetTimerNoSleep),
                          hudTargetExpected);
    const bool allHooksOk = timerOk && havokOk && captureGateOk && frameProbesOk && dispatchProbesOk &&
                            sceneDrawReplayOk && postPresentReplayOk && singleCoreFrameOk &&
                            hudTargetOk;
    if (!allHooksOk) {
        if (g_hudTimerNoSleepEnabled && hudTargetOk) {
            RestoreBytes(kHUDTargetTimerCall, hudTargetExpected);
        }
        if (timerOk) RestoreBytes(kTimerCall, timerExpected);
        if (havokOk) RestoreBytes(kHavokScheduleCall, havokExpected);
        if (outerFrameHookWanted && singleCoreFrameOk) {
            RestoreBytes(kOuterFrameCall, outerFrameExpected);
        }
        if (dispatchProbesOk) UninstallEventDispatchProbes();
        if (frameProbesOk) UninstallFrameRegionProbes();
        if (postPresentReplayOk) UninstallPostPresentReplay();
        if (sceneDrawReplayOk) UninstallSceneDrawReplay();
        if (captureGateOk) UninstallCaptureGate();
        AppendStatus("hooks rolled back after partial installation failure");
    }
    if (allHooksOk && g_debugHandWriteTrace) {
        AddVectoredExceptionHandler(1, &HandWriteTraceHandler);
    }
    if (allHooksOk && g_renderTranslationInterpolationEnabled) {
        // Not essential: a site that does not match is left as it is.
        struct FovSite {
            uintptr_t address;
            uint8_t expected[5];
        };
        static const FovSite kFovSites[] = {
            {0x006EDFE8, {0xE8, 0x03, 0x0B, 0x3C, 0x00}},
            {0x006E627D, {0xE8, 0x6E, 0x88, 0x3C, 0x00}},
            {0x006E6351, {0xE8, 0x9A, 0x87, 0x3C, 0x00}},
            {0x006E6700, {0xE8, 0xEB, 0x83, 0x3C, 0x00}},
            {0x006E6BEE, {0xE8, 0xFD, 0x7E, 0x3C, 0x00}},
            {0x006E707C, {0xE8, 0x6F, 0x7A, 0x3C, 0x00}},
            {0x006E71BD, {0xE8, 0x2E, 0x79, 0x3C, 0x00}},
            {0x006EADD9, {0xE8, 0x12, 0x3D, 0x3C, 0x00}},
            {0x006EAE4E, {0xE8, 0x9D, 0x3C, 0x3C, 0x00}},
            // Every other caller of FUN_00AAEAF0. With only the nine sites
            // above the substitution ran but the picture still stepped, so
            // one of these presumably sets the frustum last before the draw.
            {0x005339DA, {0xE8, 0x11, 0xB1, 0x57, 0x00}},
            {0x006202ED, {0xE8, 0xFE, 0xE7, 0x48, 0x00}},
            {0x006236A6, {0xE8, 0x45, 0xB4, 0x48, 0x00}},
            {0x006E5C5E, {0xE8, 0x8D, 0x8E, 0x3C, 0x00}},
            {0x0076FC2D, {0xE8, 0xBE, 0xEE, 0x33, 0x00}},
            {0x0077ADB8, {0xE8, 0x33, 0x3D, 0x33, 0x00}},
            {0x00787EC9, {0xE8, 0x22, 0x6C, 0x32, 0x00}},
            {0x0078804C, {0xE8, 0x9F, 0x6A, 0x32, 0x00}},
            {0x00AAEE6B, {0xE8, 0x80, 0xFC, 0xFF, 0xFF}},
            {0x00AAF528, {0xE8, 0xC3, 0xF5, 0xFF, 0xFF}},
        };
        const bool probesInstalled = g_frameRegionTelemetryEnabled ||
            g_authoritativeStateTelemetryEnabled || g_eventDispatchTelemetryEnabled ||
            g_sceneTransformTelemetryEnabled;
        LONG sites = 0;
        for (const FovSite &site : kFovSites) {
            if (site.address == 0x006EDFE8 && probesInstalled) {
                // Already redirected through probe 1710.
                ++sites;
                continue;
            }
            if (MatchesBytes(site.address, site.expected, 5) &&
                PatchRelativeCall(site.address,
                                  reinterpret_cast<const void *>(&SetCameraFovHook),
                                  site.expected)) {
                ++sites;
            }
        }
        InterlockedExchange(&g_fovStatSites, sites);
    }
    AppendStatus("timer hook=%d havok hook=%d frame_probes=%d state_telemetry=%d dispatch_probes=%d scene_transform_telemetry=%d telemetry=%d experimental_quantized_delta=%d experimental_single_core_frame=%d experimental_scene_draw_replay=%d experimental_post_present_replay=%d experimental_post_present_same_frame_id=%d experimental_leaf_resource_retention=%d experimental_post_present_leaf_replay=%d experimental_hud_timer_no_sleep=%d experimental_render_camera_position_interpolation=%d experimental_render_translation_interpolation=%d sim_hz=%.3f",
                 allHooksOk ? 1 : 0, allHooksOk ? 1 : 0,
                 allHooksOk && (g_frameRegionTelemetryEnabled ||
                                g_authoritativeStateTelemetryEnabled ||
                                g_eventDispatchTelemetryEnabled ||
                                g_sceneTransformTelemetryEnabled) ? 1 : 0,
                 allHooksOk && g_authoritativeStateTelemetryEnabled ? 1 : 0,
                 allHooksOk && g_eventDispatchTelemetryEnabled ? 1 : 0,
                 allHooksOk && g_sceneTransformTelemetryEnabled ? 1 : 0,
                 g_telemetryEnabled ? 1 : 0,
                 g_quantizedDeltaEnabled ? 1 : 0,
                 allHooksOk && g_singleCoreFrameEnabled ? 1 : 0,
                 allHooksOk && g_sceneDrawReplayEnabled ? 1 : 0,
                 allHooksOk && g_postPresentReplayEnabled ? 1 : 0,
                 allHooksOk && g_postPresentSameFrameIdEnabled ? 1 : 0,
                 allHooksOk && g_leafResourceRetentionEnabled ? 1 : 0,
                 allHooksOk && g_postPresentLeafReplayEnabled ? 1 : 0,
                 allHooksOk && g_hudTimerNoSleepEnabled ? 1 : 0,
                 allHooksOk && g_renderCameraPositionInterpolationEnabled ? 1 : 0,
                 allHooksOk && g_renderTranslationInterpolationEnabled ? 1 : 0,
                 1000.0 / g_simulationStepMs);
    AppendStatus("experimental_freeze_render_frames=%d experimental_align_havok_step=%d experimental_latch_input_edges=%d capture_gate=%d arm_at_startup=%d quiet_telemetry=%d actors_and_first_person=%d",
                 allHooksOk && g_freezeRenderFramesEnabled ? 1 : 0,
                 allHooksOk && g_alignHavokStepEnabled ? 1 : 0,
                 allHooksOk && g_latchInputEdgesEnabled ? 1 : 0,
                 g_captureActiveEvent != nullptr ? 1 : 0,
                 g_armAtStartup ? 1 : 0, g_quietTelemetry ? 1 : 0,
                 allHooksOk && g_actorTranslationInterpolationEnabled ? 1 : 0);
    return TRUE;
}

} // namespace

// Two ways in, one patch.
//
// ASI plugin (Fallout3HFR.asi, FALLOUT3HFR_ASI defined): an ASI loader loads
// the file at process start and the patch is installed from DllMain. That
// runs under the loader lock, which is why installation uses nothing that
// loads further modules: it reads an INI, compares bytes, patches call sites,
// allocates stubs and creates a thread. InitializeASI is the entry some
// loaders call after loading; it leads to the same once-only installation.
//
// dinput8.dll proxy (development): the game imports DirectInput8Create, the
// proxy forwards it to the system DLL and installs the patch on the first
// call.
#ifdef FALLOUT3HFR_ASI
extern "C" __declspec(dllexport) void __cdecl InitializeASI() {
    InitOnceExecuteOnce(&g_patchInitOnce, InitializePatch, nullptr, nullptr);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = instance;
        DisableThreadLibraryCalls(instance);
        InitOnceExecuteOnce(&g_patchInitOnce, InitializePatch, nullptr, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_stop.store(true, std::memory_order_release);
    }
    return TRUE;
}
#else
extern "C" HRESULT WINAPI DirectInput8Create(HINSTANCE instance, DWORD version, REFIID iid,
                                              LPVOID *output, LPUNKNOWN outer) {
    if (!InitOnceExecuteOnce(&g_proxyInitOnce, InitializeProxy, nullptr, nullptr) ||
        g_realDirectInput8Create == nullptr) {
        return E_FAIL;
    }
    InitOnceExecuteOnce(&g_patchInitOnce, InitializePatch, nullptr, nullptr);
    return g_realDirectInput8Create(instance, version, iid, output, outer);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = instance;
        DisableThreadLibraryCalls(instance);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_stop.store(true, std::memory_order_release);
    }
    return TRUE;
}
#endif
