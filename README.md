# Fallout3HFR

A high-frame-rate patch for Fallout 3: the game keeps simulating at 60 ticks a
second while the picture is drawn at the display rate, with the motion in
between interpolated. Design, measurements and the full history are in
`research/docs/fallout3-high-frame-rate-plan.md`.

## Forms

One source, `src/dinput8_proxy.cpp`, builds two ways:

- `Fallout3HFR.asi` - the release form, an ASI plugin. It needs an ASI loader
  (developed with the 32-bit Ultimate ASI Loader named `dinput8.dll`) and can
  sit in the game folder or in the loader's `plugins`, `scripts` or `update`
  folder. `Fallout3HFR.ini` and `Fallout3HFR.log` live next to the plugin.
  The patch is installed when the plugin is loaded, at process start.
- `dinput8.dll` - the development form, a DirectInput proxy that forwards
  `DirectInput8Create` to the system DLL and installs the patch on the first
  call. The research launchers under `research/scripts` use it. It must not
  be installed together with an ASI loader of the same name.

`research/scripts/install-play-build.ps1` installs the plugin and, if needed,
the loader.

## Which executables it accepts

Developed against GOG Fallout 3 1.7.0.3 (PE timestamp `4A40F18B`). The
executable is not identified by hash. Before anything is changed the patch
checks that it is a 32-bit image loaded at `0x00400000`, that the fixed data
addresses it reads are referenced by the expected instructions, and that
every call site it redirects holds exactly the expected call. If any check
fails nothing is patched and the log says which check failed. An executable
from another storefront is accepted if, and only if, it has the same code
layout; none has been tried.

## What is implemented

- verifies the executable's layout and every hook's instruction bytes before
  touching code;
- observes the global `BSTimer` update—including its input tick, clamp, clamp
  remainder, and output delta—and the Havok step scheduler;
- writes `Fallout3HFR.csv` without doing file I/O on the game thread;
- can opt into 69 non-mutating monolithic-frame boundary probes for Milestone 2
  duration analysis;
- can opt into explicit authoritative-state and event-queue fingerprints at the
  frame boundaries without hashing renderer caches or whole engine objects;
- can log raw renderer/render-target/camera identity and narrowly classify
  script entries that overlap the D3D9 Present call by executing thread;
- can trace the target-close/implicit-buffer/Present queue lifecycle, the
  retained geometry accumulator, and the final image-space composite interval;
- includes opt-in quantized-delta, single-core-frame, and guarded render-owner
  replay experiments.

The experiment is deliberately not called a fix. A near-zero delta does not
prove that scripts, animation events, AI, input, or audio are presentation-only.

`[Tracing] bFrameRegionTelemetry=1` enables call-boundary observation only. It
does not skip, repeat, or modify any game update, but its extra telemetry can
affect performance and therefore remains disabled in the distributed template.
It exists to quantify which subsystems still change on intervening frames.

`bAuthoritativeStateTelemetry=1` adds a second read-only audit layer. It hashes
documented player transform/cell/process fields, game time, process-manager
time, Havok scheduling state, save changed-form count, and audio request/playing
counts. The raw inputs are included in the CSV so every hash transition can be
explained. These queue counts are useful sentinels, not yet proof that script,
animation-note, or audio dispatch is event-exact; dedicated dispatch counters
remain required before a presentation-only path can pass Milestone 2.

`bEventDispatchTelemetry=1` installs the direct entry counters, pre/post-Present
markers, state-1 final-pass-begin markers, and a post-activation marker for each
state-2 render-target pass. It also records renderer queue head/tail/count and
the queued implicit-buffer/vtable/swap-chain identities at markers 1301-1304,
captures the retained geometry accumulator at marker 1310, counts direct
geometry dispatches, and brackets the final image-space pass graph with markers
1320/1321. Marker 1330 records each `FUN_00B86390` image-space pass entry,
including its ordinal, pass/base/vtable identities, output-target binding and
refcount, caller, and four actual arguments. Marker 1340 records the enclosing
`FUN_00B1D860` graph executor's graph pointer, caller, selected index, and
five remaining arguments. Marker 1350 observes the fully bound final leaf at
`00B3063B`, immediately before its virtual draw; it records the leaf/root/caller
and draw arguments, all four binding-wrapper addresses, and the transient
wrappers' flags, resources, metadata, auxiliary values, vtables, and refcounts.
Marker 1360 observes the slot-1 resource after the stock stack-wrapper
release so the expected reference-count transition can be verified without
modifying it. The state-2 marker records its original runtime
return address,
while a function-entry marker records the caller of the identified
full-resolution activation owner one stack level higher. Target activations
can therefore be attributed to both their inner and outer caller.
`analyze-state-boundaries.ps1` reports the new queue identities and groups each
1320-to-1321 interval by geometry-dispatch count, state-2/state-1 activation
count, accumulator traversal, renderer-state transition, and
authoritative/event changes. It also groups marker-1330 descriptors by pass
ordinal together with the correlated executor context, and separately groups
the marker-1350 final-leaf binding signatures and marker-1360 post-release
refcounts.
Marker 1400 observes the actual `NiControllerSequence` queued-note fan-out at
`008BB4B0`. Markers 1401/1403 bracket the normal player-control handler and
1402/1404 bracket the alternate early-frame handler; their snapshots include
the cumulative device-poll count so sample/consumer ordering can be measured.
Active firing and reload left marker 1400 at zero, so this generic fan-out is
not the ordinary first-person weapon sentinel. Marker 1410 instead observes
`HighProcess::AttackCallback` at `0073B980`, a concrete callback that increments
the pending-attack accumulator, while leaving the callback unchanged.
The deployed observer is archived as
`artifacts/dinput8-attack-callback-observer-ACCB3A15.dll` (SHA-256
`ACCB3A154FCCCAD34E4247E3087097F418471CC58F4867087CEFE60FB529F164`).
In the controlled validation, marker 1410 fired exactly once for each of 13
spaced player shots, never for either reload, and always between markers 1401
and 1403 with the current frame's fresh input-poll serial.
The successor observer adds markers 1420/1421 at the two concrete attack
callback call sites and 1430/1431 at the two candidate pending-count clears.
The initial `CB8EF2AD...4289441` build is rejected: its nine-byte clear probe
exceeded the jump writer's legacy eight-byte maximum and caused safe complete
hook rollback. The corrected observer extends that bounded buffer to twelve
bytes and is archived as
`artifacts/dinput8-attack-retirement-observer-67253274.dll` (SHA-256
`67253274DAF99FC811685C45F1CB81B5BEEBB6A7B6A1493CA00C8F2AF41AA41F`).
In its corrected capture, six player shots used marker 1420 exclusively and
reached marker 1410 1.0-1.6 microseconds later; marker 1421 and both clear
markers stayed zero. HighProcess `+0x2B8` is consequently treated as an
accumulating attack count for this path, not a same-frame pending command.
The marker-1501-1527 active capture reduced the steady marker-10-to-14 path to
eight executed direct calls with no authoritative-hash change. Two delayed
script increments appeared inside the broad marker-1515-to-13 interval after
the single shot. Markers 1610/1611 at the ScriptRunner entry bodies then proved
that the timed variant also runs on a worker throughout active play. That first
capture exposed a telemetry-ring reservation race: simultaneous frame/worker
markers could claim one slot even though the capacity-overflow counter stayed
zero. Atomic compare-exchange reservations corrected it. The repaired capture
accounted for all 55,619 ScriptRunner entries and proved that both post-shot
`1515 -> 13` increments ran on the worker, not inside `FUN_00AE6870`.
The marker-7-to-10 capture validated one stable active-world call sequence but
also exposed destructive garbage/decal retirement, streaming maintenance,
scene ownership mutation, and the paired render-worker launch. The current
read-only observer retains both call ledgers and the corrected multi-producer
ring, then adds markers 1801-1806 around the three function-pointer-only
worker callback bodies. Existing marker 1715 timestamps worker launch, marker
111 timestamps the blocking join, and marker 15 records its completion. No
worker semaphore, barrier, renderer call, or gameplay path is changed. It is
archived as `artifacts/dinput8-render-worker-provenance-7180F5A8.dll`
(SHA-256
`7180F5A8302D2674C669E7FC6D3676A643295067B6E2BD3383646D58CAC77086`).
That observer proved callback A is the only active body and linked its
bimodality to the old Present/join alternation. The first wait-split successor,
`C28528EB...2A4B947E`, is rejected: marker 1814 patched across inbound branch
target `007243E0`, and an empty second worker slot jumped into the middle of
the trampoline jump. The current read-only correction moves marker 1814 to
that branch target and replays only the complete iteration-advance block. It
is archived as `artifacts/dinput8-worker-wait-split-fixed-AFBEE56B.dll`
(SHA-256
`AFBEE56B631E849EF2F5DBE3C50B38D2AFEE7459CE9BBED79157568F4DE257D0`).
The corrected capture balances 2,282 active callbacks and proves the slow
join follows a 9.8837 ms callback pre-wait phase, not the internal semaphore
wait. The current successor adds direct-call markers 1820-1835 across the 16
calls in that pre-wait phase. It is archived as
`artifacts/dinput8-worker-prewait-call-ledger-0DEF676F.dll` (SHA-256
`0DEF676F4A210A5808739B2998D1963D5B3DCA0F3EFC7A258B53412959419123`).
That ledger isolates the full 9.2936 ms class shift to the first call group.
The next observer added markers 1840-1845 around its
three nested update routines, conditional `ReleaseSemaphore`, and following
`InterlockedIncrement`. It is archived as
`artifacts/dinput8-worker-first-group-split-5A036E49.dll` (SHA-256
`5A036E498A7BC7DB5B318116C303B1D17869D0F220950CFD4BC39F05940A1633`).
Its lossless 1,669-frame capture places the entire 9.2992 ms shift inside
`FUN_00619230` (0.0825 versus 9.3817 ms), not in either synchronization
operation. That routine reaches input/controller update `FUN_006275F0`, so
callback A is not render-only. The current successor brackets the opening
`XInputGetState` call with markers 1850/1851. It is archived as
`artifacts/dinput8-worker-xinput-split-B2695E6C.dll` (SHA-256
`B2695E6C54B0D1FAD66C14E29D3E64EC948E3AFD55D3DF024C14824CC42FB0DA`).
Its lossless 1,577-frame capture rejects `XInputGetState` as the delay: the API
is steady near 0.042 ms, while the post-call remainder grows by 9.3088 ms. The
current observer brackets an early critical-section-bearing input-effect
update and adds coarse milestones across that remainder. It is archived as
`artifacts/dinput8-worker-post-xinput-milestones-5B0BBFE9.dll` (SHA-256
`5B0BBFE9B2DE310ACE78C0BBC3B82DAEB226EF278B7A9385FC151ED06A79D550`).
That capture rejects the early critical-section candidate and places the full
9.2892 ms shift later, between `FUN_00BFB870` effect retirement and a final
input-state query. The current observer adds merge-point markers within that
interval and is archived as `artifacts/dinput8-worker-late-update-split-9B968B9B.dll`
(SHA-256 `9B968B9B67E03C3392EA0FCA1C9ADBA98BD4472D75AF5B7A4CC25978F8B39B46`).
That split rejects `FUN_00BFB870`: the full 9.2738 ms shift occurs in the
following linked-list traversal. The successor counts each node and separates
its lookup from its virtual effect callback. It is archived as
`artifacts/dinput8-worker-effect-list-loop-10AD45F6.dll` (SHA-256
`10AD45F67C96C790E95D13E8522F8883631D5D395B23DEDEEA5EDA258322D150`).
Its lossless 1,586-frame capture proves that every worker pass traverses five
nodes and that only the fifth virtual callback carries the delay: 0.0260 ms in
the early class versus 9.3371 ms in the late class. The current observer reads
that callback object's vtable `+0x2C` slot and publishes the concrete function
address without changing the original call. It is archived as
`artifacts/dinput8-worker-effect-callback-target-C1F5B32E.dll` (SHA-256
`C1F5B32EC2B9355219DE13288CB25D647253D7ACABA48079406FE96E564F354D`).
The resulting lossless capture identifies the fifth target as
`HUDMainMenu::Update` at `00652000` in both timing classes. Its opening timer
call explicitly sleeps until a 10 ms interval has elapsed. The current
read-only successor brackets only that timer call with markers 1880/1881 and
is archived as `artifacts/dinput8-hud-timer-boundary-A7852AAB.dll` (SHA-256
`A7852AABA0C77CFAEEECEAAD73A1A836A6F74A67B4184921523D8659121C541E`).
That capture attributes 99.85% of the callback shift to the timer itself. The
current capture-gated experiment preserves the timer's real-time fields and
all later HUD work but omits only its wait-to-10-ms sleep at call site
`0065202A`; marker 1882 proves activation. It is archived as
`artifacts/dinput8-hud-timer-nosleep-B272DF46.dll` (SHA-256
`B272DF46CDDD1A06D61653450943C7B38E1E7B94E00BD899F43E90E0B7A3277E`).
The dedicated launcher enables it for one capture and restores the original
installed INI bytes afterward.
The lossless validation removed the 9.3 ms worker stall and reached 140.364
active-world frames/s under a 144 Hz cap with a stable HUD. It is nevertheless
rejected as a standalone fix: the frame delta stayed fixed at 16.666667 ms, so
the engine accumulated about 2.339 seconds of game time per real second and the
operator observed very fast walking. The mutation remains gated and disabled.
The current read-only successor adds markers 1890-1945 at every remaining
direct call in `FUN_006ED560`, completing the marker-14 composition/finalizer
ledger without changing call order or renderer state. It is archived as
`artifacts/dinput8-region14-call-ledger-AE2CA6D6.dll` (SHA-256
`AE2CA6D6B20BB6D657F42025A03276996E422C3FEED8D2A74201865FD18691AA`).
`analyze-region14-call-ledger.ps1` groups exact active paths, state/counter
changes, and adjacent timing.
The preceding read-only observer added markers 1950-1953 around mapped
attack and the shared tap-reload/hold-to-holster button inside the normal
player-control handler. Static tracing and the latest capture corrected their
semantics: marker 1951 belongs only to the timed ready/holster branch, and
marker 1953 is a common attack-gate fall-through rather than proof of
rejection. It is archived as
`artifacts/dinput8-input-acceptance-ledger-702AAEE1.dll` (SHA-256
`702AAEE1F33B71050E9DC36AB56C853E600C1C635FA91B305B38B220C6AD49D4`).
The preceding read-only successor also samples the first-person weapon animation
group, its two sequence states, and its sequence pointer. Reload groups
were visible as a stable encoded raw value in the first capture without
calling engine animation methods or changing input/weapon state. It is archived as
`artifacts/dinput8-reload-animation-sentinel-7A7C591B.dll` (SHA-256
`7A7C591B924D06C5DF6F5AD8AABA9EA96BC58B6C92748DEC26D66FE0CDE02DF7`).
The current read-only observer follows the active sequence to its canonical
animation-group index, where 173-199 are the reload groups, and adds direct-call
markers 1960-1978 inside `FUN_006E4510`. Those markers divide the exact routine
that contained a recovered 10.546-second stall. It is archived as
`artifacts/dinput8-final-sync-reload-sentinel-30C4080A.dll` (SHA-256
`30C4080A26E8DB03ED7E7EF61DB494980DF0CA99F7394CCCF8C013FC2B286D8B`).
`analyze-quantized-nosleep.ps1` reports canonical reload-animation episodes
and their delay from the preceding action-7 sample when this schema is present.
The current research-only timing candidate combines the existing 60 Hz
quantized delta with the call-site-specific HUD no-sleep path. Both are inert
unless the manual capture gate is armed, and the dedicated launcher restores
the exact installed INI afterward. It is archived as
`artifacts/dinput8-quantized-nosleep-80C80683.dll` (SHA-256
`80C80683C2BD48E37722C7A0D72AF7406E4FD5B19B0FDAC2F729F1EAFD669822`).
This is an event-safety experiment, not a validated fix.
Its first lossless active-world capture reached 141.260 outer frames/s while
the settled fixed-step pulse held 60.036 Hz. Engine and integrated Havok time
tracked wall time within 0.061%, ScriptRunner completed at the pulse rate, and
the operator reported smooth 144 Hz camera motion, normal gameplay speed, and
a stable UI. An initial active-input run reported several fire and reload
presses that needed repetition, but its one-second cadence did not separate
input loss from the weapon's own action-readiness gate. A controlled follow-up
with two-second shot spacing produced one accepted callback for each of nine
intended shots, with successful attacks in both fixed-pulse and near-zero
frame classes; both reload presses were also freshly sampled and worked
visibly. The input-loss verdict is therefore withdrawn, not converted into a
validation claim. Exact tap-reload acceptance and the remaining event-like
paths still need dedicated sentinels before this can become a scheduler.
The former `00474930` animation sentinel was retired because it remained zero
during active first-person weapon fire and reload.
Renderer, render-target, and camera fields are logged as raw diagnostics but
excluded from the hashes.
Script calls observed only while Present is pending are additionally classified
as executing on the Present thread or another thread without emitting a
telemetry row for every call.
The temporary changed-forms destructor and shared backing-buffer hooks have
been retired after attributing the normal clear to asynchronous
`FUN_006CF2B0` work on a different thread from the render pass.

`bExperimentalSceneDrawReplay=1` repeats the full-resolution
`FUN_006EB5E0` scene draw once with its original `this` pointer and four
arguments. The normal call runs first. Replay is allowed only while renderer
state 2 and its target remain active, a valid player and cell exist, and 240
consecutive calls have met those conditions. Marker 1102 is emitted
immediately before the repeated call. This experiment deliberately does not
add a second Present; it tests whether the scene draw itself is repeat-safe
before scheduler work begins.

`bExperimentalPostPresentReplay=1` is an archived diagnostic and is
mutually exclusive with the scene-draw replay. The stock renderer finalizer
and Present run first. If the renderer has returned to idle state 0 with no
active/current target, a valid player and cell have remained stable for 240
calls, marker 1201 is emitted. The hook then calls the stock render dispatcher
with its preserved owner and three zero arguments, followed by the stock
finalizer for a genuine second Present. It remains inside the existing render
critical section and does not repeat input, simulation, worker barriers, or
the separate queue/lock cleanup path.
The replay gate is additionally armed only while the capture script holds its
named capture event, ensuring that the first experimental call and any crash
are inside the evidence window.

This experiment is rejected for further gameplay use. It reduced the enclosing
engine-loop rate, produced alternating presentation intervals and UI pulsing,
and a delayed shutdown ended in `FAST_FAIL_CORRUPT_WOW64_STATE`.

`bExperimentalPostPresentSameFrameId=1` modifies that replay so both renders
use one logical value of the renderer frame counter at offset `+0x204`. Marker
1201 captures the value after the stock Present; the hook then restores the
pre-Present value, and marker 1202 captures state after the replay finalizer.
On success the two markers have the same frame ID and the engine frame has a
net counter increment of one. This variant is also rejected: it retained the
same slowdown/UI pulse and the following stock frame crashed while traversing
a retained geometry array. Static audit found no direct stock reader of the
renderer frame-ID field, so the failure is not attributed to a proven
frame-ID-keyed cache.

`bExperimentalLeafResourceRetention=1` is a capture-gated ownership-only
experiment. After marker 1321 validates a complete ordinary eight-pass graph,
it builds private normalized binding clones and adds one intrusive reference
to each non-null final-leaf resource. Marker 402 releases the three references
after the existing stock Present. It never invokes a pass, finalizer, or extra
Present. Loading/transition graphs and unfamiliar resource signatures are
rejected. The switch requires `bEventDispatchTelemetry=1` and is mutually
exclusive with every timing, topology, and replay mutation.

`bExperimentalPostPresentLeafReplay=1` is the narrower successor experiment
and requires leaf-resource retention. After 240 consecutive eligible frames
in one cell, it keeps the three proven resource references alive through the
stock Present, binds private wrappers to the persistent final pass, invokes
only that pass's validated `FUN_00B86390` virtual draw, and calls the stock
`FUN_00AEEAC0` finalizer for one additional Present. Markers 1370-1373 bracket
the extra leaf, finalizer, and release; marker 1374 records a failed guard and
1375 a warm-up release. It never calls the full graph executor or render
dispatcher and is inert unless the manual capture event is signaled.

## Build

Generate a Win32 build with CMake and Visual Studio, then build Release. The
result must be a 32-bit DLL because `Fallout3.exe` is 32-bit.

## Research-only installation

Copy the built `dinput8.dll` and `Fallout3HFR.ini` beside `Fallout3.exe`.
Do not install it alongside another `dinput8.dll` proxy. Remove those two files
to roll back. The game executable and INI files are not modified.

Keep `bExperimentalQuantizedDelta=0` for baseline captures. Pair the CSV with a
PresentMon capture to correlate engine frame deltas and Havok substeps with
actual presentation intervals.

From the workspace root, a timed PresentMon capture can be started with:

```powershell
powershell -ExecutionPolicy Bypass -File research\scripts\capture-presentmon.ps1 `
  -DurationSeconds 120 -Label stock-60
```

PresentMon's `--qpc_time` output and `Fallout3HFR.csv` use the same QPC domain.
