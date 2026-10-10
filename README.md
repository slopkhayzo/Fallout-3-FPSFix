# Fallout3HFR

> [!WARNING]
> This patch has been pretty much entirely been generated using AI; 
> I won't and will never claim to have enough knowledge or expertise to do this 
> kind of reverse-engineering by myself; I've tested about 2-3 hours of gameplay (reached the GNR Building Plaza) at 360hz + 
> briefly tested at 120, 144 and 240 and so far spotted 
> no major issues (on my machine ofc, if you have issues feel free to open an Issue)
> this patch currently probably only works for the latest GOG version of the game, I do have 
> the Steam version too but still have to test that, so no guarantees for now.
> If you're interested and want more (human generated) info, I have a blog post [here](https://slop-blog.enkhayzomachines.net/posts/fallout-3-high-fps-ril) :)

Fallout3HFR is a high-frame-rate patch for Fallout 3. It keeps the game
simulation at 60 ticks per second while rendering and interpolating motion at
the display frame rate. This provides smooth motion above 60 FPS without
speeding up the game.

Version 1.0.0 was developed and tested with the GOG release of Fallout 3
1.7.0.3.

## Features

- Smooth player, camera, character, creature, ragdoll, object, door, and sky
  motion at the display frame rate
- Interpolated first-person arms and weapons, third-person player movement,
  view animations, and FOV transitions
- Display-rate mouse look with a fixed 60 Hz simulation
- Input latching so short key and mouse-button presses are not lost between
  simulation ticks
- Removal of two engine-side 10 ms frame delays
- An optional fix for stretched or shrunken third-person fingers ("spider
  hands")
- Runtime layout and hook checks that leave the game untouched when an
  unsupported executable or conflicting patch is detected

## Requirements

- Fallout 3 1.7.0.3. Only the GOG executable has been tested.
- A 32-bit ASI loader. The bundled release includes
  [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader).
- An external frame-rate cap, configured through the graphics driver or a
  limiter. Caps of 144, 240, and 350 FPS have been tested.
- `iFPSClamp=60` in `Fallout.ini`. Other values have not been tested.

The patch may accept another storefront's executable when its code layout is
identical, but no other release has been verified.

## Installation

Download either the plugin-only archive or the archive with an ASI loader from
the [Releases page](https://github.com/slopkhayzo/Fallout-3-FPSFix/releases).

1. Open the folder containing `Fallout3.exe`.
2. Copy `Fallout3HFR.asi` and `Fallout3HFR.ini` into it.
3. If you do not already have an ASI loader, also copy the bundled
   `dinput8.dll`.
4. Set an external frame-rate limit and start the game normally.

Do not overwrite an existing `dinput8.dll` from another mod. Keep your current
ASI loader, or rename the bundled Ultimate ASI Loader to another supported
proxy name such as `d3d9.dll` or `winmm.dll`.

The plugin may instead be placed in the ASI loader's `plugins`, `scripts`, or
`update` directory. Keep `Fallout3HFR.ini` beside the plugin.

## Configuration

The release defaults are intended for normal play. Only these settings should
normally be changed:

| Setting | Description |
| --- | --- |
| `bArmAtStartup` | Master switch. Set to `0` to run the game unmodified. |
| `fSimulationHz` | Simulation rate. Leave at `60.0`. |
| `bExperimentalNativeStepUnfrozen` | Keeps menus and conversations smooth. Set to `0` first if a crash or physics glitch occurs after closing a menu. |
| `bExperimentalFingerLengthFix` | Enables the third-person "spider hands" correction. |
| `bTelemetry` | Writes detailed diagnostics. Leave at `0` unless reporting a problem. |

Leave all settings marked **Internals: do not change** at their defaults.

## Known limitations

- Menus, conversations, and the first 30 frames after them use real frame time
  by default because they cannot use frozen presentation frames safely.
- Interpolated motion is displayed up to one 60 Hz tick behind the simulation.
  Mouse look is not delayed.
- A moving object in a quiet neighbouring area may take a fraction of a second
  to begin interpolating.
- Parts of some weapon animations can still look uneven; this has been noticed
  on the laser-rifle reload.
- VATS and kill cameras have not been specifically tested.
- The finger-length fix applies only to the player's third-person body.
- The patch costs approximately 0.2-0.3 ms of CPU time per rendered frame.
- Tick-fix and stutter-remover mods that patch the same code are incompatible.
  Fallout3HFR will refuse to install its hooks when it detects a conflict.

## Troubleshooting

Run the game once, then open `Fallout3HFR.log` beside the plugin.

| Log result | Meaning |
| --- | --- |
| No log file | The ASI loader did not load the plugin. Check the file locations and loader installation. |
| `unsupported executable` or `layout check failed` | The executable layout is not supported. The game was left unmodified. |
| `hook signature mismatch` or `hooks rolled back` | Another mod changed required code first. Fallout3HFR rolled back its changes. |
| `timer hook=1 havok hook=1 ...` | The patch installed successfully. |

Detailed telemetry can grow by several megabytes per hour, so enable
`bTelemetry` only while diagnosing an issue.

## Uninstallation

Delete `Fallout3HFR.asi`, `Fallout3HFR.ini`, and `Fallout3HFR.log`. Remove the
ASI loader DLL only if no other mod needs it. Fallout3HFR does not modify the
game executable, game configuration, or save files.

## Building from source

The project requires CMake 3.20 or newer and Visual Studio with the C++ tools.
Fallout 3 is a 32-bit process, so configure a Win32 build:

```powershell
cmake -S . -B build-x86 -A Win32
cmake --build build-x86 --config Release
```

The source builds both `Fallout3HFR.asi`, the release plugin, and
`dinput8.dll`, a development-only DirectInput proxy. Never install both forms
at the same time. Smoke-test executables are also built for each loading form.

Release archives can be assembled with:

```powershell
powershell -ExecutionPolicy Bypass -File research\scripts\package-release.ps1
```

## Research and porting

The implementation history, measurements, and validation results live in the
[Fallout 3 high-frame-rate plan](research/docs/fallout3-high-frame-rate-plan.md).
The reusable architecture and porting checklist are documented in the
[Fallout HFR port template](research/docs/fallout-hfr-port-template.md).

## Credits and license

Ultimate ASI Loader is created by ThirteenAG and distributed under the MIT
License. Fallout3HFR is also available under the [MIT License](LICENSE).

For more game fixes, visit
[slop-blog.enkhayzomachines.net/fixes](https://slop-blog.enkhayzomachines.net/fixes).
