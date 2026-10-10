Fallout3HFR 1.0.0
High-frame-rate patch for Fallout 3
==================================================

What it does
------------
Fallout 3 ties its game logic to the frame rate and is unstable when run much
above 60 frames a second. This patch keeps the game simulating at a fixed 60
ticks a second and draws the picture at whatever frame rate your system
reaches, with the motion between ticks interpolated. The result is smooth
motion at 120, 240 or more frames a second without running the game logic
faster.

Interpolated at the display frame rate:
  - player movement and the first- and third-person cameras, including
    crouching, falling, aiming (field of view) and reload view animations
  - the first-person arms and weapon
  - the player's body in third person
  - other characters and creatures, including ragdolls
  - objects that move: carried, dropped and knocked-over items, doors and
    other animated objects, in the loaded area around you
  - the sky
Mouse look runs at the display frame rate.

It also:
  - removes a 10 ms sleep the game takes on some frames (among them, while
    the crosshair rests on an enemy you have already hit)
  - reads key and mouse-button presses at the 60 Hz tick, so a press between
    ticks is not lost
  - corrects the "spider hands" bug on the player in third person (fingers
    stretching or shrinking)


Requirements
------------
  - Fallout 3 version 1.7.0.3. Developed and tested on the GOG release only.
    Other releases are accepted if their executable has the same code layout;
    none has been tried. See "If it does not load" below.
  - A 32-bit ASI loader, for example Ultimate ASI Loader. The download
    comes in two forms: the plugin alone, for those who already have a
    loader, and a bundle that includes Ultimate ASI Loader as dinput8.dll.
  - A frame rate limit set outside the game (graphics driver or a limiter
    tool). Tested with limits of 144, 240 and 350.
  - Tested with iFPSClamp=60 in Fallout.ini. Other values have not been
    tested.


Install
-------
Copy into the folder that contains Fallout3.exe:

    Fallout3HFR.asi
    Fallout3HFR.ini
    dinput8.dll                  (the ASI loader; bundle only)

Plugin-only download: you need a 32-bit ASI loader already installed in the
game folder.

Bundle: if you already use an ASI loader, do not copy dinput8.dll; keep
yours. If you already have a different dinput8.dll from another mod, do not
overwrite it: rename the included loader to another name it supports and the
game loads, for example d3d9.dll or winmm.dll.

Fallout3HFR.asi may instead be put in the loader's "plugins", "scripts" or
"update" folder. Fallout3HFR.ini must be in the same folder as the .asi.


Uninstall
---------
Delete Fallout3HFR.asi, Fallout3HFR.ini and Fallout3HFR.log. Delete
dinput8.dll too if nothing else needs the ASI loader. The patch changes
nothing on disk besides its own log file; saves are not affected.

To switch the patch off without removing it, set bArmAtStartup=0 in
Fallout3HFR.ini.


Settings (Fallout3HFR.ini)
--------------------------
  bArmAtStartup                    1 = patch active, 0 = game unmodified.
  bExperimentalNativeStepUnfrozen  1 = menus, conversations and the 30 frames
                                   after them run on the real frame time.
                                   Set to 0 if you get a crash or a physics
                                   glitch right after closing a menu; those
                                   moments then look stepped instead.
  bExperimentalFingerLengthFix     1 = correct "spider hands".
  bTelemetry                       1 = write diagnostics to Fallout3HFR.log
                                   (several megabytes an hour). Leave at 0
                                   unless you are reporting a problem.
  fSimulationHz                    Leave at 60.

Leave the settings marked "Internals" as they are.


Known limitations
-----------------
  - In normal play the game is simulated at 60 ticks a second. In menus and
    conversations, and for 30 frames after they close, it is stepped at your
    frame rate (see bExperimentalNativeStepUnfrozen).
  - The picture runs up to one tick (1/60 s) behind the simulation. That is
    what makes interpolation possible. Mouse look is not delayed.
  - An object in a quiet neighbouring area starts being interpolated a
    fraction of a second after it first moves.
  - Parts of some weapon animations can look uneven (noticed on the laser
    rifle reload). The cause was not found and may be the animation itself.
  - VATS and kill cameras were not specifically tested.
  - The "spider hands" correction covers the player's third-person body only,
    not the first-person arms or other characters.
  - The patch costs roughly 0.2 to 0.3 ms of CPU time per frame.
  - Mods that change the same parts of the game's code (tick-fix or
    stutter-remover style mods) are not compatible: if another mod has
    already changed a location this patch needs, the patch does not install.


If it does not load
-------------------
Start the game once and open Fallout3HFR.log next to the .asi.

  - No log file: the .asi was not loaded. Check that the ASI loader is in the
    game folder and that the .asi is next to Fallout3.exe or in "plugins",
    "scripts" or "update".
  - "unsupported executable" or "layout check failed": your Fallout3.exe does
    not have the code layout the patch was made for (a different version, or
    an executable that is still packed when the patch loads). Nothing was
    changed; the game runs unmodified.
  - "hook signature mismatch" or "hooks rolled back": something else changed
    the game's code first. Nothing was changed by this patch.
  - "timer hook=1 havok hook=1 ..." near the top: the patch is installed.


Credits
-------
Ultimate ASI Loader by ThirteenAG, MIT licence,
https://github.com/ThirteenAG/Ultimate-ASI-Loader
The bundle includes it unmodified, with its licence in
Ultimate-ASI-Loader-LICENSE.txt.


Misc
-------
For more game fixes, visit https://slop-blog.enkhayzomachines.net/fixes :)
