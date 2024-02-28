# k1 full control

> full control over the software running your k1 printer.

The end goal of this project is to remove all non-open source code from your K1 printer and to create or further improve features for the K1 through open-source development.

This has only been tested on the normal k1 and k1 max; however, the k1c and k1 max se should work.

- [k1 full control](#k1-full-control)
  - [software](#software)
    - [klipper fork](#klipper-fork)
      - [changelog](#changelog)
    - [ai app laser](#ai-app-laser)
    - [boot screen](#boot-screen)
      - [info](#info)
  - [philosophy](#philosophy)

## software

The source code for all programs mentioned can be found in each folder along with the shipped binaries.
None of this decompiled code compiles.... yet. (prs welcome)

> [!WARNING]
> Most of this code remains not fully understood, and an even greater portion isn't human readable.
> Contributions from the community are warmly welcomed.

### klipper fork

A diff of this code to stock is in `CrealityKlipper/NOTSTOCKmy_diff.patch`, a human redable format is in `CrealityKlipper/NOTSTOCKdiff.html`.

#### changelog

*WIP*

- errors are now in json format with keys
- changed saving config file logic
- changes to adxl345 code to work with nozzle mcu
  - this also broke it and made it map Y resonances to X
- custom macros in python for print starting
- DirZCtl
- FanFeedback (maybe unused)
- RCTFilter
- changed power loss handling
- gcode file metadata reading
- prTouch
- deleted random files

### ai app laser

Not well documented/decompiled, more to come.

This is a CPython program that seems to work with flow detection using the lidar system and also performs first layer detection; it's almost impossible to read because CPython generates lots of extra functions, but it does point to some useful files.

- `/usr/data/creality/tmp/pointCloud/laser_offset_correction_table_pc.temp`
- `/usr/data/ai_image`

### boot screen

shows the video (really just image array) that plays while linux and klipper starts

#### info

- config `/etc/boot-display/boot-display.conf`
- directory `/etc/boot-display/`
- display `/dev/video1`
- frame buffer `/dev/fb1`
- waits for `/tmp/load_done` to exist, then exists
- exec from `/usr/bin/boot_display`

## philosophy

The advancement of 3D printers has only been possible due to their their ability for contributions from anyone and access to the full software and hardware design. A printer utilizing works created by the community should also share its output with the community.
