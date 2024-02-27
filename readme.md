# k1 full control

full control over the software running your k1 printer.

this has only been tested on the normal k1 and k1 max; however, the k1c and k1 max se should work.

## k1 klipper fork

> [!WARNING]
> a diff of this code to stock is in `CrealityKlipper/NOTSTOCKmy_diff.patch`, a human redable format is in `CrealityKlipper/NOTSTOCKdiff.html`.
> there may be some changes due to mods, expect future changes.

### change log (more to come)

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

## k1 boot screen

> [!WARNING]
> currently won't compile and is just for reverse engineering. pull requests are welcome if you don't feel like waiting

shows the video/image array that plays while linux and klipper starts

### info

- config `/etc/boot-display/boot-display.conf`
- directory `/etc/boot-display/`
- display `/dev/video1`
- frame buffer `/dev/fb1`
- waits for `/tmp/load_done` to exist, then exists
  
### building (soon :tm: )

compile and replace with `/usr/bin/boot_display` using sftp

## philosophy

The advancement of 3D printers has only been possible due to their their ability for contributions from anyone and access to the full software and hardware design. A printer utilizing works created by the community should also share its output with the community.
