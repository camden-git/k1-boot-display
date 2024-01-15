# k1 full control 

full control over the software running your k1(max) printer.

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

The advancement of 3D printers has only been possible due to their their openness and the inclusivity of contributions from anyone. A printer utilizing works created by the community should also share its output.
