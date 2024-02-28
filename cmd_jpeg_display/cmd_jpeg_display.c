#include "cmd_jpeg_display.h"



void _DT_INIT(void)

{
  __gmon_start__();
  thunk_FUN_00400e14();
  FUN_00400fc0();
  return;
}



undefined4 _ftext(int param_1,undefined4 *param_2)

{
  byte *pbVar1;
  byte *pbVar2;
  byte bVar3;
  int iVar4;
  FILE *__stream;
  void **ppvVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  void *pvVar9;
  byte *pbVar10;
  char *__format;
  int iVar11;
  uint *puVar12;
  int iVar13;
  uint uVar14;
  size_t __size;
  void *__ptr;
  undefined4 local_3a8;
  int local_3a4;
  int local_37c;
  undefined4 local_378;
  undefined4 local_374;
  uint local_338;
  uint local_334;
  int local_32c;
  uint local_31c;
  uint local_1c0;
  uint local_1bc;
  int local_1b4;
  uint local_1b0;
  int local_1a4;
  undefined auStack_bc [132];
  uint local_38;
  uint local_34;
  int local_30;
  
  DAT_00411360 = *param_2;
  if (param_1 < 2) {
    fprintf(stderr,"Usage: %s jpeg_path\n");
    fputs("Example:\n",stderr);
    fprintf(stderr,"\t%s /etc/logo.jpeg\n",DAT_00411360);
  }
  else {
    iVar4 = fb_open("/dev/fb0",&local_1c0);
    if (-1 < iVar4) {
      if (local_1b0 < 0x12) {
        __format = "error:display not supprot bits_per_pixel: %d\n";
      }
      else {
        local_3a8 = jpeg_std_error(auStack_bc);
        jpeg_CreateDecompress(&local_3a8,0x5a,0x1e8);
        __stream = fopen((char *)param_2[1],"rb");
        if (__stream != (FILE *)0x0) {
          jpeg_stdio_src(&local_3a8,__stream);
          jpeg_read_header(&local_3a8,1);
          local_378 = 1;
          local_374 = 1;
          jpeg_start_decompress(&local_3a8);
          __size = local_338 * local_32c;
          __ptr = (void *)0x0;
          ppvVar5 = (void **)(**(code **)(local_3a4 + 8))(&local_3a8,1,__size,1);
          uVar6 = local_338;
          if (local_1c0 <= local_338) {
            uVar6 = local_1c0;
          }
          local_38 = local_1c0 - uVar6 >> 1;
          uVar8 = local_334;
          if (local_1bc <= local_334) {
            uVar8 = local_1bc;
          }
          local_34 = local_334 - uVar8 >> 1;
          uVar14 = local_338 - uVar6;
          if (local_37c == 4) {
            __ptr = malloc(__size);
          }
          iVar13 = (local_1bc - uVar8 >> 1) * local_1b4 + local_1a4;
          iVar7 = 0;
          while (iVar7 < (int)local_34) {
            local_30 = iVar7;
            jpeg_read_scanlines(&local_3a8,ppvVar5,1);
            iVar7 = local_30 + 1;
          }
          local_38 = local_38 << 2;
          local_34 = (uVar14 & 0xfffffffe) + (uVar14 >> 1);
          for (iVar7 = 0; iVar7 < (int)uVar8; iVar7 = iVar7 + 1) {
            jpeg_read_scanlines(&local_3a8,ppvVar5,1);
            pvVar9 = *ppvVar5;
            if (local_37c == 4) {
              cmyk_to_rgb24(*ppvVar5,__ptr,__size,__size,local_338,1);
              pvVar9 = __ptr;
            }
            pbVar10 = (byte *)((int)pvVar9 + local_34);
            puVar12 = (uint *)(iVar13 + local_38);
            for (iVar11 = 0; iVar11 < (int)uVar6; iVar11 = iVar11 + 1) {
              pbVar1 = pbVar10 + 2;
              bVar3 = *pbVar10;
              pbVar2 = pbVar10 + 1;
              pbVar10 = pbVar10 + 3;
              *puVar12 = *pbVar1 | 0xff000000 | (uint)bVar3 << 0x10 | (uint)*pbVar2 << 8;
              puVar12 = puVar12 + 1;
            }
            iVar13 = iVar13 + local_1b4;
          }
          local_31c = local_334;
          fb_enable(iVar4);
          fb_pan_display(iVar4,&local_1c0,0);
          jpeg_finish_decompress(&local_3a8);
          if (local_37c == 4) {
            free(__ptr);
          }
          jpeg_destroy_decompress(&local_3a8);
          fclose(__stream);
          fb_close(iVar4,&local_1c0);
          return 0;
        }
        local_1b0 = param_2[1];
        __format = "fopen fail: not found %s\n";
      }
      fprintf(stderr,__format,local_1b0);
      fb_close(iVar4,&local_1c0);
      return 0xffffffff;
    }
    fputs("/dev/fb0 not found!\n",stderr);
  }
                    // WARNING: Subroutine does not return
  exit(-1);
}



void processEntry entry(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_20 [16];
  undefined *local_10;
  undefined4 local_c;
  undefined *local_8;
  
  local_8 = auStack_20;
  local_10 = &LAB_00400fb4;
  local_c = param_1;
  __libc_start_main(_ftext,param_2,&stack0x00000004,&LAB_00400f10);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x00400df8)
// WARNING: Removing unreachable block (ram,0x00400e04)

void FUN_00400de0(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00400e40)
// WARNING: Removing unreachable block (ram,0x00400e4c)

void FUN_00400e14(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00400eb8)

void FUN_00400e5c(void)

{
  if (DAT_00411350 == '\0') {
    FUN_00400de0();
    DAT_00411350 = '\x01';
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00400e40)
// WARNING: Removing unreachable block (ram,0x00400e4c)

void thunk_FUN_00400e14(void)

{
  return;
}



void FUN_00400fc0(void)

{
  code **ppcVar1;
  code *pcVar2;
  
  if (DAT_00411290 != (code *)0xffffffff) {
    ppcVar1 = &DAT_00411290;
    pcVar2 = DAT_00411290;
    do {
      ppcVar1 = ppcVar1 + -1;
      (*pcVar2)();
      pcVar2 = *ppcVar1;
    } while (pcVar2 != (code *)0xffffffff);
    return;
  }
  return;
}



void _DT_FINI(void)

{
  FUN_00400e5c();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputs(char *__s,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputs(__s,__stream);
  return iVar1;
}



void jpeg_stdio_src(void)

{
  jpeg_stdio_src();
  return;
}



void cmyk_to_rgb24(void)

{
  cmyk_to_rgb24();
  return;
}



void fb_open(void)

{
  fb_open();
  return;
}



void jpeg_destroy_decompress(void)

{
  jpeg_destroy_decompress();
  return;
}



void __libc_start_main(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void jpeg_CreateDecompress(void)

{
  jpeg_CreateDecompress();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



void jpeg_std_error(void)

{
  jpeg_std_error();
  return;
}



void fb_enable(void)

{
  fb_enable();
  return;
}



void fb_close(void)

{
  fb_close();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fclose(__stream);
  return iVar1;
}



void fb_pan_display(void)

{
  fb_pan_display();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fprintf(FILE *__stream,char *__format,...)

{
  int iVar1;
  
  iVar1 = fprintf(__stream,__format);
  return iVar1;
}



void jpeg_read_scanlines(void)

{
  jpeg_read_scanlines();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = malloc(__size);
  return pvVar1;
}



void jpeg_finish_decompress(void)

{
  jpeg_finish_decompress();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = fopen(__filename,__modes);
  return pFVar1;
}



void jpeg_read_header(void)

{
  jpeg_read_header();
  return;
}



void jpeg_start_decompress(void)

{
  jpeg_start_decompress();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void exit(int __status)

{
                    // WARNING: Subroutine does not return
  exit(__status);
}


