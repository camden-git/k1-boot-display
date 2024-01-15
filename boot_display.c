#include "boot_display.h"
#include <stdio.h>

void _DT_INIT(void)

{
  __gmon_start__();
  compilerTempThing1();
  executeStoredFunctions();
  return;
}



undefined4 _ftext(int param_1,int param_2)

{
  FILE *__stream;
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  char acStack_a8 [132];
  
  __stream = fopen("/etc/boot-display/boot-display.conf","r");
  if (__stream == (FILE *)0x0) {
    fprintf(stderr,"fopen %s failed.\n","/etc/boot-display/boot-display.conf");
LAB_00400ee8:
    fputs("parse_conf failed.\n",stderr);
    uVar3 = 0xffffffff;
  }
  else {
    memset(acStack_a8,0,0x80);
LAB_00400f28:
    pcVar1 = fgets(acStack_a8,0x80,__stream);
    if (pcVar1 != (char *)0x0) {
      iVar4 = __isoc99_sscanf(acStack_a8,"width: %d",&frameBufferSize);
      if (((iVar4 != 1) &&
          (iVar4 = __isoc99_sscanf(acStack_a8,"height: %d",&frameBufferHeight), iVar4 != 1)) &&
         (iVar4 = __isoc99_sscanf(acStack_a8,"fps: %d",&DAT_00412730), iVar4 != 1))
      goto code_r0x004010ec;
      goto LAB_004010a0;
    }
    iVar4 = 0;
    fseek(__stream,0,0);
    while( true ) {
      pcVar1 = fgets(acStack_a8,0x80,__stream);
      if (pcVar1 == (char *)0x0) break;
      iVar2 = __isoc99_sscanf(acStack_a8,&DAT_00402134,additionalPointer + iVar4 * 0x10);
      if (iVar2 == 1) {
        iVar4 = iVar4 + 1;
      }
      memset(acStack_a8,0,0x80);
    }
    fclose(__stream);
    signal(10,(__sighandler_t)&LAB_00401624);
    signal(8,(__sighandler_t)&LAB_00401624);
    signal(1,(__sighandler_t)&LAB_00401624);
    signal(4,(__sighandler_t)&LAB_00401624);
    signal(2,(__sighandler_t)&LAB_00401624);
    signal(6,(__sighandler_t)&LAB_00401624);
    signal(0xd,(__sighandler_t)&LAB_00401624);
    signal(3,(__sighandler_t)&LAB_00401624);
    signal(0xb,(__sighandler_t)&LAB_00401624);
    signal(0xc,(__sighandler_t)&LAB_00401624);
    signal(0xf,(__sighandler_t)&LAB_00401624);
    signal(5,(__sighandler_t)&LAB_00401624);
    signal(9,(__sighandler_t)&LAB_00401624);
    signal(0x10,(__sighandler_t)&LAB_00401624);
    signal(0x11,(__sighandler_t)&LAB_00401624);
    uVar3 = 0xffffffff;
    if (param_1 < 3) {
      pcVar1 = *(char **)(param_2 + 4);
      iVar4 = strcmp("shutdown",pcVar1);
      if (iVar4 == 0) {
        fputs("boot display shutdown!\n",stderr);
        system("mkdir /tmp/load_done");
LAB_00401080:
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      iVar4 = strcmp("display",pcVar1);
      if (iVar4 == 0) {
        sigaction(0xf,(sigaction *)&DAT_00412650,(sigaction *)0x0);
        sigaction(0x10,(sigaction *)&DAT_00412650,(sigaction *)0x0);
        sigaction(0x11,(sigaction *)&DAT_00412650,(sigaction *)0x0);
        uloop_init();
        fputs("boot display\n",stderr);
        DAT_004128d4 = &LAB_00401460;
        processIdToKill = fork();
        if (processIdToKill == 0) {
          processImageData();
          fputs("boot display exit!\n",stderr);
          goto LAB_00401080;
        }
        if (processIdToKill < 1) {
          fputs("Failed to start new boot display instance\n",stderr);
        }
        else {
          uloop_process_add(&DAT_004128c8);
        }
        DAT_004128bc = &LAB_00401478;
        uloop_timeout_set(&DAT_004128b0,150000);
        uloop_timeout_add(&DAT_004128b0);
        uloop_run();
        uloop_done();
        uVar3 = 0;
      }
      else {
        uVar3 = 0;
      }
    }
  }
  return uVar3;
code_r0x004010ec:
  iVar4 = __isoc99_sscanf(acStack_a8,"parts: %d",&DAT_0041272c);
  if (iVar4 == 1) {
    additionalPointer = (undefined4 *)malloc(DAT_0041272c << 6);
    if (additionalPointer == (undefined4 *)0x0) {
      fputs("malloc failed.\n",stderr);
      goto LAB_00400ee8;
    }
    *additionalPointer = 0;
LAB_004010a0:
    memset(acStack_a8,0,0x80);
  }
  goto LAB_00400f28;
}



void processEntry entry(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_20 [16];
  undefined *local_10;
  undefined4 local_c;
  undefined *local_8;
  
  local_8 = auStack_20;
  local_10 = &LAB_00401e44;
  local_c = param_1;
  __libc_start_main(_ftext,param_2,&stack0x00000004,&LAB_00401da0);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



/* WARNING: Removing unreachable block (ram,0x00401338) */
/* WARNING: Removing unreachable block (ram,0x00401344) */

void performInitialization(void)

{
  return;
}



/* WARNING: Removing unreachable block (ram,0x00401380) */
/* WARNING: Removing unreachable block (ram,0x0040138c) */

void compilerTempThing1(void)

{
  return;
}



/* WARNING: Removing unreachable block (ram,0x004013f8) */

void initializeIfNeeded(void)

{
  if (globalFlag == '\0') {
    performInitialization();
    globalFlag = '\x01';
  }
  return;
}



/* WARNING: Removing unreachable block (ram,0x00401380) */
/* WARNING: Removing unreachable block (ram,0x0040138c) */

void compilerTempThing1(void)

{
  return;
}



void cleanupResources(void)

{
  if (jpegDecoderStatus != 0) {
    v4l2_jpeg_decoder_close();
    jpegDecoderStatus = 0;
  }
  if (-1 < frameBufferIndex) {
    fb_disable();
    frameBufferIndex = -1;
  }
  if (bufferPointer != (void *)0x0) {
    free(bufferPointer);
    bufferPointer = (void *)0x0;
  }
  if (-1 < memoryIndex) {
    if (memorySize1 != 0) {
      rmem_free(memoryIndex,memorySize1,memorySize1,(frameBufferSize * frameBufferHeight) / 2);
    }
    if (DAT_004128a8 != 0) {
      rmem_free(memoryIndex,DAT_004128a8,DAT_004128a0,frameBufferSize * frameBufferHeight);
    }
    rmem_close(memoryIndex);
    fb_close(frameBufferIndex,&DAT_00412798);
  }
  if (additionalPointer != (void *)0x0) {
    free(additionalPointer);
    additionalPointer = (void *)0x0;
  }
  return;
}



void shutdownBootDisplay(void)

{
  fputs("boot display shutdown\n",stderr);
  fflush(stderr);
  cleanupResources();
  sync();
  if (processIdToKill != 0) {
    kill(processIdToKill,0xf);
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}



void processImageData(void)

{
  int iVar1;
  int iVar2;
  FILE *__stream;
  size_t __size;
  char *pcVar3;
  uint uVar4;
  char *__format;
  int iVar5;
  int iVar6;
  char acStack_8148 [32768];
  char acStack_148 [128];
  char acStack_c8 [64];
  char *local_88;
  int local_84;
  int local_80;
  undefined4 local_7c;
  timeval local_78;
  timeval local_70;
  undefined auStack_68 [8];
  dirent **local_60 [2];
  int local_58;
  int local_54;
  char *local_50;
  int local_4c;
  int local_48;
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  char *local_30;
  
  frameBufferIndex = fb_open("/dev/fb1",&DAT_00412798);
  local_48 = 0x410000;
  local_54 = 0x410000;
  if (frameBufferIndex < 0) {
    __format = "fb_scale : open %s device fail\n";
    pcVar3 = "/dev/fb1";
LAB_004016e4:
    fprintf(stderr,__format,pcVar3);
    goto LAB_00401728;
  }
  fb_enable(frameBufferIndex);
  memoryIndex = rmem_open();
  if (memoryIndex < 0) {
    pcVar3 = "fb_scale : open rmem device fail\n";
  }
  else {
    DAT_004128a8 = rmem_alloc(memoryIndex,&DAT_004128a0,frameBufferSize * frameBufferHeight);
    local_44 = 0x410000;
    local_40 = 0x410000;
    if (DAT_004128a8 != 0) {
      memorySize1 = rmem_alloc(memoryIndex,&memorySize1,(frameBufferSize * frameBufferHeight) / 2);
      local_3c = 0x410000;
      local_38 = 0x410000;
      if (memorySize1 != 0) {
        local_88 = strdup("/dev/video1");
        iVar6 = 0;
        local_84 = frameBufferSize;
        local_80 = frameBufferHeight;
        local_7c = 0x3231564e;
        jpegDecoderStatus = v4l2_jpeg_decoder_open(&local_88);
        local_4c = 0x410000;
        if (jpegDecoderStatus != 0) {
          while (iVar6 < DAT_0041272c) {
            iVar1 = additionalPointer + iVar6 * 0x40;
            snprintf(acStack_c8,0x40,"%s/%s","/etc/boot-display/",iVar1);
            iVar2 = scandir(acStack_c8,local_60,(__selector *)&LAB_00401450,alphasort);
            local_34 = 0x400000;
            if (iVar2 < 0) {
              fprintf(stderr,"scandir num = %d\n",iVar2);
              iVar6 = iVar6 + 1;
            }
            else {
              memset(acStack_8148,0,0x8000);
              for (iVar5 = 0; iVar5 != iVar2; iVar5 = iVar5 + 1) {
                if ((local_60[0][iVar5]->d_type & 8) != 0) {
                  local_58 = iVar5 * 4;
                  snprintf(acStack_8148 + iVar5 * 0x40,0x40,"%s",local_60[0][iVar5]->d_name,iVar1);
                  free(*(void **)((int)local_60[0] + local_58));
                }
              }
              free(local_60[0]);
              local_30 = "rb";
              do {
                for (local_58 = 0; iVar5 != local_58; local_58 = local_58 + 1) {
                  local_70.tv_sec = 0;
                  local_70.tv_usec = 0;
                  local_78.tv_sec = 0;
                  local_78.tv_usec = 0;
                  gettimeofday(&local_70,(__timezone_ptr_t)0x0);
                  memset(acStack_148,0,0x80);
                  local_50 = acStack_8148 + local_58 * 0x40;
                  snprintf(acStack_148,0x80,(char *)(local_34 + 0x2008),acStack_c8,local_50);
                  __stream = fopen(acStack_148,local_30);
                  if (__stream == (FILE *)0x0) {
                    __size = 0xffffffff;
                  }
                  else {
                    fseek(__stream,0,2);
                    __size = ftell(__stream);
                    fseek(__stream,0,0);
                    bufferPointer = malloc(__size);
                    fread(bufferPointer,1,__size,__stream);
                    fclose(__stream);
                    if (__size == 0) {
                      __format = "failed to read file %s\n";
                      pcVar3 = local_50;
                      goto LAB_004016e4;
                    }
                  }
                  iVar1 = v4l2_jpeg_decoder_work
                                    (*(undefined4 *)(local_4c + 0x2794),bufferPointer,__size,
                                     auStack_68);
                  if (iVar1 < 0) {
                    pcVar3 = "failed to decode jpeg\n";
                    goto LAB_00401720;
                  }
                  iVar1 = *(int *)(local_4c + 0x2794);
                  memcpy(*(void **)(local_40 + 0x28a8),*(void **)(iVar1 + 0xc),
                         frameBufferHeight * frameBufferSize);
                  memcpy(*(void **)(local_38 + 0x28a4),*(void **)(iVar1 + 0x10),
                         (frameBufferHeight / 2) * frameBufferSize);
                  DAT_00412704 = *(undefined4 *)(local_44 + 0x28a0);
                  DAT_004126e8 = frameBufferHeight;
                  DAT_0041270c = *(undefined4 *)(local_3c + 0x289c);
                  DAT_00412720 = frameBufferHeight;
                  DAT_004126e4 = frameBufferSize;
                  DAT_00412708 = frameBufferSize;
                  DAT_00412710 = frameBufferSize;
                  DAT_0041271c = frameBufferSize;
                  iVar1 = fb_pan_display_set_user_cfg
                                    (*(undefined4 *)(local_54 + 0x2728),&DAT_004126e0);
                  if (iVar1 != 0) {
                    pcVar3 = "fd set user config fail\n";
                    goto LAB_00401720;
                  }
                  iVar1 = fb_pan_display_enable_user_cfg(*(undefined4 *)(local_54 + 0x2728));
                  if (iVar1 != 0) {
                    pcVar3 = "fd enable user config fail\n";
                    goto LAB_00401720;
                  }
                  iVar1 = fb_pan_display(*(undefined4 *)(local_54 + 0x2728),local_48 + 0x2798,0);
                  if (iVar1 != 0) {
                    pcVar3 = "fd enable display fail\n";
                    goto LAB_00401720;
                  }
                  iVar1 = access("/tmp/load_done",0);
                  if (iVar1 == 0) {
                    cleanupResources();
                    /* WARNING: Subroutine does not return */
                    exit(0);
                  }
                  gettimeofday(&local_78,(__timezone_ptr_t)0x0);
                  uVar4 = (local_78.tv_sec - local_70.tv_sec) * 1000000 +
                          (local_78.tv_usec - local_70.tv_usec);
                  if (DAT_00412730 == 0) {
                    trap(7);
                  }
                  if (uVar4 < 1000000 / DAT_00412730) {
                    usleep(1000000 / DAT_00412730 - uVar4);
                  }
                  free(bufferPointer);
                  bufferPointer = (void *)0x0;
                }
              } while (DAT_0041272c + -1 == iVar6);
              iVar6 = iVar6 + 1;
            }
          }
          goto LAB_00401728;
        }
        pcVar3 = "failed to open jpeg decoder\n";
        goto LAB_00401720;
      }
    }
    pcVar3 = "fb_scale : alloc rmem space fail\n";
  }
LAB_00401720:
  fputs(pcVar3,stderr);
LAB_00401728:
  cleanupResources();
  return;
}



void executeStoredFunctions(void)

{
  code **functionPointer;
  code *currentFunction;
  
  if (::currentFunction != (code *)0xffffffff) {
    functionPointer = &::currentFunction;
    currentFunction = ::currentFunction;
    do {
      functionPointer = functionPointer + -1;
      (*currentFunction)();
      currentFunction = *functionPointer;
    } while (currentFunction != (code *)0xffffffff);
    return;
  }
  return;
}



void _DT_FINI(void)

{
  initializeIfNeeded();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = strcmp(__s1,__s2);
  return iVar1;
}



void rmem_alloc(void)

{
  rmem_alloc();
  return;
}



void fb_pan_display(void)

{
  fb_pan_display();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fflush(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fflush(__stream);
  return iVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = fopen(__filename,__modes);
  return pFVar1;
}



void fb_close(void)

{
  fb_close();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void free(void *__ptr)

{
  free(__ptr);
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * strdup(char *__s)

{
  char *pcVar1;
  
  pcVar1 = strdup(__s);
  return pcVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memcpy(__dest,__src,__n);
  return pvVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

char * fgets(char *__s,int __n,FILE *__stream)

{
  char *pcVar1;
  
  pcVar1 = fgets(__s,__n,__stream);
  return pcVar1;
}



void fb_enable(void)

{
  fb_enable();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

__sighandler_t signal(int __sig,__sighandler_t __handler)

{
  __sighandler_t p_Var1;
  
  p_Var1 = signal(__sig,__handler);
  return p_Var1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int gettimeofday(timeval *__tv,__timezone_ptr_t __tz)

{
  int iVar1;
  
  iVar1 = gettimeofday(__tv,__tz);
  return iVar1;
}



void uloop_timeout_add(void)

{
  uloop_timeout_add();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fseek(FILE *__stream,long __off,int __whence)

{
  int iVar1;
  
  iVar1 = fseek(__stream,__off,__whence);
  return iVar1;
}



void uloop_timeout_set(void)

{
  uloop_timeout_set();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int usleep(__useconds_t __useconds)

{
  int iVar1;
  
  iVar1 = usleep(__useconds);
  return iVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream)

{
  size_t sVar1;
  
  sVar1 = fread(__ptr,__size,__n,__stream);
  return sVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

__pid_t getpid(void)

{
  __pid_t _Var1;
  
  _Var1 = getpid();
  return _Var1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = malloc(__size);
  return pvVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int system(char *__command)

{
  int iVar1;
  
  iVar1 = system(__command);
  return iVar1;
}



void rmem_open(void)

{
  rmem_open();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void exit(int __status)

{
                    /* WARNING: Subroutine does not return */
  exit(__status);
}



void fb_pan_display_enable_user_cfg(void)

{
  fb_pan_display_enable_user_cfg();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int kill(__pid_t __pid,int __sig)

{
  int iVar1;
  
  iVar1 = kill(__pid,__sig);
  return iVar1;
}



void rmem_close(void)

{
  rmem_close();
  return;
}



void v4l2_jpeg_decoder_open(void)

{
  v4l2_jpeg_decoder_open();
  return;
}



void __libc_start_main(void)

{
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fprintf(FILE *__stream,char *__format,...)

{
  int iVar1;
  
  iVar1 = fprintf(__stream,__format);
  return iVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

long ftell(FILE *__stream)

{
  long lVar1;
  
  lVar1 = ftell(__stream);
  return lVar1;
}



void __isoc99_sscanf(void)

{
  __isoc99_sscanf();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int snprintf(char *__s,size_t __maxlen,char *__format,...)

{
  int iVar1;
  
  iVar1 = snprintf(__s,__maxlen,__format);
  return iVar1;
}



void uloop_init(void)

{
  uloop_init();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int scandir(char *__dir,dirent ***__namelist,__selector *__selector,__cmp *__cmp)

{
  int iVar1;
  
  iVar1 = scandir(__dir,__namelist,__selector,__cmp);
  return iVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int access(char *__name,int __type)

{
  int iVar1;
  
  iVar1 = access(__name,__type);
  return iVar1;
}



void uloop_process_add(void)

{
  uloop_process_add();
  return;
}



void fb_pan_display_set_user_cfg(void)

{
  fb_pan_display_set_user_cfg();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

__pid_t fork(void)

{
  __pid_t _Var1;
  
  _Var1 = fork();
  return _Var1;
}



void uloop_run(void)

{
  uloop_run();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fclose(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fclose(__stream);
  return iVar1;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int alphasort(dirent **__e1,dirent **__e2)

{
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



void fb_disable(void)

{
  fb_disable();
  return;
}



void rmem_free(void)

{
  rmem_free();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int sigaction(int __sig,sigaction *__act,sigaction *__oact)

{
  int iVar1;
  
  iVar1 = sigaction(__sig,__act,__oact);
  return iVar1;
}



void uloop_done(void)

{
  uloop_done();
  return;
}



void v4l2_jpeg_decoder_close(void)

{
  v4l2_jpeg_decoder_close();
  return;
}



void v4l2_jpeg_decoder_work(void)

{
  v4l2_jpeg_decoder_work();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fputs(char *__s,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputs(__s,__stream);
  return iVar1;
}



void fb_open(void)

{
  fb_open();
  return;
}



/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void sync(void)

{
  sync();
  return;
}


