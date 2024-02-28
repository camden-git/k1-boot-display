#include "libai_engine.so.h"



void _DT_INIT(void)

{
  __gmon_start__();
  (*(code *)0xf34)();
  (*(code *)0x1570)();
  return;
}



undefined4 processEntry main(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int in_a0;
  undefined4 *in_a1;
  undefined4 uVar4;
  undefined4 *puVar5;
  char acStack_210 [256];
  undefined4 local_110 [60];
  int local_20 [7];
  
  memset(local_110,0,0xf0);
  memset(acStack_210,0,0xff);
  if (in_a0 == 3) {
    uVar1 = atoi((char *)in_a1[1]);
    if (1 < uVar1) {
      uVar1 = 0;
    }
    uVar2 = atoi((char *)in_a1[2]);
    if (1 < uVar2) {
      uVar2 = 0;
    }
    if (uVar1 == 0) {
      uVar4 = 0x1898;
    }
    else {
      uVar4 = 0x18ac;
    }
    sprintf(acStack_210,(char *)0x17c0,0x17ac,uVar4);
    iVar3 = start_ai_engine(uVar1,uVar2,local_110,local_20,acStack_210);
    uVar4 = 0xffffffff;
    if (-1 < iVar3) {
      printf((char *)0x18c0,local_20[0]);
      puts((char *)0x18e4);
      puVar5 = local_110;
      for (iVar3 = 0; iVar3 < local_20[0]; iVar3 = iVar3 + 1) {
        printf((char *)0x1948,iVar3,*puVar5);
        puVar5 = puVar5 + 6;
      }
      uVar4 = 0;
    }
  }
  else {
    puts((char *)0x17ec);
    printf((char *)0x1800,*in_a1);
    puts((char *)0x1820);
    puts((char *)0x1840);
    puts((char *)0x1860);
    puts((char *)0x1878);
    uVar4 = 0xffffffff;
  }
  return uVar4;
}



// WARNING: Removing unreachable block (ram,0x00010df0)
// WARNING: Removing unreachable block (ram,0x00010df8)

void FUN_00010dd0(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00010e3c)
// WARNING: Removing unreachable block (ram,0x00010e44)

void FUN_00010e08(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00010ed8)
// WARNING: Removing unreachable block (ram,0x00010f00)

void FUN_00010e54(void)

{
  if (DAT_00021bb0 == '\0') {
    __cxa_finalize(PTR_LOOP_00021ba4);
    FUN_00010dd0();
    DAT_00021bb0 = '\x01';
  }
  return;
}



void FUN_00010f34(void)

{
  FUN_00010e08();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// ai_engine_read_write(char const*, _ai_mode, Results*, int*, char const*)

char * ai_engine_read_write
                 (char *imagePath,_ai_mode mode,Results *results,int *resultCount,char *outputPath)

{
  size_t length;
  void *__dest;
  undefined4 *puVar1;
  int iVar2;
  char *__ptr;
  int *piVar3;
  int iVar4;
  char *pcVar5;
  undefined4 local_b0;
  int local_ac;
  int local_a8;
  int local_a4;
  int local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  int *local_88;
  undefined4 *local_84;
  undefined4 auStack_80 [2];
  undefined4 local_78;
  int local_74;
  int localVar13;
  int local_6c;
  int local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  int *localIterator;
  undefined4 *localTempPtr;
  undefined4 localVar21;
  undefined4 local_44;
  void *local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  
  local_78 = 0x42ff0000;
  local_74 = 0;
  localVar13 = 0;
  local_6c = 0;
  local_68 = 0;
  local_64 = 0;
  local_60 = 0;
  local_5c = 0;
  local_58 = 0;
  local_54 = 0;
  localVar21 = 0;
  local_44 = 0;
  local_40 = (void *)0x0;
  local_3c = 0;
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  localIterator = &localVar13;
  localTempPtr = &localVar21;
  if ((imagePath != (char *)0x0) && (length = strlen(imagePath), length != 0)) {
                    // try { // try from 00011020 to 00011027 has its CatchHandler @ 00011378
    __dest = (void *)cv::String::allocate((uint)&local_34);
    memcpy(__dest,imagePath,length);
  }
                    // try { // try from 00011054 to 0001105b has its CatchHandler @ 0001136c
  cv::imread((String *)&local_b0,(int)&local_34);
                    // try { // try from 00011064 to 000110d3 has its CatchHandler @ 00011310
  cv::Mat::release();
  local_78 = local_b0;
  local_74 = local_ac;
  localVar13 = local_a8;
  local_6c = local_a4;
  local_68 = local_a0;
  local_64 = local_9c;
  local_60 = local_98;
  local_5c = local_94;
  local_58 = local_90;
  local_54 = local_8c;
  if (localTempPtr != &localVar21) {
    cv::fastFree(localTempPtr);
    localIterator = &localVar13;
    localTempPtr = &localVar21;
  }
  puVar1 = local_84;
  if (local_ac < 3) {
    *localTempPtr = *local_84;
    localTempPtr[1] = local_84[1];
  }
  else {
    localIterator = local_88;
    local_84 = auStack_80;
    local_88 = &local_a8;
    localTempPtr = puVar1;
  }
  local_b0 = 0x42ff0000;
  local_a4 = 0;
  local_a8 = 0;
  local_ac = 0;
  local_a0 = 0;
  local_9c = 0;
  local_98 = 0;
  local_94 = 0;
  local_90 = 0;
  local_8c = 0;
  cv::Mat::~Mat((Mat *)&local_b0);
  cv::String::deallocate();
  if (local_68 != 0) {
    if (local_74 < 3) {
      iVar2 = localVar13 * local_6c;
    }
    else {
      iVar2 = 1;
      piVar3 = localIterator;
      do {
        iVar4 = *piVar3;
        piVar3 = piVar3 + 1;
        iVar2 = iVar2 * iVar4;
      } while (localIterator + local_74 != piVar3);
    }
    if ((iVar2 != 0) && (local_74 != 0)) {
      __ptr = strdup((char *)0x1874);
      if (mode == 1) {
        free(__ptr);
        __ptr = strdup((char *)0x1790);
      }
                    // try { // try from 000111dc to 00011307 has its CatchHandler @ 00011378
      detect_yolov5((Mat *)&local_78,(vector *)&local_40,__ptr);
      get_results((Mat *)&local_78,(vector *)&local_40,results,resultCount,__ptr);
      if (0 < *resultCount) {
        draw_objects((Mat *)&local_78,(vector *)&local_40,outputPath,__ptr);
      }
      pcVar5 = __ptr;
      if (__ptr != (char *)0x0) {
        pcVar5 = (char *)0x0;
        free(__ptr);
      }
      goto LAB_00011254;
    }
  }
  fprintf(_stderr,(char *)0x1778,imagePath);
  pcVar5 = (char *)0xffffffff;
LAB_00011254:
  if (local_40 != (void *)0x0) {
    operator_delete(local_40);
  }
  cv::Mat::~Mat((Mat *)&local_78);
  return pcVar5;
}



int start_ai_engine(int mode,_ai_mode aiMode,Results *results,int *resultCount,char *outputPath)

{
  int returnValue;
  undefined4 formatSpecifier;
  char formatBuffer [256];
  
  if (mode == 0) {
    formatSpecifier = 0x1798;
  }
  else {
    formatSpecifier = 0x17c8;
  }
  sprintf(formatBuffer,(char *)0x17c0,0x17ac,formatSpecifier);
  returnValue = ai_snapshot(mode);
  if (returnValue < 0) {
    puts((char *)0x17d8);
    returnValue = -1;
  }
  else {
    returnValue = ai_engine_read_write(formatBuffer,aiMode,results,resultCount,outputPath);
    returnValue = returnValue >> 0x1f;
  }
  return returnValue;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// cv::Mat::release()

void cv::Mat::release(void)

{
  int iVar1;
  int iVar2;
  int in_a0;
  
  iVar1 = *(int *)(in_a0 + 0x24);
  if (iVar1 != 0) {
    SYNC(0);
    iVar2 = *(int *)(iVar1 + 0xc);
    *(int *)(iVar1 + 0xc) = iVar2 + -1;
    SYNC(0);
    if (iVar2 == 1) {
      cv::Mat::deallocate();
    }
  }
  *(undefined4 *)(in_a0 + 0x24) = 0;
  *(undefined4 *)(in_a0 + 0x10) = 0;
  *(undefined4 *)(in_a0 + 0x1c) = 0;
  *(undefined4 *)(in_a0 + 0x18) = 0;
  *(undefined4 *)(in_a0 + 0x14) = 0;
  for (iVar1 = 0; iVar1 < *(int *)(in_a0 + 4); iVar1 = iVar1 + 1) {
    *(undefined4 *)(*(int *)(in_a0 + 0x28) + iVar1 * 4) = 0;
  }
  return;
}



// cv::Mat::~Mat()

void __thiscall cv::Mat::~Mat(Mat *this)

{
  release();
  if (*(Mat **)(this + 0x2c) != this + 0x30) {
                    // WARNING: Could not recover jumptable at 0x00011558. Too many branches
                    // WARNING: Treating indirect jump as call
    cv::fastFree(*(Mat **)(this + 0x2c));
    return;
  }
  return;
}



void FUN_00011570(void)

{
  code **ppcVar1;
  code *pcVar2;
  
  if (DAT_00021adc != (code *)0xffffffff) {
    ppcVar1 = &DAT_00021adc;
    pcVar2 = DAT_00021adc;
    do {
      ppcVar1 = ppcVar1 + -1;
      (*pcVar2)();
      pcVar2 = *ppcVar1;
    } while (pcVar2 != (code *)0xffffffff);
  }
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sprintf(char *__s,char *__format,...)

{
  int iVar1;
  
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  iVar1 = (*(code *)0xe54)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void cv::Mat::deallocate(void)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void draw_objects(Mat *param_1,vector *param_2,char *param_3,char *param_4)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  pvVar1 = (void *)(*(code *)0xe54)();
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void operator_delete(void *param_1)

{
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)(undefined *)0x0)();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  pvVar1 = (void *)(*(code *)0xe54)();
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  sVar1 = (*(code *)0xe54)();
  return sVar1;
}



void ai_snapshot(void)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

{
  int iVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  iVar1 = (*(code *)0xe54)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int atoi(char *__nptr)

{
  int iVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  iVar1 = (*(code *)0xe54)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fprintf(FILE *__stream,char *__format,...)

{
  int iVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  iVar1 = (*(code *)0xe54)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void cv::String::allocate(uint param_1)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void cv::String::deallocate(void)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
  int iVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  iVar1 = (*(code *)0xe54)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void cv::fastFree(void *param_1)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void get_results(Mat *param_1,vector *param_2,Results *param_3,int *param_4,char *param_5)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strdup(char *__s)

{
  char *pcVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  pcVar1 = (char *)(*(code *)0xe54)();
  return pcVar1;
}



void _Unwind_Resume(void)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void detect_yolov5(Mat *param_1,vector *param_2,char *param_3)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void cv::imread(String *param_1,int param_2)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0xe54)();
  return;
}



void _DT_FINI(void)

{
  (*(code *)0xe54)();
  return;
}


