#include "libai_capture.so.h"



void _DT_INIT(void)

{
  __gmon_start__();
  (*(code *)0x984)();
  (*(code *)0xd20)();
  return;
}



undefined4 processEntry main(void)

{
  uint argumentCount;
  undefined4 result;
  int argc;
  undefined4 *argv;
  
  if (argc == 2) {
    argumentCount = atoi((char *)argv[1]);
    if (1 < argumentCount) {
      argumentCount = 0;
    }
    ai_snapshot(argumentCount);
    result = 0;
  }
  else {
    puts((char *)0x1000);
    printf((char *)0x1014,*argv);
    puts((char *)0x102c);
    puts((char *)0x104c);
    result = 0xffffffff;
  }
  return result;
}



// WARNING: Removing unreachable block (ram,0x00010840)
// WARNING: Removing unreachable block (ram,0x00010848)

void executeInitialization(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x0001088c)
// WARNING: Removing unreachable block (ram,0x00010894)

void FUN_00010858(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00010928)
// WARNING: Removing unreachable block (ram,0x00010950)

void initializeFunction(void)

{
  if (flag == '\0') {
    __cxa_finalize(POINTER);
    executeInitialization();
    flag = '\x01';
  }
  return;
}



void FUN_00010984(void)

{
  FUN_00010858();
  return;
}



int checkThePid(undefined4 param_1)

{
  FILE *__stream;
  char *ptr;
  int result;
  char commandBuffer [256];
  
  memset(commandBuffer,0,0xff);
  result = -1;
  sprintf(commandBuffer,(char *)0xee8,param_1);
  __stream = popen(commandBuffer,(char *)0xf0c);
  if (__stream != (FILE *)0x0) {
    ptr = fgets(commandBuffer,0xff,__stream);
    if (ptr != (char *)0x0) {
      result = atoi(commandBuffer);
      result = -(uint)(result < 1);
    }
    fclose(__stream);
  }
  return result;
}



int ai_snapshot(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char fileNameBuffer [256];
  char commandBuffer [256];
  char localBuffer [12];
  
  localBuffer[0] = '\0';
  memset(commandBuffer,0,0xff);
  memset(fileNameBuffer,0,0xff);
  if (param_1 == 0) {
    strcpy(commandBuffer,(char *)0xf10);
    pcVar4 = (char *)0xf2c;
  }
  else {
    strcpy(commandBuffer,(char *)0xf3c);
    pcVar4 = (char *)0xf58;
  }
  strcpy(fileNameBuffer,pcVar4);
  iVar1 = open(commandBuffer,0);
  if (iVar1 < 0) {
    pcVar4 = (char *)0xf68;
  }
  else {
    read(iVar1,localBuffer,1);
    iVar2 = atoi(localBuffer);
    close(iVar1);
    iVar1 = checkThePid(iVar2);
    if (iVar1 == 0) {
      puts((char *)0xf80);
    }
    iVar1 = ipc_shm_alloc(fileNameBuffer,1);
    if (iVar1 == 0) {
      pcVar4 = (char *)0xf98;
    }
    else {
      iVar2 = checkThePid(iVar2);
      if (iVar2 == 0) {
        localBuffer[0] = '\x01';
        iVar2 = ipc_write_data(iVar1,localBuffer,1);
        if (-1 < iVar2) {
          iVar2 = 0x96;
          do {
            if (iVar2 == 0) {
              iVar3 = -3;
              break;
            }
            usleep(10000);
            iVar3 = ipc_read_data(iVar1,localBuffer,1);
            if (iVar3 < 0) {
              pcVar4 = (char *)0xfdc;
              goto LAB_00010b40;
            }
            iVar3 = (int)localBuffer[0];
            iVar2 = iVar2 + -1;
          } while (iVar3 == 1);
          localBuffer[0] = '\0';
          iVar2 = ipc_write_data(iVar1,localBuffer,1);
          if (-1 < iVar2) {
            printf((char *)0xff4,iVar3);
            ipc_shm_release_part(iVar1);
            return iVar3;
          }
        }
        pcVar4 = (char *)0xfc4;
      }
      else {
        pcVar4 = (char *)0xfb0;
      }
    }
  }
LAB_00010b40:
  puts(pcVar4);
  return -1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  ssize_t sVar1;
  
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
  sVar1 = (*(code *)0x8a4)();
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

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
  iVar1 = (*(code *)0x8a4)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * fgets(char *__s,int __n,FILE *__stream)

{
  char *pcVar1;
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
  pcVar1 = (char *)(*(code *)0x8a4)();
  return pcVar1;
}



void ipc_write_data(void)

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
  (*(code *)0x8a4)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int usleep(__useconds_t __useconds)

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
  (**(code **)(unaff_gp + -0x7ff0))();
  iVar1 = (*(code *)0x8a4)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strcpy(char *__dest,char *__src)

{
  char *pcVar1;
  
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
  pcVar1 = (char *)(*(code *)0x8a4)();
  return pcVar1;
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
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  iVar1 = (*(code *)0x8a4)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int open(char *__file,int __oflag,...)

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
  iVar1 = (*(code *)0x8a4)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

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
  pvVar1 = (void *)(*(code *)0x8a4)();
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * popen(char *__command,char *__modes)

{
  FILE *pFVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  pFVar1 = (FILE *)(*(code *)0x8a4)();
  return pFVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

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
  iVar1 = (*(code *)0x8a4)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sprintf(char *__s,char *__format,...)

{
  int iVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  iVar1 = (*(code *)0x8a4)();
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
  iVar1 = (*(code *)0x8a4)();
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int close(int __fd)

{
  int iVar1;
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  iVar1 = (*(code *)0x8a4)();
  return iVar1;
}



void ipc_shm_release_part(void)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0x8a4)();
  return;
}



void ipc_shm_alloc(void)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0x8a4)();
  return;
}



void ipc_read_data(void)

{
  int unaff_gp;
  
  (**(code **)(unaff_gp + -0x7ff0))();
  (*(code *)0x8a4)();
  return;
}



void _DT_FINI(void)

{
  (*(code *)0x8a4)();
  return;
}


