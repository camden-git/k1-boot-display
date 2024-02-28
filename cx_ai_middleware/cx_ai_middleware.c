#include "cx_ai_middleware.h"



void _DT_INIT(void)

{
  __gmon_start__();
  unreachableFunction();
  FUN_0042df20();
  return;
}



undefined4 _ftext(void)

{
  int iVar1;
  size_t sVar2;
  undefined4 uVar3;
  
  signal(2,blackbox_handler);
  signal(10,blackbox_handler);
  signal(8,blackbox_handler);
  signal(1,blackbox_handler);
  signal(4,blackbox_handler);
  signal(6,blackbox_handler);
  signal(0xd,blackbox_handler);
  signal(3,blackbox_handler);
  signal(0xb,blackbox_handler);
  signal(0xc,blackbox_handler);
  signal(0xf,blackbox_handler);
  signal(5,blackbox_handler);
  signal(0x10,blackbox_handler);
  signal(0x11,blackbox_handler);
  CrLogOpen("/usr/data//creality/userdata/log/","cx_ai_middleware");
  createPThreadForDataProcessing();
  iVar1 = pthread_create(&DAT_0044da70,(pthread_attr_t *)0x0,FUN_004041b4,(void *)0x0);
  if (iVar1 == 0) {
    pthread_join(DAT_0044da70,(void **)0x0);
    uVar3 = 0;
  }
  else {
    uVar3 = 0xffffffff;
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044da78,0,0x800);
      snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) create pthread error!\n","WARNING","main/main.c",
               0xeb);
      sVar2 = strlen(&DAT_0044da78);
      CrLogWrite(3,&DAT_0044da78,sVar2);
      CrLogUnLock();
    }
  }
  return uVar3;
}



void processEntry entry(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_20 [16];
  undefined *local_10;
  undefined4 local_c;
  undefined *local_8;
  
  local_8 = auStack_20;
  local_10 = &LAB_0042df14;
  local_c = param_1;
  __libc_start_main(_ftext,param_2,&stack0x00000004,FUN_0042de70);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x00403bd8)
// WARNING: Removing unreachable block (ram,0x00403be4)

void performInitialization(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00403c20)
// WARNING: Removing unreachable block (ram,0x00403c2c)

void unreachableFunction(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00403c98)

void initializeIfNeeded(void)

{
  if (DAT_0044da60 == '\0') {
    performInitialization();
    DAT_0044da60 = '\x01';
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00403c20)
// WARNING: Removing unreachable block (ram,0x00403c2c)

void unreachableFunction(void)

{
  return;
}



void checkLaserConnectState(void)

{
  int jsonResult;
  int logLevel;
  size_t length;
  int laserPluggedObj;
  char *logMessageFormat;
  undefined4 logMessageCode;
  
  jsonResult = json_tokener_parse();
  if (jsonResult == 0) {
    return;
  }
  logLevel = GetLogLevel();
  if (logLevel < 3) {
    CrLogLock();
    memset(&DAT_0044da78,0,0x800);
    snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) get laser connect state\n",&DAT_0042dfc4,
             "main/main.c",0x32);
    length = strlen(&DAT_0044da78);
    CrLogWrite(2,&DAT_0044da78,length);
    CrLogUnLock();
  }
  logLevel = json_object_is_type(jsonResult,4);
  if (logLevel == 0) goto LAB_00403f14;
  logLevel = json_object_object_get(jsonResult,"laser_plugged");
  if ((logLevel == 0) || (laserPluggedObj = json_object_is_type(logLevel,3), laserPluggedObj == 0))
  {
    logLevel = GetLogLevel();
    if (3 < logLevel) goto LAB_00403f14;
    CrLogLock();
    memset(&DAT_0044da78,0,0x800);
    logMessageCode = 0x44;
    logMessageFormat = "[%s]-[%s](%d) plugged Obj fail\n";
  }
  else {
    logLevel = json_object_get_int(logLevel);
    laserPluggedObj = GetLogLevel();
    if (laserPluggedObj < 3) {
      CrLogLock();
      memset(&DAT_0044da78,0,0x800);
      snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) laser plugged = %d\n",&DAT_0042dfc4,"main/main.c",
               0x39,logLevel);
      length = strlen(&DAT_0044da78);
      CrLogWrite(2,&DAT_0044da78,length);
      CrLogUnLock();
    }
    if (logLevel == 0) {
      logLevel = FUN_00412300();
      if (logLevel != 0) {
        FUN_004122d8();
        goto LAB_00403f14;
      }
      logLevel = GetLogLevel();
      if (3 < logLevel) goto LAB_00403f14;
      CrLogLock();
      memset(&DAT_0044da78,0,0x800);
      logMessageCode = 0x42;
      logMessageFormat = "[%s]-[%s](%d) laser drive no init";
    }
    else {
      logLevel = FUN_00410980("/dev/serial/by-id/creality-laser");
      if ((logLevel == 0) || (logLevel = GetLogLevel(), 3 < logLevel)) goto LAB_00403f14;
      CrLogLock();
      memset(&DAT_0044da78,0,0x800);
      logMessageCode = 0x3e;
      logMessageFormat = "[%s]-[%s](%d) laser drive init fail\n";
    }
  }
  snprintf(&DAT_0044da78,0x800,logMessageFormat,"WARNING","main/main.c",logMessageCode);
  length = strlen(&DAT_0044da78);
  CrLogWrite(3,&DAT_0044da78,length);
  CrLogUnLock();
LAB_00403f14:
  json_object_put(jsonResult);
  return;
}



void blackbox_handler(int signal_num)

{
  int log_level;
  size_t length;
  char *signal_name;
  
  log_level = GetLogLevel();
  if (log_level < 3) {
    CrLogLock();
    memset(&DAT_0044da78,0,0x800);
    snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) Enter blackbox_handler: ",&DAT_0042dfc4,
             "main/main.c",0xbd);
    length = strlen(&DAT_0044da78);
    CrLogWrite(2,&DAT_0044da78,length);
    CrLogUnLock();
  }
  log_level = GetLogLevel();
  if (log_level < 3) {
    CrLogLock();
    memset(&DAT_0044da78,0,0x800);
    signal_name = strsignal(signal_num);
    snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) Got signal name %s, num %d; exiting ...",
             &DAT_0042dfc4,"main/main.c",0xbe,signal_name,signal_num);
    length = strlen(&DAT_0044da78);
    CrLogWrite(2,&DAT_0044da78,length);
    CrLogUnLock();
  }
  pthread_cancel(DAT_0044da70);
  DAT_0044da70 = 0xffffffff;
  FUN_004122d8();
  cleanupAndShutdown();
  log_level = GetLogLevel();
  if (log_level < 3) {
    CrLogLock();
    memset(&DAT_0044da78,0,0x800);
    snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) \nRelease resource.\n",&DAT_0042dfc4,"main/main.c",
             200);
    length = strlen(&DAT_0044da78);
    CrLogWrite(2,&DAT_0044da78,length);
    CrLogUnLock();
  }
  CrLogClose();
                    // WARNING: Subroutine does not return
  exit(1);
}



undefined4 FUN_004041b4(void)

{
  int iVar1;
  size_t sVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 local_28 [2];
  int local_20;
  
  uloop_init();
  DAT_0044da74 = ubus_connect(0);
  if (DAT_0044da74 == 0) {
    iVar1 = GetLogLevel();
    if (3 < iVar1) {
      return 0;
    }
    CrLogLock();
    memset(&DAT_0044da78,0,0x800);
    snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) Failed to connect to ubus\n","WARNING","main/main.c"
             ,0x9c);
    sVar2 = strlen(&DAT_0044da78);
    CrLogWrite(3,&DAT_0044da78,sVar2);
    CrLogUnLock();
    return 0;
  }
  uloop_fd_add(DAT_0044da74 + 0x2c,9);
  iVar1 = ubus_lookup_id(DAT_0044da74,"laser",local_28);
  if (iVar1 == 0) {
    local_20 = DAT_0044da74;
    ubus_invoke_fd(DAT_0044da74,local_28[0],"status",0,&LAB_00404588,0,1000,0xffffffff);
    iVar1 = ubus_register_subscriber(DAT_0044da74,&DAT_0044d840);
    if ((iVar1 != 0) && (iVar3 = GetLogLevel(), iVar3 < 4)) {
      CrLogLock();
      memset(&DAT_0044da78,0,0x800);
      uVar4 = ubus_strerror(iVar1);
      snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) Failed to add ubus_register_subscriber: %s\n",
               "WARNING","main/main.c",0x86,uVar4);
      sVar2 = strlen(&DAT_0044da78);
      CrLogWrite(3,&DAT_0044da78,sVar2);
      CrLogUnLock();
    }
    iVar1 = ubus_subscribe(DAT_0044da74,&DAT_0044d840,local_28[0]);
    if ((iVar1 == 0) || (iVar3 = GetLogLevel(), 3 < iVar3)) goto LAB_00404328;
    CrLogLock();
    memset(&DAT_0044da78,0,0x800);
    uVar4 = ubus_strerror(iVar1);
    snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) Failed to ubus_subscribe: %s\n","WARNING",
             "main/main.c",0x8a,uVar4);
  }
  else {
    iVar1 = GetLogLevel();
    if (3 < iVar1) goto LAB_00404328;
    CrLogLock();
    memset(&DAT_0044da78,0,0x800);
    snprintf(&DAT_0044da78,0x800,"[%s]-[%s](%d) Failed to look up laser object\n","WARNING",
             "main/main.c",0x7e);
  }
  sVar2 = strlen(&DAT_0044da78);
  CrLogWrite(3,&DAT_0044da78,sVar2);
  CrLogUnLock();
LAB_00404328:
  uloop_run();
  ubus_free(DAT_0044da74);
  uloop_done();
  return 0;
}



void processReceivedData(void)

{
  undefined4 *dataProcessingResult;
  char *substringPtr;
  int logLevel;
  size_t length;
  int controlJsonObj;
  int typeCheckResult;
  char *controlString;
  undefined **functionPointerArray;
  
  FUN_0040ea58();
  createThread();
  do {
    dataProcessingResult = getLinkedListHead();
    if (dataProcessingResult != (undefined4 *)0x0) {
      controlString = (char *)dataProcessingResult[1];
      while ((controlString != (char *)0x0 &&
             (substringPtr = strchr(controlString,3), substringPtr != (char *)0x0))) {
        *substringPtr = '\0';
        logLevel = json_tokener_parse(controlString);
        if (logLevel == 0) {
          logLevel = GetLogLevel();
          if (logLevel < 4) {
            CrLogLock();
            memset(&DAT_0044e284,0,0x800);
            snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) cmd recv data to json fail\n","WARNING",
                     "main/server_cmd.c",0x83c);
            length = strlen(&DAT_0044e284);
            CrLogWrite(3,&DAT_0044e284,length);
            CrLogUnLock();
          }
        }
        else {
          controlJsonObj = json_object_object_get(logLevel,"control");
          if ((controlJsonObj == 0) ||
             (typeCheckResult = json_object_is_type(controlJsonObj,6), typeCheckResult == 0)) {
            controlJsonObj = GetLogLevel();
            if (controlJsonObj < 4) {
              CrLogLock();
              memset(&DAT_0044e284,0,0x800);
              snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) get control json fail\n","WARNING",
                       "main/server_cmd.c",0x84e);
              length = strlen(&DAT_0044e284);
              CrLogWrite(3,&DAT_0044e284,length);
              CrLogUnLock();
            }
          }
          else {
            controlString = (char *)json_object_get_string(controlJsonObj);
            functionPointerArray = &PTR_s_open_flow_0042f520;
            controlJsonObj = 0;
            do {
              typeCheckResult = strcmp(controlString,*functionPointerArray);
              if (typeCheckResult == 0) {
                (*(code *)functionPointerArray[1])(controlString,logLevel,dataProcessingResult);
              }
              controlJsonObj = controlJsonObj + 1;
              functionPointerArray = functionPointerArray + 2;
            } while (controlJsonObj != 0x22);
          }
          json_object_put(logLevel);
        }
        controlString = substringPtr + 1;
      }
      removeFromLinkedList(dataProcessingResult);
    }
    usleep(10000);
  } while( true );
}



undefined4 writeToFile(char *filename,void *data,size_t dataSize)

{
  FILE *fileStream;
  int logLevel;
  size_t length;
  
  fileStream = fopen(filename,"ab+");
  if (fileStream == (FILE *)0x0) {
    logLevel = GetLogLevel();
    if (logLevel < 4) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) Failed to open file %s\n","WARNING",
               "main/server_cmd.c",0x58,filename);
      length = strlen(&DAT_0044e284);
      CrLogWrite(3,&DAT_0044e284,length);
      CrLogUnLock();
    }
  }
  else {
    fwrite(data,1,dataSize,fileStream);
    fclose(fileStream);
  }
  return 0xffffffff;
}



undefined4 createAndSendJsonResponse(int connection,undefined4 controlCommand,undefined4 result)

{
  undefined4 jsonObject;
  undefined4 controlKey;
  char *jsonString;
  size_t jsonStringLength;
  void *memoryPtr;
  uint length;
  undefined auStack_20 [8];
  
  jsonObject = json_object_new_object();
  controlKey = json_object_new_string(controlCommand);
  json_object_object_add(jsonObject,"control",controlKey);
  json_object_object_add(jsonObject,"result",result);
  jsonString = (char *)json_object_to_json_string(jsonObject);
  jsonStringLength = strlen(jsonString);
  length = jsonStringLength & 0xffff;
  memoryPtr = memset(auStack_20 + -(length + 0xc & 0xfffffff8),0,length + 5);
  memoryPtr = memcpy(memoryPtr,jsonString,length);
  *(undefined *)((int)memoryPtr + length) = 3;
  sendData(connection,memoryPtr,length + 1);
  json_object_put(jsonObject);
  return 0;
}



void getLaserCorrection02mmResult(undefined4 param_1,undefined4 param_2,int *param_3)

{
  undefined4 resultCode;
  int tablePcPath;
  int scanPcPath;
  size_t length;
  int iVar1;
  char *scanPcPathStr;
  undefined4 resultValue;
  char *tablePcPathStr;
  undefined4 yOffset;
  undefined4 uStack_2c;
  undefined4 xOffset;
  undefined4 uStack_24;
  
  resultCode = json_object_new_object();
  tablePcPath = json_object_object_get(param_2,"table_pc_path");
  scanPcPath = json_object_object_get(param_2,"scan_pc_path");
  if ((((scanPcPath == 0) || (iVar1 = json_object_is_type(scanPcPath,6), iVar1 == 0)) ||
      (tablePcPath == 0)) || (iVar1 = json_object_is_type(tablePcPath,6), iVar1 == 0)) {
    tablePcPath = GetLogLevel();
    if (tablePcPath < 4) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetLaserCorrection02mmResult] Parameter error\n",
               "WARNING","main/server_cmd.c",0x7bd);
      length = strlen(&DAT_0044e284);
      CrLogWrite(3,&DAT_0044e284,length);
      CrLogUnLock();
    }
    resultValue = 0x67;
  }
  else {
    tablePcPathStr = (char *)json_object_get_string(tablePcPath);
    scanPcPathStr = (char *)json_object_get_string(scanPcPath);
    tablePcPath = GetLogLevel();
    if (tablePcPath < 3) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) table_pc_path=%s, scan_pc_path=%s",&DAT_0042dfc4,
               "main/server_cmd.c",0x7c5,tablePcPathStr,scanPcPathStr);
      length = strlen(&DAT_0044e284);
      CrLogWrite(2,&DAT_0044e284,length);
      CrLogUnLock();
    }
    tablePcPath = access(tablePcPathStr,0);
    resultValue = 0x66;
    if (tablePcPath == 0) {
      tablePcPath = access(scanPcPathStr,0);
      resultValue = 0x66;
      if (tablePcPath == 0) {
        xOffset = 0;
        uStack_24 = 0;
        yOffset = 0;
        uStack_2c = 0;
        tablePcPath = FUN_0040e61c(tablePcPathStr,scanPcPathStr,(undefined8 *)&xOffset,
                                   (undefined8 *)&yOffset);
        scanPcPath = GetLogLevel();
        if (scanPcPath < 3) {
          CrLogLock();
          memset(&DAT_0044e284,0,0x800);
          snprintf(&DAT_0044e284,0x800,
                   "[%s]-[%s](%d) [GetLaserCorrection02mmResult] ret = %d get_x_offset=%lf get_y_offset=%lf"
                   ,&DAT_0042dfc4,"main/server_cmd.c",0x7cd,tablePcPath);
          length = strlen(&DAT_0044e284);
          CrLogWrite(2,&DAT_0044e284,length);
          CrLogUnLock();
        }
        resultValue = 0x66;
        if (-1 < tablePcPath) {
          resultValue = json_object_new_int(0);
          json_object_object_add(resultCode,&DAT_0042e428,resultValue);
          resultValue = json_object_new_double(CONCAT44(uStack_24,xOffset));
          json_object_object_add(resultCode,"x_offset",resultValue);
          resultValue = json_object_new_double(CONCAT44(uStack_2c,yOffset));
          tablePcPathStr = "y_offset";
          goto LAB_00404f68;
        }
      }
    }
  }
  resultValue = json_object_new_int(resultValue);
  tablePcPathStr = "code";
LAB_00404f68:
  json_object_object_add(resultCode,tablePcPathStr,resultValue);
  createAndSendJsonResponse(*param_3,param_1,resultCode);
  return;
}



void getLaserOffsetCorrectionTowPoint(undefined4 param_1,undefined4 param_2,int *param_3)

{
  undefined4 resultCode;
  int pcExp1000;
  int pcExp2000;
  size_t length;
  undefined4 resultValue;
  int pointExp1000Len;
  uint uVar1;
  int pointExp2000Len;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  uint uVar6;
  uint uVar7;
  undefined4 *puVar8;
  undefined auStack_70 [16];
  float *local_60 [2];
  uint local_58 [4];
  float xOffset;
  float yOffset;
  undefined4 *pointExp1000;
  undefined *local_3c;
  uint local_38;
  undefined4 *local_34;
  int local_30;
  
  resultCode = json_object_new_object();
  pcExp1000 = json_object_object_get(param_2,"pcExp1000");
  pcExp2000 = json_object_object_get(param_2,"pcExp2000");
  if (((((pcExp1000 == 0) ||
        (pointExp1000Len = json_object_is_type(pcExp1000,5), pointExp1000Len == 0)) ||
       (pcExp2000 == 0)) ||
      ((pointExp1000Len = json_object_is_type(pcExp2000,5), pointExp1000Len == 0 ||
       (pointExp1000Len = json_object_array_length(pcExp1000), pointExp1000Len == 0)))) ||
     (pointExp1000Len = json_object_array_length(pcExp2000), pointExp1000Len == 0)) {
    pcExp1000 = GetLogLevel();
    if (pcExp1000 < 4) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      local_60[1] = (float *)0x6ec;
      local_60[0] = (float *)0x42e2c4;
      snprintf(&DAT_0044e284,0x800,
               "[%s]-[%s](%d) [GetLaserOffsetCorrectionTowPoint] Parameter error\n","WARNING");
      length = strlen(&DAT_0044e284);
      CrLogWrite(3,&DAT_0044e284,length);
      CrLogUnLock();
    }
    resultValue = json_object_new_int(0x67);
    json_object_object_add(resultCode,&DAT_0042e428,resultValue);
  }
  else {
    local_3c = auStack_70;
    uVar1 = json_object_array_length(pcExp1000);
    local_38 = uVar1 & 0xffff;
    pointExp1000Len = GetLogLevel();
    uVar1 = uVar1 & 0xffff;
    if (pointExp1000Len < 3) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      local_60[1] = (float *)0x6f2;
      local_60[0] = (float *)0x42e2c4;
      local_58[0] = uVar1;
      snprintf(&DAT_0044e284,0x800,
               "[%s]-[%s](%d) [GetLaserOffsetCorrectionTowPoint] pointExp1000_len=%d",&DAT_0042dfc4)
      ;
      length = strlen(&DAT_0044e284);
      CrLogWrite(2,&DAT_0044e284,length);
      CrLogUnLock();
    }
    pointExp1000Len = -(uVar1 * 0xc + 10 & 0xfffffff8);
    pointExp1000 = (undefined4 *)((int)local_58 + pointExp1000Len + 8);
    memset(pointExp1000,0,uVar1 * 0xc);
    for (uVar6 = 0; (uVar6 & 0xffff) < local_38; uVar6 = uVar6 + 1) {
      pointExp2000Len = json_object_array_get_idx(pcExp1000,uVar6);
      if ((pointExp2000Len != 0) &&
         (iVar3 = json_object_is_type(pointExp2000Len,5), puVar8 = pointExp1000, iVar3 != 0)) {
        iVar3 = 0;
        do {
          puVar2 = (undefined4 *)json_object_array_get_idx(pointExp2000Len,iVar3);
          if (puVar2 != (undefined4 *)0x0) {
            local_34 = puVar2;
            iVar4 = json_object_is_type(puVar2,3);
            if (iVar4 != 0) {
              resultValue = json_object_get_int(local_34);
              puVar8[uVar6 * 3 + iVar3] = resultValue;
            }
          }
          iVar3 = iVar3 + 1;
        } while (iVar3 != 3);
      }
    }
    uVar6 = json_object_array_length(pcExp2000);
    local_38 = uVar6 & 0xffff;
    pcExp1000 = GetLogLevel();
    uVar6 = uVar6 & 0xffff;
    if (pcExp1000 < 3) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      *(undefined4 *)((int)local_60 + pointExp1000Len + 4) = 0x707;
      *(uint *)((int)local_58 + pointExp1000Len) = uVar6;
      *(char **)((int)local_60 + pointExp1000Len) = "main/server_cmd.c";
      snprintf(&DAT_0044e284,0x800,
               "[%s]-[%s](%d) [GetLaserOffsetCorrectionTowPoint] pointExp2000_len=%d",&DAT_0042dfc4)
      ;
      length = strlen(&DAT_0044e284);
      CrLogWrite(2,&DAT_0044e284,length);
      CrLogUnLock();
    }
    pcExp1000 = -(uVar6 * 0xc + 10 & 0xfffffff8);
    puVar8 = (undefined4 *)((int)local_58 + pcExp1000 + pointExp1000Len + 8);
    memset(puVar8,0,uVar6 * 0xc);
    for (uVar7 = 0; (uVar7 & 0xffff) < local_38; uVar7 = uVar7 + 1) {
      pointExp2000Len = json_object_array_get_idx(pcExp2000,uVar7);
      if ((pointExp2000Len != 0) && (iVar3 = json_object_is_type(pointExp2000Len,5), iVar3 != 0)) {
        iVar3 = 0;
        local_34 = puVar8 + uVar7 * 3;
        do {
          iVar4 = json_object_array_get_idx(pointExp2000Len,iVar3);
          if (iVar4 != 0) {
            local_30 = iVar4;
            iVar4 = json_object_is_type(iVar4,3);
            if (iVar4 != 0) {
              resultValue = json_object_get_int(local_30);
              local_34[iVar3] = resultValue;
            }
          }
          iVar3 = iVar3 + 1;
        } while (iVar3 != 3);
      }
    }
    xOffset = 0.0;
    yOffset = 0.0;
    *(float **)((int)local_60 + pcExp1000 + pointExp1000Len) = &xOffset;
    pcExp2000 = FUN_0040d608(pointExp1000,uVar1,puVar8,uVar6,
                             *(float **)((int)local_60 + pcExp1000 + pointExp1000Len));
    pointExp2000Len = GetLogLevel();
    if (pointExp2000Len < 3) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      *(undefined4 *)((int)local_60 + pcExp1000 + pointExp1000Len + 4) = 0x71e;
      *(int *)((int)local_58 + pcExp1000 + pointExp1000Len) = pcExp2000;
      *(char **)((int)local_60 + pcExp1000 + pointExp1000Len) = "main/server_cmd.c";
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetLaserOffsetCorrectionTowPoint] ret = %d",
               &DAT_0042dfc4);
      length = strlen(&DAT_0044e284);
      CrLogWrite(2,&DAT_0044e284,length);
      CrLogUnLock();
    }
    if (pcExp2000 < 0) {
      resultValue = json_object_new_int(0x66);
      pcVar5 = "code";
    }
    else {
      resultValue = json_object_new_int(0);
      json_object_object_add(resultCode,&DAT_0042e428,resultValue);
      resultValue = json_object_new_double((double)xOffset);
      json_object_object_add(resultCode,"x_offset",resultValue);
      resultValue = json_object_new_double((double)yOffset);
      pcVar5 = "y_offset";
    }
    json_object_object_add(resultCode,pcVar5,resultValue);
  }
  createAndSendJsonResponse(*param_3,param_1,resultCode);
  return;
}



void getFirstFloorDetectionInfo(undefined4 param_1,undefined4 param_2,int *param_3)

{
  undefined4 jsonObject;
  int scan1path;
  int scan2path;
  int gcodePath;
  size_t length;
  int logLevel;
  char *tableName;
  char *scanPath;
  undefined4 resultCode;
  char *resultCodeKey;
  undefined4 local_30 [3];
  
  jsonObject = json_object_new_object();
  scan1path = json_object_object_get(param_2,"scan1_path");
  scan2path = json_object_object_get(param_2,"scan2_path");
  gcodePath = json_object_object_get(param_2,"gcode_path");
  if (((((scan2path == 0) || (logLevel = json_object_is_type(scan2path,6), logLevel == 0)) ||
       (scan1path == 0)) ||
      ((logLevel = json_object_is_type(scan1path,6), logLevel == 0 || (gcodePath == 0)))) ||
     (logLevel = json_object_is_type(gcodePath,6), logLevel == 0)) {
    scan1path = GetLogLevel();
    if (scan1path < 4) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetFirstFloorDetectNew] Parameter error\n",
               "WARNING","main/server_cmd.c",0x76a);
      length = strlen(&DAT_0044e284);
      CrLogWrite(3,&DAT_0044e284,length);
      CrLogUnLock();
    }
    resultCode = 0x67;
  }
  else {
    resultCodeKey = (char *)json_object_get_string(scan1path);
    tableName = (char *)json_object_get_string(scan2path);
    scanPath = (char *)json_object_get_string(gcodePath);
    scan1path = GetLogLevel();
    if (scan1path < 3) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,
               "[%s]-[%s](%d) [GetFirstFloorDetectNew] table_path=%s, scan_path=%s, gcode_path",
               &DAT_0042dfc4,"main/server_cmd.c",0x772,resultCodeKey,tableName,scanPath);
      length = strlen(&DAT_0044e284);
      CrLogWrite(2,&DAT_0044e284,length);
      CrLogUnLock();
    }
    scan1path = access(resultCodeKey,0);
    if (((scan1path == 0) && (scan1path = access(tableName,0), scan1path == 0)) &&
       (scan1path = access(scanPath,0), scan1path == 0)) {
      local_30[0] = 0xffffffff;
      scan1path = FUN_0040e03c(resultCodeKey,tableName,scanPath,local_30);
      scan2path = GetLogLevel();
      if (scan2path < 3) {
        CrLogLock();
        memset(&DAT_0044e284,0,0x800);
        snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetFirstFloorDetectNew] ret = %d ,result = %d",
                 &DAT_0042dfc4,"main/server_cmd.c",0x778,scan1path,local_30[0]);
        length = strlen(&DAT_0044e284);
        CrLogWrite(2,&DAT_0044e284,length);
        CrLogUnLock();
      }
      resultCode = 0x66;
      if (-1 < scan1path) {
        resultCode = json_object_new_int(0);
        json_object_object_add(jsonObject,&DAT_0042e428,resultCode);
        resultCode = json_object_new_int(local_30[0]);
        resultCodeKey = "result";
        goto LAB_00405d20;
      }
    }
    else {
      scan1path = GetLogLevel();
      if (scan1path < 4) {
        CrLogLock();
        memset(&DAT_0044e284,0,0x800);
        snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetFirstFloorDetectNew] File not exist\n",
                 "WARNING","main/server_cmd.c",0x781);
        length = strlen(&DAT_0044e284);
        CrLogWrite(3,&DAT_0044e284,length);
        CrLogUnLock();
      }
      resultCode = 0x66;
    }
  }
  resultCode = json_object_new_int(resultCode);
  resultCodeKey = "code";
LAB_00405d20:
  json_object_object_add(jsonObject,resultCodeKey,resultCode);
  createAndSendJsonResponse(*param_3,param_1,jsonObject);
  return;
}



void getLaserOffsetCorrection(undefined4 param_1,undefined4 param_2,int *param_3)

{
  double dVar1;
  undefined4 resultCode;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  size_t sVar6;
  undefined4 uVar7;
  int iVar8;
  uint uVar9;
  undefined4 *puVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  char *pcVar14;
  uint uVar15;
  double dVar16;
  undefined auStack_88 [16];
  char *local_78;
  float local_74;
  float *local_70 [4];
  float xOffset;
  float yOffset;
  float confidence;
  undefined4 *tablePointArray;
  undefined4 *scanPointArray;
  float *local_48;
  undefined *local_44;
  undefined4 *local_40;
  undefined4 *local_3c;
  int local_38;
  
  resultCode = json_object_new_object();
  iVar2 = json_object_object_get(param_2,"table_point");
  iVar3 = json_object_object_get(param_2,"scan_point");
  iVar4 = json_object_object_get(param_2,"local_cx");
  iVar5 = json_object_object_get(param_2,"local_cy");
  if ((((((iVar2 == 0) || (iVar8 = json_object_is_type(iVar2,5), iVar8 == 0)) || (iVar3 == 0)) ||
       ((iVar8 = json_object_is_type(iVar3,5), iVar8 == 0 || (iVar4 == 0)))) ||
      ((iVar8 = json_object_is_type(iVar4,2), iVar8 == 0 ||
       ((iVar5 == 0 || (iVar8 = json_object_is_type(iVar5,2), iVar8 == 0)))))) ||
     ((iVar8 = json_object_array_length(iVar3), iVar8 == 0 ||
      (iVar8 = json_object_array_length(iVar2), iVar8 == 0)))) {
    iVar2 = GetLogLevel();
    if (iVar2 < 4) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      local_74 = 2.356984e-42;
      local_78 = "main/server_cmd.c";
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetLaserOffsetCorrectionNew] Parameter error\n",
               "WARNING");
      sVar6 = strlen(&DAT_0044e284);
      CrLogWrite(3,&DAT_0044e284,sVar6);
      CrLogUnLock();
    }
    uVar7 = json_object_new_int(0x67);
    json_object_object_add(resultCode,&DAT_0042e428,uVar7);
  }
  else {
    local_44 = auStack_88;
    uVar9 = json_object_array_length(iVar2);
    scanPointArray = (undefined4 *)(uVar9 & 0xffff);
    iVar8 = GetLogLevel();
    local_48 = (float *)(uVar9 & 0xffff);
    if (iVar8 < 3) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      local_70[0] = local_48;
      local_74 = 2.366793e-42;
      local_78 = "main/server_cmd.c";
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetLaserOffsetCorrectionNew] table_point_len=%d",
               &DAT_0042dfc4);
      sVar6 = strlen(&DAT_0044e284);
      CrLogWrite(2,&DAT_0044e284,sVar6);
      CrLogUnLock();
    }
    iVar8 = -((int)local_48 * 0xc + 10U & 0xfffffff8);
    tablePointArray = (undefined4 *)((int)local_70 + iVar8 + 8);
    memset(tablePointArray,0,(int)local_48 * 0xc);
    for (uVar9 = 0; (uVar9 & 0xffff) < scanPointArray; uVar9 = uVar9 + 1) {
      iVar11 = json_object_array_get_idx(iVar2,uVar9);
      if (iVar11 != 0) {
        iVar12 = json_object_is_type(iVar11,5);
        if (iVar12 != 0) {
          iVar12 = 0;
          local_40 = tablePointArray + uVar9 * 3;
          do {
            puVar10 = (undefined4 *)json_object_array_get_idx(iVar11,iVar12);
            if (puVar10 != (undefined4 *)0x0) {
              local_3c = puVar10;
              iVar13 = json_object_is_type(puVar10,3);
              if (iVar13 != 0) {
                uVar7 = json_object_get_int(local_3c);
                local_40[iVar12] = uVar7;
              }
            }
            iVar12 = iVar12 + 1;
          } while (iVar12 != 3);
        }
      }
    }
    uVar9 = json_object_array_length(iVar3);
    local_40 = (undefined4 *)(uVar9 & 0xffff);
    iVar2 = GetLogLevel();
    uVar9 = uVar9 & 0xffff;
    if (iVar2 < 3) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      *(undefined4 *)((int)&local_74 + iVar8) = 0x6af;
      *(uint *)((int)local_70 + iVar8) = uVar9;
      *(char **)((int)&local_78 + iVar8) = "main/server_cmd.c";
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetLaserOffsetCorrectionNew] scan_point_len=%d",
               &DAT_0042dfc4);
      sVar6 = strlen(&DAT_0044e284);
      CrLogWrite(2,&DAT_0044e284,sVar6);
      CrLogUnLock();
    }
    iVar2 = -(uVar9 * 0xc + 10 & 0xfffffff8);
    scanPointArray = (undefined4 *)((int)local_70 + iVar2 + iVar8 + 8);
    memset(scanPointArray,0,uVar9 * 0xc);
    for (uVar15 = 0; (undefined4 *)(uVar15 & 0xffff) < local_40; uVar15 = uVar15 + 1) {
      iVar11 = json_object_array_get_idx(iVar3,uVar15);
      if (iVar11 != 0) {
        iVar12 = json_object_is_type(iVar11,5);
        if (iVar12 != 0) {
          iVar12 = 0;
          local_3c = scanPointArray + uVar15 * 3;
          do {
            iVar13 = json_object_array_get_idx(iVar11,iVar12);
            if (iVar13 != 0) {
              local_38 = iVar13;
              iVar13 = json_object_is_type(iVar13,3);
              if (iVar13 != 0) {
                uVar7 = json_object_get_int(local_38);
                local_3c[iVar12] = uVar7;
              }
            }
            iVar12 = iVar12 + 1;
          } while (iVar12 != 3);
        }
      }
    }
    dVar16 = (double)json_object_get_double(iVar4);
    dVar1 = (double)json_object_get_double(iVar5);
    xOffset = 0.0;
    yOffset = 0.0;
    confidence = 0.0;
    *(float *)((int)&local_74 + iVar2 + iVar8) = (float)dVar1;
    *(float **)((int)local_70 + iVar2 + iVar8) = &xOffset;
    *(float *)((int)&local_78 + iVar2 + iVar8) = (float)dVar16;
    iVar3 = FUN_0040cf84(tablePointArray,(int)local_48,scanPointArray,uVar9,
                         *(undefined4 *)((int)&local_78 + iVar2 + iVar8),
                         *(undefined4 *)((int)&local_74 + iVar2 + iVar8),
                         *(float **)((int)local_70 + iVar2 + iVar8));
    iVar4 = GetLogLevel();
    if (iVar4 < 3) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      *(undefined4 *)((int)&local_74 + iVar2 + iVar8) = 0x6ca;
      *(int *)((int)local_70 + iVar2 + iVar8) = iVar3;
      *(char **)((int)&local_78 + iVar2 + iVar8) = "main/server_cmd.c";
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) [GetLaserOffsetCorrectionNew] ret = %d",
               &DAT_0042dfc4);
      sVar6 = strlen(&DAT_0044e284);
      CrLogWrite(2,&DAT_0044e284,sVar6);
      CrLogUnLock();
    }
    if (iVar3 < 0) {
      uVar7 = json_object_new_int(0x66);
      pcVar14 = "code";
    }
    else {
      uVar7 = json_object_new_int(0);
      json_object_object_add(resultCode,&DAT_0042e428,uVar7);
      uVar7 = json_object_new_double((double)xOffset);
      json_object_object_add(resultCode,"x_offset",uVar7);
      uVar7 = json_object_new_double((double)yOffset);
      json_object_object_add(resultCode,"y_offset",uVar7);
      uVar7 = json_object_new_double((double)confidence);
      pcVar14 = "confidence";
    }
    json_object_object_add(resultCode,pcVar14,uVar7);
  }
  createAndSendJsonResponse(*param_3,param_1,resultCode);
  return;
}



void processJsonResponse(undefined4 param_1,undefined4 param_2,int *param_3)

{
  undefined uVar1;
  int iVar2;
  undefined4 resultCode;
  undefined4 resultValue;
  int iVar3;
  char resultChar;
  char local_80 [108];
  
  iVar2 = FUN_00412300();
  resultChar = 'e';
  if (iVar2 != 0) {
    iVar2 = json_object_object_get(param_2,&DAT_0042eea8);
    if ((iVar2 == 0) || (iVar3 = json_object_is_type(iVar2,3), iVar3 == 0)) {
      resultChar = 'g';
    }
    else {
      memset(local_80,0,100);
      uVar1 = json_object_get_int(iVar2);
      iVar2 = FUN_00410368(local_80,100,uVar1);
      if (((iVar2 < 0) || (resultChar = '\0', local_80[0] != '\0')) &&
         (resultChar = 'f', local_80[0] != '\0')) {
        resultChar = local_80[0];
      }
    }
  }
  resultCode = json_object_new_object();
  resultValue = json_object_new_int(resultChar);
  json_object_object_add(resultCode,&DAT_0042e428,resultValue);
  createAndSendJsonResponse(*param_3,param_1,resultCode);
  return;
}



// needs var names

void processJsonLines(undefined4 param_1,undefined4 param_2,int *param_3)

{
  double dVar1;
  ushort uVar2;
  undefined4 result;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  size_t sVar8;
  undefined4 uVar9;
  int iVar10;
  uint uVar11;
  int iVar12;
  char *pcVar13;
  void *destination;
  void *destination_00;
  uint uVar14;
  undefined auStack_b0 [16];
  char *local_a0;
  uint local_9c;
  char *local_98;
  uint local_94;
  uint local_90;
  float afStack_88 [2];
  undefined auStack_80 [64];
  void *local_40;
  uint local_3c;
  uint local_38;
  undefined *local_34;
  int local_30;
  
  result = json_object_new_object();
  iVar3 = json_object_object_get(param_2,"line1");
  uVar4 = json_object_array_length(iVar3);
  iVar5 = json_object_object_get(param_2,"line2");
  uVar6 = json_object_array_length(iVar5);
  iVar7 = json_object_object_get(param_2,"line3");
  uVar2 = json_object_array_length(iVar7);
  if ((((iVar3 != 0) && (iVar10 = json_object_is_type(iVar3,5), iVar10 != 0)) && (iVar5 != 0)) &&
     ((iVar10 = json_object_is_type(iVar5,5), iVar10 != 0 && (iVar7 != 0)))) {
    iVar10 = json_object_is_type(iVar7,5);
    uVar14 = uVar4 & 0xffff;
    if (((iVar10 != 0) &&
        ((uVar11 = uVar6 & 0xffff, uVar14 != 0 && (local_38 = uVar11, uVar11 != 0)))) &&
       (uVar2 != 0)) {
      sVar8 = (uVar4 & 0xffff) * 4;
      iVar10 = -(sVar8 + 10 & 0xfffffff8);
      local_40 = (void *)((int)afStack_88 + iVar10);
      uVar11 = 0;
      local_3c = uVar4 & 0xffff;
      local_34 = auStack_b0;
      memset(local_40,0,sVar8);
      do {
        iVar12 = json_object_array_get_idx(iVar3,uVar11);
        if (iVar12 != 0) {
          local_30 = iVar12;
          iVar12 = json_object_is_type(iVar12,2);
          if (iVar12 != 0) {
            dVar1 = (double)json_object_get_double(local_30);
            *(float *)(uVar11 * 4 + (int)local_40) = (float)dVar1;
          }
        }
        uVar11 = uVar11 + 1;
      } while ((uVar11 & 0xffff) < uVar14);
      sVar8 = (uVar6 & 0xffff) * 4;
      iVar3 = -(sVar8 + 10 & 0xfffffff8);
      destination = (void *)((int)afStack_88 + iVar3 + iVar10);
      uVar4 = 0;
      memset(destination,0,sVar8);
      do {
        iVar12 = json_object_array_get_idx(iVar5,uVar4);
        if (iVar12 != 0) {
          local_30 = iVar12;
          iVar12 = json_object_is_type(iVar12,2);
          if (iVar12 != 0) {
            dVar1 = (double)json_object_get_double(local_30);
            *(float *)(uVar4 * 4 + (int)destination) = (float)dVar1;
          }
        }
        uVar4 = uVar4 + 1;
      } while ((uVar4 & 0xffff) < local_38);
      sVar8 = (uint)uVar2 * 4;
      iVar5 = -(sVar8 + 10 & 0xfffffff8);
      destination_00 = (void *)((int)afStack_88 + iVar5 + iVar3 + iVar10);
      uVar4 = 0;
      memset(destination_00,0,sVar8);
      do {
        uVar11 = json_object_array_get_idx(iVar7,uVar4);
        if (uVar11 != 0) {
          local_38 = uVar11;
          iVar12 = json_object_is_type(uVar11,2);
          if (iVar12 != 0) {
            dVar1 = (double)json_object_get_double(local_38);
            *(float *)(uVar4 * 4 + (int)destination_00) = (float)dVar1;
          }
        }
        uVar4 = uVar4 + 1;
      } while ((uVar4 & 0xffff) < uVar14);
      memset(auStack_80,0,0x40);
      *(uint *)((int)&local_9c + iVar5 + iVar3 + iVar10) = (uint)uVar2;
      *(undefined **)((int)&local_98 + iVar5 + iVar3 + iVar10) = auStack_80;
      *(void **)((int)&local_a0 + iVar5 + iVar3 + iVar10) = destination_00;
      iVar3 = getSelectLineFromAi(local_40,local_3c,destination,uVar6 & 0xffff,
                                  *(undefined4 *)((int)&local_a0 + iVar5 + iVar3 + iVar10),
                                  *(int *)((int)&local_9c + iVar5 + iVar3 + iVar10),
                                  *(char **)((int)&local_98 + iVar5 + iVar3 + iVar10));
      if (iVar3 < 0) {
        uVar9 = json_object_new_int(0x67);
        pcVar13 = "code";
      }
      else {
        uVar9 = json_object_new_int(0);
        json_object_object_add(result,&DAT_0042e428,uVar9);
        uVar9 = json_object_new_string(auStack_80);
        pcVar13 = "best_line";
      }
      json_object_object_add(result,pcVar13,uVar9);
      goto LAB_0040871c;
    }
  }
  iVar3 = GetLogLevel();
  if (iVar3 < 3) {
    CrLogLock();
    memset(&DAT_0044e284,0,0x800);
    local_9c = 0x326;
    local_90 = (uint)uVar2;
    local_94 = uVar6 & 0xffff;
    local_98 = (char *)(uVar4 & 0xffff);
    local_a0 = "main/server_cmd.c";
    snprintf(&DAT_0044e284,0x800,
             "[%s]-[%s](%d) [GetSelectLine]line1_len=%d, line2_len=%d, line3_len=%d\n",&DAT_0042dfc4
            );
    sVar8 = strlen(&DAT_0044e284);
    CrLogWrite(2,&DAT_0044e284,sVar8);
    CrLogUnLock();
  }
  uVar9 = json_object_new_int(0x67);
  json_object_object_add(result,&DAT_0042e428,uVar9);
LAB_0040871c:
  createAndSendJsonResponse(*param_3,param_1,result);
  return;
}



void getLaserStatus(undefined4 param_1,undefined4 param_2,int *param_3)

{
  int iVar1;
  undefined4 result;
  undefined4 uVar2;
  char cVar3;
  char local_80 [108];
  
  iVar1 = FUN_00412300();
  cVar3 = 'e';
  if (iVar1 != 0) {
    memset(local_80,0,100);
    iVar1 = FUN_0040ffe4(local_80,100);
    if (((iVar1 < 0) || (cVar3 = '\0', local_80[0] != '\0')) && (cVar3 = 'f', local_80[0] != '\0'))
    {
      cVar3 = local_80[0];
    }
  }
  result = json_object_new_object();
  uVar2 = json_object_new_int(cVar3);
  json_object_object_add(result,&DAT_0042e428,uVar2);
  createAndSendJsonResponse(*param_3,param_1,result);
  return;
}



void controlAndLogLaserStatus(undefined4 param_1,undefined4 param_2,int *param_3)

{
  int laserStatus;
  size_t logMessageLength;
  undefined4 jsonResponse;
  undefined4 logLevel;
  char cVar1;
  char logMessage [108];
  
  laserStatus = FUN_00412300();
  cVar1 = 'e';
  if (laserStatus != 0) {
    memset(logMessage,0,100);
    laserStatus = FUN_0040ffac(logMessage,100);
    if ((laserStatus < 0) || (logMessage[0] != '\0')) {
      cVar1 = logMessage[0];
      if (logMessage[0] == '\0') {
        cVar1 = 'f';
      }
      laserStatus = GetLogLevel();
      if (3 < laserStatus) goto LAB_004096b8;
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) set laser close fail!!\n","WARNING",
               "main/server_cmd.c",0x1cc);
      logMessageLength = strlen(&DAT_0044e284);
      logLevel = 3;
    }
    else {
      cVar1 = '\0';
      laserStatus = GetLogLevel();
      if (2 < laserStatus) goto LAB_004096b8;
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) set laser close success!!\n",&DAT_0042dfc4,
               "main/server_cmd.c",0x1ce);
      logMessageLength = strlen(&DAT_0044e284);
      logLevel = 2;
    }
    CrLogWrite(logLevel,&DAT_0044e284,logMessageLength);
    CrLogUnLock();
  }
LAB_004096b8:
  logLevel = json_object_new_object();
  jsonResponse = json_object_new_int(cVar1);
  json_object_object_add(logLevel,&DAT_0042e428,jsonResponse);
  createAndSendJsonResponse(*param_3,param_1,logLevel);
  return;
}



void processLogLevel(undefined4 param_1,undefined4 param_2,int *param_3)

{
  undefined4 resultCode;
  int logLevel;
  undefined4 levelValue;
  undefined local_78 [104];
  
  resultCode = json_object_new_object();
  logLevel = FUN_00412300();
  levelValue = 0x65;
  if (logLevel != 0) {
    memset(local_78,0,100);
    logLevel = FUN_0040ff14(local_78,100);
    levelValue = 0x66;
    if (-1 < logLevel) {
      levelValue = json_object_new_int(local_78[0]);
      json_object_object_add(resultCode,"level",levelValue);
      levelValue = 0;
    }
  }
  levelValue = json_object_new_int(levelValue);
  json_object_object_add(resultCode,&DAT_0042e428,levelValue);
  createAndSendJsonResponse(*param_3,param_1,resultCode);
  return;
}



void processSetLogLevel(undefined4 param_1,undefined4 param_2,int *param_3)

{
  byte bVar1;
  int logLevel;
  undefined4 resultCode;
  undefined4 resultValue;
  int jsonLevel;
  size_t logMessageLen;
  char resultChar;
  char local_80 [104];
  
  logLevel = FUN_00412300();
  resultChar = 'e';
  if (logLevel != 0) {
    logLevel = json_object_object_get(param_2,"level");
    if ((logLevel == 0) || (jsonLevel = json_object_is_type(logLevel,3), jsonLevel == 0)) {
      resultChar = 'g';
    }
    else {
      memset(local_80,0,100);
      bVar1 = json_object_get_int(logLevel);
      jsonLevel = FUN_0040fed8(local_80,100,bVar1);
      if ((jsonLevel < 0) || (local_80[0] != '\0')) {
        resultChar = local_80[0];
        if (local_80[0] == '\0') {
          resultChar = 'f';
        }
      }
      else {
        jsonLevel = GetLogLevel();
        resultChar = '\0';
        if (jsonLevel < 3) {
          CrLogLock();
          memset(&DAT_0044e284,0,0x800);
          resultCode = json_object_get_int(logLevel);
          snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) SetPointCloudLevel =%d\n",&DAT_0042dfc4,
                   "main/server_cmd.c",0x161,resultCode);
          logMessageLen = strlen(&DAT_0044e284);
          CrLogWrite(2,&DAT_0044e284,logMessageLen);
          CrLogUnLock();
        }
      }
    }
  }
  resultCode = json_object_new_object();
  resultValue = json_object_new_int(resultChar);
  json_object_object_add(resultCode,&DAT_0042e428,resultValue);
  createAndSendJsonResponse(*param_3,param_1,resultCode);
  return;
}



void processOpenFlowStatus(undefined4 param_1,undefined4 param_2,int *param_3)

{
  int logLevel;
  size_t logMessageLen;
  undefined4 resultCode;
  undefined4 resultValue;
  char resultChar;
  char local_80 [108];
  
  logLevel = FUN_00412300();
  resultChar = 'e';
  if (logLevel != 0) {
    memset(local_80,0,100);
    logLevel = FUN_0040fdb0(local_80,100);
    if ((logLevel < 0) || (local_80[0] != '\0')) {
      resultChar = local_80[0];
      if (local_80[0] == '\0') {
        resultChar = 'f';
      }
      logLevel = GetLogLevel();
      if (3 < logLevel) goto LAB_0040a4b0;
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) open flow fail!!\n","WARNING","main/server_cmd.c",
               0x91);
      logMessageLen = strlen(&DAT_0044e284);
      resultValue = 3;
    }
    else {
      resultChar = '\0';
      logLevel = GetLogLevel();
      if (2 < logLevel) goto LAB_0040a4b0;
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) open flow success!!\n",&DAT_0042dfc4,
               "main/server_cmd.c",0x93);
      logMessageLen = strlen(&DAT_0044e284);
      resultValue = 2;
    }
    CrLogWrite(resultValue,&DAT_0044e284,logMessageLen);
    CrLogUnLock();
  }
LAB_0040a4b0:
  resultValue = json_object_new_object();
  resultCode = json_object_new_int(resultChar);
  json_object_object_add(resultValue,&DAT_0042e428,resultCode);
  createAndSendJsonResponse(*param_3,param_1,resultValue);
  return;
}



int createPThreadForDataProcessing(void)

{
  int threadCreationResult;
  int logLevel;
  size_t logMessageLength;
  
  threadCreationResult =
       pthread_create(&DAT_0044e280,(pthread_attr_t *)0x0,processReceivedData,(void *)0x0);
  if (threadCreationResult != 0) {
    threadCreationResult = -1;
    logLevel = GetLogLevel();
    if (logLevel < 4) {
      CrLogLock();
      memset(&DAT_0044e284,0,0x800);
      snprintf(&DAT_0044e284,0x800,"[%s]-[%s](%d) create pthread error!\n","WARNING",
               "main/server_cmd.c",0x877);
      logMessageLength = strlen(&DAT_0044e284);
      CrLogWrite(3,&DAT_0044e284,logMessageLength);
      CrLogUnLock();
    }
  }
  return threadCreationResult;
}



// no clue this is just a guess

undefined4 cleanupAndShutdown(void)

{
  pthread_cancel(DAT_0044e280);
  DAT_0044e280 = 0xffffffff;
  FUN_0040ec08();
  cancelThread();
  return 0;
}



// WARNING: Removing unreachable block (ram,0x0040ab14)
// WARNING: Removing unreachable block (ram,0x0040a9b4)
// WARNING: Removing unreachable block (ram,0x0040a9fc)
// WARNING: Removing unreachable block (ram,0x0040b064)
// WARNING: Removing unreachable block (ram,0x0040b13c)

undefined4 initializeServer(void)

{
  int socket_fd;
  int *errno_ptr;
  size_t recv_size;
  int bind_result;
  size_t *client_fds;
  void *destination;
  __fd_mask *fd_mask_ptr;
  size_t max_fd;
  size_t client_fd;
  undefined4 result;
  uint select_result;
  char *log_msg;
  size_t *client_fds_ptr;
  int client_sock_fd;
  __fd_mask read_fds [1024];
  fd_set read_fd_set;
  sockaddr server_address [7];
  timeval timeout;
  undefined *local_40;
  undefined *local_3c;
  undefined *local_38;
  size_t local_34;
  char *local_30;
  size_t local_2c;
  
  pthread_rwlock_init((pthread_rwlock_t *)&DAT_0044ea94,(pthread_rwlockattr_t *)0x0);
  DAT_0044eab4 = &DAT_0044eab4;
  DAT_0044eab8 = &DAT_0044eab4;
  unlink("/tmp/ai_server_uds");
  server_address[0].sa_family = 1;
  strcpy(server_address[0].sa_data,"/tmp/ai_server_uds");
  socket_fd = socket(1,2,0);
  local_40 = &DAT_00450000;
  local_3c = &DAT_00450000;
  local_38 = &DAT_00450000;
  DAT_0044d890 = socket_fd;
  if (socket_fd == -1) {
    socket_fd = GetLogLevel();
    if (3 < socket_fd) {
      return 0xffffffff;
    }
    CrLogLock();
    memset(&DAT_0044eae4,0,0x800);
    errno_ptr = __errno_location();
    strerror(*errno_ptr);
    log_msg = "[%s]-[%s](%d) create socket error %s";
  }
  else {
    bind_result = bind(socket_fd,server_address,0x6e);
    if (bind_result == -1) {
      socket_fd = GetLogLevel();
      if (3 < socket_fd) {
        return 0xffffffff;
      }
      CrLogLock();
      memset(&DAT_0044eae4,0,0x800);
      errno_ptr = __errno_location();
      strerror(*errno_ptr);
      log_msg = "[%s]-[%s](%d) remote debug bind error %s";
    }
    else {
      socket_fd = listen(socket_fd,5);
      if (socket_fd != -1) {
        fd_mask_ptr = read_fd_set.fds_bits;
        socket_fd = 0;
        do {
          socket_fd = socket_fd + 1;
          *fd_mask_ptr = 0;
          fd_mask_ptr = fd_mask_ptr + 1;
        } while (socket_fd != 0x20);
        recv_size = 0xffffffff;
        do {
          while( true ) {
            client_fds_ptr = &DAT_0044eabc;
            max_fd = *(size_t *)(local_38 + -0x2770);
            client_fd = max_fd + 0x1f;
            if (-1 < (int)max_fd) {
              client_fd = max_fd;
            }
            read_fd_set.fds_bits[(int)client_fd >> 5] =
                 1 << ((int)max_fd % 0x20 & 0x1fU) | read_fd_set.fds_bits[(int)client_fd >> 5];
            if ((int)recv_size < (int)max_fd) {
              recv_size = max_fd;
            }
            socket_fd = 0;
            client_fds = client_fds_ptr;
            do {
              client_fd = *client_fds;
              if (client_fd != 0) {
                max_fd = client_fd + 0x1f;
                if (-1 < (int)client_fd) {
                  max_fd = client_fd;
                }
                read_fd_set.fds_bits[(int)max_fd >> 5] =
                     1 << ((int)client_fd % 0x20 & 0x1fU) | read_fd_set.fds_bits[(int)max_fd >> 5];
                if ((int)recv_size < (int)client_fd) {
                  recv_size = client_fd;
                }
              }
              socket_fd = socket_fd + 1;
              client_fds = client_fds + 1;
            } while (socket_fd != 10);
            socket_fd = select(recv_size + 1,&read_fd_set,(fd_set *)0x0,(fd_set *)0x0,(timeval *)0x0
                              );
            if (-1 < socket_fd) break;
            socket_fd = GetLogLevel();
            if (socket_fd < 4) {
              CrLogLock();
              memset(&DAT_0044eae4,0,0x800);
              snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) remote debug select fail","WARNING");
              client_fd = strlen(&DAT_0044eae4);
              CrLogWrite(3,&DAT_0044eae4,client_fd);
              CrLogUnLock();
            }
          }
          bind_result = *(int *)(local_38 + -0x2770);
          socket_fd = bind_result + 0x1f;
          if (-1 < bind_result) {
            socket_fd = bind_result;
          }
          if ((1 << (bind_result % 0x20 & 0x1fU) & read_fd_set.fds_bits[socket_fd >> 5]) != 0) {
            read_fds[0] = 0x6e;
            socket_fd = accept(bind_result,(sockaddr *)&stack0xffafeec8,(socklen_t *)read_fds);
            bind_result = GetLogLevel();
            if (bind_result < 3) {
              CrLogLock();
              memset(&DAT_0044eae4,0,0x800);
              snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) new connection clientSockFd = %d\n",
                       &DAT_0042dfc4);
              client_fd = strlen(&DAT_0044eae4);
              CrLogWrite(2,&DAT_0044eae4,client_fd);
              CrLogUnLock();
            }
            if (0 < socket_fd) {
              client_fds = client_fds_ptr;
              bind_result = 0;
              do {
                client_sock_fd = bind_result + 1;
                if (*client_fds == 0) {
                  (&DAT_0044eabc)[bind_result] = socket_fd;
                  socket_fd = GetLogLevel();
                  if (2 < socket_fd) goto LAB_0040ac84;
                  CrLogLock();
                  memset(&DAT_0044eae4,0,0x800);
                  snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) new client (%d) join success\n",
                           &DAT_0042dfc4);
                  client_fd = strlen(&DAT_0044eae4);
                  result = 2;
                  goto LAB_0040ac70;
                }
                client_fds = client_fds + 1;
                bind_result = client_sock_fd;
              } while (client_sock_fd != 10);
              send(socket_fd,
                   "The number of clients joined by the server has reached the maximum value and cannot join!\n"
                   ,0x5a,0);
              socket_fd = GetLogLevel();
              if (socket_fd < 4) {
                CrLogLock();
                memset(&DAT_0044eae4,0,0x800);
                snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) client connec max, new client join fail"
                         ,"WARNING");
                client_fd = strlen(&DAT_0044eae4);
                result = 3;
LAB_0040ac70:
                CrLogWrite(result,&DAT_0044eae4,client_fd);
                CrLogUnLock();
              }
            }
          }
LAB_0040ac84:
          socket_fd = 0;
          local_30 = "FuseFromAi offset=[%f,%f]\n";
          do {
            select_result = *client_fds_ptr;
            if ((0 < (int)select_result) &&
               ((1 << (select_result & 0x1f) & read_fd_set.fds_bits[(int)select_result >> 5]) != 0))
            {
              memset(&stack0xffafeec8,0,0x500000);
              select_result = 0;
              do {
                do {
                  memset(read_fds,0,0x1000);
                  client_fd = recv(*client_fds_ptr,read_fds,0x1000,0);
                  if ((int)client_fd < 1) {
                    if (client_fd != 0) {
                      bind_result = GetLogLevel();
                      if (3 < bind_result) goto LAB_0040af40;
                      CrLogLock();
                      memset(&DAT_0044eae4,0,0x800);
                      snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) client (%d) recv fail\n","WARNING"
                              );
                      goto LAB_0040b1e8;
                    }
                    max_fd = *client_fds_ptr;
                    *client_fds_ptr = 0;
                    client_fd = max_fd + 0x1f;
                    if (-1 < (int)max_fd) {
                      client_fd = max_fd;
                    }
                    read_fd_set.fds_bits[(int)client_fd >> 5] =
                         ~(1 << ((int)max_fd % 0x20 & 0x1fU)) &
                         read_fd_set.fds_bits[(int)client_fd >> 5];
                    bind_result = GetLogLevel();
                    if (2 < bind_result) goto LAB_0040af40;
                    CrLogLock();
                    memset(&DAT_0044eae4,0,0x800);
                    snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) client (%d) exit\n",
                             local_30 + -0x203c);
                    client_fd = strlen(&DAT_0044eae4);
                    result = 2;
                    goto LAB_0040b1fc;
                  }
                  local_34 = client_fd;
                  memcpy(&stack0xffafeec8 + select_result,read_fds,client_fd);
                  select_result = select_result + local_34;
                  if ((&stack0xffafeec7)[select_result] == '\x03') {
                    local_34 = *client_fds_ptr;
                    client_fds = (size_t *)malloc(0x14);
                    if (client_fds != (size_t *)0x0) {
                      *client_fds = 0;
                      client_fds[1] = 0;
                      client_fds[2] = 0;
                      client_fds[3] = 0;
                      client_fds[4] = 0;
                      local_2c = (select_result & 0xffff) + 5;
                      destination = malloc(local_2c);
                      client_fds[1] = (size_t)destination;
                      if (destination == (void *)0x0) {
                        bind_result = GetLogLevel();
                        if (bind_result < 4) {
                          CrLogLock();
                          memset(&DAT_0044eae4,0,0x800);
                          snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) Unable to allocate memory\n",
                                   "WARNING");
                          client_fd = strlen(&DAT_0044eae4);
                          CrLogWrite(3,&DAT_0044eae4,client_fd);
                          CrLogUnLock();
                        }
                        free(client_fds);
                      }
                      else {
                        memset(destination,0,local_2c);
                        memcpy((void *)client_fds[1],&stack0xffafeec8,select_result & 0xffff);
                        *(short *)(client_fds + 2) = (short)select_result;
                        *client_fds = local_34;
                        pthread_rwlock_wrlock((pthread_rwlock_t *)(local_40 + -0x156c));
                        client_fd = *(size_t *)(local_3c + -0x154c);
                        *(size_t **)(client_fd + 4) = client_fds + 3;
                        client_fds[3] = client_fd;
                        *(size_t **)(local_3c + -0x154c) = client_fds + 3;
                        client_fds[4] = (size_t)&DAT_0044eab4;
                        pthread_rwlock_unlock((pthread_rwlock_t *)(local_40 + -0x156c));
                      }
                      goto LAB_0040af40;
                    }
                    bind_result = GetLogLevel();
                    if (3 < bind_result) goto LAB_0040af40;
                    CrLogLock();
                    memset(&DAT_0044eae4,0,0x800);
                    log_msg = "[%s]-[%s](%d) Unable to allocate memory\n";
                    goto LAB_0040b1dc;
                  }
                  usleep(10000);
                } while (select_result == 0);
                bind_result = 0;
                fd_mask_ptr = read_fds;
                do {
                  bind_result = bind_result + 1;
                  *fd_mask_ptr = 0;
                  fd_mask_ptr = fd_mask_ptr + 1;
                } while (bind_result != 0x20);
                max_fd = *client_fds_ptr;
                timeout.tv_sec = 0;
                client_fd = max_fd + 0x1f;
                if (-1 < (int)max_fd) {
                  client_fd = max_fd;
                }
                fd_mask_ptr = read_fds + ((int)client_fd >> 5);
                *fd_mask_ptr = 1 << ((int)max_fd % 0x20 & 0x1fU) | *fd_mask_ptr;
                timeout.tv_usec = 10000;
                bind_result = select(max_fd + 1,(fd_set *)read_fds,(fd_set *)0x0,(fd_set *)0x0,
                                     &timeout);
              } while (bind_result != 0);
              bind_result = GetLogLevel();
              if (bind_result < 4) {
                CrLogLock();
                memset(&DAT_0044eae4,0,0x800);
                log_msg = "[%s]-[%s](%d) recv time out\n\n";
LAB_0040b1dc:
                snprintf(&DAT_0044eae4,0x800,log_msg,"WARNING");
LAB_0040b1e8:
                client_fd = strlen(&DAT_0044eae4);
                result = 3;
LAB_0040b1fc:
                CrLogWrite(result,&DAT_0044eae4,client_fd);
                CrLogUnLock();
              }
            }
LAB_0040af40:
            socket_fd = socket_fd + 1;
            client_fds_ptr = client_fds_ptr + 1;
          } while (socket_fd != 10);
        } while( true );
      }
      socket_fd = GetLogLevel();
      if (3 < socket_fd) {
        return 0xffffffff;
      }
      CrLogLock();
      memset(&DAT_0044eae4,0,0x800);
      errno_ptr = __errno_location();
      strerror(*errno_ptr);
      log_msg = "[%s]-[%s](%d) remote debug listen error %s";
    }
  }
  snprintf(&DAT_0044eae4,0x800,log_msg,"WARNING");
  recv_size = strlen(&DAT_0044eae4);
  CrLogWrite(3,&DAT_0044eae4,recv_size);
  CrLogUnLock();
  return 0xffffffff;
}



undefined4 FUN_0040b214(void)

{
  pthread_t __th;
  
  initializeServer();
  __th = pthread_self();
  pthread_detach(__th);
  return 0;
}



undefined4 removeFromLinkedList(void *param_1)

{
  int logLevel;
  size_t logStringLength;
  int *prevElement;
  undefined4 result;
  
  if ((undefined4 **)DAT_0044eab4 == &DAT_0044eab4) {
    result = 0xffffffff;
    logLevel = GetLogLevel();
    if (logLevel < 4) {
      CrLogLock();
      memset(&DAT_0044eae4,0,0x800);
      snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) linked list is empty\n","WARNING",
               "localSocket/localSocket.c",0x53);
      logStringLength = strlen(&DAT_0044eae4);
      CrLogWrite(3,&DAT_0044eae4,logStringLength);
      CrLogUnLock();
    }
  }
  else {
    pthread_rwlock_wrlock((pthread_rwlock_t *)&DAT_0044ea94);
    logLevel = *(int *)((int)param_1 + 0xc);
    prevElement = *(int **)((int)param_1 + 0x10);
    *(int **)(logLevel + 4) = prevElement;
    *prevElement = logLevel;
    *(int *)((int)param_1 + 0xc) = (int)param_1 + 0xc;
    *(int *)((int)param_1 + 0x10) = (int)param_1 + 0xc;
    pthread_rwlock_unlock((pthread_rwlock_t *)&DAT_0044ea94);
    if (*(void **)((int)param_1 + 4) != (void *)0x0) {
      free(*(void **)((int)param_1 + 4));
    }
    free(param_1);
    result = 0;
  }
  return result;
}



undefined4 * getLinkedListHead(void)

{
  undefined4 *result;
  
  result = (undefined4 *)0x0;
  if (((DAT_0044eab8 != 0) && (DAT_0044eab4 != (undefined4 *)0x0)) &&
     ((undefined4 **)DAT_0044eab4 != &DAT_0044eab4)) {
    result = DAT_0044eab4 + -3;
  }
  return result;
}



undefined4 sendData(int socketFD,void *data,size_t dataSize)

{
  int status;
  size_t logLength;
  undefined4 result;
  
  if (socketFD < 1) {
    result = 0xffffffff;
    status = GetLogLevel();
    if (status < 5) {
      CrLogLock();
      memset(&DAT_0044eae4,0,0x800);
      snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) fd invalid\n","ERROR","localSocket/localSocket.c",
               0x7a);
      logLength = strlen(&DAT_0044eae4);
      CrLogWrite(4,&DAT_0044eae4,logLength);
      CrLogUnLock();
    }
  }
  else {
    send(socketFD,data,dataSize,0);
    result = 0;
  }
  return result;
}



int createThread(void)

{
  int threadCreationResult;
  int logLevel;
  size_t logMessageLength;
  
  threadCreationResult =
       pthread_create(&DAT_0044ea90,(pthread_attr_t *)0x0,FUN_0040b214,(void *)0x0);
  if (threadCreationResult != 0) {
    threadCreationResult = -1;
    logLevel = GetLogLevel();
    if (logLevel < 4) {
      CrLogLock();
      memset(&DAT_0044eae4,0,0x800);
      snprintf(&DAT_0044eae4,0x800,"[%s]-[%s](%d) create pthread error!","WARNING",
               "localSocket/localSocket.c",0x14a);
      logMessageLength = strlen(&DAT_0044eae4);
      CrLogWrite(3,&DAT_0044eae4,logMessageLength);
      CrLogUnLock();
    }
  }
  return threadCreationResult;
}



undefined4 cancelThread(void)

{
  pthread_cancel(DAT_0044ea90);
  DAT_0044ea90 = 0xffffffff;
  if (-1 < DAT_0044d890) {
    close(DAT_0044d890);
    DAT_0044d890 = -1;
  }
  return 0;
}



void decreaseAndDeallocate(int *count)

{
  int tmpState;
  
  if ((count != (int *)0x0) && (tmpState = *count, *count = tmpState + -1, tmpState + -1 == 0)) {
    _Py_Dealloc();
    return;
  }
  return;
}



int processLaserData(short *laserData,int param_2,float *param_3)

{
  int laserList;
  size_t stringLength;
  int logLevelCheck;
  char *__logMessageFormat;
  int *pythonCallResult;
  int *pythonParseResult;
  short *currentShortPtr;
  short currentShortValue;
  bool isDataRemaining;
  undefined4 logWriteParameter;
  undefined8 logWriteStringLength;
  short *nextShortPtr;
  
  laserList = PyList_New(param_2);
  if (laserList == 0) {
    laserList = GetLogLevel();
    if (laserList < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      logWriteStringLength = 0x2600430578;
      logWriteParameter = 0x26;
      __logMessageFormat = "[%s]-[%s](%d) [%s %d] PyList_New Fail!!!\n";
LAB_0040b74c:
      snprintf(&DAT_0044f2f8,0x800,__logMessageFormat,"WARNING","laserAi/LaserAiServer.c",
               logWriteParameter,logWriteStringLength);
LAB_0040b758:
      stringLength = strlen(&DAT_0044f2f8);
      logWriteParameter = 3;
LAB_0040b9dc:
      CrLogWrite(logWriteParameter,&DAT_0044f2f8,stringLength);
      CrLogUnLock();
    }
LAB_0040b9ec:
    PyErr_Print();
  }
  else {
    isDataRemaining = 0 < param_2;
    logLevelCheck = 0;
    while (isDataRemaining) {
      currentShortPtr = laserData + 2;
      nextShortPtr = laserData + 1;
      currentShortValue = *laserData;
      laserData = laserData + 3;
      logWriteParameter =
           Py_BuildValue("[i,i,i]",(int)currentShortValue,(int)*nextShortPtr,(int)*currentShortPtr);
      PyList_SetItem(laserList,logLevelCheck,logWriteParameter);
      isDataRemaining = logLevelCheck + 1 < param_2;
      logLevelCheck = logLevelCheck + 1;
    }
    pythonParseResult = (int *)PyTuple_New(1);
    if (pythonParseResult == (int *)0x0) {
      laserList = GetLogLevel();
      if (laserList < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        logWriteStringLength = 0x3400430578;
        logWriteParameter = 0x34;
        __logMessageFormat = "[%s]-[%s](%d) [%s %d]PyTuple_New Fail!!!\n";
        goto LAB_0040b74c;
      }
      goto LAB_0040b9ec;
    }
    PyTuple_SetItem(pythonParseResult,0,laserList);
    laserList = PyDict_GetItemString(DAT_0044f2f0,"laser_level");
    if ((laserList != 0) && (logLevelCheck = PyCallable_Check(laserList), logLevelCheck != 0)) {
      pythonCallResult = (int *)PyObject_CallObject(laserList,pythonParseResult);
      if ((pythonCallResult == (int *)0x0) || (laserList = PyErr_Occurred(), laserList != 0)) {
        laserList = GetLogLevel();
        if (3 < laserList) goto LAB_0040b9ec;
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [GetLevelValueFromAi] return NULL\n","WARNING",
                 "laserAi/LaserAiServer.c",0x55);
        goto LAB_0040b758;
      }
      laserList = PyArg_Parse(pythonCallResult,&DAT_0042f9b0,param_3);
      if (laserList != 0) {
        logLevelCheck = GetLogLevel();
        if (logLevelCheck < 3) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [GetLevelValueFromAi]level=%f\n",&DAT_0042dfc4
                   ,"laserAi/LaserAiServer.c",0x4c,(double)*param_3);
          stringLength = strlen(&DAT_0044f2f8);
          CrLogWrite(2,&DAT_0044f2f8,stringLength);
          CrLogUnLock();
        }
        goto LAB_0040b8b8;
      }
      laserList = GetLogLevel();
      if (2 < laserList) goto LAB_0040b9ec;
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [GetLevelValueFromAi]PyArg_Parse return NULL",
               &DAT_0042dfc4,"laserAi/LaserAiServer.c",0x4e);
      stringLength = strlen(&DAT_0044f2f8);
      logWriteParameter = 2;
      goto LAB_0040b9dc;
    }
    laserList = GetLogLevel();
    if (3 < laserList) {
      laserList = -1;
      goto LAB_0040b8b8;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) can\'t find function [laser_level]\n","WARNING",
             "laserAi/LaserAiServer.c",0x40);
    stringLength = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,stringLength);
    CrLogUnLock();
  }
  laserList = -1;
LAB_0040b8b8:
  decreaseAndDeallocate(pythonCallResult);
  decreaseAndDeallocate(pythonParseResult);
  return laserList;
}



// why is there python here? what is PyList and PyTuple

undefined4 processFlowDetection(short *param_1,int param_2,float *param_3)

{
  int iVar1;
  size_t stringLength;
  int loopIndex;
  undefined4 pythonList;
  char *__logMessageFormat;
  int pythonBuildResult;
  int *unaff_s3;
  int *unaff_s4;
  undefined4 uVar2;
  undefined8 uVar3;
  short *currentShortPtr;
  short currentShortValue;
  short *nextShortPtr;
  
  iVar1 = PyList_New(param_2);
  if (iVar1 == 0) {
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar3 = 0x6900430560;
      uVar2 = 0x69;
      __logMessageFormat = "[%s]-[%s](%d) [%s %d] PyList_New Fail!!!\n";
LAB_0040bb9c:
      snprintf(&DAT_0044f2f8,0x800,__logMessageFormat,"WARNING","laserAi/LaserAiServer.c",uVar2,
               uVar3);
LAB_0040bba8:
      stringLength = strlen(&DAT_0044f2f8);
      CrLogWrite(3,&DAT_0044f2f8,stringLength);
      CrLogUnLock();
    }
LAB_0040bbc8:
    PyErr_Print();
  }
  else {
    for (pythonBuildResult = 0; pythonBuildResult < param_2;
        pythonBuildResult = pythonBuildResult + 1) {
      currentShortPtr = param_1 + 2;
      nextShortPtr = param_1 + 1;
      currentShortValue = *param_1;
      param_1 = param_1 + 3;
      loopIndex = Py_BuildValue("[i,i,i]",(int)currentShortValue,(int)*nextShortPtr,
                                (int)*currentShortPtr);
      if (loopIndex == 0) {
        iVar1 = GetLogLevel();
        if (3 < iVar1) goto LAB_0040bbc8;
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar3 = 0x7100430560;
        uVar2 = 0x71;
        __logMessageFormat = "[%s]-[%s](%d) [%s %d] Py_BuildValue Fail!!!\n";
        goto LAB_0040bb9c;
      }
      PyList_SetItem(iVar1,pythonBuildResult,loopIndex);
    }
    unaff_s3 = (int *)PyTuple_New(1);
    if (unaff_s3 == (int *)0x0) {
      iVar1 = GetLogLevel();
      if (iVar1 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar3 = 0x7d00430560;
        uVar2 = 0x7d;
        __logMessageFormat = "[%s]-[%s](%d) [%s %d] PyTuple_New Fail!!!\n";
        goto LAB_0040bb9c;
      }
      goto LAB_0040bbc8;
    }
    PyTuple_SetItem(unaff_s3,0,iVar1);
    iVar1 = PyDict_GetItemString(DAT_0044f2f0,"flow_detection");
    if ((iVar1 != 0) && (pythonBuildResult = PyCallable_Check(iVar1), pythonBuildResult != 0)) {
      unaff_s4 = (int *)PyObject_CallObject(iVar1,unaff_s3);
      if (unaff_s4 != (int *)0x0) {
        iVar1 = PyErr_Occurred();
        if (iVar1 == 0) {
          iVar1 = PyArg_ParseTuple(unaff_s4,&DAT_0042fae4,param_3,param_3 + 1,param_3 + 2);
          if (iVar1 == 0) {
            uVar2 = 0xffffffff;
            iVar1 = GetLogLevel();
            if (3 < iVar1) goto LAB_0040bd8c;
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [flow_detection]PyArg_ParseTuple fail\n",
                     "WARNING","laserAi/LaserAiServer.c",0x8e);
            stringLength = strlen(&DAT_0044f2f8);
            pythonList = 3;
          }
          else {
            uVar2 = 0;
            iVar1 = GetLogLevel();
            if (2 < iVar1) goto LAB_0040bd8c;
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,
                     "[%s]-[%s](%d) [GetFlowDetectionFromAi]node_width=[%f,%f,%f]\n",&DAT_0042dfc4,
                     "laserAi/LaserAiServer.c",0x92,(double)*param_3,(double)param_3[1],
                     (double)param_3[2]);
            stringLength = strlen(&DAT_0044f2f8);
            pythonList = 2;
          }
          CrLogWrite(pythonList,&DAT_0044f2f8,stringLength);
          CrLogUnLock();
          goto LAB_0040bd8c;
        }
      }
      iVar1 = GetLogLevel();
      if (3 < iVar1) goto LAB_0040bbc8;
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [flow_detection] return NULL\n","WARNING",
               "laserAi/LaserAiServer.c",0x94);
      goto LAB_0040bba8;
    }
    iVar1 = GetLogLevel();
    if (3 < iVar1) {
      uVar2 = 0xffffffff;
      goto LAB_0040bd8c;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) can\'t find function [flow_detection]\n","WARNING",
             "laserAi/LaserAiServer.c",0x86);
    stringLength = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,stringLength);
    CrLogUnLock();
  }
  uVar2 = 0xffffffff;
LAB_0040bd8c:
  decreaseAndDeallocate(unaff_s4);
  decreaseAndDeallocate(unaff_s3);
  return uVar2;
}



// why am i seeing python with c and cpp in the prints??

undefined4
getSelectLineFromAi(undefined4 param_1,int param_2,undefined4 param_3,int param_4,undefined4 param_5
                   ,int param_6,char *param_7)

{
  int pythonList1;
  undefined4 uVar1;
  int pythonList2;
  int pythonList3;
  size_t sVar2;
  char *__logMessageFormat;
  int iVar3;
  int *unaff_s1;
  int *unaff_s3;
  undefined4 uVar4;
  bool loopCondition;
  
  pythonList1 = PyList_New(param_2);
  if (pythonList1 == 0) {
    pythonList2 = GetLogLevel();
    if (pythonList2 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [%s %d] PyList_New Fail!!!","WARNING",
               "laserAi/LaserAiServer.c",0xa8,"GetSelectLineFromAi",0xa8);
      sVar2 = strlen(&DAT_0044f2f8);
      CrLogWrite(3,&DAT_0044f2f8,sVar2);
      CrLogUnLock();
    }
    PyErr_Print();
  }
  else {
    loopCondition = 0 < param_2;
    pythonList2 = 0;
    while (loopCondition) {
      uVar1 = Py_BuildValue(&DAT_0042f9b0);
      PyList_SetItem(pythonList1,pythonList2,uVar1);
      loopCondition = pythonList2 + 1 < param_2;
      pythonList2 = pythonList2 + 1;
    }
  }
  pythonList2 = PyList_New(param_4);
  if (pythonList2 == 0) {
    pythonList1 = GetLogLevel();
    if (pythonList1 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar4 = 0xb3;
      uVar1 = 0xb3;
      __logMessageFormat = "[%s]-[%s](%d) [%s %d] PyList_New Fail!!!";
LAB_0040c160:
      snprintf(&DAT_0044f2f8,0x800,__logMessageFormat,"WARNING","laserAi/LaserAiServer.c",uVar1,
               "GetSelectLineFromAi",uVar4);
LAB_0040c16c:
      sVar2 = strlen(&DAT_0044f2f8);
      CrLogWrite(3,&DAT_0044f2f8,sVar2);
      CrLogUnLock();
    }
LAB_0040c18c:
    PyErr_Print();
  }
  else {
    loopCondition = 0 < param_4;
    pythonList3 = 0;
    while (loopCondition) {
      uVar1 = Py_BuildValue(&DAT_0042f9b0);
      PyList_SetItem(pythonList2,pythonList3,uVar1);
      loopCondition = pythonList3 + 1 < param_4;
      pythonList3 = pythonList3 + 1;
    }
    pythonList3 = PyList_New(param_6);
    if (pythonList3 == 0) {
      iVar3 = GetLogLevel();
      if (iVar3 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [%s %d] PyList_New Fail!!!","WARNING",
                 "laserAi/LaserAiServer.c",0xbf,"GetSelectLineFromAi",0xbf);
        sVar2 = strlen(&DAT_0044f2f8);
        CrLogWrite(3,&DAT_0044f2f8,sVar2);
        CrLogUnLock();
      }
      PyErr_Print();
    }
    else {
      for (iVar3 = 0; iVar3 < param_6; iVar3 = iVar3 + 1) {
        uVar1 = Py_BuildValue(&DAT_0042f9b0);
        PyList_SetItem(pythonList3,iVar3,uVar1);
      }
    }
    unaff_s1 = (int *)PyTuple_New(3);
    if (unaff_s1 == (int *)0x0) {
      pythonList1 = GetLogLevel();
      if (pythonList1 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar4 = 0xc9;
        uVar1 = 0xc9;
        __logMessageFormat = "[%s]-[%s](%d) [%s %d] PyTuple_New Fail!!!";
        goto LAB_0040c160;
      }
      goto LAB_0040c18c;
    }
    PyTuple_SetItem(unaff_s1,0,pythonList1);
    PyTuple_SetItem(unaff_s1,1,pythonList2);
    PyTuple_SetItem(unaff_s1,2,pythonList3);
    pythonList1 = PyDict_GetItemString(DAT_0044f2f0,"select_line");
    if ((pythonList1 != 0) && (pythonList2 = PyCallable_Check(pythonList1), pythonList2 != 0)) {
      unaff_s3 = (int *)PyObject_CallObject(pythonList1,unaff_s1);
      if ((unaff_s3 != (int *)0x0) && (pythonList1 = PyErr_Occurred(), pythonList1 == 0)) {
        pythonList1 = PyUnicode_AsUTF8(unaff_s3);
        uVar1 = 0xffffffff;
        if (pythonList1 != 0) {
          snprintf(param_7,0x40,"%s",pythonList1);
          uVar1 = 0;
          pythonList1 = GetLogLevel();
          if (pythonList1 < 3) {
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [GetSelectLineFromAi]result=%s",
                     &DAT_0042dfc4,"laserAi/LaserAiServer.c",0xe5,param_7);
            sVar2 = strlen(&DAT_0044f2f8);
            CrLogWrite(2,&DAT_0044f2f8,sVar2);
            CrLogUnLock();
          }
        }
        goto LAB_0040c420;
      }
      pythonList1 = GetLogLevel();
      if (3 < pythonList1) goto LAB_0040c18c;
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [select_line] return NULL ","WARNING",
               "laserAi/LaserAiServer.c",0xeb);
      goto LAB_0040c16c;
    }
    pythonList1 = GetLogLevel();
    if (3 < pythonList1) {
      uVar1 = 0xffffffff;
      goto LAB_0040c420;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) can\'t find function [select_line]\n","WARNING",
             "laserAi/LaserAiServer.c",0xd8);
    sVar2 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar2);
    CrLogUnLock();
  }
  uVar1 = 0xffffffff;
LAB_0040c420:
  decreaseAndDeallocate(unaff_s3);
  decreaseAndDeallocate(unaff_s1);
  return uVar1;
}



undefined4
FUN_0040c540(undefined4 *param_1,int param_2,undefined4 *param_3,int param_4,undefined4 *param_5,
            int param_6,undefined4 *param_7)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  size_t sVar6;
  char *pcVar7;
  undefined4 uVar8;
  int iVar9;
  int *unaff_s3;
  int iVar10;
  int *unaff_s4;
  
  uVar8 = 0xffffffff;
  if (((param_1 == (undefined4 *)0x0) || (param_3 == (undefined4 *)0x0)) ||
     (param_5 == (undefined4 *)0x0)) goto LAB_0040c964;
  iVar4 = PyList_New(param_2);
  if (iVar4 == 0) {
    iVar4 = GetLogLevel();
    if (iVar4 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar8 = 0x108;
LAB_0040c6c0:
      pcVar7 = "[%s]-[%s](%d) [%s %d] PyList_New Fail!!!";
LAB_0040c6f0:
      snprintf(&DAT_0044f2f8,0x800,pcVar7,"WARNING","laserAi/LaserAiServer.c",uVar8,
               "GetFirstLayerDetectFromAi",uVar8);
LAB_0040c6fc:
      sVar6 = strlen(&DAT_0044f2f8);
      CrLogWrite(3,&DAT_0044f2f8,sVar6);
      CrLogUnLock();
    }
LAB_0040c71c:
    PyErr_Print();
  }
  else {
    for (iVar9 = 0; iVar9 < param_2; iVar9 = iVar9 + 1) {
      uVar8 = Py_BuildValue("[i,i,i]",*param_1,param_1[1],param_1[2]);
      PyList_SetItem(iVar4,iVar9,uVar8);
      param_1 = param_1 + 3;
    }
    iVar9 = PyList_New(param_4);
    if (iVar9 == 0) {
      iVar4 = GetLogLevel();
      if (iVar4 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar8 = 0x115;
        goto LAB_0040c6c0;
      }
      goto LAB_0040c71c;
    }
    bVar3 = 0 < param_4;
    iVar5 = 0;
    while (bVar3) {
      puVar1 = param_3 + 2;
      puVar2 = param_3 + 1;
      uVar8 = *param_3;
      param_3 = param_3 + 3;
      uVar8 = Py_BuildValue("[i,i,i]",uVar8,*puVar2,*puVar1);
      PyList_SetItem(iVar9,iVar5,uVar8);
      bVar3 = iVar5 + 1 < param_4;
      iVar5 = iVar5 + 1;
    }
    iVar5 = PyList_New(param_6);
    if (iVar5 == 0) {
      iVar4 = GetLogLevel();
      if (iVar4 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar8 = 0x122;
        goto LAB_0040c6c0;
      }
      goto LAB_0040c71c;
    }
    for (iVar10 = 0; iVar10 < param_6; iVar10 = iVar10 + 1) {
      puVar1 = param_5 + 2;
      puVar2 = param_5 + 1;
      uVar8 = *param_5;
      param_5 = param_5 + 3;
      uVar8 = Py_BuildValue("[i,i,i]",uVar8,*puVar2,*puVar1);
      PyList_SetItem(iVar5,iVar10,uVar8);
    }
    unaff_s3 = (int *)PyTuple_New(3);
    if (unaff_s3 == (int *)0x0) {
      iVar4 = GetLogLevel();
      if (3 < iVar4) goto LAB_0040c71c;
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar8 = 0x130;
      pcVar7 = "[%s]-[%s](%d) [%s %d]PyTuple_New Fail!!!";
      goto LAB_0040c6f0;
    }
    PyTuple_SetItem(unaff_s3,0,iVar4);
    PyTuple_SetItem(unaff_s3,1,iVar9);
    PyTuple_SetItem(unaff_s3,2,iVar5);
    iVar4 = PyDict_GetItemString(DAT_0044f2f0,"First_Layer_Detect");
    if ((iVar4 != 0) && (iVar9 = PyCallable_Check(iVar4), iVar9 != 0)) {
      unaff_s4 = (int *)PyObject_CallObject(iVar4,unaff_s3);
      if ((unaff_s4 == (int *)0x0) || (iVar4 = PyErr_Occurred(), iVar4 != 0)) {
        iVar4 = GetLogLevel();
        if (iVar4 < 4) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar8 = 0x150;
          pcVar7 = "[%s]-[%s](%d) [GetFirstLayerDetectFromAi] return NULL ";
LAB_0040ca70:
          snprintf(&DAT_0044f2f8,0x800,pcVar7,"WARNING","laserAi/LaserAiServer.c",uVar8);
          goto LAB_0040c6fc;
        }
      }
      else {
        iVar4 = PyArg_Parse(unaff_s4,&DAT_0042fcf4,param_7);
        if (iVar4 != 0) {
          uVar8 = 0;
          iVar4 = GetLogLevel();
          if (iVar4 < 3) {
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [GetFirstLayerDetectFromAi]result=%d",
                     &DAT_0042dfc4,"laserAi/LaserAiServer.c",0x148,*param_7);
            sVar6 = strlen(&DAT_0044f2f8);
            CrLogWrite(2,&DAT_0044f2f8,sVar6);
            CrLogUnLock();
          }
          goto LAB_0040c964;
        }
        iVar4 = GetLogLevel();
        if (iVar4 < 4) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar8 = 0x14a;
          pcVar7 = "[%s]-[%s](%d) [GetFirstLayerDetectFromAi] res is NULL ";
          goto LAB_0040ca70;
        }
      }
      goto LAB_0040c71c;
    }
    iVar4 = GetLogLevel();
    if (3 < iVar4) {
      uVar8 = 0xffffffff;
      goto LAB_0040c964;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) can\'t find function [GetFirstLayerDetectFromAi]",
             "WARNING","laserAi/LaserAiServer.c",0x13d);
    sVar6 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar6);
    CrLogUnLock();
  }
  uVar8 = 0xffffffff;
LAB_0040c964:
  decreaseAndDeallocate(unaff_s4);
  decreaseAndDeallocate(unaff_s3);
  return uVar8;
}



undefined4
FUN_0040cadc(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,float *param_5)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  size_t sVar4;
  int iVar5;
  char *pcVar6;
  int iVar7;
  int *unaff_s2;
  int *unaff_s3;
  undefined4 uVar8;
  undefined8 uVar9;
  
  iVar3 = PyList_New(param_2);
  if (iVar3 == 0) {
    iVar3 = GetLogLevel();
    if (iVar3 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar9 = 0x16b00430518;
      uVar8 = 0x16b;
      pcVar6 = "[%s]-[%s](%d) [%s %d] PyList_New Fail!!!\n";
LAB_0040cc14:
      snprintf(&DAT_0044f2f8,0x800,pcVar6,"WARNING","laserAi/LaserAiServer.c",uVar8,uVar9);
LAB_0040cc20:
      sVar4 = strlen(&DAT_0044f2f8);
      CrLogWrite(3,&DAT_0044f2f8,sVar4);
      CrLogUnLock();
    }
LAB_0040cc40:
    PyErr_Print();
  }
  else {
    for (iVar7 = 0; iVar7 < param_2; iVar7 = iVar7 + 1) {
      puVar1 = param_1 + 2;
      puVar2 = param_1 + 1;
      uVar8 = *param_1;
      param_1 = param_1 + 3;
      iVar5 = Py_BuildValue("[i,i,i]",uVar8,*puVar2,*puVar1);
      if (iVar5 == 0) {
        iVar3 = GetLogLevel();
        if (3 < iVar3) goto LAB_0040cc40;
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar9 = 0x17300430518;
        uVar8 = 0x173;
        pcVar6 = "[%s]-[%s](%d) [%s %d] Py_BuildValue Fail!!!\n";
        goto LAB_0040cc14;
      }
      PyList_SetItem(iVar3,iVar7,iVar5);
    }
    unaff_s2 = (int *)PyTuple_New(1);
    if (unaff_s2 == (int *)0x0) {
      iVar3 = GetLogLevel();
      if (iVar3 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar9 = 0x17f00430518;
        uVar8 = 0x17f;
        pcVar6 = "[%s]-[%s](%d) [%s %d] PyTuple_New Fail!!!\n";
        goto LAB_0040cc14;
      }
      goto LAB_0040cc40;
    }
    PyTuple_SetItem(unaff_s2,0,iVar3);
    iVar3 = PyDict_GetItemString(DAT_0044f2f0,"TwoPointCalib");
    if ((iVar3 != 0) && (iVar7 = PyCallable_Check(iVar3), iVar7 != 0)) {
      unaff_s3 = (int *)PyObject_CallObject(iVar3,unaff_s2);
      if ((unaff_s3 == (int *)0x0) || (iVar3 = PyErr_Occurred(), iVar3 != 0)) {
        iVar3 = GetLogLevel();
        if (iVar3 < 4) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar8 = 0x197;
          pcVar6 = "[%s]-[%s](%d) [TwoPointCalib] return NULL\n";
LAB_0040cdd0:
          snprintf(&DAT_0044f2f8,0x800,pcVar6,"WARNING","laserAi/LaserAiServer.c",uVar8);
          goto LAB_0040cc20;
        }
      }
      else {
        iVar3 = PyArg_ParseTuple(unaff_s3,&DAT_0042fde0,param_5,param_5 + 1);
        if (iVar3 != 0) {
          uVar8 = 0;
          iVar3 = GetLogLevel();
          if (iVar3 < 3) {
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [GetLaserOffsetFromAi]offset=[%f,%f]\n",
                     &DAT_0042dfc4,"laserAi/LaserAiServer.c",0x195,(double)*param_5,
                     (double)param_5[1]);
            sVar4 = strlen(&DAT_0044f2f8);
            CrLogWrite(2,&DAT_0044f2f8,sVar4);
            CrLogUnLock();
          }
          goto LAB_0040ceec;
        }
        iVar3 = GetLogLevel();
        if (iVar3 < 4) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar8 = 400;
          pcVar6 = "[%s]-[%s](%d) [TwoPointCalib]PyArg_ParseTuple fail\n";
          goto LAB_0040cdd0;
        }
      }
      goto LAB_0040cc40;
    }
    iVar3 = GetLogLevel();
    if (3 < iVar3) {
      uVar8 = 0xffffffff;
      goto LAB_0040ceec;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) can\'t find function [TwoPointCalib]\n","WARNING",
             "laserAi/LaserAiServer.c",0x188);
    sVar4 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar4);
    CrLogUnLock();
  }
  uVar8 = 0xffffffff;
LAB_0040ceec:
  decreaseAndDeallocate(unaff_s3);
  decreaseAndDeallocate(unaff_s2);
  return uVar8;
}



undefined4
FUN_0040cf84(undefined4 *param_1,int param_2,undefined4 *param_3,int param_4,undefined4 param_5,
            undefined4 param_6,float *param_7)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  size_t sVar4;
  int iVar5;
  undefined4 uVar6;
  char *pcVar7;
  int iVar8;
  int *unaff_s1;
  int iVar9;
  int *unaff_s3;
  undefined8 uVar10;
  
  iVar3 = PyList_New(param_2);
  if (iVar3 == 0) {
    iVar3 = GetLogLevel();
    if (3 < iVar3) goto LAB_0040d104;
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    uVar6 = 0x1b2;
LAB_0040d0a8:
    uVar10 = CONCAT44(uVar6,"GetLaserOffsetNewFromAi");
    pcVar7 = "[%s]-[%s](%d) [%s %d] PyList_New Fail!!!\n";
LAB_0040d0d8:
    snprintf(&DAT_0044f2f8,0x800,pcVar7,"WARNING","laserAi/LaserAiServer.c",uVar6,uVar10);
LAB_0040d0e4:
    sVar4 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar4);
    CrLogUnLock();
LAB_0040d104:
    PyErr_Print();
  }
  else {
    for (iVar8 = 0; iVar8 < param_2; iVar8 = iVar8 + 1) {
      puVar1 = param_1 + 2;
      puVar2 = param_1 + 1;
      uVar6 = *param_1;
      param_1 = param_1 + 3;
      iVar9 = Py_BuildValue("[i,i,i]",uVar6,*puVar2,*puVar1);
      if (iVar9 == 0) {
        iVar3 = GetLogLevel();
        if (3 < iVar3) goto LAB_0040d104;
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar6 = 0x1ba;
        goto LAB_0040d164;
      }
      PyList_SetItem(iVar3,iVar8,iVar9);
    }
    iVar8 = PyList_New(param_4);
    if (iVar8 == 0) {
      iVar3 = GetLogLevel();
      if (iVar3 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar6 = 0x1c4;
        goto LAB_0040d0a8;
      }
      goto LAB_0040d104;
    }
    for (iVar9 = 0; iVar9 < param_4; iVar9 = iVar9 + 1) {
      puVar1 = param_3 + 2;
      puVar2 = param_3 + 1;
      uVar6 = *param_3;
      param_3 = param_3 + 3;
      iVar5 = Py_BuildValue("[i,i,i]",uVar6,*puVar2,*puVar1);
      if (iVar5 == 0) {
        iVar3 = GetLogLevel();
        if (3 < iVar3) goto LAB_0040d104;
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar6 = 0x1cc;
        goto LAB_0040d164;
      }
      PyList_SetItem(iVar8,iVar9,iVar5);
    }
    iVar9 = Py_BuildValue("d");
    if (iVar9 == 0) {
      iVar3 = GetLogLevel();
      if (iVar3 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar6 = 0x1d6;
LAB_0040d164:
        uVar10 = CONCAT44(uVar6,"GetLaserOffsetNewFromAi");
        pcVar7 = "[%s]-[%s](%d) [%s %d] Py_BuildValue Fail!!!\n";
        goto LAB_0040d0d8;
      }
      goto LAB_0040d104;
    }
    iVar5 = Py_BuildValue("d");
    if (iVar5 == 0) {
      iVar3 = GetLogLevel();
      if (iVar3 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar6 = 0x1dd;
        goto LAB_0040d164;
      }
      goto LAB_0040d104;
    }
    unaff_s1 = (int *)PyTuple_New(4);
    if (unaff_s1 == (int *)0x0) {
      iVar3 = GetLogLevel();
      if (3 < iVar3) goto LAB_0040d104;
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar10 = 0x1e600430500;
      uVar6 = 0x1e6;
      pcVar7 = "[%s]-[%s](%d) [%s %d] PyTuple_New Fail!!!\n";
      goto LAB_0040d0d8;
    }
    PyTuple_SetItem(unaff_s1,0,iVar3);
    PyTuple_SetItem(unaff_s1,1,iVar8);
    PyTuple_SetItem(unaff_s1,2,iVar9);
    PyTuple_SetItem(unaff_s1,3,iVar5);
    iVar3 = PyDict_GetItemString(DAT_0044f2f0,"get_xy_offset");
    if ((iVar3 != 0) && (iVar8 = PyCallable_Check(iVar3), iVar8 != 0)) {
      unaff_s3 = (int *)PyObject_CallObject(iVar3,unaff_s1);
      if (unaff_s3 == (int *)0x0) {
LAB_0040d5b0:
        iVar3 = GetLogLevel();
        if (3 < iVar3) goto LAB_0040d104;
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar6 = 0x202;
        pcVar7 = "[%s]-[%s](%d) [get_xy_offset] return NULL\n";
      }
      else {
        iVar3 = PyErr_Occurred();
        if (iVar3 != 0) goto LAB_0040d5b0;
        iVar3 = PyArg_ParseTuple(unaff_s3,&DAT_0042fae4,param_7,param_7 + 1,param_7 + 2);
        if (iVar3 != 0) {
          uVar6 = 0;
          iVar3 = GetLogLevel();
          if (iVar3 < 3) {
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,
                     "[%s]-[%s](%d) [GetLaserOffsetNewFromAi]offset=[%f,%f,%f]\n",&DAT_0042dfc4,
                     "laserAi/LaserAiServer.c",0x200,(double)*param_7,(double)param_7[1],
                     (double)param_7[2]);
            sVar4 = strlen(&DAT_0044f2f8);
            uVar6 = 0;
            CrLogWrite(2,&DAT_0044f2f8,sVar4);
            CrLogUnLock();
          }
          goto LAB_0040d56c;
        }
        iVar3 = GetLogLevel();
        if (3 < iVar3) goto LAB_0040d104;
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar6 = 0x1fb;
        pcVar7 = "[%s]-[%s](%d) [get_xy_offset]PyArg_ParseTuple fail\n";
      }
      snprintf(&DAT_0044f2f8,0x800,pcVar7,"WARNING","laserAi/LaserAiServer.c",uVar6);
      goto LAB_0040d0e4;
    }
    iVar3 = GetLogLevel();
    if (3 < iVar3) {
      uVar6 = 0xffffffff;
      goto LAB_0040d56c;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) can\'t find function [get_xy_offset]\n","WARNING",
             "laserAi/LaserAiServer.c",499);
    sVar4 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar4);
    CrLogUnLock();
  }
  uVar6 = 0xffffffff;
LAB_0040d56c:
  decreaseAndDeallocate(unaff_s3);
  decreaseAndDeallocate(unaff_s1);
  return uVar6;
}



undefined4
FUN_0040d608(undefined4 *param_1,int param_2,undefined4 *param_3,int param_4,float *param_5)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  size_t sVar4;
  int iVar5;
  char *pcVar6;
  int iVar7;
  int iVar8;
  int *unaff_s2;
  int *unaff_s3;
  undefined4 uVar9;
  undefined8 uVar10;
  
  iVar3 = PyList_New(param_2);
  if (iVar3 == 0) {
    iVar3 = GetLogLevel();
    if (iVar3 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar9 = 0x21c;
LAB_0040d748:
      uVar10 = CONCAT44(uVar9,"GetLaserOffsetTwoPointFuseFromAi");
      pcVar6 = "[%s]-[%s](%d) [%s %d] PyList_New Fail!!!\n";
LAB_0040d778:
      snprintf(&DAT_0044f2f8,0x800,pcVar6,"WARNING","laserAi/LaserAiServer.c",uVar9,uVar10);
LAB_0040d784:
      sVar4 = strlen(&DAT_0044f2f8);
      CrLogWrite(3,&DAT_0044f2f8,sVar4);
      CrLogUnLock();
    }
LAB_0040d7a4:
    PyErr_Print();
  }
  else {
    for (iVar7 = 0; iVar7 < param_2; iVar7 = iVar7 + 1) {
      puVar1 = param_1 + 2;
      puVar2 = param_1 + 1;
      uVar9 = *param_1;
      param_1 = param_1 + 3;
      iVar8 = Py_BuildValue("[i,i,i]",uVar9,*puVar2,*puVar1);
      if (iVar8 == 0) {
        iVar3 = GetLogLevel();
        if (3 < iVar3) goto LAB_0040d7a4;
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar9 = 0x224;
        goto LAB_0040d804;
      }
      PyList_SetItem(iVar3,iVar7,iVar8);
    }
    iVar7 = PyList_New(param_4);
    if (iVar7 == 0) {
      iVar3 = GetLogLevel();
      if (iVar3 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar9 = 0x22e;
        goto LAB_0040d748;
      }
      goto LAB_0040d7a4;
    }
    iVar8 = 0;
LAB_0040d690:
    if (iVar8 < param_4) {
      puVar1 = param_3 + 2;
      puVar2 = param_3 + 1;
      uVar9 = *param_3;
      param_3 = param_3 + 3;
      iVar5 = Py_BuildValue("[i,i,i]",uVar9,*puVar2,*puVar1);
      if (iVar5 != 0) goto LAB_0040d8d8;
      iVar3 = GetLogLevel();
      if (iVar3 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar9 = 0x236;
LAB_0040d804:
        uVar10 = CONCAT44(uVar9,"GetLaserOffsetTwoPointFuseFromAi");
        pcVar6 = "[%s]-[%s](%d) [%s %d] Py_BuildValue Fail!!!\n";
        goto LAB_0040d778;
      }
      goto LAB_0040d7a4;
    }
    unaff_s2 = (int *)PyTuple_New(2);
    if (unaff_s2 == (int *)0x0) {
      iVar3 = GetLogLevel();
      if (3 < iVar3) goto LAB_0040d7a4;
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar10 = 0x242004304dc;
      uVar9 = 0x242;
      pcVar6 = "[%s]-[%s](%d) [%s %d] PyTuple_New Fail!!!\n";
      goto LAB_0040d778;
    }
    PyTuple_SetItem(unaff_s2,0,iVar3);
    PyTuple_SetItem(unaff_s2,1,iVar7);
    iVar3 = PyDict_GetItemString(DAT_0044f2f0,"TwoPointCalibFuse");
    if ((iVar3 != 0) && (iVar7 = PyCallable_Check(iVar3), iVar7 != 0)) {
      unaff_s3 = (int *)PyObject_CallObject(iVar3,unaff_s2);
      if ((unaff_s3 == (int *)0x0) || (iVar3 = PyErr_Occurred(), iVar3 != 0)) {
        iVar3 = GetLogLevel();
        if (iVar3 < 4) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar9 = 0x25c;
          pcVar6 = "[%s]-[%s](%d) [TwoPointCalibFuse] return NULL\n";
LAB_0040d9e4:
          snprintf(&DAT_0044f2f8,0x800,pcVar6,"WARNING","laserAi/LaserAiServer.c",uVar9);
          goto LAB_0040d784;
        }
      }
      else {
        iVar3 = PyArg_ParseTuple(unaff_s3,&DAT_0042fde0,param_5,param_5 + 1);
        if (iVar3 != 0) {
          uVar9 = 0;
          iVar3 = GetLogLevel();
          if (iVar3 < 3) {
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,
                     "[%s]-[%s](%d) GetLaserOffsetTwoPointFuseFromAi offset=[%f,%f]\n",&DAT_0042dfc4
                     ,"laserAi/LaserAiServer.c",0x25a,(double)*param_5,(double)param_5[1]);
            sVar4 = strlen(&DAT_0044f2f8);
            CrLogWrite(2,&DAT_0044f2f8,sVar4);
            CrLogUnLock();
          }
          goto LAB_0040db00;
        }
        iVar3 = GetLogLevel();
        if (iVar3 < 4) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar9 = 0x255;
          pcVar6 = "[%s]-[%s](%d) [TwoPointCalibFuse]PyArg_ParseTuple fail\n";
          goto LAB_0040d9e4;
        }
      }
      goto LAB_0040d7a4;
    }
    iVar3 = GetLogLevel();
    if (3 < iVar3) {
      uVar9 = 0xffffffff;
      goto LAB_0040db00;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) can\'t find function [TwoPointCalibFuse]\n",
             "WARNING","laserAi/LaserAiServer.c",0x24d);
    sVar4 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar4);
    CrLogUnLock();
  }
  uVar9 = 0xffffffff;
LAB_0040db00:
  decreaseAndDeallocate(unaff_s3);
  decreaseAndDeallocate(unaff_s2);
  return uVar9;
LAB_0040d8d8:
  PyList_SetItem(iVar7,iVar8,iVar5);
  iVar8 = iVar8 + 1;
  goto LAB_0040d690;
}



// WARNING: Removing unreachable block (ram,0x0040dfec)
// WARNING: Removing unreachable block (ram,0x0040dd14)
// WARNING: Removing unreachable block (ram,0x0040ddd4)

undefined4 FUN_0040db9c(undefined4 param_1,undefined4 param_2,char *param_3)

{
  int *count;
  int iVar1;
  size_t sVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  int *unaff_s6;
  uint uVar6;
  timeval local_40;
  timeval local_38;
  int local_30;
  
  count = (int *)PyTuple_New(2);
  if (count == (int *)0x0) {
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [%s %d] PyTuple_New Fail!!!\n","WARNING",
               "laserAi/LaserAiServer.c",0x275,"GetFlowDetectNewFromAi",0x275);
      sVar2 = strlen(&DAT_0044f2f8);
LAB_0040dc64:
      uVar4 = 3;
LAB_0040df60:
      CrLogWrite(uVar4,&DAT_0044f2f8,sVar2);
      CrLogUnLock();
    }
LAB_0040df70:
    PyErr_Print();
  }
  else {
    uVar4 = PyUnicode_FromString(param_1);
    PyTuple_SetItem(count,0,uVar4);
    uVar4 = PyUnicode_FromString(param_2);
    PyTuple_SetItem(count,1,uVar4);
    iVar1 = PyDict_GetItemString(DAT_0044f2f0,"flow_detection_new_version_4node");
    if ((iVar1 != 0) && (iVar3 = PyCallable_Check(iVar1), iVar3 != 0)) {
      gettimeofday(&local_38,(__timezone_ptr_t)0x0);
      iVar3 = (local_38.tv_sec * 1000000 + local_38.tv_usec) / 1000;
      unaff_s6 = (int *)PyObject_CallObject(iVar1,count);
      if ((unaff_s6 == (int *)0x0) || (iVar1 = PyErr_Occurred(), iVar1 != 0)) {
        gettimeofday(&local_40,(__timezone_ptr_t)0x0);
        iVar1 = GetLogLevel();
        if (iVar1 < 4) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar6 = (local_40.tv_sec * 1000000 + local_40.tv_usec) / 1000;
          uVar5 = uVar6 - iVar3;
          snprintf(&DAT_0044f2f8,0x800,
                   "[%s]-[%s](%d) [GetFlowDetectNewFromAi] return NULL time=%ldms","WARNING",
                   "laserAi/LaserAiServer.c",0x2a1,uVar5,
                   (((int)uVar6 >> 0x1f) - (iVar3 >> 0x1f)) - (uint)(uVar6 < uVar5));
          sVar2 = strlen(&DAT_0044f2f8);
          goto LAB_0040dc64;
        }
      }
      else {
        iVar1 = PyUnicode_AsUTF8(unaff_s6);
        if (iVar1 != 0) {
          gettimeofday(&local_40,(__timezone_ptr_t)0x0);
          local_30 = local_40.tv_usec;
          snprintf(param_3,0x40,"%s",iVar1);
          iVar1 = GetLogLevel();
          if (iVar1 < 3) {
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [GetFlowDetectNewFromAi]result=%s time=%ld",
                     &DAT_0042dfc4,"laserAi/LaserAiServer.c",0x295,param_3);
            sVar2 = strlen(&DAT_0044f2f8);
            CrLogWrite(2,&DAT_0044f2f8,sVar2);
            CrLogUnLock();
          }
          uVar4 = 0;
          goto LAB_0040de34;
        }
        iVar1 = GetLogLevel();
        if (iVar1 < 3) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          snprintf(&DAT_0044f2f8,0x800,
                   "[%s]-[%s](%d) [GetFlowDetectNewFromAi]PyUnicode_AsUTF8 return NULL",
                   &DAT_0042dfc4,"laserAi/LaserAiServer.c",0x297);
          sVar2 = strlen(&DAT_0044f2f8);
          uVar4 = 2;
          goto LAB_0040df60;
        }
      }
      goto LAB_0040df70;
    }
    iVar1 = GetLogLevel();
    if (3 < iVar1) {
      uVar4 = 0xffffffff;
      goto LAB_0040de34;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,
             "[%s]-[%s](%d) can\'t find python function [flow_detection_new_version_4node]\n",
             "WARNING","laserAi/LaserAiServer.c",0x281);
    sVar2 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar2);
    CrLogUnLock();
  }
  uVar4 = 0xffffffff;
LAB_0040de34:
  decreaseAndDeallocate(unaff_s6);
  decreaseAndDeallocate(count);
  return uVar4;
}



undefined4 FUN_0040e03c(char *param_1,char *param_2,char *param_3,undefined4 *param_4)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  size_t sVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  timeval local_28;
  char *local_20;
  
  local_20 = param_3;
  gettimeofday(&local_28,(__timezone_ptr_t)0x0);
  iVar5 = local_28.tv_usec;
  iVar1 = local_28.tv_sec;
  uVar2 = FUN_00413860(param_1,param_2,local_20);
  *param_4 = uVar2;
  iVar3 = GetLogLevel();
  if (iVar3 < 3) {
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    uVar2 = *param_4;
    gettimeofday(&local_28,(__timezone_ptr_t)0x0);
    uVar7 = local_28.tv_sec * 1000000 + local_28.tv_usec;
    iVar5 = iVar1 * 1000000 + iVar5;
    uVar6 = uVar7 - iVar5;
    __divdi3(uVar6,(((int)uVar7 >> 0x1f) - (iVar5 >> 0x1f)) - (uint)(uVar7 < uVar6),1000,0);
    snprintf(&DAT_0044f2f8,0x800,
             "[%s]-[%s](%d) [GetFirstLayerDetectNewFromAi]result=%d  time=%lld ms\n",&DAT_0042dfc4,
             "laserAi/LaserAiServer.c",699,uVar2);
    sVar4 = strlen(&DAT_0044f2f8);
    CrLogWrite(2,&DAT_0044f2f8,sVar4);
    CrLogUnLock();
  }
  return 0;
}



// WARNING: Removing unreachable block (ram,0x0040e3ac)
// WARNING: Removing unreachable block (ram,0x0040e308)
// WARNING: Removing unreachable block (ram,0x0040e5cc)

undefined4 FUN_0040e190(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  int *count;
  int iVar1;
  size_t sVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  int *unaff_s6;
  uint uVar6;
  timeval local_40;
  timeval local_38;
  int local_30;
  
  count = (int *)PyTuple_New(2);
  if (count == (int *)0x0) {
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [%s %d] PyTuple_New Fail!!!\n","WARNING",
               "laserAi/LaserAiServer.c",0x2cd,"GetLaserAutoTestResultFromAi",0x2cd);
      sVar2 = strlen(&DAT_0044f2f8);
LAB_0040e258:
      uVar4 = 3;
LAB_0040e540:
      CrLogWrite(uVar4,&DAT_0044f2f8,sVar2);
      CrLogUnLock();
    }
LAB_0040e550:
    PyErr_Print();
  }
  else {
    uVar4 = PyUnicode_FromString(param_1);
    PyTuple_SetItem(count,0,uVar4);
    uVar4 = PyUnicode_FromString(param_2);
    PyTuple_SetItem(count,1,uVar4);
    iVar1 = PyDict_GetItemString(DAT_0044f2f0,"ai_laser_install_factory");
    if ((iVar1 != 0) && (iVar3 = PyCallable_Check(iVar1), iVar3 != 0)) {
      gettimeofday(&local_38,(__timezone_ptr_t)0x0);
      iVar3 = (local_38.tv_sec * 1000000 + local_38.tv_usec) / 1000;
      unaff_s6 = (int *)PyObject_CallObject(iVar1,count);
      if ((unaff_s6 == (int *)0x0) || (iVar1 = PyErr_Occurred(), iVar1 != 0)) {
        gettimeofday(&local_40,(__timezone_ptr_t)0x0);
        iVar1 = GetLogLevel();
        if (iVar1 < 4) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar6 = (local_40.tv_sec * 1000000 + local_40.tv_usec) / 1000;
          uVar5 = uVar6 - iVar3;
          snprintf(&DAT_0044f2f8,0x800,
                   "[%s]-[%s](%d) [GetLaserAutoTestResultFromAi] return NULL time=%ldms","WARNING",
                   "laserAi/LaserAiServer.c",0x2f7,uVar5,
                   (((int)uVar6 >> 0x1f) - (iVar3 >> 0x1f)) - (uint)(uVar6 < uVar5));
          sVar2 = strlen(&DAT_0044f2f8);
          goto LAB_0040e258;
        }
      }
      else {
        iVar1 = PyArg_Parse(unaff_s6,&DAT_0042fcf4,param_3);
        if (iVar1 != 0) {
          gettimeofday(&local_40,(__timezone_ptr_t)0x0);
          local_30 = local_40.tv_usec;
          iVar1 = GetLogLevel();
          if (iVar1 < 3) {
            CrLogLock();
            memset(&DAT_0044f2f8,0,0x800);
            snprintf(&DAT_0044f2f8,0x800,
                     "[%s]-[%s](%d) [GetLaserAutoTestResultFromAi]result=%d time=%ld",&DAT_0042dfc4,
                     "laserAi/LaserAiServer.c",0x2eb,*param_3);
            sVar2 = strlen(&DAT_0044f2f8);
            CrLogWrite(2,&DAT_0044f2f8,sVar2);
            CrLogUnLock();
          }
          uVar4 = 0;
          goto LAB_0040e414;
        }
        iVar1 = GetLogLevel();
        if (iVar1 < 3) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          snprintf(&DAT_0044f2f8,0x800,
                   "[%s]-[%s](%d) [GetLaserAutoTestResultFromAi]PyArg_Parse return NULL",
                   &DAT_0042dfc4,"laserAi/LaserAiServer.c",0x2ed);
          sVar2 = strlen(&DAT_0044f2f8);
          uVar4 = 2;
          goto LAB_0040e540;
        }
      }
      goto LAB_0040e550;
    }
    iVar1 = GetLogLevel();
    if (3 < iVar1) {
      uVar4 = 0xffffffff;
      goto LAB_0040e414;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,
             "[%s]-[%s](%d) can\'t find python function [ai_laser_install_factory]\n","WARNING",
             "laserAi/LaserAiServer.c",0x2d9);
    sVar2 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar2);
    CrLogUnLock();
  }
  uVar4 = 0xffffffff;
LAB_0040e414:
  decreaseAndDeallocate(unaff_s6);
  decreaseAndDeallocate(count);
  return uVar4;
}



// WARNING: Removing unreachable block (ram,0x0040ea08)
// WARNING: Removing unreachable block (ram,0x0040e7b0)
// WARNING: Removing unreachable block (ram,0x0040e870)

undefined4
FUN_0040e61c(undefined4 param_1,undefined4 param_2,undefined8 *param_3,undefined8 *param_4)

{
  int *count;
  int iVar1;
  size_t sVar2;
  int iVar3;
  undefined4 uVar4;
  int *unaff_s4;
  undefined8 uVar5;
  uint uVar6;
  timeval local_40;
  timeval local_38;
  int local_30;
  int local_2c;
  
  count = (int *)PyTuple_New(2);
  if (count == (int *)0x0) {
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) [%s %d] PyTuple_New Fail!!!\n","WARNING",
               "laserAi/LaserAiServer.c",0x30b,"GetLaserCorrection02mmResultFromAi",0x30b);
      sVar2 = strlen(&DAT_0044f2f8);
LAB_0040e6e8:
      CrLogWrite(3,&DAT_0044f2f8,sVar2);
      CrLogUnLock();
    }
LAB_0040e6f8:
    PyErr_Print();
  }
  else {
    uVar4 = PyUnicode_FromString(param_1);
    PyTuple_SetItem(count,0,uVar4);
    uVar4 = PyUnicode_FromString(param_2);
    PyTuple_SetItem(count,1,uVar4);
    iVar1 = PyDict_GetItemString(DAT_0044f2f0,"offsetDxDy");
    if ((iVar1 != 0) && (iVar3 = PyCallable_Check(iVar1), iVar3 != 0)) {
      gettimeofday(&local_38,(__timezone_ptr_t)0x0);
      iVar3 = (local_38.tv_sec * 1000000 + local_38.tv_usec) / 1000;
      unaff_s4 = (int *)PyObject_CallObject(iVar1,count);
      if ((unaff_s4 != (int *)0x0) && (iVar1 = PyErr_Occurred(), iVar1 == 0)) {
        gettimeofday(&local_40,(__timezone_ptr_t)0x0);
        local_30 = local_40.tv_sec;
        local_2c = local_40.tv_usec;
        uVar4 = PyTuple_GetItem(unaff_s4,0);
        uVar5 = PyFloat_AsDouble(uVar4);
        *param_3 = uVar5;
        uVar4 = PyTuple_GetItem(unaff_s4,1);
        uVar5 = PyFloat_AsDouble(uVar4);
        *param_4 = uVar5;
        iVar1 = GetLogLevel();
        if (iVar1 < 3) {
          CrLogLock();
          memset(&DAT_0044f2f8,0,0x800);
          uVar6 = (local_30 * 1000000 + local_2c) / 1000;
          snprintf(&DAT_0044f2f8,0x800,
                   "[%s]-[%s](%d) [GetLaserCorrection02mmResultFromAi]x_offset=%f y_offset=%f time=%ld"
                   ,&DAT_0042dfc4,"laserAi/LaserAiServer.c",0x329,*param_3,*param_4,uVar6 - iVar3,
                   (((int)uVar6 >> 0x1f) - (iVar3 >> 0x1f)) - (uint)(uVar6 < uVar6 - iVar3));
          sVar2 = strlen(&DAT_0044f2f8);
          CrLogWrite(2,&DAT_0044f2f8,sVar2);
          CrLogUnLock();
        }
        uVar4 = 0;
        goto LAB_0040e8e4;
      }
      gettimeofday(&local_40,(__timezone_ptr_t)0x0);
      iVar1 = GetLogLevel();
      if (iVar1 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar6 = (local_40.tv_sec * 1000000 + local_40.tv_usec) / 1000;
        snprintf(&DAT_0044f2f8,0x800,
                 "[%s]-[%s](%d) [GetLaserCorrection02mmResultFromAi] return NULL time=%ldms",
                 "WARNING","laserAi/LaserAiServer.c",0x32f,uVar6 - iVar3,
                 (((int)uVar6 >> 0x1f) - (iVar3 >> 0x1f)) - (uint)(uVar6 < uVar6 - iVar3));
        sVar2 = strlen(&DAT_0044f2f8);
        goto LAB_0040e6e8;
      }
      goto LAB_0040e6f8;
    }
    iVar1 = GetLogLevel();
    if (3 < iVar1) {
      uVar4 = 0xffffffff;
      goto LAB_0040e8e4;
    }
    CrLogLock();
    memset(&DAT_0044f2f8,0,0x800);
    snprintf(&DAT_0044f2f8,0x800,"[%s]-[%s](%d) can\'t find python function [offsetDxDy]\n",
             "WARNING","laserAi/LaserAiServer.c",0x317);
    sVar2 = strlen(&DAT_0044f2f8);
    CrLogWrite(3,&DAT_0044f2f8,sVar2);
    CrLogUnLock();
  }
  uVar4 = 0xffffffff;
LAB_0040e8e4:
  decreaseAndDeallocate(unaff_s4);
  decreaseAndDeallocate(count);
  return uVar4;
}



undefined4 FUN_0040ea58(void)

{
  int iVar1;
  size_t sVar2;
  char *__format;
  undefined4 uVar3;
  
  Py_Initialize();
  iVar1 = Py_IsInitialized();
  if (iVar1 == 0) {
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044f2f8,0,0x800);
      uVar3 = 0x344;
      __format = "[%s]-[%s](%d) python init fail\n";
      goto LAB_0040eadc;
    }
  }
  else {
    PyRun_SimpleStringFlags("import sys",0);
    PyRun_SimpleStringFlags("sys.path.append(\'/usr/lib/\')",0);
    DAT_0044f2f4 = PyImport_ImportModule("ai_app_laser");
    if (DAT_0044f2f4 == 0) {
      iVar1 = GetLogLevel();
      if (iVar1 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar3 = 0x352;
        __format = "[%s]-[%s](%d) Cant open python file!\n";
LAB_0040eadc:
        snprintf(&DAT_0044f2f8,0x800,__format,"WARNING","laserAi/LaserAiServer.c",uVar3);
        sVar2 = strlen(&DAT_0044f2f8);
        CrLogWrite(3,&DAT_0044f2f8,sVar2);
        CrLogUnLock();
        return 0xffffffff;
      }
    }
    else {
      DAT_0044f2f0 = PyModule_GetDict(DAT_0044f2f4);
      if (DAT_0044f2f0 != 0) {
        return 0;
      }
      iVar1 = GetLogLevel();
      if (iVar1 < 4) {
        CrLogLock();
        memset(&DAT_0044f2f8,0,0x800);
        uVar3 = 0x359;
        __format = "[%s]-[%s](%d) Cant find dictionary\n";
        goto LAB_0040eadc;
      }
    }
  }
  return 0xffffffff;
}



undefined4 FUN_0040ec08(void)

{
  decreaseAndDeallocate(DAT_0044f2f4);
  Py_Finalize();
  return 0;
}



// WARNING: Removing unreachable block (ram,0x0040ed10)

int FUN_0040ec40(void *param_1,size_t param_2,int param_3)

{
  int iVar1;
  size_t sVar2;
  __fd_mask *p_Var3;
  int iVar4;
  __fd_mask local_a0 [32];
  timeval local_20;
  
  if ((int)DAT_0044d8a0 < 0) {
    iVar4 = -1;
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044fb04,0,0x800);
      snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) The device cannot be used\n","WARNING",
               "laser/SerialPort.c",0xb4);
      sVar2 = strlen(&DAT_0044fb04);
      CrLogWrite(3,&DAT_0044fb04,sVar2);
      CrLogUnLock();
    }
  }
  else {
    local_20.tv_sec = param_3 / 1000;
    iVar4 = 0;
    local_20.tv_usec = (param_3 % 1000) * 1000;
    p_Var3 = local_a0;
    do {
      iVar4 = iVar4 + 1;
      *p_Var3 = 0;
      p_Var3 = p_Var3 + 1;
    } while (iVar4 != 0x20);
    p_Var3 = local_a0 + ((int)DAT_0044d8a0 >> 5);
    *p_Var3 = 1 << (DAT_0044d8a0 & 0x1f) | *p_Var3;
    iVar4 = select(DAT_0044d8a0 + 1,(fd_set *)local_a0,(fd_set *)0x0,(fd_set *)0x0,&local_20);
    if (0 < iVar4) {
      iVar4 = read(DAT_0044d8a0,param_1,param_2);
    }
  }
  return iVar4;
}



size_t FUN_0040eda8(void *param_1,size_t param_2)

{
  int iVar1;
  size_t sVar2;
  size_t sVar3;
  
  if (DAT_0044d8a0 < 0) {
    sVar3 = 0xffffffff;
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044fb04,0,0x800);
      snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) The device cannot be used\n","WARNING",
               "laser/SerialPort.c",0xd1);
      sVar2 = strlen(&DAT_0044fb04);
      CrLogWrite(3,&DAT_0044fb04,sVar2);
      CrLogUnLock();
    }
  }
  else {
    sVar3 = write(DAT_0044d8a0,param_1,param_2);
    if (param_2 != sVar3) {
      iVar1 = GetLogLevel();
      if (iVar1 < 4) {
        CrLogLock();
        memset(&DAT_0044fb04,0,0x800);
        snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) write device error\n","WARNING",
                 "laser/SerialPort.c",0xda);
        sVar3 = strlen(&DAT_0044fb04);
        CrLogWrite(3,&DAT_0044fb04,sVar3);
        CrLogUnLock();
      }
      sVar3 = 0xffffffff;
      tcflush(DAT_0044d8a0,1);
    }
  }
  return sVar3;
}



undefined4 FUN_0040ef18(char *param_1)

{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  size_t sVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined auStack_80 [60];
  undefined4 local_44;
  undefined local_37;
  undefined local_36;
  
  DAT_0044d8a0 = open(param_1,0x882);
  if (DAT_0044d8a0 < 0) {
    uVar7 = 0xffffffff;
    iVar1 = GetLogLevel();
    if (3 < iVar1) {
      return 0xffffffff;
    }
    CrLogLock();
    memset(&DAT_0044fb04,0,0x800);
    piVar2 = __errno_location();
    pcVar3 = strerror(*piVar2);
    snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) device open fail, name = %s, err = %s\n","WARNING",
             "laser/SerialPort.c",0xea,param_1,pcVar3);
    sVar4 = strlen(&DAT_0044fb04);
    uVar6 = 3;
    goto LAB_0040efd0;
  }
  iVar1 = fcntl(DAT_0044d8a0,4,0);
  if (iVar1 < 0) {
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044fb04,0,0x800);
      snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) fcntl failed!\n","WARNING","laser/SerialPort.c",
               0xf0);
      sVar4 = strlen(&DAT_0044fb04);
      uVar7 = 3;
LAB_0040f070:
      CrLogWrite(uVar7,&DAT_0044fb04,sVar4);
      CrLogUnLock();
    }
  }
  else {
    iVar1 = GetLogLevel();
    if (iVar1 < 3) {
      CrLogLock();
      memset(&DAT_0044fb04,0,0x800);
      iVar1 = fcntl(DAT_0044d8a0,4,0);
      snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) fcntl=%d\n",&DAT_0042dfc4,"laser/SerialPort.c",
               0xf3,iVar1);
      sVar4 = strlen(&DAT_0044fb04);
      uVar7 = 2;
      goto LAB_0040f070;
    }
  }
  iVar1 = isatty(DAT_0044d8a0);
  if (iVar1 == 0) {
    iVar1 = GetLogLevel();
    if (iVar1 < 4) {
      CrLogLock();
      memset(&DAT_0044fb04,0,0x800);
      snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) standard input is not a terminal device\n",
               "WARNING","laser/SerialPort.c",0xf7);
      sVar4 = strlen(&DAT_0044fb04);
      CrLogWrite(3,&DAT_0044fb04,sVar4);
      CrLogUnLock();
    }
    close(DAT_0044d8a0);
    DAT_0044d8a0 = 0xffffffff;
    return 0xffffffff;
  }
  iVar1 = GetLogLevel();
  if (iVar1 < 3) {
    CrLogLock();
    memset(&DAT_0044fb04,0,0x800);
    snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) is a tty success!, name = %s\n",&DAT_0042dfc4,
             "laser/SerialPort.c",0xfd,param_1);
    sVar4 = strlen(&DAT_0044fb04);
    CrLogWrite(2,&DAT_0044fb04,sVar4);
    CrLogUnLock();
  }
  iVar1 = GetLogLevel();
  if (iVar1 < 3) {
    CrLogLock();
    memset(&DAT_0044fb04,0,0x800);
    snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) fd-open=%d\n",&DAT_0042dfc4,"laser/SerialPort.c",
             0xff,DAT_0044d8a0);
    sVar4 = strlen(&DAT_0044fb04);
    CrLogWrite(2,&DAT_0044fb04,sVar4);
    CrLogUnLock();
  }
  iVar1 = DAT_0044d8a0;
  iVar5 = tcgetattr(DAT_0044d8a0,(termios *)auStack_80);
  if (iVar5 == 0) {
    memset(auStack_80 + 0x34,0,0x34);
    local_44 = 0x8b0;
    cfsetispeed((termios *)(auStack_80 + 0x34),0x100a);
    cfsetospeed((termios *)(auStack_80 + 0x34),0x100a);
    local_36 = 1;
    local_37 = 1;
    tcflush(iVar1,0);
    iVar1 = tcsetattr(iVar1,0x540e,(termios *)(auStack_80 + 0x34));
    if (iVar1 == 0) {
      iVar1 = GetLogLevel();
      if (iVar1 < 3) {
        CrLogLock();
        memset(&DAT_0044fb04,0,0x800);
        snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) Serial set done!\n",&DAT_0042dfc4,
                 "laser/SerialPort.c",0xa5);
        sVar4 = strlen(&DAT_0044fb04);
        CrLogWrite(2,&DAT_0044fb04,sVar4);
        CrLogUnLock();
      }
      iVar1 = DAT_0044d8a0;
      tcflush(DAT_0044d8a0,2);
      fcntl(iVar1,4,0);
      DAT_0044fb00 = 1;
      iVar1 = GetLogLevel();
      if (2 < iVar1) {
        return 0;
      }
      CrLogLock();
      memset(&DAT_0044fb04,0,0x800);
      snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) Serial Port Init success!\n\n",&DAT_0042dfc4,
               "laser/SerialPort.c",0x10d);
      sVar4 = strlen(&DAT_0044fb04);
      uVar6 = 2;
      uVar7 = 0;
LAB_0040efd0:
      CrLogWrite(uVar6,&DAT_0044fb04,sVar4);
      CrLogUnLock();
      return uVar7;
    }
    iVar1 = GetLogLevel();
    if (3 < iVar1) goto LAB_0040f368;
    CrLogLock();
    memset(&DAT_0044fb04,0,0x800);
    uVar7 = 0xa1;
    pcVar3 = "[%s]-[%s](%d) Setup Serial fail 2!\n";
  }
  else {
    iVar1 = GetLogLevel();
    if (3 < iVar1) goto LAB_0040f368;
    CrLogLock();
    memset(&DAT_0044fb04,0,0x800);
    uVar7 = 0x36;
    pcVar3 = "[%s]-[%s](%d) Setup Serial fail 1!\n";
  }
  snprintf(&DAT_0044fb04,0x800,pcVar3,"WARNING","laser/SerialPort.c",uVar7);
  sVar4 = strlen(&DAT_0044fb04);
  CrLogWrite(3,&DAT_0044fb04,sVar4);
  CrLogUnLock();
LAB_0040f368:
  fputs("Set opt Error\n",stderr);
  close(DAT_0044d8a0);
                    // WARNING: Subroutine does not return
  DAT_0044d8a0 = 0xffffffff;
  exit(1);
}



undefined4 FUN_0040f55c(void)

{
  int iVar1;
  size_t sVar2;
  
  if (0 < DAT_0044d8a0) {
    close(DAT_0044d8a0);
    DAT_0044d8a0 = -1;
  }
  iVar1 = GetLogLevel();
  if (iVar1 < 3) {
    CrLogLock();
    memset(&DAT_0044fb04,0,0x800);
    snprintf(&DAT_0044fb04,0x800,"[%s]-[%s](%d) Serial Port Deinit\n",&DAT_0042dfc4,
             "laser/SerialPort.c",0x11c);
    sVar2 = strlen(&DAT_0044fb04);
    CrLogWrite(2,&DAT_0044fb04,sVar2);
    CrLogUnLock();
  }
  DAT_0044fb00 = 0;
  return 0;
}



undefined4 FUN_0040f620(void)

{
  return DAT_0044fb00;
}



uint FUN_0040f640(uint param_1,void *param_2,size_t param_3)

{
  int iVar1;
  byte *pbVar2;
  uint uVar3;
  int iVar4;
  size_t sVar5;
  ushort uVar6;
  uint uVar7;
  uint uVar8;
  byte *pbVar9;
  char *__format;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  byte *destination;
  ushort uVar13;
  char *apcStack_440 [2];
  uint auStack_438 [2];
  byte abStack_430 [8];
  undefined auStack_428 [1024];
  
  iVar1 = -(param_3 + 7 & 0xfffffff8);
  destination = abStack_430 + iVar1;
  uVar12 = 0;
  memset(destination,0,param_3);
  uVar13 = 0;
  do {
    memset(auStack_428,0,0x400);
    uVar3 = FUN_0040ec40(auStack_428,0x400,10);
    if ((int)uVar3 < 1) {
      if (uVar12 != 0) {
        uVar3 = 0;
        do {
          pbVar2 = destination + uVar3;
          do {
            pbVar9 = pbVar2;
            uVar10 = uVar3;
            if (uVar12 <= uVar10) {
              iVar4 = GetLogLevel();
              if (3 < iVar4) {
                return 0xffffffff;
              }
              CrLogLock();
              memset(&DAT_00450314,0,0x800);
              *(undefined4 *)((int)apcStack_440 + iVar1 + 4) = 0x6c;
              *(uint *)((int)apcStack_440 + iVar1 + 8) = uVar12;
              *(char **)((int)apcStack_440 + iVar1) = "laser/LaserDrive.c";
              __format = "[%s]-[%s](%d) no find data header, recvLen = %d\n";
              goto LAB_0040f85c;
            }
            uVar8 = uVar10 + 1 & 0xffff;
            uVar3 = uVar8;
            pbVar2 = pbVar9 + 1;
          } while (*pbVar9 != 0xaf);
          uVar3 = uVar10 + 2 & 0xffff;
        } while (destination[uVar8] != 0xff);
        if (destination[uVar10 + 4 & 0xffff] == 2) {
          if (destination[uVar10 + 5 & 0xffff] == param_1) {
            uVar8 = (uint)destination[uVar10 + 3 & 0xffff] * 0x100 + (uint)destination[uVar3] &
                    0xffff;
            uVar3 = uVar8 - 2 & 0xffff;
            if (param_3 < uVar3) {
              iVar4 = GetLogLevel();
              if (3 < iVar4) {
                return 0xffffffff;
              }
              CrLogLock();
              memset(&DAT_00450314,0,0x800);
              *(undefined4 *)((int)apcStack_440 + iVar1 + 4) = 0x89;
              *(char **)((int)apcStack_440 + iVar1) = "laser/LaserDrive.c";
              snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) data len more than max len\n","WARNING");
              goto LAB_0040fa08;
            }
            uVar10 = uVar10 + 6 & 0xffff;
            if (param_2 != (void *)0x0) {
              memcpy(param_2,destination + uVar10,uVar3);
            }
            uVar11 = uVar10 + uVar3 & 0xffff;
            uVar10 = 0;
            for (uVar7 = 0; uVar7 <= uVar8 + 3; uVar7 = uVar7 + 1 & 0xffff) {
              uVar10 = uVar10 + pbVar9[uVar7] & 0xffff;
            }
            if (((uint)destination[uVar11] == (-uVar10 & 0xff)) &&
               ((uint)destination[uVar11 + 1 & 0xffff] == (-uVar10 & 0xffff) >> 8)) {
              return uVar3;
            }
            if (param_2 != (void *)0x0) {
              memset(param_2,0,param_3);
            }
            iVar4 = GetLogLevel();
            if (3 < iVar4) {
              return 0xffffffff;
            }
            CrLogLock();
            memset(&DAT_00450314,0,0x800);
            *(undefined4 *)((int)apcStack_440 + iVar1 + 4) = 0x9f;
            *(uint *)((int)apcStack_440 + iVar1 + 8) = uVar12;
            *(char **)((int)apcStack_440 + iVar1) = "laser/LaserDrive.c";
            __format = "[%s]-[%s](%d) data check fail, recvLen = %d\n";
          }
          else {
            iVar4 = GetLogLevel();
            if (3 < iVar4) {
              return 0xffffffff;
            }
            CrLogLock();
            memset(&DAT_00450314,0,0x800);
            *(undefined4 *)((int)apcStack_440 + iVar1 + 4) = 0x83;
            *(uint *)((int)apcStack_440 + iVar1 + 8) = uVar12;
            *(char **)((int)apcStack_440 + iVar1) = "laser/LaserDrive.c";
            __format = "[%s]-[%s](%d) frame cmd fail, recvLen = %d\n";
          }
        }
        else {
          iVar4 = GetLogLevel();
          if (3 < iVar4) {
            return 0xffffffff;
          }
          CrLogLock();
          memset(&DAT_00450314,0,0x800);
          *(undefined4 *)((int)apcStack_440 + iVar1 + 4) = 0x7e;
          *(uint *)((int)apcStack_440 + iVar1 + 8) = uVar12;
          *(char **)((int)apcStack_440 + iVar1) = "laser/LaserDrive.c";
          __format = "[%s]-[%s](%d) frame source fail, recvLen = %d\n";
        }
LAB_0040f85c:
        snprintf(&DAT_00450314,0x800,__format,"WARNING");
LAB_0040fa08:
        sVar5 = strlen(&DAT_00450314);
        CrLogWrite(3,&DAT_00450314,sVar5);
        CrLogUnLock();
        return 0xffffffff;
      }
LAB_0040f718:
      uVar6 = uVar13 + 1;
      if (800 < uVar13) {
        iVar4 = GetLogLevel();
        if (iVar4 < 4) {
          CrLogLock();
          memset(&DAT_00450314,0,0x800);
          *(undefined4 *)((int)apcStack_440 + iVar1 + 4) = 0x5d;
          *(char **)((int)apcStack_440 + iVar1) = "laser/LaserDrive.c";
          snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) recv timeout\n","WARNING");
          sVar5 = strlen(&DAT_00450314);
          CrLogWrite(3,&DAT_00450314,sVar5);
          CrLogUnLock();
        }
        return 0xfffffffe;
      }
    }
    else {
      uVar6 = uVar13;
      if (uVar12 == 0) goto LAB_0040f718;
    }
    if ((int)param_3 < (int)(uVar12 + uVar3)) {
      uVar3 = param_3 - uVar12;
    }
    memcpy(destination + uVar12,auStack_428,uVar3 & 0xffff);
    uVar12 = uVar12 + (uVar3 & 0xffff) & 0xffff;
    uVar13 = uVar6;
  } while( true );
}



uint sendCommandAndGetResponse
               (uint param_1,void *param_2,size_t param_3,void *param_4,ushort param_5)

{
  int result;
  size_t logLength;
  uint checksumSize;
  uint uVar1;
  uint uVar2;
  char *__format;
  byte *buffer;
  undefined4 uVar3;
  byte responseBuffer [8];
  
  result = FUN_0040f620();
  if (result == 0) {
    checksumSize = 0xffffffff;
    result = GetLogLevel();
    if (3 < result) {
      return 0xffffffff;
    }
    CrLogLock();
    memset(&DAT_00450314,0,0x800);
    uVar3 = 0xb0;
    __format = "[%s]-[%s](%d) serial port not init\n";
  }
  else {
    result = -(param_3 + 0x11 & 0xfffffff8);
    buffer = responseBuffer + result;
    memset(buffer,0,param_3 + 10);
    responseBuffer[result] = 0xaf;
    responseBuffer[result + 1] = 0xff;
    checksumSize = param_3 + 2 & 0xffff;
    responseBuffer[result + 2] = (byte)checksumSize;
    responseBuffer[result + 3] = (byte)(checksumSize >> 8);
    responseBuffer[result + 4] = 1;
    responseBuffer[result + 5] = (byte)param_1;
    memcpy(responseBuffer + result + 6,param_2,param_3);
    uVar1 = param_3 + 6 & 0xffff;
    checksumSize = 0;
    for (uVar2 = 0; (uVar2 & 0xffff) < uVar1; uVar2 = uVar2 + 1) {
      checksumSize = checksumSize + buffer[uVar2] & 0xffff;
    }
    buffer[uVar1] = (byte)(-checksumSize & 0xffff);
    buffer[param_3 + 7 & 0xffff] = (byte)((-checksumSize & 0xffff) >> 8);
    logLength = FUN_0040eda8(buffer,param_3 + 8 & 0xffff);
    if ((int)logLength < 0) {
      checksumSize = 0xfffffffe;
      result = GetLogLevel();
      if (3 < result) {
        return 0xfffffffe;
      }
      CrLogLock();
      memset(&DAT_00450314,0,0x800);
      uVar3 = 0xb6;
      __format = "[%s]-[%s](%d) send cmd fail\n";
    }
    else {
      checksumSize = FUN_0040f640(param_1,param_4,(uint)param_5);
      if (-1 < (int)checksumSize) {
        return checksumSize;
      }
      checksumSize = 0xfffffffd;
      result = GetLogLevel();
      if (3 < result) {
        return 0xfffffffd;
      }
      CrLogLock();
      memset(&DAT_00450314,0,0x800);
      uVar3 = 0xbd;
      __format = "[%s]-[%s](%d) recv cmd fail\n";
    }
  }
  snprintf(&DAT_00450314,0x800,__format,"WARNING","laser/LaserDrive.c",uVar3);
  logLength = strlen(&DAT_00450314);
  CrLogWrite(3,&DAT_00450314,logLength);
  CrLogUnLock();
  return checksumSize;
}



void FUN_0040fdb0(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(1,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_0040fddc(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(2,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_0040fe08(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(3,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_0040fe34(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(4,(void *)0x0,0,param_1,param_2);
  return;
}



void copyArrayHalves(undefined2 *sourceArray,uint arrayLength,undefined2 *destinationArray)

{
  int loopIndex;
  bool loopCondition;
  
  loopIndex = 0;
  while (loopCondition = loopIndex < (int)(arrayLength >> 1), loopIndex = loopIndex + 1,
        loopCondition) {
    *destinationArray = *sourceArray;
    sourceArray = sourceArray + 1;
    destinationArray = destinationArray + 1;
  }
  return;
}



void FUN_0040fe9c(void *param_1,ushort param_2,byte param_3)

{
  uint local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_18 = (uint)param_3;
  local_14 = 0;
  local_10 = 0;
  sendCommandAndGetResponse(5,&local_18,1,param_1,param_2);
  return;
}



void FUN_0040fed8(void *param_1,ushort param_2,byte param_3)

{
  uint local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_18 = (uint)param_3;
  local_14 = 0;
  local_10 = 0;
  sendCommandAndGetResponse(8,&local_18,1,param_1,param_2);
  return;
}



void FUN_0040ff14(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(9,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_0040ff40(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x11,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_0040ff6c(void *param_1,ushort param_2)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_14 = 0;
  local_10 = 0;
  local_18 = 1;
  sendCommandAndGetResponse(0x13,&local_18,1,param_1,param_2);
  return;
}



void FUN_0040ffac(void *param_1,ushort param_2)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_18 = 0;
  local_14 = 0;
  local_10 = 0;
  sendCommandAndGetResponse(0x13,&local_18,1,param_1,param_2);
  return;
}



void FUN_0040ffe4(void *param_1,ushort param_2)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_14 = 0;
  local_10 = 0;
  local_18 = 1;
  sendCommandAndGetResponse(0x14,&local_18,1,param_1,param_2);
  return;
}



void FUN_00410024(void *param_1,ushort param_2)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_18 = 0;
  local_14 = 0;
  local_10 = 0;
  sendCommandAndGetResponse(0x14,&local_18,1,param_1,param_2);
  return;
}



void FUN_0041005c(void *param_1,ushort param_2,undefined param_3,undefined param_4)

{
  undefined local_18;
  undefined local_17;
  undefined2 local_16;
  undefined2 local_14;
  undefined2 local_12;
  undefined2 local_10;
  
  local_16 = 0;
  local_14 = 0;
  local_12 = 0;
  local_10 = 0;
  local_18 = param_3;
  local_17 = param_4;
  sendCommandAndGetResponse(0x56,&local_18,2,param_1,param_2);
  return;
}



void FUN_004100a0(void *param_1,ushort param_2,byte param_3)

{
  uint local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_18 = (uint)param_3;
  local_14 = 0;
  local_10 = 0;
  sendCommandAndGetResponse(0x57,&local_18,1,param_1,param_2);
  return;
}



void FUN_004100dc(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x55,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_00410108(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x10,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_00410134(void *param_1,ushort param_2,undefined4 param_3)

{
  undefined local_10;
  undefined local_f;
  undefined local_e;
  
  local_10 = (undefined)param_3;
  local_e = (undefined)((uint)param_3 >> 0x10);
  local_f = (undefined)((uint)param_3 >> 8);
  sendCommandAndGetResponse(0x19,&local_10,3,param_1,param_2);
  return;
}



void FUN_00410174(void *param_1,undefined4 param_2,undefined4 param_3,void *param_4,size_t param_5)

{
  int iVar1;
  undefined4 auStack_38 [2];
  undefined auStack_30 [12];
  
  iVar1 = -(param_5 + 9 & 0xfffffff8);
  memset(auStack_30 + iVar1,0,param_5 + 2);
  auStack_30[iVar1] = (char)param_3;
  auStack_30[iVar1 + 1] = (char)((uint)param_3 >> 8);
  memcpy(auStack_30 + iVar1 + 2,param_4,param_5);
  *(undefined4 *)((int)auStack_38 + iVar1) = param_2;
  sendCommandAndGetResponse
            (0x1a,auStack_30 + iVar1,param_5 + 2 & 0xffff,param_1,
             *(ushort *)((int)auStack_38 + iVar1));
  return;
}



uint FUN_00410240(void *param_1,ushort param_2,uint param_3,uint param_4)

{
  uint uVar1;
  undefined local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  
  if (((param_3 < 0x641) && (param_3 <= param_4)) && (param_4 < 0x641)) {
    local_10 = (undefined)param_3;
    local_f = (undefined)(param_3 >> 8);
    local_e = (undefined)param_4;
    local_d = (undefined)(param_4 >> 8);
    uVar1 = sendCommandAndGetResponse(10,&local_10,4,param_1,param_2);
    return uVar1;
  }
  return 0xffffffff;
}



void FUN_004102b0(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0xb,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_004102dc(void *param_1,ushort param_2,undefined param_3)

{
  undefined local_10 [12];
  
  local_10[0] = param_3;
  sendCommandAndGetResponse(0xc,local_10,1,param_1,param_2);
  return;
}



void FUN_0041030c(void *param_1,ushort param_2,undefined param_3)

{
  undefined local_10 [12];
  
  local_10[0] = param_3;
  sendCommandAndGetResponse(6,local_10,1,param_1,param_2);
  return;
}



void FUN_0041033c(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0xd,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_00410368(void *param_1,ushort param_2,undefined param_3)

{
  undefined local_10 [12];
  
  local_10[0] = param_3;
  sendCommandAndGetResponse(0xe,local_10,1,param_1,param_2);
  return;
}



void FUN_00410398(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0xf,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_004103c4(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x12,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_004103f0(void *param_1,ushort param_2,undefined4 param_3)

{
  undefined local_10;
  undefined local_f;
  undefined local_e;
  
  local_10 = (undefined)param_3;
  local_e = (undefined)((uint)param_3 >> 0x10);
  local_f = (undefined)((uint)param_3 >> 8);
  sendCommandAndGetResponse(0x15,&local_10,3,param_1,param_2);
  return;
}



void FUN_00410430(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x16,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_0041045c(void *param_1,ushort param_2,undefined4 param_3)

{
  undefined local_10;
  undefined local_f;
  undefined local_e;
  
  local_10 = (undefined)param_3;
  local_e = (undefined)((uint)param_3 >> 0x10);
  local_f = (undefined)((uint)param_3 >> 8);
  sendCommandAndGetResponse(0x17,&local_10,3,param_1,param_2);
  return;
}



void FUN_0041049c(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x18,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_004104c8(void *param_1,ushort param_2,undefined param_3,undefined param_4)

{
  undefined local_10;
  undefined local_f;
  
  local_10 = param_3;
  local_f = param_4;
  sendCommandAndGetResponse(0x1b,&local_10,2,param_1,param_2);
  return;
}



void FUN_004104fc(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x1c,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_00410528(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x1d,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_00410554(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0x1e,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_00410580(void *param_1,ushort param_2)

{
  sendCommandAndGetResponse(0xa0,(void *)0x0,0,param_1,param_2);
  return;
}



void FUN_004105ac(void *param_1,ushort param_2,void *param_3,size_t param_4)

{
  sendCommandAndGetResponse(0xa1,param_3,param_4,param_1,param_2);
  return;
}



void FUN_004105dc(char *param_1,uchar *param_2,uchar *param_3)

{
  size_t sVar1;
  byte *pbVar2;
  int iVar3;
  int iVar4;
  uchar auStack_130 [128];
  char acStack_b0 [128];
  byte local_30 [20];
  
  sVar1 = strlen((char *)param_2);
  iVar3 = 0;
  MD5(param_2,sVar1,local_30);
  iVar4 = 0;
  memset(acStack_b0,0,0x80);
  do {
    pbVar2 = local_30 + iVar3;
    iVar3 = iVar3 + 1;
    sprintf(acStack_b0 + iVar4,"%02x",(uint)*pbVar2);
    iVar4 = iVar4 + 2;
  } while (iVar3 != 0x10);
  memset(auStack_130,0,0x80);
  strcat((char *)auStack_130,param_1);
  strcat((char *)auStack_130,acStack_b0);
  sVar1 = strlen((char *)auStack_130);
  SHA256(auStack_130,sVar1,param_3);
  return;
}



int FUN_004106d0(void)

{
  int iVar1;
  int iVar2;
  size_t sVar3;
  char *__format;
  undefined4 uVar4;
  byte local_1a0 [128];
  char acStack_120 [128];
  byte local_a0;
  byte local_9f;
  byte local_9e;
  byte local_9d;
  byte local_9c;
  char local_9b;
  char local_9a;
  char local_99;
  char local_98;
  uchar auStack_3c [32];
  uchar local_1c;
  char local_1b;
  char local_1a;
  char local_19;
  undefined local_18;
  
  memset(&local_a0,0,100);
  iVar1 = FUN_00410580(&local_a0,100);
  if ((iVar1 < 0) || (local_a0 != 0)) {
    iVar2 = GetLogLevel();
    if (3 < iVar2) {
      return iVar1;
    }
    CrLogLock();
    memset(&DAT_00450314,0,0x800);
    uVar4 = 700;
    __format = "[%s]-[%s](%d) GetModuleAuthenticationStr fail!! %d\n";
  }
  else {
    memset(acStack_120,0,0x80);
    snprintf(acStack_120,0x80,"%d",
             (-(uint)local_9e & 0xff) << 8 |
             (uint)local_9c * -0x1000000 | (-(uint)local_9d & 0xff) << 0x10 | -(uint)local_9f & 0xff
            );
    local_1c = -local_9b;
    local_18 = 0;
    local_1b = -local_9a;
    local_1a = -local_99;
    local_19 = -local_98;
    memset(auStack_3c,0,0x20);
    FUN_004105dc(acStack_120,&local_1c,auStack_3c);
    memset(local_1a0,0,0x80);
    iVar1 = FUN_004105ac(local_1a0,0x80,auStack_3c,0x20);
    if ((-1 < iVar1) && (local_1a0[0] == 0)) {
      iVar2 = GetLogLevel();
      if (2 < iVar2) {
        return iVar1;
      }
      CrLogLock();
      memset(&DAT_00450314,0,0x800);
      snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) Send Encryption Key success!!\n",&DAT_0042dfc4,
               "laser/LaserDrive.c",0x2dd);
      sVar3 = strlen(&DAT_00450314);
      uVar4 = 2;
      goto LAB_0041078c;
    }
    iVar2 = GetLogLevel();
    if (3 < iVar2) {
      return iVar1;
    }
    CrLogLock();
    memset(&DAT_00450314,0,0x800);
    uVar4 = 0x2da;
    __format = "[%s]-[%s](%d) Send Encryption Key fail!! %d\n";
    local_a0 = local_1a0[0];
  }
  snprintf(&DAT_00450314,0x800,__format,"WARNING","laser/LaserDrive.c",uVar4,(uint)local_a0);
  sVar3 = strlen(&DAT_00450314);
  uVar4 = 3;
LAB_0041078c:
  CrLogWrite(uVar4,&DAT_00450314,sVar3);
  CrLogUnLock();
  return iVar1;
}



undefined4 FUN_00410980(char *param_1)

{
  int iVar1;
  size_t sVar2;
  char *__format;
  undefined4 uVar3;
  byte local_158;
  byte local_157;
  byte local_156;
  byte local_f4 [100];
  undefined auStack_90 [64];
  byte local_50;
  byte local_4f;
  byte local_4e;
  byte local_4d;
  byte local_4c;
  byte local_4b;
  byte local_4a;
  byte local_49;
  byte local_48;
  byte local_47;
  byte local_46;
  byte local_45;
  
  iVar1 = FUN_0040ef18(param_1);
  if (iVar1 == 0) {
    memset(local_f4,0,100);
    iVar1 = FUN_004100dc(local_f4,100);
    if ((iVar1 < 0) || (local_f4[0] != 0)) {
      iVar1 = GetLogLevel();
      if (iVar1 < 4) {
        CrLogLock();
        memset(&DAT_00450314,0,0x800);
        snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) module init fail\n","WARNING",
                 "laser/LaserDrive.c",0x2f2);
        sVar2 = strlen(&DAT_00450314);
        CrLogWrite(3,&DAT_00450314,sVar2);
        CrLogUnLock();
      }
      if (((local_f4[0] & 1) != 0) && (iVar1 = GetLogLevel(), iVar1 < 4)) {
        CrLogLock();
        memset(&DAT_00450314,0,0x800);
        snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) IR sensor I2C fail\n","WARNING",
                 "laser/LaserDrive.c",0x2f3);
        sVar2 = strlen(&DAT_00450314);
        CrLogWrite(3,&DAT_00450314,sVar2);
        CrLogUnLock();
      }
      if (((local_f4[0] & 2) != 0) && (iVar1 = GetLogLevel(), iVar1 < 4)) {
        CrLogLock();
        memset(&DAT_00450314,0,0x800);
        snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) laser starter I2C fail\n","WARNING",
                 "laser/LaserDrive.c",0x2f4);
        sVar2 = strlen(&DAT_00450314);
        CrLogWrite(3,&DAT_00450314,sVar2);
        CrLogUnLock();
      }
      if (((local_f4[0] & 4) != 0) && (iVar1 = GetLogLevel(), iVar1 < 4)) {
        CrLogLock();
        memset(&DAT_00450314,0,0x800);
        snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) IR sensor mipi fail\n","WARNING",
                 "laser/LaserDrive.c",0x2f5);
        sVar2 = strlen(&DAT_00450314);
        CrLogWrite(3,&DAT_00450314,sVar2);
        CrLogUnLock();
      }
      if ((local_f4[0] & 8) == 0) {
        return 0xffffffff;
      }
      iVar1 = GetLogLevel();
      if (3 < iVar1) {
        return 0xffffffff;
      }
      CrLogLock();
      memset(&DAT_00450314,0,0x800);
      uVar3 = 0x2f6;
      __format = "[%s]-[%s](%d) Algorithm init fail\n";
    }
    else {
      iVar1 = GetLogLevel();
      if (iVar1 < 3) {
        CrLogLock();
        memset(&DAT_00450314,0,0x800);
        snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) module init finish\n",&DAT_0042dfc4,
                 "laser/LaserDrive.c",0x301);
        sVar2 = strlen(&DAT_00450314);
        CrLogWrite(2,&DAT_00450314,sVar2);
        CrLogUnLock();
      }
      memset(&local_158,0,100);
      iVar1 = FUN_0040fe08(&local_158,100);
      if (iVar1 < 0) {
        iVar1 = GetLogLevel();
        if (2 < iVar1) {
          return 0xffffffff;
        }
        CrLogLock();
        memset(&DAT_00450314,0,0x800);
        snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) get software version fail\n",&DAT_0042dfc4,
                 "laser/LaserDrive.c",0x306);
        sVar2 = strlen(&DAT_00450314);
        uVar3 = 2;
        goto LAB_00410e04;
      }
      iVar1 = GetLogLevel();
      if (iVar1 < 3) {
        CrLogLock();
        memset(&DAT_00450314,0,0x800);
        snprintf(&DAT_00450314,0x800,"[%s]-[%s](%d) software version = %d_%d_%d\n",&DAT_0042dfc4,
                 "laser/LaserDrive.c",0x309,(uint)local_158,(uint)local_157,(uint)local_156);
        sVar2 = strlen(&DAT_00450314);
        CrLogWrite(2,&DAT_00450314,sVar2);
        CrLogUnLock();
      }
      memset(&local_50,0,0x40);
      iVar1 = FUN_00410528(&local_50,0x40);
      if (((0 < iVar1) && (local_50 == 0)) && (iVar1 = GetLogLevel(), iVar1 < 3)) {
        CrLogLock();
        memset(&DAT_00450314,0,0x800);
        snprintf(&DAT_00450314,0x800,
                 "[%s]-[%s](%d) SN number = %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                 &DAT_0042dfc4,"laser/LaserDrive.c",0x30f,(uint)local_50,(uint)local_4f,
                 (uint)local_4e,(uint)local_4d,(uint)local_4c,(uint)local_4b,(uint)local_4a,
                 (uint)local_49,(uint)local_48,(uint)local_47,(uint)local_46,(uint)local_45);
        sVar2 = strlen(&DAT_00450314);
        CrLogWrite(2,&DAT_00450314,sVar2);
        CrLogUnLock();
      }
      memset(auStack_90,0,0x40);
      iVar1 = FUN_00410368(auStack_90,0x40,1);
      if (-1 < iVar1) {
        DAT_00450310 = 1;
        return 0;
      }
      iVar1 = GetLogLevel();
      if (3 < iVar1) {
        return 0xffffffff;
      }
      CrLogLock();
      memset(&DAT_00450314,0,0x800);
      uVar3 = 0x314;
      __format = "[%s]-[%s](%d) set coor fail\n";
    }
  }
  else {
    iVar1 = GetLogLevel();
    if (3 < iVar1) {
      return 0xffffffff;
    }
    CrLogLock();
    memset(&DAT_00450314,0,0x800);
    uVar3 = 0x2eb;
    __format = "[%s]-[%s](%d) serial port init fail\n";
  }
  snprintf(&DAT_00450314,0x800,__format,"WARNING","laser/LaserDrive.c",uVar3);
  sVar2 = strlen(&DAT_00450314);
  uVar3 = 3;
LAB_00410e04:
  CrLogWrite(uVar3,&DAT_00450314,sVar2);
  CrLogUnLock();
  return 0xffffffff;
}



undefined4 FUN_004122d8(void)

{
  FUN_0040f55c();
  DAT_00450310 = 0;
  return 0;
}



undefined4 FUN_00412300(void)

{
  return DAT_00450310;
}



undefined4 FUN_00412310(int param_1,float *param_2,float *param_3)

{
  int iVar1;
  float *pfVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  undefined auStack_10c [28];
  undefined auStack_f0 [28];
  undefined auStack_d4 [28];
  undefined auStack_b8 [28];
  undefined auStack_9c [28];
  undefined auStack_80 [28];
  uint local_64;
  int local_60;
  int local_5c;
  uint local_58;
  int local_54;
  int local_50;
  undefined auStack_4c [28];
  undefined auStack_30 [36];
  
  setValuesInArrayFromMemory(&local_58,param_1,0,1);
  MaybeProccessDataBlock((int)auStack_4c,param_1,local_58,local_54,local_50,0);
  setValuesInArrayFromMemory(&local_64,param_1,0,1);
                    // try { // try from 004123b4 to 004123bb has its CatchHandler @ 00412670
  MaybeProccessDataBlock((int)auStack_30,param_1,local_64,local_60,local_5c,2);
  iVar1 = FUN_00418280((int)auStack_4c);
                    // try { // try from 004123e4 to 0041247b has its CatchHandler @ 00412654
  FUN_00418328((int)auStack_80,(int)auStack_4c,0);
  pfVar2 = (float *)FUN_0041888c((int)auStack_80,0);
  fVar3 = *pfVar2;
  FUN_00418168((int)auStack_80);
  FUN_00418328((int)auStack_9c,(int)auStack_30,0);
  pfVar2 = (float *)FUN_0041888c((int)auStack_9c,0);
  fVar4 = *pfVar2;
  FUN_00418168((int)auStack_9c);
  FUN_00418930((int)auStack_d4,(int)auStack_4c);
                    // try { // try from 00412490 to 00412497 has its CatchHandler @ 0041261c
  FUN_00418328((int)auStack_b8,(int)auStack_d4,0);
  pfVar2 = (float *)FUN_0041888c((int)auStack_b8,0);
  fVar5 = *pfVar2;
  FUN_00418168((int)auStack_b8);
  FUN_00418168((int)auStack_d4);
                    // try { // try from 004124ec to 004124f3 has its CatchHandler @ 00412654
  FUN_00418a24((int)auStack_10c,(int)auStack_4c,(int)auStack_30);
                    // try { // try from 00412508 to 0041250f has its CatchHandler @ 00412638
  FUN_00418328((int)auStack_f0,(int)auStack_10c,0);
  pfVar2 = (float *)FUN_0041888c((int)auStack_f0,0);
  fVar6 = *pfVar2;
  FUN_00418168((int)auStack_f0);
  FUN_00418168((int)auStack_10c);
  *param_3 = (fVar4 * fVar5 - fVar3 * fVar6) / ((float)iVar1 * fVar5 - fVar3 * fVar3);
  *param_2 = ((float)iVar1 * fVar6 - fVar3 * fVar4) / ((float)iVar1 * fVar5 - fVar3 * fVar3);
  FUN_00418168((int)auStack_30);
  FUN_00418168((int)auStack_4c);
  return 0;
}



int FUN_004126b0(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined auStack_30 [36];
  
  FUN_00418a74((int)auStack_30,param_3,param_2);
                    // try { // try from 00412700 to 00412707 has its CatchHandler @ 00412720
  FUN_00418afc(param_1,(int)auStack_30,param_4);
  FUN_00418168((int)auStack_30);
  return param_1;
}



int FUN_00412764(int param_1,int param_2,float param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined auStack_d0 [28];
  undefined auStack_b4 [28];
  undefined auStack_98 [28];
  undefined auStack_7c [28];
  uint local_60;
  int local_5c;
  int local_58;
  uint local_54;
  int local_50;
  int local_4c;
  undefined auStack_48 [28];
  undefined auStack_2c [32];
  
  setValuesInArrayFromMemory(&local_54,param_2,0,1);
  MaybeProccessDataBlock((int)auStack_48,param_2,local_54,local_50,local_4c,0);
  setValuesInArrayFromMemory(&local_60,param_2,0,1);
                    // try { // try from 0041280c to 00412813 has its CatchHandler @ 004129bc
  MaybeProccessDataBlock((int)auStack_2c,param_2,local_60,local_5c,local_58,1);
                    // try { // try from 00412828 to 0041282f has its CatchHandler @ 004129a0
  FUN_00418a74((int)auStack_d0,param_3,(int)auStack_48);
                    // try { // try from 00412844 to 0041284b has its CatchHandler @ 00412984
  FUN_00418bf8((int)auStack_b4,param_4,(int)auStack_d0);
                    // try { // try from 00412864 to 0041286b has its CatchHandler @ 00412968
  FUN_00418c48((int)auStack_98,(int)auStack_b4,(int)auStack_2c);
                    // try { // try from 0041287c to 00412883 has its CatchHandler @ 0041294c
  FUN_004163c0((int)auStack_7c,(int)auStack_98);
  uVar1 = FUN_00414e60(param_3 * param_3 + 1.0);
                    // try { // try from 004128bc to 004128c3 has its CatchHandler @ 00412930
  FUN_00419244(param_1,(int)auStack_7c,uVar1);
  FUN_00418168((int)auStack_7c);
  FUN_00418168((int)auStack_98);
  FUN_00418168((int)auStack_b4);
  FUN_00418168((int)auStack_d0);
  FUN_00418168((int)auStack_2c);
  FUN_00418168((int)auStack_48);
  return param_1;
}



// WARNING: Control flow encountered bad instruction data

undefined4 FUN_00412a00(int param_1,int param_2,int param_3,undefined4 *param_4,float *param_5)

{
  int iVar1;
  float *pfVar2;
  uint uVar3;
  double *pdVar4;
  undefined4 **ppuVar5;
  undefined4 uVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  undefined auStack_4c4 [28];
  undefined auStack_4a8 [28];
  undefined auStack_48c [28];
  uint local_470;
  int local_46c;
  int local_468;
  undefined auStack_464 [28];
  undefined auStack_448 [28];
  uint local_42c;
  int local_428;
  int local_424;
  undefined auStack_420 [28];
  undefined auStack_404 [28];
  undefined auStack_3e8 [28];
  uint local_3cc;
  int local_3c8;
  int local_3c4;
  undefined auStack_3c0 [28];
  undefined auStack_3a4 [28];
  uint local_388;
  int local_384;
  int local_380;
  undefined auStack_37c [28];
  undefined auStack_360 [28];
  undefined auStack_344 [28];
  uint local_328;
  int local_324;
  int local_320;
  undefined auStack_31c [28];
  undefined auStack_300 [28];
  uint local_2e4;
  int local_2e0;
  int local_2dc;
  undefined auStack_2d8 [28];
  undefined auStack_2bc [28];
  uint local_2a0;
  int local_29c;
  int local_298;
  undefined auStack_294 [28];
  undefined auStack_278 [28];
  uint local_25c;
  int local_258;
  int local_254;
  undefined auStack_250 [28];
  undefined auStack_234 [28];
  undefined auStack_218 [28];
  undefined auStack_1fc [28];
  undefined auStack_1e0 [28];
  undefined auStack_1c4 [28];
  undefined4 *apuStack_1a8 [7];
  undefined auStack_18c [28];
  undefined **local_170;
  undefined4 local_16c;
  uint local_168;
  int local_164;
  int local_160;
  uint local_15c;
  int local_158;
  int local_154;
  undefined8 local_150;
  undefined auStack_148 [28];
  undefined auStack_12c [28];
  undefined auStack_110 [28];
  undefined auStack_f4 [28];
  undefined auStack_d8 [28];
  undefined auStack_bc [28];
  undefined auStack_a0 [28];
  undefined auStack_84 [28];
  undefined auStack_68 [28];
  undefined auStack_4c [28];
  undefined auStack_30 [32];
  
  setValuesInArrayFromMemory(&local_15c,param_2,0,1);
  MaybeProccessDataBlock((int)auStack_148,param_2,local_15c,local_158,local_154,0);
  setValuesInArrayFromMemory(&local_168,param_2,0,1);
                    // try { // try from 00412ab0 to 00412ab7 has its CatchHandler @ 0041381c
  MaybeProccessDataBlock((int)auStack_12c,param_2,local_168,local_164,local_160,2);
                    // try { // try from 00412acc to 00412afb has its CatchHandler @ 00413800
  FUN_00412310(param_1,(float *)&local_150,(float *)((int)&local_150 + 4));
  FUN_004126b0((int)auStack_110,(int)auStack_148,(int)local_150,(int)((ulonglong)local_150 >> 0x20))
  ;
                    // try { // try from 00412b0c to 00412b2f has its CatchHandler @ 004137e4
  FUN_00419340((int)apuStack_1a8,(int)auStack_148);
  FUN_00419340((int)auStack_18c,(int)auStack_12c);
  local_170 = (undefined **)apuStack_1a8;
  local_16c = 2;
                    // try { // try from 00412b54 to 00412b5b has its CatchHandler @ 004134d0
  FUN_00419474((int)auStack_f4,local_170,2,2);
  ppuVar5 = &local_170;
  while (ppuVar5 != apuStack_1a8) {
    ppuVar5 = ppuVar5 + -7;
    FUN_00418168((int)ppuVar5);
  }
                    // try { // try from 00412ba8 to 00412baf has its CatchHandler @ 004137c8
  FUN_00412764((int)auStack_d8,(int)auStack_f4,(float)local_150,(int)((ulonglong)local_150 >> 0x20))
  ;
                    // try { // try from 00412bd0 to 00412bd7 has its CatchHandler @ 004137ac
  FUN_00419758((int)auStack_1c4,(int)auStack_d8,0x3d6147ae);
                    // try { // try from 00412bf0 to 00412bf7 has its CatchHandler @ 00413528
  FUN_004198e4((int)auStack_1e0,(int)auStack_12c,(int)auStack_110);
                    // try { // try from 00412c10 to 00412c17 has its CatchHandler @ 0041350c
  FUN_00419be4((int)auStack_bc,(int)auStack_1c4,(int)auStack_1e0);
  FUN_0041778c((int)auStack_1e0);
  FUN_0041778c((int)auStack_1c4);
                    // try { // try from 00412c50 to 00412c57 has its CatchHandler @ 00413790
  FUN_00419c34((int)auStack_1fc,(int)auStack_bc,1,2);
                    // try { // try from 00412c70 to 00412c77 has its CatchHandler @ 00413544
  FUN_00419f14((int)auStack_a0,(int)auStack_f4,(int)auStack_1fc);
  FUN_0041778c((int)auStack_1fc);
                    // try { // try from 00412ca0 to 00412ca7 has its CatchHandler @ 00413774
  FUN_00419f14((int)auStack_84,(int)auStack_d8,(int)auStack_bc);
                    // try { // try from 00412cc8 to 00412ccf has its CatchHandler @ 00413758
  FUN_0041a288((int)auStack_218,(int)auStack_d8,0x3ecccccd);
                    // try { // try from 00412ce8 to 00412cef has its CatchHandler @ 00413560
  FUN_00419f14((int)auStack_68,(int)auStack_d8,(int)auStack_218);
  FUN_0041778c((int)auStack_218);
  iVar1 = FUN_00418280((int)auStack_a0);
  if (iVar1 == 0) {
    setValuesInArrayFromMemory(&local_25c,param_2,0,1);
                    // try { // try from 00412d74 to 00412d7b has its CatchHandler @ 0041373c
    MaybeProccessDataBlock((int)auStack_250,param_2,local_25c,local_258,local_254,0);
                    // try { // try from 00412d90 to 00412d97 has its CatchHandler @ 0041357c
    FUN_0041a414((int)auStack_234,(int)auStack_250,0);
    pfVar2 = (float *)FUN_0041888c((int)auStack_234,0);
    fVar7 = *pfVar2;
    FUN_00418168((int)auStack_234);
    FUN_00418168((int)auStack_250);
    setValuesInArrayFromMemory(&local_2a0,param_2,0,1);
                    // try { // try from 00412e10 to 00412e17 has its CatchHandler @ 0041373c
    MaybeProccessDataBlock((int)auStack_294,param_2,local_2a0,local_29c,local_298,0);
                    // try { // try from 00412e2c to 00412e33 has its CatchHandler @ 00413598
    FUN_0041aa40((int)auStack_278,(int)auStack_294,0);
    pfVar2 = (float *)FUN_0041888c((int)auStack_278,0);
    fVar8 = *pfVar2;
    FUN_00418168((int)auStack_278);
    FUN_00418168((int)auStack_294);
    setValuesInArrayFromMemory(&local_2e4,param_2,0,1);
                    // try { // try from 00412eb0 to 00412eb7 has its CatchHandler @ 0041373c
    MaybeProccessDataBlock((int)auStack_2d8,param_2,local_2e4,local_2e0,local_2dc,1);
                    // try { // try from 00412ecc to 00412ed3 has its CatchHandler @ 004135b4
    FUN_0041a414((int)auStack_2bc,(int)auStack_2d8,0);
    pfVar2 = (float *)FUN_0041888c((int)auStack_2bc,0);
    fVar9 = *pfVar2;
    FUN_00418168((int)auStack_2bc);
    FUN_00418168((int)auStack_2d8);
    setValuesInArrayFromMemory(&local_328,param_2,0,1);
                    // try { // try from 00412f50 to 00412f57 has its CatchHandler @ 0041373c
    MaybeProccessDataBlock((int)auStack_31c,param_2,local_328,local_324,local_320,1);
                    // try { // try from 00412f6c to 00412f73 has its CatchHandler @ 004135d0
    FUN_0041aa40((int)auStack_300,(int)auStack_31c,0);
    pfVar2 = (float *)FUN_0041888c((int)auStack_300,0);
    fVar10 = *pfVar2;
    FUN_00418168((int)auStack_300);
    FUN_00418168((int)auStack_31c);
    setValuesInArrayFromMemory(&local_388,param_3,0,1);
                    // try { // try from 0041302c to 00413033 has its CatchHandler @ 0041373c
    MaybeProccessDataBlock((int)auStack_37c,param_3,local_388,local_384,local_380,0);
                    // try { // try from 00413048 to 0041304f has its CatchHandler @ 004136e8
    FUN_0041a288((int)auStack_360,(int)auStack_37c,fVar7 - 1.0);
    setValuesInArrayFromMemory(&local_3cc,param_3,0,1);
                    // try { // try from 0041308c to 00413093 has its CatchHandler @ 004136cc
    MaybeProccessDataBlock((int)auStack_3c0,param_3,local_3cc,local_3c8,local_3c4,0);
                    // try { // try from 004130a8 to 004130af has its CatchHandler @ 004136b0
    FUN_0041b028((int)auStack_3a4,(int)auStack_3c0,fVar8 + 1.0);
                    // try { // try from 004130c8 to 004130cf has its CatchHandler @ 00413694
    FUN_0041b124((int)auStack_344,(int)auStack_360,(int)auStack_3a4);
    setValuesInArrayFromMemory(&local_42c,param_3,0,1);
                    // try { // try from 00413110 to 00413117 has its CatchHandler @ 00413678
    MaybeProccessDataBlock((int)auStack_420,param_3,local_42c,local_428,local_424,1);
                    // try { // try from 0041312c to 00413133 has its CatchHandler @ 0041365c
    FUN_0041a288((int)auStack_404,(int)auStack_420,fVar9 - 0.3);
    setValuesInArrayFromMemory(&local_470,param_3,0,1);
                    // try { // try from 00413174 to 0041317b has its CatchHandler @ 00413640
    MaybeProccessDataBlock((int)auStack_464,param_3,local_470,local_46c,local_468,1);
                    // try { // try from 00413190 to 00413197 has its CatchHandler @ 00413624
    FUN_0041b028((int)auStack_448,(int)auStack_464,fVar10 + 0.3);
                    // try { // try from 004131b0 to 004131b7 has its CatchHandler @ 00413608
    FUN_0041b124((int)auStack_3e8,(int)auStack_404,(int)auStack_448);
                    // try { // try from 004131d0 to 004131d7 has its CatchHandler @ 004135ec
    FUN_00419be4((int)auStack_4c,(int)auStack_344,(int)auStack_3e8);
    FUN_0041778c((int)auStack_3e8);
    FUN_0041778c((int)auStack_448);
    FUN_00418168((int)auStack_464);
    FUN_0041778c((int)auStack_404);
    FUN_00418168((int)auStack_420);
    FUN_0041778c((int)auStack_344);
    FUN_0041778c((int)auStack_3a4);
    FUN_00418168((int)auStack_3c0);
    FUN_0041778c((int)auStack_360);
    FUN_00418168((int)auStack_37c);
                    // try { // try from 00413290 to 00413297 has its CatchHandler @ 00413720
    FUN_00419c34((int)auStack_48c,(int)auStack_4c,1,3);
                    // try { // try from 004132ac to 004132b3 has its CatchHandler @ 00413704
    FUN_00419f14((int)auStack_30,param_3,(int)auStack_48c);
    FUN_0041778c((int)auStack_48c);
    iVar1 = FUN_00418280((int)auStack_30);
    if (iVar1 == 0) {
      uVar6 = 0x14;
    }
    else {
      uVar6 = 2;
    }
    FUN_00418168((int)auStack_30);
    FUN_0041778c((int)auStack_4c);
  }
  else {
    uVar3 = FUN_00418280((int)auStack_68);
    if (uVar3 < 0x3c) {
      FUN_0041b1ac((int)auStack_4c4,(int)auStack_84,0);
      FUN_004172f8((int)auStack_4c4,0);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar6 = FUN_00418280((int)auStack_68);
    *param_4 = uVar6;
                    // try { // try from 00413370 to 004133d3 has its CatchHandler @ 0041373c
    FUN_0041b1ac((int)auStack_4a8,(int)auStack_68,0);
    pdVar4 = (double *)FUN_004172f8((int)auStack_4a8,0);
    *param_5 = (float)*pdVar4;
    FUN_00416f88((int)auStack_4a8);
    uVar6 = 1;
  }
  FUN_00418168((int)auStack_68);
  FUN_00418168((int)auStack_84);
  FUN_00418168((int)auStack_a0);
  FUN_0041778c((int)auStack_bc);
  FUN_00418168((int)auStack_d8);
  FUN_00418168((int)auStack_f4);
  FUN_00418168((int)auStack_110);
  FUN_00418168((int)auStack_12c);
  FUN_00418168((int)auStack_148);
  return uVar6;
}



// WARNING: Control flow encountered bad instruction data

undefined4 FUN_00413860(char *param_1,char *param_2,char *param_3)

{
  bool bVar1;
  int iVar2;
  size_t sVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  float *pfVar9;
  int iVar10;
  undefined4 *puVar11;
  int iVar12;
  int *piVar13;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined4 uVar14;
  float fVar15;
  int local_180;
  int local_17c;
  int local_178;
  int local_174;
  undefined4 uStack_124;
  int aiStack_120 [2];
  int iStack_118;
  undefined4 local_114;
  int local_110;
  int local_10c;
  undefined4 local_108;
  int local_104;
  int local_100;
  undefined4 local_fc;
  int local_f8;
  int local_f4;
  undefined4 uStack_f0;
  float fStack_ec;
  char acStack_e8 [64];
  undefined auStack_a8 [28];
  undefined auStack_8c [28];
  undefined4 auStack_70 [3];
  undefined4 auStack_64 [3];
  undefined auStack_58 [28];
  undefined auStack_3c [28];
  int iStack_20;
  int aiStack_1c [2];
  
  local_174 = 0;
  memset(acStack_e8,0,0x40);
  if (((param_1 == (char *)0x0) || (param_2 == (char *)0x0)) || (param_3 == (char *)0x0)) {
    iVar2 = GetLogLevel();
    if (iVar2 < 5) {
      CrLogLock();
      bzero(&DAT_004514f0,0x800);
      snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) file path is invalid!\n","ERROR",
               "laserAi/LaserAiAlgo.cpp",0xd1);
      sVar3 = strlen(&DAT_004514f0);
      CrLogWrite(4,&DAT_004514f0,sVar3);
      CrLogUnLock();
    }
    uVar14 = 0xffffffff;
  }
  else {
    iVar2 = access(param_1,0);
    if (((iVar2 == 0) && (iVar2 = access(param_2,0), iVar2 == 0)) &&
       (iVar2 = access(param_3,0), iVar2 == 0)) {
      bVar1 = true;
    }
    else {
      bVar1 = false;
    }
    if (bVar1) {
      iVar2 = json_object_from_file(param_1);
      if (iVar2 == 0) {
        iVar2 = GetLogLevel();
        if (iVar2 < 5) {
          CrLogLock();
          bzero(&DAT_004514f0,0x800);
          snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) load json file: %s failed!\n","ERROR",
                   "laserAi/LaserAiAlgo.cpp",0xdb,param_1);
          sVar3 = strlen(&DAT_004514f0);
          CrLogWrite(4,&DAT_004514f0,sVar3);
          CrLogUnLock();
        }
        uVar14 = 6;
      }
      else {
        local_178 = json_object_object_length(iVar2);
        iVar4 = json_object_from_file(param_2);
        if (iVar4 == 0) {
          iVar2 = GetLogLevel();
          if (iVar2 < 5) {
            CrLogLock();
            bzero(&DAT_004514f0,0x800);
            snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) load json file: %s failed!\n","ERROR",
                     "laserAi/LaserAiAlgo.cpp",0xe3,param_2);
            sVar3 = strlen(&DAT_004514f0);
            CrLogWrite(4,&DAT_004514f0,sVar3);
            CrLogUnLock();
          }
          uVar14 = 7;
        }
        else {
          iVar5 = json_object_object_length(iVar4);
          if (iVar5 < local_178) {
            local_178 = iVar5;
          }
          iVar5 = json_object_from_file(param_3);
          if (iVar5 == 0) {
            iVar2 = GetLogLevel();
            if (iVar2 < 5) {
              CrLogLock();
              bzero(&DAT_004514f0,0x800);
              snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) load json file: %s failed!\n","ERROR",
                       "laserAi/LaserAiAlgo.cpp",0xf0,param_3);
              sVar3 = strlen(&DAT_004514f0);
              CrLogWrite(4,&DAT_004514f0,sVar3);
              CrLogUnLock();
            }
            uVar14 = 8;
          }
          else {
            iVar6 = json_object_array_length(iVar5);
            FUN_0041b7e0((int)auStack_a8,iVar6,3);
            for (local_180 = 0; local_180 < iVar6; local_180 = local_180 + 1) {
                    // try { // try from 00413cd8 to 00413e0f has its CatchHandler @ 00414abc
              uVar14 = json_object_array_get_idx(iVar5,local_180);
              uVar7 = json_object_array_get_idx(uVar14,0);
              iVar8 = json_object_get_int(uVar7);
              fVar15 = (float)iVar8;
              pfVar9 = (float *)calculateOffset((int)auStack_a8,local_180,0);
              *pfVar9 = fVar15 / 1000.0;
              uVar7 = json_object_array_get_idx(uVar14,1);
              iVar8 = json_object_get_int(uVar7);
              fVar15 = (float)iVar8;
              pfVar9 = (float *)calculateOffset((int)auStack_a8,local_180,1);
              *pfVar9 = fVar15 / 1000.0;
              uVar14 = json_object_array_get_idx(uVar14,2);
              iVar8 = json_object_get_int(uVar14);
              fVar15 = (float)iVar8;
              pfVar9 = (float *)calculateOffset((int)auStack_a8,local_180,2);
              *pfVar9 = fVar15 / 1000.0;
            }
            json_object_put(iVar5);
            FUN_0041b940((int)auStack_8c,1,local_178);
            FUN_0041ba58(auStack_70);
            FUN_0041bb20(auStack_64);
            for (local_180 = 0; local_180 < local_178; local_180 = local_180 + 1) {
              memset(acStack_e8,0,0x40);
              sprintf(acStack_e8,"table%d",local_180);
                    // try { // try from 00413e88 to 004140bf has its CatchHandler @ 00414a80
              iVar5 = json_object_object_get(iVar2,acStack_e8);
              if (iVar5 == 0) {
                iVar2 = GetLogLevel();
                if (iVar2 < 5) {
                  CrLogLock();
                  bzero(&DAT_004514f0,0x800);
                  snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) get object failed!\n","ERROR",
                           "laserAi/LaserAiAlgo.cpp",0x107);
                  sVar3 = strlen(&DAT_004514f0);
                  CrLogWrite(4,&DAT_004514f0,sVar3);
                  CrLogUnLock();
                }
                uVar14 = 0xffffffff;
                goto LAB_004149f0;
              }
              iVar6 = json_object_array_length(iVar5);
              memset(acStack_e8,0,0x40);
              sprintf(acStack_e8,"scan%d",local_180);
              iVar8 = json_object_object_get(iVar4,acStack_e8);
              if (iVar8 == 0) {
                iVar2 = GetLogLevel();
                if (iVar2 < 5) {
                  CrLogLock();
                  bzero(&DAT_004514f0,0x800);
                  snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) get object failed!\n","ERROR",
                           "laserAi/LaserAiAlgo.cpp",0x111);
                  sVar3 = strlen(&DAT_004514f0);
                  CrLogWrite(4,&DAT_004514f0,sVar3);
                  CrLogUnLock();
                }
                uVar14 = 0xffffffff;
                goto LAB_004149f0;
              }
              iVar10 = json_object_array_length(iVar8);
              if ((iVar6 == 0) || (iVar10 == 0)) {
                puVar11 = (undefined4 *)FUN_0041bbe8((int)auStack_8c,0,local_180);
                *puVar11 = 0;
              }
              else {
                FUN_0041b7e0((int)auStack_58,iVar6,3);
                for (local_17c = 0; local_17c < iVar6; local_17c = local_17c + 1) {
                    // try { // try from 004140e4 to 0041420f has its CatchHandler @ 00414a64
                  uVar14 = json_object_array_get_idx(iVar5,local_17c);
                  uVar7 = json_object_array_get_idx(uVar14,0);
                  iVar12 = json_object_get_int(uVar7);
                  fVar15 = (float)iVar12;
                  pfVar9 = (float *)calculateOffset((int)auStack_58,local_17c,0);
                  *pfVar9 = fVar15 / 1000.0;
                  uVar7 = json_object_array_get_idx(uVar14,1);
                  iVar12 = json_object_get_int(uVar7);
                  fVar15 = (float)iVar12;
                  pfVar9 = (float *)calculateOffset((int)auStack_58,local_17c,1);
                  *pfVar9 = fVar15 / 1000.0;
                  uVar14 = json_object_array_get_idx(uVar14,2);
                  iVar12 = json_object_get_int(uVar14);
                  fVar15 = (float)iVar12;
                  pfVar9 = (float *)calculateOffset((int)auStack_58,local_17c,2);
                  *pfVar9 = fVar15 / 1000.0;
                }
                FUN_0041b7e0((int)auStack_3c,iVar10,3);
                for (local_17c = 0; local_17c < iVar10; local_17c = local_17c + 1) {
                    // try { // try from 00414234 to 004143b7 has its CatchHandler @ 00414a48
                  uVar14 = json_object_array_get_idx(iVar8,local_17c);
                  uVar7 = json_object_array_get_idx(uVar14,0);
                  iVar5 = json_object_get_int(uVar7);
                  fVar15 = (float)iVar5;
                  pfVar9 = (float *)calculateOffset((int)auStack_3c,local_17c,0);
                  *pfVar9 = fVar15 / 1000.0;
                  uVar7 = json_object_array_get_idx(uVar14,1);
                  iVar5 = json_object_get_int(uVar7);
                  fVar15 = (float)iVar5;
                  pfVar9 = (float *)calculateOffset((int)auStack_3c,local_17c,1);
                  *pfVar9 = fVar15 / 1000.0;
                  uVar14 = json_object_array_get_idx(uVar14,2);
                  iVar5 = json_object_get_int(uVar14);
                  fVar15 = (float)iVar5;
                  pfVar9 = (float *)calculateOffset((int)auStack_3c,local_17c,2);
                  *pfVar9 = fVar15 / 1000.0;
                }
                iVar5 = FUN_00412a00((int)auStack_58,(int)auStack_3c,(int)auStack_a8,&uStack_f0,
                                     &fStack_ec);
                if (iVar5 == 1) {
                  FUN_0041bc7c((int)auStack_70,&uStack_f0);
                  FUN_0041bcd8((int)auStack_64,&fStack_ec);
                }
                piVar13 = (int *)FUN_0041bbe8((int)auStack_8c,0,local_180);
                *piVar13 = iVar5;
                FUN_00418168((int)auStack_3c);
                FUN_00418168((int)auStack_58);
              }
            }
                    // try { // try from 00414414 to 004147bf has its CatchHandler @ 00414a80
            json_object_put(iVar2);
            json_object_put(iVar4);
            malloc_trim(0);
            iVar2 = FUN_0041bd34((int)auStack_8c);
            FUN_0041bd60(&local_f4,(int)auStack_8c);
            FUN_0041bdac(&local_f8,(int)auStack_8c);
            local_fc = 1;
            iVar4 = FUN_0041be20(local_f4,local_f8,&local_fc);
            FUN_0041bd60(&local_100,(int)auStack_8c);
            FUN_0041bdac(&local_104,(int)auStack_8c);
            local_108 = 2;
            iVar5 = FUN_0041be20(local_100,local_104,&local_108);
            FUN_0041bd60(&local_10c,(int)auStack_8c);
            FUN_0041bdac(&local_110,(int)auStack_8c);
            local_114 = 3;
            iVar6 = FUN_0041be20(local_10c,local_110,&local_114);
            iVar8 = GetLogLevel();
            if (iVar8 < 3) {
              CrLogLock();
              bzero(&DAT_004514f0,0x800);
              snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) 1: %f%%\n",&DAT_00431fe4,
                       "laserAi/LaserAiAlgo.cpp",0x14a,
                       (double)(((float)iVar4 / (float)iVar2) * 100.0));
              sVar3 = strlen(&DAT_004514f0);
              CrLogWrite(2,&DAT_004514f0,sVar3);
              CrLogUnLock();
            }
            iVar4 = GetLogLevel();
            if (iVar4 < 3) {
              CrLogLock();
              bzero(&DAT_004514f0,0x800);
              snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) 2: %f%%\n",&DAT_00431fe4,
                       "laserAi/LaserAiAlgo.cpp",0x14b,
                       (double)(((float)iVar5 / (float)iVar2) * 100.0));
              sVar3 = strlen(&DAT_004514f0);
              CrLogWrite(2,&DAT_004514f0,sVar3);
              CrLogUnLock();
            }
            iVar4 = GetLogLevel();
            if (iVar4 < 3) {
              CrLogLock();
              bzero(&DAT_004514f0,0x800);
              snprintf(&DAT_004514f0,0x800,"[%s]-[%s](%d) 3: %f%%\n",&DAT_00431fe4,
                       "laserAi/LaserAiAlgo.cpp",0x14c,
                       (double)(((float)iVar6 / (float)iVar2) * 100.0));
              sVar3 = strlen(&DAT_004514f0);
              CrLogWrite(2,&DAT_004514f0,sVar3);
              CrLogUnLock();
            }
            FUN_0041be68(&iStack_20,auStack_64);
            FUN_0041beb4(&iStack_118,auStack_64);
            bVar1 = FUN_0041befc(&iStack_20,&iStack_118);
            if (CONCAT31(extraout_var,bVar1) != 0) {
              FUN_0041bf98(&iStack_20);
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            FUN_0041bfd8(aiStack_1c,auStack_70);
            while( true ) {
              FUN_0041c024(aiStack_120,auStack_70);
              bVar1 = FUN_0041c06c(aiStack_1c,aiStack_120);
              if (CONCAT31(extraout_var_00,bVar1) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              piVar13 = (int *)FUN_0041c108(aiStack_1c);
              if (2 < *piVar13) {
                local_174 = local_174 + 1;
              }
              if (1 < local_174) break;
              FUN_0041c0b0(&uStack_124,aiStack_1c);
            }
            uVar14 = 1;
LAB_004149f0:
            FUN_004164e8(auStack_64);
            FUN_004164a8(auStack_70);
            FUN_0041ba0c((int)auStack_8c);
            FUN_00418168((int)auStack_a8);
          }
        }
      }
    }
    else {
      uVar14 = 0xffffffff;
    }
  }
  return uVar14;
}



void FUN_00414b00(int param_1,int param_2)

{
  undefined *puVar1;
  
  if ((param_1 == 1) && (param_2 == 0xffff)) {
    std::ios_base::Init::Init((Init *)&DAT_00450b20);
    puVar1 = &DAT_00450b20;
    __cxa_atexit(std::ios_base::Init::~Init,&DAT_00450b20,&DAT_0044d8ec);
    FUN_004179b4((undefined8 *)&DAT_00450b28,puVar1,0x1571,0);
    if (DAT_00451e80 == '\0') {
      DAT_00451e80 = '\x01';
      FUN_00428040();
    }
    if (DAT_00451e88 == '\0') {
      DAT_00451e88 = '\x01';
      FUN_00428080();
    }
    if (DAT_00451e90 == '\0') {
      DAT_00451e90 = '\x01';
      FUN_0042b304(&DAT_00451e78,puVar1);
    }
    if (DAT_00451e98 == '\0') {
      DAT_00451e98 = '\x01';
      FUN_0042d4f0();
    }
  }
  return;
}



void _INIT_0(void)

{
  FUN_00414b00(1,0xffff);
  return;
}



float FUN_00414cb0(float param_1)

{
  return ABS(param_1);
}



void FUN_00414cdc(undefined8 param_1)

{
  ceill(param_1);
  return;
}



void FUN_00414d14(undefined8 param_1)

{
  expl(param_1);
  return;
}



double FUN_00414d4c(double param_1)

{
  return ABS(param_1);
}



void FUN_00414d78(undefined8 param_1)

{
  floorl(param_1);
  return;
}



void FUN_00414db0(undefined8 param_1)

{
  logl(param_1);
  return;
}



void FUN_00414de8(undefined8 param_1,undefined8 param_2)

{
  powl(param_1,param_2);
  return;
}



void FUN_00414e28(undefined8 param_1)

{
  sinl(param_1);
  return;
}



void FUN_00414e60(float param_1)

{
  sqrtf(param_1);
  return;
}



// WARNING: Control flow encountered bad instruction data

undefined4 FUN_00414e98(double param_1)

{
  if (NAN(ABS(param_1))) {
    return 0;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_00414f40(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



bool FUN_00414f9c(ulonglong param_1)

{
  return (param_1 & 0x8000000000000000) != 0;
}



undefined4 FUN_00414fd4(undefined4 param_1,undefined4 param_2)

{
  return param_2;
}



void FUN_00415000(char *param_1)

{
  strlen(param_1);
  return;
}



basic_string<> * FUN_00415038(basic_string<> *param_1)

{
  FUN_00416528(param_1,vsnprintf,0x10,&DAT_00431154);
  return param_1;
}



basic_string<> * FUN_00415098(basic_string<> *param_1)

{
  FUN_00416528(param_1,vsnprintf,0x10,&DAT_00431158);
  return param_1;
}



uint FUN_004150f8(uint param_1,uint param_2)

{
  return param_1 | param_2;
}



undefined4 FUN_0041512c(void)

{
  return 0x80000000;
}



undefined4 FUN_00415150(void)

{
  return 0x7fffffff;
}



undefined8 FUN_00415178(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



undefined8 FUN_004151a0(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



undefined8 FUN_004151c8(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



undefined8 FUN_004151f0(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



// what is the point of this and why is it called 11 times?
// 

void setTwoValues(undefined4 *destinationArray,undefined4 value1,undefined4 value2)

{
  *destinationArray = value1;
  destinationArray[1] = value2;
  return;
}



undefined4 FUN_00415260(int *param_1,int *param_2)

{
  undefined4 uVar1;
  
  if ((*param_1 == *param_2) && (param_1[1] == param_2[1])) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



uint FUN_004152c8(int *param_1,int *param_2)

{
  uint uVar1;
  
  uVar1 = FUN_00415260(param_1,param_2);
  return (uVar1 ^ 1) & 0xff;
}



int FUN_00415310(int *param_1)

{
  return *param_1 * param_1[1];
}



undefined4 FUN_00415348(int *param_1)

{
  undefined4 uVar1;
  
  if ((*param_1 == 0) && (param_1[1] == 0)) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



void GenericSetvaluesinarray
               (undefined4 *array,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  *array = param_2;
  array[1] = param_3;
  array[2] = param_4;
  return;
}



void FUN_004153f4(int *param_1,int param_2)

{
  allocator<char> aaStack_1b8 [4];
  basic_string<> abStack_1b4 [24];
  allocator<char> aaStack_19c [4];
  basic_string<> abStack_198 [24];
  allocator<char> aaStack_180 [4];
  basic_string<> abStack_17c [24];
  allocator<char> aaStack_164 [4];
  basic_string<> abStack_160 [24];
  allocator<char> aaStack_148 [4];
  basic_string<> abStack_144 [24];
  allocator<char> aaStack_12c [4];
  basic_string<> abStack_128 [24];
  basic_string<> abStack_110 [24];
  basic_string abStack_f8 [6];
  basic_string abStack_e0 [6];
  allocator<char> aaStack_c8 [4];
  basic_string<> abStack_c4 [24];
  allocator<char> aaStack_ac [4];
  basic_string<> abStack_a8 [24];
  basic_string<> abStack_90 [24];
  basic_string abStack_78 [6];
  basic_string abStack_60 [6];
  allocator<char> aaStack_48 [4];
  basic_string<> abStack_44 [24];
  allocator<char> aaStack_2c [4];
  basic_string<> abStack_28 [28];
  
  if (*param_1 < 0) {
    *param_1 = *param_1 + param_2;
  }
  if (param_2 + -1 < *param_1) {
    std::allocator<char>::allocator();
                    // try { // try from 00415484 to 0041548b has its CatchHandler @ 00415a88
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_28,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/Core/Slice.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 004154b4 to 004154bb has its CatchHandler @ 00415a5c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_44,(allocator *)"makePositiveAndValidate");
                    // try { // try from 004154c8 to 004154cf has its CatchHandler @ 00415a40
    FUN_0041685c(abStack_90);
                    // try { // try from 004154e8 to 004154ef has its CatchHandler @ 00415a24
    FUN_00416790(abStack_78,"Invalid start value for array of size ",(uint)abStack_90);
                    // try { // try from 00415508 to 0041550f has its CatchHandler @ 00415a08
    appendStringToBasicString(abStack_60,(char *)abStack_78);
                    // try { // try from 0041552c to 00415533 has its CatchHandler @ 004159ec
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_60);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_78);
    std::__cxx11::basic_string<>::~basic_string(abStack_90);
    std::__cxx11::basic_string<>::~basic_string(abStack_44);
    std::allocator<char>::~allocator(aaStack_48);
    std::__cxx11::basic_string<>::~basic_string(abStack_28);
    std::allocator<char>::~allocator(aaStack_2c);
  }
  if (param_1[1] < 0) {
    param_1[1] = param_1[1] + param_2;
  }
  if (param_2 < param_1[1]) {
    std::allocator<char>::allocator();
                    // try { // try from 00415614 to 0041561b has its CatchHandler @ 00415b48
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_a8,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/Core/Slice.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 00415644 to 0041564b has its CatchHandler @ 00415b1c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_c4,(allocator *)"makePositiveAndValidate");
                    // try { // try from 00415658 to 0041565f has its CatchHandler @ 00415b00
    FUN_0041685c(abStack_110);
                    // try { // try from 00415678 to 0041567f has its CatchHandler @ 00415ae4
    FUN_00416790(abStack_f8,"Invalid stop value for array of size ",(uint)abStack_110);
                    // try { // try from 00415698 to 0041569f has its CatchHandler @ 00415ac8
    appendStringToBasicString(abStack_e0,(char *)abStack_f8);
                    // try { // try from 004156bc to 004156c3 has its CatchHandler @ 00415aac
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_e0);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_f8);
    std::__cxx11::basic_string<>::~basic_string(abStack_110);
    std::__cxx11::basic_string<>::~basic_string(abStack_c4);
    std::allocator<char>::~allocator(aaStack_c8);
    std::__cxx11::basic_string<>::~basic_string(abStack_a8);
    std::allocator<char>::~allocator(aaStack_ac);
  }
  if ((*param_1 < param_1[1]) && (param_1[2] < 0)) {
    std::allocator<char>::allocator();
                    // try { // try from 00415788 to 0041578f has its CatchHandler @ 00415be0
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_128,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/Core/Slice.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 004157b8 to 004157bf has its CatchHandler @ 00415bb4
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_144,(allocator *)"makePositiveAndValidate");
    std::allocator<char>::allocator();
                    // try { // try from 004157e8 to 004157ef has its CatchHandler @ 00415b88
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_160,(allocator *)"Invalid slice values.");
                    // try { // try from 0041580c to 00415813 has its CatchHandler @ 00415b6c
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_160);
    std::allocator<char>::~allocator(aaStack_164);
    std::__cxx11::basic_string<>::~basic_string(abStack_144);
    std::allocator<char>::~allocator(aaStack_148);
    std::__cxx11::basic_string<>::~basic_string(abStack_128);
    std::allocator<char>::~allocator(aaStack_12c);
  }
  if (param_1[1] < *param_1) {
    if (0 < param_1[2]) {
      std::allocator<char>::allocator();
                    // try { // try from 004158c8 to 004158cf has its CatchHandler @ 00415c78
      std::__cxx11::basic_string<>::basic_string
                ((char *)abStack_17c,
                 (allocator *)
                 "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/Core/Slice.hpp"
                );
      std::allocator<char>::allocator();
                    // try { // try from 004158f8 to 004158ff has its CatchHandler @ 00415c4c
      std::__cxx11::basic_string<>::basic_string
                ((char *)abStack_198,(allocator *)"makePositiveAndValidate");
      std::allocator<char>::allocator();
                    // try { // try from 00415928 to 0041592f has its CatchHandler @ 00415c20
      std::__cxx11::basic_string<>::basic_string
                ((char *)abStack_1b4,(allocator *)"Invalid slice values.");
                    // try { // try from 0041594c to 00415953 has its CatchHandler @ 00415c04
      MAYBElogAndThrowException();
      std::__cxx11::basic_string<>::~basic_string(abStack_1b4);
      std::allocator<char>::~allocator(aaStack_1b8);
      std::__cxx11::basic_string<>::~basic_string(abStack_198);
      std::allocator<char>::~allocator(aaStack_19c);
      std::__cxx11::basic_string<>::~basic_string(abStack_17c);
      std::allocator<char>::~allocator(aaStack_180);
    }
    FUN_00416c5c(param_1,param_1 + 1);
    param_1[2] = -param_1[2];
  }
  return;
}



int FUN_00415cbc(int *param_1,int param_2)

{
  int local_10;
  int local_c;
  
  FUN_004153f4(param_1,param_2);
  local_10 = 0;
  for (local_c = *param_1; local_c < param_1[1]; local_c = local_c + param_1[2]) {
    local_10 = local_10 + 1;
  }
  return local_10;
}



void FUN_00415d50(int param_1)

{
  FUN_004170a0();
  setTwoValues((undefined4 *)(param_1 + 4),0,0);
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  return;
}



void FUN_00415dcc(undefined4 *param_1)

{
  *param_1 = &PTR___cxa_pure_virtual_0043368c;
  FUN_00417530(param_1 + 1);
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0xffffffff;
  return;
}



void FUN_00415e3c(undefined4 *param_1)

{
  *param_1 = &PTR___cxa_pure_virtual_0043368c;
  freeResource((int **)(param_1 + 1));
  return;
}



void FUN_00415e90(undefined4 *param_1)

{
  FUN_00415e3c(param_1);
  operator_delete(param_1,0x14);
  return;
}



void setPureVirtualFunctionPointer(undefined4 *destinationPointer)

{
  *destinationPointer = &PTR___cxa_pure_virtual_00433674;
  return;
}



void FUN_00415f10(undefined4 *param_1)

{
  setPureVirtualFunctionPointer(param_1);
  operator_delete(param_1,4);
  return;
}



void FUN_00415f58(int param_1,int param_2)

{
  int *piVar1;
  int *piStack_1c;
  int *apiStack_18 [3];
  
  FUN_00417530(apiStack_18);
  piVar1 = (int *)FUN_0041759c((undefined4 *)(param_2 + 4));
  if (piVar1 != (int *)0x0) {
                    // try { // try from 00415fc8 to 00415fcf has its CatchHandler @ 00416078
    (**(code **)(*piVar1 + 0x14))(&piStack_1c,piVar1);
                    // try { // try from 00415fe0 to 00415fe7 has its CatchHandler @ 0041605c
    FUN_004175c8(apiStack_18,&piStack_1c);
    freeResource(&piStack_1c);
  }
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 8);
                    // try { // try from 0041603c to 00416043 has its CatchHandler @ 00416078
  FUN_004175c8((int **)(param_1 + 4),apiStack_18);
  freeResource(apiStack_18);
  return;
}



void FUN_004160b8(void)

{
  return;
}



undefined4 * FUN_004160e0(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



void FUN_00416118(undefined4 *param_1,basic_string *param_2)

{
  std::runtime_error::runtime_error((runtime_error *)param_1,param_2);
  *param_1 = &PTR_FUN_00433660;
  return;
}



void FUN_00416170(char *param_1,char *param_2,char *param_3)

{
  char *pcVar1;
  uint uVar2;
  
  pcVar1 = (char *)strlen(param_2);
  strlen(param_3);
  while( true ) {
    uVar2 = std::__cxx11::basic_string<>::find(param_1,(uint)param_2);
    if (uVar2 == 0xffffffff) break;
    std::__cxx11::basic_string<>::replace((uint)param_1,uVar2,pcVar1);
  }
  return;
}



char * FUN_0041622c(void)

{
  return "long double";
}



undefined8 FUN_00416254(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



undefined8 FUN_0041627c(int param_1)

{
  undefined8 uVar1;
  undefined auStack_560 [1368];
  
  memcpy(auStack_560,&DAT_004319d8,0x558);
  uVar1 = FUN_00417614((int)auStack_560,param_1);
  return uVar1;
}



undefined4 FUN_004162e4(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



void FUN_00416310(float param_1)

{
  FUN_00414cb0(param_1);
  return;
}



void FUN_00416348(undefined4 param_1,float param_2)

{
  FUN_00416310(param_2);
  return;
}



void FUN_00416384(float param_1)

{
  FUN_00416348(0,param_1);
  return;
}



int FUN_004163c0(int param_1,int param_2)

{
  int local_2c;
  int local_28;
  int local_24;
  int iStack_20;
  undefined4 auStack_1c [4];
  
  copyValuesToBuffer(auStack_1c,param_2);
  FUN_00418f88(param_1,auStack_1c);
  processDataBlock(&local_24,param_2);
  copyDataToArray(&local_28,param_2);
  FUN_00419164(&local_2c,param_1);
                    // try { // try from 00416458 to 0041645f has its CatchHandler @ 00416468
  FUN_004191b0(&iStack_20,local_24,local_28,local_2c);
  return param_1;
}



void FUN_004164a8(undefined4 *param_1)

{
  FUN_0041bad4(param_1);
  return;
}



void FUN_004164e8(undefined4 *param_1)

{
  FUN_0041bb9c(param_1);
  return;
}



basic_string<> *
FUN_00416528(basic_string<> *param_1,undefined *param_2,int param_3,undefined4 param_4)

{
  char *pcVar1;
  char acStack_28 [8];
  char *local_20;
  int local_1c;
  allocator aaStack_18 [4];
  undefined *local_14;
  
  local_20 = acStack_28 + -(param_3 + 0xeU & 0xfffffff8);
  local_14 = &stack0x00000010;
  local_1c = (*(code *)param_2)(local_20,param_3,param_4,local_14);
  pcVar1 = local_20 + local_1c;
  std::allocator<char>::allocator();
                    // try { // try from 004165d8 to 004165df has its CatchHandler @ 004165f8
  std::__cxx11::basic_string<>::basic_string<char*,void>(param_1,local_20,pcVar1,aaStack_18);
  std::allocator<char>::~allocator((allocator<char> *)aaStack_18);
  return param_1;
}



void FUN_0041663c(allocator<char> *param_1)

{
  std::allocator<char>::~allocator(param_1);
  return;
}



basic_string * FUN_00416678(basic_string *param_1,basic_string *param_2,uint param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  
  iVar2 = std::__cxx11::basic_string<>::size();
  iVar3 = std::__cxx11::basic_string<>::size();
  uVar4 = std::__cxx11::basic_string<>::capacity();
  if ((uVar4 < (uint)(iVar2 + iVar3)) &&
     (uVar4 = std::__cxx11::basic_string<>::capacity(), (uint)(iVar2 + iVar3) <= uVar4)) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if (bVar1) {
    uVar5 = std::__cxx11::basic_string<>::insert(param_3,(basic_string *)0x0);
    FUN_0041c1ec(uVar5);
  }
  else {
    uVar5 = std::__cxx11::basic_string<>::append(param_2);
    FUN_0041c1ec(uVar5);
  }
  std::__cxx11::basic_string<>::basic_string(param_1);
  return param_1;
}



basic_string * FUN_00416790(basic_string *param_1,undefined4 param_2,uint param_3)

{
  undefined4 uVar1;
  
  uVar1 = std::__cxx11::basic_string<>::insert(param_3,(char *)0x0);
  FUN_0041c1ec(uVar1);
  std::__cxx11::basic_string<>::basic_string(param_1);
  return param_1;
}



basic_string * FUN_004167f8(basic_string *param_1,basic_string *param_2)

{
  undefined4 uVar1;
  
  uVar1 = std::__cxx11::basic_string<>::append(param_2);
  FUN_0041c1ec(uVar1);
  std::__cxx11::basic_string<>::basic_string(param_1);
  return param_1;
}



basic_string<> * FUN_0041685c(basic_string<> *param_1)

{
  FUN_00415098(param_1);
  return param_1;
}



// no clue
// 

basic_string * appendStringToBasicString(basic_string *str,char *appendStr)

{
  undefined4 result;
  
  result = std::__cxx11::basic_string<>::append(appendStr);
  FUN_0041c1ec(result);
  std::__cxx11::basic_string<>::basic_string(str);
  return str;
}



basic_string<> * FUN_00416908(basic_string<> *param_1)

{
  FUN_00415038(param_1);
  return param_1;
}



// what is this???? is this code the compiler added?? looks like exception related?

void MAYBElogAndThrowException(void)

{
  invalid_argument *this;
  basic_string<> abStack_d0 [24];
  basic_string abStack_b8 [6];
  basic_string abStack_a0 [6];
  basic_string abStack_88 [6];
  basic_string abStack_70 [6];
  basic_string abStack_58 [6];
  basic_string abStack_40 [6];
  basic_string abStack_28 [6];
  
  std::operator+(abStack_b8,"File: ");
                    // try { // try from 004169ac to 004169b3 has its CatchHandler @ 00416bd0
  appendStringToBasicString(abStack_a0,(char *)abStack_b8);
                    // try { // try from 004169c8 to 004169cf has its CatchHandler @ 00416bb4
  FUN_004167f8(abStack_88,abStack_a0);
                    // try { // try from 004169e8 to 004169ef has its CatchHandler @ 00416b98
  appendStringToBasicString(abStack_70,(char *)abStack_88);
                    // try { // try from 004169fc to 00416a03 has its CatchHandler @ 00416b7c
  FUN_00415098(abStack_d0);
                    // try { // try from 00416a1c to 00416a23 has its CatchHandler @ 00416b60
  FUN_00416678(abStack_58,abStack_70,(uint)abStack_d0);
                    // try { // try from 00416a3c to 00416a43 has its CatchHandler @ 00416b44
  appendStringToBasicString(abStack_40,(char *)abStack_58);
                    // try { // try from 00416a58 to 00416a5f has its CatchHandler @ 00416b28
  FUN_004167f8(abStack_28,abStack_40);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_40);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_58);
  std::__cxx11::basic_string<>::~basic_string(abStack_d0);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_70);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_88);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_a0);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_b8);
                    // try { // try from 00416ae0 to 00416ae7 has its CatchHandler @ 00416c10
  std::operator<<((basic_ostream *)std::cerr,abStack_28);
  this = (invalid_argument *)__cxa_allocate_exception(8);
                    // try { // try from 00416b04 to 00416b0b has its CatchHandler @ 00416bf4
  std::invalid_argument::invalid_argument(this,abStack_28);
                    // WARNING: Subroutine does not return
                    // try { // try from 00416b20 to 00416b27 has its CatchHandler @ 00416c10
  __cxa_throw(this,std::invalid_argument::typeinfo,std::invalid_argument::~invalid_argument);
}



undefined4 FUN_00416c34(undefined4 param_1)

{
  return param_1;
}



void FUN_00416c5c(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 local_10 [2];
  
  puVar1 = (undefined4 *)FUN_00416c34(param_1);
  local_10[0] = *puVar1;
  puVar1 = (undefined4 *)FUN_00416c34(param_2);
  *param_1 = *puVar1;
  puVar1 = (undefined4 *)FUN_00416c34(local_10);
  *param_2 = *puVar1;
  return;
}



// std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >
// std::TEMPNAMEPLACEHOLDERVALUE(char const*, std::__cxx11::basic_string<char,
// std::char_traits<char>, std::allocator<char> > const&)

basic_string * std::operator+(basic_string *param_1,char *param_2)

{
  FUN_00415000(param_2);
  std::__cxx11::basic_string<>::basic_string();
  std::__cxx11::basic_string<>::size();
                    // try { // try from 00416d34 to 00416d5f has its CatchHandler @ 00416d68
  std::__cxx11::basic_string<>::reserve((uint)param_1);
  std::__cxx11::basic_string<>::append((char *)param_1,(uint)param_2);
  std::__cxx11::basic_string<>::append(param_1);
  return param_1;
}



undefined4 FUN_00416da8(undefined4 *param_1)

{
  return *param_1;
}



int FUN_00416dd4(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_00416da8(param_1);
  iVar2 = FUN_004162e4((int)param_1);
  return iVar1 + iVar2 * 8;
}



void FUN_00416e2c(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 local_res4;
  undefined4 local_res8;
  int local_18;
  int iStack_14;
  
  local_res4 = param_2;
  local_res8 = param_3;
  FUN_004170a0();
  uVar1 = FUN_004162e4((int)&local_res4);
  setTwoValues((undefined4 *)(param_1 + 4),1,uVar1);
  iVar2 = FUN_00415310((int *)(param_1 + 4));
  *(int *)(param_1 + 0xc) = iVar2;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 00416ec8 to 00416ecf has its CatchHandler @ 00416f40
  FUN_0041c264(param_1);
  if (*(int *)(param_1 + 0xc) != 0) {
    uVar1 = FUN_00416da8(&local_res4);
    iVar2 = FUN_00416dd4(&local_res4);
    FUN_00417230(&local_18,param_1);
    FUN_0041c2dc(&iStack_14,uVar1,iVar2,local_18);
  }
  return;
}



void FUN_00416f88(int param_1)

{
  FUN_0041c334(param_1);
  FUN_004170dc();
  return;
}



void FUN_00416fd4(int param_1,int param_2)

{
  undefined4 uVar1;
  
  FUN_004170a0();
  uVar1 = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_2 + 4);
  *(undefined4 *)(param_1 + 8) = uVar1;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x14);
  *(undefined *)(param_1 + 0x18) = *(undefined *)(param_2 + 0x18);
  *(undefined4 *)(param_2 + 8) = 0;
  *(undefined4 *)(param_2 + 4) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_2 + 0xc) = 0;
  *(undefined *)(param_2 + 0x18) = 0;
  *(undefined4 *)(param_2 + 0x14) = 0;
  return;
}



void FUN_004170a0(void)

{
  FUN_0041c3e4();
  return;
}



void FUN_004170dc(void)

{
  FUN_0041c40c();
  return;
}



void FUN_00417118(int param_1,int param_2,int param_3)

{
  FUN_004170a0();
  setTwoValues((undefined4 *)(param_1 + 4),param_2,param_3);
  *(int *)(param_1 + 0xc) = param_2 * param_3;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 00417194 to 0041719b has its CatchHandler @ 004171a4
  FUN_0041c264(param_1);
  return;
}



void FUN_004171e4(int *param_1,int param_2)

{
  FUN_0041c434(param_1,param_2);
  return;
}



int * FUN_00417230(int *param_1,int param_2)

{
  FUN_004171e4(param_1,*(int *)(param_2 + 0x14));
  return param_1;
}



int * FUN_0041727c(int *param_1)

{
  FUN_0041c63c(param_1);
  return param_1;
}



void FUN_004172bc(undefined4 *param_1)

{
  FUN_0041c678(param_1);
  return;
}



int FUN_004172f8(int param_1,int param_2)

{
  int local_res4;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 0xc) + param_2;
  }
  return *(int *)(param_1 + 0x14) + local_res4 * 8;
}



int FUN_00417354(int param_1,int param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  char *pcVar2;
  void *apvStack_28 [3];
  int local_1c;
  int iStack_18;
  int aiStack_14 [2];
  
  FUN_004178b0(apvStack_28);
  local_1c = 0;
  FUN_0041c6a4(&iStack_18,param_2);
  FUN_0041c6ec(aiStack_14,param_2);
  while (bVar1 = FUN_0041c734(&iStack_18,aiStack_14), CONCAT31(extraout_var,bVar1) != 0) {
    pcVar2 = (char *)FUN_0041c7b8(&iStack_18);
    if (*pcVar2 != '\0') {
                    // try { // try from 00417418 to 0041745b has its CatchHandler @ 00417474
      FUN_0041c7e4(apvStack_28,&local_1c);
    }
    local_1c = local_1c + 1;
    FUN_0041c77c(&iStack_18);
  }
  FUN_0041c894(param_1,(int *)apvStack_28,'\x01');
  FUN_004178f0(apvStack_28);
  return param_1;
}



void FUN_004174b8(int param_1)

{
  FUN_0041ca58(param_1);
  FUN_0041ca1c();
  return;
}



undefined4 FUN_00417504(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



void FUN_00417530(undefined4 *param_1)

{
  *param_1 = 0;
  return;
}



void freeResource(int **resource)

{
  releaseMemory(resource);
  return;
}



undefined4 FUN_0041759c(undefined4 *param_1)

{
  return *param_1;
}



int ** FUN_004175c8(int **param_1,int **param_2)

{
  FUN_0041cc34(param_1,*param_2);
  return param_1;
}



void FUN_00417614(int param_1,int param_2)

{
  FUN_0041cc8c(param_1,param_2);
  return;
}



void FUN_00417658(int param_1,int param_2)

{
  undefined4 uVar1;
  int local_20;
  int local_1c;
  int local_18;
  int aiStack_14 [2];
  
  FUN_0041ccc4();
  uVar1 = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_2 + 4);
  *(undefined4 *)(param_1 + 8) = uVar1;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 004176d0 to 004176d7 has its CatchHandler @ 00417748
  FUN_0041cd3c(param_1);
  if (*(int *)(param_1 + 0xc) != 0) {
    FUN_0041cdb4(&local_18,param_2);
    FUN_0041ce00(&local_1c,param_2);
    FUN_0041cec0(&local_20,param_1);
    FUN_0041cf0c(aiStack_14,local_18,local_1c,local_20);
  }
  return;
}



void FUN_0041778c(int param_1)

{
  FUN_0041cf64(param_1);
  FUN_0041cd00();
  return;
}



undefined4 * FUN_004177d8(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_2 + 8);
  *param_1 = *(undefined4 *)(param_2 + 4);
  param_1[1] = uVar1;
  return param_1;
}



int FUN_0041781c(int param_1,int param_2,int param_3)

{
  int local_res4;
  int local_res8;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 4) + param_2;
  }
  local_res8 = param_3;
  if (param_3 < 0) {
    local_res8 = *(int *)(param_1 + 8) + param_3;
  }
  return *(int *)(param_1 + 0x14) + (*(int *)(param_1 + 8) * local_res4 + local_res8) * 8;
}



void FUN_004178b0(undefined4 *param_1)

{
  FUN_0041d050(param_1);
  return;
}



void FUN_004178f0(void **param_1)

{
  FUN_0041d108(param_1);
  FUN_0041d130();
  FUN_0041d090(param_1);
  return;
}



int FUN_00417974(int *param_1)

{
  return param_1[1] - *param_1 >> 2;
}



void FUN_004179b4(undefined8 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  FUN_00417a00(param_1,param_2,param_3,param_4);
  return;
}



void FUN_00417a00(undefined8 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  longlong lVar1;
  uint uVar2;
  uint uVar3;
  undefined8 uVar4;
  longlong lVar5;
  uint local_28;
  undefined4 local_20;
  undefined4 local_1c;
  
  uVar4 = FUN_0041d178(param_3,param_4);
  *param_1 = uVar4;
  for (local_28 = 1; local_28 < 0x138; local_28 = local_28 + 1) {
    uVar3 = *(uint *)((int)(param_1 + (local_28 - 1)) + 4);
    uVar2 = *(uint *)(param_1 + (local_28 - 1)) ^ uVar3 >> 0x1e;
    lVar1 = (ulonglong)uVar2 * 0x4c957f2d;
    lVar5 = FUN_0041d1b8(local_28,0);
    lVar5 = lVar5 + CONCAT44(uVar3 * 0x4c957f2d + uVar2 * 0x5851f42d +
                             (int)((ulonglong)lVar1 >> 0x20),(int)lVar1);
    local_20 = (undefined4)lVar5;
    local_1c = (undefined4)((ulonglong)lVar5 >> 0x20);
    uVar4 = FUN_0041d178(local_20,local_1c);
    param_1[local_28] = uVar4;
  }
  *(undefined4 *)(param_1 + 0x138) = 0x138;
  return;
}



void FUN_00417bb8(void)

{
  runtime_error *this;
  basic_string<> abStack_d0 [24];
  basic_string abStack_b8 [6];
  basic_string abStack_a0 [6];
  basic_string abStack_88 [6];
  basic_string abStack_70 [6];
  basic_string abStack_58 [6];
  basic_string abStack_40 [6];
  basic_string abStack_28 [6];
  
  std::operator+(abStack_b8,"File: ");
                    // try { // try from 00417c14 to 00417c1b has its CatchHandler @ 00417e38
  appendStringToBasicString(abStack_a0,(char *)abStack_b8);
                    // try { // try from 00417c30 to 00417c37 has its CatchHandler @ 00417e1c
  FUN_004167f8(abStack_88,abStack_a0);
                    // try { // try from 00417c50 to 00417c57 has its CatchHandler @ 00417e00
  appendStringToBasicString(abStack_70,(char *)abStack_88);
                    // try { // try from 00417c64 to 00417c6b has its CatchHandler @ 00417de4
  FUN_00415098(abStack_d0);
                    // try { // try from 00417c84 to 00417c8b has its CatchHandler @ 00417dc8
  FUN_00416678(abStack_58,abStack_70,(uint)abStack_d0);
                    // try { // try from 00417ca4 to 00417cab has its CatchHandler @ 00417dac
  appendStringToBasicString(abStack_40,(char *)abStack_58);
                    // try { // try from 00417cc0 to 00417cc7 has its CatchHandler @ 00417d90
  FUN_004167f8(abStack_28,abStack_40);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_40);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_58);
  std::__cxx11::basic_string<>::~basic_string(abStack_d0);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_70);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_88);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_a0);
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_b8);
                    // try { // try from 00417d48 to 00417d4f has its CatchHandler @ 00417e78
  std::operator<<((basic_ostream *)std::cerr,abStack_28);
  this = (runtime_error *)__cxa_allocate_exception(8);
                    // try { // try from 00417d6c to 00417d73 has its CatchHandler @ 00417e5c
  std::runtime_error::runtime_error(this,abStack_28);
                    // WARNING: Subroutine does not return
                    // try { // try from 00417d88 to 00417d8f has its CatchHandler @ 00417e78
  __cxa_throw(this,std::runtime_error::typeinfo,std::runtime_error::~runtime_error);
}



int * FUN_00417e9c(int *param_1,int param_2)

{
  FUN_0041d33c(param_1,*(int *)(param_2 + 0x14));
  return param_1;
}



int * FUN_00417ee8(int *param_1,int param_2)

{
  int *piVar1;
  int aiStack_10 [2];
  
  FUN_00417e9c(aiStack_10,param_2);
  piVar1 = FUN_0041d544(aiStack_10,*(int *)(param_2 + 0xc));
  *param_1 = *piVar1;
  return param_1;
}



void FUN_00417f5c(int *param_1,int param_2)

{
  FUN_0041d604(param_1,param_2);
  return;
}



int * FUN_00417fa8(int *param_1,int param_2)

{
  FUN_00417f5c(param_1,*(int *)(param_2 + 0x14));
  return param_1;
}



undefined4 *
setValuesInArrayFromMemory
          (undefined4 *array,int sourceAddress,undefined4 param_3,undefined4 param_4)

{
  GenericSetvaluesinarray(array,param_3,*(undefined4 *)(sourceAddress + 4),param_4);
  return array;
}



int MaybeProccessDataBlock
              (int destination,int param_2,uint param_3,int param_4,int param_5,uint param_6)

{
  int iVar1;
  undefined4 *sourceData;
  undefined4 *destinationOffset;
  uint blockOffset;
  int local_resc;
  int localOffset;
  uint loopIndex;
  
  blockOffset = param_3;
  local_resc = param_4;
  iVar1 = FUN_00415cbc((int *)&blockOffset,*(int *)(param_2 + 4));
  FUN_0041b7e0(destination,iVar1,1);
  localOffset = 0;
  for (loopIndex = blockOffset; (int)loopIndex < local_resc; loopIndex = loopIndex + param_5) {
                    // try { // try from 004180d8 to 004180df has its CatchHandler @ 00418124
    sourceData = (undefined4 *)FUN_0041d80c(param_2,loopIndex,param_6);
    destinationOffset = (undefined4 *)calculateOffset(destination,localOffset,0);
    *destinationOffset = *sourceData;
    localOffset = localOffset + 1;
  }
  return destination;
}



// no clue
// 

void FUN_00418168(int param_1)

{
  cleanupFunction(param_1);
  FUN_0041de34();
  return;
}



void FUN_004181b4(int param_1,int param_2)

{
  undefined4 uVar1;
  
  FUN_0041df20();
  uVar1 = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_2 + 4);
  *(undefined4 *)(param_1 + 8) = uVar1;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x14);
  *(undefined *)(param_1 + 0x18) = *(undefined *)(param_2 + 0x18);
  *(undefined4 *)(param_2 + 8) = 0;
  *(undefined4 *)(param_2 + 4) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_2 + 0xc) = 0;
  *(undefined *)(param_2 + 0x18) = 0;
  *(undefined4 *)(param_2 + 0x14) = 0;
  return;
}



undefined4 FUN_00418280(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



void FUN_004182ac(int param_1)

{
  FUN_0041df20();
  setTwoValues((undefined4 *)(param_1 + 4),0,0);
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  return;
}



int FUN_00418328(int param_1,int param_2,int param_3)

{
  float *pfVar1;
  float fVar2;
  uint local_110;
  uint local_10c;
  allocator<char> aaStack_108 [4];
  basic_string<> abStack_104 [24];
  allocator<char> aaStack_ec [4];
  basic_string<> abStack_e8 [24];
  allocator<char> aaStack_d0 [4];
  basic_string<> abStack_cc [24];
  int local_b4;
  int local_b0;
  int local_ac;
  int local_a8;
  int local_a4;
  int local_a0;
  float local_9c;
  float *local_98;
  undefined4 local_94;
  undefined auStack_90 [28];
  undefined auStack_74 [28];
  undefined auStack_58 [28];
  uint local_3c [2];
  undefined auStack_34 [32];
  
  if (param_3 == 1) {
    FUN_0041e690((int)auStack_58,param_2);
    copyValuesToBuffer(local_3c,(int)auStack_58);
                    // try { // try from 00418530 to 00418537 has its CatchHandler @ 004187ac
    FUN_0041b7e0((int)auStack_34,1,local_3c[0]);
    for (local_10c = 0; local_10c < local_3c[0]; local_10c = local_10c + 1) {
                    // try { // try from 00418564 to 00418587 has its CatchHandler @ 00418790
      FUN_0041e1ec(&local_b0,(int)auStack_58,local_10c);
      FUN_0041e440(&local_b4,(int)auStack_58,local_10c);
      fVar2 = 0.0;
      pfVar1 = (float *)calculateOffset((int)auStack_34,0,local_10c);
      fVar2 = FUN_0041df5c(local_b0,local_b4,fVar2);
      *pfVar1 = fVar2;
    }
    FUN_004181b4(param_1,(int)auStack_34);
    FUN_00418168((int)auStack_34);
    FUN_00418168((int)auStack_58);
  }
  else if (param_3 == 2) {
    FUN_0041b7e0((int)auStack_74,1,*(int *)(param_2 + 4));
    for (local_110 = 0; local_110 < *(uint *)(param_2 + 4); local_110 = local_110 + 1) {
                    // try { // try from 00418454 to 00418473 has its CatchHandler @ 0041876c
      FUN_0041e1ec(&local_a8,param_2,local_110);
      FUN_0041e440(&local_ac,param_2,local_110);
      fVar2 = 0.0;
      pfVar1 = (float *)calculateOffset((int)auStack_74,0,local_110);
      fVar2 = FUN_0041df5c(local_a8,local_ac,fVar2);
      *pfVar1 = fVar2;
    }
    FUN_004181b4(param_1,(int)auStack_74);
    FUN_00418168((int)auStack_74);
  }
  else if (param_3 == 0) {
    processDataBlock(&local_a0,param_2);
    copyDataToArray(&local_a4,param_2);
    local_9c = FUN_0041df5c(local_a0,local_a4,0.0);
    local_98 = &local_9c;
    local_94 = 1;
    FUN_0041e090((int)auStack_90,local_98,1);
    FUN_004181b4(param_1,(int)auStack_90);
    FUN_00418168((int)auStack_90);
  }
  else {
    std::allocator<char>::allocator();
                    // try { // try from 0041863c to 00418643 has its CatchHandler @ 00418844
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_cc,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041866c to 00418673 has its CatchHandler @ 00418818
    std::__cxx11::basic_string<>::basic_string((char *)abStack_e8,(allocator *)&DAT_00432df4);
    std::allocator<char>::allocator();
                    // try { // try from 0041869c to 004186a3 has its CatchHandler @ 004187ec
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_104,(allocator *)"Unimplemented axis type.");
                    // try { // try from 004186c0 to 004186c7 has its CatchHandler @ 004187d0
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_104);
    std::allocator<char>::~allocator(aaStack_108);
    std::__cxx11::basic_string<>::~basic_string(abStack_e8);
    std::allocator<char>::~allocator(aaStack_ec);
    std::__cxx11::basic_string<>::~basic_string(abStack_cc);
    std::allocator<char>::~allocator(aaStack_d0);
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    *(undefined4 *)(param_1 + 0x10) = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined *)(param_1 + 0x18) = 0;
    FUN_004182ac(param_1);
  }
  return param_1;
}



int FUN_0041888c(int param_1,int param_2)

{
  int local_res4;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 0xc) + param_2;
  }
  return *(int *)(param_1 + 0x14) + local_res4 * 4;
}



void FUN_004188e8(byte *param_1,float param_2)

{
  FUN_0041e798(param_2,param_1,*param_1);
  return;
}



int FUN_00418930(int param_1,int param_2)

{
  int local_28;
  int local_24;
  int local_20;
  int iStack_1c;
  undefined4 auStack_18 [3];
  
  copyValuesToBuffer(auStack_18,param_2);
  FUN_00418f88(param_1,auStack_18);
  processDataBlock(&local_20,param_2);
  copyDataToArray(&local_24,param_2);
  FUN_00419164(&local_28,param_1);
                    // try { // try from 004189d4 to 004189db has its CatchHandler @ 004189e4
  FUN_0041e7e0(&iStack_1c,local_20,local_24,local_28);
  return param_1;
}



int FUN_00418a24(int param_1,int param_2,int param_3)

{
  FUN_0041e840(param_1,param_2,param_3);
  return param_1;
}



int FUN_00418a74(int param_1,undefined4 param_2,int param_3)

{
  FUN_0041eb74(param_1,param_3,param_2);
  return param_1;
}



float FUN_00418ac4(float *param_1,float param_2)

{
  return *param_1 + param_2;
}



int FUN_00418afc(int param_1,int param_2,undefined4 param_3)

{
  int local_30;
  int local_2c;
  int local_28;
  int iStack_24;
  undefined4 auStack_20 [2];
  undefined4 local_18;
  
  local_18 = param_3;
  copyValuesToBuffer(auStack_20,param_2);
  FUN_00418f88(param_1,auStack_20);
  processDataBlock(&local_28,param_2);
  copyDataToArray(&local_2c,param_2);
  FUN_00419164(&local_30,param_1);
                    // try { // try from 00418ba4 to 00418bab has its CatchHandler @ 00418bb8
  FUN_0041ec70(&iStack_24,local_28,local_2c,local_30);
  return param_1;
}



int FUN_00418bf8(int param_1,undefined4 param_2,int param_3)

{
  FUN_00418afc(param_1,param_3,param_2);
  return param_1;
}



int FUN_00418c48(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int local_94;
  int local_90;
  int local_8c;
  int local_88;
  int iStack_84;
  undefined4 auStack_80 [2];
  allocator<char> aaStack_78 [4];
  basic_string<> abStack_74 [24];
  allocator<char> aaStack_5c [4];
  basic_string<> abStack_58 [24];
  allocator<char> aaStack_40 [4];
  basic_string<> abStack_3c [24];
  int aiStack_24 [2];
  int aiStack_1c [4];
  
  copyValuesToBuffer(aiStack_1c,param_2);
  copyValuesToBuffer(aiStack_24,param_3);
  uVar1 = FUN_004152c8(aiStack_1c,aiStack_24);
  if (uVar1 != 0) {
    std::allocator<char>::allocator();
                    // try { // try from 00418cd8 to 00418cdf has its CatchHandler @ 00418ee0
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_3c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayOperators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 00418d08 to 00418d0f has its CatchHandler @ 00418eb4
    std::__cxx11::basic_string<>::basic_string((char *)abStack_58,(allocator *)"operator-");
    std::allocator<char>::allocator();
                    // try { // try from 00418d38 to 00418d3f has its CatchHandler @ 00418e88
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_74,(allocator *)"Array dimensions do not match.");
                    // try { // try from 00418d5c to 00418d63 has its CatchHandler @ 00418e6c
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_74);
    std::allocator<char>::~allocator(aaStack_78);
    std::__cxx11::basic_string<>::~basic_string(abStack_58);
    std::allocator<char>::~allocator(aaStack_5c);
    std::__cxx11::basic_string<>::~basic_string(abStack_3c);
    std::allocator<char>::~allocator(aaStack_40);
  }
  copyValuesToBuffer(auStack_80,param_2);
  FUN_00418f88(param_1,auStack_80);
  processDataBlock(&local_88,param_2);
  copyDataToArray(&local_8c,param_2);
  processDataBlock(&local_90,param_3);
  FUN_00419164(&local_94,param_1);
                    // try { // try from 00418e5c to 00418e63 has its CatchHandler @ 00418f04
  FUN_0041ecd0(&iStack_84,local_88,local_8c,local_90,local_94);
  return param_1;
}



undefined4 * copyValuesToBuffer(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_2 + 8);
  *param_1 = *(undefined4 *)(param_2 + 4);
  param_1[1] = uVar1;
  return param_1;
}



void FUN_00418f88(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  FUN_0041df20();
  uVar2 = param_2[1];
  *(undefined4 *)(param_1 + 4) = *param_2;
  *(undefined4 *)(param_1 + 8) = uVar2;
  iVar1 = FUN_00415310((int *)(param_1 + 4));
  *(int *)(param_1 + 0xc) = iVar1;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 00419008 to 0041900f has its CatchHandler @ 00419018
  FUN_0041ed34(param_1);
  return;
}



int * processDataBlock(int *destination,int sourceAddress)

{
  handleException(destination,*(int *)(sourceAddress + 0x14));
  return destination;
}



int * copyDataToArray(int *destination,int sourceAddress)

{
  int *sourceData;
  int stackBuffer [2];
  
  processDataBlock(stackBuffer,sourceAddress);
  sourceData = FUN_0041efb4(stackBuffer,*(int *)(sourceAddress + 0xc));
  *destination = *sourceData;
  return destination;
}



void FUN_00419118(int *param_1,int param_2)

{
  FUN_0041effc(param_1,param_2);
  return;
}



int * FUN_00419164(int *param_1,int param_2)

{
  FUN_00419118(param_1,*(int *)(param_2 + 0x14));
  return param_1;
}



int * FUN_004191b0(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_0041f204(param_1,param_2,param_3,param_4);
  return param_1;
}



float FUN_0041920c(float *param_1,float param_2)

{
  return param_2 / *param_1;
}



int FUN_00419244(int param_1,int param_2,undefined4 param_3)

{
  int local_30;
  int local_2c;
  int local_28;
  int iStack_24;
  undefined4 auStack_20 [2];
  undefined4 local_18;
  
  local_18 = param_3;
  copyValuesToBuffer(auStack_20,param_2);
  FUN_00418f88(param_1,auStack_20);
  processDataBlock(&local_28,param_2);
  copyDataToArray(&local_2c,param_2);
  FUN_00419164(&local_30,param_1);
                    // try { // try from 004192ec to 004192f3 has its CatchHandler @ 00419300
  FUN_0041f2e4(&iStack_24,local_28,local_2c,local_30);
  return param_1;
}



void FUN_00419340(int param_1,int param_2)

{
  undefined4 uVar1;
  int local_20;
  int local_1c;
  int local_18;
  int aiStack_14 [2];
  
  FUN_0041df20();
  uVar1 = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_2 + 4);
  *(undefined4 *)(param_1 + 8) = uVar1;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 004193b8 to 004193bf has its CatchHandler @ 00419430
  FUN_0041ed34(param_1);
  if (*(int *)(param_1 + 0xc) != 0) {
    processDataBlock(&local_18,param_2);
    copyDataToArray(&local_1c,param_2);
    FUN_00419164(&local_20,param_1);
    FUN_0041f344(aiStack_14,local_18,local_1c,local_20);
  }
  return;
}



int FUN_00419474(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  undefined4 local_res4;
  undefined4 local_res8;
  int local_resc;
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  if (param_4 == 1) {
    FUN_0041f39c(param_1,&local_res4);
  }
  else if (param_4 == 2) {
    FUN_0041f7bc(param_1,&local_res4);
  }
  else {
    std::allocator<char>::allocator();
                    // try { // try from 00419524 to 0041952b has its CatchHandler @ 004196c8
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/Functions/stack.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 00419554 to 0041955b has its CatchHandler @ 0041969c
    std::__cxx11::basic_string<>::basic_string((char *)abStack_48,(allocator *)"stack");
    std::allocator<char>::allocator();
                    // try { // try from 00419584 to 0041958b has its CatchHandler @ 00419670
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"inAxis must be either ROW or COL.");
                    // try { // try from 004195a8 to 004195af has its CatchHandler @ 00419654
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    *(undefined4 *)(param_1 + 0x10) = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined *)(param_1 + 0x18) = 0;
    FUN_004182ac(param_1);
  }
  return param_1;
}



bool FUN_0041970c(float *param_1,float param_2)

{
  return *param_1 < param_2;
}



int FUN_00419758(int param_1,int param_2,undefined4 param_3)

{
  int local_30;
  int local_2c;
  int local_28;
  int iStack_24;
  undefined4 auStack_20 [2];
  undefined4 local_18;
  
  copyValuesToBuffer(auStack_20,param_2);
  FUN_0041d1f8(param_1,auStack_20);
  local_18 = param_3;
  processDataBlock(&local_28,param_2);
  copyDataToArray(&local_2c,param_2);
  FUN_0041cec0(&local_30,param_1);
                    // try { // try from 00419800 to 00419807 has its CatchHandler @ 00419814
  FUN_0041fbd8(&iStack_24,local_28,local_2c,local_30);
  return param_1;
}



bool FUN_00419854(undefined4 param_1,float param_2,float param_3)

{
  return param_2 < param_3;
}



void FUN_004198a0(float param_1,float param_2)

{
  FUN_00419854(0,param_1,param_2);
  return;
}



int FUN_004198e4(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int local_98;
  int local_94;
  int local_90;
  int local_8c;
  int iStack_88;
  undefined4 auStack_84 [2];
  allocator<char> aaStack_7c [4];
  basic_string<> abStack_78 [24];
  allocator<char> aaStack_60 [4];
  basic_string<> abStack_5c [24];
  allocator<char> aaStack_44 [4];
  basic_string<> abStack_40 [24];
  int aiStack_28 [2];
  int aiStack_20 [5];
  
  copyValuesToBuffer(aiStack_20,param_2);
  copyValuesToBuffer(aiStack_28,param_3);
  uVar1 = FUN_004152c8(aiStack_20,aiStack_28);
  if (uVar1 != 0) {
    std::allocator<char>::allocator();
                    // try { // try from 00419974 to 0041997b has its CatchHandler @ 00419b80
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_40,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayOperators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 004199a4 to 004199ab has its CatchHandler @ 00419b54
    std::__cxx11::basic_string<>::basic_string((char *)abStack_5c,(allocator *)"operator<");
    std::allocator<char>::allocator();
                    // try { // try from 004199d4 to 004199db has its CatchHandler @ 00419b28
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_78,(allocator *)"Array dimensions do not match.");
                    // try { // try from 004199f8 to 004199ff has its CatchHandler @ 00419b0c
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_78);
    std::allocator<char>::~allocator(aaStack_7c);
    std::__cxx11::basic_string<>::~basic_string(abStack_5c);
    std::allocator<char>::~allocator(aaStack_60);
    std::__cxx11::basic_string<>::~basic_string(abStack_40);
    std::allocator<char>::~allocator(aaStack_44);
  }
  copyValuesToBuffer(auStack_84,param_2);
  FUN_0041d1f8(param_1,auStack_84);
  processDataBlock(&local_8c,param_2);
  copyDataToArray(&local_90,param_2);
  processDataBlock(&local_94,param_3);
  FUN_0041cec0(&local_98,param_1);
                    // try { // try from 00419af8 to 00419aff has its CatchHandler @ 00419ba4
  FUN_0041fc38(&iStack_88,local_8c,local_90,local_94,local_98);
  return param_1;
}



int FUN_00419be4(int param_1,int param_2,int param_3)

{
  FUN_0041fd54(param_1,param_2,param_3);
  return param_1;
}



int FUN_00419c34(int param_1,int param_2,uint param_3,uint param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  uint local_60;
  uint local_5c;
  int local_58;
  uint local_54;
  uint local_50;
  undefined auStack_3c [32];
  void *apvStack_1c [4];
  
  FUN_00420054(param_1,*(int *)(param_2 + 4) * param_3,*(int *)(param_2 + 8) * param_4);
  for (local_60 = 0; local_60 < param_3; local_60 = local_60 + 1) {
    for (local_5c = 0; local_5c < param_4; local_5c = local_5c + 1) {
      uVar1 = FUN_00415310((int *)(param_2 + 4));
      FUN_0041cb08();
                    // try { // try from 00419cf8 to 00419cff has its CatchHandler @ 00419e88
      FUN_00420120((int *)apvStack_1c,uVar1);
      FUN_0041ca1c();
      iVar2 = *(int *)(param_2 + 8);
      iVar3 = *(int *)(param_2 + 4);
      iVar4 = *(int *)(param_2 + 8);
      local_58 = 0;
      for (local_54 = local_60 * *(int *)(param_2 + 4); local_50 = local_5c * iVar2,
          local_54 < (local_60 + 1) * iVar3; local_54 = local_54 + 1) {
        for (; local_50 < (local_5c + 1) * iVar4; local_50 = local_50 + 1) {
          iVar6 = *(int *)(param_1 + 8);
          piVar5 = (int *)FUN_004201b0((int *)apvStack_1c,local_58);
          *piVar5 = iVar6 * local_54 + local_50;
          local_58 = local_58 + 1;
        }
      }
                    // try { // try from 00419e20 to 00419e27 has its CatchHandler @ 00419ec0
      FUN_0041c894((int)auStack_3c,(int *)apvStack_1c,'\x01');
                    // try { // try from 00419e38 to 00419e3f has its CatchHandler @ 00419ea4
      FUN_004201ec(param_1,(int)auStack_3c,param_2);
      FUN_004174b8((int)auStack_3c);
      FUN_004178f0(apvStack_1c);
    }
  }
  return param_1;
}



int FUN_00419f14(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  uint local_90;
  allocator<char> aaStack_8c [4];
  basic_string<> abStack_88 [24];
  allocator<char> aaStack_70 [4];
  basic_string<> abStack_6c [24];
  allocator<char> aaStack_54 [4];
  basic_string<> abStack_50 [24];
  int aiStack_38 [2];
  undefined auStack_30 [36];
  
  FUN_004177d8(aiStack_38,param_3);
  uVar1 = FUN_004152c8(aiStack_38,(int *)(param_2 + 4));
  if (uVar1 != 0) {
    std::allocator<char>::allocator();
                    // try { // try from 00419f94 to 00419f9b has its CatchHandler @ 0041a1d4
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_50,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 00419fc4 to 00419fcb has its CatchHandler @ 0041a1a8
    std::__cxx11::basic_string<>::basic_string((char *)abStack_6c,(allocator *)"operator[]");
    std::allocator<char>::allocator();
                    // try { // try from 00419ff4 to 00419ffb has its CatchHandler @ 0041a17c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_88,
               (allocator *)
               "input inMask must have the same shape as the NdArray it will be masking.");
                    // try { // try from 0041a018 to 0041a01f has its CatchHandler @ 0041a160
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_88);
    std::allocator<char>::~allocator(aaStack_8c);
    std::__cxx11::basic_string<>::~basic_string(abStack_6c);
    std::allocator<char>::~allocator(aaStack_70);
    std::__cxx11::basic_string<>::~basic_string(abStack_50);
    std::allocator<char>::~allocator(aaStack_54);
  }
  FUN_00417354((int)auStack_30,param_3);
  iVar2 = FUN_00417504((int)auStack_30);
                    // try { // try from 0041a0b0 to 0041a0b7 has its CatchHandler @ 0041a1f8
  FUN_0041b7e0(param_1,1,iVar2);
  for (local_90 = 0; uVar1 = FUN_00417504((int)auStack_30), local_90 < uVar1;
      local_90 = local_90 + 1) {
    piVar3 = (int *)FUN_0041cb44((int)auStack_30,local_90);
    puVar4 = (undefined4 *)FUN_004204cc(param_2,*piVar3);
    puVar5 = (undefined4 *)FUN_0041888c(param_1,local_90);
    *puVar5 = *puVar4;
  }
  FUN_004174b8((int)auStack_30);
  return param_1;
}



bool FUN_0041a23c(float *param_1,float param_2)

{
  return *param_1 <= param_2;
}



int FUN_0041a288(int param_1,int param_2,undefined4 param_3)

{
  int local_30;
  int local_2c;
  int local_28;
  int iStack_24;
  undefined4 auStack_20 [2];
  undefined4 local_18;
  
  copyValuesToBuffer(auStack_20,param_2);
  FUN_0041d1f8(param_1,auStack_20);
  local_18 = param_3;
  processDataBlock(&local_28,param_2);
  copyDataToArray(&local_2c,param_2);
  FUN_0041cec0(&local_30,param_1);
                    // try { // try from 0041a330 to 0041a337 has its CatchHandler @ 0041a344
  FUN_00420528(&iStack_24,local_28,local_2c,local_30);
  return param_1;
}



bool FUN_0041a384(undefined4 param_1,float param_2,float param_3)

{
  return param_2 < param_3;
}



void FUN_0041a3d0(float param_1,float param_2)

{
  FUN_0041a384(0,param_1,param_2);
  return;
}



int FUN_0041a414(int param_1,int param_2,int param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  uint local_118;
  uint local_114;
  allocator<char> aaStack_110 [4];
  basic_string<> abStack_10c [24];
  allocator<char> aaStack_f4 [4];
  basic_string<> abStack_f0 [24];
  allocator<char> aaStack_d8 [4];
  basic_string<> abStack_d4 [24];
  int local_bc;
  int local_b8;
  int iStack_b4;
  int local_b0;
  int local_ac;
  int iStack_a8;
  int local_a4;
  int local_a0;
  int iStack_9c;
  undefined4 local_98;
  undefined4 *local_94;
  undefined4 local_90;
  undefined auStack_88 [28];
  undefined auStack_6c [28];
  undefined auStack_50 [4];
  uint local_4c;
  undefined auStack_34 [32];
  
  if (param_3 == 1) {
    FUN_0041e690((int)auStack_50,param_2);
                    // try { // try from 0041a638 to 0041a63f has its CatchHandler @ 0041a8cc
    FUN_0041b7e0((int)auStack_34,1,local_4c);
    for (local_114 = 0; local_114 < local_4c; local_114 = local_114 + 1) {
                    // try { // try from 0041a66c to 0041a68f has its CatchHandler @ 0041a8b0
      FUN_0041e1ec(&local_b8,(int)auStack_50,local_114);
      FUN_0041e440(&local_bc,(int)auStack_50,local_114);
      FUN_0042082c(&iStack_b4,local_b8,local_bc);
      puVar1 = (undefined4 *)FUN_00420884(&iStack_b4);
      puVar2 = (undefined4 *)calculateOffset((int)auStack_34,0,local_114);
      *puVar2 = *puVar1;
    }
    FUN_004181b4(param_1,(int)auStack_34);
    FUN_00418168((int)auStack_34);
    FUN_00418168((int)auStack_50);
  }
  else if (param_3 == 2) {
    FUN_0041b7e0((int)auStack_6c,1,*(int *)(param_2 + 4));
    for (local_118 = 0; local_118 < *(uint *)(param_2 + 4); local_118 = local_118 + 1) {
                    // try { // try from 0041a55c to 0041a57b has its CatchHandler @ 0041a88c
      FUN_0041e1ec(&local_ac,param_2,local_118);
      FUN_0041e440(&local_b0,param_2,local_118);
      FUN_0042082c(&iStack_a8,local_ac,local_b0);
      puVar1 = (undefined4 *)FUN_00420884(&iStack_a8);
      puVar2 = (undefined4 *)calculateOffset((int)auStack_6c,0,local_118);
      *puVar2 = *puVar1;
    }
    FUN_004181b4(param_1,(int)auStack_6c);
    FUN_00418168((int)auStack_6c);
  }
  else if (param_3 == 0) {
    processDataBlock(&local_a0,param_2);
    copyDataToArray(&local_a4,param_2);
    FUN_0042082c(&iStack_9c,local_a0,local_a4);
    puVar1 = (undefined4 *)FUN_00420884(&iStack_9c);
    local_98 = *puVar1;
    local_94 = &local_98;
    local_90 = 1;
    FUN_0041e090((int)auStack_88,local_94,1);
    FUN_004181b4(param_1,(int)auStack_88);
    FUN_00418168((int)auStack_88);
  }
  else {
    std::allocator<char>::allocator();
                    // try { // try from 0041a75c to 0041a763 has its CatchHandler @ 0041a964
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_d4,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041a78c to 0041a793 has its CatchHandler @ 0041a938
    std::__cxx11::basic_string<>::basic_string((char *)abStack_f0,(allocator *)&DAT_00432e5c);
    std::allocator<char>::allocator();
                    // try { // try from 0041a7bc to 0041a7c3 has its CatchHandler @ 0041a90c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_10c,(allocator *)"Unimplemented axis type.");
                    // try { // try from 0041a7e0 to 0041a7e7 has its CatchHandler @ 0041a8f0
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_10c);
    std::allocator<char>::~allocator(aaStack_110);
    std::__cxx11::basic_string<>::~basic_string(abStack_f0);
    std::allocator<char>::~allocator(aaStack_f4);
    std::__cxx11::basic_string<>::~basic_string(abStack_d4);
    std::allocator<char>::~allocator(aaStack_d8);
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    *(undefined4 *)(param_1 + 0x10) = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined *)(param_1 + 0x18) = 0;
    FUN_004182ac(param_1);
  }
  return param_1;
}



bool FUN_0041a9b0(undefined4 param_1,float param_2,float param_3)

{
  return param_2 < param_3;
}



void FUN_0041a9fc(float param_1,float param_2)

{
  FUN_0041a9b0(0,param_1,param_2);
  return;
}



int FUN_0041aa40(int param_1,int param_2,int param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  uint local_118;
  uint local_114;
  allocator<char> aaStack_110 [4];
  basic_string<> abStack_10c [24];
  allocator<char> aaStack_f4 [4];
  basic_string<> abStack_f0 [24];
  allocator<char> aaStack_d8 [4];
  basic_string<> abStack_d4 [24];
  int local_bc;
  int local_b8;
  int iStack_b4;
  int local_b0;
  int local_ac;
  int iStack_a8;
  int local_a4;
  int local_a0;
  int iStack_9c;
  undefined4 local_98;
  undefined4 *local_94;
  undefined4 local_90;
  undefined auStack_88 [28];
  undefined auStack_6c [28];
  undefined auStack_50 [4];
  uint local_4c;
  undefined auStack_34 [32];
  
  if (param_3 == 1) {
    FUN_0041e690((int)auStack_50,param_2);
                    // try { // try from 0041ac64 to 0041ac6b has its CatchHandler @ 0041aef8
    FUN_0041b7e0((int)auStack_34,1,local_4c);
    for (local_114 = 0; local_114 < local_4c; local_114 = local_114 + 1) {
                    // try { // try from 0041ac98 to 0041acbb has its CatchHandler @ 0041aedc
      FUN_0041e1ec(&local_b8,(int)auStack_50,local_114);
      FUN_0041e440(&local_bc,(int)auStack_50,local_114);
      FUN_00420b54(&iStack_b4,local_b8,local_bc);
      puVar1 = (undefined4 *)FUN_00420884(&iStack_b4);
      puVar2 = (undefined4 *)calculateOffset((int)auStack_34,0,local_114);
      *puVar2 = *puVar1;
    }
    FUN_004181b4(param_1,(int)auStack_34);
    FUN_00418168((int)auStack_34);
    FUN_00418168((int)auStack_50);
  }
  else if (param_3 == 2) {
    FUN_0041b7e0((int)auStack_6c,1,*(int *)(param_2 + 4));
    for (local_118 = 0; local_118 < *(uint *)(param_2 + 4); local_118 = local_118 + 1) {
                    // try { // try from 0041ab88 to 0041aba7 has its CatchHandler @ 0041aeb8
      FUN_0041e1ec(&local_ac,param_2,local_118);
      FUN_0041e440(&local_b0,param_2,local_118);
      FUN_00420b54(&iStack_a8,local_ac,local_b0);
      puVar1 = (undefined4 *)FUN_00420884(&iStack_a8);
      puVar2 = (undefined4 *)calculateOffset((int)auStack_6c,0,local_118);
      *puVar2 = *puVar1;
    }
    FUN_004181b4(param_1,(int)auStack_6c);
    FUN_00418168((int)auStack_6c);
  }
  else if (param_3 == 0) {
    processDataBlock(&local_a0,param_2);
    copyDataToArray(&local_a4,param_2);
    FUN_00420b54(&iStack_9c,local_a0,local_a4);
    puVar1 = (undefined4 *)FUN_00420884(&iStack_9c);
    local_98 = *puVar1;
    local_94 = &local_98;
    local_90 = 1;
    FUN_0041e090((int)auStack_88,local_94,1);
    FUN_004181b4(param_1,(int)auStack_88);
    FUN_00418168((int)auStack_88);
  }
  else {
    std::allocator<char>::allocator();
                    // try { // try from 0041ad88 to 0041ad8f has its CatchHandler @ 0041af90
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_d4,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041adb8 to 0041adbf has its CatchHandler @ 0041af64
    std::__cxx11::basic_string<>::basic_string((char *)abStack_f0,(allocator *)&DAT_00432e60);
    std::allocator<char>::allocator();
                    // try { // try from 0041ade8 to 0041adef has its CatchHandler @ 0041af38
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_10c,(allocator *)"Unimplemented axis type.");
                    // try { // try from 0041ae0c to 0041ae13 has its CatchHandler @ 0041af1c
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_10c);
    std::allocator<char>::~allocator(aaStack_110);
    std::__cxx11::basic_string<>::~basic_string(abStack_f0);
    std::allocator<char>::~allocator(aaStack_f4);
    std::__cxx11::basic_string<>::~basic_string(abStack_d4);
    std::allocator<char>::~allocator(aaStack_d8);
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    *(undefined4 *)(param_1 + 0x10) = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined *)(param_1 + 0x18) = 0;
    FUN_004182ac(param_1);
  }
  return param_1;
}



bool FUN_0041afdc(float *param_1,float param_2)

{
  return param_2 <= *param_1;
}



int FUN_0041b028(int param_1,int param_2,undefined4 param_3)

{
  int local_30;
  int local_2c;
  int local_28;
  int iStack_24;
  undefined4 auStack_20 [2];
  undefined4 local_18;
  
  copyValuesToBuffer(auStack_20,param_2);
  FUN_0041d1f8(param_1,auStack_20);
  local_18 = param_3;
  processDataBlock(&local_28,param_2);
  copyDataToArray(&local_2c,param_2);
  FUN_0041cec0(&local_30,param_1);
                    // try { // try from 0041b0d0 to 0041b0d7 has its CatchHandler @ 0041b0e4
  FUN_00420bac(&iStack_24,local_28,local_2c,local_30);
  return param_1;
}



int FUN_0041b124(int param_1,int param_2,int param_3)

{
  FUN_00417658(param_1,param_2);
                    // try { // try from 0041b15c to 0041b163 has its CatchHandler @ 0041b16c
  FUN_00420c0c(param_1,param_3);
  return param_1;
}



// WARNING: Control flow encountered bad instruction data

int FUN_0041b1ac(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  double *pdVar3;
  double dVar4;
  double dVar5;
  uint local_138;
  uint local_134;
  allocator<char> aaStack_118 [4];
  basic_string<> abStack_114 [24];
  allocator<char> aaStack_fc [4];
  basic_string<> abStack_f8 [24];
  allocator<char> aaStack_e0 [4];
  basic_string<> abStack_dc [24];
  int local_c4;
  int local_c0;
  int local_bc;
  int local_b8 [6];
  int local_a0;
  int local_9c [8];
  undefined auStack_7c [28];
  undefined auStack_60 [28];
  undefined auStack_44 [28];
  
  if (param_3 == 1) {
    FUN_0041e690((int)auStack_60,param_2);
    iVar1 = FUN_00420f48((int)auStack_60);
                    // try { // try from 0041b430 to 0041b437 has its CatchHandler @ 0041b6ec
    dVar4 = (double)FUN_00417118((int)auStack_44,1,iVar1);
    for (local_134 = 0; uVar2 = FUN_00420f48((int)auStack_60), local_134 < uVar2;
        local_134 = local_134 + 1) {
                    // try { // try from 0041b478 to 0041b49b has its CatchHandler @ 0041b6d0
      FUN_0041e1ec(&local_c0,(int)auStack_60,local_134);
      FUN_0041e440(&local_c4,(int)auStack_60,local_134);
      FUN_00420ebc(local_c0,local_c4,0,0);
      uVar2 = FUN_00420f74((int)auStack_60);
      dVar5 = (double)(ulonglong)uVar2;
      pdVar3 = (double *)FUN_0041781c((int)auStack_44,0,local_134);
      dVar4 = dVar4 / dVar5;
      *pdVar3 = dVar4;
    }
    FUN_00416fd4(param_1,(int)auStack_44);
    FUN_00416f88((int)auStack_44);
    FUN_00418168((int)auStack_60);
  }
  else if (param_3 == 2) {
    iVar1 = FUN_00420f48(param_2);
    dVar4 = (double)FUN_00417118((int)auStack_7c,1,iVar1);
    for (local_138 = 0; uVar2 = FUN_00420f48(param_2), local_138 < uVar2; local_138 = local_138 + 1)
    {
                    // try { // try from 0041b334 to 0041b353 has its CatchHandler @ 0041b6ac
      FUN_0041e1ec(local_b8,param_2,local_138);
      FUN_0041e440(&local_bc,param_2,local_138);
      FUN_00420ebc(local_b8[0],local_bc,0,0);
      uVar2 = FUN_00420f74(param_2);
      dVar5 = (double)(ulonglong)uVar2;
      pdVar3 = (double *)FUN_0041781c((int)auStack_7c,0,local_138);
      dVar4 = dVar4 / dVar5;
      *pdVar3 = dVar4;
    }
    FUN_00416fd4(param_1,(int)auStack_7c);
    FUN_00416f88((int)auStack_7c);
  }
  else {
    if (param_3 == 0) {
      processDataBlock(local_9c,param_2);
      copyDataToArray(&local_a0,param_2);
      FUN_00420ebc(local_9c[0],local_a0,0,0);
      FUN_00418280(param_2);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    std::allocator<char>::allocator();
                    // try { // try from 0041b57c to 0041b583 has its CatchHandler @ 0041b784
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_dc,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/Functions/mean.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041b5ac to 0041b5b3 has its CatchHandler @ 0041b758
    std::__cxx11::basic_string<>::basic_string((char *)abStack_f8,(allocator *)&DAT_00432ed8);
    std::allocator<char>::allocator();
                    // try { // try from 0041b5dc to 0041b5e3 has its CatchHandler @ 0041b72c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_114,(allocator *)"Unimplemented axis type.");
                    // try { // try from 0041b600 to 0041b607 has its CatchHandler @ 0041b710
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_114);
    std::allocator<char>::~allocator(aaStack_118);
    std::__cxx11::basic_string<>::~basic_string(abStack_f8);
    std::allocator<char>::~allocator(aaStack_fc);
    std::__cxx11::basic_string<>::~basic_string(abStack_dc);
    std::allocator<char>::~allocator(aaStack_e0);
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    *(undefined4 *)(param_1 + 0x10) = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined *)(param_1 + 0x18) = 0;
    FUN_00415d50(param_1);
  }
  return param_1;
}



void FUN_0041b7e0(int param_1,int param_2,int param_3)

{
  FUN_0041df20();
  setTwoValues((undefined4 *)(param_1 + 4),param_2,param_3);
  *(int *)(param_1 + 0xc) = param_2 * param_3;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 0041b85c to 0041b863 has its CatchHandler @ 0041b86c
  FUN_0041ed34(param_1);
  return;
}



int calculateOffset(int baseAddress,int rowOffset,int columnOffset)

{
  int rowIndex;
  int columnIndex;
  
  rowIndex = rowOffset;
  if (rowOffset < 0) {
    rowIndex = *(int *)(baseAddress + 4) + rowOffset;
  }
  columnIndex = columnOffset;
  if (columnOffset < 0) {
    columnIndex = *(int *)(baseAddress + 8) + columnOffset;
  }
  return *(int *)(baseAddress + 0x14) + (*(int *)(baseAddress + 8) * rowIndex + columnIndex) * 4;
}



void FUN_0041b940(int param_1,int param_2,int param_3)

{
  FUN_00420fa0();
  setTwoValues((undefined4 *)(param_1 + 4),param_2,param_3);
  *(int *)(param_1 + 0xc) = param_2 * param_3;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 0041b9bc to 0041b9c3 has its CatchHandler @ 0041b9cc
  FUN_00421018(param_1);
  return;
}



void FUN_0041ba0c(int param_1)

{
  FUN_00421090(param_1);
  FUN_00420fdc();
  return;
}



void FUN_0041ba58(undefined4 *param_1)

{
  FUN_00421140(param_1);
  return;
}



void FUN_0041ba98(void)

{
  FUN_0042118c();
  return;
}



void FUN_0041bad4(undefined4 *param_1)

{
  FUN_004211c8(param_1);
  FUN_0041ba98();
  return;
}



void FUN_0041bb20(undefined4 *param_1)

{
  FUN_0042126c(param_1);
  return;
}



void FUN_0041bb60(void)

{
  FUN_004212b8();
  return;
}



void FUN_0041bb9c(undefined4 *param_1)

{
  FUN_004212f4(param_1);
  FUN_0041bb60();
  return;
}



int FUN_0041bbe8(int param_1,int param_2,int param_3)

{
  int local_res4;
  int local_res8;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 4) + param_2;
  }
  local_res8 = param_3;
  if (param_3 < 0) {
    local_res8 = *(int *)(param_1 + 8) + param_3;
  }
  return *(int *)(param_1 + 0x14) + (*(int *)(param_1 + 8) * local_res4 + local_res8) * 4;
}



void FUN_0041bc7c(int param_1,undefined4 param_2)

{
  undefined4 local_10 [2];
  
  FUN_0041c024(local_10,param_1);
  FUN_004213c0(param_1,local_10[0],param_2);
  return;
}



void FUN_0041bcd8(int param_1,undefined4 param_2)

{
  undefined4 local_10 [2];
  
  FUN_0041beb4(local_10,param_1);
  FUN_0042146c(param_1,local_10[0],param_2);
  return;
}



undefined4 FUN_0041bd34(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



int * FUN_0041bd60(int *param_1,int param_2)

{
  FUN_004214f0(param_1,*(int *)(param_2 + 0x14));
  return param_1;
}



int * FUN_0041bdac(int *param_1,int param_2)

{
  int *piVar1;
  int aiStack_10 [2];
  
  FUN_0041bd60(aiStack_10,param_2);
  piVar1 = FUN_004216f8(aiStack_10,*(int *)(param_2 + 0xc));
  *param_1 = *piVar1;
  return param_1;
}



void FUN_0041be20(int param_1,int param_2,undefined4 param_3)

{
  FUN_00421740(param_1,param_2,param_3);
  return;
}



undefined4 * FUN_0041be68(undefined4 *param_1,undefined4 *param_2)

{
  FUN_0042179c(param_1,*param_2);
  return param_1;
}



undefined4 * FUN_0041beb4(undefined4 *param_1,undefined4 param_2)

{
  FUN_0042179c(param_1,param_2);
  return param_1;
}



bool FUN_0041befc(int *param_1,int *param_2)

{
  return *param_1 != *param_2;
}



undefined4 * FUN_0041bf40(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = *param_2;
  *param_2 = *(undefined4 *)*param_2;
  return param_1;
}



void FUN_0041bf98(int *param_1)

{
  FUN_004217d4(*param_1);
  return;
}



undefined4 * FUN_0041bfd8(undefined4 *param_1,undefined4 *param_2)

{
  FUN_00421814(param_1,*param_2);
  return param_1;
}



undefined4 * FUN_0041c024(undefined4 *param_1,undefined4 param_2)

{
  FUN_00421814(param_1,param_2);
  return param_1;
}



bool FUN_0041c06c(int *param_1,int *param_2)

{
  return *param_1 != *param_2;
}



undefined4 * FUN_0041c0b0(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = *param_2;
  *param_2 = *(undefined4 *)*param_2;
  return param_1;
}



void FUN_0041c108(int *param_1)

{
  FUN_0042184c(*param_1);
  return;
}



// std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>
// >::basic_string<char*, void>(char*, char*, std::allocator<char> const&)

void __thiscall
std::__cxx11::basic_string<>::basic_string<char*,void>
          (basic_string<> *this,char *param_1,char *param_2,allocator *param_3)

{
  char *pcVar1;
  
  pcVar1 = (char *)std::__cxx11::basic_string<>::_M_local_data();
  std::__cxx11::basic_string<>::_Alloc_hider::_Alloc_hider((_Alloc_hider *)this,pcVar1,param_3);
                    // try { // try from 0041c19c to 0041c1a3 has its CatchHandler @ 0041c1ac
  FUN_0041c214((uint *)this,param_1,param_2);
  return;
}



undefined4 FUN_0041c1ec(undefined4 param_1)

{
  return param_1;
}



void FUN_0041c214(uint *param_1,char *param_2,char *param_3)

{
  FUN_0042188c(param_1,param_2,param_3);
  return;
}



void FUN_0041c264(int param_1)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0xc) != 0) {
    uVar1 = FUN_004218e0(param_1,*(uint *)(param_1 + 0xc));
    *(undefined4 *)(param_1 + 0x14) = uVar1;
    *(undefined *)(param_1 + 0x18) = 1;
  }
  return;
}



int * FUN_0041c2dc(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  FUN_00421954(param_1,param_2,param_3,param_4);
  return param_1;
}



void FUN_0041c334(int param_1)

{
  if ((*(char *)(param_1 + 0x18) != '\0') && (*(int *)(param_1 + 0x14) != 0)) {
    FUN_004219d4(param_1,*(void **)(param_1 + 0x14));
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_0041c3e4(void)

{
  return;
}



void FUN_0041c40c(void)

{
  return;
}



void FUN_0041c434(int *param_1,int param_2)

{
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  *param_1 = param_2;
  if (param_2 == 0) {
    std::allocator<char>::allocator();
                    // try { // try from 0041c490 to 0041c497 has its CatchHandler @ 0041c5f8
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayIterators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041c4c0 to 0041c4c7 has its CatchHandler @ 0041c5cc
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_48,(allocator *)"NdArrayConstIterator");
    std::allocator<char>::allocator();
                    // try { // try from 0041c4f0 to 0041c4f7 has its CatchHandler @ 0041c5a0
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"NdArray has not been initialized.");
                    // try { // try from 0041c514 to 0041c51b has its CatchHandler @ 0041c584
    FUN_00417bb8();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
  }
  return;
}



int * FUN_0041c63c(int *param_1)

{
  *param_1 = *param_1 + 8;
  return param_1;
}



undefined4 FUN_0041c678(undefined4 *param_1)

{
  return *param_1;
}



int * FUN_0041c6a4(int *param_1,int param_2)

{
  FUN_0041cdb4(param_1,param_2);
  return param_1;
}



int * FUN_0041c6ec(int *param_1,int param_2)

{
  FUN_0041ce00(param_1,param_2);
  return param_1;
}



bool FUN_0041c734(int *param_1,int *param_2)

{
  bool bVar1;
  
  bVar1 = FUN_00421a18(param_1,param_2);
  return !bVar1;
}



int * FUN_0041c77c(int *param_1)

{
  *param_1 = *param_1 + 1;
  return param_1;
}



undefined4 FUN_0041c7b8(undefined4 *param_1)

{
  return *param_1;
}



void FUN_0041c7e4(void **param_1,undefined4 param_2)

{
  undefined4 local_10 [2];
  
  if (param_1[1] == param_1[2]) {
    FUN_00421adc(local_10,(int)param_1);
    FUN_00421b28(param_1,local_10[0],param_2);
  }
  else {
    FUN_00421a84(param_1,param_1[1],param_2);
    param_1[1] = (void *)((int)param_1[1] + 4);
  }
  return;
}



void FUN_0041c894(int param_1,int *param_2,char param_3)

{
  int iVar1;
  undefined4 uVar2;
  int local_20;
  undefined4 local_1c;
  undefined4 local_18;
  int aiStack_14 [2];
  
  FUN_0041cb08();
  iVar1 = FUN_00417974(param_2);
  setTwoValues((undefined4 *)(param_1 + 4),1,iVar1);
  iVar1 = FUN_00415310((int *)(param_1 + 4));
  *(int *)(param_1 + 0xc) = iVar1;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  if (param_3 == '\0') {
    uVar2 = FUN_00421e98(param_2);
    *(undefined4 *)(param_1 + 0x14) = uVar2;
    *(undefined *)(param_1 + 0x18) = 0;
  }
  else {
                    // try { // try from 0041c938 to 0041c93f has its CatchHandler @ 0041c9d8
    FUN_0041d58c(param_1);
    if (*(int *)(param_1 + 0xc) != 0) {
      FUN_00421df8(&local_18,param_2);
      FUN_00421adc(&local_1c,(int)param_2);
      FUN_00417fa8(&local_20,param_1);
      FUN_00421e40(aiStack_14,local_18,local_1c,local_20);
    }
  }
  return;
}



void FUN_0041ca1c(void)

{
  FUN_00421edc();
  return;
}



void FUN_0041ca58(int param_1)

{
  if ((*(char *)(param_1 + 0x18) != '\0') && (*(int *)(param_1 + 0x14) != 0)) {
    FUN_00421f04(param_1,*(void **)(param_1 + 0x14));
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_0041cb08(void)

{
  FUN_00421f48();
  return;
}



int FUN_0041cb44(int param_1,int param_2)

{
  int local_res4;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 0xc) + param_2;
  }
  return *(int *)(param_1 + 0x14) + local_res4 * 4;
}



void releaseMemory(int **ptr)

{
  int iVar1;
  bool isMemoryReleased;
  
  if ((*ptr == (int *)0x0) || (iVar1 = (**(code **)(**ptr + 0x10))(*ptr), iVar1 == 0)) {
    isMemoryReleased = false;
  }
  else {
    isMemoryReleased = true;
  }
  if (isMemoryReleased) {
    *ptr = (int *)0x0;
  }
  return;
}



void FUN_0041cc34(int **param_1,int *param_2)

{
  releaseMemory(param_1);
  *param_1 = param_2;
  FUN_00421f70(param_1);
  return;
}



int FUN_0041cc8c(int param_1,int param_2)

{
  return param_1 + param_2 * 8;
}



void FUN_0041ccc4(void)

{
  FUN_004220d4();
  return;
}



void FUN_0041cd00(void)

{
  FUN_004220fc();
  return;
}



void FUN_0041cd3c(int param_1)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0xc) != 0) {
    uVar1 = FUN_00422124(param_1,*(uint *)(param_1 + 0xc));
    *(undefined4 *)(param_1 + 0x14) = uVar1;
    *(undefined *)(param_1 + 0x18) = 1;
  }
  return;
}



int * FUN_0041cdb4(int *param_1,int param_2)

{
  FUN_00422190(param_1,*(int *)(param_2 + 0x14));
  return param_1;
}



int * FUN_0041ce00(int *param_1,int param_2)

{
  int *piVar1;
  int aiStack_10 [2];
  
  FUN_0041cdb4(aiStack_10,param_2);
  piVar1 = FUN_00422398(aiStack_10,*(int *)(param_2 + 0xc));
  *param_1 = *piVar1;
  return param_1;
}



void FUN_0041ce74(int *param_1,int param_2)

{
  FUN_004223dc(param_1,param_2);
  return;
}



int * FUN_0041cec0(int *param_1,int param_2)

{
  FUN_0041ce74(param_1,*(int *)(param_2 + 0x14));
  return param_1;
}



int * FUN_0041cf0c(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  FUN_004225e4(param_1,param_2,param_3,param_4);
  return param_1;
}



void FUN_0041cf64(int param_1)

{
  if ((*(char *)(param_1 + 0x18) != '\0') && (*(int *)(param_1 + 0x14) != 0)) {
    FUN_00422664(param_1,*(void **)(param_1 + 0x14));
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_0041d014(void)

{
  FUN_0041ca1c();
  return;
}



void FUN_0041d050(undefined4 *param_1)

{
  FUN_004226a8(param_1);
  return;
}



void FUN_0041d090(void **param_1)

{
  FUN_004226fc(param_1,*param_1);
  FUN_0041d014();
  return;
}



undefined4 FUN_0041d108(undefined4 param_1)

{
  return param_1;
}



void FUN_0041d130(void)

{
  FUN_00422758();
  return;
}



undefined8 FUN_0041d178(undefined4 param_1,undefined4 param_2)

{
  undefined8 uVar1;
  
  uVar1 = FUN_0042279c(param_1,param_2);
  return uVar1;
}



undefined8 FUN_0041d1b8(undefined4 param_1,undefined4 param_2)

{
  undefined8 uVar1;
  
  uVar1 = FUN_004227dc(param_1,param_2);
  return uVar1;
}



void FUN_0041d1f8(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  FUN_0041ccc4();
  uVar2 = param_2[1];
  *(undefined4 *)(param_1 + 4) = *param_2;
  *(undefined4 *)(param_1 + 8) = uVar2;
  iVar1 = FUN_00415310((int *)(param_1 + 4));
  *(int *)(param_1 + 0xc) = iVar1;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 0041d278 to 0041d27f has its CatchHandler @ 0041d288
  FUN_0041cd3c(param_1);
  return;
}



int * FUN_0041d2c8(int *param_1,int param_2)

{
  int *piVar1;
  int aiStack_10 [2];
  
  FUN_0041cec0(aiStack_10,param_2);
  piVar1 = FUN_0042284c(aiStack_10,*(int *)(param_2 + 0xc));
  *param_1 = *piVar1;
  return param_1;
}



void FUN_0041d33c(int *param_1,int param_2)

{
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  *param_1 = param_2;
  if (param_2 == 0) {
    std::allocator<char>::allocator();
                    // try { // try from 0041d398 to 0041d39f has its CatchHandler @ 0041d500
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayIterators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041d3c8 to 0041d3cf has its CatchHandler @ 0041d4d4
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_48,(allocator *)"NdArrayConstIterator");
    std::allocator<char>::allocator();
                    // try { // try from 0041d3f8 to 0041d3ff has its CatchHandler @ 0041d4a8
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"NdArray has not been initialized.");
                    // try { // try from 0041d41c to 0041d423 has its CatchHandler @ 0041d48c
    FUN_00417bb8();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
  }
  return;
}



int * FUN_0041d544(int *param_1,int param_2)

{
  *param_1 = *param_1 + param_2 * 4;
  return param_1;
}



void FUN_0041d58c(int param_1)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0xc) != 0) {
    uVar1 = FUN_00422aec(param_1,*(uint *)(param_1 + 0xc));
    *(undefined4 *)(param_1 + 0x14) = uVar1;
    *(undefined *)(param_1 + 0x18) = 1;
  }
  return;
}



void FUN_0041d604(int *param_1,int param_2)

{
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  *param_1 = param_2;
  if (param_2 == 0) {
    std::allocator<char>::allocator();
                    // try { // try from 0041d660 to 0041d667 has its CatchHandler @ 0041d7c8
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayIterators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041d690 to 0041d697 has its CatchHandler @ 0041d79c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_48,(allocator *)"NdArrayConstIterator");
    std::allocator<char>::allocator();
                    // try { // try from 0041d6c0 to 0041d6c7 has its CatchHandler @ 0041d770
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"NdArray has not been initialized.");
                    // try { // try from 0041d6e4 to 0041d6eb has its CatchHandler @ 0041d754
    FUN_00417bb8();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
  }
  return;
}



void FUN_0041d80c(int param_1,uint param_2,uint param_3)

{
  allocator<char> aaStack_170 [4];
  basic_string<> abStack_16c [24];
  allocator<char> aaStack_154 [4];
  basic_string<> abStack_150 [24];
  basic_string<> abStack_138 [24];
  basic_string abStack_120 [6];
  basic_string abStack_108 [6];
  basic_string<> abStack_f0 [24];
  allocator<char> aaStack_d8 [4];
  basic_string<> abStack_d4 [24];
  allocator<char> aaStack_bc [4];
  basic_string<> abStack_b8 [24];
  basic_string<> abStack_a0 [24];
  basic_string abStack_88 [6];
  basic_string abStack_70 [6];
  basic_string<> abStack_58 [24];
  basic_string abStack_40 [6];
  basic_string abStack_28 [7];
  
  if (*(int *)(param_1 + 4) + -1 < (int)(((int)param_2 >> 0x1f ^ param_2) - ((int)param_2 >> 0x1f)))
  {
    FUN_00416908(abStack_58);
                    // try { // try from 0041d884 to 0041d88b has its CatchHandler @ 0041dc18
    FUN_00416790(abStack_40,"Row index ",(uint)abStack_58);
    std::__cxx11::basic_string<>::~basic_string(abStack_58);
                    // try { // try from 0041d8b0 to 0041d8b7 has its CatchHandler @ 0041dcf4
    FUN_0041685c(abStack_a0);
                    // try { // try from 0041d8d0 to 0041d8d7 has its CatchHandler @ 0041dc74
    FUN_00416790(abStack_88," is out of bounds for array of size ",(uint)abStack_a0);
                    // try { // try from 0041d8f0 to 0041d8f7 has its CatchHandler @ 0041dc58
    appendStringToBasicString(abStack_70,(char *)abStack_88);
                    // try { // try from 0041d908 to 0041d90f has its CatchHandler @ 0041dc3c
    std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_40,abStack_70);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_70);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_88);
    std::__cxx11::basic_string<>::~basic_string(abStack_a0);
    std::allocator<char>::allocator();
                    // try { // try from 0041d968 to 0041d96f has its CatchHandler @ 0041dcd8
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_b8,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041d998 to 0041d99f has its CatchHandler @ 0041dcac
    std::__cxx11::basic_string<>::basic_string((char *)abStack_d4,(allocator *)&DAT_00432db4);
                    // try { // try from 0041d9bc to 0041d9c3 has its CatchHandler @ 0041dc90
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_d4);
    std::allocator<char>::~allocator(aaStack_d8);
    std::__cxx11::basic_string<>::~basic_string(abStack_b8);
    std::allocator<char>::~allocator(aaStack_bc);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_40);
  }
  if (*(int *)(param_1 + 8) + -1 < (int)(((int)param_3 >> 0x1f ^ param_3) - ((int)param_3 >> 0x1f)))
  {
    FUN_00416908(abStack_f0);
                    // try { // try from 0041da6c to 0041da73 has its CatchHandler @ 0041dd18
    FUN_00416790(abStack_28,"Column index ",(uint)abStack_f0);
    std::__cxx11::basic_string<>::~basic_string(abStack_f0);
                    // try { // try from 0041da98 to 0041da9f has its CatchHandler @ 0041ddf4
    FUN_0041685c(abStack_138);
                    // try { // try from 0041dab8 to 0041dabf has its CatchHandler @ 0041dd74
    FUN_00416790(abStack_120," is out of bounds for array of size ",(uint)abStack_138);
                    // try { // try from 0041dad8 to 0041dadf has its CatchHandler @ 0041dd58
    appendStringToBasicString(abStack_108,(char *)abStack_120);
                    // try { // try from 0041daf0 to 0041daf7 has its CatchHandler @ 0041dd3c
    std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_28,abStack_108);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_108);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_120);
    std::__cxx11::basic_string<>::~basic_string(abStack_138);
    std::allocator<char>::allocator();
                    // try { // try from 0041db50 to 0041db57 has its CatchHandler @ 0041ddd8
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_150,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041db80 to 0041db87 has its CatchHandler @ 0041ddac
    std::__cxx11::basic_string<>::basic_string((char *)abStack_16c,(allocator *)&DAT_00432db4);
                    // try { // try from 0041dba4 to 0041dbab has its CatchHandler @ 0041dd90
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_16c);
    std::allocator<char>::~allocator(aaStack_170);
    std::__cxx11::basic_string<>::~basic_string(abStack_150);
    std::allocator<char>::~allocator(aaStack_154);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_28);
  }
  FUN_00422bdc(param_1,param_2,param_3);
  return;
}



void FUN_0041de34(void)

{
  FUN_00422c70();
  return;
}



void cleanupFunction(int param_1)

{
  if ((*(char *)(param_1 + 0x18) != '\0') && (*(int *)(param_1 + 0x14) != 0)) {
    FUN_00422c98(param_1,*(void **)(param_1 + 0x14));
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_0041df20(void)

{
  FUN_00422cdc();
  return;
}



float FUN_0041df5c(int param_1,int param_2,float param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  int local_res0;
  int local_res4;
  float local_res8;
  
  local_res0 = param_1;
  local_res4 = param_2;
  local_res8 = param_3;
  while (bVar1 = areNotEqualBytes(&local_res0,&local_res4), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res0);
    local_res8 = local_res8 + *pfVar2;
    FUN_00422d4c(&local_res0);
  }
  return local_res8;
}



undefined4 FUN_0041dfe0(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



undefined4 FUN_0041e00c(undefined4 *param_1)

{
  return *param_1;
}



int FUN_0041e038(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_0041e00c(param_1);
  iVar2 = FUN_0041dfe0((int)param_1);
  return iVar1 + iVar2 * 4;
}



void FUN_0041e090(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 local_res4;
  undefined4 local_res8;
  int local_18;
  int iStack_14;
  
  local_res4 = param_2;
  local_res8 = param_3;
  FUN_0041df20();
  uVar1 = FUN_0041dfe0((int)&local_res4);
  setTwoValues((undefined4 *)(param_1 + 4),1,uVar1);
  iVar2 = FUN_00415310((int *)(param_1 + 4));
  *(int *)(param_1 + 0xc) = iVar2;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 0041e12c to 0041e133 has its CatchHandler @ 0041e1a4
  FUN_0041ed34(param_1);
  if (*(int *)(param_1 + 0xc) != 0) {
    uVar1 = FUN_0041e00c(&local_res4);
    iVar2 = FUN_0041e038(&local_res4);
    FUN_00419164(&local_18,param_1);
    FUN_00422d88(&iStack_14,uVar1,iVar2,local_18);
  }
  return;
}



int * FUN_0041e1ec(int *param_1,int param_2,uint param_3)

{
  int *piVar1;
  int iStack_68;
  allocator<char> aaStack_64 [4];
  basic_string<> abStack_60 [24];
  allocator<char> aaStack_48 [4];
  basic_string<> abStack_44 [24];
  allocator<char> aaStack_2c [4];
  basic_string<> abStack_28 [28];
  
  if (*(uint *)(param_2 + 4) <= param_3) {
    std::allocator<char>::allocator();
                    // try { // try from 0041e24c to 0041e253 has its CatchHandler @ 0041e3fc
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_28,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041e27c to 0041e283 has its CatchHandler @ 0041e3d0
    std::__cxx11::basic_string<>::basic_string((char *)abStack_44,(allocator *)"cbegin");
    std::allocator<char>::allocator();
                    // try { // try from 0041e2ac to 0041e2b3 has its CatchHandler @ 0041e3a4
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_60,
               (allocator *)"input row is greater than the number of rows in the array.");
                    // try { // try from 0041e2d0 to 0041e2d7 has its CatchHandler @ 0041e388
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_60);
    std::allocator<char>::~allocator(aaStack_64);
    std::__cxx11::basic_string<>::~basic_string(abStack_44);
    std::allocator<char>::~allocator(aaStack_48);
    std::__cxx11::basic_string<>::~basic_string(abStack_28);
    std::allocator<char>::~allocator(aaStack_2c);
  }
  processDataBlock(&iStack_68,param_2);
  piVar1 = FUN_0041efb4(&iStack_68,*(int *)(param_2 + 8) * param_3);
  *param_1 = *piVar1;
  return param_1;
}



int * FUN_0041e440(int *param_1,int param_2,uint param_3)

{
  int *piVar1;
  int iStack_68;
  allocator<char> aaStack_64 [4];
  basic_string<> abStack_60 [24];
  allocator<char> aaStack_48 [4];
  basic_string<> abStack_44 [24];
  allocator<char> aaStack_2c [4];
  basic_string<> abStack_28 [28];
  
  if (*(uint *)(param_2 + 4) <= param_3) {
    std::allocator<char>::allocator();
                    // try { // try from 0041e4a0 to 0041e4a7 has its CatchHandler @ 0041e64c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_28,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041e4d0 to 0041e4d7 has its CatchHandler @ 0041e620
    std::__cxx11::basic_string<>::basic_string((char *)abStack_44,(allocator *)&DAT_00432e00);
    std::allocator<char>::allocator();
                    // try { // try from 0041e500 to 0041e507 has its CatchHandler @ 0041e5f4
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_60,
               (allocator *)"input row is greater than the number of rows in the array.");
                    // try { // try from 0041e524 to 0041e52b has its CatchHandler @ 0041e5d8
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_60);
    std::allocator<char>::~allocator(aaStack_64);
    std::__cxx11::basic_string<>::~basic_string(abStack_44);
    std::allocator<char>::~allocator(aaStack_48);
    std::__cxx11::basic_string<>::~basic_string(abStack_28);
    std::allocator<char>::~allocator(aaStack_2c);
  }
  FUN_0041e1ec(&iStack_68,param_2,param_3);
  piVar1 = FUN_0041efb4(&iStack_68,*(int *)(param_2 + 8));
  *param_1 = *piVar1;
  return param_1;
}



int FUN_0041e690(int param_1,int param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  uint local_18;
  uint local_14;
  
  FUN_0041b7e0(param_1,*(int *)(param_2 + 8),*(int *)(param_2 + 4));
  for (local_18 = 0; local_18 < *(uint *)(param_2 + 4); local_18 = local_18 + 1) {
    for (local_14 = 0; local_14 < *(uint *)(param_2 + 8); local_14 = local_14 + 1) {
      puVar1 = (undefined4 *)FUN_00422bdc(param_2,local_18,local_14);
      puVar2 = (undefined4 *)calculateOffset(param_1,local_14,local_18);
      *puVar2 = *puVar1;
    }
  }
  return param_1;
}



void FUN_0041e798(float param_1,undefined4 param_2,byte param_3)

{
  FUN_00422de0(param_1,param_2,param_3);
  return;
}



int * FUN_0041e7e0(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_00422e74(param_1,param_2,param_3,param_4);
  return param_1;
}



int FUN_0041e840(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int local_94;
  int local_90;
  int local_8c;
  int local_88;
  int iStack_84;
  undefined4 auStack_80 [2];
  allocator<char> aaStack_78 [4];
  basic_string<> abStack_74 [24];
  allocator<char> aaStack_5c [4];
  basic_string<> abStack_58 [24];
  allocator<char> aaStack_40 [4];
  basic_string<> abStack_3c [24];
  int aiStack_24 [2];
  int aiStack_1c [4];
  
  copyValuesToBuffer(aiStack_1c,param_2);
  copyValuesToBuffer(aiStack_24,param_3);
  uVar1 = FUN_004152c8(aiStack_1c,aiStack_24);
  if (uVar1 != 0) {
    std::allocator<char>::allocator();
                    // try { // try from 0041e8d0 to 0041e8d7 has its CatchHandler @ 0041ead8
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_3c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayOperators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041e900 to 0041e907 has its CatchHandler @ 0041eaac
    std::__cxx11::basic_string<>::basic_string((char *)abStack_58,(allocator *)"operator*");
    std::allocator<char>::allocator();
                    // try { // try from 0041e930 to 0041e937 has its CatchHandler @ 0041ea80
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_74,(allocator *)"Array dimensions do not match.");
                    // try { // try from 0041e954 to 0041e95b has its CatchHandler @ 0041ea64
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_74);
    std::allocator<char>::~allocator(aaStack_78);
    std::__cxx11::basic_string<>::~basic_string(abStack_58);
    std::allocator<char>::~allocator(aaStack_5c);
    std::__cxx11::basic_string<>::~basic_string(abStack_3c);
    std::allocator<char>::~allocator(aaStack_40);
  }
  copyValuesToBuffer(auStack_80,param_2);
  FUN_00418f88(param_1,auStack_80);
  processDataBlock(&local_88,param_2);
  copyDataToArray(&local_8c,param_2);
  processDataBlock(&local_90,param_3);
  FUN_00419164(&local_94,param_1);
                    // try { // try from 0041ea54 to 0041ea5b has its CatchHandler @ 0041eafc
  FUN_00422f54(&iStack_84,local_88,local_8c,local_90,local_94);
  return param_1;
}



float FUN_0041eb3c(float *param_1,float param_2)

{
  return *param_1 * param_2;
}



int FUN_0041eb74(int param_1,int param_2,undefined4 param_3)

{
  int local_30;
  int local_2c;
  int local_28;
  int iStack_24;
  undefined4 auStack_20 [2];
  undefined4 local_18;
  
  local_18 = param_3;
  copyValuesToBuffer(auStack_20,param_2);
  FUN_00418f88(param_1,auStack_20);
  processDataBlock(&local_28,param_2);
  copyDataToArray(&local_2c,param_2);
  FUN_00419164(&local_30,param_1);
                    // try { // try from 0041ec1c to 0041ec23 has its CatchHandler @ 0041ec30
  FUN_00422fb8(&iStack_24,local_28,local_2c,local_30);
  return param_1;
}



int * FUN_0041ec70(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_00423018(param_1,param_2,param_3,param_4);
  return param_1;
}



int * FUN_0041ecd0(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  FUN_004230f8(param_1,param_2,param_3,param_4,param_5);
  return param_1;
}



void FUN_0041ed34(int param_1)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0xc) != 0) {
    uVar1 = FUN_00423208(param_1,*(uint *)(param_1 + 0xc));
    *(undefined4 *)(param_1 + 0x14) = uVar1;
    *(undefined *)(param_1 + 0x18) = 1;
  }
  return;
}



void handleException(int *errorCode,int exceptionCode)

{
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  *errorCode = exceptionCode;
  if (exceptionCode == 0) {
    std::allocator<char>::allocator();
                    // try { // try from 0041ee08 to 0041ee0f has its CatchHandler @ 0041ef70
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayIterators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041ee38 to 0041ee3f has its CatchHandler @ 0041ef44
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_48,(allocator *)"NdArrayConstIterator");
    std::allocator<char>::allocator();
                    // try { // try from 0041ee68 to 0041ee6f has its CatchHandler @ 0041ef18
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"NdArray has not been initialized.");
                    // try { // try from 0041ee8c to 0041ee93 has its CatchHandler @ 0041eefc
    FUN_00417bb8();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
  }
  return;
}



int * FUN_0041efb4(int *param_1,int param_2)

{
  *param_1 = *param_1 + param_2 * 4;
  return param_1;
}



void FUN_0041effc(int *param_1,int param_2)

{
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  *param_1 = param_2;
  if (param_2 == 0) {
    std::allocator<char>::allocator();
                    // try { // try from 0041f058 to 0041f05f has its CatchHandler @ 0041f1c0
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayIterators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041f088 to 0041f08f has its CatchHandler @ 0041f194
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_48,(allocator *)"NdArrayConstIterator");
    std::allocator<char>::allocator();
                    // try { // try from 0041f0b8 to 0041f0bf has its CatchHandler @ 0041f168
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"NdArray has not been initialized.");
                    // try { // try from 0041f0dc to 0041f0e3 has its CatchHandler @ 0041f14c
    FUN_00417bb8();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
  }
  return;
}



int * FUN_0041f204(int *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  float fVar5;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar5 = *pfVar2;
    puVar3 = (undefined4 *)FUN_004232bc(&local_resc);
    uVar4 = FUN_00416348(&stack0x00000010,fVar5);
    *puVar3 = uVar4;
    FUN_00422d4c(&local_res4);
    FUN_0042327c(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



int * FUN_0041f2e4(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_004232f8(param_1,param_2,param_3,param_4);
  return param_1;
}



int * FUN_0041f344(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  FUN_004233d8(param_1,param_2,param_3,param_4);
  return param_1;
}



int FUN_0041f39c(int param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int local_b8;
  int local_b4;
  int local_b0;
  uint local_ac;
  uint local_a8;
  int local_8c [2];
  allocator<char> aaStack_84 [4];
  basic_string<> abStack_80 [24];
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  undefined4 uStack_30;
  int local_2c;
  int local_28;
  int local_24;
  uint local_20;
  uint local_1c;
  int local_18;
  int local_14;
  
  local_28 = 0;
  local_24 = 0;
  local_b8 = FUN_00423458(param_2);
  iVar1 = FUN_00423484(param_2);
  for (; local_b8 != iVar1; local_b8 = local_b8 + 0x1c) {
    iVar2 = FUN_00415348(&local_28);
    if (iVar2 == 0) {
      copyValuesToBuffer(&uStack_30,local_b8);
      if (local_2c == local_24) {
        copyValuesToBuffer(local_8c,local_b8);
        local_28 = local_8c[0] + local_28;
      }
      else {
        std::allocator<char>::allocator();
                    // try { // try from 0041f49c to 0041f4a3 has its CatchHandler @ 0041f774
        std::__cxx11::basic_string<>::basic_string
                  ((char *)abStack_48,
                   (allocator *)
                   "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/Functions/row_stack.hpp"
                  );
        std::allocator<char>::allocator();
                    // try { // try from 0041f4cc to 0041f4d3 has its CatchHandler @ 0041f748
        std::__cxx11::basic_string<>::basic_string((char *)abStack_64,(allocator *)"row_stack");
        std::allocator<char>::allocator();
                    // try { // try from 0041f4fc to 0041f503 has its CatchHandler @ 0041f71c
        std::__cxx11::basic_string<>::basic_string
                  ((char *)abStack_80,
                   (allocator *)"input arrays must have the same number of columns.");
                    // try { // try from 0041f520 to 0041f527 has its CatchHandler @ 0041f700
        MAYBElogAndThrowException();
        std::__cxx11::basic_string<>::~basic_string(abStack_80);
        std::allocator<char>::~allocator(aaStack_84);
        std::__cxx11::basic_string<>::~basic_string(abStack_64);
        std::allocator<char>::~allocator(aaStack_68);
        std::__cxx11::basic_string<>::~basic_string(abStack_48);
        std::allocator<char>::~allocator(aaStack_4c);
      }
    }
    else {
      copyValuesToBuffer(&local_18,local_b8);
      local_28 = local_18;
      local_24 = local_14;
    }
  }
  FUN_00418f88(param_1,&local_28);
  local_b4 = 0;
  local_b0 = FUN_00423458(param_2);
  iVar1 = FUN_00423484(param_2);
  for (; local_b0 != iVar1; local_b0 = local_b0 + 0x1c) {
    copyValuesToBuffer(&local_20,local_b0);
    for (local_ac = 0; local_ac < local_20; local_ac = local_ac + 1) {
      for (local_a8 = 0; local_a8 < local_1c; local_a8 = local_a8 + 1) {
        puVar3 = (undefined4 *)FUN_00422bdc(local_b0,local_ac,local_a8);
        puVar4 = (undefined4 *)calculateOffset(param_1,local_b4 + local_ac,local_a8);
        *puVar4 = *puVar3;
      }
    }
    local_b4 = local_b4 + local_20;
  }
  return param_1;
}



int FUN_0041f7bc(int param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int local_b8;
  int local_b4;
  int local_b0;
  uint local_ac;
  uint local_a8;
  undefined4 uStack_8c;
  int local_88;
  allocator<char> aaStack_84 [4];
  basic_string<> abStack_80 [24];
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  int local_30 [2];
  int local_28;
  int local_24;
  uint local_20;
  uint local_1c;
  int local_18;
  int local_14;
  
  local_28 = 0;
  local_24 = 0;
  local_b8 = FUN_00423458(param_2);
  iVar1 = FUN_00423484(param_2);
  for (; local_b8 != iVar1; local_b8 = local_b8 + 0x1c) {
    iVar2 = FUN_00415348(&local_28);
    if (iVar2 == 0) {
      copyValuesToBuffer(local_30,local_b8);
      if (local_30[0] == local_28) {
        copyValuesToBuffer(&uStack_8c,local_b8);
        local_24 = local_88 + local_24;
      }
      else {
        std::allocator<char>::allocator();
                    // try { // try from 0041f8bc to 0041f8c3 has its CatchHandler @ 0041fb90
        std::__cxx11::basic_string<>::basic_string
                  ((char *)abStack_48,
                   (allocator *)
                   "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/Functions/column_stack.hpp"
                  );
        std::allocator<char>::allocator();
                    // try { // try from 0041f8ec to 0041f8f3 has its CatchHandler @ 0041fb64
        std::__cxx11::basic_string<>::basic_string((char *)abStack_64,(allocator *)"column_stack");
        std::allocator<char>::allocator();
                    // try { // try from 0041f91c to 0041f923 has its CatchHandler @ 0041fb38
        std::__cxx11::basic_string<>::basic_string
                  ((char *)abStack_80,(allocator *)"input arrays must have the same number of rows."
                  );
                    // try { // try from 0041f940 to 0041f947 has its CatchHandler @ 0041fb1c
        MAYBElogAndThrowException();
        std::__cxx11::basic_string<>::~basic_string(abStack_80);
        std::allocator<char>::~allocator(aaStack_84);
        std::__cxx11::basic_string<>::~basic_string(abStack_64);
        std::allocator<char>::~allocator(aaStack_68);
        std::__cxx11::basic_string<>::~basic_string(abStack_48);
        std::allocator<char>::~allocator(aaStack_4c);
      }
    }
    else {
      copyValuesToBuffer(&local_18,local_b8);
      local_28 = local_18;
      local_24 = local_14;
    }
  }
  FUN_00418f88(param_1,&local_28);
  local_b4 = 0;
  local_b0 = FUN_00423458(param_2);
  iVar1 = FUN_00423484(param_2);
  for (; local_b0 != iVar1; local_b0 = local_b0 + 0x1c) {
    copyValuesToBuffer(&local_20,local_b0);
    for (local_ac = 0; local_ac < local_20; local_ac = local_ac + 1) {
      for (local_a8 = 0; local_a8 < local_1c; local_a8 = local_a8 + 1) {
        puVar3 = (undefined4 *)FUN_00422bdc(local_b0,local_ac,local_a8);
        puVar4 = (undefined4 *)calculateOffset(param_1,local_ac,local_b4 + local_a8);
        *puVar4 = *puVar3;
      }
    }
    local_b4 = local_b4 + local_1c;
  }
  return param_1;
}



int * FUN_0041fbd8(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_004234ec(param_1,param_2,param_3,param_4);
  return param_1;
}



int * FUN_0041fc38(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  FUN_004235cc(param_1,param_2,param_3,param_4,param_5);
  return param_1;
}



undefined4 FUN_0041fc9c(undefined4 param_1,char param_2,char param_3)

{
  undefined4 uVar1;
  
  if ((param_2 == '\0') || (param_3 == '\0')) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_0041fcfc(char param_1,char param_2)

{
  FUN_0041fc9c(0,param_1,param_2);
  return;
}



int FUN_0041fd54(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int local_98;
  int local_94;
  int local_90;
  int local_8c;
  int iStack_88;
  undefined4 auStack_84 [2];
  allocator<char> aaStack_7c [4];
  basic_string<> abStack_78 [24];
  allocator<char> aaStack_60 [4];
  basic_string<> abStack_5c [24];
  allocator<char> aaStack_44 [4];
  basic_string<> abStack_40 [24];
  int aiStack_28 [2];
  int aiStack_20 [5];
  
  FUN_004177d8(aiStack_20,param_2);
  FUN_004177d8(aiStack_28,param_3);
  uVar1 = FUN_004152c8(aiStack_20,aiStack_28);
  if (uVar1 != 0) {
    std::allocator<char>::allocator();
                    // try { // try from 0041fde4 to 0041fdeb has its CatchHandler @ 0041fff0
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_40,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayOperators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0041fe14 to 0041fe1b has its CatchHandler @ 0041ffc4
    std::__cxx11::basic_string<>::basic_string((char *)abStack_5c,(allocator *)"operator&&");
    std::allocator<char>::allocator();
                    // try { // try from 0041fe44 to 0041fe4b has its CatchHandler @ 0041ff98
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_78,(allocator *)"Array dimensions do not match.");
                    // try { // try from 0041fe68 to 0041fe6f has its CatchHandler @ 0041ff7c
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_78);
    std::allocator<char>::~allocator(aaStack_7c);
    std::__cxx11::basic_string<>::~basic_string(abStack_5c);
    std::allocator<char>::~allocator(aaStack_60);
    std::__cxx11::basic_string<>::~basic_string(abStack_40);
    std::allocator<char>::~allocator(aaStack_44);
  }
  FUN_004177d8(auStack_84,param_2);
  FUN_0041d1f8(param_1,auStack_84);
  FUN_0041cdb4(&local_8c,param_2);
  FUN_0041ce00(&local_90,param_2);
  FUN_0041cdb4(&local_94,param_3);
  FUN_0041cec0(&local_98,param_1);
                    // try { // try from 0041ff68 to 0041ff6f has its CatchHandler @ 00420014
  FUN_004236dc(&iStack_88,local_8c,local_90,local_94,local_98);
  return param_1;
}



void FUN_00420054(int param_1,int param_2,int param_3)

{
  FUN_0041ccc4();
  setTwoValues((undefined4 *)(param_1 + 4),param_2,param_3);
  *(int *)(param_1 + 0xc) = param_2 * param_3;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
                    // try { // try from 004200d0 to 004200d7 has its CatchHandler @ 004200e0
  FUN_0041cd3c(param_1);
  return;
}



void FUN_00420120(int *param_1,uint param_2)

{
  FUN_00423740(param_1,param_2);
                    // try { // try from 00420160 to 00420167 has its CatchHandler @ 00420170
  FUN_004237cc(param_1,param_2);
  return;
}



int FUN_004201b0(int *param_1,int param_2)

{
  return *param_1 + param_2 * 4;
}



int FUN_004201ec(int param_1,int param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  undefined3 extraout_var;
  uint *puVar4;
  uint uVar5;
  undefined *puVar6;
  int local_78;
  allocator<char> aaStack_6c [4];
  basic_string<> abStack_68 [24];
  allocator<char> aaStack_50 [4];
  basic_string<> abStack_4c [24];
  allocator<char> aaStack_34 [4];
  basic_string<> abStack_30 [24];
  int iStack_18;
  int aiStack_14 [2];
  
  iVar2 = FUN_00417504(param_2);
  iVar3 = FUN_00423840(param_3);
  if (iVar2 != iVar3) {
    std::allocator<char>::allocator();
                    // try { // try from 00420264 to 0042026b has its CatchHandler @ 0042048c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_30,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 00420294 to 0042029b has its CatchHandler @ 00420460
    std::__cxx11::basic_string<>::basic_string((char *)abStack_4c,(allocator *)&DAT_00432eac);
    std::allocator<char>::allocator();
                    // try { // try from 004202c4 to 004202cb has its CatchHandler @ 00420434
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_68,(allocator *)"Input indices do not match values dimensions.");
                    // try { // try from 004202e8 to 004202ef has its CatchHandler @ 00420418
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_68);
    std::allocator<char>::~allocator(aaStack_6c);
    std::__cxx11::basic_string<>::~basic_string(abStack_4c);
    std::allocator<char>::~allocator(aaStack_50);
    std::__cxx11::basic_string<>::~basic_string(abStack_30);
    std::allocator<char>::~allocator(aaStack_34);
  }
  local_78 = 0;
  FUN_00422958(&iStack_18,param_2);
  FUN_004229a0(aiStack_14,param_2);
  while (bVar1 = FUN_004229e8(&iStack_18,aiStack_14), CONCAT31(extraout_var,bVar1) != 0) {
    puVar4 = (uint *)FUN_00422a6c(&iStack_18);
    uVar5 = *puVar4;
    puVar6 = (undefined *)FUN_0042386c(param_3,local_78);
    FUN_004238c4(param_1,uVar5,*puVar6);
    FUN_00422a30(&iStack_18);
    local_78 = local_78 + 1;
  }
  return param_1;
}



int FUN_004204cc(int param_1,int param_2)

{
  int local_res4;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 0xc) + param_2;
  }
  return *(int *)(param_1 + 0x14) + local_res4 * 4;
}



int * FUN_00420528(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_0042391c(param_1,param_2,param_3,param_4);
  return param_1;
}



undefined4 FUN_00420588(undefined4 param_1)

{
  return param_1;
}



void FUN_004205b0(undefined4 param_1,undefined param_2)

{
  undefined local_res4 [12];
  
  local_res4[0] = param_2;
  FUN_00420588(local_res4);
  return;
}



undefined4 FUN_004205f4(undefined4 param_1,undefined param_2)

{
  undefined unaff_s0;
  undefined local_res4 [12];
  
  local_res4[0] = param_2;
  FUN_00420588(local_res4);
  FUN_004205b0(param_1,unaff_s0);
  return param_1;
}



void FUN_00420650(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  float *pfVar1;
  float fVar2;
  undefined4 local_res4;
  undefined4 local_res8 [2];
  
  local_res4 = param_2;
  local_res8[0] = param_3;
  pfVar1 = (float *)FUN_00420884(&local_res4);
  fVar2 = *pfVar1;
  pfVar1 = (float *)FUN_00420884(local_res8);
  FUN_0041a384(param_1,fVar2,*pfVar1);
  return;
}



int * FUN_004206d4(int *param_1,int param_2,int param_3,undefined param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  int *piVar2;
  undefined3 extraout_var_00;
  int iVar3;
  int local_res4;
  int local_res8;
  undefined local_resc [4];
  int local_10;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc[0] = param_4;
  bVar1 = intEquals(&local_res4,&local_res8);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_10 = local_res4;
    while( true ) {
      piVar2 = FUN_00422d4c(&local_res4);
      bVar1 = areNotEqualBytes(piVar2,&local_res8);
      if (CONCAT31(extraout_var_00,bVar1) == 0) break;
      iVar3 = FUN_00420650(local_resc,local_res4,local_10);
      if (iVar3 != 0) {
        local_10 = local_res4;
      }
    }
    *param_1 = local_10;
  }
  else {
    *param_1 = local_res4;
  }
  return param_1;
}



int * FUN_004207b8(int *param_1,int param_2,int param_3)

{
  undefined in_v0;
  undefined unaff_s0;
  undefined auStack_18 [12];
  
  FUN_004205f4(auStack_18,in_v0);
  FUN_004206d4(param_1,param_2,param_3,unaff_s0);
  return param_1;
}



int * FUN_0042082c(int *param_1,int param_2,int param_3)

{
  FUN_004207b8(param_1,param_2,param_3);
  return param_1;
}



// junk

undefined4 FUN_00420884(undefined4 *param_1)

{
  return *param_1;
}



undefined4 FUN_004208b0(undefined4 param_1)

{
  return param_1;
}



void FUN_004208d8(undefined4 param_1,undefined param_2)

{
  undefined local_res4 [12];
  
  local_res4[0] = param_2;
  FUN_004208b0(local_res4);
  return;
}



undefined4 FUN_0042091c(undefined4 param_1,undefined param_2)

{
  undefined unaff_s0;
  undefined local_res4 [12];
  
  local_res4[0] = param_2;
  FUN_004208b0(local_res4);
  FUN_004208d8(param_1,unaff_s0);
  return param_1;
}



void FUN_00420978(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  float *pfVar1;
  float fVar2;
  undefined4 local_res4;
  undefined4 local_res8 [2];
  
  local_res4 = param_2;
  local_res8[0] = param_3;
  pfVar1 = (float *)FUN_00420884(&local_res4);
  fVar2 = *pfVar1;
  pfVar1 = (float *)FUN_00420884(local_res8);
  FUN_0041a9b0(param_1,fVar2,*pfVar1);
  return;
}



int * FUN_004209fc(int *param_1,int param_2,int param_3,undefined param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  int *piVar2;
  undefined3 extraout_var_00;
  int iVar3;
  int local_res4;
  int local_res8;
  undefined local_resc [4];
  int local_10;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc[0] = param_4;
  bVar1 = intEquals(&local_res4,&local_res8);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_10 = local_res4;
    while( true ) {
      piVar2 = FUN_00422d4c(&local_res4);
      bVar1 = areNotEqualBytes(piVar2,&local_res8);
      if (CONCAT31(extraout_var_00,bVar1) == 0) break;
      iVar3 = FUN_00420978(local_resc,local_10,local_res4);
      if (iVar3 != 0) {
        local_10 = local_res4;
      }
    }
    *param_1 = local_10;
  }
  else {
    *param_1 = local_res4;
  }
  return param_1;
}



int * FUN_00420ae0(int *param_1,int param_2,int param_3)

{
  undefined in_v0;
  undefined unaff_s0;
  undefined auStack_18 [12];
  
  FUN_0042091c(auStack_18,in_v0);
  FUN_004209fc(param_1,param_2,param_3,unaff_s0);
  return param_1;
}



int * FUN_00420b54(int *param_1,int param_2,int param_3)

{
  FUN_00420ae0(param_1,param_2,param_3);
  return param_1;
}



int * FUN_00420bac(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_00423a40(param_1,param_2,param_3,param_4);
  return param_1;
}



int FUN_00420c0c(int param_1,int param_2)

{
  uint uVar1;
  int local_8c;
  int local_88;
  int local_84;
  int local_80;
  int iStack_7c;
  allocator<char> aaStack_78 [4];
  basic_string<> abStack_74 [24];
  allocator<char> aaStack_5c [4];
  basic_string<> abStack_58 [24];
  allocator<char> aaStack_40 [4];
  basic_string<> abStack_3c [24];
  int aiStack_24 [2];
  int aiStack_1c [4];
  
  FUN_004177d8(aiStack_1c,param_1);
  FUN_004177d8(aiStack_24,param_2);
  uVar1 = FUN_004152c8(aiStack_1c,aiStack_24);
  if (uVar1 != 0) {
    std::allocator<char>::allocator();
                    // try { // try from 00420c98 to 00420c9f has its CatchHandler @ 00420e7c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_3c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayOperators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 00420cc8 to 00420ccf has its CatchHandler @ 00420e50
    std::__cxx11::basic_string<>::basic_string((char *)abStack_58,(allocator *)"operator&=");
    std::allocator<char>::allocator();
                    // try { // try from 00420cf8 to 00420cff has its CatchHandler @ 00420e24
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_74,(allocator *)"Array dimensions do not match.");
                    // try { // try from 00420d1c to 00420d23 has its CatchHandler @ 00420e08
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_74);
    std::allocator<char>::~allocator(aaStack_78);
    std::__cxx11::basic_string<>::~basic_string(abStack_58);
    std::allocator<char>::~allocator(aaStack_5c);
    std::__cxx11::basic_string<>::~basic_string(abStack_3c);
    std::allocator<char>::~allocator(aaStack_40);
  }
  FUN_0041cec0(&local_80,param_1);
  FUN_0041d2c8(&local_84,param_1);
  FUN_0041cdb4(&local_88,param_2);
  FUN_0041cec0(&local_8c,param_1);
  FUN_00423b20(&iStack_7c,local_80,local_84,local_88,local_8c);
  return param_1;
}



// WARNING: Control flow encountered bad instruction data

longlong FUN_00420ebc(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  uint in_v1;
  int local_res0;
  int local_res4;
  undefined4 local_res8;
  undefined4 uStackX_c;
  
  local_res0 = param_1;
  local_res4 = param_2;
  local_res8 = param_3;
  uStackX_c = param_4;
  bVar1 = areNotEqualBytes(&local_res0,&local_res4);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    FUN_00420884(&local_res0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return (ulonglong)in_v1 << 0x20;
}



undefined4 FUN_00420f48(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



undefined4 FUN_00420f74(int param_1)

{
  return *(undefined4 *)(param_1 + 8);
}



void FUN_00420fa0(void)

{
  FUN_00423b84();
  return;
}



void FUN_00420fdc(void)

{
  FUN_00423bac();
  return;
}



void FUN_00421018(int param_1)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0xc) != 0) {
    uVar1 = FUN_00423bd4(param_1,*(uint *)(param_1 + 0xc));
    *(undefined4 *)(param_1 + 0x14) = uVar1;
    *(undefined *)(param_1 + 0x18) = 1;
  }
  return;
}



void FUN_00421090(int param_1)

{
  if ((*(char *)(param_1 + 0x18) != '\0') && (*(int *)(param_1 + 0x14) != 0)) {
    FUN_00423c48(param_1,*(void **)(param_1 + 0x14));
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_00421140(undefined4 *param_1)

{
  FUN_00423c8c(param_1);
  FUN_00423d00((int)param_1);
  return;
}



void FUN_0042118c(void)

{
  FUN_00423d58();
  return;
}



void FUN_004211c8(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 *local_18;
  
  local_18 = (undefined4 *)*param_1;
  while (local_18 != param_1) {
    puVar1 = (undefined4 *)*local_18;
    FUN_0042184c((int)local_18);
    FUN_00423d80(param_1);
    FUN_00423da8();
    FUN_00423dec(param_1,local_18);
    local_18 = puVar1;
  }
  return;
}



void FUN_0042126c(undefined4 *param_1)

{
  FUN_00423e38(param_1);
  FUN_00423eac((int)param_1);
  return;
}



void FUN_004212b8(void)

{
  FUN_00423f04();
  return;
}



void FUN_004212f4(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 *local_18;
  
  local_18 = (undefined4 *)*param_1;
  while (local_18 != param_1) {
    puVar1 = (undefined4 *)*local_18;
    FUN_004217d4((int)local_18);
    FUN_00423f2c(param_1);
    FUN_00423f54();
    FUN_00423f98(param_1,local_18);
    local_18 = puVar1;
  }
  return;
}



undefined4 FUN_00421398(undefined4 param_1)

{
  return param_1;
}



void FUN_004213c0(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  _List_node_base *p_Var2;
  
  uVar1 = FUN_00421398(param_3);
  p_Var2 = (_List_node_base *)FUN_00423fe4(param_1,uVar1);
  std::__detail::_List_node_base::_M_hook(p_Var2);
  FUN_004240e4(param_1,1);
  return;
}



undefined4 FUN_00421444(undefined4 param_1)

{
  return param_1;
}



void FUN_0042146c(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  _List_node_base *p_Var2;
  
  uVar1 = FUN_00421444(param_3);
  p_Var2 = (_List_node_base *)FUN_00424138(param_1,uVar1);
  std::__detail::_List_node_base::_M_hook(p_Var2);
  FUN_00424238(param_1,1);
  return;
}



void FUN_004214f0(int *param_1,int param_2)

{
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  *param_1 = param_2;
  if (param_2 == 0) {
    std::allocator<char>::allocator();
                    // try { // try from 0042154c to 00421553 has its CatchHandler @ 004216b4
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayIterators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0042157c to 00421583 has its CatchHandler @ 00421688
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_48,(allocator *)"NdArrayConstIterator");
    std::allocator<char>::allocator();
                    // try { // try from 004215ac to 004215b3 has its CatchHandler @ 0042165c
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"NdArray has not been initialized.");
                    // try { // try from 004215d0 to 004215d7 has its CatchHandler @ 00421640
    FUN_00417bb8();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
  }
  return;
}



int * FUN_004216f8(int *param_1,int param_2)

{
  *param_1 = *param_1 + param_2 * 4;
  return param_1;
}



void FUN_00421740(int param_1,int param_2,undefined4 param_3)

{
  int *local_10 [2];
  
  FUN_0042428c(local_10,param_3);
  FUN_004242d0(param_1,param_2,local_10[0]);
  return;
}



void FUN_0042179c(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return;
}



void FUN_004217d4(int param_1)

{
  FUN_00424364(param_1 + 8);
  return;
}



void FUN_00421814(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return;
}



void FUN_0042184c(int param_1)

{
  FUN_0042439c(param_1 + 8);
  return;
}



void FUN_0042188c(uint *param_1,char *param_2,char *param_3)

{
  std::__cxx11::basic_string<>::_M_construct<char*>(param_1,param_2,param_3);
  return;
}



void FUN_004218e0(undefined4 param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_0042453c();
  if (uVar1 < param_2) {
    std::__throw_bad_alloc();
  }
  operator_new(param_2 << 3);
  return;
}



int * FUN_00421954(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_00424568(param_2);
  uVar2 = FUN_00424568(param_3);
  FUN_00424590(param_1,uVar1,uVar2,param_4);
  return param_1;
}



void FUN_004219d4(undefined4 param_1,void *param_2)

{
  operator_delete(param_2);
  return;
}



bool FUN_00421a18(int *param_1,int *param_2)

{
  return *param_1 == *param_2;
}



undefined4 FUN_00421a5c(undefined4 param_1)

{
  return param_1;
}



void FUN_00421a84(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00421a5c(param_3);
  FUN_0042462c(param_1,param_2,uVar1);
  return;
}



undefined4 * FUN_00421adc(undefined4 *param_1,int param_2)

{
  FUN_0042469c(param_1,(undefined4 *)(param_2 + 4));
  return param_1;
}



void FUN_00421b28(void **param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  void *pvVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  void *pvVar6;
  undefined4 local_res4;
  undefined4 local_res8;
  undefined4 auStack_18 [2];
  
  local_res4 = param_2;
  local_res8 = param_3;
  uVar1 = FUN_004246d8((int *)param_1,1,"vector::_M_realloc_insert");
  FUN_00421df8(auStack_18,param_1);
  iVar2 = FUN_004247f4(&local_res4,auStack_18);
  pvVar3 = (void *)FUN_00424858(param_1,uVar1);
  uVar4 = FUN_00421a5c(local_res8);
  FUN_00421a84(param_1,(void *)((int)pvVar3 + iVar2 * 4),uVar4);
  pvVar6 = *param_1;
  puVar5 = (undefined4 *)FUN_004248b4(&local_res4);
  uVar4 = *puVar5;
  FUN_0041d108(param_1);
                    // try { // try from 00421c2c to 00421c87 has its CatchHandler @ 00421d34
  iVar2 = FUN_004248dc(pvVar6,uVar4,pvVar3);
  puVar5 = (undefined4 *)FUN_004248b4(&local_res4);
  uVar4 = *puVar5;
  pvVar6 = param_1[1];
  FUN_0041d108(param_1);
  pvVar6 = (void *)FUN_004248dc(uVar4,pvVar6,iVar2 + 4);
  FUN_0041d108(param_1);
  FUN_0041d130();
  FUN_004226fc(param_1,*param_1);
  *param_1 = pvVar3;
  param_1[1] = pvVar6;
  param_1[2] = (void *)((int)pvVar3 + uVar1 * 4);
  return;
}



undefined4 * FUN_00421df8(undefined4 *param_1,undefined4 *param_2)

{
  FUN_0042469c(param_1,param_2);
  return param_1;
}



int * FUN_00421e40(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  FUN_00424998(param_1,param_2,param_3,param_4);
  return param_1;
}



void FUN_00421e98(undefined4 *param_1)

{
  FUN_00424a18(param_1,*param_1);
  return;
}



void FUN_00421edc(void)

{
  return;
}



void FUN_00421f04(undefined4 param_1,void *param_2)

{
  operator_delete(param_2);
  return;
}



void FUN_00421f48(void)

{
  return;
}



void FUN_00421f70(int **param_1)

{
  if (*param_1 != (int *)0x0) {
    (**(code **)(**param_1 + 0xc))(*param_1);
  }
  return;
}



undefined8 FUN_00421fdc(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00422014();
  return uVar1;
}



undefined8 FUN_00422014(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



undefined8 FUN_00422040(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00422070();
  return uVar1;
}



undefined8 FUN_00422070(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_004220a8();
  return uVar1;
}



undefined8 FUN_004220a8(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



void FUN_004220d4(void)

{
  return;
}



void FUN_004220fc(void)

{
  return;
}



void FUN_00422124(undefined4 param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_00424ae0();
  if (uVar1 < param_2) {
    std::__throw_bad_alloc();
  }
  operator_new(param_2);
  return;
}



void FUN_00422190(int *param_1,int param_2)

{
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  *param_1 = param_2;
  if (param_2 == 0) {
    std::allocator<char>::allocator();
                    // try { // try from 004221ec to 004221f3 has its CatchHandler @ 00422354
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayIterators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 0042221c to 00422223 has its CatchHandler @ 00422328
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_48,(allocator *)"NdArrayConstIterator");
    std::allocator<char>::allocator();
                    // try { // try from 0042224c to 00422253 has its CatchHandler @ 004222fc
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"NdArray has not been initialized.");
                    // try { // try from 00422270 to 00422277 has its CatchHandler @ 004222e0
    FUN_00417bb8();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
  }
  return;
}



int * FUN_00422398(int *param_1,int param_2)

{
  *param_1 = *param_1 + param_2;
  return param_1;
}



void FUN_004223dc(int *param_1,int param_2)

{
  allocator<char> aaStack_68 [4];
  basic_string<> abStack_64 [24];
  allocator<char> aaStack_4c [4];
  basic_string<> abStack_48 [24];
  allocator<char> aaStack_30 [4];
  basic_string<> abStack_2c [32];
  
  *param_1 = param_2;
  if (param_2 == 0) {
    std::allocator<char>::allocator();
                    // try { // try from 00422438 to 0042243f has its CatchHandler @ 004225a0
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_2c,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayIterators.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 00422468 to 0042246f has its CatchHandler @ 00422574
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_48,(allocator *)"NdArrayConstIterator");
    std::allocator<char>::allocator();
                    // try { // try from 00422498 to 0042249f has its CatchHandler @ 00422548
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_64,(allocator *)"NdArray has not been initialized.");
                    // try { // try from 004224bc to 004224c3 has its CatchHandler @ 0042252c
    FUN_00417bb8();
    std::__cxx11::basic_string<>::~basic_string(abStack_64);
    std::allocator<char>::~allocator(aaStack_68);
    std::__cxx11::basic_string<>::~basic_string(abStack_48);
    std::allocator<char>::~allocator(aaStack_4c);
    std::__cxx11::basic_string<>::~basic_string(abStack_2c);
    std::allocator<char>::~allocator(aaStack_30);
  }
  return;
}



int * FUN_004225e4(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  
  FUN_00424b08(&local_c,param_2);
  FUN_00424b08(&local_10,param_3);
  FUN_00424b40(param_1,local_c,local_10,param_4);
  return param_1;
}



void FUN_00422664(undefined4 param_1,void *param_2)

{
  operator_delete(param_2);
  return;
}



void FUN_004226a8(undefined4 *param_1)

{
  FUN_0041cb08();
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



void FUN_004226fc(undefined4 param_1,void *param_2)

{
  if (param_2 != (void *)0x0) {
    FUN_00424bd4(param_1,param_2);
  }
  return;
}



void FUN_00422758(void)

{
  FUN_00424c20();
  return;
}



undefined8 FUN_0042279c(undefined4 param_1,undefined4 param_2)

{
  return CONCAT44(param_2,param_1);
}



undefined8 FUN_004227dc(undefined4 param_1,undefined4 param_2)

{
  undefined8 uVar1;
  
  uVar1 = __umoddi3(param_1,param_2,0x138,0);
  return uVar1;
}



int * FUN_0042284c(int *param_1,int param_2)

{
  FUN_00424c4c(param_1,param_2);
  return param_1;
}



bool FUN_00422894(int *param_1,int *param_2)

{
  bool bVar1;
  
  bVar1 = FUN_00424c90(param_1,param_2);
  return !bVar1;
}



int * FUN_004228dc(int *param_1)

{
  FUN_00424cd4(param_1);
  return param_1;
}



void FUN_0042291c(undefined4 *param_1)

{
  FUN_00424d10(param_1);
  return;
}



int * FUN_00422958(int *param_1,int param_2)

{
  FUN_00417e9c(param_1,param_2);
  return param_1;
}



int * FUN_004229a0(int *param_1,int param_2)

{
  FUN_00417ee8(param_1,param_2);
  return param_1;
}



bool FUN_004229e8(int *param_1,int *param_2)

{
  bool bVar1;
  
  bVar1 = FUN_00424d3c(param_1,param_2);
  return !bVar1;
}



int * FUN_00422a30(int *param_1)

{
  *param_1 = *param_1 + 4;
  return param_1;
}



undefined4 FUN_00422a6c(undefined4 *param_1)

{
  return *param_1;
}



uint * FUN_00422a98(uint *param_1,uint *param_2)

{
  if (*param_1 < *param_2) {
    param_1 = param_2;
  }
  return param_1;
}



void FUN_00422aec(undefined4 param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_00424d80();
  if (uVar1 < param_2) {
    std::__throw_bad_alloc();
  }
  operator_new(param_2 << 2);
  return;
}



int * FUN_00422b60(int *param_1)

{
  FUN_00424dac(param_1);
  return param_1;
}



void FUN_00422ba0(undefined4 *param_1)

{
  FUN_00424de8(param_1);
  return;
}



int FUN_00422bdc(int param_1,int param_2,int param_3)

{
  int local_res4;
  int local_res8;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 4) + param_2;
  }
  local_res8 = param_3;
  if (param_3 < 0) {
    local_res8 = *(int *)(param_1 + 8) + param_3;
  }
  return *(int *)(param_1 + 0x14) + (*(int *)(param_1 + 8) * local_res4 + local_res8) * 4;
}



void FUN_00422c70(void)

{
  return;
}



void FUN_00422c98(undefined4 param_1,void *param_2)

{
  operator_delete(param_2);
  return;
}



void FUN_00422cdc(void)

{
  return;
}



bool areNotEqualBytes(int *param_1,int *param_2)

{
  bool result;
  
  result = intEquals(param_1,param_2);
  return !result;
}



int * FUN_00422d4c(int *param_1)

{
  *param_1 = *param_1 + 4;
  return param_1;
}



int * FUN_00422d88(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  FUN_00424e14(param_1,param_2,param_3,param_4);
  return param_1;
}



float FUN_00422de0(float param_1,undefined4 param_2,byte param_3)

{
  float local_10;
  byte local_c;
  
  if (param_3 == 0) {
    local_10 = 1.0;
  }
  else {
    local_10 = param_1;
    for (local_c = 1; local_c < param_3; local_c = local_c + 1) {
      local_10 = local_10 * param_1;
    }
  }
  return local_10;
}



int * FUN_00422e74(int *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  float fVar5;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar5 = *pfVar2;
    puVar3 = (undefined4 *)FUN_004232bc(&local_resc);
    uVar4 = FUN_004188e8(&stack0x00000010,fVar5);
    *puVar3 = uVar4;
    FUN_00422d4c(&local_res4);
    FUN_0042327c(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



int * FUN_00422f54(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  FUN_00424e94(param_1,param_2,param_3,param_4,param_5);
  return param_1;
}



int * FUN_00422fb8(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_00424fa4(param_1,param_2,param_3,param_4);
  return param_1;
}



int * FUN_00423018(int *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  float fVar3;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar3 = *pfVar2;
    pfVar2 = (float *)FUN_004232bc(&local_resc);
    fVar3 = FUN_00418ac4((float *)&stack0x00000010,fVar3);
    *pfVar2 = fVar3;
    FUN_00422d4c(&local_res4);
    FUN_0042327c(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



int * FUN_004230f8(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  float *pfVar3;
  float *pfVar4;
  float fVar5;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    pfVar3 = (float *)FUN_00420884(&local_resc);
    pfVar4 = (float *)FUN_004232bc(&param_5);
    fVar5 = FUN_00425084(&stack0x00000014,pfVar2,pfVar3);
    *pfVar4 = fVar5;
    FUN_00422d4c(&local_res4);
    FUN_00422d4c(&local_resc);
    FUN_0042327c(&param_5);
  }
  *param_1 = param_5;
  return param_1;
}



void FUN_00423208(undefined4 param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_004250c4();
  if (uVar1 < param_2) {
    std::__throw_bad_alloc();
  }
  operator_new(param_2 << 2);
  return;
}



int * FUN_0042327c(int *param_1)

{
  FUN_004250f0(param_1);
  return param_1;
}



void FUN_004232bc(undefined4 *param_1)

{
  FUN_0042512c(param_1);
  return;
}



int * FUN_004232f8(int *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  float fVar3;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar3 = *pfVar2;
    pfVar2 = (float *)FUN_004232bc(&local_resc);
    fVar3 = FUN_0041920c((float *)&stack0x00000010,fVar3);
    *pfVar2 = fVar3;
    FUN_00422d4c(&local_res4);
    FUN_0042327c(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



int * FUN_004233d8(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  
  FUN_00425158(&local_c,param_2);
  FUN_00425158(&local_10,param_3);
  FUN_00425190(param_1,local_c,local_10,param_4);
  return param_1;
}



undefined4 FUN_00423458(undefined4 *param_1)

{
  return *param_1;
}



int FUN_00423484(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_00423458(param_1);
  iVar2 = FUN_00425224((int)param_1);
  return iVar1 + iVar2 * 0x1c;
}



int * FUN_004234ec(int *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  undefined4 uVar3;
  float fVar4;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar4 = *pfVar2;
    uVar3 = FUN_0042291c(&local_resc);
    bVar1 = FUN_0041970c((float *)&stack0x00000010,fVar4);
    *(bool *)uVar3 = bVar1;
    FUN_00422d4c(&local_res4);
    FUN_004228dc(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



int * FUN_004235cc(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  undefined4 uVar3;
  float fVar4;
  float fVar5;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar4 = *pfVar2;
    pfVar2 = (float *)FUN_00420884(&local_resc);
    fVar5 = *pfVar2;
    uVar3 = FUN_0042291c(&param_5);
    bVar1 = FUN_00419854(&stack0x00000014,fVar4,fVar5);
    *(bool *)uVar3 = bVar1;
    FUN_00422d4c(&local_res4);
    FUN_00422d4c(&local_resc);
    FUN_004228dc(&param_5);
  }
  *param_1 = param_5;
  return param_1;
}



int * FUN_004236dc(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  FUN_00425250(param_1,param_2,param_3,param_4,param_5);
  return param_1;
}



void FUN_00423740(int *param_1,uint param_2)

{
  FUN_00425360(param_1);
                    // try { // try from 0042377c to 00423783 has its CatchHandler @ 0042378c
  FUN_004253bc(param_1,param_2);
  return;
}



void FUN_004237cc(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = *param_1;
  FUN_0041d108(param_1);
  uVar1 = FUN_00425438(uVar1,param_2);
  param_1[1] = uVar1;
  return;
}



undefined4 FUN_00423840(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



int FUN_0042386c(int param_1,int param_2)

{
  int local_res4;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 0xc) + param_2;
  }
  return *(int *)(param_1 + 0x14) + local_res4;
}



int FUN_004238c4(int param_1,uint param_2,undefined param_3)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)FUN_0042547c(param_1,param_2);
  *puVar1 = param_3;
  return param_1;
}



int * FUN_0042391c(int *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  undefined4 uVar3;
  float fVar4;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar4 = *pfVar2;
    uVar3 = FUN_0042291c(&local_resc);
    bVar1 = FUN_0041a23c((float *)&stack0x00000010,fVar4);
    *(bool *)uVar3 = bVar1;
    FUN_00422d4c(&local_res4);
    FUN_004228dc(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



bool intEquals(int *param_1,int *param_2)

{
  return *param_1 == *param_2;
}



int * FUN_00423a40(int *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  undefined4 uVar3;
  float fVar4;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar4 = *pfVar2;
    uVar3 = FUN_0042291c(&local_resc);
    bVar1 = FUN_0041afdc((float *)&stack0x00000010,fVar4);
    *(bool *)uVar3 = bVar1;
    FUN_00422d4c(&local_res4);
    FUN_004228dc(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



int * FUN_00423b20(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  FUN_004257e0(param_1,param_2,param_3,param_4,param_5);
  return param_1;
}



void FUN_00423b84(void)

{
  return;
}



void FUN_00423bac(void)

{
  return;
}



void FUN_00423bd4(undefined4 param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_004258f0();
  if (uVar1 < param_2) {
    std::__throw_bad_alloc();
  }
  operator_new(param_2 << 2);
  return;
}



void FUN_00423c48(undefined4 param_1,void *param_2)

{
  operator_delete(param_2);
  return;
}



void FUN_00423c8c(undefined4 *param_1)

{
  int iVar1;
  
  FUN_0042591c();
  *param_1 = 0;
  param_1[1] = 0;
  for (iVar1 = 0; *(undefined *)((int)param_1 + iVar1 + 8) = 0, iVar1 != 3; iVar1 = iVar1 + 1) {
  }
  return;
}



void FUN_00423d00(int param_1)

{
  *(int *)param_1 = param_1;
  *(int *)(param_1 + 4) = param_1;
  FUN_00425958(param_1,0);
  return;
}



void FUN_00423d58(void)

{
  return;
}



undefined4 FUN_00423d80(undefined4 param_1)

{
  return param_1;
}



void FUN_00423da8(void)

{
  FUN_004259a8();
  return;
}



void FUN_00423dec(undefined4 param_1,void *param_2)

{
  FUN_004259d4(param_1,param_2);
  return;
}



void FUN_00423e38(undefined4 *param_1)

{
  int iVar1;
  
  FUN_00425a20();
  *param_1 = 0;
  param_1[1] = 0;
  for (iVar1 = 0; *(undefined *)((int)param_1 + iVar1 + 8) = 0, iVar1 != 3; iVar1 = iVar1 + 1) {
  }
  return;
}



void FUN_00423eac(int param_1)

{
  *(int *)param_1 = param_1;
  *(int *)(param_1 + 4) = param_1;
  FUN_00425a5c(param_1,0);
  return;
}



void FUN_00423f04(void)

{
  return;
}



undefined4 FUN_00423f2c(undefined4 param_1)

{
  return param_1;
}



void FUN_00423f54(void)

{
  FUN_00425aac();
  return;
}



void FUN_00423f98(undefined4 param_1,void *param_2)

{
  FUN_00425ad8(param_1,param_2);
  return;
}



int FUN_00423fe4(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 auStack_18 [3];
  
  iVar1 = FUN_00425b24(param_1);
  uVar2 = FUN_00423d80(param_1);
  FUN_00425b64(auStack_18,uVar2,iVar1);
  uVar3 = FUN_0042184c(iVar1);
  uVar4 = FUN_00421398(param_2);
                    // try { // try from 00424068 to 0042406f has its CatchHandler @ 004240a4
  FUN_00425c24(uVar2,uVar3,uVar4);
  FUN_00425c7c((int)auStack_18);
  FUN_00425bc0(auStack_18);
  return iVar1;
}



void FUN_004240e4(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = (int *)FUN_00425cb0(param_1);
  *piVar1 = *piVar1 + param_2;
  return;
}



int FUN_00424138(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 auStack_18 [3];
  
  iVar1 = FUN_00425cf0(param_1);
  uVar2 = FUN_00423f2c(param_1);
  FUN_00425d30(auStack_18,uVar2,iVar1);
  uVar3 = FUN_004217d4(iVar1);
  uVar4 = FUN_00421444(param_2);
                    // try { // try from 004241bc to 004241c3 has its CatchHandler @ 004241f8
  FUN_00425df0(uVar2,uVar3,uVar4);
  FUN_00425e48((int)auStack_18);
  FUN_00425d8c(auStack_18);
  return iVar1;
}



void FUN_00424238(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = (int *)FUN_00425cb0(param_1);
  *piVar1 = *piVar1 + param_2;
  return;
}



undefined4 * FUN_0042428c(undefined4 *param_1,undefined4 param_2)

{
  FUN_00425e7c(param_1,param_2);
  return param_1;
}



int FUN_004242d0(int param_1,int param_2,int *param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int local_res0;
  int local_res4;
  int *local_res8 [2];
  int local_10;
  
  local_10 = 0;
  local_res0 = param_1;
  local_res4 = param_2;
  local_res8[0] = param_3;
  while (bVar1 = FUN_00425eb4(&local_res0,&local_res4), CONCAT31(extraout_var,bVar1) != 0) {
    bVar1 = FUN_00425f38(local_res8,local_res0);
    if (CONCAT31(extraout_var_00,bVar1) != 0) {
      local_10 = local_10 + 1;
    }
    FUN_00425efc(&local_res0);
  }
  return local_10;
}



void FUN_00424364(undefined4 param_1)

{
  FUN_00425f94(param_1);
  return;
}



void FUN_0042439c(undefined4 param_1)

{
  FUN_00425fbc(param_1);
  return;
}



// void std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>
// >::_M_construct<char*>(char*, char*, std::forward_iterator_tag)

void std::__cxx11::basic_string<>::_M_construct<char*>(uint *param_1,char *param_2,char *param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  char *pcVar2;
  uint local_18 [3];
  
  bVar1 = FUN_00425fe4((int)param_2);
  if ((CONCAT31(extraout_var,bVar1) == 0) || (param_2 == param_3)) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if (bVar1) {
    std::__throw_logic_error("basic_string::_M_construct null not valid");
  }
  local_18[0] = FUN_00426014((int)param_2,(int)param_3);
  if (0xf < local_18[0]) {
    std::__cxx11::basic_string<>::_M_create(param_1,(uint)local_18);
    std::__cxx11::basic_string<>::_M_data((char *)param_1);
    std::__cxx11::basic_string<>::_M_capacity((uint)param_1);
  }
                    // try { // try from 004244a8 to 004244af has its CatchHandler @ 004244e0
  pcVar2 = (char *)std::__cxx11::basic_string<>::_M_data();
  std::__cxx11::basic_string<>::_S_copy_chars(pcVar2,param_2,param_3);
  std::__cxx11::basic_string<>::_M_set_length((uint)param_1);
  return;
}



undefined4 FUN_0042453c(void)

{
  return 0x1fffffff;
}



undefined4 FUN_00424568(undefined4 param_1)

{
  return param_1;
}



int * FUN_00424590(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined8 *puVar1;
  int iVar2;
  int local_18 [2];
  
  puVar1 = (undefined8 *)FUN_00426080(param_2);
  iVar2 = FUN_00426080(param_3);
  FUN_004260a8(local_18,param_4);
  FUN_004260e0(param_1,puVar1,iVar2,local_18[0]);
  return param_1;
}



void FUN_0042462c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = (undefined4 *)FUN_00421a5c(param_3);
  uVar2 = *puVar1;
  puVar1 = (undefined4 *)FUN_00414fd4(4,param_2);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = uVar2;
  }
  return;
}



void FUN_0042469c(undefined4 *param_1,undefined4 *param_2)

{
  *param_1 = *param_2;
  return;
}



uint FUN_004246d8(int *param_1,uint param_2,char *param_3)

{
  int iVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  uint local_res4;
  char *local_res8;
  uint local_14 [2];
  
  local_res4 = param_2;
  local_res8 = param_3;
  iVar1 = FUN_0042613c(param_1);
  iVar2 = FUN_00417974(param_1);
  if ((uint)(iVar1 - iVar2) < local_res4) {
    std::__throw_length_error(local_res8);
  }
  iVar1 = FUN_00417974(param_1);
  local_14[0] = FUN_00417974(param_1);
  puVar3 = FUN_00422a98(local_14,&local_res4);
  uVar4 = iVar1 + *puVar3;
  uVar5 = FUN_00417974(param_1);
  if ((uVar4 < uVar5) || (uVar5 = FUN_0042613c(param_1), uVar5 < uVar4)) {
    uVar4 = FUN_0042613c(param_1);
  }
  return uVar4;
}



int FUN_004247f4(undefined4 param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)FUN_004248b4(param_1);
  iVar2 = *piVar1;
  piVar1 = (int *)FUN_004248b4(param_2);
  return iVar2 - *piVar1 >> 2;
}



undefined4 FUN_00424858(undefined4 param_1,uint param_2)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = FUN_00426184(param_1,param_2);
  }
  return uVar1;
}



undefined4 FUN_004248b4(undefined4 param_1)

{
  return param_1;
}



void FUN_004248dc(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 local_10;
  undefined4 local_c;
  
  FUN_004261c8(&local_c,param_1);
  FUN_004261c8(&local_10,param_2);
  FUN_0042620c(local_c,local_10,param_3);
  return;
}



void FUN_00424954(void)

{
  FUN_00426258();
  return;
}



int * FUN_00424998(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  
  FUN_00426284(&local_c,param_2);
  FUN_00426284(&local_10,param_3);
  FUN_004262bc(param_1,local_c,local_10,param_4);
  return param_1;
}



undefined4 FUN_00424a18(undefined4 param_1,undefined4 param_2)

{
  return param_2;
}



undefined8 FUN_00424a44(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00424a7c();
  return uVar1;
}



undefined8 FUN_00424a7c(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_004151a0();
  return uVar1;
}



undefined8 FUN_00424ab0(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00415178();
  return uVar1;
}



undefined4 FUN_00424ae0(void)

{
  return 0xffffffff;
}



undefined4 * FUN_00424b08(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



int * FUN_00424b40(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int local_18;
  int local_14;
  int local_10 [2];
  
  FUN_00426554(local_10,param_2);
  FUN_00426554(&local_14,param_3);
  FUN_0042658c(&local_18,param_4);
  FUN_004265c4(param_1,local_10[0],local_14,local_18);
  return param_1;
}



void FUN_00424bd4(undefined4 param_1,void *param_2)

{
  FUN_00421f04(param_1,param_2);
  return;
}



void FUN_00424c20(void)

{
  return;
}



int * FUN_00424c4c(int *param_1,int param_2)

{
  *param_1 = *param_1 + param_2;
  return param_1;
}



bool FUN_00424c90(int *param_1,int *param_2)

{
  return *param_1 == *param_2;
}



int * FUN_00424cd4(int *param_1)

{
  *param_1 = *param_1 + 1;
  return param_1;
}



undefined4 FUN_00424d10(undefined4 *param_1)

{
  return *param_1;
}



bool FUN_00424d3c(int *param_1,int *param_2)

{
  return *param_1 == *param_2;
}



undefined4 FUN_00424d80(void)

{
  return 0x3fffffff;
}



int * FUN_00424dac(int *param_1)

{
  *param_1 = *param_1 + 4;
  return param_1;
}



undefined4 FUN_00424de8(undefined4 *param_1)

{
  return *param_1;
}



int * FUN_00424e14(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_0042742c(param_2);
  uVar2 = FUN_0042742c(param_3);
  FUN_00427454(param_1,uVar1,uVar2,param_4);
  return param_1;
}



int * FUN_00424e94(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  float *pfVar3;
  float *pfVar4;
  float fVar5;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    pfVar3 = (float *)FUN_00420884(&local_resc);
    pfVar4 = (float *)FUN_004232bc(&param_5);
    fVar5 = FUN_004274f0(&stack0x00000014,pfVar2,pfVar3);
    *pfVar4 = fVar5;
    FUN_00422d4c(&local_res4);
    FUN_00422d4c(&local_resc);
    FUN_0042327c(&param_5);
  }
  *param_1 = param_5;
  return param_1;
}



int * FUN_00424fa4(int *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  float *pfVar2;
  float fVar3;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = areNotEqualBytes(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pfVar2 = (float *)FUN_00420884(&local_res4);
    fVar3 = *pfVar2;
    pfVar2 = (float *)FUN_004232bc(&local_resc);
    fVar3 = FUN_0041eb3c((float *)&stack0x00000010,fVar3);
    *pfVar2 = fVar3;
    FUN_00422d4c(&local_res4);
    FUN_0042327c(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



float FUN_00425084(undefined4 param_1,float *param_2,float *param_3)

{
  return *param_2 - *param_3;
}



undefined4 FUN_004250c4(void)

{
  return 0x3fffffff;
}



int * FUN_004250f0(int *param_1)

{
  *param_1 = *param_1 + 4;
  return param_1;
}



undefined4 FUN_0042512c(undefined4 *param_1)

{
  return *param_1;
}



undefined4 * FUN_00425158(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



int * FUN_00425190(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int local_18;
  int local_14;
  int local_10 [2];
  
  FUN_00427530(local_10,param_2);
  FUN_00427530(&local_14,param_3);
  FUN_00427568(&local_18,param_4);
  FUN_004275a0(param_1,local_10[0],local_14,local_18);
  return param_1;
}



undefined4 FUN_00425224(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



int * FUN_00425250(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  char cVar1;
  char cVar2;
  bool bVar3;
  undefined3 extraout_var;
  char *pcVar4;
  undefined *puVar5;
  undefined4 uVar6;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar3 = FUN_0041c734(&local_res4,&local_res8), CONCAT31(extraout_var,bVar3) != 0) {
    pcVar4 = (char *)FUN_0041c7b8(&local_res4);
    cVar1 = *pcVar4;
    pcVar4 = (char *)FUN_0041c7b8(&local_resc);
    cVar2 = *pcVar4;
    puVar5 = (undefined *)FUN_0042291c(&param_5);
    uVar6 = FUN_0041fc9c(&stack0x00000014,cVar1,cVar2);
    *puVar5 = (char)uVar6;
    FUN_0041c77c(&local_res4);
    FUN_0041c77c(&local_resc);
    FUN_004228dc(&param_5);
  }
  *param_1 = param_5;
  return param_1;
}



void FUN_00425360(undefined4 *param_1)

{
  FUN_004275fc();
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



void FUN_004253bc(int *param_1,uint param_2)

{
  int iVar1;
  
  iVar1 = FUN_00424858(param_1,param_2);
  *param_1 = iVar1;
  param_1[1] = *param_1;
  param_1[2] = *param_1 + param_2 * 4;
  return;
}



void FUN_00425438(undefined4 param_1,int param_2)

{
  FUN_00427640(param_1,param_2);
  return;
}



void FUN_0042547c(int param_1,uint param_2)

{
  uint uVar1;
  allocator<char> aaStack_c0 [4];
  basic_string<> abStack_bc [24];
  allocator<char> aaStack_a4 [4];
  basic_string<> abStack_a0 [24];
  basic_string<> abStack_88 [24];
  basic_string abStack_70 [6];
  basic_string abStack_58 [6];
  basic_string<> abStack_40 [24];
  basic_string abStack_28 [7];
  
  uVar1 = ((int)param_2 >> 0x1f ^ param_2) - ((int)param_2 >> 0x1f);
  if ((0 < (int)uVar1 >> 0x1f) || ((-1 < (int)uVar1 && (*(int *)(param_1 + 0xc) - 1U < uVar1)))) {
    FUN_00416908(abStack_40);
                    // try { // try from 0042551c to 00425523 has its CatchHandler @ 004256c4
    FUN_00416790(abStack_28,"Input index ",(uint)abStack_40);
    std::__cxx11::basic_string<>::~basic_string(abStack_40);
                    // try { // try from 00425548 to 0042554f has its CatchHandler @ 004257a0
    FUN_0041685c(abStack_88);
                    // try { // try from 00425568 to 0042556f has its CatchHandler @ 00425720
    FUN_00416790(abStack_70," is out of bounds for array of size ",(uint)abStack_88);
                    // try { // try from 00425588 to 0042558f has its CatchHandler @ 00425704
    appendStringToBasicString(abStack_58,(char *)abStack_70);
                    // try { // try from 004255a0 to 004255a7 has its CatchHandler @ 004256e8
    std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_28,abStack_58);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_58);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_70);
    std::__cxx11::basic_string<>::~basic_string(abStack_88);
    std::allocator<char>::allocator();
                    // try { // try from 00425600 to 00425607 has its CatchHandler @ 00425784
    std::__cxx11::basic_string<>::basic_string
              ((char *)abStack_a0,
               (allocator *)
               "../../../buildroot/buildroot/output/host/mipsel-buildroot-linux-gnu/sysroot/usr/include/NumCpp/NdArray/NdArrayCore.hpp"
              );
    std::allocator<char>::allocator();
                    // try { // try from 00425630 to 00425637 has its CatchHandler @ 00425758
    std::__cxx11::basic_string<>::basic_string((char *)abStack_bc,(allocator *)&DAT_00432ec8);
                    // try { // try from 00425654 to 0042565b has its CatchHandler @ 0042573c
    MAYBElogAndThrowException();
    std::__cxx11::basic_string<>::~basic_string(abStack_bc);
    std::allocator<char>::~allocator(aaStack_c0);
    std::__cxx11::basic_string<>::~basic_string(abStack_a0);
    std::allocator<char>::~allocator(aaStack_a4);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)abStack_28);
  }
  FUN_00427688(param_1,param_2);
  return;
}



int * FUN_004257e0(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  bool bVar1;
  undefined3 extraout_var;
  byte *pbVar2;
  byte *pbVar3;
  undefined4 uVar4;
  int local_res4;
  int local_res8;
  int local_resc;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  while (bVar1 = FUN_00422894(&local_res4,&local_res8), CONCAT31(extraout_var,bVar1) != 0) {
    pbVar2 = (byte *)FUN_0042291c(&local_res4);
    pbVar3 = (byte *)FUN_0041c7b8(&local_resc);
    uVar4 = FUN_0042291c(&param_5);
    bVar1 = FUN_004276e0(&stack0x00000014,pbVar2,pbVar3);
    *(bool *)uVar4 = bVar1;
    FUN_004228dc(&local_res4);
    FUN_0041c77c(&local_resc);
    FUN_004228dc(&param_5);
  }
  *param_1 = param_5;
  return param_1;
}



undefined4 FUN_004258f0(void)

{
  return 0x3fffffff;
}



void FUN_0042591c(void)

{
  FUN_0042772c();
  return;
}



void FUN_00425958(int param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_00425cb0(param_1);
  *puVar1 = param_2;
  return;
}



void FUN_004259a8(void)

{
  return;
}



void FUN_004259d4(undefined4 param_1,void *param_2)

{
  FUN_00427754(param_1,param_2);
  return;
}



void FUN_00425a20(void)

{
  FUN_00427798();
  return;
}



void FUN_00425a5c(int param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_00425cb0(param_1);
  *puVar1 = param_2;
  return;
}



void FUN_00425aac(void)

{
  return;
}



void FUN_00425ad8(undefined4 param_1,void *param_2)

{
  FUN_004277c0(param_1,param_2);
  return;
}



void FUN_00425b24(undefined4 param_1)

{
  FUN_00427804(param_1,1);
  return;
}



void FUN_00425b64(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00427848(param_2);
  *param_1 = uVar1;
  param_1[1] = param_3;
  return;
}



void FUN_00425bc0(undefined4 *param_1)

{
  if (param_1[1] != 0) {
    FUN_004259d4(*param_1,(void *)param_1[1]);
  }
  return;
}



void FUN_00425c24(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00421398(param_3);
  FUN_00427870(param_1,param_2,uVar1);
  return;
}



int FUN_00425c7c(int param_1)

{
  *(undefined4 *)(param_1 + 4) = 0;
  return param_1;
}



void FUN_00425cb0(int param_1)

{
  FUN_004278e0(param_1 + 8);
  return;
}



void FUN_00425cf0(undefined4 param_1)

{
  FUN_00427918(param_1,1);
  return;
}



void FUN_00425d30(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = FUN_0042795c(param_2);
  *param_1 = uVar1;
  param_1[1] = param_3;
  return;
}



void FUN_00425d8c(undefined4 *param_1)

{
  if (param_1[1] != 0) {
    FUN_00425ad8(*param_1,(void *)param_1[1]);
  }
  return;
}



void FUN_00425df0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00421444(param_3);
  FUN_00427984(param_1,param_2,uVar1);
  return;
}



int FUN_00425e48(int param_1)

{
  *(undefined4 *)(param_1 + 4) = 0;
  return param_1;
}



void FUN_00425e7c(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return;
}



bool FUN_00425eb4(int *param_1,int *param_2)

{
  bool bVar1;
  
  bVar1 = FUN_004279f4(param_1,param_2);
  return !bVar1;
}



int * FUN_00425efc(int *param_1)

{
  *param_1 = *param_1 + 4;
  return param_1;
}



bool FUN_00425f38(int **param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 local_res4 [3];
  
  local_res4[0] = param_2;
  piVar1 = (int *)FUN_00427a38(local_res4);
  return *piVar1 == **param_1;
}



undefined4 FUN_00425f94(undefined4 param_1)

{
  return param_1;
}



undefined4 FUN_00425fbc(undefined4 param_1)

{
  return param_1;
}



bool FUN_00425fe4(int param_1)

{
  return param_1 == 0;
}



void FUN_00426014(int param_1,int param_2)

{
  undefined auStack_18 [8];
  
  FUN_00427a64(auStack_18);
  FUN_00427a94(param_1,param_2);
  return;
}



undefined4 FUN_00426080(undefined4 param_1)

{
  return param_1;
}



undefined4 * FUN_004260a8(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



int * FUN_004260e0(int *param_1,undefined8 *param_2,int param_3,int param_4)

{
  FUN_00427acc(param_1,param_2,param_3,param_4);
  return param_1;
}



void FUN_0042613c(undefined4 param_1)

{
  FUN_00427bbc(param_1);
  FUN_00427b84();
  return;
}



void FUN_00426184(undefined4 param_1,uint param_2)

{
  FUN_00422aec(param_1,param_2);
  return;
}



undefined4 * FUN_004261c8(undefined4 *param_1,undefined4 param_2)

{
  FUN_00427be4(param_1,param_2);
  return param_1;
}



void FUN_0042620c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00427c1c(param_1,param_2,param_3);
  return;
}



void FUN_00426258(void)

{
  return;
}



undefined4 * FUN_00426284(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



int * FUN_004262bc(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  int iVar2;
  int local_18 [2];
  
  puVar1 = (undefined4 *)FUN_00427c6c(param_2);
  iVar2 = FUN_00427c6c(param_3);
  FUN_00427ca8(local_18,param_4);
  FUN_00427ce0(param_1,puVar1,iVar2,local_18[0]);
  return param_1;
}



void FUN_00426358(longdouble param_1,allocator *param_2,char *param_3)

{
  if (param_3 == (char *)0x0) {
    param_3 = "Value %1% can not be represented in the target integer type.";
  }
  FUN_00427d3c(param_1,param_2,(allocator *)param_3);
  return;
}



undefined8 FUN_004263d0(longdouble param_1,allocator *param_2,allocator *param_3)

{
  undefined8 uVar1;
  
  FUN_00427d8c(param_1,param_2,param_3);
  uVar1 = FUN_004151f0();
  return uVar1;
}



void FUN_00426424(undefined4 param_1,undefined4 param_2)

{
  FUN_004280c0(param_1,param_2);
  return;
}



undefined8 FUN_00426468(allocator *param_1,char *param_2)

{
  undefined8 uVar1;
  
  if (param_2 == (char *)0x0) {
    param_2 = "Overflow Error";
  }
  uVar1 = FUN_0042814c(param_1,param_2);
  return uVar1;
}



// WARNING: Control flow encountered bad instruction data

void FUN_004264d4(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



undefined4 * FUN_00426554(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



undefined4 * FUN_0042658c(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



int * FUN_004265c4(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_00428298(param_1,param_2,param_3,param_4);
  return param_1;
}



void FUN_00426620(undefined4 *param_1)

{
  *param_1 = &PTR___cxa_pure_virtual_00433674;
  return;
}



void FUN_0042665c(undefined4 *param_1,logic_error *param_2)

{
  std::logic_error::logic_error((logic_error *)param_1,param_2);
  *param_1 = 0x44d998;
  return;
}



void FUN_004266b8(undefined4 *param_1,int param_2)

{
  *param_1 = &PTR___cxa_pure_virtual_0043368c;
  FUN_00428530((int **)(param_1 + 1),(int **)(param_2 + 4));
  param_1[2] = *(undefined4 *)(param_2 + 8);
  param_1[3] = *(undefined4 *)(param_2 + 0xc);
  param_1[4] = *(undefined4 *)(param_2 + 0x10);
  return;
}



void FUN_0042674c(undefined4 *param_1,logic_error *param_2)

{
  FUN_0042665c(param_1,param_2);
                    // try { // try from 00426798 to 0042679f has its CatchHandler @ 004267c8
  FUN_004266b8(param_1 + 2,(int)(param_2 + 8));
  *param_1 = &PTR_FUN_0043363c;
  param_1[2] = &PTR_FUN_00433650;
  return;
}



void FUN_00426808(undefined4 *param_1,logic_error *param_2)

{
  FUN_00426620(param_1 + 7);
                    // try { // try from 00426868 to 0042686f has its CatchHandler @ 004268ac
  FUN_0042674c(param_1,param_2);
  *param_1 = &PTR_FUN_004335e4;
  param_1[2] = &PTR_FUN_00433600;
  param_1[7] = &PTR_FUN_0043361c;
  return;
}



void FUN_004268f0(logic_error *param_1)

{
  int *piVar1;
  
  FUN_004160b8();
  piVar1 = (int *)__cxa_allocate_exception(0x20);
                    // try { // try from 00426934 to 0042693b has its CatchHandler @ 00426958
  FUN_00428374(piVar1,param_1);
                    // WARNING: Subroutine does not return
  __cxa_throw(piVar1,&DAT_004338d0,FUN_00428414);
}



void FUN_00426978(void)

{
  FUN_004287f0();
  return;
}



void FUN_004269c0(undefined4 *param_1,runtime_error *param_2)

{
  std::runtime_error::runtime_error((runtime_error *)param_1,param_2);
  *param_1 = 0x44d984;
  return;
}



void FUN_00426a1c(undefined4 *param_1,runtime_error *param_2)

{
  FUN_004269c0(param_1,param_2);
                    // try { // try from 00426a68 to 00426a6f has its CatchHandler @ 00426a98
  FUN_004266b8(param_1 + 2,(int)(param_2 + 8));
  *param_1 = &PTR_FUN_00433514;
  param_1[2] = &PTR_FUN_00433528;
  return;
}



void FUN_00426ad8(undefined4 *param_1,runtime_error *param_2)

{
  FUN_00426620(param_1 + 7);
                    // try { // try from 00426b38 to 00426b3f has its CatchHandler @ 00426b7c
  FUN_00426a1c(param_1,param_2);
  *param_1 = &PTR_FUN_004334bc;
  param_1[2] = &PTR_FUN_004334d8;
  param_1[7] = &PTR_FUN_004334f4;
  return;
}



void FUN_00426bc0(runtime_error *param_1)

{
  int *piVar1;
  
  FUN_004160b8();
  piVar1 = (int *)__cxa_allocate_exception(0x20);
                    // try { // try from 00426c04 to 00426c0b has its CatchHandler @ 00426c28
  FUN_0042883c(piVar1,param_1);
                    // WARNING: Subroutine does not return
  __cxa_throw(piVar1,&DAT_004337bc,FUN_004288dc);
}



undefined8 FUN_00426c48(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00426c84();
  return uVar1;
}



undefined8 FUN_00426c84(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



undefined8 FUN_00426cb4(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00426ce4();
  return uVar1;
}



undefined8 FUN_00426ce4(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00426d1c();
  return uVar1;
}



undefined8 FUN_00426d1c(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



undefined8 FUN_00426d48(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00426d78();
  return uVar1;
}



undefined8 FUN_00426d78(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00426db0();
  return uVar1;
}



undefined8 FUN_00426db0(void)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,"FuseFromAi offset=[%f,%f]\n");
}



// WARNING: Control flow encountered bad instruction data

void FUN_00426ddc(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



undefined4 FUN_0042742c(undefined4 param_1)

{
  return param_1;
}



int * FUN_00427454(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  int iVar2;
  int local_18 [2];
  
  puVar1 = (undefined4 *)FUN_0042909c(param_2);
  iVar2 = FUN_0042909c(param_3);
  FUN_00427568(local_18,param_4);
  FUN_004290c4(param_1,puVar1,iVar2,local_18[0]);
  return param_1;
}



float FUN_004274f0(undefined4 param_1,float *param_2,float *param_3)

{
  return *param_2 * *param_3;
}



undefined4 * FUN_00427530(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



undefined4 * FUN_00427568(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



int * FUN_004275a0(int *param_1,int param_2,int param_3,int param_4)

{
  FUN_00429120(param_1,param_2,param_3,param_4);
  return param_1;
}



void FUN_004275fc(void)

{
  FUN_004291f8();
  return;
}



void FUN_00427640(undefined4 param_1,int param_2)

{
  FUN_00429224(param_1,param_2);
  return;
}



int FUN_00427688(int param_1,int param_2)

{
  int local_res4;
  
  local_res4 = param_2;
  if (param_2 < 0) {
    local_res4 = *(int *)(param_1 + 0xc) + param_2;
  }
  return *(int *)(param_1 + 0x14) + local_res4;
}



bool FUN_004276e0(undefined4 param_1,byte *param_2,byte *param_3)

{
  return (*param_2 & *param_3) != 0;
}



void FUN_0042772c(void)

{
  return;
}



void FUN_00427754(undefined4 param_1,void *param_2)

{
  operator_delete(param_2);
  return;
}



void FUN_00427798(void)

{
  return;
}



void FUN_004277c0(undefined4 param_1,void *param_2)

{
  operator_delete(param_2);
  return;
}



void FUN_00427804(undefined4 param_1,uint param_2)

{
  FUN_00429270(param_1,param_2);
  return;
}



undefined4 FUN_00427848(undefined4 param_1)

{
  return param_1;
}



void FUN_00427870(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = (undefined4 *)FUN_00421398(param_3);
  uVar2 = *puVar1;
  puVar1 = (undefined4 *)FUN_00414fd4(4,param_2);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = uVar2;
  }
  return;
}



void FUN_004278e0(undefined4 param_1)

{
  FUN_004292f0(param_1);
  return;
}



void FUN_00427918(undefined4 param_1,uint param_2)

{
  FUN_00429318(param_1,param_2);
  return;
}



undefined4 FUN_0042795c(undefined4 param_1)

{
  return param_1;
}



void FUN_00427984(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = (undefined4 *)FUN_00421444(param_3);
  uVar2 = *puVar1;
  puVar1 = (undefined4 *)FUN_00414fd4(4,param_2);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = uVar2;
  }
  return;
}



bool FUN_004279f4(int *param_1,int *param_2)

{
  return *param_1 == *param_2;
}



undefined4 FUN_00427a38(undefined4 *param_1)

{
  return *param_1;
}



undefined4 FUN_00427a64(undefined4 param_1)

{
  return param_1;
}



int FUN_00427a94(int param_1,int param_2)

{
  return param_2 - param_1;
}



int * FUN_00427acc(int *param_1,undefined8 *param_2,int param_3,int param_4)

{
  undefined8 *puVar1;
  undefined8 *local_res4;
  int local_resc;
  int local_10;
  
  local_res4 = param_2;
  local_resc = param_4;
  for (local_10 = param_3 - (int)param_2 >> 3; 0 < local_10; local_10 = local_10 + -1) {
    puVar1 = (undefined8 *)FUN_004172bc(&local_resc);
    *puVar1 = *local_res4;
    local_res4 = local_res4 + 1;
    FUN_0041727c(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



void FUN_00427b84(void)

{
  FUN_00424d80();
  return;
}



undefined4 FUN_00427bbc(undefined4 param_1)

{
  return param_1;
}



void FUN_00427be4(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return;
}



void FUN_00427c1c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00429398(param_1,param_2,param_3);
  return;
}



undefined4 FUN_00427c6c(undefined4 param_1)

{
  undefined4 *puVar1;
  undefined4 local_res0 [4];
  
  local_res0[0] = param_1;
  puVar1 = (undefined4 *)FUN_004248b4(local_res0);
  return *puVar1;
}



undefined4 * FUN_00427ca8(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return param_1;
}



int * FUN_00427ce0(int *param_1,undefined4 *param_2,int param_3,int param_4)

{
  FUN_004293e0(param_1,param_2,param_3,param_4);
  return param_1;
}



undefined4 FUN_00427d3c(longdouble param_1,allocator *param_2,allocator *param_3)

{
  error_handler(param_1,param_2,param_3);
  return 0;
}



void FUN_00427d8c(longdouble param_1,allocator *param_2,allocator *param_3)

{
  char *pcVar1;
  logic_error *plVar2;
  char *local_res0;
  char *local_res4;
  allocator<char> aaStack_88 [4];
  allocator<char> aaStack_84 [4];
  allocator<char> aaStack_80 [4];
  basic_string abStack_7c [6];
  basic_string abStack_64 [6];
  basic_string abStack_4c [6];
  undefined auStack_34 [24];
  domain_error adStack_1c [16];
  
  local_res0 = (char *)param_2;
  if (param_2 == (allocator *)0x0) {
    local_res0 = "Unknown function operating on type %1%";
  }
  local_res4 = (char *)param_3;
  if (param_3 == (allocator *)0x0) {
    local_res4 = "Cause unknown: error caused by bad argument with value %1%";
  }
  std::allocator<char>::allocator();
                    // try { // try from 00427e00 to 00427e07 has its CatchHandler @ 00427f68
  std::__cxx11::basic_string<>::basic_string((char *)abStack_7c,(allocator *)local_res0);
  std::allocator<char>::~allocator(aaStack_80);
  std::allocator<char>::allocator();
                    // try { // try from 00427e3c to 00427e43 has its CatchHandler @ 00427f8c
  std::__cxx11::basic_string<>::basic_string((char *)abStack_64,(allocator *)local_res4);
  std::allocator<char>::~allocator(aaStack_84);
  std::allocator<char>::allocator();
                    // try { // try from 00427e7c to 00427e83 has its CatchHandler @ 00427fa8
  std::__cxx11::basic_string<>::basic_string((char *)abStack_4c,(allocator *)"Error in function ");
  std::allocator<char>::~allocator(aaStack_88);
  pcVar1 = FUN_0041622c();
                    // try { // try from 00427eb0 to 00427efb has its CatchHandler @ 00427ffc
  FUN_00416170((char *)abStack_7c,"%1%",pcVar1);
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_4c,abStack_7c);
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_4c,": ");
  FUN_0042985c(param_1,auStack_34);
  pcVar1 = (char *)std::__cxx11::basic_string<>::c_str();
                    // try { // try from 00427f20 to 00427f57 has its CatchHandler @ 00427fe0
  FUN_00416170((char *)abStack_64,"%1%",pcVar1);
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_4c,abStack_64);
  std::domain_error::domain_error(adStack_1c,abStack_4c);
  plVar2 = (logic_error *)adStack_1c;
                    // try { // try from 00427f60 to 00427f67 has its CatchHandler @ 00427fc4
  FUN_004268f0(plVar2);
                    // catch() { ... } // from try @ 00427e00 with catch @ 00427f68
  std::allocator<char>::~allocator(aaStack_80);
                    // WARNING: Subroutine does not return
  _Unwind_Resume(plVar2);
}



void FUN_00428040(void)

{
  FUN_0042996c();
  return;
}



void FUN_00428080(void)

{
  FUN_00429994();
  return;
}



void FUN_004280c0(undefined4 param_1,undefined4 param_2)

{
  double dVar1;
  
  FUN_00429a94();
                    // try { // try from 00428100 to 0042811b has its CatchHandler @ 00428124
  dVar1 = (double)FUN_00429ad0();
  FUN_004299bc(dVar1,param_1,param_2,(allocator *)"boost::math::lgamma<%1%>(%1%)");
  return;
}



undefined8 FUN_0042814c(allocator *param_1,char *param_2)

{
  undefined8 uVar1;
  
  if (param_2 == (char *)0x0) {
    param_2 = "numeric overflow";
  }
  FUN_00429f5c(param_1,param_2);
  uVar1 = FUN_004151c8();
  return uVar1;
}



undefined4 FUN_004281b8(void)

{
  return 0;
}



undefined4 FUN_004281e8(void)

{
  return 0;
}



void FUN_00428218(ulonglong param_1)

{
  FUN_0042a144(param_1);
  return;
}



void FUN_00428258(void)

{
  FUN_0042a198();
  return;
}



int * FUN_00428298(int *param_1,int param_2,int param_3,int param_4)

{
  undefined *puVar1;
  undefined *puVar2;
  int local_res4;
  int local_res8;
  int local_resc;
  int local_18;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  for (local_18 = FUN_0042a1d4(&local_res8,&local_res4); 0 < local_18; local_18 = local_18 + -1) {
    puVar1 = (undefined *)FUN_0041c7b8(&local_res4);
    puVar2 = (undefined *)FUN_0042291c(&local_resc);
    *puVar2 = *puVar1;
    FUN_0041c77c(&local_res4);
    FUN_004228dc(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



int * FUN_00428374(int *param_1,logic_error *param_2)

{
  undefined4 auStack_30 [9];
  
  FUN_0042a214(auStack_30,param_2);
                    // try { // try from 004283b0 to 004283b7 has its CatchHandler @ 004283d0
  FUN_0042a290(param_1,(logic_error *)auStack_30);
  FUN_00428580(auStack_30);
  return param_1;
}



void FUN_00428414(int *param_1)

{
  *param_1 = (int)&PTR_FUN_0043353c;
  param_1[2] = (int)&PTR_FUN_00433558;
  param_1[7] = (int)&PTR_FUN_00433574;
  FUN_00428654(param_1,(int *)&PTR_DAT_00433588);
  setPureVirtualFunctionPointer(param_1 + 7);
  return;
}



void FUN_004284a8(int param_1)

{
  FUN_00428414((int *)(param_1 + -8));
  return;
}



void FUN_004284b4(int *param_1)

{
  FUN_00428414((int *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_004284c8(int *param_1)

{
  FUN_00428414(param_1);
  operator_delete(param_1,0x20);
  return;
}



void FUN_00428510(int param_1)

{
  FUN_004284c8((int *)(param_1 + -8));
  return;
}



void FUN_0042851c(int *param_1)

{
  FUN_004284c8((int *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_00428530(int **param_1,int **param_2)

{
  *param_1 = *param_2;
  FUN_00421f70(param_1);
  return;
}



void FUN_00428580(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0043363c;
  param_1[2] = &PTR_FUN_00433650;
  FUN_00415e3c(param_1 + 2);
  std::domain_error::~domain_error((domain_error *)param_1);
  return;
}



void FUN_004285f4(int param_1)

{
  FUN_00428580((undefined4 *)(param_1 + -8));
  return;
}



void FUN_00428600(undefined4 *param_1)

{
  FUN_00428580(param_1);
  operator_delete(param_1,0x1c);
  return;
}



void FUN_00428648(int param_1)

{
  FUN_00428600((undefined4 *)(param_1 + -8));
  return;
}



void FUN_00428654(int *param_1,int *param_2)

{
  *param_1 = *param_2;
  param_1[2] = (int)&PTR_FUN_00433600;
  *(int *)((int)param_1 + *(int *)(*param_1 + -0xc)) = param_2[1];
  FUN_00428580(param_1);
  return;
}



void FUN_004286e0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_004335e4;
  param_1[2] = &PTR_FUN_00433600;
  param_1[7] = &PTR_FUN_0043361c;
  FUN_00428580(param_1);
  setPureVirtualFunctionPointer(param_1 + 7);
  return;
}



void FUN_00428768(int param_1)

{
  FUN_004286e0((undefined4 *)(param_1 + -8));
  return;
}



void FUN_00428774(int *param_1)

{
  FUN_004286e0((undefined4 *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_00428788(undefined4 *param_1)

{
  FUN_004286e0(param_1);
  operator_delete(param_1,0x20);
  return;
}



void FUN_004287d0(int param_1)

{
  FUN_00428788((undefined4 *)(param_1 + -8));
  return;
}



void FUN_004287dc(int *param_1)

{
  FUN_00428788((undefined4 *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_004287f0(void)

{
  FUN_0042a360();
  return;
}



int * FUN_0042883c(int *param_1,runtime_error *param_2)

{
  undefined4 auStack_30 [9];
  
  FUN_0042aad8(auStack_30,param_2);
                    // try { // try from 00428878 to 0042887f has its CatchHandler @ 00428898
  FUN_0042ab1c(param_1,(runtime_error *)auStack_30);
  FUN_004289f8(auStack_30);
  return param_1;
}



void FUN_004288dc(int *param_1)

{
  *param_1 = (int)&PTR_FUN_00433414;
  param_1[2] = (int)&PTR_FUN_00433430;
  param_1[7] = (int)&PTR_FUN_0043344c;
  FUN_00428acc(param_1,(int *)&PTR_DAT_00433460);
  setPureVirtualFunctionPointer(param_1 + 7);
  return;
}



void FUN_00428970(int param_1)

{
  FUN_004288dc((int *)(param_1 + -8));
  return;
}



void FUN_0042897c(int *param_1)

{
  FUN_004288dc((int *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_00428990(int *param_1)

{
  FUN_004288dc(param_1);
  operator_delete(param_1,0x20);
  return;
}



void FUN_004289d8(int param_1)

{
  FUN_00428990((int *)(param_1 + -8));
  return;
}



void FUN_004289e4(int *param_1)

{
  FUN_00428990((int *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_004289f8(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_00433514;
  param_1[2] = &PTR_FUN_00433528;
  FUN_00415e3c(param_1 + 2);
  std::overflow_error::~overflow_error((overflow_error *)param_1);
  return;
}



void FUN_00428a6c(int param_1)

{
  FUN_004289f8((undefined4 *)(param_1 + -8));
  return;
}



void FUN_00428a78(undefined4 *param_1)

{
  FUN_004289f8(param_1);
  operator_delete(param_1,0x1c);
  return;
}



void FUN_00428ac0(int param_1)

{
  FUN_00428a78((undefined4 *)(param_1 + -8));
  return;
}



void FUN_00428acc(int *param_1,int *param_2)

{
  *param_1 = *param_2;
  param_1[2] = (int)&PTR_FUN_004334d8;
  *(int *)((int)param_1 + *(int *)(*param_1 + -0xc)) = param_2[1];
  FUN_004289f8(param_1);
  return;
}



void FUN_00428b58(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_004334bc;
  param_1[2] = &PTR_FUN_004334d8;
  param_1[7] = &PTR_FUN_004334f4;
  FUN_004289f8(param_1);
  setPureVirtualFunctionPointer(param_1 + 7);
  return;
}



void FUN_00428be0(int param_1)

{
  FUN_00428b58((undefined4 *)(param_1 + -8));
  return;
}



void FUN_00428bec(int *param_1)

{
  FUN_00428b58((undefined4 *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_00428c00(undefined4 *param_1)

{
  FUN_00428b58(param_1);
  operator_delete(param_1,0x20);
  return;
}



void FUN_00428c48(int param_1)

{
  FUN_00428c00((undefined4 *)(param_1 + -8));
  return;
}



void FUN_00428c54(int *param_1)

{
  FUN_00428c00((undefined4 *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



undefined8 FUN_00428c68(longdouble param_1,allocator *param_2,char *param_3)

{
  undefined8 uVar1;
  
  if (param_3 == (char *)0x0) {
    param_3 = "Evaluation of function at pole %1%";
  }
  uVar1 = FUN_0042abec(param_1,param_2,(allocator *)param_3);
  return uVar1;
}



// WARNING: Control flow encountered bad instruction data

void FUN_00428cdc(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



undefined8 FUN_00428e48(void)

{
  undefined8 uVar1;
  
  uVar1 = FUN_0042ac80();
  return uVar1;
}



void FUN_00428eb4(double param_1)

{
  FUN_0042acb4(param_1);
  return;
}



undefined8 FUN_00428ef4(undefined4 param_1,char *param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  
  if (param_2 == (char *)0x0) {
    param_2 = "Denorm Error";
  }
  uVar1 = FUN_0042acf0(param_1,param_2,param_3);
  return uVar1;
}



// WARNING: Control flow encountered bad instruction data

void FUN_00428f68(longdouble *param_1)

{
  FUN_0042ad28(param_1);
  FUN_00415150();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void FUN_00429054(void)

{
  FUN_004287f0();
  return;
}



undefined4 FUN_0042909c(undefined4 param_1)

{
  return param_1;
}



int * FUN_004290c4(int *param_1,undefined4 *param_2,int param_3,int param_4)

{
  FUN_0042ad70(param_1,param_2,param_3,param_4);
  return param_1;
}



int * FUN_00429120(int *param_1,int param_2,int param_3,int param_4)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int local_res4;
  int local_res8;
  int local_resc;
  int local_18;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  for (local_18 = FUN_0042ae28(&local_res8,&local_res4); 0 < local_18; local_18 = local_18 + -1) {
    puVar1 = (undefined4 *)FUN_00420884(&local_res4);
    puVar2 = (undefined4 *)FUN_004232bc(&local_resc);
    *puVar2 = *puVar1;
    FUN_00422d4c(&local_res4);
    FUN_0042327c(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



void FUN_004291f8(void)

{
  return;
}



void FUN_00429224(undefined4 param_1,int param_2)

{
  undefined4 local_10 [2];
  
  local_10[0] = 0;
  FUN_0042ae6c(param_1,param_2,local_10);
  return;
}



void FUN_00429270(undefined4 param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_0042aec0();
  if (uVar1 < param_2) {
    std::__throw_bad_alloc();
  }
  operator_new(param_2 * 0xc);
  return;
}



undefined4 FUN_004292f0(undefined4 param_1)

{
  return param_1;
}



void FUN_00429318(undefined4 param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_0042aeec();
  if (uVar1 < param_2) {
    std::__throw_bad_alloc();
  }
  operator_new(param_2 * 0xc);
  return;
}



void FUN_00429398(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_0042af18(param_1,param_2,param_3);
  return;
}



int * FUN_004293e0(int *param_1,undefined4 *param_2,int param_3,int param_4)

{
  undefined4 *puVar1;
  undefined4 *local_res4;
  int local_resc;
  int local_10;
  
  local_res4 = param_2;
  local_resc = param_4;
  for (local_10 = param_3 - (int)param_2 >> 2; 0 < local_10; local_10 = local_10 + -1) {
    puVar1 = (undefined4 *)FUN_00422ba0(&local_resc);
    *puVar1 = *local_res4;
    local_res4 = local_res4 + 1;
    FUN_00422b60(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



undefined8 FUN_00429498(longdouble param_1,allocator *param_2,char *param_3)

{
  undefined8 uVar1;
  
  if (param_3 == (char *)0x0) {
    param_3 = "Value %1% can not be represented in the target integer type.";
  }
  uVar1 = FUN_0042af84(param_1,param_2,(allocator *)param_3);
  return uVar1;
}



void FUN_00429510(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_00433660;
  std::runtime_error::~runtime_error((runtime_error *)param_1);
  return;
}



void FUN_00429560(undefined4 *param_1)

{
  FUN_00429510(param_1);
  operator_delete(param_1,8);
  return;
}



void error_handler(longdouble param_1,allocator *param_2,allocator *param_3)

{
  char *result;
  undefined4 *catchVar;
  char *functionName;
  char *errorMsg;
  allocator<char> stack1 [4];
  allocator<char> stack2 [4];
  allocator<char> stack3 [4];
  basic_string string1 [6];
  basic_string string2 [6];
  basic_string string3 [6];
  undefined stack4 [24];
  undefined4 stack5 [4];
  
  functionName = (char *)param_2;
  if (param_2 == (allocator *)0x0) {
    functionName = "Unknown function operating on type %1%";
  }
  errorMsg = (char *)param_3;
  if (param_3 == (allocator *)0x0) {
    errorMsg = "Cause unknown: error caused by bad argument with value %1%";
  }
  std::allocator<char>::allocator();
                    // try { // try from 0042961c to 00429623 has its CatchHandler @ 00429784
  std::__cxx11::basic_string<>::basic_string((char *)string1,(allocator *)functionName);
  std::allocator<char>::~allocator(stack3);
  std::allocator<char>::allocator();
                    // try { // try from 00429658 to 0042965f has its CatchHandler @ 004297a8
  std::__cxx11::basic_string<>::basic_string((char *)string2,(allocator *)errorMsg);
  std::allocator<char>::~allocator(stack2);
  std::allocator<char>::allocator();
                    // try { // try from 00429698 to 0042969f has its CatchHandler @ 004297c4
  std::__cxx11::basic_string<>::basic_string((char *)string3,(allocator *)"Error in function ");
  std::allocator<char>::~allocator(stack1);
  result = FUN_0041622c();
                    // try { // try from 004296cc to 00429717 has its CatchHandler @ 00429818
  FUN_00416170((char *)string1,"%1%",result);
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)string3,string1);
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)string3,": ");
  FUN_0042985c(param_1,stack4);
  result = (char *)std::__cxx11::basic_string<>::c_str();
                    // try { // try from 0042973c to 00429773 has its CatchHandler @ 004297fc
  FUN_00416170((char *)string2,"%1%",result);
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)string3,string2);
  FUN_00416118(stack5,string3);
  catchVar = stack5;
                    // try { // try from 0042977c to 00429783 has its CatchHandler @ 004297e0
  FUN_0042b1d8((runtime_error *)catchVar);
                    // catch() { ... } // from try @ 0042961c with catch @ 00429784
  std::allocator<char>::~allocator(stack3);
                    // WARNING: Subroutine does not return
  _Unwind_Resume(catchVar);
}



undefined4 FUN_0042985c(longdouble param_1,undefined4 param_2)

{
  _Setprecision local_e4;
  basic_stringstream<> abStack_e0 [8];
  basic_ostream abStack_d8 [204];
  
  FUN_004150f8(0x10,8);
  std::__cxx11::basic_stringstream<>::basic_stringstream((_Ios_Openmode)abStack_e0);
  FUN_004160e0(&local_e4,0x11);
                    // try { // try from 004298cc to 0042990f has its CatchHandler @ 00429928
  std::operator<<(abStack_d8,local_e4);
  std::basic_ostream<>::operator<<((basic_ostream<> *)abStack_d8,param_1);
  std::__cxx11::basic_stringstream<>::str();
  std::__cxx11::basic_stringstream<>::~basic_stringstream(abStack_e0);
  return param_2;
}



void FUN_0042996c(void)

{
  return;
}



void FUN_00429994(void)

{
  return;
}



double FUN_004299bc(double param_1,undefined4 param_2,undefined4 param_3,allocator *param_4)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 local_10;
  undefined4 uStack_c;
  
  local_10 = 0;
  uStack_c = 0;
  uVar2 = FUN_0042b260(param_1,param_2,param_3,(double *)&local_10,param_4);
  if ((int)uVar2 == 0) {
    iVar1 = FUN_004281b8();
    if (iVar1 == 0) {
      iVar1 = FUN_004281e8();
      if (iVar1 != 0) {
        param_1 = (double)CONCAT44(uStack_c,local_10);
      }
    }
    else {
      param_1 = (double)CONCAT44(uStack_c,local_10);
    }
  }
  else {
    param_1 = (double)CONCAT44(uStack_c,local_10);
  }
  return param_1;
}



void FUN_00429a94(void)

{
  FUN_0042b344();
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_00429ad0(void)

{
  FUN_00426c48();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void FUN_00429f5c(allocator *param_1,char *param_2)

{
  char *pcVar1;
  runtime_error *prVar2;
  char *local_res0;
  char *local_res4;
  allocator<char> aaStack_50 [4];
  allocator<char> aaStack_4c [4];
  basic_string abStack_48 [6];
  basic_string abStack_30 [6];
  overflow_error aoStack_18 [12];
  
  local_res0 = (char *)param_1;
  if (param_1 == (allocator *)0x0) {
    local_res0 = "Unknown function operating on type %1%";
  }
  local_res4 = param_2;
  if (param_2 == (char *)0x0) {
    local_res4 = "Cause unknown";
  }
  std::allocator<char>::allocator();
                    // try { // try from 00429fcc to 00429fd3 has its CatchHandler @ 0042a0b4
  std::__cxx11::basic_string<>::basic_string((char *)abStack_48,(allocator *)local_res0);
  std::allocator<char>::~allocator(aaStack_4c);
  std::allocator<char>::allocator();
                    // try { // try from 0042a00c to 0042a013 has its CatchHandler @ 0042a0d8
  std::__cxx11::basic_string<>::basic_string((char *)abStack_30,(allocator *)"Error in function ");
  std::allocator<char>::~allocator(aaStack_50);
  pcVar1 = FUN_0041622c();
                    // try { // try from 0042a040 to 0042a0a3 has its CatchHandler @ 0042a110
  FUN_00416170((char *)abStack_48,"%1%",pcVar1);
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_30,abStack_48);
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_30,": ");
  std::__cxx11::basic_string<>::operator+=((basic_string<> *)abStack_30,local_res4);
  std::overflow_error::overflow_error(aoStack_18,abStack_30);
  prVar2 = (runtime_error *)aoStack_18;
                    // try { // try from 0042a0ac to 0042a0b3 has its CatchHandler @ 0042a0f4
  FUN_00426bc0(prVar2);
                    // catch() { ... } // from try @ 00429fcc with catch @ 0042a0b4
  std::allocator<char>::~allocator(aaStack_4c);
                    // WARNING: Subroutine does not return
  _Unwind_Resume(prVar2);
}



bool FUN_0042a144(ulonglong param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_00414f9c(param_1);
  return CONCAT31(extraout_var,bVar1) != 0;
}



void FUN_0042a198(void)

{
  FUN_00414f40();
  return;
}



int FUN_0042a1d4(int *param_1,int *param_2)

{
  return *param_1 - *param_2;
}



undefined4 * FUN_0042a214(undefined4 *param_1,logic_error *param_2)

{
  FUN_0042c480(param_1,param_2);
  return param_1;
}



void FUN_0042a258(undefined4 *param_1)

{
  *param_1 = &PTR___cxa_pure_virtual_00433674;
  return;
}



void FUN_0042a290(int *param_1,logic_error *param_2)

{
  FUN_0042a258(param_1 + 7);
                    // try { // try from 0042a2d8 to 0042a2df has its CatchHandler @ 0042a31c
  FUN_0042c4fc(param_1,(int *)&PTR_DAT_00433588,param_2);
  *param_1 = (int)&PTR_FUN_0043353c;
  param_1[2] = (int)&PTR_FUN_00433558;
  param_1[7] = (int)&PTR_FUN_00433574;
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_0042a360(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



undefined4 * FUN_0042aad8(undefined4 *param_1,runtime_error *param_2)

{
  FUN_0042c5e0(param_1,param_2);
  return param_1;
}



void FUN_0042ab1c(int *param_1,runtime_error *param_2)

{
  FUN_0042a258(param_1 + 7);
                    // try { // try from 0042ab64 to 0042ab6b has its CatchHandler @ 0042aba8
  FUN_0042c65c(param_1,(int *)&PTR_DAT_00433460,param_2);
  *param_1 = (int)&PTR_FUN_00433414;
  param_1[2] = (int)&PTR_FUN_00433430;
  param_1[7] = (int)&PTR_FUN_0043344c;
  return;
}



undefined8 FUN_0042abec(longdouble param_1,allocator *param_2,allocator *param_3)

{
  undefined8 uVar1;
  
  uVar1 = FUN_004263d0(param_1,param_2,param_3);
  return uVar1;
}



void FUN_0042ac40(double param_1)

{
  FUN_0042c740(param_1);
  return;
}



undefined8 FUN_0042ac80(void)

{
  undefined4 in_v0;
  undefined4 in_v1;
  
  return CONCAT44(in_v1,in_v0);
}



void FUN_0042acb4(double param_1)

{
  FUN_00414e98(param_1);
  return;
}



undefined8 FUN_0042acf0(undefined4 param_1,undefined4 param_2,undefined8 *param_3)

{
  undefined4 in_v1;
  
  return CONCAT44(in_v1,param_3);
}



undefined8 FUN_0042ad28(longdouble *param_1)

{
  undefined8 uVar1;
  
  uVar1 = FUN_0042c788(param_1);
  return uVar1;
}



int * FUN_0042ad70(int *param_1,undefined4 *param_2,int param_3,int param_4)

{
  undefined4 *puVar1;
  undefined4 *local_res4;
  int local_resc;
  int local_10;
  
  local_res4 = param_2;
  local_resc = param_4;
  for (local_10 = param_3 - (int)param_2 >> 2; 0 < local_10; local_10 = local_10 + -1) {
    puVar1 = (undefined4 *)FUN_004232bc(&local_resc);
    *puVar1 = *local_res4;
    local_res4 = local_res4 + 1;
    FUN_0042327c(&local_resc);
  }
  *param_1 = local_resc;
  return param_1;
}



int FUN_0042ae28(int *param_1,int *param_2)

{
  return *param_1 - *param_2 >> 2;
}



void FUN_0042ae6c(undefined4 param_1,int param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0042c87c(param_1);
  FUN_0042c8a4(puVar1,param_2,param_3);
  return;
}



undefined4 FUN_0042aec0(void)

{
  return 0x15555555;
}



undefined4 FUN_0042aeec(void)

{
  return 0x15555555;
}



void FUN_0042af18(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_0042c920(param_1);
  uVar2 = FUN_0042c920(param_2);
  FUN_0042c964(uVar1,uVar2,param_3);
  return;
}



undefined8 FUN_0042af84(longdouble param_1,allocator *param_2,allocator *param_3)

{
  undefined8 uVar1;
  
  uVar1 = error_handler(param_1,param_2,param_3);
  return uVar1;
}



void FUN_0042afd8(undefined4 *param_1,runtime_error *param_2)

{
  std::runtime_error::runtime_error((runtime_error *)param_1,param_2);
  *param_1 = &PTR_FUN_00433660;
  return;
}



void FUN_0042b034(undefined4 *param_1,runtime_error *param_2)

{
  FUN_0042afd8(param_1,param_2);
                    // try { // try from 0042b080 to 0042b087 has its CatchHandler @ 0042b0b0
  FUN_004266b8(param_1 + 2,(int)(param_2 + 8));
  *param_1 = &PTR_FUN_004333ec;
  param_1[2] = &PTR_FUN_00433400;
  return;
}



void FUN_0042b0f0(undefined4 *param_1,runtime_error *param_2)

{
  FUN_00426620(param_1 + 7);
                    // try { // try from 0042b150 to 0042b157 has its CatchHandler @ 0042b194
  FUN_0042b034(param_1,param_2);
  *param_1 = &PTR_FUN_00433394;
  param_1[2] = &PTR_FUN_004333b0;
  param_1[7] = &PTR_FUN_004333cc;
  return;
}



void FUN_0042b1d8(runtime_error *param_1)

{
  int *piVar1;
  
  FUN_004160b8();
  piVar1 = (int *)__cxa_allocate_exception(0x20);
                    // try { // try from 0042b21c to 0042b223 has its CatchHandler @ 0042b240
  FUN_0042c9e8(piVar1,param_1);
                    // WARNING: Subroutine does not return
  __cxa_throw(piVar1,&DAT_00433694,FUN_0042ca88);
}



undefined8
FUN_0042b260(double param_1,undefined4 param_2,undefined4 param_3,double *param_4,allocator *param_5
            )

{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  undefined8 uVar4;
  
  dVar2 = FUN_00414d4c(param_1);
  dVar3 = dVar2;
  uVar4 = FUN_00424ab0();
  uVar1 = (undefined4)((ulonglong)uVar4 >> 0x20);
  if (dVar2 < dVar3) {
    uVar4 = FUN_0042814c(param_5,(char *)0x0);
    uVar1 = (undefined4)((ulonglong)uVar4 >> 0x20);
    *param_4 = param_1;
  }
  return CONCAT44(uVar1,(uint)(dVar2 < dVar3));
}



void FUN_0042b304(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_10 [8];
  
  FUN_0042ce14(auStack_10,param_2);
  return;
}



void FUN_0042b344(void)

{
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_0042b36c(void)

{
  FUN_00424a44();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void FUN_0042c480(undefined4 *param_1,logic_error *param_2)

{
  FUN_0042665c(param_1,param_2);
  FUN_00415dcc(param_1 + 2);
  *param_1 = &PTR_FUN_0043363c;
  param_1[2] = &PTR_FUN_00433650;
  return;
}



void FUN_0042c4fc(int *param_1,int *param_2,logic_error *param_3)

{
  FUN_0042674c(param_1,param_3);
  *param_1 = *param_2;
  param_1[2] = (int)&PTR_FUN_00433600;
  *(int *)((int)param_1 + *(int *)(*param_1 + -0xc)) = param_2[1];
                    // try { // try from 0042c590 to 0042c597 has its CatchHandler @ 0042c5a0
  FUN_00415f58((int)(param_1 + 2),(int)(param_3 + 8));
  return;
}



void FUN_0042c5e0(undefined4 *param_1,runtime_error *param_2)

{
  FUN_004269c0(param_1,param_2);
  FUN_00415dcc(param_1 + 2);
  *param_1 = &PTR_FUN_00433514;
  param_1[2] = &PTR_FUN_00433528;
  return;
}



void FUN_0042c65c(int *param_1,int *param_2,runtime_error *param_3)

{
  FUN_00426a1c(param_1,param_3);
  *param_1 = *param_2;
  param_1[2] = (int)&PTR_FUN_004334d8;
  *(int *)((int)param_1 + *(int *)(*param_1 + -0xc)) = param_2[1];
                    // try { // try from 0042c6f0 to 0042c6f7 has its CatchHandler @ 0042c700
  FUN_00415f58((int)(param_1 + 2),(int)(param_3 + 8));
  return;
}



bool FUN_0042c740(double param_1)

{
  return ((int)param_1 & 1U) != 0;
}



// WARNING: Control flow encountered bad instruction data

undefined8 FUN_0042c788(longdouble *param_1)

{
  char cVar1;
  longdouble lVar2;
  undefined8 uVar3;
  
  lVar2 = *param_1;
  cVar1 = FUN_00428258();
  if (cVar1 != '\x01') {
    uVar3 = FUN_00429498(lVar2,(allocator *)"boost::math::trunc<%1%>(%1%)",(char *)0x0);
    return uVar3;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



undefined4 FUN_0042c87c(undefined4 param_1)

{
  return param_1;
}



undefined4 * FUN_0042c8a4(undefined4 *param_1,int param_2,undefined4 *param_3)

{
  undefined4 uVar1;
  undefined4 *local_res0;
  int local_10;
  
  uVar1 = *param_3;
  local_res0 = param_1;
  for (local_10 = param_2; local_10 != 0; local_10 = local_10 + -1) {
    *local_res0 = uVar1;
    local_res0 = local_res0 + 1;
  }
  return local_res0;
}



void FUN_0042c920(undefined4 param_1)

{
  undefined4 uVar1;
  undefined4 local_res0 [4];
  
  local_res0[0] = param_1;
  uVar1 = FUN_0042cfc0(local_res0);
  FUN_0042cfec(uVar1);
  return;
}



void FUN_0042c964(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  void *pvVar1;
  int iVar2;
  void *pvVar3;
  
  pvVar1 = (void *)FUN_0042c87c(param_1);
  iVar2 = FUN_0042c87c(param_2);
  pvVar3 = (void *)FUN_0042c87c(param_3);
  FUN_0042d014(pvVar1,iVar2,pvVar3);
  return;
}



int * FUN_0042c9e8(int *param_1,runtime_error *param_2)

{
  undefined4 auStack_30 [9];
  
  FUN_0042d064(auStack_30,param_2);
                    // try { // try from 0042ca24 to 0042ca2b has its CatchHandler @ 0042ca44
  FUN_0042d0a8(param_1,(runtime_error *)auStack_30);
  FUN_0042cba4(auStack_30);
  return param_1;
}



void FUN_0042ca88(int *param_1)

{
  *param_1 = (int)&PTR_FUN_004332ec;
  param_1[2] = (int)&PTR_FUN_00433308;
  param_1[7] = (int)&PTR_FUN_00433324;
  FUN_0042cc78(param_1,(int *)&PTR_DAT_00433338);
  setPureVirtualFunctionPointer(param_1 + 7);
  return;
}



void FUN_0042cb1c(int param_1)

{
  FUN_0042ca88((int *)(param_1 + -8));
  return;
}



void FUN_0042cb28(int *param_1)

{
  FUN_0042ca88((int *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_0042cb3c(int *param_1)

{
  FUN_0042ca88(param_1);
  operator_delete(param_1,0x20);
  return;
}



void FUN_0042cb84(int param_1)

{
  FUN_0042cb3c((int *)(param_1 + -8));
  return;
}



void FUN_0042cb90(int *param_1)

{
  FUN_0042cb3c((int *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_0042cba4(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_004333ec;
  param_1[2] = &PTR_FUN_00433400;
  FUN_00415e3c(param_1 + 2);
  FUN_00429510(param_1);
  return;
}



void FUN_0042cc18(int param_1)

{
  FUN_0042cba4((undefined4 *)(param_1 + -8));
  return;
}



void FUN_0042cc24(undefined4 *param_1)

{
  FUN_0042cba4(param_1);
  operator_delete(param_1,0x1c);
  return;
}



void FUN_0042cc6c(int param_1)

{
  FUN_0042cc24((undefined4 *)(param_1 + -8));
  return;
}



void FUN_0042cc78(int *param_1,int *param_2)

{
  *param_1 = *param_2;
  param_1[2] = (int)&PTR_FUN_004333b0;
  *(int *)((int)param_1 + *(int *)(*param_1 + -0xc)) = param_2[1];
  FUN_0042cba4(param_1);
  return;
}



void FUN_0042cd04(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_00433394;
  param_1[2] = &PTR_FUN_004333b0;
  param_1[7] = &PTR_FUN_004333cc;
  FUN_0042cba4(param_1);
  setPureVirtualFunctionPointer(param_1 + 7);
  return;
}



void FUN_0042cd8c(int param_1)

{
  FUN_0042cd04((undefined4 *)(param_1 + -8));
  return;
}



void FUN_0042cd98(int *param_1)

{
  FUN_0042cd04((undefined4 *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_0042cdac(undefined4 *param_1)

{
  FUN_0042cd04(param_1);
  operator_delete(param_1,0x20);
  return;
}



void FUN_0042cdf4(int param_1)

{
  FUN_0042cdac((undefined4 *)(param_1 + -8));
  return;
}



void FUN_0042ce00(int *param_1)

{
  FUN_0042cdac((undefined4 *)((int)param_1 + *(int *)(*param_1 + -0x14)));
  return;
}



void FUN_0042ce14(undefined4 param_1,undefined4 param_2)

{
  FUN_00426424(param_1,param_2);
  FUN_00426424(param_1,param_2);
  FUN_00426424(param_1,param_2);
  return;
}



undefined * FUN_0042ce98(void)

{
  return PTR_DAT_0044d8b8;
}



undefined8 FUN_0042cec4(undefined8 param_1)

{
  return param_1;
}



void FUN_0042cef4(void)

{
  FUN_0042d178();
  return;
}



void FUN_0042cf38(void)

{
  FUN_0042d2a0();
  return;
}



void FUN_0042cf7c(void)

{
  FUN_0042d3f0();
  return;
}



undefined4 FUN_0042cfc0(undefined4 *param_1)

{
  return *param_1;
}



undefined4 FUN_0042cfec(undefined4 param_1)

{
  return param_1;
}



void FUN_0042d014(void *param_1,int param_2,void *param_3)

{
  FUN_0042d530(param_1,param_2,param_3);
  return;
}



undefined4 * FUN_0042d064(undefined4 *param_1,runtime_error *param_2)

{
  FUN_0042d5b0(param_1,param_2);
  return param_1;
}



void FUN_0042d0a8(int *param_1,runtime_error *param_2)

{
  FUN_0042a258(param_1 + 7);
                    // try { // try from 0042d0f0 to 0042d0f7 has its CatchHandler @ 0042d134
  FUN_0042d62c(param_1,(int *)&PTR_DAT_00433338,param_2);
  *param_1 = (int)&PTR_FUN_004332ec;
  param_1[2] = (int)&PTR_FUN_00433308;
  param_1[7] = (int)&PTR_FUN_00433324;
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_0042d178(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_0042d2a0(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_0042d3f0(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void FUN_0042d4f0(void)

{
  FUN_0042d710();
  return;
}



void * FUN_0042d530(void *param_1,int param_2,void *param_3)

{
  int iVar1;
  
  iVar1 = param_2 - (int)param_1 >> 2;
  if (iVar1 != 0) {
    memmove(param_3,param_1,iVar1 << 2);
  }
  return (void *)((int)param_3 + iVar1 * 4);
}



void FUN_0042d5b0(undefined4 *param_1,runtime_error *param_2)

{
  FUN_0042afd8(param_1,param_2);
  FUN_00415dcc(param_1 + 2);
  *param_1 = &PTR_FUN_004333ec;
  param_1[2] = &PTR_FUN_00433400;
  return;
}



void FUN_0042d62c(int *param_1,int *param_2,runtime_error *param_3)

{
  FUN_0042b034(param_1,param_3);
  *param_1 = *param_2;
  param_1[2] = (int)&PTR_FUN_004333b0;
  *(int *)((int)param_1 + *(int *)(*param_1 + -0xc)) = param_2[1];
                    // try { // try from 0042d6c0 to 0042d6c7 has its CatchHandler @ 0042d6d0
  FUN_00415f58((int)(param_1 + 2),(int)(param_3 + 8));
  return;
}



void FUN_0042d710(void)

{
  return;
}



int FUN_0042d738(runtime_error *param_1)

{
  int *piVar1;
  int iVar2;
  
                    // try { // try from 0042d758 to 0042d75f has its CatchHandler @ 0042d7c4
  piVar1 = (int *)operator_new(0x20);
                    // try { // try from 0042d770 to 0042d777 has its CatchHandler @ 0042d7a4
  FUN_0042db4c(piVar1,param_1);
  if (piVar1 == (int *)0x0) {
    iVar2 = 0;
  }
  else {
    iVar2 = (int)piVar1 + *(int *)(*piVar1 + -0xc);
  }
  return iVar2;
}



void FUN_0042d7f4(int *param_1)

{
  FUN_0042d738((runtime_error *)((int)param_1 + *(int *)(*param_1 + -0xc)));
  return;
}



void FUN_0042d808(runtime_error *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)__cxa_allocate_exception(0x20);
                    // try { // try from 0042d83c to 0042d843 has its CatchHandler @ 0042d860
  FUN_0042b0f0(puVar1,param_1);
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&DAT_004336d0,FUN_0042cd04);
}



void FUN_0042d880(int *param_1)

{
  FUN_0042d808((runtime_error *)((int)param_1 + *(int *)(*param_1 + -0x10)));
  return;
}



int FUN_0042d894(runtime_error *param_1)

{
  int *piVar1;
  int iVar2;
  
                    // try { // try from 0042d8b4 to 0042d8bb has its CatchHandler @ 0042d920
  piVar1 = (int *)operator_new(0x20);
                    // try { // try from 0042d8cc to 0042d8d3 has its CatchHandler @ 0042d900
  FUN_0042dc54(piVar1,param_1);
  if (piVar1 == (int *)0x0) {
    iVar2 = 0;
  }
  else {
    iVar2 = (int)piVar1 + *(int *)(*piVar1 + -0xc);
  }
  return iVar2;
}



void FUN_0042d950(int *param_1)

{
  FUN_0042d894((runtime_error *)((int)param_1 + *(int *)(*param_1 + -0xc)));
  return;
}



void FUN_0042d964(runtime_error *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)__cxa_allocate_exception(0x20);
                    // try { // try from 0042d998 to 0042d99f has its CatchHandler @ 0042d9bc
  FUN_00426ad8(puVar1,param_1);
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&DAT_004337f4,FUN_00428b58);
}



void FUN_0042d9dc(int *param_1)

{
  FUN_0042d964((runtime_error *)((int)param_1 + *(int *)(*param_1 + -0x10)));
  return;
}



int FUN_0042d9f0(logic_error *param_1)

{
  int *piVar1;
  int iVar2;
  
                    // try { // try from 0042da10 to 0042da17 has its CatchHandler @ 0042da7c
  piVar1 = (int *)operator_new(0x20);
                    // try { // try from 0042da28 to 0042da2f has its CatchHandler @ 0042da5c
  FUN_0042dd5c(piVar1,param_1);
  if (piVar1 == (int *)0x0) {
    iVar2 = 0;
  }
  else {
    iVar2 = (int)piVar1 + *(int *)(*piVar1 + -0xc);
  }
  return iVar2;
}



void FUN_0042daac(int *param_1)

{
  FUN_0042d9f0((logic_error *)((int)param_1 + *(int *)(*param_1 + -0xc)));
  return;
}



void FUN_0042dac0(logic_error *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)__cxa_allocate_exception(0x20);
                    // try { // try from 0042daf4 to 0042dafb has its CatchHandler @ 0042db18
  FUN_00426808(puVar1,param_1);
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&DAT_00433904,FUN_004286e0);
}



void FUN_0042db38(int *param_1)

{
  FUN_0042dac0((logic_error *)((int)param_1 + *(int *)(*param_1 + -0x10)));
  return;
}



void FUN_0042db4c(undefined4 *param_1,runtime_error *param_2)

{
  FUN_0042a258(param_1 + 7);
                    // try { // try from 0042db90 to 0042db97 has its CatchHandler @ 0042dc10
  FUN_0042b034(param_1,param_2);
  *param_1 = &PTR_FUN_00433394;
  param_1[2] = &PTR_FUN_004333b0;
  param_1[7] = &PTR_FUN_004333cc;
                    // try { // try from 0042dbe4 to 0042dbeb has its CatchHandler @ 0042dbf4
  FUN_00415f58((int)(param_1 + 2),(int)(param_2 + 8));
  return;
}



void FUN_0042dc54(undefined4 *param_1,runtime_error *param_2)

{
  FUN_0042a258(param_1 + 7);
                    // try { // try from 0042dc98 to 0042dc9f has its CatchHandler @ 0042dd18
  FUN_00426a1c(param_1,param_2);
  *param_1 = &PTR_FUN_004334bc;
  param_1[2] = &PTR_FUN_004334d8;
  param_1[7] = &PTR_FUN_004334f4;
                    // try { // try from 0042dcec to 0042dcf3 has its CatchHandler @ 0042dcfc
  FUN_00415f58((int)(param_1 + 2),(int)(param_2 + 8));
  return;
}



void FUN_0042dd5c(undefined4 *param_1,logic_error *param_2)

{
  FUN_0042a258(param_1 + 7);
                    // try { // try from 0042dda0 to 0042dda7 has its CatchHandler @ 0042de20
  FUN_0042674c(param_1,param_2);
  *param_1 = &PTR_FUN_004335e4;
  param_1[2] = &PTR_FUN_00433600;
  param_1[7] = &PTR_FUN_0043361c;
                    // try { // try from 0042ddf4 to 0042ddfb has its CatchHandler @ 0042de04
  FUN_00415f58((int)(param_1 + 2),(int)(param_2 + 8));
  return;
}



void FUN_0042de70(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined **ppuVar1;
  int iVar2;
  
  _DT_INIT();
  ppuVar1 = &__DT_INIT_ARRAY;
  iVar2 = 0;
  do {
    iVar2 = iVar2 + 1;
    (*(code *)*ppuVar1)(param_1,param_2,param_3);
    ppuVar1 = (code **)ppuVar1 + 1;
  } while (iVar2 != 1);
  return;
}



void FUN_0042df20(void)

{
  code **ppcVar1;
  code *pcVar2;
  
  if (DAT_0044d4e4 != (code *)0xffffffff) {
    ppcVar1 = &DAT_0044d4e4;
    pcVar2 = DAT_0044d4e4;
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
  initializeIfNeeded();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int open(char *__file,int __oflag,...)

{
  int iVar1;
  
  iVar1 = open(__file,__oflag);
  return iVar1;
}



void PyTuple_SetItem(void)

{
  PyTuple_SetItem();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::_M_dispose(void)

{
  _M_dispose();
  return;
}



void malloc_trim(void)

{
  malloc_trim();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void rewind(FILE *__stream)

{
  rewind(__stream);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strcat(char *__dest,char *__src)

{
  char *pcVar1;
  
  pcVar1 = strcat(__dest,__src);
  return pcVar1;
}



void CrLogClose(void)

{
  CrLogClose();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream)

{
  size_t sVar1;
  
  sVar1 = fread(__ptr,__size,__n,__stream);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int tcsetattr(int __fd,int __optional_actions,termios *__termios_p)

{
  int iVar1;
  
  iVar1 = tcsetattr(__fd,__optional_actions,__termios_p);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::basic_string(void)

{
  basic_string();
  return;
}



void sinl(void)

{
  sinl();
  return;
}



void __thiscall std::overflow_error::~overflow_error(overflow_error *this)

{
  ~overflow_error(this);
  return;
}



void expl(void)

{
  expl();
  return;
}



void json_object_object_add(void)

{
  json_object_object_add();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::find(char *param_1,uint param_2)

{
  find(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int socket(int __domain,int __type,int __protocol)

{
  int iVar1;
  
  iVar1 = socket(__domain,__type,__protocol);
  return iVar1;
}



void PyDict_GetItemString(void)

{
  PyDict_GetItemString();
  return;
}



void __cxa_pure_virtual(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int isatty(int __fd)

{
  int iVar1;
  
  iVar1 = isatty(__fd);
  return iVar1;
}



void CrLogUnLock(void)

{
  CrLogUnLock();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int access(char *__name,int __type)

{
  int iVar1;
  
  iVar1 = access(__name,__type);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_rwlock_init(pthread_rwlock_t *__rwlock,pthread_rwlockattr_t *__attr)

{
  int iVar1;
  
  iVar1 = pthread_rwlock_init(__rwlock,__attr);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

float sqrtf(float __x)

{
  float fVar1;
  
  fVar1 = sqrtf(__x);
  return fVar1;
}



void __thiscall std::__cxx11::basic_string<>::operator+=(basic_string<> *this,basic_string *param_1)

{
  operator+=(this,param_1);
  return;
}



void __thiscall std::overflow_error::overflow_error(overflow_error *this,basic_string *param_1)

{
  overflow_error(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = fopen(__filename,__modes);
  return pFVar1;
}



void json_object_object_length(void)

{
  json_object_object_length();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::insert(uint param_1,char *param_2)

{
  insert(param_1,param_2);
  return;
}



void GetLogLevel(void)

{
  GetLogLevel();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int select(int __nfds,fd_set *__readfds,fd_set *__writefds,fd_set *__exceptfds,timeval *__timeout)

{
  int iVar1;
  
  iVar1 = select(__nfds,__readfds,__writefds,__exceptfds,__timeout);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_cancel(pthread_t __th)

{
  int iVar1;
  
  iVar1 = pthread_cancel(__th);
  return iVar1;
}



void __cxa_rethrow(void)

{
  __cxa_rethrow();
  return;
}



void __thiscall std::__cxx11::basic_string<>::operator+=(basic_string<> *this,char *param_1)

{
  operator+=(this,param_1);
  return;
}



void json_object_to_json_string(void)

{
  json_object_to_json_string();
  return;
}



void CrLogLock(void)

{
  CrLogLock();
  return;
}



void PyModule_GetDict(void)

{
  PyModule_GetDict();
  return;
}



void PyRun_SimpleStringFlags(void)

{
  PyRun_SimpleStringFlags();
  return;
}



// std::invalid_argument::~invalid_argument()

void __thiscall std::invalid_argument::~invalid_argument(invalid_argument *this)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __thiscall std::overflow_error::~overflow_error(overflow_error *this)

{
  ~overflow_error(this);
  return;
}



void __divdi3(void)

{
  __divdi3();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int ferror(FILE *__stream)

{
  int iVar1;
  
  iVar1 = ferror(__stream);
  return iVar1;
}



void __thiscall std::domain_error::domain_error(domain_error *this,basic_string *param_1)

{
  domain_error(this,param_1);
  return;
}



void __thiscall std::ios_base::Init::Init(Init *this)

{
  Init(this);
  return;
}



void PyTuple_New(void)

{
  PyTuple_New();
  return;
}



void blobmsg_format_json_with_cb(void)

{
  blobmsg_format_json_with_cb();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
  size_t sVar1;
  
  sVar1 = fwrite(__ptr,__size,__n,__s);
  return sVar1;
}



void json_object_new_double(void)

{
  json_object_new_double();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memcpy(__dest,__src,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t write(int __fd,void *__buf,size_t __n)

{
  ssize_t sVar1;
  
  sVar1 = write(__fd,__buf,__n);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = malloc(__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__throw_bad_alloc(void)

{
  __throw_bad_alloc();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



void __thiscall std::allocator<char>::~allocator(allocator<char> *this)

{
  ~allocator(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int usleep(__useconds_t __useconds)

{
  int iVar1;
  
  iVar1 = usleep(__useconds);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int accept(int __fd,sockaddr *__addr,socklen_t *__addr_len)

{
  int iVar1;
  
  iVar1 = accept(__fd,__addr,__addr_len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_rwlock_wrlock(pthread_rwlock_t *__rwlock)

{
  int iVar1;
  
  iVar1 = pthread_rwlock_wrlock(__rwlock);
  return iVar1;
}



void __cxa_throw(void)

{
                    // WARNING: Subroutine does not return
  __cxa_throw();
}



void __thiscall std::basic_ostream<>::operator<<(basic_ostream<> *this,longdouble param_1)

{
  operator<<(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__detail::_List_node_base::_M_hook(_List_node_base *param_1)

{
  _M_hook(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sprintf(char *__s,char *__format,...)

{
  int iVar1;
  
  iVar1 = sprintf(__s,__format);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void operator_delete(void *param_1)

{
  operator_delete(param_1);
  return;
}



void uloop_run(void)

{
  uloop_run();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

basic_ostream * std::operator<<(basic_ostream *param_1,_Setprecision param_2)

{
  basic_ostream *pbVar1;
  
  pbVar1 = operator<<(param_1,param_2);
  return pbVar1;
}



void PyObject_CallObject(void)

{
  PyObject_CallObject();
  return;
}



void __thiscall std::domain_error::~domain_error(domain_error *this)

{
  ~domain_error(this);
  return;
}



void __thiscall std::runtime_error::runtime_error(runtime_error *this,basic_string *param_1)

{
  runtime_error(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::basic_string(char *param_1,allocator *param_2)

{
  basic_string(param_1,param_2);
  return;
}



void __thiscall std::runtime_error::~runtime_error(runtime_error *this)

{
  ~runtime_error(this);
  return;
}



void __cxa_atexit(void)

{
  __cxa_atexit();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int tcgetattr(int __fd,termios *__termios_p)

{
  int iVar1;
  
  iVar1 = tcgetattr(__fd,__termios_p);
  return iVar1;
}



void PyFloat_AsDouble(void)

{
  PyFloat_AsDouble();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = strcmp(__s1,__s2);
  return iVar1;
}



void Py_Finalize(void)

{
  Py_Finalize();
  return;
}



void powl(void)

{
  powl();
  return;
}



void _Py_Dealloc(void)

{
  _Py_Dealloc();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int * __errno_location(void)

{
  int *piVar1;
  
  piVar1 = __errno_location();
  return piVar1;
}



void __thiscall
std::invalid_argument::invalid_argument(invalid_argument *this,basic_string *param_1)

{
  invalid_argument(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fclose(__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t send(int __fd,void *__buf,size_t __n,int __flags)

{
  ssize_t sVar1;
  
  sVar1 = send(__fd,__buf,__n,__flags);
  return sVar1;
}



void Py_BuildValue(void)

{
  Py_BuildValue();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int memcmp(void *__s1,void *__s2,size_t __n)

{
  int iVar1;
  
  iVar1 = memcmp(__s1,__s2,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::size(void)

{
  size();
  return;
}



void ubus_connect(void)

{
  ubus_connect();
  return;
}



void PyList_New(void)

{
  PyList_New();
  return;
}



void PyImport_ImportModule(void)

{
  PyImport_ImportModule();
  return;
}



void ubus_subscribe(void)

{
  ubus_subscribe();
  return;
}



void __umoddi3(void)

{
  __umoddi3();
  return;
}



void PyUnicode_FromString(void)

{
  PyUnicode_FromString();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fcntl(int __fd,int __cmd,...)

{
  int iVar1;
  
  iVar1 = fcntl(__fd,__cmd);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fseek(FILE *__stream,long __off,int __whence)

{
  int iVar1;
  
  iVar1 = fseek(__stream,__off,__whence);
  return iVar1;
}



void ceill(void)

{
  ceill();
  return;
}



void json_object_new_int(void)

{
  json_object_new_int();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::allocator<char>::allocator(void)

{
  allocator();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputs(char *__s,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputs(__s,__stream);
  return iVar1;
}



void json_object_object_get(void)

{
  json_object_object_get();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::logic_error::what() const

void std::logic_error::what(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __cxa_free_exception(void)

{
  __cxa_free_exception();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::_M_local_data(void)

{
  _M_local_data();
  return;
}



void CrLogWrite(void)

{
  CrLogWrite();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strchr(char *__s,int __c)

{
  char *pcVar1;
  
  pcVar1 = strchr(__s,__c);
  return pcVar1;
}



// std::runtime_error::~runtime_error()

void __thiscall std::runtime_error::~runtime_error(runtime_error *this)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_detach(pthread_t __th)

{
  int iVar1;
  
  iVar1 = pthread_detach(__th);
  return iVar1;
}



void __libc_start_main(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __thiscall std::domain_error::~domain_error(domain_error *this)

{
  ~domain_error(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int vsnprintf(char *__s,size_t __maxlen,char *__format,__gnuc_va_list __arg)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::append(basic_string *param_1)

{
  append(param_1);
  return;
}



void json_object_get_int(void)

{
  json_object_get_int();
  return;
}



void __thiscall std::runtime_error::runtime_error(runtime_error *this,basic_string *param_1)

{
  runtime_error(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__sighandler_t signal(int __sig,__sighandler_t __handler)

{
  __sighandler_t p_Var1;
  
  p_Var1 = signal(__sig,__handler);
  return p_Var1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int gettimeofday(timeval *__tv,__timezone_ptr_t __tz)

{
  int iVar1;
  
  iVar1 = gettimeofday(__tv,__tz);
  return iVar1;
}



void uloop_init(void)

{
  uloop_init();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int cfsetospeed(termios *__termios_p,speed_t __speed)

{
  int iVar1;
  
  iVar1 = cfsetospeed(__termios_p,__speed);
  return iVar1;
}



void __thiscall std::logic_error::logic_error(logic_error *this,logic_error *param_1)

{
  logic_error(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strsignal(int __sig)

{
  char *pcVar1;
  
  pcVar1 = strsignal(__sig);
  return pcVar1;
}



void json_object_new_array(void)

{
  json_object_new_array();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::_S_copy_chars(char *param_1,char *param_2,char *param_3)

{
  _S_copy_chars(param_1,param_2,param_3);
  return;
}



void __thiscall std::runtime_error::runtime_error(runtime_error *this,runtime_error *param_1)

{
  runtime_error(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void operator_delete(void *param_1,uint param_2)

{
  operator_delete(param_1,param_2);
  return;
}



void __thiscall std::allocator<char>::~allocator(allocator<char> *this)

{
  ~allocator(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_create(pthread_t *__newthread,pthread_attr_t *__attr,__start_routine *__start_routine,
                  void *__arg)

{
  int iVar1;
  
  iVar1 = pthread_create(__newthread,__attr,__start_routine,__arg);
  return iVar1;
}



void json_object_new_string(void)

{
  json_object_new_string();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::_M_set_length(uint param_1)

{
  _M_set_length(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



void PyArg_ParseTuple(void)

{
  PyArg_ParseTuple();
  return;
}



void PyUnicode_AsUTF8(void)

{
  PyUnicode_AsUTF8();
  return;
}



// std::ios_base::Init::~Init()

void __thiscall std::ios_base::Init::~Init(Init *this)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * operator_new(uint param_1)

{
  void *pvVar1;
  
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void CrLogOpen(void)

{
  CrLogOpen();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_stringstream<>::str(void)

{
  str();
  return;
}



void __cxa_begin_catch(void)

{
  __cxa_begin_catch();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_join(pthread_t __th,void **__thread_return)

{
  int iVar1;
  
  iVar1 = pthread_join(__th,__thread_return);
  return iVar1;
}



void ubus_free(void)

{
  ubus_free();
  return;
}



void ubus_lookup_id(void)

{
  ubus_lookup_id();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::capacity(void)

{
  capacity();
  return;
}



void json_object_array_add(void)

{
  json_object_array_add();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::_M_data(void)

{
  _M_data();
  return;
}



void logl(void)

{
  logl();
  return;
}



void json_object_array_length(void)

{
  json_object_array_length();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void exit(int __status)

{
                    // WARNING: Subroutine does not return
  exit(__status);
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_stringstream<>::basic_stringstream(_Ios_Openmode param_1)

{
  basic_stringstream(param_1);
  return;
}



void json_object_get_string(void)

{
  json_object_get_string();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strerror(int __errnum)

{
  char *pcVar1;
  
  pcVar1 = strerror(__errnum);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uchar * SHA256(uchar *d,size_t n,uchar *md)

{
  uchar *puVar1;
  
  puVar1 = SHA256(d,n,md);
  return puVar1;
}



void __cxa_end_catch(void)

{
  __cxa_end_catch();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uchar * MD5(uchar *d,size_t n,uchar *md)

{
  uchar *puVar1;
  
  puVar1 = MD5(d,n,md);
  return puVar1;
}



void __thiscall std::__cxx11::basic_string<>::~basic_string(basic_string<> *this)

{
  ~basic_string(this);
  return;
}



void ubus_invoke_fd(void)

{
  ubus_invoke_fd();
  return;
}



void json_object_put(void)

{
  json_object_put();
  return;
}



void __cxa_allocate_exception(void)

{
  __cxa_allocate_exception();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_rwlock_unlock(pthread_rwlock_t *__rwlock)

{
  int iVar1;
  
  iVar1 = pthread_rwlock_unlock(__rwlock);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::_M_capacity(uint param_1)

{
  _M_capacity(param_1);
  return;
}



void PyErr_Occurred(void)

{
  PyErr_Occurred();
  return;
}



void json_object_array_get_idx(void)

{
  json_object_array_get_idx();
  return;
}



void uloop_fd_add(void)

{
  uloop_fd_add();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *destination,int value,size_t size)

{
  void *pvVar1;
  
  pvVar1 = memset(destination,value,size);
  return pvVar1;
}



void floorl(void)

{
  floorl();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

pthread_t pthread_self(void)

{
  pthread_t pVar1;
  
  pVar1 = pthread_self();
  return pVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::reserve(uint param_1)

{
  reserve(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t recv(int __fd,void *__buf,size_t __n,int __flags)

{
  ssize_t sVar1;
  
  sVar1 = recv(__fd,__buf,__n,__flags);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__throw_length_error(char *param_1)

{
  __throw_length_error(param_1);
  return;
}



void PyList_SetItem(void)

{
  PyList_SetItem();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int cfsetispeed(termios *__termios_p,speed_t __speed)

{
  int iVar1;
  
  iVar1 = cfsetispeed(__termios_p,__speed);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int listen(int __fd,int __n)

{
  int iVar1;
  
  iVar1 = listen(__fd,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::basic_string(basic_string *param_1)

{
  basic_string(param_1);
  return;
}



void uloop_done(void)

{
  uloop_done();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::replace(uint param_1,uint param_2,char *param_3)

{
  replace(param_1,param_2,param_3);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int snprintf(char *__s,size_t __maxlen,char *__format,...)

{
  int iVar1;
  
  iVar1 = snprintf(__s,__maxlen,__format);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::_M_create(uint *param_1,uint param_2)

{
  _M_create(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int close(int __fd)

{
  int iVar1;
  
  iVar1 = close(__fd);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  ssize_t sVar1;
  
  sVar1 = read(__fd,__buf,__nbytes);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

basic_ostream * std::operator<<(basic_ostream *param_1,basic_string *param_2)

{
  basic_ostream *pbVar1;
  
  pbVar1 = operator<<(param_1,param_2);
  return pbVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::runtime_error::what() const

void std::runtime_error::what(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void PyCallable_Check(void)

{
  PyCallable_Check();
  return;
}



void _Unwind_Resume(void)

{
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



void PyArg_Parse(void)

{
  PyArg_Parse();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memmove(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memmove(__dest,__src,__n);
  return pvVar1;
}



void json_object_get_double(void)

{
  json_object_get_double();
  return;
}



void json_tokener_parse(void)

{
  json_tokener_parse();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int unlink(char *__name)

{
  int iVar1;
  
  iVar1 = unlink(__name);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__throw_logic_error(char *param_1)

{
  __throw_logic_error(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int tcflush(int __fd,int __queue_selector)

{
  int iVar1;
  
  iVar1 = tcflush(__fd,__queue_selector);
  return iVar1;
}



void Py_Initialize(void)

{
  Py_Initialize();
  return;
}



void __thiscall
std::__cxx11::basic_string<>::_Alloc_hider::_Alloc_hider
          (_Alloc_hider *this,char *param_1,allocator *param_2)

{
  _Alloc_hider(this,param_1,param_2);
  return;
}



void ubus_register_subscriber(void)

{
  ubus_register_subscriber();
  return;
}



void PyErr_Print(void)

{
  PyErr_Print();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strcpy(char *__dest,char *__src)

{
  char *pcVar1;
  
  pcVar1 = strcpy(__dest,__src);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::append(char *param_1,uint param_2)

{
  append(param_1,param_2);
  return;
}



void PyTuple_GetItem(void)

{
  PyTuple_GetItem();
  return;
}



void json_object_new_object(void)

{
  json_object_new_object();
  return;
}



void Py_IsInitialized(void)

{
  Py_IsInitialized();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::insert(uint param_1,basic_string *param_2)

{
  insert(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::c_str(void)

{
  c_str();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::append(char *param_1)

{
  append(param_1);
  return;
}



void __thiscall std::__cxx11::basic_stringstream<>::~basic_stringstream(basic_stringstream<> *this)

{
  ~basic_stringstream(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void bzero(void *__s,size_t __n)

{
  bzero(__s,__n);
  return;
}



void json_object_from_file(void)

{
  json_object_from_file();
  return;
}



void ubus_strerror(void)

{
  ubus_strerror();
  return;
}



void json_object_is_type(void)

{
  json_object_is_type();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void std::__cxx11::basic_string<>::_M_data(char *param_1)

{
  _M_data(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int bind(int __fd,sockaddr *__addr,socklen_t __len)

{
  int iVar1;
  
  iVar1 = bind(__fd,__addr,__len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

long ftell(FILE *__stream)

{
  long lVar1;
  
  lVar1 = ftell(__stream);
  return lVar1;
}


