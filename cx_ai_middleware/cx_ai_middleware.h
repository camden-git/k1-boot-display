typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef long double    longdouble;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
#define unkbyte9   unsigned long long
#define unkbyte10   unsigned long long
#define unkbyte11   unsigned long long
#define unkbyte12   unsigned long long
#define unkbyte13   unsigned long long
#define unkbyte14   unsigned long long
#define unkbyte15   unsigned long long
#define unkbyte16   unsigned long long

#define unkuint9   unsigned long long
#define unkuint10   unsigned long long
#define unkuint11   unsigned long long
#define unkuint12   unsigned long long
#define unkuint13   unsigned long long
#define unkuint14   unsigned long long
#define unkuint15   unsigned long long
#define unkuint16   unsigned long long

#define unkint9   long long
#define unkint10   long long
#define unkint11   long long
#define unkint12   long long
#define unkint13   long long
#define unkint14   long long
#define unkint15   long long
#define unkint16   long long

#define unkfloat1   float
#define unkfloat2   float
#define unkfloat3   float
#define unkfloat5   double
#define unkfloat6   double
#define unkfloat7   double
#define unkfloat9   long double
#define unkfloat11   long double
#define unkfloat12   long double
#define unkfloat13   long double
#define unkfloat14   long double
#define unkfloat15   long double
#define unkfloat16   long double

#define BADSPACEBASE   void
#define code   void

typedef enum Elf32_GPRMask_MIPS {
    gpr_zero=1,
    gpr_at=2,
    gpr_v0=4,
    gpr_v1=8,
    gpr_a0=16,
    gpr_a1=32,
    gpr_a2=64,
    gpr_a3=128,
    gpr_t0=256,
    gpr_t1=512,
    gpr_t2=1024,
    gpr_t3=2048,
    gpr_t4=4096,
    gpr_t5=8192,
    gpr_t6=16384,
    gpr_t7=32768,
    gpr_s0=65536,
    gpr_s1=131072,
    gpr_s2=262144,
    gpr_s3=524288,
    gpr_s4=1048576,
    gpr_s5=2097152,
    gpr_s6=4194304,
    gpr_s7=8388608,
    gpr_t8=16777216,
    gpr_t9=33554432,
    gpr_k0=67108864,
    gpr_k1=134217728,
    gpr_gp=268435456,
    gpr_sp=536870912,
    gpr_fp=1073741824,
    gpr_ra=2147483648
} Elf32_GPRMask_MIPS;

typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry {
    dword initial_loc; // Initial Location
    dword data_loc; // Data location
};

typedef struct termios termios, *Ptermios;

typedef uint tcflag_t;

typedef uchar cc_t;

typedef uint speed_t;

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_line;
    cc_t c_cc[32];
    speed_t c_ispeed;
    speed_t c_ospeed;
};

typedef ushort sa_family_t;

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef longlong __quad_t;

typedef __quad_t __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    void *__pad1;
    void *__pad2;
    void *__pad3;
    void *__pad4;
    size_t __pad5;
    int _mode;
    char _unused2[40];
};

struct _IO_marker {
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};

typedef struct _IO_FILE FILE;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

typedef uint __socklen_t;

typedef __socklen_t socklen_t;

typedef int __ssize_t;

typedef __ssize_t ssize_t;

typedef long __time_t;

typedef long __suseconds_t;

typedef uint __useconds_t;

typedef union pthread_rwlockattr_t pthread_rwlockattr_t, *Ppthread_rwlockattr_t;

union pthread_rwlockattr_t {
    char __size[8];
    long __align;
};

typedef ulong pthread_t;

typedef struct _struct_19 _struct_19, *P_struct_19;

struct _struct_19 {
    int __lock;
    uint __nr_readers;
    uint __readers_wakeup;
    uint __writer_wakeup;
    uint __nr_readers_queued;
    uint __nr_writers_queued;
    uchar __flags;
    uchar __shared;
    uchar __pad1;
    uchar __pad2;
    int __writer;
};

typedef union pthread_rwlock_t pthread_rwlock_t, *Ppthread_rwlock_t;

union pthread_rwlock_t {
    struct _struct_19 __data;
    char __size[32];
    long __align;
};

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[36];
    long __align;
};

typedef void *__gnuc_va_list;

typedef struct timeval timeval, *Ptimeval;

struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};

typedef struct timezone timezone, *Ptimezone;

typedef struct timezone *__timezone_ptr_t;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

typedef long __fd_mask;

typedef struct fd_set fd_set, *Pfd_set;

struct fd_set {
    __fd_mask fds_bits[32];
};

typedef void (*__sighandler_t)(int);

typedef struct logic_error logic_error, *Plogic_error;

struct logic_error { // PlaceHolder Structure
};

typedef struct invalid_argument invalid_argument, *Pinvalid_argument;

struct invalid_argument { // PlaceHolder Structure
};

typedef struct allocator<char> allocator<char>, *Pallocator<char>;

struct allocator<char> { // PlaceHolder Structure
};

typedef struct allocator allocator, *Pallocator;

struct allocator { // PlaceHolder Structure
};

typedef dword _Ios_Openmode;

typedef struct runtime_error runtime_error, *Pruntime_error;

struct runtime_error { // PlaceHolder Structure
};

typedef struct basic_ostream basic_ostream, *Pbasic_ostream;

struct basic_ostream { // PlaceHolder Structure
};

typedef struct overflow_error overflow_error, *Poverflow_error;

struct overflow_error { // PlaceHolder Structure
};

typedef struct domain_error domain_error, *Pdomain_error;

struct domain_error { // PlaceHolder Structure
};

typedef dword _Setprecision;

typedef dword forward_iterator_tag;

typedef struct basic_ostream<char,std::char_traits<char>> basic_ostream<char,std::char_traits<char>>, *Pbasic_ostream<char,std::char_traits<char>>;

struct basic_ostream<char,std::char_traits<char>> { // PlaceHolder Structure
};

typedef struct basic_string.conflict basic_string.conflict, *Pbasic_string.conflict;

struct basic_string.conflict { // PlaceHolder Structure
};

typedef dword basic_string;

typedef struct basic_string<char,std::char_traits<char>,std::allocator<char>> basic_string<char,std::char_traits<char>,std::allocator<char>>, *Pbasic_string<char,std::char_traits<char>,std::allocator<char>>;

struct basic_string<char,std::char_traits<char>,std::allocator<char>> { // PlaceHolder Structure
};

typedef struct basic_stringstream<char,std::char_traits<char>,std::allocator<char>> basic_stringstream<char,std::char_traits<char>,std::allocator<char>>, *Pbasic_stringstream<char,std::char_traits<char>,std::allocator<char>>;

struct basic_stringstream<char,std::char_traits<char>,std::allocator<char>> { // PlaceHolder Structure
};

typedef struct _Alloc_hider _Alloc_hider, *P_Alloc_hider;

struct _Alloc_hider { // PlaceHolder Structure
};

typedef struct Init Init, *PInit;

struct Init { // PlaceHolder Structure
};

typedef struct _List_node_base _List_node_base, *P_List_node_base;

struct _List_node_base { // PlaceHolder Structure
};

typedef struct Elf32_RegInfo_MIPS Elf32_RegInfo_MIPS, *PElf32_RegInfo_MIPS;

struct Elf32_RegInfo_MIPS {
    enum Elf32_GPRMask_MIPS ri_gprmask;
    dword field1_0x4[4];
    dword ri_gp_value;
};

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

typedef enum Elf_ProgramHeaderType_MIPS {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482,
    PT_MIPS_REGINFO=1879048192,
    PT_MIPS_RTPROC=1879048193,
    PT_MIPS_OPTIONS=1879048194,
    PT_MIPS_ABIFLAGS=1879048195
} Elf_ProgramHeaderType_MIPS;

struct Elf32_Phdr {
    enum Elf_ProgramHeaderType_MIPS p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef enum Elf_SectionHeaderType_MIPS {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191,
    SHT_MIPS_LIBLIST=1879048192,
    SHT_MIPS_MSYM=1879048193,
    SHT_MIPS_CONFLICT=1879048194,
    SHT_MIPS_GPTAB=1879048195,
    SHT_MIPS_UCODE=1879048196,
    SHT_MIPS_DEBUG=1879048197,
    SHT_MIPS_REGINFO=1879048198,
    SHT_MIPS_PACKAGE=1879048199,
    SHT_MIPS_PACKSYM=1879048200,
    SHT_MIPS_RELD=1879048201,
    =1879048203,
    SHT_MIPS_CONTENT=1879048204,
    SHT_MIPS_OPTIONS=1879048205,
    SHT_MIPS_SHDR=1879048208,
    SHT_MIPS_FDESC=1879048209,
    SHT_MIPS_EXTSYM=1879048210,
    SHT_MIPS_DENSE=1879048211,
    SHT_MIPS_PDESC=1879048212,
    SHT_MIPS_LOCSYM=1879048213,
    SHT_MIPS_AUXSYM=1879048214,
    SHT_MIPS_OPTSYM=1879048215,
    SHT_MIPS_LOCSTR=1879048216,
    SHT_MIPS_LINE=1879048217,
    SHT_MIPS_RFDESC=1879048218,
    SHT_MIPS_DELTASYM=1879048219,
    SHT_MIPS_DELTAINST=1879048220,
    SHT_MIPS_DELTACLASS=1879048221,
    SHT_MIPS_DWARF=1879048222,
    SHT_MIPS_DELTADECL=1879048223,
    SHT_MIPS_SYMBOL_LIB=1879048224,
    SHT_MIPS_EVENTS=1879048225,
    SHT_MIPS_TRANSLATE=1879048226,
    SHT_MIPS_PIXIE=1879048227,
    SHT_MIPS_XLATE=1879048228,
    SHT_MIPS_XLATE_DEBUG=1879048229,
    SHT_MIPS_WHIRL=1879048230,
    SHT_MIPS_EH_REGION=1879048231,
    SHT_MIPS_XLATE_OLD=1879048232,
    SHT_MIPS_PDR_EXCEPTION=1879048233,
    SHT_MIPS_ABIFLAGS=1879048234
} Elf_SectionHeaderType_MIPS;

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
};

typedef struct Elf32_Dyn_MIPS Elf32_Dyn_MIPS, *PElf32_Dyn_MIPS;

typedef enum Elf32_DynTag_MIPS {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_XHASH=1879047924,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_MIPS_RLD_VERSION=1879048193,
    DT_MIPS_TIME_STAMP=1879048194,
    DT_MIPS_ICHECKSUM=1879048195,
    DT_MIPS_IVERSION=1879048196,
    DT_MIPS_FLAGS=1879048197,
    DT_MIPS_BASE_ADDRESS=1879048198,
    DT_MIPS_MSYM=1879048199,
    DT_MIPS_CONFLICT=1879048200,
    DT_MIPS_LIBLIST=1879048201,
    DT_MIPS_LOCAL_GOTNO=1879048202,
    DT_MIPS_CONFLICTNO=1879048203,
    DT_MIPS_LIBLISTNO=1879048208,
    DT_MIPS_SYMTABNO=1879048209,
    DT_MIPS_UNREFEXTNO=1879048210,
    DT_MIPS_GOTSYM=1879048211,
    DT_MIPS_HIPAGENO=1879048212,
    DT_MIPS_RLD_MAP=1879048214,
    DT_MIPS_DELTA_CLASS=1879048215,
    DT_MIPS_DELTA_CLASS_NO=1879048216,
    DT_MIPS_DELTA_INSTANCE=1879048217,
    DT_MIPS_DELTA_INSTANCE_NO=1879048218,
    DT_MIPS_DELTA_RELOC=1879048219,
    DT_MIPS_DELTA_RELOC_NO=1879048220,
    DT_MIPS_DELTA_SYM=1879048221,
    DT_MIPS_DELTA_SYM_NO=1879048222,
    DT_MIPS_DELTA_CLASSSYM=1879048224,
    DT_MIPS_DELTA_CLASSSYM_NO=1879048225,
    DT_MIPS_CXX_FLAGS=1879048226,
    DT_MIPS_PIXIE_INIT=1879048227,
    DT_MIPS_SYMBOL_LIB=1879048228,
    DT_MIPS_LOCALPAGE_GOTIDX=1879048229,
    DT_MIPS_LOCAL_GOTIDX=1879048230,
    DT_MIPS_HIDDEN_GOTIDX=1879048231,
    DT_MIPS_PROTECTED_GOTIDX=1879048232,
    DT_MIPS_OPTIONS=1879048233,
    DT_MIPS_INTERFACE=1879048234,
    DT_MIPS_DYNSTR_ALIGN=1879048235,
    DT_MIPS_INTERFACE_SIZE=1879048236,
    DT_MIPS_RLD_TEXT_RESOLVE_ADDR=1879048237,
    DT_MIPS_PERF_SUFFIX=1879048238,
    DT_MIPS_COMPACT_SIZE=1879048239,
    DT_MIPS_GP_VALUE=1879048240,
    DT_MIPS_AUX_DYNAMIC=1879048241,
    DT_MIPS_PLTGOT=1879048242,
    DT_MIPS_RWPLT=1879048244,
    DT_MIPS_RLD_MAP_REL=1879048245,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf32_DynTag_MIPS;

struct Elf32_Dyn_MIPS {
    enum Elf32_DynTag_MIPS d_tag;
    dword d_val;
};

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

struct Elf32_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_MIPS sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym {
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef struct NoteAbiTag NoteAbiTag, *PNoteAbiTag;

struct NoteAbiTag {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    dword abiType; // 0 == Linux
    dword requiredKernelVersion[3]; // Major.minor.patch
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};




void _DT_INIT(void);
undefined4 _ftext(void);
void processEntry entry(undefined4 param_1,undefined4 param_2);
void performInitialization(void);
void unreachableFunction(void);
void initializeIfNeeded(void);
void unreachableFunction(void);
void checkLaserConnectState(void);
void blackbox_handler(int signal_num);
undefined4 FUN_004041b4(void);
void processReceivedData(void);
undefined4 writeToFile(char *filename,void *data,size_t dataSize);
undefined4 createAndSendJsonResponse(int connection,undefined4 controlCommand,undefined4 result);
void getLaserCorrection02mmResult(undefined4 param_1,undefined4 param_2,int *param_3);
void getLaserOffsetCorrectionTowPoint(undefined4 param_1,undefined4 param_2,int *param_3);
void getFirstFloorDetectionInfo(undefined4 param_1,undefined4 param_2,int *param_3);
void getLaserOffsetCorrection(undefined4 param_1,undefined4 param_2,int *param_3);
void processJsonResponse(undefined4 param_1,undefined4 param_2,int *param_3);
void processJsonLines(undefined4 param_1,undefined4 param_2,int *param_3);
void getLaserStatus(undefined4 param_1,undefined4 param_2,int *param_3);
void controlAndLogLaserStatus(undefined4 param_1,undefined4 param_2,int *param_3);
void processLogLevel(undefined4 param_1,undefined4 param_2,int *param_3);
void processSetLogLevel(undefined4 param_1,undefined4 param_2,int *param_3);
void processOpenFlowStatus(undefined4 param_1,undefined4 param_2,int *param_3);
int createPThreadForDataProcessing(void);
undefined4 cleanupAndShutdown(void);
undefined4 initializeServer(void);
undefined4 FUN_0040b214(void);
undefined4 removeFromLinkedList(void *param_1);
undefined4 * getLinkedListHead(void);
undefined4 sendData(int socketFD,void *data,size_t dataSize);
int createThread(void);
undefined4 cancelThread(void);
void decreaseAndDeallocate(int *count);
int processLaserData(short *laserData,int param_2,float *param_3);
undefined4 processFlowDetection(short *param_1,int param_2,float *param_3);
undefined4 getSelectLineFromAi(undefined4 param_1,int param_2,undefined4 param_3,int param_4,undefined4 param_5,int param_6,char *param_7);
undefined4 FUN_0040c540(undefined4 *param_1,int param_2,undefined4 *param_3,int param_4,undefined4 *param_5,int param_6,undefined4 *param_7);
undefined4 FUN_0040cadc(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,float *param_5);
undefined4 FUN_0040cf84(undefined4 *param_1,int param_2,undefined4 *param_3,int param_4,undefined4 param_5,undefined4 param_6,float *param_7);
undefined4 FUN_0040d608(undefined4 *param_1,int param_2,undefined4 *param_3,int param_4,float *param_5);
undefined4 FUN_0040db9c(undefined4 param_1,undefined4 param_2,char *param_3);
undefined4 FUN_0040e03c(char *param_1,char *param_2,char *param_3,undefined4 *param_4);
undefined4 FUN_0040e190(undefined4 param_1,undefined4 param_2,undefined4 *param_3);
undefined4 FUN_0040e61c(undefined4 param_1,undefined4 param_2,undefined8 *param_3,undefined8 *param_4);
undefined4 FUN_0040ea58(void);
undefined4 FUN_0040ec08(void);
int FUN_0040ec40(void *param_1,size_t param_2,int param_3);
size_t FUN_0040eda8(void *param_1,size_t param_2);
undefined4 FUN_0040ef18(char *param_1);
undefined4 FUN_0040f55c(void);
undefined4 FUN_0040f620(void);
uint FUN_0040f640(uint param_1,void *param_2,size_t param_3);
uint sendCommandAndGetResponse(uint param_1,void *param_2,size_t param_3,void *param_4,ushort param_5);
void FUN_0040fdb0(void *param_1,ushort param_2);
void FUN_0040fddc(void *param_1,ushort param_2);
void FUN_0040fe08(void *param_1,ushort param_2);
void FUN_0040fe34(void *param_1,ushort param_2);
void copyArrayHalves(undefined2 *sourceArray,uint arrayLength,undefined2 *destinationArray);
void FUN_0040fe9c(void *param_1,ushort param_2,byte param_3);
void FUN_0040fed8(void *param_1,ushort param_2,byte param_3);
void FUN_0040ff14(void *param_1,ushort param_2);
void FUN_0040ff40(void *param_1,ushort param_2);
void FUN_0040ff6c(void *param_1,ushort param_2);
void FUN_0040ffac(void *param_1,ushort param_2);
void FUN_0040ffe4(void *param_1,ushort param_2);
void FUN_00410024(void *param_1,ushort param_2);
void FUN_0041005c(void *param_1,ushort param_2,undefined param_3,undefined param_4);
void FUN_004100a0(void *param_1,ushort param_2,byte param_3);
void FUN_004100dc(void *param_1,ushort param_2);
void FUN_00410108(void *param_1,ushort param_2);
void FUN_00410134(void *param_1,ushort param_2,undefined4 param_3);
void FUN_00410174(void *param_1,undefined4 param_2,undefined4 param_3,void *param_4,size_t param_5);
uint FUN_00410240(void *param_1,ushort param_2,uint param_3,uint param_4);
void FUN_004102b0(void *param_1,ushort param_2);
void FUN_004102dc(void *param_1,ushort param_2,undefined param_3);
void FUN_0041030c(void *param_1,ushort param_2,undefined param_3);
void FUN_0041033c(void *param_1,ushort param_2);
void FUN_00410368(void *param_1,ushort param_2,undefined param_3);
void FUN_00410398(void *param_1,ushort param_2);
void FUN_004103c4(void *param_1,ushort param_2);
void FUN_004103f0(void *param_1,ushort param_2,undefined4 param_3);
void FUN_00410430(void *param_1,ushort param_2);
void FUN_0041045c(void *param_1,ushort param_2,undefined4 param_3);
void FUN_0041049c(void *param_1,ushort param_2);
void FUN_004104c8(void *param_1,ushort param_2,undefined param_3,undefined param_4);
void FUN_004104fc(void *param_1,ushort param_2);
void FUN_00410528(void *param_1,ushort param_2);
void FUN_00410554(void *param_1,ushort param_2);
void FUN_00410580(void *param_1,ushort param_2);
void FUN_004105ac(void *param_1,ushort param_2,void *param_3,size_t param_4);
void FUN_004105dc(char *param_1,uchar *param_2,uchar *param_3);
int FUN_004106d0(void);
undefined4 FUN_00410980(char *param_1);
undefined4 FUN_004122d8(void);
undefined4 FUN_00412300(void);
undefined4 FUN_00412310(int param_1,float *param_2,float *param_3);
int FUN_004126b0(int param_1,int param_2,undefined4 param_3,undefined4 param_4);
int FUN_00412764(int param_1,int param_2,float param_3,undefined4 param_4);
undefined4 FUN_00412a00(int param_1,int param_2,int param_3,undefined4 *param_4,float *param_5);
undefined4 FUN_00413860(char *param_1,char *param_2,char *param_3);
void FUN_00414b00(int param_1,int param_2);
void _INIT_0(void);
float FUN_00414cb0(float param_1);
void FUN_00414cdc(undefined8 param_1);
void FUN_00414d14(undefined8 param_1);
double FUN_00414d4c(double param_1);
void FUN_00414d78(undefined8 param_1);
void FUN_00414db0(undefined8 param_1);
void FUN_00414de8(undefined8 param_1,undefined8 param_2);
void FUN_00414e28(undefined8 param_1);
void FUN_00414e60(float param_1);
undefined4 FUN_00414e98(double param_1);
void FUN_00414f40(void);
bool FUN_00414f9c(ulonglong param_1);
undefined4 FUN_00414fd4(undefined4 param_1,undefined4 param_2);
void FUN_00415000(char *param_1);
basic_string<> * FUN_00415038(basic_string<> *param_1);
basic_string<> * FUN_00415098(basic_string<> *param_1);
uint FUN_004150f8(uint param_1,uint param_2);
undefined4 FUN_0041512c(void);
undefined4 FUN_00415150(void);
undefined8 FUN_00415178(void);
undefined8 FUN_004151a0(void);
undefined8 FUN_004151c8(void);
undefined8 FUN_004151f0(void);
void setTwoValues(undefined4 *destinationArray,undefined4 value1,undefined4 value2);
undefined4 FUN_00415260(int *param_1,int *param_2);
uint FUN_004152c8(int *param_1,int *param_2);
int FUN_00415310(int *param_1);
undefined4 FUN_00415348(int *param_1);
void GenericSetvaluesinarray(undefined4 *array,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_004153f4(int *param_1,int param_2);
int FUN_00415cbc(int *param_1,int param_2);
void FUN_00415d50(int param_1);
void FUN_00415dcc(undefined4 *param_1);
void FUN_00415e3c(undefined4 *param_1);
void FUN_00415e90(undefined4 *param_1);
void setPureVirtualFunctionPointer(undefined4 *destinationPointer);
void FUN_00415f10(undefined4 *param_1);
void FUN_00415f58(int param_1,int param_2);
void FUN_004160b8(void);
undefined4 * FUN_004160e0(undefined4 *param_1,undefined4 param_2);
void FUN_00416118(undefined4 *param_1,basic_string *param_2);
void FUN_00416170(char *param_1,char *param_2,char *param_3);
char * FUN_0041622c(void);
undefined8 FUN_00416254(void);
undefined8 FUN_0041627c(int param_1);
undefined4 FUN_004162e4(int param_1);
void FUN_00416310(float param_1);
void FUN_00416348(undefined4 param_1,float param_2);
void FUN_00416384(float param_1);
int FUN_004163c0(int param_1,int param_2);
void FUN_004164a8(undefined4 *param_1);
void FUN_004164e8(undefined4 *param_1);
basic_string<> *FUN_00416528(basic_string<> *param_1,undefined *param_2,int param_3,undefined4 param_4);
void FUN_0041663c(allocator<char> *param_1);
basic_string * FUN_00416678(basic_string *param_1,basic_string *param_2,uint param_3);
basic_string * FUN_00416790(basic_string *param_1,undefined4 param_2,uint param_3);
basic_string * FUN_004167f8(basic_string *param_1,basic_string *param_2);
basic_string<> * FUN_0041685c(basic_string<> *param_1);
basic_string * appendStringToBasicString(basic_string *str,char *appendStr);
basic_string<> * FUN_00416908(basic_string<> *param_1);
void MAYBElogAndThrowException(void);
undefined4 FUN_00416c34(undefined4 param_1);
void FUN_00416c5c(undefined4 *param_1,undefined4 *param_2);
basic_string * std::operator+(basic_string *param_1,char *param_2);
undefined4 FUN_00416da8(undefined4 *param_1);
int FUN_00416dd4(undefined4 *param_1);
void FUN_00416e2c(int param_1,undefined4 param_2,undefined4 param_3);
void FUN_00416f88(int param_1);
void FUN_00416fd4(int param_1,int param_2);
void FUN_004170a0(void);
void FUN_004170dc(void);
void FUN_00417118(int param_1,int param_2,int param_3);
void FUN_004171e4(int *param_1,int param_2);
int * FUN_00417230(int *param_1,int param_2);
int * FUN_0041727c(int *param_1);
void FUN_004172bc(undefined4 *param_1);
int FUN_004172f8(int param_1,int param_2);
int FUN_00417354(int param_1,int param_2);
void FUN_004174b8(int param_1);
undefined4 FUN_00417504(int param_1);
void FUN_00417530(undefined4 *param_1);
void freeResource(int **resource);
undefined4 FUN_0041759c(undefined4 *param_1);
int ** FUN_004175c8(int **param_1,int **param_2);
void FUN_00417614(int param_1,int param_2);
void FUN_00417658(int param_1,int param_2);
void FUN_0041778c(int param_1);
undefined4 * FUN_004177d8(undefined4 *param_1,int param_2);
int FUN_0041781c(int param_1,int param_2,int param_3);
void FUN_004178b0(undefined4 *param_1);
void FUN_004178f0(void **param_1);
int FUN_00417974(int *param_1);
void FUN_004179b4(undefined8 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_00417a00(undefined8 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_00417bb8(void);
int * FUN_00417e9c(int *param_1,int param_2);
int * FUN_00417ee8(int *param_1,int param_2);
void FUN_00417f5c(int *param_1,int param_2);
int * FUN_00417fa8(int *param_1,int param_2);
undefined4 *setValuesInArrayFromMemory(undefined4 *array,int sourceAddress,undefined4 param_3,undefined4 param_4);
int MaybeProccessDataBlock(int destination,int param_2,uint param_3,int param_4,int param_5,uint param_6);
void FUN_00418168(int param_1);
void FUN_004181b4(int param_1,int param_2);
undefined4 FUN_00418280(int param_1);
void FUN_004182ac(int param_1);
int FUN_00418328(int param_1,int param_2,int param_3);
int FUN_0041888c(int param_1,int param_2);
void FUN_004188e8(byte *param_1,float param_2);
int FUN_00418930(int param_1,int param_2);
int FUN_00418a24(int param_1,int param_2,int param_3);
int FUN_00418a74(int param_1,undefined4 param_2,int param_3);
float FUN_00418ac4(float *param_1,float param_2);
int FUN_00418afc(int param_1,int param_2,undefined4 param_3);
int FUN_00418bf8(int param_1,undefined4 param_2,int param_3);
int FUN_00418c48(int param_1,int param_2,int param_3);
undefined4 * copyValuesToBuffer(undefined4 *param_1,int param_2);
void FUN_00418f88(int param_1,undefined4 *param_2);
int * processDataBlock(int *destination,int sourceAddress);
int * copyDataToArray(int *destination,int sourceAddress);
void FUN_00419118(int *param_1,int param_2);
int * FUN_00419164(int *param_1,int param_2);
int * FUN_004191b0(int *param_1,int param_2,int param_3,int param_4);
float FUN_0041920c(float *param_1,float param_2);
int FUN_00419244(int param_1,int param_2,undefined4 param_3);
void FUN_00419340(int param_1,int param_2);
int FUN_00419474(int param_1,undefined4 param_2,undefined4 param_3,int param_4);
bool FUN_0041970c(float *param_1,float param_2);
int FUN_00419758(int param_1,int param_2,undefined4 param_3);
bool FUN_00419854(undefined4 param_1,float param_2,float param_3);
void FUN_004198a0(float param_1,float param_2);
int FUN_004198e4(int param_1,int param_2,int param_3);
int FUN_00419be4(int param_1,int param_2,int param_3);
int FUN_00419c34(int param_1,int param_2,uint param_3,uint param_4);
int FUN_00419f14(int param_1,int param_2,int param_3);
bool FUN_0041a23c(float *param_1,float param_2);
int FUN_0041a288(int param_1,int param_2,undefined4 param_3);
bool FUN_0041a384(undefined4 param_1,float param_2,float param_3);
void FUN_0041a3d0(float param_1,float param_2);
int FUN_0041a414(int param_1,int param_2,int param_3);
bool FUN_0041a9b0(undefined4 param_1,float param_2,float param_3);
void FUN_0041a9fc(float param_1,float param_2);
int FUN_0041aa40(int param_1,int param_2,int param_3);
bool FUN_0041afdc(float *param_1,float param_2);
int FUN_0041b028(int param_1,int param_2,undefined4 param_3);
int FUN_0041b124(int param_1,int param_2,int param_3);
int FUN_0041b1ac(int param_1,int param_2,int param_3);
void FUN_0041b7e0(int param_1,int param_2,int param_3);
int calculateOffset(int baseAddress,int rowOffset,int columnOffset);
void FUN_0041b940(int param_1,int param_2,int param_3);
void FUN_0041ba0c(int param_1);
void FUN_0041ba58(undefined4 *param_1);
void FUN_0041ba98(void);
void FUN_0041bad4(undefined4 *param_1);
void FUN_0041bb20(undefined4 *param_1);
void FUN_0041bb60(void);
void FUN_0041bb9c(undefined4 *param_1);
int FUN_0041bbe8(int param_1,int param_2,int param_3);
void FUN_0041bc7c(int param_1,undefined4 param_2);
void FUN_0041bcd8(int param_1,undefined4 param_2);
undefined4 FUN_0041bd34(int param_1);
int * FUN_0041bd60(int *param_1,int param_2);
int * FUN_0041bdac(int *param_1,int param_2);
void FUN_0041be20(int param_1,int param_2,undefined4 param_3);
undefined4 * FUN_0041be68(undefined4 *param_1,undefined4 *param_2);
undefined4 * FUN_0041beb4(undefined4 *param_1,undefined4 param_2);
bool FUN_0041befc(int *param_1,int *param_2);
undefined4 * FUN_0041bf40(undefined4 *param_1,undefined4 *param_2);
void FUN_0041bf98(int *param_1);
undefined4 * FUN_0041bfd8(undefined4 *param_1,undefined4 *param_2);
undefined4 * FUN_0041c024(undefined4 *param_1,undefined4 param_2);
bool FUN_0041c06c(int *param_1,int *param_2);
undefined4 * FUN_0041c0b0(undefined4 *param_1,undefined4 *param_2);
void FUN_0041c108(int *param_1);
void __thiscall std::__cxx11::basic_string<>::basic_string<char*,void>(basic_string<> *this,char *param_1,char *param_2,allocator *param_3);
undefined4 FUN_0041c1ec(undefined4 param_1);
void FUN_0041c214(uint *param_1,char *param_2,char *param_3);
void FUN_0041c264(int param_1);
int * FUN_0041c2dc(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_0041c334(int param_1);
void FUN_0041c3e4(void);
void FUN_0041c40c(void);
void FUN_0041c434(int *param_1,int param_2);
int * FUN_0041c63c(int *param_1);
undefined4 FUN_0041c678(undefined4 *param_1);
int * FUN_0041c6a4(int *param_1,int param_2);
int * FUN_0041c6ec(int *param_1,int param_2);
bool FUN_0041c734(int *param_1,int *param_2);
int * FUN_0041c77c(int *param_1);
undefined4 FUN_0041c7b8(undefined4 *param_1);
void FUN_0041c7e4(void **param_1,undefined4 param_2);
void FUN_0041c894(int param_1,int *param_2,char param_3);
void FUN_0041ca1c(void);
void FUN_0041ca58(int param_1);
void FUN_0041cb08(void);
int FUN_0041cb44(int param_1,int param_2);
void releaseMemory(int **ptr);
void FUN_0041cc34(int **param_1,int *param_2);
int FUN_0041cc8c(int param_1,int param_2);
void FUN_0041ccc4(void);
void FUN_0041cd00(void);
void FUN_0041cd3c(int param_1);
int * FUN_0041cdb4(int *param_1,int param_2);
int * FUN_0041ce00(int *param_1,int param_2);
void FUN_0041ce74(int *param_1,int param_2);
int * FUN_0041cec0(int *param_1,int param_2);
int * FUN_0041cf0c(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_0041cf64(int param_1);
void FUN_0041d014(void);
void FUN_0041d050(undefined4 *param_1);
void FUN_0041d090(void **param_1);
undefined4 FUN_0041d108(undefined4 param_1);
void FUN_0041d130(void);
undefined8 FUN_0041d178(undefined4 param_1,undefined4 param_2);
undefined8 FUN_0041d1b8(undefined4 param_1,undefined4 param_2);
void FUN_0041d1f8(int param_1,undefined4 *param_2);
int * FUN_0041d2c8(int *param_1,int param_2);
void FUN_0041d33c(int *param_1,int param_2);
int * FUN_0041d544(int *param_1,int param_2);
void FUN_0041d58c(int param_1);
void FUN_0041d604(int *param_1,int param_2);
void FUN_0041d80c(int param_1,uint param_2,uint param_3);
void FUN_0041de34(void);
void cleanupFunction(int param_1);
void FUN_0041df20(void);
float FUN_0041df5c(int param_1,int param_2,float param_3);
undefined4 FUN_0041dfe0(int param_1);
undefined4 FUN_0041e00c(undefined4 *param_1);
int FUN_0041e038(undefined4 *param_1);
void FUN_0041e090(int param_1,undefined4 param_2,undefined4 param_3);
int * FUN_0041e1ec(int *param_1,int param_2,uint param_3);
int * FUN_0041e440(int *param_1,int param_2,uint param_3);
int FUN_0041e690(int param_1,int param_2);
void FUN_0041e798(float param_1,undefined4 param_2,byte param_3);
int * FUN_0041e7e0(int *param_1,int param_2,int param_3,int param_4);
int FUN_0041e840(int param_1,int param_2,int param_3);
float FUN_0041eb3c(float *param_1,float param_2);
int FUN_0041eb74(int param_1,int param_2,undefined4 param_3);
int * FUN_0041ec70(int *param_1,int param_2,int param_3,int param_4);
int * FUN_0041ecd0(int *param_1,int param_2,int param_3,int param_4,int param_5);
void FUN_0041ed34(int param_1);
void handleException(int *errorCode,int exceptionCode);
int * FUN_0041efb4(int *param_1,int param_2);
void FUN_0041effc(int *param_1,int param_2);
int * FUN_0041f204(int *param_1,int param_2,int param_3,int param_4);
int * FUN_0041f2e4(int *param_1,int param_2,int param_3,int param_4);
int * FUN_0041f344(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
int FUN_0041f39c(int param_1,undefined4 *param_2);
int FUN_0041f7bc(int param_1,undefined4 *param_2);
int * FUN_0041fbd8(int *param_1,int param_2,int param_3,int param_4);
int * FUN_0041fc38(int *param_1,int param_2,int param_3,int param_4,int param_5);
undefined4 FUN_0041fc9c(undefined4 param_1,char param_2,char param_3);
void FUN_0041fcfc(char param_1,char param_2);
int FUN_0041fd54(int param_1,int param_2,int param_3);
void FUN_00420054(int param_1,int param_2,int param_3);
void FUN_00420120(int *param_1,uint param_2);
int FUN_004201b0(int *param_1,int param_2);
int FUN_004201ec(int param_1,int param_2,int param_3);
int FUN_004204cc(int param_1,int param_2);
int * FUN_00420528(int *param_1,int param_2,int param_3,int param_4);
undefined4 FUN_00420588(undefined4 param_1);
void FUN_004205b0(undefined4 param_1,undefined param_2);
undefined4 FUN_004205f4(undefined4 param_1,undefined param_2);
void FUN_00420650(undefined4 param_1,undefined4 param_2,undefined4 param_3);
int * FUN_004206d4(int *param_1,int param_2,int param_3,undefined param_4);
int * FUN_004207b8(int *param_1,int param_2,int param_3);
int * FUN_0042082c(int *param_1,int param_2,int param_3);
undefined4 FUN_00420884(undefined4 *param_1);
undefined4 FUN_004208b0(undefined4 param_1);
void FUN_004208d8(undefined4 param_1,undefined param_2);
undefined4 FUN_0042091c(undefined4 param_1,undefined param_2);
void FUN_00420978(undefined4 param_1,undefined4 param_2,undefined4 param_3);
int * FUN_004209fc(int *param_1,int param_2,int param_3,undefined param_4);
int * FUN_00420ae0(int *param_1,int param_2,int param_3);
int * FUN_00420b54(int *param_1,int param_2,int param_3);
int * FUN_00420bac(int *param_1,int param_2,int param_3,int param_4);
int FUN_00420c0c(int param_1,int param_2);
longlong FUN_00420ebc(int param_1,int param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_00420f48(int param_1);
undefined4 FUN_00420f74(int param_1);
void FUN_00420fa0(void);
void FUN_00420fdc(void);
void FUN_00421018(int param_1);
void FUN_00421090(int param_1);
void FUN_00421140(undefined4 *param_1);
void FUN_0042118c(void);
void FUN_004211c8(undefined4 *param_1);
void FUN_0042126c(undefined4 *param_1);
void FUN_004212b8(void);
void FUN_004212f4(undefined4 *param_1);
undefined4 FUN_00421398(undefined4 param_1);
void FUN_004213c0(int param_1,undefined4 param_2,undefined4 param_3);
undefined4 FUN_00421444(undefined4 param_1);
void FUN_0042146c(int param_1,undefined4 param_2,undefined4 param_3);
void FUN_004214f0(int *param_1,int param_2);
int * FUN_004216f8(int *param_1,int param_2);
void FUN_00421740(int param_1,int param_2,undefined4 param_3);
void FUN_0042179c(undefined4 *param_1,undefined4 param_2);
void FUN_004217d4(int param_1);
void FUN_00421814(undefined4 *param_1,undefined4 param_2);
void FUN_0042184c(int param_1);
void FUN_0042188c(uint *param_1,char *param_2,char *param_3);
void FUN_004218e0(undefined4 param_1,uint param_2);
int * FUN_00421954(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_004219d4(undefined4 param_1,void *param_2);
bool FUN_00421a18(int *param_1,int *param_2);
undefined4 FUN_00421a5c(undefined4 param_1);
void FUN_00421a84(undefined4 param_1,undefined4 param_2,undefined4 param_3);
undefined4 * FUN_00421adc(undefined4 *param_1,int param_2);
void FUN_00421b28(void **param_1,undefined4 param_2,undefined4 param_3);
undefined4 * FUN_00421df8(undefined4 *param_1,undefined4 *param_2);
int * FUN_00421e40(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_00421e98(undefined4 *param_1);
void FUN_00421edc(void);
void FUN_00421f04(undefined4 param_1,void *param_2);
void FUN_00421f48(void);
void FUN_00421f70(int **param_1);
undefined8 FUN_00421fdc(void);
undefined8 FUN_00422014(void);
undefined8 FUN_00422040(void);
undefined8 FUN_00422070(void);
undefined8 FUN_004220a8(void);
void FUN_004220d4(void);
void FUN_004220fc(void);
void FUN_00422124(undefined4 param_1,uint param_2);
void FUN_00422190(int *param_1,int param_2);
int * FUN_00422398(int *param_1,int param_2);
void FUN_004223dc(int *param_1,int param_2);
int * FUN_004225e4(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_00422664(undefined4 param_1,void *param_2);
void FUN_004226a8(undefined4 *param_1);
void FUN_004226fc(undefined4 param_1,void *param_2);
void FUN_00422758(void);
undefined8 FUN_0042279c(undefined4 param_1,undefined4 param_2);
undefined8 FUN_004227dc(undefined4 param_1,undefined4 param_2);
int * FUN_0042284c(int *param_1,int param_2);
bool FUN_00422894(int *param_1,int *param_2);
int * FUN_004228dc(int *param_1);
void FUN_0042291c(undefined4 *param_1);
int * FUN_00422958(int *param_1,int param_2);
int * FUN_004229a0(int *param_1,int param_2);
bool FUN_004229e8(int *param_1,int *param_2);
int * FUN_00422a30(int *param_1);
undefined4 FUN_00422a6c(undefined4 *param_1);
uint * FUN_00422a98(uint *param_1,uint *param_2);
void FUN_00422aec(undefined4 param_1,uint param_2);
int * FUN_00422b60(int *param_1);
void FUN_00422ba0(undefined4 *param_1);
int FUN_00422bdc(int param_1,int param_2,int param_3);
void FUN_00422c70(void);
void FUN_00422c98(undefined4 param_1,void *param_2);
void FUN_00422cdc(void);
bool areNotEqualBytes(int *param_1,int *param_2);
int * FUN_00422d4c(int *param_1);
int * FUN_00422d88(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
float FUN_00422de0(float param_1,undefined4 param_2,byte param_3);
int * FUN_00422e74(int *param_1,int param_2,int param_3,int param_4);
int * FUN_00422f54(int *param_1,int param_2,int param_3,int param_4,int param_5);
int * FUN_00422fb8(int *param_1,int param_2,int param_3,int param_4);
int * FUN_00423018(int *param_1,int param_2,int param_3,int param_4);
int * FUN_004230f8(int *param_1,int param_2,int param_3,int param_4,int param_5);
void FUN_00423208(undefined4 param_1,uint param_2);
int * FUN_0042327c(int *param_1);
void FUN_004232bc(undefined4 *param_1);
int * FUN_004232f8(int *param_1,int param_2,int param_3,int param_4);
int * FUN_004233d8(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_00423458(undefined4 *param_1);
int FUN_00423484(undefined4 *param_1);
int * FUN_004234ec(int *param_1,int param_2,int param_3,int param_4);
int * FUN_004235cc(int *param_1,int param_2,int param_3,int param_4,int param_5);
int * FUN_004236dc(int *param_1,int param_2,int param_3,int param_4,int param_5);
void FUN_00423740(int *param_1,uint param_2);
void FUN_004237cc(undefined4 *param_1,int param_2);
undefined4 FUN_00423840(int param_1);
int FUN_0042386c(int param_1,int param_2);
int FUN_004238c4(int param_1,uint param_2,undefined param_3);
int * FUN_0042391c(int *param_1,int param_2,int param_3,int param_4);
bool intEquals(int *param_1,int *param_2);
int * FUN_00423a40(int *param_1,int param_2,int param_3,int param_4);
int * FUN_00423b20(int *param_1,int param_2,int param_3,int param_4,int param_5);
void FUN_00423b84(void);
void FUN_00423bac(void);
void FUN_00423bd4(undefined4 param_1,uint param_2);
void FUN_00423c48(undefined4 param_1,void *param_2);
void FUN_00423c8c(undefined4 *param_1);
void FUN_00423d00(int param_1);
void FUN_00423d58(void);
undefined4 FUN_00423d80(undefined4 param_1);
void FUN_00423da8(void);
void FUN_00423dec(undefined4 param_1,void *param_2);
void FUN_00423e38(undefined4 *param_1);
void FUN_00423eac(int param_1);
void FUN_00423f04(void);
undefined4 FUN_00423f2c(undefined4 param_1);
void FUN_00423f54(void);
void FUN_00423f98(undefined4 param_1,void *param_2);
int FUN_00423fe4(undefined4 param_1,undefined4 param_2);
void FUN_004240e4(int param_1,int param_2);
int FUN_00424138(undefined4 param_1,undefined4 param_2);
void FUN_00424238(int param_1,int param_2);
undefined4 * FUN_0042428c(undefined4 *param_1,undefined4 param_2);
int FUN_004242d0(int param_1,int param_2,int *param_3);
void FUN_00424364(undefined4 param_1);
void FUN_0042439c(undefined4 param_1);
void std::__cxx11::basic_string<>::_M_construct<char*>(uint *param_1,char *param_2,char *param_3);
undefined4 FUN_0042453c(void);
undefined4 FUN_00424568(undefined4 param_1);
int * FUN_00424590(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_0042462c(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void FUN_0042469c(undefined4 *param_1,undefined4 *param_2);
uint FUN_004246d8(int *param_1,uint param_2,char *param_3);
int FUN_004247f4(undefined4 param_1,undefined4 param_2);
undefined4 FUN_00424858(undefined4 param_1,uint param_2);
undefined4 FUN_004248b4(undefined4 param_1);
void FUN_004248dc(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void FUN_00424954(void);
int * FUN_00424998(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_00424a18(undefined4 param_1,undefined4 param_2);
undefined8 FUN_00424a44(void);
undefined8 FUN_00424a7c(void);
undefined8 FUN_00424ab0(void);
undefined4 FUN_00424ae0(void);
undefined4 * FUN_00424b08(undefined4 *param_1,undefined4 param_2);
int * FUN_00424b40(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_00424bd4(undefined4 param_1,void *param_2);
void FUN_00424c20(void);
int * FUN_00424c4c(int *param_1,int param_2);
bool FUN_00424c90(int *param_1,int *param_2);
int * FUN_00424cd4(int *param_1);
undefined4 FUN_00424d10(undefined4 *param_1);
bool FUN_00424d3c(int *param_1,int *param_2);
undefined4 FUN_00424d80(void);
int * FUN_00424dac(int *param_1);
undefined4 FUN_00424de8(undefined4 *param_1);
int * FUN_00424e14(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
int * FUN_00424e94(int *param_1,int param_2,int param_3,int param_4,int param_5);
int * FUN_00424fa4(int *param_1,int param_2,int param_3,int param_4);
float FUN_00425084(undefined4 param_1,float *param_2,float *param_3);
undefined4 FUN_004250c4(void);
int * FUN_004250f0(int *param_1);
undefined4 FUN_0042512c(undefined4 *param_1);
undefined4 * FUN_00425158(undefined4 *param_1,undefined4 param_2);
int * FUN_00425190(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_00425224(int param_1);
int * FUN_00425250(int *param_1,int param_2,int param_3,int param_4,int param_5);
void FUN_00425360(undefined4 *param_1);
void FUN_004253bc(int *param_1,uint param_2);
void FUN_00425438(undefined4 param_1,int param_2);
void FUN_0042547c(int param_1,uint param_2);
int * FUN_004257e0(int *param_1,int param_2,int param_3,int param_4,int param_5);
undefined4 FUN_004258f0(void);
void FUN_0042591c(void);
void FUN_00425958(int param_1,undefined4 param_2);
void FUN_004259a8(void);
void FUN_004259d4(undefined4 param_1,void *param_2);
void FUN_00425a20(void);
void FUN_00425a5c(int param_1,undefined4 param_2);
void FUN_00425aac(void);
void FUN_00425ad8(undefined4 param_1,void *param_2);
void FUN_00425b24(undefined4 param_1);
void FUN_00425b64(undefined4 *param_1,undefined4 param_2,undefined4 param_3);
void FUN_00425bc0(undefined4 *param_1);
void FUN_00425c24(undefined4 param_1,undefined4 param_2,undefined4 param_3);
int FUN_00425c7c(int param_1);
void FUN_00425cb0(int param_1);
void FUN_00425cf0(undefined4 param_1);
void FUN_00425d30(undefined4 *param_1,undefined4 param_2,undefined4 param_3);
void FUN_00425d8c(undefined4 *param_1);
void FUN_00425df0(undefined4 param_1,undefined4 param_2,undefined4 param_3);
int FUN_00425e48(int param_1);
void FUN_00425e7c(undefined4 *param_1,undefined4 param_2);
bool FUN_00425eb4(int *param_1,int *param_2);
int * FUN_00425efc(int *param_1);
bool FUN_00425f38(int **param_1,undefined4 param_2);
undefined4 FUN_00425f94(undefined4 param_1);
undefined4 FUN_00425fbc(undefined4 param_1);
bool FUN_00425fe4(int param_1);
void FUN_00426014(int param_1,int param_2);
undefined4 FUN_00426080(undefined4 param_1);
undefined4 * FUN_004260a8(undefined4 *param_1,undefined4 param_2);
int * FUN_004260e0(int *param_1,undefined8 *param_2,int param_3,int param_4);
void FUN_0042613c(undefined4 param_1);
void FUN_00426184(undefined4 param_1,uint param_2);
undefined4 * FUN_004261c8(undefined4 *param_1,undefined4 param_2);
void FUN_0042620c(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void FUN_00426258(void);
undefined4 * FUN_00426284(undefined4 *param_1,undefined4 param_2);
int * FUN_004262bc(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void FUN_00426358(longdouble param_1,allocator *param_2,char *param_3);
undefined8 FUN_004263d0(longdouble param_1,allocator *param_2,allocator *param_3);
void FUN_00426424(undefined4 param_1,undefined4 param_2);
undefined8 FUN_00426468(allocator *param_1,char *param_2);
void FUN_004264d4(void);
undefined4 * FUN_00426554(undefined4 *param_1,undefined4 param_2);
undefined4 * FUN_0042658c(undefined4 *param_1,undefined4 param_2);
int * FUN_004265c4(int *param_1,int param_2,int param_3,int param_4);
void FUN_00426620(undefined4 *param_1);
void FUN_0042665c(undefined4 *param_1,logic_error *param_2);
void FUN_004266b8(undefined4 *param_1,int param_2);
void FUN_0042674c(undefined4 *param_1,logic_error *param_2);
void FUN_00426808(undefined4 *param_1,logic_error *param_2);
void FUN_004268f0(logic_error *param_1);
void FUN_00426978(void);
void FUN_004269c0(undefined4 *param_1,runtime_error *param_2);
void FUN_00426a1c(undefined4 *param_1,runtime_error *param_2);
void FUN_00426ad8(undefined4 *param_1,runtime_error *param_2);
void FUN_00426bc0(runtime_error *param_1);
undefined8 FUN_00426c48(void);
undefined8 FUN_00426c84(void);
undefined8 FUN_00426cb4(void);
undefined8 FUN_00426ce4(void);
undefined8 FUN_00426d1c(void);
undefined8 FUN_00426d48(void);
undefined8 FUN_00426d78(void);
undefined8 FUN_00426db0(void);
void FUN_00426ddc(void);
undefined4 FUN_0042742c(undefined4 param_1);
int * FUN_00427454(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
float FUN_004274f0(undefined4 param_1,float *param_2,float *param_3);
undefined4 * FUN_00427530(undefined4 *param_1,undefined4 param_2);
undefined4 * FUN_00427568(undefined4 *param_1,undefined4 param_2);
int * FUN_004275a0(int *param_1,int param_2,int param_3,int param_4);
void FUN_004275fc(void);
void FUN_00427640(undefined4 param_1,int param_2);
int FUN_00427688(int param_1,int param_2);
bool FUN_004276e0(undefined4 param_1,byte *param_2,byte *param_3);
void FUN_0042772c(void);
void FUN_00427754(undefined4 param_1,void *param_2);
void FUN_00427798(void);
void FUN_004277c0(undefined4 param_1,void *param_2);
void FUN_00427804(undefined4 param_1,uint param_2);
undefined4 FUN_00427848(undefined4 param_1);
void FUN_00427870(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void FUN_004278e0(undefined4 param_1);
void FUN_00427918(undefined4 param_1,uint param_2);
undefined4 FUN_0042795c(undefined4 param_1);
void FUN_00427984(undefined4 param_1,undefined4 param_2,undefined4 param_3);
bool FUN_004279f4(int *param_1,int *param_2);
undefined4 FUN_00427a38(undefined4 *param_1);
undefined4 FUN_00427a64(undefined4 param_1);
int FUN_00427a94(int param_1,int param_2);
int * FUN_00427acc(int *param_1,undefined8 *param_2,int param_3,int param_4);
void FUN_00427b84(void);
undefined4 FUN_00427bbc(undefined4 param_1);
void FUN_00427be4(undefined4 *param_1,undefined4 param_2);
void FUN_00427c1c(undefined4 param_1,undefined4 param_2,undefined4 param_3);
undefined4 FUN_00427c6c(undefined4 param_1);
undefined4 * FUN_00427ca8(undefined4 *param_1,undefined4 param_2);
int * FUN_00427ce0(int *param_1,undefined4 *param_2,int param_3,int param_4);
undefined4 FUN_00427d3c(longdouble param_1,allocator *param_2,allocator *param_3);
void FUN_00427d8c(longdouble param_1,allocator *param_2,allocator *param_3);
void FUN_00428040(void);
void FUN_00428080(void);
void FUN_004280c0(undefined4 param_1,undefined4 param_2);
undefined8 FUN_0042814c(allocator *param_1,char *param_2);
undefined4 FUN_004281b8(void);
undefined4 FUN_004281e8(void);
void FUN_00428218(ulonglong param_1);
void FUN_00428258(void);
int * FUN_00428298(int *param_1,int param_2,int param_3,int param_4);
int * FUN_00428374(int *param_1,logic_error *param_2);
void FUN_00428414(int *param_1);
void FUN_004284a8(int param_1);
void FUN_004284b4(int *param_1);
void FUN_004284c8(int *param_1);
void FUN_00428510(int param_1);
void FUN_0042851c(int *param_1);
void FUN_00428530(int **param_1,int **param_2);
void FUN_00428580(undefined4 *param_1);
void FUN_004285f4(int param_1);
void FUN_00428600(undefined4 *param_1);
void FUN_00428648(int param_1);
void FUN_00428654(int *param_1,int *param_2);
void FUN_004286e0(undefined4 *param_1);
void FUN_00428768(int param_1);
void FUN_00428774(int *param_1);
void FUN_00428788(undefined4 *param_1);
void FUN_004287d0(int param_1);
void FUN_004287dc(int *param_1);
void FUN_004287f0(void);
int * FUN_0042883c(int *param_1,runtime_error *param_2);
void FUN_004288dc(int *param_1);
void FUN_00428970(int param_1);
void FUN_0042897c(int *param_1);
void FUN_00428990(int *param_1);
void FUN_004289d8(int param_1);
void FUN_004289e4(int *param_1);
void FUN_004289f8(undefined4 *param_1);
void FUN_00428a6c(int param_1);
void FUN_00428a78(undefined4 *param_1);
void FUN_00428ac0(int param_1);
void FUN_00428acc(int *param_1,int *param_2);
void FUN_00428b58(undefined4 *param_1);
void FUN_00428be0(int param_1);
void FUN_00428bec(int *param_1);
void FUN_00428c00(undefined4 *param_1);
void FUN_00428c48(int param_1);
void FUN_00428c54(int *param_1);
undefined8 FUN_00428c68(longdouble param_1,allocator *param_2,char *param_3);
void FUN_00428cdc(void);
undefined8 FUN_00428e48(void);
void FUN_00428eb4(double param_1);
undefined8 FUN_00428ef4(undefined4 param_1,char *param_2,undefined8 *param_3);
void FUN_00428f68(longdouble *param_1);
void FUN_00429054(void);
undefined4 FUN_0042909c(undefined4 param_1);
int * FUN_004290c4(int *param_1,undefined4 *param_2,int param_3,int param_4);
int * FUN_00429120(int *param_1,int param_2,int param_3,int param_4);
void FUN_004291f8(void);
void FUN_00429224(undefined4 param_1,int param_2);
void FUN_00429270(undefined4 param_1,uint param_2);
undefined4 FUN_004292f0(undefined4 param_1);
void FUN_00429318(undefined4 param_1,uint param_2);
void FUN_00429398(undefined4 param_1,undefined4 param_2,undefined4 param_3);
int * FUN_004293e0(int *param_1,undefined4 *param_2,int param_3,int param_4);
undefined8 FUN_00429498(longdouble param_1,allocator *param_2,char *param_3);
void FUN_00429510(undefined4 *param_1);
void FUN_00429560(undefined4 *param_1);
void error_handler(longdouble param_1,allocator *param_2,allocator *param_3);
undefined4 FUN_0042985c(longdouble param_1,undefined4 param_2);
void FUN_0042996c(void);
void FUN_00429994(void);
double FUN_004299bc(double param_1,undefined4 param_2,undefined4 param_3,allocator *param_4);
void FUN_00429a94(void);
void FUN_00429ad0(void);
void FUN_00429f5c(allocator *param_1,char *param_2);
bool FUN_0042a144(ulonglong param_1);
void FUN_0042a198(void);
int FUN_0042a1d4(int *param_1,int *param_2);
undefined4 * FUN_0042a214(undefined4 *param_1,logic_error *param_2);
void FUN_0042a258(undefined4 *param_1);
void FUN_0042a290(int *param_1,logic_error *param_2);
void FUN_0042a360(void);
undefined4 * FUN_0042aad8(undefined4 *param_1,runtime_error *param_2);
void FUN_0042ab1c(int *param_1,runtime_error *param_2);
undefined8 FUN_0042abec(longdouble param_1,allocator *param_2,allocator *param_3);
void FUN_0042ac40(double param_1);
undefined8 FUN_0042ac80(void);
void FUN_0042acb4(double param_1);
undefined8 FUN_0042acf0(undefined4 param_1,undefined4 param_2,undefined8 *param_3);
undefined8 FUN_0042ad28(longdouble *param_1);
int * FUN_0042ad70(int *param_1,undefined4 *param_2,int param_3,int param_4);
int FUN_0042ae28(int *param_1,int *param_2);
void FUN_0042ae6c(undefined4 param_1,int param_2,undefined4 *param_3);
undefined4 FUN_0042aec0(void);
undefined4 FUN_0042aeec(void);
void FUN_0042af18(undefined4 param_1,undefined4 param_2,undefined4 param_3);
undefined8 FUN_0042af84(longdouble param_1,allocator *param_2,allocator *param_3);
void FUN_0042afd8(undefined4 *param_1,runtime_error *param_2);
void FUN_0042b034(undefined4 *param_1,runtime_error *param_2);
void FUN_0042b0f0(undefined4 *param_1,runtime_error *param_2);
void FUN_0042b1d8(runtime_error *param_1);
undefined8 FUN_0042b260(double param_1,undefined4 param_2,undefined4 param_3,double *param_4,allocator *param_5);
void FUN_0042b304(undefined4 param_1,undefined4 param_2);
void FUN_0042b344(void);
void FUN_0042b36c(void);
void FUN_0042c480(undefined4 *param_1,logic_error *param_2);
void FUN_0042c4fc(int *param_1,int *param_2,logic_error *param_3);
void FUN_0042c5e0(undefined4 *param_1,runtime_error *param_2);
void FUN_0042c65c(int *param_1,int *param_2,runtime_error *param_3);
bool FUN_0042c740(double param_1);
undefined8 FUN_0042c788(longdouble *param_1);
undefined4 FUN_0042c87c(undefined4 param_1);
undefined4 * FUN_0042c8a4(undefined4 *param_1,int param_2,undefined4 *param_3);
void FUN_0042c920(undefined4 param_1);
void FUN_0042c964(undefined4 param_1,undefined4 param_2,undefined4 param_3);
int * FUN_0042c9e8(int *param_1,runtime_error *param_2);
void FUN_0042ca88(int *param_1);
void FUN_0042cb1c(int param_1);
void FUN_0042cb28(int *param_1);
void FUN_0042cb3c(int *param_1);
void FUN_0042cb84(int param_1);
void FUN_0042cb90(int *param_1);
void FUN_0042cba4(undefined4 *param_1);
void FUN_0042cc18(int param_1);
void FUN_0042cc24(undefined4 *param_1);
void FUN_0042cc6c(int param_1);
void FUN_0042cc78(int *param_1,int *param_2);
void FUN_0042cd04(undefined4 *param_1);
void FUN_0042cd8c(int param_1);
void FUN_0042cd98(int *param_1);
void FUN_0042cdac(undefined4 *param_1);
void FUN_0042cdf4(int param_1);
void FUN_0042ce00(int *param_1);
void FUN_0042ce14(undefined4 param_1,undefined4 param_2);
undefined * FUN_0042ce98(void);
undefined8 FUN_0042cec4(undefined8 param_1);
void FUN_0042cef4(void);
void FUN_0042cf38(void);
void FUN_0042cf7c(void);
undefined4 FUN_0042cfc0(undefined4 *param_1);
undefined4 FUN_0042cfec(undefined4 param_1);
void FUN_0042d014(void *param_1,int param_2,void *param_3);
undefined4 * FUN_0042d064(undefined4 *param_1,runtime_error *param_2);
void FUN_0042d0a8(int *param_1,runtime_error *param_2);
void FUN_0042d178(void);
void FUN_0042d2a0(void);
void FUN_0042d3f0(void);
void FUN_0042d4f0(void);
void * FUN_0042d530(void *param_1,int param_2,void *param_3);
void FUN_0042d5b0(undefined4 *param_1,runtime_error *param_2);
void FUN_0042d62c(int *param_1,int *param_2,runtime_error *param_3);
void FUN_0042d710(void);
int FUN_0042d738(runtime_error *param_1);
void FUN_0042d7f4(int *param_1);
void FUN_0042d808(runtime_error *param_1);
void FUN_0042d880(int *param_1);
int FUN_0042d894(runtime_error *param_1);
void FUN_0042d950(int *param_1);
void FUN_0042d964(runtime_error *param_1);
void FUN_0042d9dc(int *param_1);
int FUN_0042d9f0(logic_error *param_1);
void FUN_0042daac(int *param_1);
void FUN_0042dac0(logic_error *param_1);
void FUN_0042db38(int *param_1);
void FUN_0042db4c(undefined4 *param_1,runtime_error *param_2);
void FUN_0042dc54(undefined4 *param_1,runtime_error *param_2);
void FUN_0042dd5c(undefined4 *param_1,logic_error *param_2);
void FUN_0042de70(undefined4 param_1,undefined4 param_2,undefined4 param_3);
void FUN_0042df20(void);
void _DT_FINI(void);
int open(char *__file,int __oflag,...);
void PyTuple_SetItem(void);
void std::__cxx11::basic_string<>::_M_dispose(void);
void malloc_trim(void);
void rewind(FILE *__stream);
char * strcat(char *__dest,char *__src);
void CrLogClose(void);
size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream);
int tcsetattr(int __fd,int __optional_actions,termios *__termios_p);
void std::__cxx11::basic_string<>::basic_string(void);
void sinl(void);
void __thiscall std::overflow_error::~overflow_error(overflow_error *this);
void expl(void);
void json_object_object_add(void);
void std::__cxx11::basic_string<>::find(char *param_1,uint param_2);
int socket(int __domain,int __type,int __protocol);
void PyDict_GetItemString(void);
void __cxa_pure_virtual(void);
int isatty(int __fd);
void CrLogUnLock(void);
int access(char *__name,int __type);
int pthread_rwlock_init(pthread_rwlock_t *__rwlock,pthread_rwlockattr_t *__attr);
float sqrtf(float __x);
void __thiscall std::__cxx11::basic_string<>::operator+=(basic_string<> *this,basic_string *param_1);
void __thiscall std::overflow_error::overflow_error(overflow_error *this,basic_string *param_1);
FILE * fopen(char *__filename,char *__modes);
void json_object_object_length(void);
void std::__cxx11::basic_string<>::insert(uint param_1,char *param_2);
void GetLogLevel(void);
int select(int __nfds,fd_set *__readfds,fd_set *__writefds,fd_set *__exceptfds,timeval *__timeout);
int pthread_cancel(pthread_t __th);
void __cxa_rethrow(void);
void __thiscall std::__cxx11::basic_string<>::operator+=(basic_string<> *this,char *param_1);
void json_object_to_json_string(void);
void CrLogLock(void);
void PyModule_GetDict(void);
void PyRun_SimpleStringFlags(void);
void __thiscall std::invalid_argument::~invalid_argument(invalid_argument *this);
void __thiscall std::overflow_error::~overflow_error(overflow_error *this);
void __divdi3(void);
int ferror(FILE *__stream);
void __thiscall std::domain_error::domain_error(domain_error *this,basic_string *param_1);
void __thiscall std::ios_base::Init::Init(Init *this);
void PyTuple_New(void);
void blobmsg_format_json_with_cb(void);
size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s);
void json_object_new_double(void);
void * memcpy(void *__dest,void *__src,size_t __n);
ssize_t write(int __fd,void *__buf,size_t __n);
void * malloc(size_t __size);
void std::__throw_bad_alloc(void);
size_t strlen(char *__s);
void __thiscall std::allocator<char>::~allocator(allocator<char> *this);
int usleep(__useconds_t __useconds);
int accept(int __fd,sockaddr *__addr,socklen_t *__addr_len);
int pthread_rwlock_wrlock(pthread_rwlock_t *__rwlock);
void __cxa_throw(void);
void __thiscall std::basic_ostream<>::operator<<(basic_ostream<> *this,longdouble param_1);
void std::__detail::_List_node_base::_M_hook(_List_node_base *param_1);
int sprintf(char *__s,char *__format,...);
void operator.delete(void *param_1);
void uloop_run(void);
basic_ostream * std::operator<<(basic_ostream *param_1,_Setprecision param_2);
void PyObject_CallObject(void);
void __thiscall std::domain_error::~domain_error(domain_error *this);
void __thiscall std::runtime_error::runtime_error(runtime_error *this,basic_string *param_1);
void std::__cxx11::basic_string<>::basic_string(char *param_1,allocator *param_2);
void __thiscall std::runtime_error::~runtime_error(runtime_error *this);
void __cxa_atexit(void);
int tcgetattr(int __fd,termios *__termios_p);
void PyFloat_AsDouble(void);
int strcmp(char *__s1,char *__s2);
void Py_Finalize(void);
void powl(void);
void _Py_Dealloc(void);
int * __errno_location(void);
void __thiscall std::invalid_argument::invalid_argument(invalid_argument *this,basic_string *param_1);
int fclose(FILE *__stream);
ssize_t send(int __fd,void *__buf,size_t __n,int __flags);
void Py_BuildValue(void);
int memcmp(void *__s1,void *__s2,size_t __n);
void std::__cxx11::basic_string<>::size(void);
void ubus_connect(void);
void PyList_New(void);
void PyImport_ImportModule(void);
void ubus_subscribe(void);
void __umoddi3(void);
void PyUnicode_FromString(void);
int fcntl(int __fd,int __cmd,...);
int fseek(FILE *__stream,long __off,int __whence);
void ceill(void);
void json_object_new_int(void);
void std::allocator<char>::allocator(void);
int fputs(char *__s,FILE *__stream);
void json_object_object_get(void);
void std::logic_error::what(void);
void __cxa_free_exception(void);
void std::__cxx11::basic_string<>::_M_local_data(void);
void CrLogWrite(void);
char * strchr(char *__s,int __c);
void __thiscall std::runtime_error::~runtime_error(runtime_error *this);
int pthread_detach(pthread_t __th);
void __libc_start_main(void);
void __thiscall std::domain_error::~domain_error(domain_error *this);
int vsnprintf(char *__s,size_t __maxlen,char *__format,__gnuc_va_list __arg);
void std::__cxx11::basic_string<>::append(basic_string *param_1);
void json_object_get_int(void);
void __thiscall std::runtime_error::runtime_error(runtime_error *this,basic_string *param_1);
__sighandler_t signal(int __sig,__sighandler_t __handler);
int gettimeofday(timeval *__tv,__timezone_ptr_t __tz);
void uloop_init(void);
int cfsetospeed(termios *__termios_p,speed_t __speed);
void __thiscall std::logic_error::logic_error(logic_error *this,logic_error *param_1);
char * strsignal(int __sig);
void json_object_new_array(void);
void std::__cxx11::basic_string<>::_S_copy_chars(char *param_1,char *param_2,char *param_3);
void __thiscall std::runtime_error::runtime_error(runtime_error *this,runtime_error *param_1);
void operator.delete(void *param_1,uint param_2);
void __thiscall std::allocator<char>::~allocator(allocator<char> *this);
int pthread_create(pthread_t *__newthread,pthread_attr_t *__attr,__start_routine *__start_routine,void *__arg);
void json_object_new_string(void);
void std::__cxx11::basic_string<>::_M_set_length(uint param_1);
void free(void *__ptr);
void PyArg_ParseTuple(void);
void PyUnicode_AsUTF8(void);
void __thiscall std::ios_base::Init::~Init(Init *this);
void * operator.new(uint param_1);
void CrLogOpen(void);
void std::__cxx11::basic_stringstream<>::str(void);
void __cxa_begin_catch(void);
int pthread_join(pthread_t __th,void **__thread_return);
void ubus_free(void);
void ubus_lookup_id(void);
void std::__cxx11::basic_string<>::capacity(void);
void json_object_array_add(void);
void std::__cxx11::basic_string<>::_M_data(void);
void logl(void);
void json_object_array_length(void);
void exit(int __status);
void std::__cxx11::basic_stringstream<>::basic_stringstream(_Ios_Openmode param_1);
void json_object_get_string(void);
char * strerror(int __errnum);
uchar * SHA256(uchar *d,size_t n,uchar *md);
void __cxa_end_catch(void);
uchar * MD5(uchar *d,size_t n,uchar *md);
void __thiscall std::__cxx11::basic_string<>::~basic_string(basic_string<> *this);
void ubus_invoke_fd(void);
void json_object_put(void);
void __cxa_allocate_exception(void);
int pthread_rwlock_unlock(pthread_rwlock_t *__rwlock);
void std::__cxx11::basic_string<>::_M_capacity(uint param_1);
void PyErr_Occurred(void);
void json_object_array_get_idx(void);
void uloop_fd_add(void);
void * memset(void *destination,int value,size_t size);
void floorl(void);
pthread_t pthread_self(void);
void std::__cxx11::basic_string<>::reserve(uint param_1);
ssize_t recv(int __fd,void *__buf,size_t __n,int __flags);
void std::__throw_length_error(char *param_1);
void PyList_SetItem(void);
int cfsetispeed(termios *__termios_p,speed_t __speed);
int listen(int __fd,int __n);
void std::__cxx11::basic_string<>::basic_string(basic_string *param_1);
void uloop_done(void);
void std::__cxx11::basic_string<>::replace(uint param_1,uint param_2,char *param_3);
int snprintf(char *__s,size_t __maxlen,char *__format,...);
void std::__cxx11::basic_string<>::_M_create(uint *param_1,uint param_2);
int close(int __fd);
ssize_t read(int __fd,void *__buf,size_t __nbytes);
basic_ostream * std::operator<<(basic_ostream *param_1,basic_string *param_2);
void std::runtime_error::what(void);
void PyCallable_Check(void);
void _Unwind_Resume(void);
void PyArg_Parse(void);
void * memmove(void *__dest,void *__src,size_t __n);
void json_object_get_double(void);
void json_tokener_parse(void);
int unlink(char *__name);
void std::__throw_logic_error(char *param_1);
int tcflush(int __fd,int __queue_selector);
void Py_Initialize(void);
void __thiscall std::__cxx11::basic_string<>::_Alloc_hider::_Alloc_hider(_Alloc_hider *this,char *param_1,allocator *param_2);
void ubus_register_subscriber(void);
void PyErr_Print(void);
char * strcpy(char *__dest,char *__src);
void std::__cxx11::basic_string<>::append(char *param_1,uint param_2);
void PyTuple_GetItem(void);
void json_object_new_object(void);
void Py_IsInitialized(void);
void std::__cxx11::basic_string<>::insert(uint param_1,basic_string *param_2);
void std::__cxx11::basic_string<>::c_str(void);
void std::__cxx11::basic_string<>::append(char *param_1);
void __thiscall std::__cxx11::basic_stringstream<>::~basic_stringstream(basic_stringstream<> *this);
void bzero(void *__s,size_t __n);
void json_object_from_file(void);
void ubus_strerror(void);
void json_object_is_type(void);
void std::__cxx11::basic_string<>::_M_data(char *param_1);
int bind(int __fd,sockaddr *__addr,socklen_t __len);
long ftell(FILE *__stream);
int open(char * __file, int __oflag, ...);
undefined PyTuple_SetItem();
undefined _M_dispose(void);
undefined malloc_trim();
void rewind(FILE * __stream);
char * strcat(char * __dest, char * __src);
undefined CrLogClose();
size_t fread(void * __ptr, size_t __size, size_t __n, FILE * __stream);
int tcsetattr(int __fd, int __optional_actions, termios * __termios_p);
undefined basic_string(void);
undefined sinl();
undefined ~overflow_error(overflow_error * this);
undefined expl();
undefined json_object_object_add();
undefined find(char * param_1, uint param_2);
int socket(int __domain, int __type, int __protocol);
undefined PyDict_GetItemString();
int isatty(int __fd);
undefined CrLogUnLock();
int access(char * __name, int __type);
int pthread_rwlock_init(pthread_rwlock_t * __rwlock, pthread_rwlockattr_t * __attr);
float sqrtf(float __x);
undefined operator+=(basic_string<char,std::char_traits<char>,std::allocator<char>> * this, basic_string * param_1);
undefined overflow_error(overflow_error * this, basic_string * param_1);
FILE * fopen(char * __filename, char * __modes);
undefined json_object_object_length();
undefined insert(uint param_1, char * param_2);
undefined GetLogLevel();
int select(int __nfds, fd_set * __readfds, fd_set * __writefds, fd_set * __exceptfds, timeval * __timeout);
int pthread_cancel(pthread_t __th);
undefined __cxa_rethrow();
undefined operator+=(basic_string<char,std::char_traits<char>,std::allocator<char>> * this, char * param_1);
undefined json_object_to_json_string();
undefined CrLogLock();
undefined PyModule_GetDict();
undefined PyRun_SimpleStringFlags();
undefined ~overflow_error(overflow_error * this);
undefined __divdi3();
int ferror(FILE * __stream);
undefined domain_error(domain_error * this, basic_string * param_1);
undefined Init(Init * this);
undefined PyTuple_New();
undefined blobmsg_format_json_with_cb();
size_t fwrite(void * __ptr, size_t __size, size_t __n, FILE * __s);
undefined json_object_new_double();
void * memcpy(void * __dest, void * __src, size_t __n);
ssize_t write(int __fd, void * __buf, size_t __n);
void * malloc(size_t __size);
undefined __throw_bad_alloc(void);
size_t strlen(char * __s);
undefined ~allocator(allocator<char> * this);
int usleep(__useconds_t __useconds);
int accept(int __fd, sockaddr * __addr, socklen_t * __addr_len);
int pthread_rwlock_wrlock(pthread_rwlock_t * __rwlock);
undefined __cxa_throw();
undefined operator<<(basic_ostream<char,std::char_traits<char>> * this, longdouble param_1);
undefined _M_hook(_List_node_base * param_1);
int sprintf(char * __s, char * __format, ...);
void operator.delete(void * param_1);
undefined uloop_run();
basic_ostream * operator<<(basic_ostream * param_1, _Setprecision param_2);
undefined PyObject_CallObject();
undefined ~domain_error(domain_error * this);
undefined runtime_error(runtime_error * this, basic_string * param_1);
undefined basic_string(char * param_1, allocator * param_2);
undefined ~runtime_error(runtime_error * this);
undefined __cxa_atexit();
int tcgetattr(int __fd, termios * __termios_p);
undefined PyFloat_AsDouble();
int strcmp(char * __s1, char * __s2);
undefined Py_Finalize();
undefined powl();
undefined _Py_Dealloc();
int * __errno_location(void);
undefined invalid_argument(invalid_argument * this, basic_string * param_1);
int fclose(FILE * __stream);
ssize_t send(int __fd, void * __buf, size_t __n, int __flags);
undefined Py_BuildValue();
int memcmp(void * __s1, void * __s2, size_t __n);
undefined size(void);
undefined ubus_connect();
undefined PyList_New();
undefined PyImport_ImportModule();
undefined ubus_subscribe();
undefined __umoddi3();
undefined PyUnicode_FromString();
int fcntl(int __fd, int __cmd, ...);
int fseek(FILE * __stream, long __off, int __whence);
undefined ceill();
undefined json_object_new_int();
undefined allocator(void);
int fputs(char * __s, FILE * __stream);
undefined json_object_object_get();
undefined __cxa_free_exception();
undefined _M_local_data(void);
undefined CrLogWrite();
char * strchr(char * __s, int __c);
int pthread_detach(pthread_t __th);
undefined ~domain_error(domain_error * this);
undefined append(basic_string * param_1);
undefined json_object_get_int();
undefined runtime_error(runtime_error * this, basic_string * param_1);
__sighandler_t signal(int __sig, __sighandler_t __handler);
int gettimeofday(timeval * __tv, __timezone_ptr_t __tz);
undefined uloop_init();
int cfsetospeed(termios * __termios_p, speed_t __speed);
undefined logic_error(logic_error * this, logic_error * param_1);
char * strsignal(int __sig);
undefined json_object_new_array();
undefined _S_copy_chars(char * param_1, char * param_2, char * param_3);
undefined runtime_error(runtime_error * this, runtime_error * param_1);
undefined __cxa_guard_acquire();
void operator.delete(void * param_1, uint param_2);
undefined ~allocator(allocator<char> * this);
int pthread_create(pthread_t * __newthread, pthread_attr_t * __attr, __start_routine * __start_routine, void * __arg);
undefined json_object_new_string();
undefined _M_set_length(uint param_1);
void free(void * __ptr);
undefined PyArg_ParseTuple();
undefined PyUnicode_AsUTF8();
void * operator.new(uint param_1);
undefined CrLogOpen();
undefined str(void);
undefined __cxa_begin_catch();
int pthread_join(pthread_t __th, void * * __thread_return);
undefined ubus_free();
undefined ubus_lookup_id();
undefined capacity(void);
undefined json_object_array_add();
undefined _M_data(void);
undefined logl();
undefined json_object_array_length();
void exit(int __status);
undefined basic_stringstream(_Ios_Openmode param_1);
undefined json_object_get_string();
char * strerror(int __errnum);
uchar * SHA256(uchar * d, size_t n, uchar * md);
undefined __cxa_end_catch();
uchar * MD5(uchar * d, size_t n, uchar * md);
undefined ~basic_string(basic_string<char,std::char_traits<char>,std::allocator<char>> * this);
undefined __cxa_guard_release();
undefined ubus_invoke_fd();
undefined json_object_put();
undefined __cxa_allocate_exception();
int pthread_rwlock_unlock(pthread_rwlock_t * __rwlock);
undefined _M_capacity(uint param_1);
undefined PyErr_Occurred();
undefined json_object_array_get_idx();
undefined uloop_fd_add();
void * memset(void * destination, int value, size_t size);
undefined floorl();
pthread_t pthread_self(void);
undefined reserve(uint param_1);
ssize_t recv(int __fd, void * __buf, size_t __n, int __flags);
undefined __throw_length_error(char * param_1);
undefined PyList_SetItem();
int cfsetispeed(termios * __termios_p, speed_t __speed);
int listen(int __fd, int __n);
undefined basic_string(basic_string * param_1);
undefined uloop_done();
undefined replace(uint param_1, uint param_2, char * param_3);
int snprintf(char * __s, size_t __maxlen, char * __format, ...);
undefined _M_create(uint * param_1, uint param_2);
int close(int __fd);
ssize_t read(int __fd, void * __buf, size_t __nbytes);
basic_ostream * operator<<(basic_ostream * param_1, basic_string * param_2);
undefined PyCallable_Check();
undefined _Unwind_Resume();
undefined PyArg_Parse();
void * memmove(void * __dest, void * __src, size_t __n);
undefined json_object_get_double();
undefined json_tokener_parse();
int unlink(char * __name);
undefined __throw_logic_error(char * param_1);
int tcflush(int __fd, int __queue_selector);
undefined Py_Initialize();
undefined _Alloc_hider(_Alloc_hider * this, char * param_1, allocator * param_2);
undefined ubus_register_subscriber();
undefined PyErr_Print();
char * strcpy(char * __dest, char * __src);
undefined append(char * param_1, uint param_2);
undefined PyTuple_GetItem();
undefined json_object_new_object();
void __assert_fail(char * __assertion, char * __file, uint __line, char * __function);
undefined Py_IsInitialized();
undefined insert(uint param_1, basic_string * param_2);
undefined c_str(void);
undefined append(char * param_1);
undefined ~basic_stringstream(basic_stringstream<char,std::char_traits<char>,std::allocator<char>> * this);
void bzero(void * __s, size_t __n);
undefined json_object_from_file();
undefined ubus_strerror();
undefined json_object_is_type();
undefined _M_data(char * param_1);
int bind(int __fd, sockaddr * __addr, socklen_t __len);
long ftell(FILE * __stream);
undefined __gmon_start__();
undefined __gxx_personality_v0();

