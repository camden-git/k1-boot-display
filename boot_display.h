typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
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

typedef struct timeval timeval, *Ptimeval;

typedef long __time_t;

typedef long __suseconds_t;

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

typedef union _union_1051 _union_1051, *P_union_1051;

typedef struct siginfo siginfo, *Psiginfo;

typedef struct siginfo siginfo_t;

typedef void (*__sighandler_t)(int);

typedef union _union_1031 _union_1031, *P_union_1031;

typedef struct _struct_1032 _struct_1032, *P_struct_1032;

typedef struct _struct_1033 _struct_1033, *P_struct_1033;

typedef struct _struct_1034 _struct_1034, *P_struct_1034;

typedef struct _struct_1035 _struct_1035, *P_struct_1035;

typedef struct _struct_1036 _struct_1036, *P_struct_1036;

typedef struct _struct_1037 _struct_1037, *P_struct_1037;

typedef int __pid_t;

typedef uint __uid_t;

typedef union sigval sigval, *Psigval;

typedef union sigval sigval_t;

typedef long __clock_t;

struct _struct_1032 {
    __pid_t si_pid;
    __uid_t si_uid;
};

union sigval {
    int sival_int;
    void *sival_ptr;
};

struct _struct_1034 {
    __pid_t si_pid;
    __uid_t si_uid;
    sigval_t si_sigval;
};

struct _struct_1035 {
    __pid_t si_pid;
    __uid_t si_uid;
    int si_status;
    __clock_t si_utime;
    __clock_t si_stime;
};

struct _struct_1037 {
    long si_band;
    int si_fd;
};

struct _struct_1033 {
    int si_tid;
    int si_overrun;
    sigval_t si_sigval;
};

struct _struct_1036 {
    void *si_addr;
};

union _union_1031 {
    int _pad[29];
    struct _struct_1032 _kill;
    struct _struct_1033 _timer;
    struct _struct_1034 _rt;
    struct _struct_1035 _sigchld;
    struct _struct_1036 _sigfault;
    struct _struct_1037 _sigpoll;
};

union _union_1051 {
    __sighandler_t sa_handler;
    void (*sa_sigaction)(int, siginfo_t *, void *);
};

struct siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    union _union_1031 _sifields;
};

typedef struct sigaction sigaction, *Psigaction;

typedef struct __sigset_t __sigset_t, *P__sigset_t;

struct __sigset_t {
    ulong __val[32];
};

struct sigaction {
    union _union_1051 __sigaction_handler;
    struct __sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};

typedef struct _IO_FILE FILE;

typedef ulonglong __u_quad_t;

typedef uint __useconds_t;

typedef __u_quad_t __ino64_t;

typedef ulong __ino_t;

typedef struct dirent dirent, *Pdirent;

struct dirent {
    __ino_t d_ino;
    __off_t d_off;
    ushort d_reclen;
    uchar d_type;
    char d_name[256];
};

typedef struct dirent64 dirent64, *Pdirent64;

struct dirent64 {
    __ino64_t d_ino;
    __off64_t d_off;
    ushort d_reclen;
    uchar d_type;
    char d_name[256];
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

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

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
    dword namesz; /* Length of name field */
    dword descsz; /* Length of description field */
    dword type; /* Vendor specific type */
    char name[4]; /* Vendor name */
    dword abiType; /* 0 == Linux */
    dword requiredKernelVersion[3]; /* Major.minor.patch */
};

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; /* location to apply the relocation action */
    dword r_info; /* the symbol table index and the type of relocation */
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
undefined4 _ftext(int param_1,int param_2);
void processEntry entry(undefined4 param_1,undefined4 param_2);
void performInitialization(void);
void compilerTempThing1(void);
void initializeIfNeeded(void);
void compilerTempThing1(void);
void cleanupResources(void);
void shutdownBootDisplay(void);
void processImageData(void);
void executeStoredFunctions(void);
void _DT_FINI(void);
int strcmp(char *__s1,char *__s2);
void rmem_alloc(void);
void fb_pan_display(void);
int fflush(FILE *__stream);
FILE * fopen(char *__filename,char *__modes);
void fb_close(void);
void free(void *__ptr);
char * strdup(char *__s);
void * memcpy(void *__dest,void *__src,size_t __n);
char * fgets(char *__s,int __n,FILE *__stream);
void fb_enable(void);
__sighandler_t signal(int __sig,__sighandler_t __handler);
int gettimeofday(timeval *__tv,__timezone_ptr_t __tz);
void uloop_timeout_add(void);
int fseek(FILE *__stream,long __off,int __whence);
void uloop_timeout_set(void);
int usleep(__useconds_t __useconds);
size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream);
__pid_t getpid(void);
void * malloc(size_t __size);
int system(char *__command);
void rmem_open(void);
void exit(int __status);
void fb_pan_display_enable_user_cfg(void);
int kill(__pid_t __pid,int __sig);
void rmem_close(void);
void v4l2_jpeg_decoder_open(void);
void __libc_start_main(void);
int fprintf(FILE *__stream,char *__format,...);
long ftell(FILE *__stream);
void __isoc99_sscanf(void);
void * memset(void *__s,int __c,size_t __n);
int snprintf(char *__s,size_t __maxlen,char *__format,...);
void uloop_init(void);
int scandir(char *__dir,dirent ***__namelist,__selector *__selector,__cmp *__cmp);
int access(char *__name,int __type);
void uloop_process_add(void);
void fb_pan_display_set_user_cfg(void);
__pid_t fork(void);
void uloop_run(void);
int fclose(FILE *__stream);
int alphasort(dirent **__e1,dirent **__e2);
void fb_disable(void);
void rmem_free(void);
int sigaction(int __sig,sigaction *__act,sigaction *__oact);
void uloop_done(void);
void v4l2_jpeg_decoder_close(void);
void v4l2_jpeg_decoder_work(void);
int fputs(char *__s,FILE *__stream);
void fb_open(void);
void sync(void);
int strcmp(char * __s1, char * __s2);
undefined rmem_alloc();
undefined fb_pan_display();
int fflush(FILE * __stream);
FILE * fopen(char * __filename, char * __modes);
undefined fb_close();
void free(void * __ptr);
char * strdup(char * __s);
void * memcpy(void * __dest, void * __src, size_t __n);
char * fgets(char * __s, int __n, FILE * __stream);
undefined fb_enable();
__sighandler_t signal(int __sig, __sighandler_t __handler);
int gettimeofday(timeval * __tv, __timezone_ptr_t __tz);
undefined uloop_timeout_add();
int fseek(FILE * __stream, long __off, int __whence);
undefined uloop_timeout_set();
int usleep(__useconds_t __useconds);
size_t fread(void * __ptr, size_t __size, size_t __n, FILE * __stream);
__pid_t getpid(void);
void * malloc(size_t __size);
int system(char * __command);
undefined rmem_open();
void exit(int __status);
undefined fb_pan_display_enable_user_cfg();
int kill(__pid_t __pid, int __sig);
undefined rmem_close();
undefined v4l2_jpeg_decoder_open();
int fprintf(FILE * __stream, char * __format, ...);
long ftell(FILE * __stream);
undefined __isoc99_sscanf();
void * memset(void * __s, int __c, size_t __n);
int snprintf(char * __s, size_t __maxlen, char * __format, ...);
undefined uloop_init();
int scandir(char * __dir, dirent * * * __namelist, __selector * __selector, __cmp * __cmp);
int access(char * __name, int __type);
undefined uloop_process_add();
undefined fb_pan_display_set_user_cfg();
__pid_t fork(void);
undefined uloop_run();
int fclose(FILE * __stream);
undefined fb_disable();
undefined rmem_free();
int sigaction(int __sig, sigaction * __act, sigaction * __oact);
undefined uloop_done();
undefined v4l2_jpeg_decoder_close();
undefined v4l2_jpeg_decoder_work();
int fputs(char * __s, FILE * __stream);
undefined fb_open();
void sync(void);
undefined __gmon_start__();

