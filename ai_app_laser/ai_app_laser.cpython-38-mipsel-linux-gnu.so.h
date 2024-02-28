typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
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

typedef ulong size_t;

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

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
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
int processEntry entry(void);
undefined4 FUN_0001c690(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5);
int FUN_0001c99c(undefined4 param_1,int param_2);
undefined4 FUN_0001caa4(undefined4 param_1);
undefined4 FUN_0001cf40(undefined4 param_1);
int * FUN_00026548(int param_1,uint param_2,uint param_3);
void PyInit_ai_app_laser(void);
void FUN_00026630(void);
void FUN_00026668(void);
void FUN_000266b4(void);
void FUN_00026794(void);
void FUN_000267b0(int *param_1);
void FUN_00026840(int param_1);
void FUN_00026880(void);
void FUN_000268a0(int param_1);
int FUN_000268cc(int param_1,int param_2,int param_3);
bool FUN_0002696c(undefined *param_1,undefined *param_2);
void FUN_000269ec(int param_1);
void FUN_00026a54(int param_1);
void FUN_00026a80(int param_1);
void FUN_00026ae8(int param_1);
void FUN_00026b4c(undefined4 param_1);
void FUN_00026b74(undefined4 param_1,int param_2,int param_3,int param_4,int param_5);
void FUN_00026c2c(undefined4 param_1);
void FUN_00026e34(undefined4 param_1);
void FUN_00026e5c(int param_1);
int * FUN_00026ea4(int param_1,undefined4 param_2);
int FUN_00026f5c(int param_1,undefined4 param_2);
int FUN_000270b8(int param_1,undefined4 param_2,undefined4 param_3);
void FUN_00027234(int param_1);
int FUN_00027264(undefined4 *param_1);
undefined4 FUN_00027300(int param_1,int *param_2);
undefined4 FUN_0002735c(int param_1,int *param_2);
void FUN_000273bc(undefined *param_1);
undefined4 * FUN_00027404(undefined4 *param_1,int *param_2);
uint FUN_00027490(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4);
int * FUN_000274e8(int *param_1,int param_2);
void FUN_00027518(int param_1);
int FUN_00027624(int param_1,code *UNRECOVERED_JUMPTABLE,undefined4 param_3);
int FUN_00027c14(int param_1,code *UNRECOVERED_JUMPTABLE,undefined4 param_3);
int FUN_00027c94(int param_1,code *UNRECOVERED_JUMPTABLE,undefined4 param_3);
int FUN_00027d14(int param_1,code *UNRECOVERED_JUMPTABLE,undefined4 param_3);
int FUN_00027d94(int param_1,code *UNRECOVERED_JUMPTABLE,undefined4 param_3);
void FUN_00027e38(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4);
void FUN_000281f4(void);
void FUN_000282f0(int param_1,int param_2,uint param_3);
int FUN_00028394(undefined4 param_1);
int * FUN_00028414(int param_1,undefined4 *param_2,int **param_3);
undefined4 FUN_000284fc(int param_1,int param_2);
undefined4 FUN_00028644(int param_1,int param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_00028684(int param_1,int param_2,undefined4 param_3,undefined4 param_4);
void FUN_00028754(int param_1,undefined4 param_2,uint param_3,int param_4);
void FUN_00028928(int param_1,undefined4 param_2,int param_3,int param_4);
void FUN_00028b98(int param_1);
void * FUN_00028c6c(int param_1);
void * FUN_00028d34(int param_1);
void * FUN_00028dfc(int param_1);
void * FUN_00028ec4(int param_1);
void * FUN_00028f8c(int param_1);
void * FUN_00029054(int param_1);
void * FUN_0002911c(int param_1);
void * FUN_000291e4(int param_1);
void * FUN_000292ac(int param_1);
void * FUN_00029374(int param_1);
void * FUN_0002943c(int param_1);
void FUN_00029504(int param_1);
void FUN_00029568(int *param_1);
undefined8 FUN_00029598(int param_1);
undefined4 FUN_00029700(undefined4 param_1,int **param_2,int param_3,undefined4 param_4);
undefined4 FUN_000298e4(int param_1);
int * FUN_00029964(int param_1);
void FUN_0002a69c(int param_1);
undefined4 FUN_0002a6c4(int param_1,undefined4 *param_2,undefined4 *param_3,int *param_4);
void FUN_0002a838(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_0002a8b8(int param_1,int *param_2);
undefined4 FUN_0002a90c(int param_1);
undefined4 FUN_0002a9b0(int param_1);
undefined4 FUN_0002aa38(int param_1);
undefined4 FUN_0002aac0(int param_1);
undefined4 FUN_0002ab48(int param_1);
undefined4 FUN_0002acb0(int param_1);
undefined4 FUN_0002ad00(int param_1);
undefined4 FUN_0002af9c(int param_1);
undefined4 FUN_0002afec(int param_1);
undefined4 FUN_0002b03c(int param_1);
undefined4 FUN_0002b0c4(int param_1);
undefined4 FUN_0002b31c(void);
undefined4 FUN_0002b3f8(int param_1,undefined4 param_2);
void FUN_0002b468(int param_1,int param_2,int *param_3,undefined4 param_4);
uint FUN_0002b9bc(int param_1);
undefined4 FUN_0002bab8(int param_1,undefined *param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_0002bc08(int param_1);
int * FUN_0002be8c(undefined4 param_1,int param_2);
uint FUN_0002c168(undefined *param_1,undefined *param_2,uint param_3);
void FUN_0002c390(void);
void FUN_0002c400(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_0002c480(undefined4 param_1,undefined *param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_0002c7d4(int param_1,undefined4 param_2,undefined4 param_3,undefined4 *param_4,undefined4 *param_5,undefined4 *param_6,int param_7,int param_8);
int FUN_0002c9a4(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
int FUN_0002ca98(undefined *param_1,int param_2);
undefined * FUN_0002cbd4(int param_1);
int FUN_0002cf04(int param_1,int *param_2,int *param_3,int *param_4,int param_5);
undefined4 FUN_0002d450(int *param_1,int *param_2,undefined4 param_3,undefined4 param_4);
void FUN_0002d630(undefined4 param_1,int param_2,uint param_3);
void FUN_0002d904(int param_1);
int FUN_0002da68(undefined4 param_1,int *param_2,undefined4 param_3,undefined4 param_4,int *param_5,undefined4 param_6);
undefined4 FUN_0002db94(undefined4 param_1,int **param_2,int param_3,int param_4,undefined4 param_5);
int * FUN_0002dddc(int param_1,uint param_2,int param_3);
undefined4 FUN_0002df90(int param_1,int param_2);
undefined4 FUN_0002e0d8(int param_1,int param_2,int param_3);
undefined4 FUN_0002e2dc(int *param_1,int *param_2,int *param_3,undefined4 param_4);
int FUN_0002e42c(int param_1,int *param_2,undefined4 param_3,undefined4 param_4);
undefined4 FUN_0002e558(int param_1,int param_2,undefined4 param_3);
void FUN_0002f46c(int param_1);
int FUN_0002f520(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6);
int FUN_0002f618(int param_1,undefined4 param_2,int **param_3);
int FUN_0003077c(int param_1,undefined4 param_2,int **param_3);
int FUN_00036e4c(undefined4 param_1,undefined4 param_2);
int * FUN_00036ed0(undefined4 param_1,int param_2,int param_3);
int FUN_0003d3b4(undefined4 param_1,undefined4 param_2);
int * FUN_0024407c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
int FUN_0027148c(int param_1,undefined *param_2,uint param_3);
undefined4 FUN_0027602c(int param_1);
void FUN_00276198(int param_1);
undefined * FUN_00276254(int param_1,undefined4 param_2,int param_3);
int ** FUN_00276b98(undefined4 param_1,undefined4 param_2,undefined4 param_3);
int * FUN_0027e9e0(undefined4 param_1,int param_2,int param_3);
void FUN_00296370(void);
void PyUnicode_FromFormat(void);
void PyNumber_Negative(void);
void PyObject_SetItem(void);
void PyList_New(void);
void _PyUnicode_Ready(void);
void PyDict_SetItemString(void);
void PyDict_Size(void);
void PyException_SetTraceback(void);
void PyObject_Format(void);
void PyObject_ClearWeakRefs(void);
void _PyThreadState_UncheckedGet(void);
void PyModuleDef_Init(void);
void PyLong_FromDouble(void);
void PyFrame_New(void);
void * memmove(void *__dest,void *__src,size_t __n);
void PyObject_GetAttrString(void);
void * memcpy(void *__dest,void *__src,size_t __n);
void PyImport_AddModule(void);
void PyBytes_FromStringAndSize(void);
void PyObject_SetAttrString(void);
void PyNumber_Float(void);
void PyErr_WarnEx(void);
void _Py_Dealloc(void);
void PyModule_NewObject(void);
void PyErr_SetObject(void);
void PyObject_GC_Del(void);
void PyErr_NormalizeException(void);
void _PyObject_CallFunction_SizeT(void);
void PyNumber_Absolute(void);
int memcmp(void *__s1,void *__s2,size_t __n);
void PyNumber_Multiply(void);
void PyObject_RichCompare(void);
void PyCode_New(void);
void _PyGen_Send(void);
void PyImport_GetModuleDict(void);
void PyObject_GC_Track(void);
void PyNumber_Long(void);
void PyErr_GivenExceptionMatches(void);
void PyErr_SetString(void);
void PyObject_DelItem(void);
void PyMethod_New(void);
void _PyObject_GC_New(void);
void PyObject_GetItem(void);
void PyInterpreterState_GetID(void);
void PyEval_EvalFrameEx(void);
void PySequence_Contains(void);
void PyTuple_GetItem(void);
void _PyLong_Copy(void);
void PyMem_Realloc(void);
void PyErr_SetNone(void);
void PyErr_ExceptionMatches(void);
void PyOS_snprintf(void);
void PyTraceBack_Here(void);
void PyObject_CallFinalizerFromDealloc(void);
void PyObject_Not(void);
void PyObject_Free(void);
void PyLong_FromSsize_t(void);
void PyFloat_FromDouble(void);
void PyType_Ready(void);
void PyLong_FromLong(void);
void PyLong_AsSsize_t(void);
void PyErr_Clear(void);
void PyList_Append(void);
void _Py_CheckRecursiveCall(void);
void _PyUnicode_FastCopyCharacters(void);
void PyNumber_And(void);
void PyTuple_New(void);
void PyThreadState_Get(void);
void PyArg_UnpackTuple(void);
void PyObject_SetAttr(void);
void PyErr_Occurred(void);
void PyImport_ImportModule(void);
void _PyDict_GetItem_KnownHash(void);
void PyObject_CallObject(void);
void PyTuple_GetSlice(void);
void PyRun_StringFlags(void);
void PyObject_CallFunctionObjArgs(void);
void PyDict_GetItemString(void);
void PyEval_EvalCodeEx(void);
void PyList_Sort(void);
void PyObject_Size(void);
void * memset(void *__s,int __c,size_t __n);
void PyObject_IsTrue(void);
void _PyType_Lookup(void);
void PyImport_ImportModuleLevelObject(void);
void PyObject_Hash(void);
void PyUnicode_Compare(void);
void PyLong_AsDouble(void);
void _PyTraceMalloc_NewReference(void);
void PyDict_New(void);
void PyDict_Next(void);
void PyUnicode_AsUTF8(void);
void _PyObject_GetDictPtr(void);
void PyUnicode_FromString(void);
void PyType_GetFlags(void);
void PyObject_GetIter(void);
void PyUnicode_InternFromString(void);
void PyDict_SetItem(void);
void PyObject_IsSubclass(void);
void PySequence_List(void);
void PyObject_Call(void);
void PyType_IsSubtype(void);
void PyUnicode_Decode(void);
void PyErr_Format(void);
void PySlice_New(void);
void PyUnicode_FromStringAndSize(void);
void PyModule_GetDict(void);
void PyLong_FromLongLong(void);
void PyUnicode_FromOrdinal(void);
void PyUnicode_Concat(void);
void PyNumber_Index(void);
void PyObject_GetAttr(void);
void PyMem_Malloc(void);
void PyUnicode_New(void);
void PyTuple_Pack(void);
void PyNumber_Power(void);
void Py_GetVersion(void);
void PyCode_NewEmpty(void);
void PyNumber_TrueDivide(void);
void PyObject_GC_UnTrack(void);
void PyErr_WriteUnraisable(void);
void PyDict_GetItemWithError(void);
void PyFloat_FromString(void);
void _DT_FINI(void);
undefined PyNumber_Subtract();
undefined _ITM_registerTMCloneTable();
undefined __gmon_start__();
undefined PyNumber_Add();
undefined PyNumber_InPlaceAdd();
undefined _ITM_deregisterTMCloneTable();
undefined __cxa_finalize();

