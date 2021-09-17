import os
from ctypes import *

# path to libelf library
PATH_TO_LIB = os.path.dirname(os.path.abspath(__file__)) + "/libelf.so.1"
# page size to align segment ranges
PAGESIZE = 0x1000
# alignment for PHDR table in file (32bit version)
PHDR32ALIGN = 8
# alignment for PHDR table in file (64bit version)
PHDR64ALIGN = 8
# alignment for SHDR table in file (32bit version)
SHDR32ALIGN = 8
# alignment for SHDR table in file (64bit version)
SHDR64ALIGN = 8

# define a type that is a pointer to the Elf structure used by libelf
Elf_p = c_void_p
# define a type for the Elf_cmd enumeration type used by libelf
Elf_cmd = c_int
# define a type that is a pointer to the Elf section structure used by libelf
Elf_Scn_p = c_void_p
# define a type for the off_t type used by libelf
off_t = c_uint64

# size of an Elf32 EHDR
SIZEOF_ELF32_EHDR = 56
# size of an Elf64 EHDR
SIZEOF_ELF64_EHDR = 64
# size of an Elf32 PHDR
SIZEOF_ELF32_PHDR = 32
# size of an Elf64 PHDR
SIZEOF_ELF64_PHDR = 56


# (Macro-)Constants from libelf
EI_NIDENT = 16
EI_DATA = 5
EI_OSABI = 7
EI_ABIVERSION = 8
EV_NONE = c_uint(0)
EV_CURRENT = c_uint(1)
ELF_C_READ = c_int(5)
ELF_C_SET = c_int(6)
ELF_C_WRITE = c_int(7)
ELF_F_LAYOUT = c_uint(1)
ELF_T_BYTE = c_int(1)
ELFCLASSNONE = c_int(0)
ELFCLASS32 = c_int(1)
SHT_NOBITS = c_int(8)
PT_LOAD = c_uint32(1)
PT_PHDR = c_uint32(6)
PF_R = 0x4
PF_X = 0x1


# /* 64 bit EHDR. */
class GElf_Ehdr(Structure):
    _fields_ = [("e_ident", c_ubyte * EI_NIDENT),    # unsigned char   e_ident[EI_NIDENT]; /* ELF identification. */
                ("e_type", c_uint16),                # Elf64_Half      e_type;             /* Object file type (ET_*). */
                ("e_machine", c_uint16),             # Elf64_Half      e_machine;          /* Machine type (EM_*). */
                ("e_version", c_uint32),             # Elf64_Word      e_version;          /* File format version (EV_*). */
                ("e_entry", c_uint64),               # Elf64_Addr      e_entry;            /* Start address. */
                ("e_phoff", c_uint64),               # Elf64_Off       e_phoff;            /* File offset to the PHDR table. */
                ("e_shoff", c_uint64),               # Elf64_Off       e_shoff;            /* File offset to the SHDR table. */
                ("e_flags", c_uint32),               # Elf64_Word      e_flags;            /* Flags (EF_*). */
                ("e_ehsize", c_uint16),              # Elf64_Half      e_ehsize;           /* Elf header size in bytes. */
                ("e_phentsize", c_uint16),           # Elf64_Half      e_phentsize;        /* PHDR table entry size in bytes. */
                ("e_phnum", c_uint16),               # Elf64_Half      e_phnum;            /* Number of PHDR entries. */
                ("e_shentsize", c_uint16),           # Elf64_Half      e_shentsize;        /* SHDR table entry size in bytes. */
                ("e_shnum", c_uint16),               # Elf64_Half      e_shnum;            /* Number of SHDR entries. */
                ("e_shstrndx", c_uint16),            # Elf64_Half      e_shstrndx;         /* Index of section name string table. */
                ]


# /* 64 bit SHDR */
class GElf_Shdr(Structure):
    _fields_ = [("sh_name", c_uint32),          # Elf64_Word    sh_name;      /* index of section name */
                ("sh_type", c_uint32),          # Elf64_Word    sh_type;      /* section type */
                ("sh_flags", c_uint64),         # Elf64_Xword   sh_flags;     /* section flags */
                ("sh_addr", c_uint64),          # Elf64_Addr    sh_addr;      /* in-memory address of section */
                ("sh_offset", c_uint64),        # Elf64_Off     sh_offset;    /* file offset of section */
                ("sh_size", c_uint64),          # Elf64_Xword   sh_size;      /* section size in bytes */
                ("sh_link", c_uint32),          # Elf64_Word    sh_link;      /* section header table link */
                ("sh_info", c_uint32),          # Elf64_Word    sh_info;      /* extra information */
                ("sh_addralign", c_uint64),     # Elf64_Xword   sh_addralign; /* alignment constraint */
                ("sh_entsize", c_uint64),       # Elf64_Xword   sh_entsize;   /* size for fixed-size entries */
                ]


# /* 64 bit PHDR entry. */
class GElf_Phdr(Structure):
    _fields_ = [("p_type", c_uint32),           # Elf64_Word    p_type;      /* Type of segment. */
                ("p_flags", c_uint32),          # Elf64_Word    p_flags;     /* Segment flags. */
                ("p_offset", c_uint64),         # Elf64_Off     p_offset;    /* File offset to segment. */
                ("p_vaddr", c_uint64),          # Elf64_Addr    p_vaddr;     /* Virtual address in memory. */
                ("p_paddr", c_uint64),          # Elf64_Addr    p_paddr;     /* Physical address (if relevant). */
                ("p_filesz", c_uint64),         # Elf64_Xword   p_filesz;    /* Size of segment in file. */
                ("p_memsz", c_uint64),          # Elf64_Xword   p_memsz;     /* Size of segment in memory. */
                ("p_align", c_uint64),          # Elf64_Xword   p_align;     /* Alignment constraints. */
                ]


class Elf_Data(Structure):
    _fields_ = [("d_align", c_uint64), ("d_buf", POINTER(c_char)), ("d_off", c_uint64), ("d_size", c_uint64),
                ("d_type", c_int), ("d_version", c_uint)]


# load libelf
libelf = cdll.LoadLibrary(PATH_TO_LIB)
# prototypes of used libelf functions
libelf.elf_version.argtypes = [c_uint]
libelf.elf_version.restype = c_uint
libelf.elf_errmsg.argtypes = [c_int]
libelf.elf_errmsg.restype = c_char_p
libelf.elf_flagelf.argtypes = [Elf_p, Elf_cmd, c_uint]
libelf.elf_flagelf.restype = c_uint
libelf.elf_fill.argtype = [c_int]
libelf.elf_fill.restype = None
libelf.elf_update.argtypes = [Elf_p, Elf_cmd]
libelf.elf_update.restype = off_t
libelf.elf_begin.argtypes = [c_int, Elf_cmd, Elf_p]
libelf.elf_begin.restype = Elf_p
libelf.elf_end.argtypes = [Elf_p]
libelf.elf_end.restype = c_int
libelf.elf_newscn.argtypes = [Elf_p]
libelf.elf_newscn.restype = Elf_Scn_p
libelf.elf_getscn.argtypes = [Elf_p, c_size_t]
libelf.elf_getscn.restype = Elf_Scn_p
libelf.elf_newdata.argtypes = [Elf_Scn_p]
libelf.elf_newdata.restype = POINTER(Elf_Data)
libelf.elf_getdata.argtypes = [Elf_Scn_p, POINTER(Elf_Data)]
libelf.elf_getdata.restype = POINTER(Elf_Data)
libelf.elf_getphdrnum.argtypes = [Elf_p, POINTER(c_size_t)]
libelf.elf_getphdrnum.restype = c_int
libelf.elf_getshdrnum.argtypes = [Elf_p, POINTER(c_size_t)]
libelf.elf_getshdrnum.restype = c_int
libelf.gelf_getclass.argtypes = [Elf_p]
libelf.gelf_getclass.restype = c_int
libelf.gelf_newehdr.argtypes = [Elf_p, c_int]
libelf.gelf_newehdr.restype = POINTER(GElf_Ehdr)
libelf.gelf_getehdr.argtypes = [Elf_p, POINTER(GElf_Ehdr)]
libelf.gelf_getehdr.restype = POINTER(GElf_Ehdr)
libelf.gelf_update_ehdr.argtypes = [Elf_p, POINTER(GElf_Ehdr)]
libelf.gelf_update_ehdr.restype = c_int
libelf.gelf_getshdr.argtypes = [Elf_Scn_p, POINTER(GElf_Shdr)]
libelf.gelf_getshdr.restype = POINTER(GElf_Shdr)
libelf.gelf_update_shdr.argtypes = [Elf_Scn_p, POINTER(GElf_Shdr)]
libelf.gelf_update_shdr.restype = c_int
libelf.gelf_newphdr.argtypes = [Elf_p, c_size_t]
libelf.gelf_newphdr.restype = POINTER(GElf_Phdr)
libelf.gelf_getphdr.argtypes = [Elf_p, c_int, POINTER(GElf_Phdr)]
libelf.gelf_getphdr.restype = POINTER(GElf_Phdr)
libelf.elf_strptr.argtypes = [Elf_p, c_size_t, c_size_t]
libelf.elf_strptr.restype = c_char_p
