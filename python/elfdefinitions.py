from ctypes import *

# (Macro-)Constants from libelf
EI_NIDENT = 16
EI_DATA = 5
EI_OSABI = 7
EI_ABIVERSION = 8

EV_NONE = c_int(0)
EV_CURRENT = c_int(1)

ELF_C_READ = c_int(5)
ELF_C_SET = c_int(6)
ELF_C_WRITE = c_int(7)

ELF_F_LAYOUT = c_uint(1)

ELFCLASSNONE = c_int(0)

SHT_NOBITS = c_int(8)

PT_LOAD = c_int(1)



# /* 64 bit EHDR. */
class GElf_Ehdr(Structure):
    _fields_ = [("e_ident", c_ubyte * EI_NIDENT),    # unsigned char   e_ident[EI_NIDENT]; /* ELF identification. */
                ("e_type", c_uint16),                # Elf64_Half      e_type;             /* Object file type (ET_*). */
                ("e_machine", c_uint16),             # Elf64_Half      e_machine;          /* Machine type (EM_*). */
                ("e_version", c_uint32),             # Elf64_Word      e_version;          /* File format version (EV_*). */
                ("e_entry", c_uint64),               # Elf64_Addr      e_entry;            /* Start address. */
                ("e_phoff", c_uint64),               # Elf64_Off       e_phoff;            /* File offset to the PHDR table. */
                ("e_shoff", c_uint64),               # Elf64_Off       e_shoff;            /* File offset to the SHDRheader. */
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



libelf = cdll.LoadLibrary("../libelf/libelf.so.1")
libelf.elf_version.restype = c_uint
libelf.elf_errmsg.restype = c_char_p
# libelf.elf_begin.restype = POINTER(Elf)
libelf.elf_flagelf.restype = c_uint
libelf.elf_fill.restype = None
libelf.elf_end.restype = c_int
# libelf.elf_getscn.restype = POINTER(Elf_Scn)
libelf.elf_getphdrnum.restype = c_int

libelf.gelf_getclass.restype = c_int
libelf.gelf_getehdr.restype = POINTER(GElf_Ehdr)
libelf.gelf_newehdr.restype = POINTER(GElf_Ehdr)
libelf.gelf_update_ehdr.restype = c_int
libelf.gelf_getshdr.restype = POINTER(GElf_Shdr)
libelf.gelf_getphdr.restype = POINTER(GElf_Phdr)
libelf.gelf_newphdr.restype = c_void_p

