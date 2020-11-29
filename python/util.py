from ctypes import Array
from typing import List


class MemoryFragment:
    """
    information about memory layout of the enclosing FileFragment

    loadable -- flag if the fragment is part of a LOAD segment
    flags -- flags of the containing segment
    align -- alignment requirement of the containing segment
    start -- start address of the enclosing FileFragment in memory
    end -- end address (exclusive) of the enclosing FileFragment in memory
    """

    loadable: bool
    flags: int
    align: int
    start: int
    end: int

    def __init__(self, start=0, end=0, align=0, flags=0, loadable=False):
        """ Initialize self.

        :param start: start address of the enclosing FileFragment in memory
        :type start: int
        :param end: end address (exclusive) of the enclosing FileFragment in memory
        :type end: int
        :param align: alignment requirement of the containing segment
        :type align: int
        :param flags: flags of the containing segment
        :type flags: int
        :param loadable: flag if the fragment is part of a LOAD segment
        :type loadable: bool
        """

        self.start = start
        self.end = end
        self.align = align
        self.flags = flags
        self.loadable = loadable


class FileFragment:
    """
    file fragment to keep

    A fragment of data that the user wants to keep. Addresses are relative to the start address of the containing
    section and based on the file representation.

    start -- start address of the file fragment relative to its containing section
    end -- end address (exclusive) of the file fragment relative to its containing section
    section_offset -- offset of the containing section in the file
    section_align -- alignment requirement of the containing section
    section_shift -- Shift of the containing section in the file. Negative values mean a shift towards the beginning of
                     the file
    fragment_shift -- Shift of the file fragment in its section. Negative values mean a shift towards the beginning of
                      the section
    buffer -- buffer for the data described by this fragment
    d_type -- value of corresponding member of Elf_Data struct from the libelf library
    d_version -- value of corresponding member of Elf_Data struct from the libelf library
    memory_info -- information regarding the memory layout of this fragment
    """

    start: int
    end: int
    section_offset: int
    section_align: int
    section_shift: int
    fragment_shift: int
    buffer: Array
    d_type: int
    d_version: int
    memory_info: MemoryFragment

    def __init__(self, start=0, end=0, section_offset=0, section_align=0, section_shift=0, fragment_shift=0,
                 buffer=None, d_type=0, d_version=0, memory_info=None):
        """ Initialize self.

        :param start: start address of the file fragment relative to its containing section
        :type start: int
        :param end: end address (exclusive) of the file fragment relative to its containing section
        :type end: int
        :param section_offset: offset of the containing section in the file
        :type section_offset: int
        :param section_align: alignment requirement of the containing section
        :type section_align: int
        :param section_shift: Shift of the containing section in the file. Negative values mean a shift towards the
                              beginning of the file
        :type section_shift: int
        :param fragment_shift: Shift of the file fragment in its section. Negative values mean a shift towards the
                               beginning of the section
        :type fragment_shift: int
        :param buffer: buffer for the data described by this fragment
        :type buffer: ctypes.Array[char]
        :param d_type: value of corresponding member of Elf_Data struct from the libelf library
        :type d_type: int
        :param d_version: value of corresponding member of Elf_Data struct from the libelf library
        :type d_version: int
        :param memory_info: information regarding the memory layout of this fragment
        :type memory_info: MemoryFragment
        """

        self.start = start
        self.end = end
        self.section_offset = section_offset
        self.section_align = section_align
        self.section_shift = section_shift
        self.fragment_shift = fragment_shift
        self.buffer = buffer
        self.d_type = d_type
        self.d_version = d_version
        if memory_info is None:
            self.memory_info = MemoryFragment()
        else:
            self.memory_info = memory_info

    def size(self):
        """ Return size of fragment.

        :return: size of the fragment
        :rtype: int
        """

        return self.end - self.start


# Fixme: Doku
class FragmentRange:
    offset: int
    fsize: int
    vaddr: int
    msize: int
    flags: int
    shift: int
    loadable: bool
    section_start: int

    # Fixme: Doku
    def __init__(self, loadable: bool = False, flags: int = 0, fsize: int = 0, msize: int = 0, offset: int = 0,
                 vaddr: int = 0, shift: int = 0, section_start: int = 0):
        self.loadable = loadable
        self.flags = flags
        self.fsize = fsize
        self.msize = msize
        self.offset = offset
        self.vaddr = vaddr
        self.shift = shift
        self.section_start = section_start

    # Fixme: Doku
    def end_regarding_section(self):
        return self.offset + self.fsize

    # Fixme: Doku
    def start_regarding_file(self):
        return self.section_start + self.offset

    # Fixme: Doku
    def end_regarding_file(self):
        return self.start_regarding_file() + self.fsize


# Fixme: Doku
class LayoutDescription:
    phdr_start: int
    phdr_vaddr: int
    phdr_entries: int
    shdr_start: int
    segments: List[List[FragmentRange]]
    segment_num: int
    segment_list: List[FragmentRange]
    list_entries: int

    # Fixme: Doku
    def __init__(self, list_entries: int = 0, segment_num: int = 0, segments=None, segment_list=None, phdr_vaddr: int = 0,
                 phdr_start: int = 0,
                 phdr_entries: int = 0, shdr_start: int = 0):
        if segment_list is None:
            segment_list = []
        if segments is None:
            segments = []
        self.list_entries = list_entries
        self.segment_num = segment_num
        self.segments = segments
        self.segment_list = segment_list
        self.phdr_vaddr = phdr_vaddr
        self.phdr_start = phdr_start
        self.phdr_entries = phdr_entries
        self.shdr_start = shdr_start

    # Fixme: Doku
    def sorted_loadable_segments(self) -> List[FragmentRange]:
        ret: List[FragmentRange] = []
        for elem in self.segment_list:
            if elem.loadable:
                ret.append(elem)

        ret.sort(key=lambda item: item.vaddr)
        return ret


# Fixme: Doku
class Permutation:
    tmp: List[int]
    result: List[int]
    num_entries: int
    size: int

    # Fixme: Doku
    def __init__(self, result=None, size=0, num_entries=0, tmp=None):
        self.result = result
        self.size = size
        self.tmp = tmp
        self.num_entries = num_entries
