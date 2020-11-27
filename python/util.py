from ctypes import Array
from typing import List


class MemoryFragment:
    loadable: bool
    flags: int
    align: int
    start: int          # from
    end: int            # to

    def __init__(self, start=0, end=0, align=0, flags=0, loadable=False):
        self.start = start
        self.end = end
        self.align = align
        self.flags = flags
        self.loadable = loadable


class FileFragment:
    start: int                      # from
    end: int                        # to
    section_offset: int
    section_align: int
    section_shift: int
    fragment_shift: int             # data_shift
    buffer: Array
    d_type: int
    d_version: int
    memory_info: MemoryFragment

    def __init__(self, start=0, end=0, section_offset=0, section_align=0, section_shift=0, fragment_shift=0,
                 buffer=None, d_type=0, d_version=0, memory_info=None):
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
        return self.end - self.start


class FragmentRange:
    offset: int
    fsize: int
    vaddr: int
    msize: int
    flags: int
    shift: int
    loadable: bool
    section_start: int

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

    def end_regarding_section(self):
        return self.offset + self.fsize

    def start_regarding_file(self):
        return self.section_start + self.offset

    def end_regarding_file(self):
        return self.start_regarding_file() + self.fsize


class LayoutDescription:
    phdr_start: int
    phdr_vaddr: int
    phdr_entries: int
    shdr_start: int
    segments: List[List[FragmentRange]]
    segment_num: int
    segment_list: List[FragmentRange]
    list_entries: int

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

    def sorted_loadable_segments(self) -> List[FragmentRange]:
        ret: List[FragmentRange] = []
        for elem in self.segment_list:
            if elem.loadable:
                ret.append(elem)

        ret.sort(key=lambda item: item.vaddr)
        return ret


class Permutation:
    tmp: List[int]
    result: List[int]
    num_entries: int
    size: int

    def __init__(self, result=None, size=0, num_entries=0, tmp=None):
        self.result = result
        self.size = size
        self.tmp = tmp
        self.num_entries = num_entries
