#!/usr/bin/python3
#
# Copyright 2019-2021, Fabian Lang <fabian.lang@fau.de>
# Copyright 2021, Andreas Ziegler <andreas.ziegler@fau.de>
#
# This file is part of shrinkelf.
#
# shrinkelf is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# shrinkelf is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with shrinkelf.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import bisect
import copy
import logging
import os
import time
from typing import Optional, Tuple, Dict

import gurobipy as gp
from gurobipy import GRB

from elfdefinitions import *
from util import *

# file suffix for output file appended to the input file when no output file was specified
FILESUFFIX: str = ".shrinked"
# command line option for permuting fragments using brute force
PERMUTE_WITH_BRUTE_FORCE: str = "brute-force"
# command line option for permuting fragments using gurobi
PERMUTE_WITH_GUROBI: str = "gurobi"
# command line option for permuting fragments using z3
PERMUTE_WITH_Z3: str = "z3"


class CleanUp(Exception):
    """ Exception used to manage control flow and clean up open file and ELF descriptors. """
    def __init__(self, level, exitstatus):
        """ Initialize self.

        :param level: indicates which file and ELF descriptors are open
        :param exitstatus: exit status to exit the program
        """
        super().__init__()
        self.level = level
        self.exitstatus = exitstatus


# global CleanUp object used for managing control flow
cu = CleanUp(0, 0)


class Done(Exception):
    """ Exception used for managing control flow. """
    pass


class EndOfSegmentException(Exception):
    pass


def insertTuple(item_03: Tuple[int, int], list_of_items: List[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """
    Insert element `item` in sorted list of ranges and return `None` on success. On failure return the range `item`
    overlaps with and do NOT insert `item` in list.
    """
    length_01 = len(list_of_items)
    if length_01 == 0:
        # list is empty
        list_of_items.append(item_03)
        return None
    else:
        idx = bisect.bisect(list_of_items, item_03)
        if idx != length_01:
            next_item = list_of_items[idx + 1]
            if item_03[1] < next_item[0]:
                # item must be sorted in before current element
                list_of_items.insert(idx, item_03)
        if idx > 0:
            prev_item = list_of_items[idx - 1]
            if item_03[0] <= prev_item[1]:
                # item overlaps with current element
                return prev_item
#        for i in range(0, length_01):
#            current_item = list_of_items[i]
#            if item_03[1] < current_item[0]:
#                # item must be sorted in before current element
#                list_of_items.insert(i, item_03)
#                return None
#            elif item_03[0] <= current_item[1]:
#                # item overlaps with current element
#                return current_item
        list_of_items.append(item_03)
        return None


def insertRange(item_04: FileFragment, list_of_items: List[FileFragment]) -> Optional[FileFragment]:
    """
    Insert element `item` in sorted list of ranges and return `None` on success. On failure return the range `item`
    overlaps with and do NOT insert `item` in list.
    """
    length_02 = len(list_of_items)
    if length_02 == 0:
        # list is empty
        list_of_items.append(item_04)
        return None
    else:
        idx = bisect.bisect(list_of_items, item_04)
        if idx != length_02:
            next_item = list_of_items[idx + 1]
            if item_04.end < next_item.start:
                # item must be sorted in before next element
                list_of_items.insert(idx, item_04)
                return None
        if idx > 0:
            prev_item = list_of_items[idx - 1]
            if item_04.start <= prev_item.end:
                # item overlaps with previous element
                return prev_item
        #for i in range(0, length_02):
        #    current_item = list_of_items[i]
        #    if item_04.end < current_item.start:
        #        # item must be sorted in before current element
        #        list_of_items.insert(i, item_04)
        #        return None
        #    elif item_04.start <= current_item.end:
        #        # item overlaps with current element
        #        return current_item
        list_of_items.append(item_04)
        return None


def countLOADs(elf) -> int:
    """ Count LOAD program headers in an ELF file.

    :param elf: the file
    :return: the number of LOAD program headers
    """
    count = 0
    # number of segments in file
    phdrnum = c_size_t(0)
    if libelf.elf_getphdrnum(elf, byref(phdrnum)) != 0:
        logging.error("Could not retrieve number of segments from source file: %s",
                      libelf.elf_errmsg(-1).decode())
        raise cu
    phdr = GElf_Phdr()
    for i in range(0, phdrnum.value):
        if not libelf.gelf_getphdr(elf, i, byref(phdr)):
            logging.error("Could not retrieve source phdr structure %d: %s",
                          i, libelf.elf_errmsg(-1).decode())
            raise cu
        if phdr.p_type == PT_LOAD.value:
            count += 1
    return count


def segments(section: List[FileFragment], section_start: int) -> Optional[List[FragmentRange]]:
    """ Construct the FragmentRanges of a section.

    :param section: list of FileFragments of a section
    :param section_start: start address of this section in the new file
    :return: a list of FragmentRanges fit for rearrangement or `None` in case of an error
    """
    if section is None or len(section) == 0:
        return None
    ret: List[FragmentRange] = []
    current = FragmentRange(offset=section[0].section_offset + section[0].start, vaddr=section[0].memory_info.start,
                            fsize=section[0].end - section[0].start, loadable=section[0].memory_info.loadable,
                            msize=section[0].memory_info.end - section[0].memory_info.start,
                            flags=section[0].memory_info.flags, section_start=section_start)
    for i in range(1, len(section)):
        if ((current.vaddr + current.msize) // PAGESIZE) == (section[i].memory_info.start // PAGESIZE):
            # data of indexed range will be loaded in the same page as content of current range => merge the ranges
            current.fsize = section[i].section_offset + section[i].end - current.offset
            current.msize = section[i].memory_info.end - current.vaddr
            current.loadable |= section[i].memory_info.loadable
            current.flags |= section[i].memory_info.flags
        else:
            # data of indexed range will not be loaded in the same page as content of current range => create new range
            ret.append(current)
            current = FragmentRange(offset=section[i].section_offset + section[i].start, section_start=section_start,
                                    fsize=section[i].end - section[i].start, vaddr=section[i].memory_info.start,
                                    msize=section[i].memory_info.end - section[i].memory_info.start,
                                    flags=section[i].memory_info.flags, loadable=section[i].memory_info.loadable)
    ret.append(current)
    return ret


def countLoadableSegmentRanges(segment_list: List[FragmentRange]):
    """ Count the loadable FragmentRanges in a list.

    :param segment_list: the list
    :return: number of loadable FragmentRanges
    """
    ret = 0
    for item_05 in segment_list:
        if item_05.loadable:
            ret += 1
    return ret


# todo: move to Permutation
def createPermutation(segments_01: List[List[FragmentRange]], index: int, current_size: int) -> Permutation:
    """ Constructor for Permutation.

    :param segments_01: List of lists of FragmentRanges imposing constraints on the permutation
    :param index: the index for which section a Permutation is constructed
    :param current_size: currently occupied size in the new file
    :return: the new Permutation
    """
    ret: Permutation = Permutation(num_entries=len(segments_01[index]))
    ret.tmp = [0] * ret.num_entries
    ret.result = [0] * ret.num_entries
    if current_size // PAGESIZE == segments_01[index][0].offset // PAGESIZE:
        # mark first element because it is on the same page as the previous section
        ret.tmp[0] = -1
        ret.result[0] = -1
    if index != len(segments_01) - 1:
        last = segments_01[index][-1]
        ahead = segments_01[index + 1][0]
        if (last.offset + last.fsize) // PAGESIZE == ahead.offset // PAGESIZE:
            # mark last element because its on the same page as the next section
            ret.tmp[-1] = -1
            ret.result[-1] = -1
    # mark size of the section under the currently best permutation as not determined yet
    ret.size = -1
    return ret


def calculateOffset(prior_offset: int, occupied_space: int) -> int:
    """ Calculate offset of a fragment in new file.

    Constraint: new offset needs to be equal to prior offset modulo page size because LOAD segments require that
    `p_offset` (offset in file) is equal to `p_vaddr` (address in virtual address space) modulo page size.

    :param prior_offset: offset of fragment in original file
    :param occupied_space: number of already occupied bytes in new file
    :return: offset in new file
    """
    prior_page_offset = prior_offset % PAGESIZE
    occupied_page_offset = occupied_space % PAGESIZE
    if occupied_page_offset <= prior_page_offset:
        return occupied_space - occupied_page_offset + prior_page_offset
    else:
        return occupied_space - occupied_page_offset + prior_page_offset + PAGESIZE


def evaluate(perm: Permutation, segments_02: List[FragmentRange]):
    """ Evaluate the current permutation of FragmentRanges.

    Compute the size of the section if the FragmentRanges it contains are inserted in the ordering described by the
    current permutation. Update the currently best permutation and its resulting size if needed.
    :param perm: the state of the permutation algorithm containing the current and the best permutation
    :param segments_02: the FragmentRanges to insert
    """
    start_01 = 0
    end_01 = 0
    # look up for every position (ranges from 1 to the number of segments) which segment to insert
    for i in range(1, perm.num_entries + 1):
        if i == 1 and perm.tmp[0] == -1:
            # first position and the (in the input file) first segment is marked to be inserted first
            start_01 = segments_02[0].offset
            end_01 = segments_02[0].offset + segments_02[0].fsize
            continue
        elif i == perm.num_entries and perm.tmp[-1] == -1:
            # last position and the (in the input file) last segment is marked to be inserted last
            tmp_07 = segments_02[-1]
            end_01 = calculateOffset(tmp_07.offset, end_01) + tmp_07.fsize
            break
        else:
            # search the segment with the index for the current position
            for j in range(0, perm.num_entries):
                if i == perm.tmp[j]:
                    tmp_08 = segments_02[j]
                    if i == 1:
                        start_01 = tmp_08.offset
                        end_01 = tmp_08.offset
                    end_01 = calculateOffset(tmp_08.offset, end_01) + tmp_08.fsize
    size = end_01 - start_01
    if size < perm.size or perm.size == -1:
        # update currently best permutation if current permutation is better
        for i in range(0, perm.num_entries):
            perm.result[i] = perm.tmp[i]
        perm.size = size


def recursive_permute(perm: Permutation, segments_04: List[FragmentRange], index: int):
    """ recursive backtracking algorithm for permutation of FragmentRanges

    :param perm: the state of the algorithm
    :param segments_04: the address ranges to permute
    :param index: the current position where a address range is inserted (doubles as depth of recursion)
    """
    if index > perm.num_entries:
        # all address ranges are inserted
        evaluate(perm, segments_04)
        return
    if index == 1 and perm.tmp[0] == -1:
        # first address range is constrained by the first element of segments
        recursive_permute(perm, segments_04, index + 1)
    elif index == perm.num_entries and perm.tmp[-1] == -1:
        # last address range is constrained by the last element of segments
        recursive_permute(perm, segments_04, index + 1)
    else:
        for i in range(0, perm.num_entries):
            # check if range is not inserted yet
            if perm.tmp[i] == 0:
                # insert range temporary
                perm.tmp[i] = index
                # try every possible permutation with the remaining ranges
                recursive_permute(perm, segments_04, index + 1)
                # remove range to try the next for this position
                perm.tmp[i] = 0


def segmentOffsets(perm: Permutation, segments_07: List[FragmentRange], current_size: int):
    """ Compute the offset of the FragmentRanges in the output file.

    :param perm: the order in which the ranges are inserted
    :param segments_07: the ranges that are inserted
    :param current_size: the already occupied size in the output file
    """
    section_start = 0
    for i in range(1, perm.num_entries + 1):
        if i == 1 and perm.result[0] == -1:
            # the first element of segments is constrained to the first position
            section_start = calculateOffset(segments_07[0].offset, current_size)
            segments_07[0].shift = section_start - segments_07[0].offset
            segments_07[0].section_start = section_start
            current_size = section_start + segments_07[0].fsize
        elif i == perm.num_entries and perm.result[-1] == -1:
            # the last element of segments is constrained to the last position
            tmp_11 = segments_07[-1]
            tmp_11.shift = calculateOffset(tmp_11.offset, current_size) - tmp_11.offset
            tmp_11.section_start = section_start
        else:
            # search the element with the matching index for the current position
            for j in range(0, perm.num_entries):
                if i == perm.result[j]:
                    tmp_12 = segments_07[j]
                    if i == 1:
                        section_start = calculateOffset(tmp_12.offset, current_size)
                    tmp_12.shift = calculateOffset(tmp_12.offset, current_size) - tmp_12.offset
                    tmp_12.section_start = section_start
                    current_size = calculateOffset(tmp_12.offset, current_size) + tmp_12.fsize


def permute(segments_08: List[List[FragmentRange]], current_size: int) -> int:
    """ Permute the address ranges for all sections.

    :param segments_08: the sections' contents
    :type segments_08: list of lists of FragmentRanges
    :param current_size: the currently occupied space in the output file
    :return: the size of the output file after inserting all sections
    """
    for i in range(1, len(segments_08)):
        perm = createPermutation(segments_08, i, current_size)
        # permute the address ranges of section i
        recursive_permute(perm, segments_08[i], 1)
        # calculate the offsets of the address ranges of section i
        segmentOffsets(perm, segments_08[i], current_size)
        # update current size
        current_size = segments_08[i][0].section_start + perm.size
    return current_size


def roundUp(value: int, base: int) -> int:
    """ Round up `value` to the next multiple of `base`.

    Compute a value `x` such that `x % base == 0`, `x >= value` and `x` is minimal.
    :param value: the value for which the next bigger multiple is computed
    :param base: the value of which the multiple is computed
    :return: the multiple of base
    """
    tmp_13 = value % base
    if tmp_13 != 0:
        return value - tmp_13 + base
    else:
        return value


def contains(segment: FragmentRange, datarange: FileFragment) -> bool:
    """ Check if a FragmentRange contains a section fragment.

    :param segment: the FragmentRange
    :param datarange: the section fragment
    :return: bool indicating if the FragmentRange contains the section fragment
    """
    if datarange.section_offset + datarange.end <= segment.offset + segment.fsize:
        if datarange.section_offset + datarange.start >= segment.offset:
            return True
    return False


def containsSegment(outer: FragmentRange, inner: FragmentRange) -> bool:
    """ Check if a FragmentRange contains another.

    :param outer: the containing FragmentRange
    :param inner: the contained FragmentRange
    :return: bool indicating if the FragmentRange contains the section fragment
    """
    if inner.offset + inner.fsize <= outer.offset + outer.fsize:
        if inner.offset >= outer.offset:
            return True
    return False


def calculateShift(ranges_07: List[List[FileFragment]], segments_17: List[List[FragmentRange]]):
    """ Compute the section and fragment shift of all FileFragments.

    :param ranges_07: the FileFragments
    :param segments_17: the FragmentRanges defining the shift
    """
    for i in range(1, len(ranges_07)):
        last_idx = 0
        for tmpSec in ranges_07[i]:
            for idx_2, tmp_21 in enumerate(segments_17[i][last_idx:], last_idx):
                if contains(tmp_21, tmpSec):
                    if idx_2 > last_idx:
                        last_idx += 1
                    tmpSec.section_shift = tmp_21.section_start - tmpSec.section_offset
                    tmpSec.fragment_shift = tmp_21.shift - tmpSec.section_shift
                    break


# FIXME: Doku
def calculatePHDRInfo(fileoffset: int, memoryoffset: int, elfclass: c_int, add_ehdr: bool) -> Tuple[int, int, int]:
    if elfclass == ELFCLASS32:
        realfileoffset = fileoffset if not add_ehdr else fileoffset + SIZEOF_ELF32_EHDR
        realmemoryoffset = memoryoffset if not add_ehdr else memoryoffset + SIZEOF_ELF32_EHDR
        phdr_start = roundUp(realfileoffset, PHDR32ALIGN)
        phdr_vaddr = roundUp(realmemoryoffset, PHDR32ALIGN)
        entry_size = SIZEOF_ELF32_PHDR
    else:
        realfileoffset = fileoffset if not add_ehdr else fileoffset + SIZEOF_ELF64_EHDR
        realmemoryoffset = memoryoffset if not add_ehdr else memoryoffset + SIZEOF_ELF64_EHDR
        phdr_start = roundUp(realfileoffset, PHDR64ALIGN)
        phdr_vaddr = roundUp(realmemoryoffset, PHDR64ALIGN)
        entry_size = SIZEOF_ELF64_PHDR
    return phdr_start, phdr_vaddr, entry_size


# Fixme: Doku
# Given a tuplelist of edges, find the shortest subtour
def subtour(start, edges, size):
    cycle = []
    current_index = start[1]
    for i in range(size):
        neighbors = edges.select(current_index, '*')
        current = neighbors[0]
        cycle.append(current)
        if current[1] == start[0]:
            break
        current_index = current[1]
    return cycle


# Fixme: Doku
# Callback - use lazy constraints to eliminate sub-tours
# noinspection PyProtectedMember
def subtourelim(model, where):
    if where == GRB.Callback.MIPSOL:
        # make a list of edges selected in the solution
        xvals = model.cbGetSolution(model._xvars)
        selected = gp.tuplelist((i, j) for i, j in model._xvars.keys() if xvals[i, j] > 0.5)
        yvals = model.cbGetSolution(model._yvars)
        ring = gp.tuplelist((i, j) for i, j in model._yvars.keys() if yvals[i, j] > 0.5)
        # find the shortest cycle in the selected edge list
        tour: List[Tuple[int, int]] = subtour(ring[0], selected, model._size)
        if len(tour) < model._size - 1:
            # add subtour elimination constr. for every pair of cities in subtour
            if len(tour) == 1:
                model.cbLazy(model._xvars[tour[0][0], tour[0][1]] + model._yvars[ring[0][0], ring[0][1]] == 1)
            else:
                model.cbLazy(gp.quicksum(model._xvars[i, j] for i, j in tour) + model._yvars[ring[0][0], ring[0][1]] <= len(tour))


# Fixme: Doku
def solve_lp_instance(segments_37: List[FragmentRange], current_size, index, fix_first, fix_last, file, log):
    size = len(segments_37)
    if size == 1:
        # Fixme: Doku
        # simply push the address ranges together
        segments_37[0].section_start = calculateOffset(segments_37[0].offset, current_size)
        segments_37[0].shift = segments_37[0].section_start - segments_37[0].offset
        return segments_37[0].section_start + segments_37[0].fsize
    # xxx: mehr als das erste bzw. letzte Fragment fixieren, für kleine Fragmente
    # xxx: funktioniert momentan, da es FragmentRanges geht, die die ganze Page abdecken
    elif size == 2 and (fix_first or fix_last):
        section_start = calculateOffset(segments_37[0].offset, current_size)
        for tmp_111 in segments_37:
            tmp_111.shift = calculateOffset(tmp_111.offset, current_size) - tmp_111.offset
            tmp_111.section_start = section_start
            current_size = calculateOffset(tmp_111.offset, current_size) + tmp_111.fsize
        return current_size
    # xxx: mehr als das erste bzw. letzte Fragment fixieren, für kleine Fragmente
    # xxx: funktioniert momentan, da es FragmentRanges geht, die die ganze Page abdecken
    elif size == 3 and fix_first and fix_last:
        section_start = calculateOffset(segments_37[0].offset, current_size)
        for tmp_111 in segments_37:
            tmp_111.shift = calculateOffset(tmp_111.offset, current_size) - tmp_111.offset
            tmp_111.section_start = section_start
            current_size = calculateOffset(tmp_111.offset, current_size) + tmp_111.fsize
        return current_size
    else:
        logging.debug('creating ILP instance for section %d: %d fragments, fix_first: %s, fix_last: %s',
                      index, size, fix_first, fix_last)
        s: Dict[Tuple[int, int], int] = {}
        d: Dict[Tuple[int, int], int] = {}
        for i in range(size):
            a = segments_37[i]
            a_start = calculateOffset(a.offset, current_size) - current_size + a.fsize
            for j in range(size):
                if i == j:
                    continue
                s[(j, i)] = a_start
                b = segments_37[j]
                b_add = ((b.offset % PAGESIZE) - (a.end_in_file() % PAGESIZE) + PAGESIZE) % PAGESIZE + b.fsize
                d[(i, j)] = b_add
        try:
            env = gp.Env(empty=True)
            env.setParam('OutputFlag', 0)
            env.start()
            m: gp.Model = gp.Model("section-{0}".format(index), env=env)
            m.Params.LogToConsole = 0
            if log:
                m.Params.LogFile = "{0}.section_{1}.log".format(file, index)
            # fragment pairs for determining their order
            x = m.addVars(d.keys(), obj=d, name="x", vtype=GRB.BINARY)
            # fragment pairs to choose the last/first one
            y = m.addVars(s.keys(), obj=s, name="y", vtype=GRB.BINARY)
            m.setAttr("ModelSense", GRB.MINIMIZE)
            # number of connections between fragments. It is size-1 because every fragment has a successor except the
            # last one
            m.addLConstr(gp.quicksum(x), rhs=size-1, sense=GRB.EQUAL, name="frag")
            # there is exactly one last/first fragment pair
            m.addLConstr(gp.quicksum(y), rhs=1, sense=GRB.EQUAL, name="ring")
            # there is exactly one 'connection' leaving a fragment: either to its successor or it is the last fragment
            # and so it 'connects' to the first
            m.addConstrs(((x.sum(j, '*') + y.sum(j, '*')) == 1 for j in range(size)), "out")
            # there is exactly one incoming 'connection' to a fragment: either from its predecessor or it is the first
            # fragment and so it is 'connected' to the last
            m.addConstrs(((x.sum('*', j) + y.sum('*', j)) == 1 for j in range(size)), "in")
            # xxx: mehr als das erste bzw. letzte Fragment fixieren, für kleine Fragmente
            # xxx: funktioniert momentan, da es FragmentRanges geht, die die ganze Page abdecken
            if fix_first:
                # keep first fragment of the section in its place because it will be loaded in the same page as the end of
                # the previous section
                m.addLConstr(y.sum('*', 0) == 1, "fix_first_fragment")
            if fix_last:
                # keep last fragment of the section in its place because it will be loaded in the same page as the start of
                # the next section
                m.addLConstr(y.sum(size - 1, '*') == 1, "fix_last_fragment")

            m._xvars = x
            m._yvars = y
            m._size = size
            m.Params.lazyConstraints = 1
            before = time.time()
            m.optimize(subtourelim)
            # m.optimize()
            if m.status != GRB.OPTIMAL:
                logging.error("Unable to solve ILP instance for section %d", index)
                raise cu

            time_taken = time.time() - before
            current_fragment_index: int = -1
            last_fragment_index: int = -1
            for key in y:
                if y[key].X > 0.5:
                    last_fragment_index = key[0]
                    current_fragment_index = key[1]
                    break
            assert current_fragment_index >= 0, "current_fragment_index not set"
            assert last_fragment_index >= 0, "last_fragment_index not set"
            seq = [k for k, v in x.items() if v.X > 0.5]
            sequence: List[int] = [current_fragment_index]
            while len(sequence) < size:
                sequence += [b for a, b in seq if a == sequence[-1]]
            assert sequence[-1] == last_fragment_index, "does not include all fragments"
            first_fragment = segments_37[sequence[0]]
            section_start = calculateOffset(first_fragment.offset, current_size)

            # If the first fragment inside the current section already
            # starts at an offset to the original section start, account
            # for this offset by moving the section start back to the original
            # alignment for the start of the section.
            first_offset_into_section = calculateOffset(first_fragment.offset,
                                                        first_fragment.section_start) \
                                        - first_fragment.section_start
            if first_offset_into_section > 0:
                section_start -= first_offset_into_section
                # The following case might happen if the first fragment is moved
                # into a gap after the previous section (i.e., into a page that
                # lies before the original beginning of the section). In order
                # to keep correct alignment for the section and avoid wrongly
                # overlapping any fragments, let's revert the forward shift for
                # now and simply start in the following page.
                if section_start < current_size:
                    section_start += PAGESIZE
                    current_size = section_start
            assert section_start >= current_size
            for fragment in sequence:
                current_fragment = segments_37[fragment]
                current_fragment.shift = calculateOffset(current_fragment.offset, current_size) - current_fragment.offset
                current_fragment.section_start = section_start
                current_size = current_fragment.offset + current_fragment.shift + current_fragment.fsize

            m.dispose()
            env.dispose()
        except Exception as e:
            print(e)
            raise e
        logging.debug('ILP: %d after %.3f seconds', current_size, time_taken)
        return current_size


# Fixme: Doku
def solve_with_gurobi(segments_36: List[List[FragmentRange]], current_size, file_name, log, section_aligns):
    for i in range(1, len(segments_36)):
        # Make sure the next section starts with proper alignment
        current_size = roundUp(current_size, section_aligns[i])
        if i == 1:
            fix_first = (segments_36[i][0].offset // PAGESIZE == 0)
        else:
            fix_first = segments_36[i-1][-1].fsize > 0 and (segments_36[i-1][-1].vaddr + segments_36[i-1][-1].msize) // PAGESIZE == segments_36[i][0].vaddr // PAGESIZE
        # fix_first = current_size // PAGESIZE == segments_36[i][0].offset // PAGESIZE
        fix_last = False
        if i != len(segments_36) - 1:
            last = segments_36[i][-1]
            ahead = segments_36[i + 1][0]
            fix_last = (last.offset + last.fsize) // PAGESIZE == ahead.offset // PAGESIZE
        current_size = solve_lp_instance(segments_36[i], current_size, i, fix_first, fix_last, file_name, log)
    return current_size


# Fixme: Doku
def solve_smt_instance(section: List[FragmentRange], current_size: int, index: int, fix_first: bool, fix_last: bool) -> int:
    size = len(section)
    if size == 1:
        # Fixme: Doku
        # simply push the address ranges together
        section[0].section_start = calculateOffset(section[0].offset, current_size)
        section[0].shift = section[0].section_start - section[0].offset
        return section[0].section_start + section[0].fsize
    # xxx: mehr als das erste bzw. letzte Fragment fixieren, für kleine Fragmente
    # xxx: funktioniert momentan, da es FragmentRanges geht, die die ganze Page abdecken
    elif size == 2 and (fix_first or fix_last):
        section_start = calculateOffset(section[0].offset, current_size)
        for tmp_111 in section:
            tmp_111.shift = calculateOffset(tmp_111.offset, current_size) - tmp_111.offset
            tmp_111.section_start = section_start
            current_size = calculateOffset(tmp_111.offset, current_size) + tmp_111.fsize
        return current_size
    # xxx: mehr als das erste bzw. letzte Fragment fixieren, für kleine Fragmente
    # xxx: funktioniert momentan, da es FragmentRanges geht, die die ganze Page abdecken
    elif size == 3 and fix_first and fix_last:
        section_start = calculateOffset(section[0].offset, current_size)
        for tmp_111 in section:
            tmp_111.shift = calculateOffset(tmp_111.offset, current_size) - tmp_111.offset
            tmp_111.section_start = section_start
            current_size = calculateOffset(tmp_111.offset, current_size) + tmp_111.fsize
        return current_size
    else:
        # This import is rather expensive for small files (0.2s) so let's do
        # it only if it's really required
        import z3
        z3.set_param("parallel.enable", True)

        smt_constants = []
        for fragment in section:
            smt_constants.append(fragment.get_smt_constants())

        # Workaround for invalid models with the new solver
        z3.set_option("smt.arith.solver","2")
        z3.set_option("smt.auto_config","false")
        z3.set_option("smt.relevancy","0")

        p = z3.IntVector("p", len(section))
        end_13 = z3.Int("end")
        start_13 = z3.Int("start")
        optimizer = z3.SolverFor('QF_LIA')
        # Try to search for a solution for 30 minutes max
        optimizer.set('timeout', 30 * 60 * 1000)
        end_terms = []
        start_terms = []
        # The start must be after the current end of file
        optimizer.add(start_13 >= current_size)
        # start must stay smaller than the end of this section
        optimizer.add(start_13 < end_13)
        # constraints
        for i in range(len(section)):
            # All fragments must start after the current end of file
            optimizer.add(p[i] >= current_size // PAGESIZE)
            start_i = smt_constants[i][0]
            end_i = start_i + smt_constants[i][1]
            # fragments can't overlap
            for j in range(i + 1, len(section)):
                if i == j:
                    continue
                start_j = smt_constants[j][0]
                end_j = start_j + smt_constants[j][1]
                optimizer.add(z3.Or(p[j] * PAGESIZE + end_j <= p[i] * PAGESIZE + start_i,
                                    p[i] * PAGESIZE + end_i <= p[j] * PAGESIZE + start_j
                                    ))
            # fragments can only be placed after the current end of file
            optimizer.add(p[i] * PAGESIZE + start_i >= current_size)
            # variable "end" shall point after all fragments
            optimizer.add(p[i] * PAGESIZE + end_i <= end_13)
            # variable "end" shall point at the end of the last fragment
            end_terms.append(p[i] * PAGESIZE + end_i == end_13)
            # variable "start" shall point before all fragments
            optimizer.add(p[i] * PAGESIZE + start_i >= start_13)
            # variable "start" shall point at the start of the first fragment
            start_terms.append(p[i] * PAGESIZE + start_i == start_13)
        optimizer.add(z3.Or(end_terms))
        optimizer.add(z3.Or(start_terms))
        # xxx: mehr als das erste bzw. letzte Fragment fixieren, für kleine Fragmente
        # xxx: funktioniert momentan, da es FragmentRanges geht, die die ganze Page abdecken
        # constraints for first range
        if fix_first:
            if current_size % PAGESIZE > smt_constants[0][0]:
                # first fragment is in the page after the current end of the file
                optimizer.add(p[0] - 1 == current_size // PAGESIZE)
            else:
                # first fragment is in the same page as the current end of the file
                optimizer.add(p[0] == current_size // PAGESIZE)
        # constraints for last range
        if fix_last:
            # last range must come last in file
            for i in range(len(section) - 1):
                optimizer.add((p[len(section) - 1] * PAGESIZE + smt_constants[-1][0]) + smt_constants[-1][1]
                              > (p[i] * PAGESIZE + smt_constants[i][0]) + smt_constants[i][1])

        last_model = None
        cur_end = section[-1].offset + section[-1].fsize
        before = time.time()
        while True:
            # Check for a smaller possible value of 'end', pin start and all
            # p[i] * PAGESIZE to be smaller than the current end
            terms = [end_13 < cur_end, start_13 < cur_end]
            for i in range(len(section)):
                terms.append(p[i] <= cur_end // PAGESIZE)

            res = optimizer.check(z3.And(terms))
            if res != z3.sat:
                break
            model = optimizer.model()

            # This check is only required if the first check is considered buggy
            terms = []
            for i in range(len(section)):
                terms.append(p[i] == model[p[i]])
            res = optimizer.check(z3.And(terms))
            if res != z3.sat:
                logging.warning('weird unsat')
                logging.debug('%s', str(model))
                break
            else:
                last_model = copy.deepcopy(model)
            # ... until here.
            cur_end = model[end_13].as_long()
            logging.debug('SMT: %d after %.3f seconds', cur_end, time.time() - before)

        if last_model is None:
            logging.error("Z3 could not find a solution for section %d", index)
            raise cu
        else:
            section_start = last_model[start_13].as_long()
            # Same reasoning as in the ILP case: if the first fragment
            # started at an offset relative to the beginning of the section
            # in the original file, section_start will be shifted by this
            # amount in the model. In this case, move the beginning of the
            # section back again.
            _, min_idx = min((last_model[p[i]].as_long(), i) for i in range(len(section)))
            first = section[min_idx]
            first_offset_into_section = calculateOffset(first.offset, first.section_start) - first.section_start
            if first_offset_into_section > 0:
                section_start -= first_offset_into_section
            for i in range(len(section)):
                section[i].section_start = section_start
                section[i].shift = (last_model.eval(p[i] * PAGESIZE + smt_constants[i][0])).as_long() - section[i].offset

        return last_model[end_13].as_long()


# Fixme: Doku
def solve_with_z3(segments_13: List[List[FragmentRange]], current_size: int, section_aligns: List[int]) -> int:
    for i in range(1, len(segments_13)):
        current_size = roundUp(current_size, section_aligns[i])
        if i == 1:
            fix_first = (segments_13[i][0].offset // PAGESIZE == 0)
        else:
            fix_first = segments_13[i-1][-1].fsize > 0 and ((segments_13[i-1][-1].vaddr + segments_13[i-1][-1].msize) // PAGESIZE == segments_13[i][0].vaddr // PAGESIZE)
        # fix_first = current_size // PAGESIZE == segments_13[i][0].offset // PAGESIZE
        fix_last = False
        if i != len(segments_13) - 1:
            last = segments_13[i][-1]
            ahead = segments_13[i + 1][0]
            fix_last = (last.offset + last.fsize) // PAGESIZE == ahead.offset // PAGESIZE
        current_size = solve_smt_instance(segments_13[i], current_size, i, fix_first, fix_last)
    return current_size

def maybe_merge_with_next_fragment(ret, frag, ahead_frag):
    # last memory page with content from the current range
    current_page = (frag.vaddr + frag.msize) // PAGESIZE
    # first memory page with content from the next range
    tmp_page = ahead_frag.vaddr // PAGESIZE
    # last file page with content from the current range
    current_filepage = (frag.offset + frag.fsize) // PAGESIZE
    # first file page with content from the next range
    tmp_filepage = (ahead_frag.offset + ahead_frag.shift) // PAGESIZE
    if current_page + 1 == tmp_page and current_filepage + 1 == tmp_filepage:
        # data of next range will be loaded in the following page as content of current range
        # => merge the ranges
        frag.fsize = ahead_frag.offset + ahead_frag.shift + ahead_frag.fsize - frag.offset
        frag.msize = ahead_frag.vaddr + ahead_frag.msize - frag.vaddr
        frag.loadable |= ahead_frag.loadable
        frag.flags |= ahead_frag.flags
        ret.list_entries -= 1
        ret.phdr_entries -= 1
        ret.segment_list.remove(ahead_frag)

# FIXME: Doku
# \brief Calculates the new file layout
#
# \param ranges Array of list of data ranges to incorporate in the new file
# \param size Size of ranges
# \param oldEntries Number of PHDR entries of original file that are NOT LOADs
# \param elfclass Elf Class (32bit or 64bit)
# \param permuteRanges Flag if the address ranges of sections should be permuted
#
# \return The [description of the file layout](@ref layoutDescription) of the output file
def calculateNewFilelayout(ranges_13: List[List[FileFragment]], old_entries: int, elfclass: c_int,
                           permute_ranges: str, file_name, log) -> LayoutDescription:
    size = len(ranges_13)
    ret: LayoutDescription = LayoutDescription()
    ret.segment_num = size
    ret.segments = [[]] * ret.segment_num
    ret.section_aligns = [1] * ret.segment_num
    # number of LOAD entries in new PHDR table
    # Start with one for file header and one for PHDR table
    loads = 2
    if elfclass == ELFCLASS32:
        current_size = SIZEOF_ELF32_EHDR
    else:
        current_size = SIZEOF_ELF64_EHDR
    # ignore section 0
    for i in range(1, size):
        # determine the address ranges from the data ranges of a section
        ret.segments[i] = segments(ranges_13[i], ranges_13[i][0].section_offset)
        ret.section_aligns[i] = ranges_13[i][0].section_align
        loads += countLoadableSegmentRanges(ret.segments[i])
    # check if user want to permute address ranges
    if permute_ranges == PERMUTE_WITH_BRUTE_FORCE:
        current_size = permute(ret.segments, current_size)
        if current_size == 0:
            raise cu
    elif permute_ranges == PERMUTE_WITH_GUROBI:
        current_size = solve_with_gurobi(ret.segments, current_size, file_name, log, ret.section_aligns)
    elif permute_ranges == PERMUTE_WITH_Z3:
        current_size = solve_with_z3(ret.segments, current_size, ret.section_aligns)
    else:
        # simply push the address ranges together
        for i in range(1, size):
            section_start = calculateOffset(ret.segments[i][0].section_start, current_size)
            for tmp_111 in ret.segments[i]:
                tmp_111.shift = calculateOffset(tmp_111.offset, current_size) - tmp_111.offset
                tmp_111.section_start = section_start
                current_size = calculateOffset(tmp_111.offset, current_size) + tmp_111.fsize

    for section_no, seg in enumerate(ret.segments):
        start_end_pairs = []
        logging.debug('calculated segments for section no. %d', section_no)
        for fr_idx, fr_rng in enumerate(seg):
            logging.debug('fr_idx %d, offset %x, shift %x -> (%x, size %x, end %x)',
                          fr_idx, fr_rng.offset, fr_rng.shift,
                          fr_rng.offset + fr_rng.shift, fr_rng.fsize,
                          fr_rng.offset + fr_rng.shift + fr_rng.fsize)
            start_end_pairs.append((fr_rng.offset + fr_rng.shift, fr_rng.offset + fr_rng.shift + fr_rng.fsize))
        start_end_pairs.sort()
        for idx, k in enumerate(start_end_pairs[:-1]):
            end_cur = k[1]
            start_next = start_end_pairs[idx + 1][0]
            if end_cur > start_next:
                logging.debug('--- end_cur > start_next: %x > %x', end_cur, start_next)

    # join address ranges between sections
    current_fragment: FragmentRange = FragmentRange()
    ret.list_entries = loads + old_entries
    current_fragment.offset = 0
    current_fragment.fsize = ret.segments[1][0].offset + ret.segments[1][0].shift + ret.segments[1][0].fsize
    current_fragment.vaddr = (ret.segments[1][0].vaddr // PAGESIZE) * PAGESIZE
    current_fragment.msize = current_fragment.fsize
    current_fragment.flags = ret.segments[1][0].flags
    current_fragment.loadable = True
    current_index = 0
    ret.list_entries -= 1
    for i in range(1, size):
        if i == 1:
            to_iterate = ret.segments[i][1:]
        else:
            to_iterate = ret.segments[i]
        for tmp_113 in to_iterate:
            # last memory page with content from the current range
            current_page = (current_fragment.vaddr + current_fragment.msize) // PAGESIZE
            # first memory page with content from the tmp_113 range
            tmp_page = tmp_113.vaddr // PAGESIZE
            # last file page with content from the current range
            current_filepage = (current_fragment.offset + current_fragment.fsize) // PAGESIZE
            # first file page with content from the tmp_113 range
            tmp_filepage = (tmp_113.offset + tmp_113.shift) // PAGESIZE
            if (current_page == tmp_page and current_filepage == tmp_filepage) or (current_page + 1 == tmp_page and current_filepage + 1 == tmp_filepage):
                # data of tmp_113 range will be loaded in the same or the following page as content of current range
                # => merge the ranges
                current_fragment.fsize = tmp_113.offset + tmp_113.shift + tmp_113.fsize - current_fragment.offset
                current_fragment.msize = tmp_113.vaddr + tmp_113.msize - current_fragment.vaddr
                current_fragment.loadable |= tmp_113.loadable
                current_fragment.flags |= tmp_113.flags
                # If we're in a loadable fragment, we can reduce the number of
                # PHDR entries by one due to this merge
                if current_fragment.loadable:
                    ret.list_entries -= 1
            else:
                # data of tmp_113 range will be loaded in a page farther away from the content of current range
                # => create new ranges
                ret.segment_list.append(current_fragment)
                current_index += 1
                current_fragment = FragmentRange()
                current_fragment.offset = tmp_113.offset + tmp_113.shift
                current_fragment.fsize = tmp_113.fsize
                current_fragment.vaddr = tmp_113.vaddr
                current_fragment.msize = tmp_113.msize
                current_fragment.flags = tmp_113.flags
                current_fragment.loadable = tmp_113.loadable
            tmp_113.contained_in = current_index

    # If the last fragment is completely unloadable, we need one less entry
    # for the PHDR table, otherwise we need to add this fragment to the list
    if not current_fragment.loadable:
        ret.list_entries -= 1
    else:
        ret.segment_list.append(current_fragment)

    # insert PHDR table
    i = 0
    try:
        for i in range(0, size):
            # determine which start addresses the PHDR table would have if it were inserted after section i (i == 0
            # meaning inserting after file header)
            if i == 0:
                tmp = ret.segments[1][0]
                phdr_start, phdr_vaddr, entry_size = calculatePHDRInfo(0, tmp.vaddr - (tmp.offset + tmp.shift), elfclass, True)
            else:
                tmp = ret.segments[i][-1]
                fileoffset = tmp.offset + tmp.fsize + tmp.shift
                memoryoffset = tmp.vaddr + tmp.msize
                phdr_start, phdr_vaddr, entry_size = calculatePHDRInfo(fileoffset, memoryoffset, elfclass, False)
            # check if PHDR table is in the first segment
            if not containsSegment(ret.segment_list[0], tmp):
                raise EndOfSegmentException()
            # check if PHDR table fits in the space in memory after section i
            if i == size - 1:
                # insert after all sections
                # xxx: untested
                # todo: Alignment not given after NOBITS sections
                ret.phdr_start = phdr_start
                ret.phdr_vaddr = phdr_vaddr
                ret.phdr_entries = ret.list_entries
                table_size = entry_size * ret.phdr_entries
                current_size = ret.phdr_start + table_size
                raise Done()
            else:
                if i == 0:
                    # Maybe there is space directly after the ELF header
                    current_start = 0
                    current_shift = 0
                    current_end = (SIZEOF_ELF32_EHDR if elfclass == ELFCLASS32 else SIZEOF_ELF64_EHDR)
                else:
                    # If there isn't, check against the last segment
                    current_fragment = ret.segments[i][-1]
                    current_start = current_fragment.offset
                    current_shift = current_fragment.shift
                    current_end = current_fragment.offset + current_fragment.fsize
                ahead = ret.segments[i + 1][0]
                if ahead.vaddr >= phdr_vaddr + entry_size * ret.list_entries:
                    # If all entries of the PHDRs fit between current_fragment
                    # and ahead in the virtual address space, place it here
                    ret.phdr_start = phdr_start
                    ret.phdr_vaddr = phdr_vaddr
                    ret.phdr_entries = ret.list_entries
                    shift = 0
                    gap_too_small = ahead.offset + ahead.shift < ret.phdr_start + ret.phdr_entries * entry_size
                    if gap_too_small:
                        # If the space in the file is currently too small,
                        # calculate how much space we need in the file and shift
                        # all following segments up by a multiple of pages.
                        shift = roundUp(ret.phdr_start + ret.phdr_entries * entry_size - (ahead.offset + ahead.shift),
                                        PAGESIZE)

                    # all later segments and the end of the file are moved up
                    # by shift bytes
                    for j in range(i + 1, size):
                        for tmp3 in ret.segments[j]:
                            tmp3.shift += shift
                            tmp3.section_start += shift
                    current_size += shift

                    # correct offset of LOAD PHDRs after inserting PHDR table
                    for index, frag in enumerate(ret.segment_list):
                        # in the gap_too_small case, the current_shift was not
                        # added to current_start before combining... why?
                        if gap_too_small and current_shift > 0:
                            logging.warning('WARNING: different than before')
                        if current_start + current_shift >= frag.offset and current_end + current_shift == frag.offset + frag.fsize:
                            frag.fsize = ret.phdr_start + ret.phdr_entries * entry_size - frag.offset
                            frag.msize = ret.phdr_vaddr + ret.phdr_entries * entry_size - frag.vaddr
                            for tmp4 in ret.segment_list[index + 1:]:
                                tmp4.offset += shift
                            if index < len(ret.segment_list):
                                ahead_frag = ret.segment_list[index + 1]
                                maybe_merge_with_next_fragment(ret, frag, ahead_frag)
                            break
                    raise Done()

    except EndOfSegmentException:
        # In this case, we did not find a space for the PHDR before
        # the next segment ahead, so we will keep searching and
        # undoing possible shifts to find the first identity-mapped
        # spot where the table can fit.
        ret.phdr_in_section = -1
        enough_space = False
        # Find a fragment which has enough space after it to
        # accommodate the PHDR table in the file with all earlier
        # shifts undone.
        while not enough_space:
            current_block = ret.segments[i]
            end = max(frag.offset + frag.shift + frag.fsize for frag in current_block)

            i += 1
            if i == len(ret.segments):
                break

            ahead = ret.segments[i]
            start_ahead = min(frag.offset for frag in ahead)
            logging.debug('Trying to place PHDR table before'\
                            ' section {}, gap from {:x} to {:x} => space 0x{:x}'.format(
                i, end, start_ahead, start_ahead - end
            ))
            phdr_start, phdr_vaddr, entry_size = calculatePHDRInfo(end, end, elfclass, False)
            enough_space = start_ahead >= phdr_vaddr + entry_size * ret.list_entries
            ret.phdr_in_section = i - 1

        if enough_space:
            logging.debug('enough space at {:x}'.format(end))
            # Shift up earlier sections
            section_shift = 0
            contained_fixed = set()
            for i in range(1, ret.phdr_in_section + 1):
                if len(ret.segments[i]) == 1:
                    section_shift = -ret.segments[i][0].shift
                    ret.segments[i][0].section_start += section_shift
                    ret.segments[i][0].shift = 0
                    logging.debug('move earlier section [{}] by {:x}, len = 1'.format(
                        i, section_shift))
                    containing_segment = ret.segments[i][0].contained_in
                    if containing_segment > 0 and containing_segment not in contained_fixed:
                        contained_fixed.add(containing_segment)
                        ret.segment_list[containing_segment].offset += section_shift
                        logging.debug('moving earlier segment [{}] forward by {:x}, len = 1'.format(
                            containing_segment, section_shift))
                else:
                    # Lowest offset with (forward) shift included
                    lowest_offset_shifted, j1 = min((ret.segments[i][j].offset + ret.segments[i][j].shift, j)
                                                for j in range(len(ret.segments[i])))
                    # Lowest offset in original file
                    lowest_offset, j2 = min((ret.segments[i][j].offset, j)
                                            for j in range(len(ret.segments[i])))
                    # note: j should be identical above
                    assert j1 == j2
                    # We determined how much the whole section is shifted
                    # so we need to take this shift out
                    section_shift = lowest_offset - lowest_offset_shifted
                    for j in range(len(ret.segments[i])):
                        ret.segments[i][j].section_start += section_shift
                        ret.segments[i][j].shift += section_shift
                        containing_segment = ret.segments[i][j].contained_in
                        logging.debug('move earlier section [{}][{}] by {:x}, len = 1'.format(
                            i, j, section_shift))
                        if containing_segment <= 0 or containing_segment == len(ret.segment_list):
                            continue
                        if containing_segment not in contained_fixed:
                            logging.debug('containing: {}, {:x} {:x}, shift {:x}'.format(
                                containing_segment, ret.segment_list[containing_segment].offset,
                                ret.segment_list[containing_segment].vaddr, section_shift
                            ))
                            contained_fixed.add(containing_segment)
                            ret.segment_list[containing_segment].offset += section_shift

            logging.debug('determined section_shift before PHDR'\
                            ' table: {:x}'.format(section_shift))
            ret.phdr_start = phdr_start + section_shift
            ret.phdr_vaddr = phdr_vaddr + section_shift
            ret.phdr_entries = ret.list_entries
            phdr_space = roundUp(ret.list_entries * entry_size, PAGESIZE)
            # Later segments need to be shifted by a) taken out
            # shift before PHDR table and b) the space of the PHDR
            # table itself
            later_segment_shift = section_shift + phdr_space
            logging.debug('PHDR: {:x}/{:x} with {} entries, takes 0x{:x} bytes'.format(
                            ret.phdr_start, ret.phdr_vaddr, ret.phdr_entries, phdr_space))

            # Fixup later segments
            for i in range(ret.phdr_in_section + 1, len(ret.segments)):
                if len(ret.segments[i]) == 1:
                    ret.segments[i][0].section_start += later_segment_shift
                    ret.segments[i][0].shift += later_segment_shift
                    logging.debug('move later section [{}] by {:x}, len = 1'.format(
                        i, later_segment_shift))
                    containing_segment = ret.segments[i][0].contained_in
                    if containing_segment == len(ret.segment_list):
                        continue
                    if containing_segment not in contained_fixed:
                        contained_fixed.add(containing_segment)
                        ret.segment_list[containing_segment].offset += later_segment_shift
                        logging.debug('moving segment_list[{}] forward by {:x}, len = 1'.format(
                            containing_segment, later_segment_shift))
                else:
                    for j in range(len(ret.segments[i])):
                        ret.segments[i][j].section_start += later_segment_shift
                        ret.segments[i][j].shift += later_segment_shift
                        logging.debug('move later section [{}][{}] by {:x}, len > 1'.format(
                            i, j, later_segment_shift))
                        containing_segment = ret.segments[i][j].contained_in
                        if containing_segment == len(ret.segment_list):
                            continue
                        if containing_segment not in contained_fixed:
                            contained_fixed.add(containing_segment)
                            ret.segment_list[containing_segment].offset += later_segment_shift
                            logging.debug('moving segment_list[{}] forward by {:x}, len > 1'.format(
                                containing_segment, later_segment_shift))

            current_size += later_segment_shift
        else:
            ret.phdr_in_section = -1

        # TODO: case that first segment contains whole .text section and PHDR table is pushed to the end of the .text section
    finally:
        calculateShift(ranges_13, ret.segments)
        # determine start of SHDR table
        if elfclass == ELFCLASS32:
            ret.shdr_start = roundUp(current_size, SHDR32ALIGN)
        else:
            ret.shdr_start = roundUp(current_size, SHDR64ALIGN)
        return ret

# \brief Compute the correct values for the MemoryInfo member of a FileFragment
#
# \param current_fragment The currently processed fragment
# \param src The original ELF file handle
# \param srcshdr The original section header for the current section
# \param phdrnum The total number of program headers in the original file
#
# \return Nothing, but updates the current_fragment.memory_info member with
#         the computed values
def computeMemoryInfoForFragment(current_fragment: FileFragment, src: c_void_p,
                                 srcshdr: GElf_Shdr, phdrnum: c_size_t):
    for j in range(0, phdrnum.value):
        srcphdr = GElf_Phdr()
        if not libelf.gelf_getphdr(src, c_int(j), byref(srcphdr)):
            logging.error("Could not retrieve source phdr structure %d: %s",
                          j, libelf.elf_errmsg(-1).decode())
            raise cu
        if srcphdr.p_type != PT_LOAD.value:
            # not a loadable segment so it contains no data about the memory layout of any part of the input
            # file
            continue
        offset_02: int = 0 if srcshdr.sh_type == SHT_NOBITS.value else srcshdr.sh_size
        offset_segment: int = srcphdr.p_memsz if srcshdr.sh_type == SHT_NOBITS.value else srcphdr.p_filesz
        if srcphdr.p_offset >= srcshdr.sh_offset + offset_02 or srcphdr.p_offset + offset_segment <= srcshdr.sh_offset:
            # loadable segment but does not load this section
            continue
        current_fragment.memory_info.loadable = True
        current_fragment.memory_info.flags = srcphdr.p_flags
        current_fragment.memory_info.align = srcphdr.p_align
        if srcshdr.sh_type == SHT_NOBITS.value:
            # range contains whole NOBITS section
            current_fragment.memory_info.start = srcshdr.sh_addr
            current_fragment.memory_info.end = current_fragment.memory_info.start + srcshdr.sh_size
        else:
            # determine start and end addresses of section range in memory
            if srcphdr.p_offset <= srcshdr.sh_offset:
                # segment starts before section starts
                current_fragment.memory_info.start = srcphdr.p_vaddr + srcshdr.sh_offset + current_fragment.start - srcphdr.p_offset
            else:
                # segment starts after section starts
                current_fragment.memory_info.start = srcphdr.p_offset - srcshdr.sh_offset
            current_fragment.memory_info.end = current_fragment.memory_info.start + current_fragment.size()
        return

# \brief Compute a FileFragment for the currently processed (input) range
#        in the section numbered section_number
# \param current_range The currently processed input range
# \param section_number The index of the current section
# \param srcshdr The original section header for the current section
# \param last A boolean indicating if we're processing a range which does not
#             end in the current section
#
# \return A FileFragment for the currently processed range
def computeFragmentForSection(current_range: Tuple[int, int], section_number: int,
                              srcshdr: GElf_Shdr, last: bool=False) -> FileFragment:
    current_fragment = FileFragment()
    # determine start and end addresses of section range in file
    if srcshdr.sh_type == SHT_NOBITS.value:
        # NOBITS section don't have data in file
        current_fragment.start = 0
        current_fragment.end = 0
    else:
        # determine start of range under construction relative to the start of its containing section
        if current_range[0] < srcshdr.sh_offset:
            # range under construction starts at the beginning of its containing section
            current_fragment.start = 0
        else:
            current_fragment.start = current_range[0] - srcshdr.sh_offset
        # determine end of range under construction relative to the end of its containing section
        if last is False and current_range[1] < srcshdr.sh_offset + srcshdr.sh_size:
            current_fragment.end = current_range[1] - srcshdr.sh_offset
        else:
            # range under construction ends at the end of its containing section
            current_fragment.end = srcshdr.sh_size
        if srcshdr.sh_entsize != 0 and current_fragment.start % srcshdr.sh_entsize != 0:
            logging.error("In section %d: range to keep is misaligned by %d byte(s) "\
                          "(start relative to section start: 0x%x, entrysize: 0x%x, "\
                          "start of problematic range to keep: 0x%x)",
                          section_number, current_fragment.start % srcshdr.sh_entsize,
                          current_fragment.start, srcshdr.sh_entsize,
                          current_fragment.start + srcshdr.sh_offset)
            raise cu
        if srcshdr.sh_entsize != 0 and current_fragment.end % srcshdr.sh_entsize != 0:
            logging.error("In section %d: range to keep is misaligned by %d byte(s) "\
                          "(end relative to section start: 0x%x, entrysize: 0x%x, "\
                          "end of problematic range to keep: 0x%x)",
                          section_number, current_fragment.end % srcshdr.sh_entsize,
                          current_fragment.end, srcshdr.sh_entsize,
                          current_fragment.end + srcshdr.sh_offset)
            raise cu

    current_fragment.section_align = 1 if srcshdr.sh_type == SHT_NOBITS.value else srcshdr.sh_addralign
    current_fragment.section_offset = srcshdr.sh_offset
    return current_fragment

# FIXME: Doku
# \brief Computes the ranges to keep per section
#
# \param src Original ELF file to get data about sections
# \param ranges Ranges specified via command line
# \param section_number Number of sections in `src`
#
# \return a List of lists containing the ranges (with additional information) per section
def computeSectionRanges(src: c_void_p, ranges_27: List[Tuple[int, int]],
                         section_number: c_size_t) -> List[List[FileFragment]]:
    # number of segments in source file
    phdrnum: c_size_t = c_size_t(0)
    if libelf.elf_getphdrnum(src, byref(phdrnum)) != 0:
        logging.error("Could not retrieve number of segments from source file: %s",
                      libelf.elf_errmsg(-1).decode())
        raise cu
    # current range to process
    r: int = 0
    # ranges split per section
    section_ranges: List[List[FileFragment]] = [[] for _ in range(section_number.value)]
    for current_section in range(0, section_number.value):
        srcscn: Elf_Scn_p = libelf.elf_getscn(src, c_size_t(current_section))
        if not srcscn:
            logging.error("Could not retrieve source section data for section %d: %s",
                          current_section, libelf.elf_errmsg(-1).decode())
            raise cu
        srcshdr: GElf_Shdr = GElf_Shdr()
        if not libelf.gelf_getshdr(srcscn, byref(srcshdr)):
            logging.error("Could not retrieve source shdr data for section %d: %s",
                          current_section, libelf.elf_errmsg(-1).decode())
            raise cu
        offset: int = 0 if srcshdr.sh_type == SHT_NOBITS.value else srcshdr.sh_size
        # split ranges in section ranges and add layout data (ranges that end in section current_section)
        while r < len(ranges_27) and ranges_27[r][1] <= srcshdr.sh_offset + offset:
            current_fragment = computeFragmentForSection(ranges_27[r], current_section, srcshdr)
            insertRange(current_fragment, section_ranges[current_section])
            r += 1
        # split ranges in section ranges and add layout data (range that begins in section current_section but does not end there)
        if r < len(ranges_27) and ranges_27[r][0] < srcshdr.sh_offset + offset:
            current_fragment = computeFragmentForSection(ranges_27[r], current_section, srcshdr, last=True)
            insertRange(current_fragment, section_ranges[current_section])
        # If we had no ranges for the current section, add a 1 byte pseudo
        # entry to keep the section around
        if current_section > 0 and not section_ranges[current_section]:
            target_size = 0 if srcshdr.sh_type == SHT_NOBITS.value else 1
            logging.warning('No ranges for section %d, creating %d byte pseudo fragment',
                            current_section, target_size)
            pseudo_fragment = FileFragment(start=0, end=target_size,
                                           section_offset=srcshdr.sh_offset,
                                           section_align=1)
            logging.debug(' created pseudo fragment with values (start %x,'\
                          ' end %x, section_offset %x', pseudo_fragment.start,
                          pseudo_fragment.end, pseudo_fragment.section_offset)
            insertRange(pseudo_fragment, section_ranges[current_section])

        # Compute the memory information structs for all new fragments
        for fragment in section_ranges[current_section]:
            computeMemoryInfoForFragment(fragment, src, srcshdr, phdrnum)

    return section_ranges


# FIXME: Doku
# \brief Calculates the size of a section
#
# \param section List of data ranges in a section
#
# \return The size of the section
def calculateSectionSize(section: List[FileFragment]):
    size = 0
    for tmp_34 in section:
        temp_size = tmp_34.end + tmp_34.fragment_shift
        if temp_size > size:
            size = temp_size
    return size


# FIXME: Doku
def shrinkelf(ranges_34: List[Tuple[int, int]], file, output_file, permute_01, log):
    # --------------------------------------------------------------------------- #
    #  Setup                                                                      #
    # --------------------------------------------------------------------------- #
    # libelf-library won't work if you don't tell it the ELF version
    if libelf.elf_version(EV_CURRENT) == EV_NONE.value:
        logging.error("ELF library initialization failed: %s",libelf.elf_errmsg(-1).decode())
        cu.exitstatus = 1
        return
    # file descriptor of input file
    try:
        srcfd: int = os.open(file, os.O_RDONLY)
    except FileNotFoundError:
        logging.error("Input file %s not found", file)
        cu.exitstatus = 1
        return
    if srcfd < 0:
        logging.error("Could not open input file %s", file)
        cu.exitstatus = 1
        return
    logging.debug('Working on file \'%s\'', output_file)
    cu.level += 1
    try:
        # ELF representation of input file
        srce: Elf_p = libelf.elf_begin(c_int(srcfd), ELF_C_READ, None)
        if not srce:
            logging.error("Could not retrieve ELF structures from input file: %s",
                          libelf.elf_errmsg(-1).decode())
            raise cu
        cu.level += 1
        # file descriptor of output file
        dstfd: int = os.open(output_file, os.O_WRONLY | os.O_CREAT, mode=0o777)
        if dstfd < 0:
            logging.error("Could not open output file %s",output_file)
            raise cu
        cu.level += 1
        # ELF representation of output file
        dste: Elf_p = libelf.elf_begin(c_int(dstfd), ELF_C_WRITE, None)
        if not dste:
            logging.error("Could not create ELF structures for output file: %s",
                          libelf.elf_errmsg(-1).decode())
            raise cu
        cu.level += 1
        # tell lib that the application will take care of the exact file layout
        if libelf.elf_flagelf(dste, ELF_C_SET, ELF_F_LAYOUT) == 0:
            logging.error("elf_flagelf() failed: %s", libelf.elf_errmsg(-1).decode())
            raise cu
        # Specify fill byte for padding -- especially the padding within the .text section. Set to 0xcc because this
        # generates an interrupt on the target platform x86_64.
        libelf.elf_fill(0xcc)
        # --------------------------------------------------------------------------- #
        #  Copy executable header                                                     #
        # --------------------------------------------------------------------------- #
        # ELF class of input file
        elfclass: c_int = libelf.gelf_getclass(srce)
        if elfclass == ELFCLASSNONE.value:
            logging.error("Could not retrieve ELF class from input file")
            raise cu
        # executable header of input file
        srcehdr = GElf_Ehdr()
        if not libelf.gelf_getehdr(srce, pointer(srcehdr)):
            logging.error("Could not retrieve executable header from input file: %s",
                         libelf.elf_errmsg(-1).decode())
            raise cu
        # gelf_newehdr sets automatically the magic numbers of an ELF header, the EI_CLASS byte according to elfclass,
        # the EI_VERSION byte and e_version to the version you told the library to use.
        #
        # The EI_DATA byte is set to ELFDATANONE, e_machine to EM_NONE and e_type to ELF_K_NONE.
        #
        # Other members are set to zero. This includes the EI_OSABI and EI_ABIVERSION bytes.
        # executable header of output file
        dstehdr_pointer: POINTER(GElf_Ehdr) = libelf.gelf_newehdr(dste, elfclass)
        if not dstehdr_pointer:
            logging.error("Could not create executable header of output file: %s",
                         libelf.elf_errmsg(-1).decode())
            raise cu
        dstehdr: GElf_Ehdr = dstehdr_pointer.contents
        dstehdr.e_ident[EI_DATA] = srcehdr.e_ident[EI_DATA]
        dstehdr.e_ident[EI_OSABI] = srcehdr.e_ident[EI_OSABI]
        dstehdr.e_ident[EI_ABIVERSION] = srcehdr.e_ident[EI_ABIVERSION]
        dstehdr.e_machine = srcehdr.e_machine
        dstehdr.e_type = srcehdr.e_type
        dstehdr.e_flags = srcehdr.e_flags
        dstehdr.e_shstrndx = srcehdr.e_shstrndx
        dstehdr.e_entry = srcehdr.e_entry
        if libelf.gelf_update_ehdr(dste, dstehdr_pointer) == 0:
            logging.error("Could not update ELF structures (Header): %s",
                         libelf.elf_errmsg(-1).decode())
            raise cu
        # --------------------------------------------------------------------------- #
        #  Copy program headers                                                       #
        # --------------------------------------------------------------------------- #
        # number of sections in input file
        scnnum: c_size_t = c_size_t(0)
        if libelf.elf_getshdrnum(srce, byref(scnnum)) != 0:
            logging.error("Could not retrieve number of sections from input file: %s",
                         libelf.elf_errmsg(-1).decode())
            raise cu
        section_ranges: List[List[FileFragment]] = computeSectionRanges(srce, ranges_34, scnnum)
        for sec_no, section_range in enumerate(section_ranges):
            logging.debug('calculated fragments for section %d:', sec_no)
            for fragment_no, fragment in enumerate(section_range):
                logging.debug('  fragment %d: %x %x', fragment_no, fragment.start, fragment.end)

        # number of segments in input file
        phdrnum: c_size_t = c_size_t(0)
        if libelf.elf_getphdrnum(srce, byref(phdrnum)) != 0:
            logging.error("Could not retrieve number of segments from input file: %s",
                         libelf.elf_errmsg(-1).decode())
            raise cu
        # number of LOAD segments in source file
        loads: int = countLOADs(srce)
        # description of layout of output file
        desc: LayoutDescription = calculateNewFilelayout(section_ranges, phdrnum.value - loads, elfclass, permute_01, file, log)
        if not desc:
            logging.error("Could not generate new file layout")
            raise cu
        if desc.phdr_in_section == -1:
            logging.error("Error calculating file layout: no space for PHDRs")
            raise cu
        dstehdr.e_phoff = c_uint64(desc.phdr_start)
        # PHDR table of output file
        dstphdrs: POINTER(GElf_Phdr) = libelf.gelf_newphdr(dste, c_size_t(desc.phdr_entries))
        if not dstphdrs:
            logging.error("Could not create PHDR table for output file: %s",
                         libelf.elf_errmsg(-1).decode())
            raise cu
        # current PHDR entry of input file
        srcphdr = GElf_Phdr()
        # index of current PHDR entry in output file
        new_index: int = 0
        # flag if the current LOAD segment is the first of the input file
        first_load: bool = True
        # construct new PHDR table from old PHDR table
        for i in range(0, phdrnum.value):
            if not libelf.gelf_getphdr(srce, c_int(i), byref(srcphdr)):
                logging.error("Could not retrieve phdr structure %d of input file: %s",
                             i, libelf.elf_errmsg(-1).decode())
                raise cu
            if srcphdr.p_type != PT_LOAD.value:
                # copy values of non-LOAD segments - addresses and offsets will be fixed later
                dstphdrs[new_index].p_type = srcphdr.p_type
                dstphdrs[new_index].p_offset = srcphdr.p_offset
                dstphdrs[new_index].p_vaddr = srcphdr.p_vaddr
                dstphdrs[new_index].p_paddr = srcphdr.p_paddr
                dstphdrs[new_index].p_filesz = srcphdr.p_filesz
                dstphdrs[new_index].p_memsz = srcphdr.p_memsz
                dstphdrs[new_index].p_flags = srcphdr.p_flags
                dstphdrs[new_index].p_align = srcphdr.p_align
                new_index += 1
            elif first_load:
                # replace first LOAD segment of input file with all LOAD segments of output file
                first_load = False
                tmp_55: FragmentRange
                for tmp_55 in desc.sorted_loadable_segments():
                    dstphdrs[new_index].p_type = PT_LOAD.value
                    dstphdrs[new_index].p_offset = c_uint64(tmp_55.offset + tmp_55.shift)
                    dstphdrs[new_index].p_vaddr = c_uint64(tmp_55.vaddr)
                    dstphdrs[new_index].p_paddr = c_uint64(tmp_55.vaddr)
                    dstphdrs[new_index].p_filesz = c_uint64(tmp_55.fsize)
                    dstphdrs[new_index].p_memsz = c_uint64(tmp_55.msize)
                    dstphdrs[new_index].p_flags = c_uint32(tmp_55.flags)
                    dstphdrs[new_index].p_align = c_uint64(PAGESIZE)
                    new_index += 1
            else:
                # skip all other LOAD segments
                continue
        # fix up non-LOAD segments
        for i in range(0, desc.phdr_entries):
            if dstphdrs[i].p_type != PT_LOAD.value:
                for tmp_56 in desc.segment_list:
                    if tmp_56.vaddr <= dstphdrs[i].p_vaddr:
                        if dstphdrs[i].p_vaddr + dstphdrs[i].p_filesz <= tmp_56.vaddr + tmp_56.fsize:
                            dstphdrs[i].p_offset = c_uint64(tmp_56.offset + (dstphdrs[i].p_vaddr - tmp_56.vaddr))
                            break
                if dstphdrs[i].p_type == PT_PHDR.value:
                    # fix up PHDR segment
                    dstphdrs[i].p_vaddr = c_uint64(desc.phdr_vaddr)
                    dstphdrs[i].p_paddr = dstphdrs[i].p_vaddr
                    dstphdrs[i].p_offset = c_uint64(desc.phdr_start)
                    if elfclass == ELFCLASS32:
                        dstphdrs[i].p_filesz = c_uint64(desc.phdr_entries * SIZEOF_ELF32_PHDR)
                    else:
                        dstphdrs[i].p_filesz = c_uint64(desc.phdr_entries * SIZEOF_ELF64_PHDR)
                    dstphdrs[i].p_memsz = dstphdrs[i].p_filesz
        # --------------------------------------------------------------------------- #
        # Copy sections and section headers                                           #
        # --------------------------------------------------------------------------- #
        # current section header of input file
        srcshdr = GElf_Shdr()
        # current section header of output file
        dstshdr = GElf_Shdr()
        # lib creates section 0 automatically so we start with section 1
        section_ranges_list = []
        for i in range(1, scnnum.value):
            srcscn: c_void_p = libelf.elf_getscn(srce, c_size_t(i))
            if not srcscn:
                logging.error("Could not retrieve section %d of input file: %s",
                             i, libelf.elf_errmsg(-1).decode())
                raise cu
            if not libelf.gelf_getshdr(srcscn, byref(srcshdr)):
                logging.error("Could not retrieve shdr structure for section %d of input file: %s",
                             i, libelf.elf_errmsg(-1).decode())
                raise cu
            dstscn: c_void_p = libelf.elf_newscn(dste)
            if not dstscn:
                logging.error("Could not create section %d in output file: %s",
                             i, libelf.elf_errmsg(-1).decode())
                raise cu
            if not libelf.gelf_getshdr(dstscn, byref(dstshdr)):
                logging.error("Could not retrieve shdr structure for section %d of output file: %s",
                             i, libelf.elf_errmsg(-1).decode())
                raise cu
            # allocate buffers for the data of the output file
            for tmp_89 in section_ranges[i]:
                if tmp_89.size() == 0:
                    continue
                tmp_89.buffer = create_string_buffer(tmp_89.size())
            # current data of current section of input file
            srcdata_pointer: POINTER(Elf_Data) = libelf.elf_getdata(srcscn, None)
            # copy data in data buffers for output file
            while srcdata_pointer:
                srcdata = srcdata_pointer.contents
                if not srcdata.d_buf:
                    # section is NOBITS section => no data to copy
                    srcdata_pointer = libelf.elf_getdata(srcscn, srcdata_pointer)
                    continue
                srcdata_begin: int = srcdata.d_off
                srcdata_end = srcdata.d_off + srcdata.d_size
                for item_01 in section_ranges[i]:
                    if item_01.size() == 0:
                        continue
                    if item_01.end <= srcdata_begin:
                        # source data begins after range ends
                        srcdata_pointer = libelf.elf_getdata(srcscn, srcdata_pointer)
                        continue
                    if srcdata_end <= item_01.start:
                        # source data ends before range (and the following range because the list is sorted) begins
                        break
                    if item_01.start <= srcdata_begin:
                        # range starts before source data starts
                        srcstart = 0
                        dststart = srcdata_begin - item_01.start
                    else:
                        # range starts after source data starts
                        srcstart = item_01.start - srcdata_begin
                        dststart = 0
                    if item_01.end >= srcdata_end:
                        # range ends after source data ends
                        srcend = srcdata_end
                    else:
                        # range ends before source data ends
                        srcend = item_01.end
                    memmove(addressof(item_01.buffer) + dststart, addressof(srcdata.d_buf.contents) + srcstart,
                            srcend - srcstart)
                    item_01.d_version = srcdata.d_version
                    item_01.d_type = srcdata.d_type
                srcdata_pointer = libelf.elf_getdata(srcscn, srcdata_pointer)
            if i == desc.phdr_in_section:
                phdr_frag = FileFragment()
                # TODO: different ELF architectures
                phdrs_type = GElf_Phdr * desc.phdr_entries
                phdrs = phdrs_type()
                memmove(addressof(phdrs[0]), dstphdrs, sizeof(phdrs))
                phdr_frag.section_align = section_ranges[i][0].section_align
                phdr_frag.section_offset = section_ranges[i][0].section_offset
                phdr_frag.section_shift = section_ranges[i][0].section_shift
                phdr_frag.d_type = ELF_T_BYTE.value
                phdr_frag.d_version = 1
                phdr_frag.buffer = cast(phdrs, POINTER(c_char))
                phdr_frag.start = desc.phdr_start - (srcshdr.sh_offset + section_ranges[i][0].section_shift)
                phdr_frag.end = phdr_frag.start + sizeof(phdrs)
                phdr_frag.fragment_shift = 0
                # TODO: different ELF architectures
                phdr_frag.memory_info = MemoryFragment(start=desc.phdr_vaddr, end=desc.phdr_vaddr + sizeof(phdrs),
                                                       loadable=True, align=PHDR64ALIGN,
                                                       flags=section_ranges[i][0].memory_info.flags)
                section_ranges[i].append(phdr_frag)

                libelf.gelf_newphdr(dste, c_size_t(0))
                dstehdr.e_phnum = c_uint16(desc.phdr_entries)
                endian = dstehdr.e_ident[EI_DATA]
            # construct data descriptors of current section
            section_ranges[i].sort(key=lambda item: item.start + item.fragment_shift)
            for item_02 in section_ranges[i]:
                if item_02.buffer is None:
                    continue
                dstdata_pointer: POINTER(Elf_Data) = libelf.elf_newdata(dstscn)
                if not dstdata_pointer:
                    logging.error("Could not add data to section %d of output file: %s",
                                 i, libelf.elf_errmsg(-1).decode())
                    raise cu
                dstdata = dstdata_pointer.contents
                # alignment does not matter here because the position of the data range is controlled via d_off
                dstdata.d_align = c_uint64(1)
                dstdata.d_type = c_int(item_02.d_type)
                dstdata.d_version = c_uint(item_02.d_version)
                dstdata.d_buf = cast(item_02.buffer, POINTER(c_char))
                dstdata.d_off = c_uint64(item_02.start + item_02.fragment_shift)
                dstdata.d_size = c_uint64(item_02.end - item_02.start)
            # construct the SHDR entry of current section
            dstshdr.sh_info = srcshdr.sh_info
            dstshdr.sh_name = srcshdr.sh_name
            dstshdr.sh_type = srcshdr.sh_type
            dstshdr.sh_addr = srcshdr.sh_addr
            dstshdr.sh_flags = srcshdr.sh_flags
            dstshdr.sh_addralign = srcshdr.sh_addralign
            dstshdr.sh_offset = c_uint64(srcshdr.sh_offset + section_ranges[i][0].section_shift)
            if srcshdr.sh_type == SHT_NOBITS.value:
                dstshdr.sh_size = srcshdr.sh_size
            else:
                dstshdr.sh_size = calculateSectionSize(section_ranges[i])
                logging.debug('calculated dstshdr.sh_size = %x, srcshdr.sh_size was %x,'\
                              ' section_shift = %x, srcshdr.sh_offset was %x, len(section_ranges[i] = %d)',
                              dstshdr.sh_size, srcshdr.sh_size,
                              section_ranges[i][0].section_shift,
                              srcshdr.sh_offset, len(section_ranges[i]))
                for fxx, r in enumerate(section_ranges[i]):
                    logging.debug('section_ranges[%d][%d]: start = %x, end = %x, size = %x,'\
                                  ' section_shift = %x, section_offset = %x, fragment_shift = %x',
                                  i, fxx, r.start, r.end, r.end - r.start, r.section_shift,
                                  r.section_offset, r.fragment_shift)
                if len(section_ranges[i]) > 0:
                    logging.debug('max start + shift: %x',
                                max(r.start + r.fragment_shift for r in section_ranges[i]))
                    for fxx, fragment in enumerate(section_ranges[i][:-1]):
                        end_cur = fragment.end + fragment.fragment_shift
                        start_next = section_ranges[i][fxx + 1].start + section_ranges[i][fxx + 1].fragment_shift
                        if end_cur > start_next:
                            logging.warning('Overlap inside sections %d and %d: %x > %x',
                                            fxx, fxx + 1, end_cur, start_next)
            dstshdr.sh_entsize = srcshdr.sh_entsize
            dstshdr.sh_link = srcshdr.sh_link
            if libelf.gelf_update_shdr(dstscn, byref(dstshdr)) == 0:
                logging.error("Could not update ELF structures (Sections): %s",
                             libelf.elf_errmsg(-1).decode())
                raise cu
            logging.debug('Section \'%s\': addr %x, offset %x, align %x, size %x -> offset + size %x',
                          libelf.elf_strptr(srce, srcehdr.e_shstrndx, srcshdr.sh_name).decode('utf-8'),
                          dstshdr.sh_addr, dstshdr.sh_offset, dstshdr.sh_addralign,
                          dstshdr.sh_size, dstshdr.sh_offset + dstshdr.sh_size)
            if dstshdr.sh_type != SHT_NOBITS.value and dstshdr.sh_offset % dstshdr.sh_addralign != 0:
                logging.warning('Section %d is NOT ALIGNED', i)
            # other checks to avoid ELF_E_LAYOUT errors:
            # - overlap of SHDR table and section (skipped if offset >= shdr_end or offset + size <= shdr_start)
            tmp_shdr_start = c_uint64(desc.shdr_start)
            if tmp_shdr_start in range(dstshdr.sh_offset, dstshdr.sh_offset + dstshdr.sh_size):
                logging.warning('shdr_start (%x) inside %x:%x',
                                tmp_shdr_start, dstshdr.sh_offset,
                                dstshdr.sh_offset + dstshdr.sh_size)
            # - offset + size >= total file size (?)
            #
            if dstshdr.sh_type != SHT_NOBITS.value:
                section_ranges_list.append((dstshdr.sh_offset, dstshdr.sh_offset + dstshdr.sh_size))
        # - phoff % align (_libelf_falign of elfclass)
        hdr_align = 4 if elfclass == ELFCLASS32 else 8
        if dstehdr.e_phoff % hdr_align != 0:
            logging.debug('e_phoff at %x is not aligned!', dstehdr.e_phoff)
        # - shoff % align
        dstehdr.e_shoff = c_uint64(desc.shdr_start)
        if dstehdr.e_shoff % hdr_align != 0:
            logging.debug('e_shoff at %x is not aligned!', dstehdr.e_shoff)
        # - overlapping sections
        for idx in range(len(section_ranges_list) - 1):
            end_cur = section_ranges_list[idx][1]
            start_next = section_ranges_list[idx + 1][0]
            if end_cur > start_next:
                logging.warning('Sections %d and %d overlap (%x > %x)',
                                idx, idx + 1, end_cur, start_next)
        # write new ELF file
        if libelf.elf_update(dste, ELF_C_WRITE) == off_t(-1).value:
            logging.error("Could not write ELF structures to output file: %s",
                          libelf.elf_errmsg(-1).decode())
            raise cu
    except CleanUp:
        cu.exitstatus = 1
    except Exception as e:
        cu.exitstatus = 1
        raise e
    finally:
        if cu.level >= 4:
            # noinspection PyUnboundLocalVariable
            libelf.elf_end(dste)
        if cu.level >= 3:
            # TODO: other ELF architectures
            # noinspection PyUnboundLocalVariable
            if cu.exitstatus == 0 and desc.phdr_in_section > 0:
                os.fsync(dstfd)
                while os.fstat(dstfd).st_size < 0x100:
                    time.sleep(0.01)
                os.close(dstfd)
                phnum_upper_half = bytes([desc.phdr_entries // 256])
                phnum_lower_half = bytes([desc.phdr_entries % 256])
                phentsize_upper_half = bytes([SIZEOF_ELF64_PHDR // 256])
                phentsize_lower_half = bytes([SIZEOF_ELF64_PHDR % 256])
                with open(output_file, mode="r+b") as f:
                    # noinspection PyUnboundLocalVariable
                    if endian == 1:
                        # LSB case
                        f.seek(0x38)
                        f.write(phnum_lower_half)
                        f.seek(0x39)
                        f.write(phnum_upper_half)
                        f.seek(0x36)
                        f.write(phentsize_lower_half)
                        f.seek(0x37)
                        f.write(phentsize_upper_half)
                    elif endian == 2:
                        f.seek(0x39)
                        f.write(phnum_lower_half)
                        f.seek(0x38)
                        f.write(phnum_upper_half)
                        f.seek(0x37)
                        f.write(phentsize_lower_half)
                        f.seek(0x36)
                        f.write(phentsize_upper_half)
            else:
                # noinspection PyUnboundLocalVariable
                os.close(dstfd)
        if cu.level >= 2:
            # noinspection PyUnboundLocalVariable
            libelf.elf_end(srce)
        if cu.level >= 1:
            os.close(srcfd)


def parse_args(keep, keep_file, file, output_file) -> Optional[Tuple[List[Tuple[int, int]], str]]:
    # parse ranges to keep
    if keep is None:
        if keep_file is None:
            logging.error("No ranges specified. Aborting!")
            cu.exitstatus = 1
            return None
        else:
            keep = []
            try:
                f = open(keep_file)
            except FileNotFoundError:
                logging.error("File %s not found. Aborting!", keep_file)
                cu.exitstatus = 1
                return None
            for line in f:
                keep.append(line.rstrip())
            f.close()
    ranges_123: List[Tuple[int, int]] = []
    error = False
    for item in keep:
        if ":" in item:
            frag_desc = item.split(":")
            if len(frag_desc) != 2:
                logging.error("Invalid range argument '%s' - ignoring!", item)
                error = True
                continue
            try:
                start = int(frag_desc[0], base=0)
            except ValueError:
                logging.error("First part ('%s') of range argument '%s' not parsable - ignoring!",
                              frag_desc[0], item)
                error = True
                continue
            try:
                length = int(frag_desc[1], base=0)
            except ValueError:
                logging.error("Second part ('%s') of range argument '%s' not parsable - ignoring!",
                              frag_desc[1], item)
                error = True
                continue
            if start < 0:
                logging.error("START of %s must be bigger than or equal to zero (is %s) - ignoring!",
                              item, start)
                error = True
                continue
            if length < 1:
                logging.error("LEN of %s must be bigger than zero (is %s) - ignoring!",
                            item, length)
                error = True
                continue
            tmp = insertTuple((start, start + length), ranges_123)
            if tmp is not None:
                logging.error("%s overlaps with %s", item, tmp)
                error = True
                continue
        elif "-" in item:
            frag_desc = item.split("-")
            if len(frag_desc) != 2:
                logging.error("Invalid range argument '%s' - ignoring!", item)
                error = True
                continue
            try:
                start = int(frag_desc[0], base=0)
            except ValueError:
                logging.error("First part ('%s') of range argument '%s' not parsable - ignoring!",
                              frag_desc[0], item)
                error = True
                continue
            try:
                end = int(frag_desc[1], base=0)
            except ValueError:
                logging.error("Second part ('%s') of range argument '%s' not parsable - ignoring!",
                              frag_desc[1], item)
                error = True
                continue
            if start < 0:
                logging.error("START of %s must be bigger than or equal to zero (is %d) - ignoring!",
                              item, start)
                error = True
                continue
            if end <= start:
                logging.error("END of %s must be bigger than START (START: %d, END: %d) - ignoring!",
                              item, start, end)
                error = True
                continue
            tmp = insertTuple((start, end), ranges_123)
            if tmp is not None:
                logging.error("%s overlaps with %s", item, tmp)
                error = True
                continue
        else:
            logging.error("Invalid range argument '%s' - ignoring!", item)
            error = True
            continue
    if len(ranges_123) == 0:
        logging.error("No valid ranges! Aborting")
        cu.exitstatus = 1
        return None
    if error:
        logging.error("Errors during argument parsing detected. Aborting")
        cu.exitstatus = 1
        return None
    # determine output file name
    if output_file is not None:
        # user specified output file name
        if output_file == file:
            logging.error("Input and output file are the same! Aborting")
            cu.exitstatus = 1
            return None
    else:
        # generate own output file name
        output_file = file + FILESUFFIX
    return ranges_123, output_file


# FIXME: Doku
if __name__ == "__main__":
    # --------------------------------------------------------------------------- #
    #  Command line argument processing                                           #
    # --------------------------------------------------------------------------- #
    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("file", help="the file, which should be shrunk")
    parser.add_argument("-k", "--keep", metavar="RANGE", action='append',
                        help="Keep given %(metavar)s in new file. Accepted formats are\n 'START-END'   exclusive END\n 'START:LEN'   LEN in bytes\nwith common prefixes for base")
    parser.add_argument("-K", "--keep-file", metavar="FILE", help="File to read ranges from")
    parser.add_argument("-p", "--permute", action='store', choices=[PERMUTE_WITH_BRUTE_FORCE, PERMUTE_WITH_GUROBI, PERMUTE_WITH_Z3],
                        help="Permute fragments for potential smaller output file.\nOption determines which method to use.\nWARNING: brute-force is in O(n!)")
    parser.add_argument("-o", "--output-file", metavar="FILE", help="Name of the output file")
    parser.add_argument("-l", "--log", action='store_true', help="Output log files when using gurobi")
    parser.add_argument("-d", "--debug", action='store_true', help="very verbose debugging output")
    args = parser.parse_args()
    loglevel = logging.WARNING
    if args.debug:
        loglevel = logging.DEBUG
    logging.basicConfig(format='%(asctime)s %(levelname)-7s %(message)s',
                        level=loglevel)
    parsed = parse_args(args.keep, args.keep_file, args.file, args.output_file)
    if parsed:
        shrinkelf(parsed[0], args.file, parsed[1], args.permute, args.log)
    exit(cu.exitstatus)
