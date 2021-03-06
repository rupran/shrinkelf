import os
import unittest
import shutil
import subprocess
import tempfile
import time

from elftools.elf.elffile import ELFFile

INPUT_FILE_FOLDER = os.path.join('test', 'test_files')
INPUT_FILE_PATH = os.path.join(INPUT_FILE_FOLDER, 'libtest.so')
SHRUNK_FILE_PATH_ILP = os.path.join(INPUT_FILE_FOLDER, 'libtest.gurobi.so')
SHRUNK_FILE_PATH_SMT = os.path.join(INPUT_FILE_FOLDER, 'libtest.z3.so')
SHRUNK_FILE_PATH_BRUTEFORCE = os.path.join(INPUT_FILE_FOLDER, 'libtest.bruteforce.so')
SHRUNK_FILE_PATH_SHIFT = os.path.join(INPUT_FILE_FOLDER, 'libtest.shift.so')

def get_ranges():
    ranges = ['0x0-0x9258',
              '0xc000-0xd000',
              '0xe820-0xeff0',
              '0xf000-0x11cb0']
    return ['{}\n'.format(r).encode('utf-8') for r in ranges]

class TestELFRemove(unittest.TestCase):

    def prepare(self, output_path):
        elf_before = ELFFile(open(INPUT_FILE_PATH, 'rb'))
        shutil.copyfile(INPUT_FILE_PATH, output_path)

    def run_solver(self, solver, rangefile, output_path):
        cmdline = ['python3', 'shrinkelf.py', '-K', rangefile.name, '-d']
        if solver == 'gurobi' or solver == 'z3' or solver == 'brute-force':
            cmdline += ['-p', solver]
        cmdline += ['-o', output_path, INPUT_FILE_PATH]
        before = time.time()
        proc = subprocess.run(cmdline)
        after = time.time()
        return proc, after - before

    def test_gurobi(self):
        fd = open(INPUT_FILE_PATH, 'rb')
        elf_before = ELFFile(fd)

        shutil.copyfile(INPUT_FILE_PATH, SHRUNK_FILE_PATH_ILP)

        with tempfile.NamedTemporaryFile() as rangefile:
            for r in get_ranges():
                rangefile.write(r)
            rangefile.flush()

            proc, time = self.run_solver('gurobi', rangefile, SHRUNK_FILE_PATH_ILP)
            self.assertEqual(proc.returncode, 0)

        fd_shrunk = open(SHRUNK_FILE_PATH_ILP, 'rb')
        elf_after = ELFFile(fd_shrunk)
        text_size = elf_after.get_section_by_name('.text')['sh_size']
        TestELFRemove.ilp_size = text_size
        TestELFRemove.ilp_time = time

    def test_z3(self):
        fd = open(INPUT_FILE_PATH, 'rb')
        elf_before = ELFFile(fd)

        shutil.copyfile(INPUT_FILE_PATH, SHRUNK_FILE_PATH_SMT)

        with tempfile.NamedTemporaryFile() as rangefile:
            for r in get_ranges():
                rangefile.write(r)
            rangefile.flush()

            proc, time = self.run_solver('z3', rangefile, SHRUNK_FILE_PATH_SMT)
            self.assertEqual(proc.returncode, 0)

        fd_shrunk = open(SHRUNK_FILE_PATH_SMT, 'rb')
        elf_after = ELFFile(fd_shrunk)
        text_size = elf_after.get_section_by_name('.text')['sh_size']
        TestELFRemove.smt_size = text_size
        TestELFRemove.smt_time = time

    def test_brute(self):
        fd = open(INPUT_FILE_PATH, 'rb')
        elf_before = ELFFile(fd)

        shutil.copyfile(INPUT_FILE_PATH, SHRUNK_FILE_PATH_BRUTEFORCE)

        with tempfile.NamedTemporaryFile() as rangefile:
            for r in get_ranges():
                rangefile.write(r)
            rangefile.flush()

            proc, time = self.run_solver('brute-force', rangefile, SHRUNK_FILE_PATH_BRUTEFORCE)
            self.assertEqual(proc.returncode, 0)

        fd_shrunk = open(SHRUNK_FILE_PATH_BRUTEFORCE, 'rb')
        elf_after = ELFFile(fd_shrunk)
        text_size = elf_after.get_section_by_name('.text')['sh_size']
        TestELFRemove.brute_size = text_size
        TestELFRemove.brute_time = time

    def test_shift(self):
        fd = open(INPUT_FILE_PATH, 'rb')
        elf_before = ELFFile(fd)

        shutil.copyfile(INPUT_FILE_PATH, SHRUNK_FILE_PATH_SHIFT)

        with tempfile.NamedTemporaryFile() as rangefile:
            for r in get_ranges():
                rangefile.write(r)
            rangefile.flush()

            proc, time = self.run_solver('', rangefile, SHRUNK_FILE_PATH_SMT)
            self.assertEqual(proc.returncode, 0)

        fd_shrunk = open(SHRUNK_FILE_PATH_SHIFT, 'rb')
        elf_after = ELFFile(fd_shrunk)
        text_size = elf_after.get_section_by_name('.text')['sh_size']
        TestELFRemove.shift_size = text_size
        TestELFRemove.shift_time = time

    @classmethod
    def tearDownClass(cls):
        print()
        print('Shift: .text[sh_size] = {} in {}'.format(cls.shift_size,
                                                        cls.shift_time))
        print('Brute: .text[sh_size] = {} in {}'.format(cls.brute_size,
                                                        cls.brute_time))
        print('SMT  : .text[sh_size] = {} in {}'.format(cls.smt_size,
                                                        cls.smt_time))
        print('ILP  : .text[sh_size] = {} in {}'.format(cls.ilp_size,
                                                        cls.ilp_time))
