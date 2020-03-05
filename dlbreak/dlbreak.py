#! /usr/bin/python

import subprocess
import re
import sys
import os
import tempfile
import json
import gdb

def run_command(command, shell=False):
    proc = subprocess.Popen(command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=shell)
    output, err = proc.communicate()

    return (output, err)

def get_parameter_value(param):
    try:
        output = gdb.parameter(param)
        return output
    except gdb.error:
        return None

def get_recording_name():
    output = gdb.execute('uinfo inferiors', to_string=True)
    m = re.search('\*\s+\d+\s+\d+\s+(.+)', output)
    if m:
        return m.group(1)
    else:
        return None

def get_recording_tmpdir():
    output = gdb.execute('maint-undodb-show-tmpdir', to_string=True)
    m = re.search('"(.+)"', output)
    if m:
        return m.group(1)
    else:
        return None

def get_current_time():
    output = gdb.execute('uinfo time', to_string=True)
    m = re.search('Current time is:\s+([\d,]+)\s+', output)
    if m:
        return m.group(1)
    else:
        return None

class DSOInfo:
    def __init__(self, name, path, linked, load_time):
        self.name = name
        m = re.search('mmap\.\d+\.(\S+\.so)', self.name)
        if m:
            self.real_name = m.group(1)
        else:
            print("Could not find mapping filename for {}".format(self.name))
            self.real_name = self.name

        self.path = path
        self.linked = linked
        self.load_time = load_time
        
        self.size = None
        self.text_offset = None
        self.load_address = None
        self.symbol_offset_map = {}

        self.generate_symbol_offset_map()
        self.find_text_offset()

    def has_symbol(self, symbol):
        return self.symbol_offset_map and symbol in self.symbol_offset_map.keys()

    def find_text_offset(self):
        section_pattern = re.compile(r'.text\s+(?P<size>[\da-fA-F]+)\s+'
                                     r'(\s+[\da-fA-F]+){2}\s+'
                                     r'(?P<offset>[\da-fA-F]+)')
        section_output, _ = run_command(['objdump', '-whj', '.text',
                                         os.path.join(self.path, self.name)])
        m = re.search(section_pattern, section_output)
        if m:
            self.size = int(m.group('size'), 16)
            self.text_offset = int(m.group('offset'), 16)

    def _read_mappings(self):
        pid = gdb.selected_inferior().pid
        print("PID: {}".format(pid))
        with tempfile.NamedTemporaryFile(mode='r', delete=True) as maps:
            gdb.execute('remote get /proc/{}/maps {}'.format(pid, maps.name))

            return maps.read()

    def find_load_address(self):
        pattern = re.compile(r'(?P<start>[\da-fA-F]+)-(?P<end>[\da-fA-F]+)'
                             r'\s+(?P<perm>[rxsp-]{4})'
                             r'\s+(?P<size>[\da-fA-F]+)'
                             r'\s+(?P<dev>[\da-fA-F]{2}:[\da-fA-F]{2})'
                             r'\s+(?P<inode>[\d]+)'
                             r'.*' + self.real_name + '.*')

        if not self.load_time:
            gdb.execute('ugo end')
        else:
            gdb.execute('ugo time {}'.format(self.load_time))

        map_data = self._read_mappings()
        m = re.search(pattern, map_data)
        if m:
            self.load_address = int(m.group('start'), 16)
        else:
            print('Error: Could not find load address for {}'.format(self.name))

    def generate_symbol_offset_map(self):
        symbol_pattern = re.compile(r'(?P<offset>[\da-fA-F]+) [T|t] '
                                    r'(?P<symbol>\S+)\(.*\)')
        output, _ = run_command(['nm', '-D', '-C', os.path.join(self.path, self.name)])

        for m in re.finditer(symbol_pattern, output):
            if m:
                self.symbol_offset_map[m.group('symbol')] = m.group('offset')

class DSODB:
    def __init__(self, root_path):
        self.dso_info_list = []
        self.dsos = []
        self.linked_dsos = []
        self.dlopened_dsos = []
        self.dlopened_dso_bbcount_map = {}
        self.root_path = root_path

    def is_dlopened_dso(self, file_name):
        return file_name in self.dlopened_dsos

    def is_linked_dso(self, file_name):
        return file_name in self.linked_dsos

    def parse_dsos(self):
        print("Parsing DSOs for symbol information")
        for dso in self.linked_dsos:
            # print("Parsing DSO {} for symbol information".format(dso))
            dso_info = DSOInfo(dso, self.root_path, True, None)
            self.dso_info_list.append(dso_info)
        
        for dso in self.dlopened_dsos:
            # print("Parsing DSO {} for symbol information".format(dso))
            load_time = self.dlopened_dso_bbcount_map[dso]
            dso_info = DSOInfo(dso, self.root_path, False, load_time)
            self.dso_info_list.append(dso_info)

    def find_dso_with_name(self, name):
        for dso in self.dso_info_list:
            if name in dso.name:
                return dso

        return None

    def find_dso_with_symbol(self, symbol):
        for dso in self.dso_info_list:
            if dso.has_symbol(symbol):
                return dso

        return None

    def save(self):
        json.dump(self.dlopened_dso_bbcount_map,
                  open('dlopened_dso_bbcount_map', 'w'))
        json.dump(self.dsos, open('dsos', 'w'))
        json.dump(self.dlopened_dsos, open('dlopened_dsos', 'w'))
        json.dump(self.linked_dsos, open('linked_dsos', 'w'))

    def load(self):
        self.dlopened_dso_bbcount_map = json.load(open('dlopened_dso_bbcount_map', 'r'))
        self.dsos = json.load(open('dsos', 'r'))
        self.dlopened_dsos = json.load(open('dlopened_dsos', 'r'))
        self.linked_dsos = json.load(open('linked_dsos', 'r'))
        self.parse_dsos()

    def print_dso_info(self):
        print("Number of DSOs: {}".format(len(self.dsos)))
        print("Number of dlopen() DSOs: {}".format(len(self.dlopened_dsos)))
        print("Number of linked DSOs: {}".format(len(self.linked_dsos)))

class DSODBExtractor:
    def __init__(self, root_path):
        self.root_path = root_path

    def generate_dsodb(self, dlopen_bbcount_map_file):
        dsodb = DSODB(self.root_path)
        print("Extracting DSOs")
        dsodb.dsos = self.extract_dsos()

        print("Extracting dlopened DSOs")
        dlopened_dso_bbcount_map = json.load(open(dlopen_bbcount_map_file, 'r'))
        dlopened_dsos = dlopened_dso_bbcount_map.keys()

        for dlopened_dso in dlopened_dso_bbcount_map.keys():
            mmap_dso = next((dso for dso in dsodb.dsos if dlopened_dso in dso),
                            dlopened_dso)
            if mmap_dso == dlopened_dso:
                print("Couldn't find mapping for {}".format(dlopened_dso))
            dsodb.dlopened_dso_bbcount_map[mmap_dso] = \
                dlopened_dso_bbcount_map[dlopened_dso]

        dsodb.dlopened_dsos = dsodb.dlopened_dso_bbcount_map.keys()

        print("Extracting linked DSOs")
        dsodb.linked_dsos = [dso for dso in dsodb.dsos
                             if dso not in dsodb.dlopened_dsos]

        dsodb.parse_dsos()

        return dsodb

    @staticmethod
    def is_dso_file(file_name):
        output, _ = run_command(['file', file_name])
        dso_pattern = r'ELF 64-bit LSB shared object, x86-64'
        return dso_pattern in output

    def extract_dsos(self):
        dsos = [file for file in os.listdir(self.root_path)
                    if self.is_dso_file(os.path.join(self.root_path, file)) and
                    os.path.isfile(os.path.join(self.root_path, file)) and
                    file.startswith('mmap') and file.endswith('.so')]
        return dsos

class DSOScan(gdb.Command):
    def __init__(self):
        super(DSOScan, self).__init__('dsoscan', gdb.COMPLETE_EXPRESSION)

    @staticmethod
    def invoke(argument, from_tty):
        args = gdb.string_to_argv(argument)
        
        tmpdir = get_recording_tmpdir()

        dso_extractor = DSODBExtractor(tmpdir)
        dso_bbcount_map = get_parameter_value('dso-bbcount-map-file')
        
        dsodb = dso_extractor.generate_dsodb(dso_bbcount_map)

        dsodb.save()

class DSOBreakPoint(gdb.Command):
    def __init__(self):
        super(DSOBreakPoint, self).__init__('dlbreak', gdb.COMPLETE_EXPRESSION)
        self.dsodb = None
        self.verbose = False
        
    def invoke(self, argument, from_tty):
        args = gdb.string_to_argv(argument)

        if args[0] == 'verbose':
            print('Usage: dlbreak <symbol> [verbose]')
            return

        if 'verbose' in args:
            self.verbose = True

        tmpdir = get_recording_tmpdir()
        recording = get_recording_name()
        
        if self.verbose:
            print("Tmpdir: {}".format(tmpdir))
            print("Recording: {} {}".format(recording, gdb.inferiors()))

        if not self.dsodb:
            dso_extractor = DSODBExtractor(tmpdir)
            dso_bbcount_map = get_parameter_value('dso-bbcount-map-file')
            if not dso_bbcount_map:
                print("dso-bbcount-map-file is not set to a valid file")
                return

            print('Generating DSO symbol database')
            self.dsodb = dso_extractor.generate_dsodb(dso_bbcount_map)
            self.dsodb.print_dso_info()
            print('Completed generating DSO symbol database')

        if self.verbose:
            print('Looking up symbol {} in DSOs'.format(args[0]))

        dso = self.dsodb.find_dso_with_symbol(args[0])

        if dso:
            if self.verbose:
                print('Found DSO containing symbol: {}'.format(dso.real_name))

            orig_time = get_current_time()

            # Load symbol file
            dso_name = os.path.splitext(dso.real_name)[0]
            pdb_name = dso_name + '.pdb'
            if self.verbose:
                print('Search for PDB file: {}'.format(pdb_name))

            solib_search_paths = get_parameter_value('solib-search-path').split(':')
            solib_search_paths.append('Recording_21st')
            pdb_file_name = None

            if self.verbose:
                print('solib-search-path: {}'.format(solib_search_paths))

            for search_path in solib_search_paths:
                file_name = os.path.join(search_path, pdb_name)
                if os.path.exists(file_name):
                    pdb_file_name = file_name
                    break
                    
            if not pdb_file_name:
                print("Could not find symbol file for DSO {}".format(dso.real_name))
                print("Try adding the directory with symbol file to solib-search-path")
                return
            else:
                if self.verbose:
                    print("PDB file found: {}".format(pdb_file_name))

            if dso.linked:
                shared_lib_name = None
                for search_path in solib_search_paths:
                    file_name = os.path.join(search_path, dso.real_name)
                    if os.path.exists(file_name):
                        shared_lib_name = file_name
                        break
                if not shared_lib_name:
                    print("Could not find DSO {}".format(dso.real_name))
                    print("Try adding the directory with the DSO to solib-search-path")
                    return
                else:
                    if self.verbose:
                        print('Found linked shared library: {}'.format(shared_lib_name))

                gdb.execute('sharedlibrary {}'.format(shared_lib_name))
            else:
                dso.find_load_address()
                pdb_file_load_addr = dso.load_address + dso.text_offset
                if self.verbose:
                    print("PDB load address: 0x{:x}".format(pdb_file_load_addr))
                gdb.execute('add-symbol-file {} 0x{:x}'.format(
                    pdb_file_name, pdb_file_load_addr))

            if self.verbose:
                print('Setting breakpoint at {}'.format(args[0]))
            gdb.execute('break {}'.format(args[0]))

            if self.verbose:
                output = gdb.execute('info breakpoints', to_string=True)
                print("Breakpoints: {}".format(output))

            if not dso.linked:
                gdb.execute('ugo time {}'.format(orig_time))
        else :
            print("Could not find symbol {} in any DSO".format(args[0]))

class DSOBBCountMap(gdb.Parameter):
    def __init__(self, name):
        super(DSOBBCountMap, self).__init__(name,
                                            gdb.COMMAND_DATA,
                                            gdb.PARAM_FILENAME)
        self.value = 'dlopen_dsos_bbcount_map'
        self.saved_value = self.value

    def get_set_string(self):
        if os.path.exists(self.value):
            self.saved_value = self.value
        else:
            file_name = self.value
            self.value = self.saved_value
            raise gdb.GdbError('{} does not exist'.format(file_name))

        return ''

    def get_show_string(self, svalue):
        svalue = self.saved_value
        return svalue

DSOBBCountMap('dso-bbcount-map-file')
DSOScan()
DSOBreakPoint()