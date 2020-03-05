#! /usr/bin/python

import sys
import os
import re
import tempfile
import subprocess
import json
import argparse

def run_command(command):
    proc = subprocess.Popen(command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    output, err = proc.communicate()

    return (output, err)

def analyse(recording, pfl_exe, savefile):
    pattern = re.compile(r'\[(?P<bbcount>[\dxa-fA-F,:]+) dlopen\]'
                         r' Library Name: (?P<dsoname>[\w]+\.so)')

    print("Analysing {} for dlopened DSOs".format(recording))
    try:
        fd, pfl_script = tempfile.mkstemp()

        with os.fdopen(fd, 'w') as tmp:
            tmp.write('dlopen => printf "Library Name: %s\\n", $rdi\n')

        command = [pfl_exe, recording, pfl_script]
        output, _ = run_command(command)

        dlopened_dso_bbcount_map = {}
        print("Parsing analysis output")
        for m in re.finditer(pattern, output):
            if m:
                dso_name, bbcount = m.group('dsoname'), m.group('bbcount')
                dlopened_dso_bbcount_map[dso_name] = bbcount

        print("Saving result to {}".format(savefile))
        json.dump(dlopened_dso_bbcount_map, open(savefile, 'w'))
    finally:
        os.remove(pfl_script)

def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     description="Analyse dlopens in a recording.")

    parser.add_argument('recording',
                        metavar='RECORDING',
                        help='LiveRecorder output to analyse for dlopen')

    parser.add_argument('savefile',
                        metavar='SAVEFILE',
                        nargs='?',
                        default='dlopen_dsos_bbcount_map',
                        help='Filename to save analysis result for dlopen')

    script_path = os.path.abspath(os.path.dirname(sys.argv[0]))
    pfl_exe = os.path.join(script_path, '..', 'undodb', 'udynlog')

    args = parser.parse_args(sys.argv[1:])

    analyse(args.recording, pfl_exe, args.savefile)

if __name__ == "__main__":
    main()

