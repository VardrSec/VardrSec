"""UNEXECUTED TEST-ONLY finite ordinary descendant/load operand."""
import hashlib, os, resource, sys, time
from pathlib import Path
sys.path.insert(0, '/opt/vardr-nm2-boundary')
from wrapper import CASES, NS, RUNS, boot, emit, require

def main():
    require(len(sys.argv) == 4)
    mode, folder, raw_beginning = sys.argv[1:]
    require(mode in CASES and raw_beginning.isascii() and raw_beginning.isdecimal())
    beginning = int(raw_beginning); root = Path(folder)
    require(root.is_absolute() and root.resolve(strict=True) == root and root.parent == RUNS)
    entered = boot(); require(0 <= entered-beginning < 35*NS)
    end = beginning+35*NS if mode == 'nm2-c09-loaded-authority' else min(entered+8*NS,beginning+35*NS)
    resource.setrlimit(resource.RLIMIT_CPU, (3,3))
    memory = bytearray(32*1024*1024)
    for offset in range(0,len(memory),4096): memory[offset] = 1
    steps = 0; touches = 1; touched_at = entered; block = b'fixed-local-fixture'*200
    emit(root,mode,'leaf','ready', {'allocated_bytes':len(memory),'steps':steps,'touches':touches})
    while boot() < end:
        if boot()-touched_at >= NS:
            for offset in range(0,len(memory),4096): memory[offset] = 1
            touches += 1; touched_at = boot()
        if time.process_time_ns() < 2_500_000_000 and (boot()-entered)%NS < 75_000_000:
            hashlib.sha256(block).digest(); steps += 1
        else: time.sleep(.01)
    require(time.process_time_ns() <= 3*NS)
    emit(root,mode,'leaf','exit', {'allocated_bytes':len(memory),'steps':steps,'touches':touches})
    require(memory[0] == memory[-4096] == 1)

if __name__ == '__main__':
    try: main()
    except BaseException: os._exit(125)
    os._exit(0)
