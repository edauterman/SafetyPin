import re
import matplotlib.pyplot as plt
import sys
import numpy as np
from matplotlib.ticker import FuncFormatter
import math
from collections import defaultdict
from matplotlib.patches import Patch
import brewer2mpl
import subprocess

pub_key_times = []
sym_key_times = []
io_times = []

level_list = [5,7,9,11,13,15,17,19,21]

# Time to audit 100K recovery attempts

def measureLatency(levels, hsm_num):
    print(("Running experiment for %d levels with HSM #%d\n") % (levels, hsm_num))
    cmd = ("cd ../host/; make clean; make LEVELS=%d") % (levels)
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    process.wait()
    cmd = ("./../host/PuncEncBench %d") % (hsm_num)
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = process.stdout.read()
    lines = output.splitlines()
    for raw_line in lines:
        line = raw_line.decode('utf-8')
        print(line)
        m = re.match(r"\*\*\*\* Public key ops time: (\d+\.\d+) sec", str(line))
        if m is not None:
            pub_key_times.append(float(m.group(1)))

        m = re.match(r"\*\*\*\* Symmetric key ops time: (\d+\.\d+) sec", str(line))
        if m is not None:
            sym_key_times.append(float(m.group(1)))

        m = re.match(r"\*\*\*\* IO time: (\d+\.\d+) sec", str(line))
        if m is not None:
            io_times.append(float(m.group(1)))

# Run experiment
for i in range(len(level_list)):
    print(("Running experiment for level = %d") % (level_list[i]))
    measureLatency(level_list[i], 90 + i)

cmd = "cd ../host/; make clean; make"
process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
process.wait()
 
f = open("out/fig9.dat", "w")

for i in range(len(level_list)):
    print(("Levels: %d") % (level_list[i]))
    print(("-> public key ops time: %f") % (pub_key_times[i]))
    print(("-> symmetric key ops time: %f") % (sym_key_times[i]))
    print(("-> IO time: %f") % (io_times[i]))

    f.write(("%f\n%f\n%f\n") % (pub_key_times[i], sym_key_times[i], io_times[i]))

f.close()
