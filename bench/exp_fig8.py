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

log_times = []

# Time to audit 100K recovery attempts

def measureLatency(chunkSize):
    cmd = ("./../host/LogEpochBench %s") % (chunkSize)
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = process.stdout.read()
    lines = output.splitlines()
    for raw_line in lines:
        line = raw_line.decode('utf-8')
        print(line)
        m = re.match(r"------ Total time: (\d+\.\d+), (.+)", str(line))
        if m is not None:
            log_times.append(float(m.group(1)))

# Run experiment
for i in range(1, 15):
    print(("Running experiment for chunk size = %d") % (i))
    measureLatency(i)

f = open("out/fig8.dat", "w")

for i in range(len(log_times)):
    chunk_sz = i + 1
    dc_sz = 10000.0 / chunk_sz

    print(("Chunk size: %d") % (chunk_sz))
    print(("Data center size (for 100K recovery attempts): %d") % (dc_sz))
    print(("Total time: %f sec\n") % (log_times[i]))

    f.write(("%d %d\n") % (chunk_sz, log_times[i]))

f.close()
