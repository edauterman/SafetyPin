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
elgamal_times = []
punc_enc_times = []

def measureLatency(N, n):
    cmd = ("./../host/RecoveryBench %s %s") % (N, n)
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = process.stdout.read()
    lines = output.splitlines()
#    lines = ["------ Log time: 0.191237, 0 sec, 191237 micros",
#        "------ ElGamal time: 0.388025, 0 sec, 388025 micros",
#        "------ Puncturable Encryption time: 1.188478, 1 sec, 188478 micros"]
    for raw_line in lines:
        line = raw_line.decode('utf-8')
        print(line)
        m = re.match(r"------ Log time: (\d+\.\d+), (.+)", str(line))
        if m is not None:
            log_times.append(float(m.group(1)))
            print("log match")

        m = re.match(r"------ ElGamal time: (\d+\.\d+), (.+)", str(line))
        if m is not None:
            elgamal_times.append(float(m.group(1)))
            print("elgamal match")

        m = re.match(r"------ Puncturable Encryption time: (\d+\.\d+), (.+)", str(line))
        if m is not None:
            punc_enc_times.append(float(m.group(1)))
            print("punc enc match")

# Run experiment
for i in range(40, 91, 10):
    print(("Running experiment for n=%d") % (i))
    measureLatency(i, i)
#    print(("log = %f, location-hiding encryption = %f, puncturable encryption = %f") % (log_times[len(log_times) - 1], elgamal_times[len(elgamal_times) - 1], punc_enc_times[len(punc_enc_times) - 1]))

punc_enc_times = [punc_enc_times[i] - elgamal_times[i] for i in range(len(punc_enc_times))]
elgamal_times = [elgamal_times[i] - log_times[i] for i in range(len(elgamal_times))]

f = open("out/fig11.dat", "w")

n_vals = range(40, 91, 10)
for i in range(len(log_times)):
    n = n_vals[i]

    print(("n = %d") % (n))
    print(("Log: %f sec") % (log_times[i]))
    print(("Location-hiding encryption: %f sec") % (elgamal_times[i]))
    print(("Puncturable encryption: %f sec") % (punc_enc_times[i]))
    print(("Total time: %f sec\n") % (log_times[i] + elgamal_times[i] + punc_enc_times[i]))

    f.write(("n = %d\n") % (n))
    f.write(("Log: %f sec\n") % (log_times[i]))
    f.write(("Location-hiding encryption: %f sec\n") % (elgamal_times[i]))
    f.write(("Puncturable encryption: %f sec\n") % (punc_enc_times[i]))
    f.write(("Total time: %f sec\n\n") % (log_times[i] + elgamal_times[i] + punc_enc_times[i]))

f.close()
