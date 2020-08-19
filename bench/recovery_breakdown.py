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

log_time = 0.0
elgamal_time = 0.0
punc_enc_time = 0.0
baseline_time = 0.0


cmd = "./../host/RecoveryBench 40 40"
print("Starting SafetyPin for n=40")
process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
output = process.stdout.read()
lines = output.splitlines()
for raw_line in lines:
    line = raw_line.decode('utf-8')
    print(line)
    m = re.match(r"------ Log time: (\d+\.\d+), (.+)", str(line))
    if m is not None:
        log_time = float(m.group(1))

    m = re.match(r"------ ElGamal time: (\d+\.\d+), (.+)", str(line))
    if m is not None:
        elgamal_time = float(m.group(1)) - log_time

    m = re.match(r"------ Puncturable Encryption time: (\d+\.\d+), (.+)", str(line))
    if m is not None:
        punc_enc_time = float(m.group(1)) - elgamal_time - log_time
print("Done with SafetyPin for n=40")

cmd = "./../host/BaselineBench" 
process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = process.stdout.read()
lines = output.splitlines()
for raw_line in lines:
    line = raw_line.decode('utf-8')
    print(line)
    m = re.match(r"\*\*\*\* Recover time: (\d+\.\d+), (.+)", str(line))
    if m is not None:
        baseline_time = float(m.group(1))
print("Done with baseline")

f = open("out/recovery_breakdown", "w")

print("SafetyPin (n = 40): ")
print(("Log: %f sec") % (log_time))
print(("Location-hiding encryption: %f sec") % (elgamal_time))
print(("Puncturable encryption: %f sec") % (punc_enc_time))
print(("Total time: %f sec\n") % (log_time + elgamal_time + punc_enc_time))

print("Baseline: ")
print(("Total time: %f sec") % (baseline_time))

f.write("SafetyPin (n = 40): \n")
f.write(("Log: %f sec\n") % (log_time))
f.write(("Location-hiding encryption: %f sec\n") % (elgamal_time))
f.write(("Puncturable encryption: %f sec\n") % (punc_enc_time))
f.write(("Total time: %f sec\n\n") % (log_time + elgamal_time + punc_enc_time))

f.write("Baseline: \n")
f.write(("Total time: %f sec\n") % (baseline_time))

f.close()
