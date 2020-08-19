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
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
for i in range(40, 110, 10):
    print(("Running experiment for n=%d") % (i))
    measureLatency(i, i)
    print(("log = %f, location-hiding encryption = %f, puncturable encryption = %f") % (log_times[len(log_times) - 1], elgamal_times[len(elgamal_times) - 1], punc_enc_times[len(punc_enc_times) - 1]))

punc_enc_times = [punc_enc_times[i] - elgamal_times[i] for i in range(len(punc_enc_times))]
elgamal_times = [elgamal_times[i] - log_times[i] for i in range(len(elgamal_times))]

print("LOG: ")
print(log_times)
print("LOCATION-HIDING ENCRYPTION: ")
print(elgamal_times)
print("PUNCTURABLE ENCRYPTION: ")
print(punc_enc_times)

# Plot
bmap1 = brewer2mpl.get_map('Set1', 'Qualitative', 7)
bmap2 = brewer2mpl.get_map('Dark2', 'Qualitative', 7)
hash_colors = bmap1.mpl_colors
mix_colors = bmap2.mpl_colors

labels = ["Log", "Location-hiding encryption", "Puncturable encryption"]
colors=[mix_colors[2], hash_colors[4], hash_colors[1], hash_colors[0]]
sec_param = [6.813781191217037, 6.491853096329675,
        6.22881869049588, 6.006426269159433,
        5.813781191217037, 5.643856189774725,
        5.491853096329675]

fig = plt.figure(figsize = (8,8))
ax = fig.add_subplot(111)
print(np.arange(40, 110, step=10))
ax.stackplot(np.arange(40, 110, step=10), log_times, elgamal_times, punc_enc_times, labels=labels, colors=colors)
ax.set_xlabel("Cluster size ($n$)", labelpad=8.0)
ax.set_ylabel("Recovery time (s)")
ax.set_ylim([0,1.5])
ax.set_xlim([40,105])
ax.minorticks_on()
ax.set_xticks(range(40,101,10))
ax.set_yticks([0.25*i for i in range(5)])

for i, xpos in enumerate(ax.get_xticks()):
    ax.text(xpos, -0.33, str(round(sec_param[i],2)), size=6, ha='center')

handles, labels = ax.get_legend_handles_labels()
handles.reverse()
labels.reverse()
ax.legend(handles, labels, bbox_to_anchor=(0, 1.0, 1., .102), loc='lower left', ncol=1, borderaxespad=0., labelspacing=0)

ax.spines['bottom'].set_position("zero")
#remove_chart_junk(plt,ax,grid=True,below=False)

ax.yaxis.grid(which='major', color='0.9', linestyle=':')
plt.savefig("cluster_sz_vs_recovery_time.png")
plt.show()
#custom_style.save_fig(fig, out_name, [1.9, 2.1])
