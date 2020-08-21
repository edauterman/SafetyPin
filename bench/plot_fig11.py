import matplotlib 
import re
import matplotlib.pyplot as plt
import sys
import numpy as np
from matplotlib.ticker import FuncFormatter
import math
from collections import defaultdict
from matplotlib.patches import Patch
import brewer2mpl

bmap1 = brewer2mpl.get_map('Set1', 'Qualitative', 7)
bmap2 = brewer2mpl.get_map('Dark2', 'Qualitative', 7)
hash_colors = bmap1.mpl_colors
mix_colors = bmap2.mpl_colors

font = {'size'   : 22}

matplotlib.rc('font', **font)

log_times = []
elgamal_times = []
punc_enc_times = []

with open("out/fig11.dat", "r") as f:
    for i, line in enumerate(f):
        m = re.match(r"Location-hiding encryption: (\d+\.\d+) sec", str(line))
        if m is not None:
            elgamal_times.append(float(m.group(1)))

        m = re.match(r"Puncturable encryption: (\d+\.\d+) sec", str(line))
        if m is not None:
            punc_enc_times.append(float(m.group(1)))

        m = re.match(r"Log: (\d+\.\d+) sec", str(line))
        if m is not None:
            log_times.append(float(m.group(1)))

labels = ["Log", "Location-hiding encryption", "Puncturable encryption"]
colors=[mix_colors[2], hash_colors[4], hash_colors[1], hash_colors[0]]
sec_param = [6.813781191217037, 6.491853096329675,
        6.22881869049588, 6.006426269159433,
        5.813781191217037, 5.643856189774725,
        5.491853096329675]

fig = plt.figure(figsize = (8,8))
ax = fig.add_subplot(111)
print(np.arange(40, 91, step=10))
print(log_times)
print(elgamal_times)
print(punc_enc_times)
ax.stackplot(np.arange(40, 91, step=10), log_times, elgamal_times, punc_enc_times, labels=labels, colors=colors)
ax.set_xlabel("Cluster size ($n$)", labelpad=8.0)
ax.set_ylabel("Recovery time (s)")
ax.set_ylim([0,1.5])
ax.set_xlim([40,105])
ax.set_xticks(range(40,91,10))
ax.set_yticks([0.25*i for i in range(5)])

handles, labels = ax.get_legend_handles_labels()
handles.reverse()
labels.reverse()
ax.legend(handles, labels, bbox_to_anchor=(0, 1.0, 1., .102), loc='lower left', ncol=1, borderaxespad=0., labelspacing=0)

ax.spines['bottom'].set_position("zero")

ax.yaxis.grid(which='major', color='0.9', linestyle=':')
plt.tight_layout()
plt.savefig("out/fig11.png")
plt.show()
