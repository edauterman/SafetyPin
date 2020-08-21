import re
import matplotlib
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

colors=[mix_colors[2], hash_colors[4], hash_colors[1], hash_colors[0]]

y = []
chunks = []
with open("out/fig8.dat", 'r') as f:
    for i, line in enumerate(f):
        words = line.split()
        chunks.append(int(words[0]))
        y.append(float(words[1]))

dc_sz = [10000.0 / x for x in chunks]

fig = plt.figure(figsize = (8,8))
ax = fig.add_subplot(111)
ax.plot(dc_sz, y, color=colors[0], marker="o")
ax.set_xlabel(r"Data center size ($N$)")
ax.set_ylabel(r"Time to audit log (s)")
ax.set_xticks([0, 2500, 5000, 7500, 10000])
ax.set_xticklabels(["0", "2.5K", "5K", "7.5K", "10K"])
plt.tight_layout()
plt.savefig("out/fig8.png")
