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

labels = ["Public key ops", "Symmetric key ops", "I/O"] 
colors=[mix_colors[3], mix_colors[0], mix_colors[2]]
sec_param = [4.64, 4.32, 4.06, 3.84, 3.64, 3.47, 3.32]

y = [[], [], []] 
with open("out/fig9.dat", 'r') as f:
    for i, line in enumerate(f):
        y[i % 3].append(float(line))
print(y)


fig = plt.figure(figsize = (8,8))
ax = fig.add_subplot(111)
x = np.arange(5,22, step=2)
ax.stackplot(x, y[0], y[1], y[2], labels=labels, colors=colors)
ax.set_xlabel("Recoveries before key rotation", labelpad=8.0)
ax.set_ylabel("Decrypt + Puncture time (s)")
ax.set_ylim([0,1])
ax.set_yticks([0.0, 0.25, 0.5, 0.75, 1.0])

ax.set_xticks([math.log2(1000000), math.log2(100000), math.log2(10000), math.log2(1000), math.log2(100)])
ax.set_xticklabels(["100K", "10K", "1K", "100", "10"])

key_sz = ["30MB", "3MB", "300KB", "30KB", "3KB"]

for i, xpos in enumerate(ax.get_xticks()):
    ax.text(xpos, -0.25, key_sz[i], size=6, ha='center')

handles, labels = ax.get_legend_handles_labels()
handles.reverse()
labels.reverse()
ax.legend(handles, labels, bbox_to_anchor=(0.1, 0.75, 1., -.102), loc='lower left', ncol=1, borderaxespad=0.,labelspacing=0)

ax.spines['bottom'].set_position("zero")

ax.yaxis.grid(which='major', color='0.9', linestyle=':')
plt.savefig("out/fig9.png")
plt.show()
