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

extras = {'edgecolor': 'black', 'linewidth': 0.5}
stages_label = ["", ""] 
#stages_label = ["-- Registration --", "Strict2F", "U2F", "-- Authentication --", "Strict2F", "U2F"]

data = defaultdict(list)
curr_stage = ""
stages = []

legend_labels = ["Log", "Location-hiding encryption", "Puncturable encryption",  
        "Public-key encryption"]
color_map = {"Puncturable encryption": hash_colors[1], "Log": mix_colors[2], "Location-hiding encryption":
        hash_colors[4], "Public-key encryption": mix_colors[0]}

with open("out/fig10.dat") as f:
    lines = f.readlines()

for line in lines:
    m = re.match('\*\*\*(.*)', line)
    if m != None:
        curr_stage = m.group(1)
        stages.append(curr_stage)
    else:
        arr = line.split(": ")
        print(arr)
        data[curr_stage].append([arr[0], float(arr[1])])

y_pos = [0, 1] #np.arange(len(data))
y_pos_ticks = [0, 1] #np.arange(len(data))

fig = plt.figure(figsize=(10,8))
ax = fig.add_subplot(111)
#for i in range(7):
#    plt.axvline(i / 5.0, linestyle='--', color='tab:gray', linewidth=0.5,zorder=-10)
for i in range(9):
    plt.axvline((i+1) / 10.0, linestyle='--', color='tab:gray', linewidth=0.5,zorder=-10)

bgbox = {'color':'white', 'pad': 0.5}

#bar_index = 0
patch_handles = []
for bar_index in range(len(stages)):
    stage = stages[bar_index]
    #stages.append(stage)
    left = np.zeros(len(data))
    patch = None
    for i in range(len(data[stage])):
        data_arr = np.zeros(len(data))
        print(data_arr)
        print(data)
        data_arr[bar_index] = data[stage][i][1]
        color = color_map[data[stage][i][0]]
        patch_handle = ax.barh(y_pos, data_arr - left, align='center', left=left, color=color, **extras)
        patch = patch_handle.get_children()[bar_index]
        bl = patch.get_xy()
        x = 0.5*patch.get_width() + bl[0]
        y = 0.5*patch.get_height() + bl[1]
        val = data[stage][i][1]
        if i > 0:
            val -= data[stage][i-1][1]
        if val > 0.1:
            ax.text(x, y, float("{0:.2f}".format(val)), ha='center', va='center', color='w')
        patch_handles.append(patch_handle)
        left = data_arr
    ax.text(patch.get_x() + patch.get_width() + 0.05, patch.get_y() +
        patch.get_height() / 2.0,
        float("{0:.2f}".format(float(data[stage][len(data[stage])-1][1]))), ha='left',
        va='center', bbox=bgbox)


    print("final left: ")
    print(left)

ax.set_yticks(y_pos_ticks)
ax.set_yticklabels(stages_label)
ax.set_xlabel(r'Recovery time (s)')

legend_elements = []
for label in legend_labels:
    legend_elements.append(Patch(color=color_map[label], label=label))

plt.legend(handles=legend_elements, ncol=1)
#fig.legend(handles=legend_elements, bbox_to_anchor=(-0.05, 1.2, 0.9, .102), loc=3, ncol=1, borderaxespad=0.)
#fig.legend(handles=legend_elements, bbox_to_anchor=(-0.05, 1.2, 0.9, .102), loc=3, ncol=1, borderaxespad=0.)

plt.savefig("out/fig10.png")
plt.show()
