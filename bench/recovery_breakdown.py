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

data = defaultdict(list)

cmd = "./../host/RecoveryBench 40 40"
print("Starting SafetyPin for n=40")
process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = process.stdout.read()
lines = output.splitlines()
for raw_line in lines:
    line = raw_line.decode('utf-8')
    print(line)
    m = re.match(r"------ Log time: (\d+\.\d+), (.+)", str(line))
    if m is not None:
        data["Log"].append(float(m.group(1)))
        print("log match")

    m = re.match(r"------ ElGamal time: (\d+\.\d+), (.+)", str(line))
    if m is not None:
        data["Location-hiding encryption"].append(float(m.group(1)))
        print("elgamal match")

    m = re.match(r"------ Puncturable Encryption time: (\d+\.\d+), (.+)", str(line))
    if m is not None:
        data["Puncturable encryption"].append(float(m.group(1)))
        print("punc enc match")
data["Public-key encryption"].append(data["Puncturable encryption"][0])
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
        data["Public-key encryption"] = float(m.group(1))
        print("baseline match")
data["Log"].append(0)
data["Location-hiding encryption"].append(0)
data["Puncturable encryption"].append(0)
print("Done with baseline")

# Plot
bmap1 = brewer2mpl.get_map('Set1', 'Qualitative', 7)
bmap2 = brewer2mpl.get_map('Dark2', 'Qualitative', 7)
hash_colors = bmap1.mpl_colors
mix_colors = bmap2.mpl_colors

extras = {'edgecolor': 'black', 'linewidth': 0.5}
legend_labels = ["Log", "Location-hiding encryption", "Puncturable encryption",
        "Public-key encryption"]
color_map = {"Puncturable encryption": hash_colors[1], "Log": mix_colors[2], "Location-hiding encryption":
        hash_colors[4], "Public-key encryption": mix_colors[0]}



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
for bar_index in range(len(legend_labels)):
    stage = legend_labels[bar_index]
    #stages.append(stage)
    left = np.zeros(len(data))
    patch = None
    for i in range(len(data[stage])):
        data_arr = np.zeros(len(data))
        print(data_arr)
        print(data)
        data_arr[bar_index] = data[stage][i]
        color = color_map[stage]
        patch_handle = ax.barh(y_pos, data_arr - left, align='center', left=left, color=color, **extras)
        patch = patch_handle.get_children()[bar_index]
        bl = patch.get_xy()
        x = 0.5*patch.get_width() + bl[0]
        y = 0.5*patch.get_height() + bl[1]
        val = data[stage][i]
        if i > 0:
            val -= data[stage][i-1]
        if val > 0.1:
            ax.text(x, y, float("{0:.2f}".format(val)), ha='center', va='center', color='w', fontsize=8)
        patch_handles.append(patch_handle)
        left = data_arr
    ax.text(patch.get_x() + patch.get_width() + 0.05, patch.get_y() +
        patch.get_height() / 2.0,
        "%s" %
        (float(data[stage][len(data[stage])-1])), ha='left',
        va='center', fontsize=8.5, bbox=bgbox)


    print("final left: ")
    print(left)

ax.set_yticks(y_pos_ticks)
#ax.set_yticklabels(stages_label, fontsize=8)
ax.set_xlabel(r'\textbf{Recovery time (s)}')

legend_elements = []
for label in legend_labels:
    legend_elements.append(Patch(color=color_map[label], label=label))



plt.savefig("recovery_breakdown.png")
plt.show()
#custom_style.save_fig(fig, out_name, [1.9, 2.1])
