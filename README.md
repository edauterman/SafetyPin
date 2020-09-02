# SafetyPin

SafetyPin is a system for encrypted backups that provides a strong defense against hardware compromise. The system only requires users to remember a short PIN and defends against brute-force PIN-guessing attacks while protecting against an attacker that can adaptively compromise many hardware elements. 

The implementation is split into two components:
- **HSM**: The HSMs (hardware security modules) are used to store user secrets. We implement the HSM functionality on [SoloKeys](https://solokeys.com/).
- **Host**: The host is not run on any special hardware and simply coordinates the HSMs.

**WARNING**: This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

This prototype is released under the Apache v2 license (see [License](#license)).

If setting up your own system, please read the instructions [here](#setup). If running artifact evaluation, please read the instructions below.

## Instructions for artifact evaluation

SSH into the test machine using the credentials provided separately. All the HSMs are connected to the machine via USB and flashed with the correct firmware. The code on the host is already built (you can rebuild the code by running `make` in `host/`.

To run all the experiments and generate all the plots, run:
 ```
cd bench
./runAll.sh     # 50 minutes
```

This will produce figures 8, 9, 10, and 11 in the `bench/out` folder. Details about running these experiments and the plots that are produced are included below. The figures we generated running the same scripts are included in `bench/ref`.

Each experiment follows the same general pattern. To run the experiment for Figure x, go to the `bench` folder and run `python3 exp_figx.py`, which will output raw data in `out/figx.dat`. To plot the data, run `python3 plot_figx.py`.

One caveat: the experiments run using a fixed source of randomness. We found that the SoloKey's RNG will occasionally crash, making it necessary to manually power cycle the key. We ran our experiments using the RNG, but for our experiments, we use a fixed source of randomness.

**Note**: If for some reason an experiment takes significantly longer than the time estimate, please contact the reviewers, as the system may need to be physically reset (for example, due to a poor USB connection).

### Figure 8

Run the experiment and plot the data for Figure 8 showing datacenter size vs audit time:

```
cd bench
python3 exp_fig8.py     # 16 minutes 
python3 plot_fig8.py    # few seconds
```

This will produce a plot close to Figure 8 on page 11 in the paper in `bench/out/fig8.png`. Use `scp` to copy this figure back to your local machine.

The only difference from the Figure 8 included in the paper is that we use 90 HSMs instead of 100 HSMs for this experiment (the remaining 10 HSMs have different firmware used to generate figure 9). To generate the figure in the paper, we reflashed HSMs between experiments (which we cannot be done remotely). The figure we generated using 90 HSMs is below for comparison:

<img src="https://github.com/edauterman/SafetyPin/blob/master/bench/ref/fig8.png" width="400">

### Figure 9 

Run the experiment and plot the data for Figure 9 showing how the number of recoveries before key rotation affects the time to decrypt and puncture:

```
cd SafetyPin/bench
python3 exp_fig9.py     # 20 minutes
python3 plot_fig9.py    # few seconds
```

This will produce a plot matching Figure 9 on page 11 in the paper in `bench/out/fig9.png`. Use `scp` to copy this figure back to your local machine.

Note that this experiment uses 10 HSMs that are flashed with firmware using different parameter settings. Between each experiment run, the code at the host is recompiled using a different setting of constants.

We include the figure we genereated below for reference:

<img src="https://github.com/edauterman/SafetyPin/blob/master/bench/ref/fig9.png" width="400">

### Figure 10

Run the experiment and plot the data for part of Figure 10 showing the breakdown for recovery time with a cluster of 40 HSMs:

```
cd SafetyPin/bench
python3 exp_fig10.py     # 2 minutes
python3 plot_fig10.py    # few seconds
```

This will produce a plot matching the right half of Figure 10 on page 11 in the paper (breakdown of recovery time) in `bench/out/fig10.png`. Use `scp` to copy this figure back to your local machine.

Note that this figure looks slightly different than the one in the camera-ready because since submission, we fixed a bug that increased the log time.

We incldue the figure we generated below for reference:

<img src="https://github.com/edauterman/SafetyPin/blob/master/bench/ref/fig10.png" width="400">

### Figure 11

Run the experiment and plot the data for Figure 11 showing how recovery time changes with cluster size:

```
cd SafetyPin/bench
python3 exp_fig11.py     # 10 minutes
python3 plot_fig11.py    # few seconds
```

This will produce a plot matching Figure 11 on page 12 up to a cluster size of 90 HSMs in `bench/out/fig11.png`. Use `scp` to copy this figure back to your local machine.

We only measure up to 90 HSMs because we reserve the last 10 HSMs for the experiment for figure 10, which requires the HSMs to use firmware with a different setting of the parameters. Note that this figure looks slightly different than the one in the camera-ready because since submission, we fixed a bug that increased the log time.

We include the figure we generated (only up to 90 HSMs) below for reference:

<img src="https://github.com/edauterman/SafetyPin/blob/master/bench/ref/fig11.png" width="400">

## Acknowledgements
The code for the HSMs was adapted from the [SoloKey project](https://github.com/solokeys/solo).
The original source of the `jedi-pairing` library is available [here](https://github.com/ucbrise/jedi-pairing). Some of the USB HID code is based on [u2f-ref-code](https://github.com/google/u2f-ref-code).

