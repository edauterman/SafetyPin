[![latest release](https://img.shields.io/github/release/solokeys/solo.svg)](https://update.solokeys.com/)
[![Keybase Chat](https://img.shields.io/badge/chat-on%20keybase-brightgreen.svg)](https://keybase.io/team/solokeys.public)
[![Build Status](https://travis-ci.com/solokeys/solo.svg?style=flat-square&branch=master)](https://travis-ci.com/solokeys/solo)

Solo is an open source security key, and you can get one at [solokeys.com](https://solokeys.com).

[<img src="https://static.solokeys.com/images/photos/hero-on-white-cropped.png" width="600">](https://solokeys.com)

Solo supports FIDO2 and U2F standards for strong two-factor authentication and password-less login, and it will protect you against phishing and other online attacks. With colored cases and multilingual guides we want to make secure login more personable and accessible to everyone around the globe.

This repo contains the Solo firmware, including implementations of FIDO2 and U2F (CTAP2 and CTAP) over USB and NFC. The main implementation is for STM32L432, but it is easily portable.

For development no hardware is needed, Solo also runs as a standalone application for Windows, Linux, and Mac OSX. If you like (or want to learn) hardware instead, you can run Solo on the NUCLEO-L432KC development board, or we make Solo for Hacker, an unlocked version of Solo that lets you customize its firmware.


# Security

Solo is based on the STM32L432 microcontroller. It offers the following security features.

- True random number generation to guarantee random keys.
- Security isolation so only simple & secure parts of code can handle keys.
- Flash protection from both external use and untrusted code segments.
- 256 KB of memory to support hardened crypto implementations and, later, additional features such as OpenPGP or SSH.
- No NDA needed to develop for.


# Solo for Hackers

Solo for Hacker is a special version of Solo that let you customize its firmware, for example you can change the LED color, and even build advanced applications.

Check out [solokeys.com](https://solokeys.com), for options on where to buy Solo.  Solo Hacker can be converted to a secure version, but normal Solo cannot be converted to a Hacker version.

If you have a Solo for Hacker, here's how you can load your own code on it. You can find more details, including how to permanently lock it, in our [documentation](https://docs.solokeys.io/solo/building/). We support Python3.

For example, if you want to turn off any blue light emission, you can edit [`led_rgb()`](https://github.com/solokeys/solo/blob/master/targets/stm32l432/src/app.h#L48) and change `LED_INIT_VALUE`
to be a different hex color.

Then recompile, load your new firmware, and enjoy a different LED color Solo.

In the Hacker version, hardware is the same but the firmware is unlocked, so you can 1) load an unsigned application, or 2) entirely reflash the key. By contrast, in a regular Solo you can only upgrade to a firmware signed by SoloKeys, and flash is locked and debug disabled permanently.

Hacker Solo isn't really secure so you should only use it for development. An attacker with physical access to a Solo for Hacker can reflash it following the steps above, and even a malware on your computer could possibly reflash it.

## Checking out the code
```bash
git clone --recurse-submodules https://github.com/solokeys/solo
cd solo
```

If you forgot the `--recurse-submodules` while cloning, simply run `git submodule update --init --recursive`.

`make update` will also checkout the latest code on `master` and submodules.

## Checking out the code to build a specific version

You can checkout the code to build a specific version of the firmware with:
```
VERSION_TO_BUILD=2.5.3
git fetch --tags
git checkout ${VERSION_TO_BUILD}
git submodule update --init --recursive
```

## Installing the toolchain

In order to compile ARM code, you need the ARM compiler and other things like bundling bootloader and firmware require the `solo-python` python package. Check our [documentation](https://docs.solokeys.io/solo/) for details

## Installing the toolkit and compiling in Docker 
Alternatively, you can use Docker to create a container with the toolchain.
You can run:

```bash
# Build the toolchain container
make docker-build-toolchain 

# Build all versions of the firmware in the "builds" folder
make docker-build-all
```

The `builds` folder will contain all the variation on the firmware in `.hex` files.

## Build locally

If you have the toolchain installed on your machine you can build the firmware with: 

```bash
cd targets/stm32l432
make cbor
make build-hacker
cd ../..

make venv
source venv/bin/activate
solo program aux enter-bootloader
solo program bootloader targets/stm32l432/solo.hex
```

# Developing Solo (No Hardware Needed)

Clone Solo and build it

```bash
git clone --recurse-submodules https://github.com/solokeys/solo
cd solo
make all
```

This builds Solo as a standalone application. Solo application is set up to send and recv USB HID messages over UDP to ease development and reduce need for hardware.

Testing can be done using our fork of Yubico's client software, python-fido2. Our fork of python-fido2 has small changes to make it send USB HID over UDP to the authenticator application. You can install our fork by running the following:

```bash
pip install -r tools/requirements.txt
```

Run the Solo application:
```bash
./main
```

In another shell, you can run our [test suite](https://github.com/solokeys/fido2-tests).

You can find more details in our [documentation](https://docs.solokeys.io/solo/), including how to build on the the NUCLEO-L432KC development board.


# Documentation

Check out our [official documentation](https://docs.solokeys.io/solo/).


# Contributors ✨

Solo is an upgrade to [U2F Zero](https://github.com/conorpp/u2f-zero). It was born from Conor's passion for making secure hardware, and from our shared belief that security should be open to be trustworthy, in hardware like in software.

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
The ultimate goal is to have a FIDO2 security key supporting USB, NFC, and BLE interfaces, that can run on a variety of MCUs.
Look at the issues to see what is currently being worked on. Feel free to add issues as well.

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/szszszsz"><img src="https://avatars0.githubusercontent.com/u/17005426?v=4" width="100px;" alt="Szczepan Zalega"/><br /><sub><b>Szczepan Zalega</b></sub></a><br /><a href="https://github.com/solokeys/solo/commits?author=szszszsz" title="Code">💻</a> <a href="https://github.com/solokeys/solo/commits?author=szszszsz" title="Documentation">📖</a> <a href="#ideas-szszszsz" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/Wesseldr"><img src="https://avatars1.githubusercontent.com/u/4012809?v=4" width="100px;" alt="Wessel dR"/><br /><sub><b>Wessel dR</b></sub></a><br /><a href="https://github.com/solokeys/solo/commits?author=Wesseldr" title="Documentation">📖</a></td>
    <td align="center"><a href="https://www.imperialviolet.org"><img src="https://avatars3.githubusercontent.com/u/21203?v=4" width="100px;" alt="Adam Langley"/><br /><sub><b>Adam Langley</b></sub></a><br /><a href="https://github.com/solokeys/solo/issues?q=author%3Aagl" title="Bug reports">🐛</a> <a href="https://github.com/solokeys/solo/commits?author=agl" title="Code">💻</a></td>
    <td align="center"><a href="http://www.lotteam.com"><img src="https://avatars2.githubusercontent.com/u/807634?v=4" width="100px;" alt="Oleg Moiseenko"/><br /><sub><b>Oleg Moiseenko</b></sub></a><br /><a href="https://github.com/solokeys/solo/commits?author=merlokk" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/aseigler"><img src="https://avatars1.githubusercontent.com/u/6605560?v=4" width="100px;" alt="Alex Seigler"/><br /><sub><b>Alex Seigler</b></sub></a><br /><a href="https://github.com/solokeys/solo/issues?q=author%3Aaseigler" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://www.cotech.de/services/"><img src="https://avatars3.githubusercontent.com/u/321888?v=4" width="100px;" alt="Dominik Schürmann"/><br /><sub><b>Dominik Schürmann</b></sub></a><br /><a href="https://github.com/solokeys/solo/issues?q=author%3Adschuermann" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/ehershey"><img src="https://avatars0.githubusercontent.com/u/286008?v=4" width="100px;" alt="Ernie Hershey"/><br /><sub><b>Ernie Hershey</b></sub></a><br /><a href="https://github.com/solokeys/solo/commits?author=ehershey" title="Documentation">📖</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/YakBizzarro"><img src="https://avatars1.githubusercontent.com/u/767740?v=4" width="100px;" alt="Andrea Corna"/><br /><sub><b>Andrea Corna</b></sub></a><br /><a href="#infra-YakBizzarro" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a></td>
    <td align="center"><a href="https://place.org/~pj/"><img src="https://avatars3.githubusercontent.com/u/11100?v=4" width="100px;" alt="Paul Jimenez"/><br /><sub><b>Paul Jimenez</b></sub></a><br /><a href="#infra-pjz" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/solokeys/solo/commits?author=pjz" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/yparitcher"><img src="https://avatars0.githubusercontent.com/u/38916402?v=4" width="100px;" alt="yparitcher"/><br /><sub><b>yparitcher</b></sub></a><br /><a href="#ideas-yparitcher" title="Ideas, Planning, & Feedback">🤔</a> <a href="#maintenance-yparitcher" title="Maintenance">🚧</a></td>
    <td align="center"><a href="https://github.com/StoyanDimitrov"><img src="https://avatars1.githubusercontent.com/u/10962709?v=4" width="100px;" alt="StoyanDimitrov"/><br /><sub><b>StoyanDimitrov</b></sub></a><br /><a href="https://github.com/solokeys/solo/commits?author=StoyanDimitrov" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/alphathegeek"><img src="https://avatars2.githubusercontent.com/u/51253712?v=4" width="100px;" alt="alphathegeek"/><br /><sub><b>alphathegeek</b></sub></a><br /><a href="#ideas-alphathegeek" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://xakcop.com"><img src="https://avatars2.githubusercontent.com/u/271616?v=4" width="100px;" alt="Radoslav Gerganov"/><br /><sub><b>Radoslav Gerganov</b></sub></a><br /><a href="#ideas-rgerganov" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/solokeys/solo/commits?author=rgerganov" title="Code">💻</a></td>
    <td align="center"><a href="http://13-37.org"><img src="https://avatars3.githubusercontent.com/u/10274356?v=4" width="100px;" alt="Manuel Domke"/><br /><sub><b>Manuel Domke</b></sub></a><br /><a href="#ideas-manuel-domke" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/solokeys/solo/commits?author=manuel-domke" title="Code">💻</a> <a href="#business-manuel-domke" title="Business development">💼</a></td>
  </tr>
  <tr>
    <td align="center"><a href="http://1bitsquared.com"><img src="https://avatars3.githubusercontent.com/u/17334?v=4" width="100px;" alt="Piotr Esden-Tempski"/><br /><sub><b>Piotr Esden-Tempski</b></sub></a><br /><a href="#business-esden" title="Business development">💼</a></td>
    <td align="center"><a href="https://github.com/m3hm00d"><img src="https://avatars1.githubusercontent.com/u/42179593?v=4" width="100px;" alt="f.m3hm00d"/><br /><sub><b>f.m3hm00d</b></sub></a><br /><a href="https://github.com/solokeys/solo/commits?author=m3hm00d" title="Documentation">📖</a></td>
    <td align="center"><a href="http://blogs.gnome.org/hughsie/"><img src="https://avatars0.githubusercontent.com/u/151380?v=4" width="100px;" alt="Richard Hughes"/><br /><sub><b>Richard Hughes</b></sub></a><br /><a href="#ideas-hughsie" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/solokeys/solo/commits?author=hughsie" title="Code">💻</a> <a href="#infra-hughsie" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="#tool-hughsie" title="Tools">🔧</a></td>
    <td align="center"><a href="http://www.schulz.dk"><img src="https://avatars1.githubusercontent.com/u/1150049?v=4" width="100px;" alt="Kim Schulz"/><br /><sub><b>Kim Schulz</b></sub></a><br /><a href="#business-kimusan" title="Business development">💼</a> <a href="#ideas-kimusan" title="Ideas, Planning, & Feedback">🤔</a></td>
    <td align="center"><a href="https://github.com/oplik0"><img src="https://avatars2.githubusercontent.com/u/25460763?v=4" width="100px;" alt="Jakub"/><br /><sub><b>Jakub</b></sub></a><br /><a href="https://github.com/solokeys/solo/issues?q=author%3Aoplik0" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/jolo1581"><img src="https://avatars1.githubusercontent.com/u/53423977?v=4" width="100px;" alt="Jan A."/><br /><sub><b>Jan A.</b></sub></a><br /><a href="https://github.com/solokeys/solo/commits?author=jolo1581" title="Code">💻</a> <a href="https://github.com/solokeys/solo/commits?author=jolo1581" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/ccinelli"><img src="https://avatars0.githubusercontent.com/u/38021940?v=4" width="100px;" alt="ccinelli"/><br /><sub><b>ccinelli</b></sub></a><br /><a href="#infra-ccinelli" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/solokeys/solo/commits?author=ccinelli" title="Tests">⚠️</a></td>
  </tr>
</table>

<!-- ALL-CONTRIBUTORS-LIST:END -->


# License

Solo is fully open source.

All software, unless otherwise noted, is dual licensed under Apache 2.0 and MIT.
You may use Solo software under the terms of either the Apache 2.0 license or MIT license.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

All hardware, unless otherwise noted, is dual licensed under CERN and CC-BY-SA.
You may use Solo hardware under the terms of either the CERN 2.1 license or CC-BY-SA 4.0 license.

All documentation, unless otherwise noted, is licensed under CC-BY-SA.
You may use Solo documentation under the terms of the CC-BY-SA 4.0 license


[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fsolokeys%2Fsolo.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fsolokeys%2Fsolo?ref=badge_large)

# Where To Buy Solo

You can buy Solo, Solo Tap, and Solo for Hackers at [solokeys.com](https://solokeys.com).

<br/>
<hr/>
<br/>

[![License](https://img.shields.io/github/license/solokeys/solo.svg)](https://github.com/solokeys/solo/blob/master/LICENSE)
[![All Contributors](https://img.shields.io/badge/all_contributors-21-orange.svg?style=flat-square)](#contributors)
[![Build Status](https://travis-ci.com/solokeys/solo.svg?branch=master)](https://travis-ci.com/solokeys/solo)
[![Discourse Users](https://img.shields.io/discourse/https/discourse.solokeys.com/users.svg)](https://discourse.solokeys.com)
[![Keybase Chat](https://img.shields.io/badge/chat-on%20keybase-brightgreen.svg)](https://keybase.io/team/solokeys.public)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fsolokeys%2Fsolo.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fsolokeys%2Fsolo?ref=badge_shield)

[![latest release](https://img.shields.io/github/release/solokeys/solo.svg)](https://github.com/solokeys/solo/releases)
[![commits since last release](https://img.shields.io/github/commits-since/solokeys/solo/latest.svg)](https://github.com/solokeys/solo/commits/master)
[![last commit](https://img.shields.io/github/last-commit/solokeys/solo.svg)](https://github.com/solokeys/solo/commits/master)
[![commit activity](https://img.shields.io/github/commit-activity/m/solokeys/solo.svg)](https://github.com/solokeys/solo/commits/master)
[![contributors](https://img.shields.io/github/contributors/solokeys/solo.svg)](https://github.com/solokeys/solo/graphs/contributors)
