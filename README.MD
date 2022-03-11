Bitcoin Extractor
================

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0) ![This script was last tested in Nuix 9.6](https://img.shields.io/badge/Script%20Tested%20in%20Nuix-9.6-green.svg)

View the GitHub project [here](https://github.com/Nuix/Bitcoin-Extractor) or download the latest release [here](https://github.com/Nuix/Bitcoin-Extractor/releases).

# Overview

This repository contains 2 scripts to assist with extraction and verification of Bitcoin addresses.

**Important:** This script is mainted by it's original author Harry F. of [SWRCCU](https://www.swrocu.police.uk/cyber-crime/).  If you have questions or wish to report an issue, please contact [swrccu@avonandsomerset.police.uk](mailto:swrccu@avonandsomerset.police.uk?subject=Bitcoin%20Extractor).

## Nuix Bitcoin Extractor

[Nuix Bitcoin Extractor.rb](https://github.com/Nuix/Bitcoin-Extractor/blob/main/Scripts/Nuix%20Bitcoin%20Extractor.rb)

Script to extract all `P2PKH`, `P2SH`, `Bech32` Bitcoin addresses/Extended Public and Private Keys (`xPubs`/`xPrvs`) from any Nuix Workstation instance. Located addresses are exported to a CSV file alongside *GUID* and *File Path*.

**P2PKH and P2SH validation code from savasadar github**

https://gist.github.com/savasadar/efd9e2a6a6540dd2b33b2a24a7996c8e

**Bech32 Checksum validation code from sipa GitHub (Pieter Wuille)**

https://github.com/sipa/bech32/tree/master/ref/ruby


Items which have an address located within them are added to an item set named **Bitcoin Extraction**.  Located addresses are recorded to a CSV in the specified output directory.  Errors are recorded to a second CSV in the specified output directory.

**LIMITATION:** Items with a **File Size** greater than 2GB (2000000000 bytes) are skipped to avoid possible issue where content text of item can exceed Java maximum String length of 2147483647 bytes.

**KNOWN ERROR:** Some false positives may still be exported, use the companion script **OSINT Nuix BTC Extractor Verify** to validate addresses.

## OSINT Nuix BTC Extractor Verify

[OSINT Nuix BTC Extractor verify.py](https://github.com/Nuix/Bitcoin-Extractor/blob/main/Scripts/OSINT%20Nuix%20BTC%20Extractor%20verify.py)

Script to ingest Nuix Bitcoin extraction script CSV result and lookup each address for num transactions/other btc details.

Any invalid addresses are void, `xyzPubs`/`xyzPrivs` are not looked up.

Once you have a CSV produced by **Nuix Bitcoin Extractor.rb**:

1. Copy that CSV to the same directory as the **OSINT Nuix BTC Extractor verify.py**
1. Run **OSINT Nuix BTC Extractor verify.py** in Python
1. When prompted, enter the number that corresponds to the CSV you wish to run the script on.

See **Setup** section below for details on first time setup of the **OSINT Nuix BTC Extractor Verify** script.

# Getting Started

## Setup

Begin by downloading the latest release of this code.  Extract the contents of the archive into your Nuix scripts directory.  In Windows the script directory is likely going to be either of the following:

- `%appdata%\Nuix\Scripts` - User level script directory
- `%programdata%\Nuix\Scripts` - System level script directory

[OSINT Nuix BTC Extractor verify.py](https://github.com/Nuix/Bitcoin-Extractor/blob/main/Scripts/OSINT%20Nuix%20BTC%20Extractor%20verify.py) is a secondary script to validate extracted addresses in a CSV.  It is intended to be ran outside of Nuix on an *internet connected machine*.  On the *internet connected machine* in which you intend to to run **OSINT Nuix BTC Extractor Verify**:

1. Install [Python 3.x](https://www.python.org/downloads/) (script tested against Python 3.6)
1. Once installed, from a Command Prompt / Terminal shell type `pip install blockchain` to install module dependencies

# Cloning this Repository

The **Nuix Bitcoin Extractor.rb** script relies on code from [Nx](https://github.com/Nuix/Nx) to present a settings dialog and progress dialog.  This JAR file is not included in the repository (although it is included in release downloads).  If you clone this repository, you will also want to obtain a copy of Nx.jar by either:
1. Building it from [the source](https://github.com/Nuix/Nx)
2. Downloading an already built JAR file from the [Nx releases](https://github.com/Nuix/Nx/releases)

Once you have a copy of Nx.jar, make sure to include it in the same directory as the **Nuix Bitcoin Extractor.rb** script.

# License

```
Copyright 2022 South West Regional Organised Cyber Crime Unit (SWRCCU)
https://www.swrocu.police.uk/cyber-crime/

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
