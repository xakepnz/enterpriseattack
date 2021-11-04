[![PyPI version](https://badge.fury.io/py/enterpriseattack.svg)](https://badge.fury.io/py/enterpriseattack)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![image](https://img.shields.io/pypi/pyversions/enterpriseattack.svg)](https://pypi.org/project/enterpriseattack/)


## enterpriseattack - Mitre's Enterprise Att&ck

A lightweight Python module to interact with the [Mitre Att&ck](https://attack.mitre.org/) Enterprise dataset. Built to be used in production applications due to it's speed and minimal depedancies. [Read the docs](https://github.com/xakepnz/enterpriseattack/tree/main/docs) for more info.

## Mitre Att&ck

MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

### Dependancies

* Python 3.x
* ujson >= 3.0.0
* requests >= 2.9.2

## Installation

### Install via Pip:
   ```sh
   pip install enterpriseattack
   ```

### Alternatively clone the repository:
   ```sh
   git clone https://github.com/xakepnz/enterpriseattack.git
   cd enterpriseattack
   python3 setup.py install
   ```

<p align="right">(<a href="#top">back to top</a>)</p>

## Usage

### Initialise an Attack object:
```py
import enterpriseattack

attack = enterpriseattack.Attack()
```

### Example: Iterate over tactics/techniques/sub_techniques:
```py
for tactic in attack.tactics:
   print(tactic.name)
   for technique in tactic.techniques:
      print(technique.name)
      print(technique.detection)

for software in attack.software:
    for technique in software.techniques:
        for sub_technique in technique.sub_techniques:
            print(software.name, technique.name, sub_technique.name)
```

For more examples, please refer to the [Documentation](https://github.com/xakepnz/enterpriseattack/tree/main/docs)

<p align="right">(<a href="#top">back to top</a>)</p>
