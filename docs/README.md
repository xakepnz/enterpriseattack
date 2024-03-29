## Table of Contents

- [What is MITRE ATT&CK?](#what-is-mitre-attck)
    - [What is enterpriseattack?](#what-is-enterpriseattack)
- [Getting Started](#getting-started)
    - [Install via pip](#install-via-pip)
    - [Install via git](#install-via-github)
- [Tactics](Tactics.md)
- [Techniques](Techniques.md)
- [Sub Techniques](SubTechniques.md)
- [Groups](Groups.md)
- [Mitigations](Mitigations.md)
- [Software (Tools/Malware)](Software.md)
- [Datasources](Datasources.md)
- [Components](Components.md)
- [Campaigns](Campaigns.md)

## What is MITRE ATT&CK?

MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community. [Read more](https://attack.mitre.org/)

## What is enterpriseattack?

A lightweight Python module to interact with the [MITRE ATT&CK](https://attack.mitre.org/) Enterprise dataset. Built to be used in production applications due to it's speed and minimal depedancies. This module does not cover ICS or Mobile.

# Getting Started

If network access restrictions apply to your situation, you can download the [MITRE ATT&CK Enterprise Json file](https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json) and package it into a local directory. For example with Docker packaging with your application, and transferring the json file into the container. The only network connections occur when there's either no file to leverage locally, or if you wish to overwrite the existing file.

## Install via Pip:

```bash
pip3 install enterpriseattack
```

## Install via GitLab:

```bash
git clone https://gitlab.com/xakepnz/enterpriseattack.git
cd enterpriseattack
python3 setup.py install
```

## Initialization:

These are the default values when initializing the attack class:
* `enterprise_json` - The full file-path to the local json.
* `url` - The URL that hosts the json, defaults to the official MITRE ATT&CK® Github.
* `include_deprecated` - Include old objects that mitre have removed from later versions.
* `update` - Force a download of the url, and rewrite the enterprise_json file.
* `mitre_version` - Choose a specific version of the MITRE ATT&CK data to download (default is latest).
* `subscriptable` - Access objects via their `name` attr, directly from the Attack class.


```py
import enterpriseattack

attack = enterpriseattack.Attack(
    enterprise_json=None,
    url='https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    include_deprecated=False,
    update=False,
    mitre_version='latest',
    subscriptable=True
)
```
That's it! Check out the other docs to learn more.

<p align="right">(<a href="#top">back to top</a>)</p>
