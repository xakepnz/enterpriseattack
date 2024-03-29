## enterpriseattack - MITRE's Enterprise ATT&CK®

A lightweight Python module to interact with the [MITRE ATT&CK](https://attack.mitre.org/) Enterprise dataset. Built to be used in production applications due to it's speed and minimal depedancies. [Read the docs](https://gitlab.com/xakepnz/enterpriseattack/tree/main/docs) for more info.

## MITRE ATT&CK®

MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

### Dependancies

* Python 3.x
* ujson >= 3.0.0
* requests >= 2.9.2

## Installation

### Install via Pip:
   ```sh
   pip3 install enterpriseattack
   ```

### Alternatively clone the repository:
   ```sh
   git clone https://gitlab.com/xakepnz/enterpriseattack.git
   cd enterpriseattack
   python3 setup.py install
   ```

<p align="right">(<a href="#top">back to top</a>)</p>

## Docker:

### Build the docker image:

```sh
docker build enterpriseattack:0.1.8 .
docker tag enterpriseattack:0.1.8 enterpriseattack:latest
```

### Run the benchmarks on the container:
```sh
docker run enterpriseattack
```

<p align="right">(<a href="#top">back to top</a>)</p>

## Usage

### Initialise an Attack object:
```py
import enterpriseattack

attack = enterpriseattack.Attack()
```

### Example Subscriptable objects:
Access any object directly from the Attack class, rather than iterating to find specific objects.

```py
attack = enterpriseattack.Attack(subscriptable=True)

wizard_spider = attack.groups.get('Wizard Spider')
print(len(wizard_spider.tactics))

execution = attack.tactics.get('Execution')
print(len(execution.techniques))
```

### Example: Passing custom args:
In this example, you can choose where to download the official Mitre Att&ck json from, including proxies to pass through. Alternatively, if you want to save the json file in a separate location, you can alter the enterprise_json arg. By default this is saved within your default site-packages location.

* `enterprise_json` - (optional) location of enterprise json file, (saved automatically in pip location)
* `url` - (optional) location of enterprise json file to download from.
* `update` - (optional) boolean forces a refresh download (each time this is called), overwriting the previous file.
* `include_deprecated` - (optional) boolean to include MITRE ATT&CK deprecated objects (from previous Att&ck versions).
* `mitre_version` - (optional) specify a MITRE ATT&CK data version.
* `proxies` - (optional) dict of proxies to pass through to reach the MITRE GitHub for the enterprise-attack.json.

```py
attack = enterpriseattack.Attack(
   enterprise_json=None,
   url='https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
   include_deprecated=False,
   update=False,
   subscriptable=True,
   mitre_version='latest',
   proxies={'http':'http://127.0.0.1:1337'}
)
```

### Example: Force Download/use an older MITRE ATT&CK data set:
```py
attack = enterpriseattack.Attack(
   mitre_version='11.3',
   update=True
)

print(attack.mitre_version)
```

### Example: Iterate over tactics/techniques/sub_techniques:
```py
attack = enterpriseattack.Attack()

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

### Example: Create a json object of any tactic/technique/sub_technique/group/software/datasource:
```py
attack = enterpriseattack.Attack()

for tactic in attack.tactics:
   print(tactic.to_json())

for group in attack.groups:
   print(group.to_json())

...
```

For more examples, please refer to the [Documentation](https://gitlab.com/xakepnz/enterpriseattack/tree/main/docs)

<p align="right">(<a href="#top">back to top</a>)</p>
