# Software

Software is a generic term for custom or commercial code, operating system utilities, open-source software, or other tools used to conduct behavior modeled in ATT&CK. Some instances of software have multiple names associated with the same instance due to various organizations tracking the same set of software by different names. The team makes a best effort to track overlaps between names based on publicly reported associations, which are designated as “Associated Software” on each page (formerly labeled “Aliases”), because we believe these overlaps are useful for analyst awareness.

* Tool - Commercial, open-source, built-in, or publicly available software that could be used by a defender, pen tester, red teamer, or an adversary. This category includes both software that generally is not found on an enterprise system as well as software generally available as part of an operating system that is already present in an environment. Examples include PsExec, Metasploit, Mimikatz, as well as Windows utilities such as Net, netstat, Tasklist, etc.
* Malware - Commercial, custom closed source, or open source software intended to be used for malicious purposes by adversaries. Examples include PlugX, CHOPSTICK, etc. [Read more](https://attack.mitre.org/software/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
software = attack.software
```

## Main Attributes:
```py
for software in attack.software:
    print(software.id) # The human-readable ID
    print(software.mid) # The Mitre ID
    print(software.created) # Date created
    print(software.modified) # Date modified
    print(software.created_by_ref) # Whom created this
    print(software.object_marking_ref) # Copyright marking
    print(software.name) # Name of object
    print(software.type) # Type of object
    print(software.description) # Description of object
    print(software.references) # Online references to this object
    print(software.url) # URL to mitre attack page
    print(software.revoked) # Has this been merged into another object or not
    print(software.deprecated) # Has this object been deprecated from the framework
    print(software.platforms) # OS platforms that this software runs on
    print(software.labels) # Define if it's a tool/malware
```

## Extra Attributes:
```py
for software in attack.softwares:
    for group in software.groups:
        print(group.name) # Group name
        # Access all of the group attributes...
    for technique in software.techniques:
        print(technique.name) # Technique name
        # Access all of the techniques attributes...
        for sub_technique in technique.sub_techniques:
            print(sub_technique.name) # Sub technique name
            # Access all of the sub techniques attributes...
```

## Functions:

* to_json - Returns a dict of the object in json format:

```py
import enterpriseattack

attack = enterpriseattack.Attack()

software = attack.software

for software in software:
    print(software.to_json())
```

```json
{
    "id": self.id,
    "mid": self.mid,
    "created": self.created,
    "modified": self.modified,
    "created_by_ref": self.created_by_ref,
    "object_marking_ref": self.object_marking_ref,
    "name": self.name,
    "type": self.type,
    "description": self.description,
    "url": self.url,
    "references": self.references,
    "labels": self.labels,
    "groups": [group.name for group in self.groups],
    "techniques": [technique.name for technique in self.techniques],
    "platforms": self.platforms,
    "type": self.type,
    "deprecated": self.deprecated,
    "revoked": self.revoked
}
```

<p align="right">(<a href="#top">back to top</a>)</p>