# Groups

Groups are sets of related intrusion activity that are tracked by a common name in the security community. Analysts track clusters of activities using various analytic methodologies and terms such as threat groups, activity groups, threat actors, intrusion sets, and campaigns. Some groups have multiple names associated with similar activities due to various organizations tracking similar activities by different names. Organizations' group definitions may partially overlap with groups designated by other organizations and may disagree on specific activity. [Read More](https://attack.mitre.org/groups/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
groups = attack.groups
```

## Main Attributes:
```py
for group in attack.groups:
    print(group.id) # The human-readable ID
    print(group.mid) # The Mitre ID
    print(group.created) # Date created
    print(group.modified) # Date modified
    print(group.created_by_ref) # Whom created this
    print(group.object_marking_ref) # Copyright marking
    print(group.aliases) # Other names this group is known by
    print(group.name) # Name of object
    print(group.type) # Type of object
    print(group.description) # Description of object
    print(group.references) # Online references to this object
    print(group.url) # URL to mitre attack page
    print(group.revoked) # Has this been merged into another object or not
    print(group.deprecated) # Has this object been deprecated from the framework
```

## Extra Attributes:
```py
for group in attack.groups:
    for malware in group.malware:
        for tool in group.tools:
            pass
    for software in group.software:
        print(software.name) # Software name
        # Access all of the software attributes...
    for technique in group.techniques:
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

groups = attack.groups

for group in groups:
    print(group.to_json())
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
    "aliases": self.aliases,
    "tactics": [tactic.name for tactic in self.tactics],
    "techniques": [technique.name for technique in self.techniques],
    "software": [{tool.type:tool.name} for tool in self.software],
    "malware": [malware.name for malware in self.malware],
    "tools": [tool.name for tool in self.tools],
    "references": self.references,
    "deprecated": self.deprecated,
    "revoked": self.revoked
}
```

<p align="right">(<a href="#top">back to top</a>)</p>