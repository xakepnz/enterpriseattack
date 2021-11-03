# Techniques

Techniques represent 'how' an adversary achieves a tactical goal by performing an action. For example, an adversary may dump credentials to achieve credential access. [Read more](https://attack.mitre.org/techniques/enterprise/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
techniques = attack.techniques
```

## Main Attributes:
```py
for technique in attack.techniques:
    print(technique.id) # The human-readable ID
    print(technique.mid) # The Mitre ID
    print(technique.created) # Date created
    print(technique.modified) # Date modified
    print(technique.created_by_ref) # Whom created this
    print(technique.object_marking_ref) # Copyright marking
    print(technique.name) # Name of object
    print(technique.type) # Type of object
    print(technique.description) # Description of object
    print(technique.references) # Online references to this object
    print(technique.url) # URL to mitre attack page
    print(technique.revoked) # Has this been merged into another object or not
    print(technique.deprecated) # Has this object been deprecated from the framework
    print(technique.x_mitre_data_sources) # Datasources associated with this technique
    print(technique.detection) # A possible detection for this technique
    print(technique.platforms) # A possible detection for this technique
    print(technique.permissions_required) # A possible detection for this technique
    print(technique.kill_chain_phases) # Tactics for this technique
```

## Extra Attributes:
```py
for technique in attack.techniques:
    for mitigation in technique.mitigations:
        print(mitigation.name) # Mitigation name
        # Access all of the mitigation attributes...
    for group in technique.groups:
        print(group.name) # Group name
        # Access all of the group attributes...
    for tactic in technique.tactics:
        print(tactic.name) # Tactic name
        # Access all of the tactic attributes...
    for datasource in technique.datasources:
        print(datasource.name) # Datasource name
        # Access all of the datasource attributes...
    for sub_technique in technique.sub_techniques:
        print(sub_technique.name) # sub_technique name
        # Access all of the sub_technique attributes...
```

## Functions:

* to_json - Returns a dict of the object in json format:

```py
import enterpriseattack

attack = enterpriseattack.Attack()

technique = attack.techniques

for technique in techniques:
    print(technique.to_json())
```

```json
{
    "id": self.id,
    "mid": self.mid,
    "created": self.created,
    "modified": self.modified,
    "created_by_ref": self.created_by_ref,
    "object_marking_ref": self.object_marking_ref,
    "permissions_required": self.permissions_required,
    "platforms": self.platforms,
    "name": self.name,
    "type": self.type,
    "description": self.description,
    "url": self.url,
    "detection": self.detection,
    "tactics": [tactic.name for tactic in self.tactics],
    "sub_techniques": [sub_technique.name for sub_technique in self.sub_techniques],
    "datasources": [datasource.name for datasource in self.datasources],
    "groups": [group.name for group in self.groups],
    "deprecated": self.deprecated,
    "revoked": self.revoked,
    "references": self.references,
    "kill_chain_phases": self.kill_chain_phases
}
```

<p align="right">(<a href="#top">back to top</a>)</p>