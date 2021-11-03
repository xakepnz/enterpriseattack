# Sub Techniques

Sub Techniques are various types of techniques broken down into separate categories. [Read more](https://attack.mitre.org/techniques/enterprise/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
sub_techniques = attack.sub_techniques
```

## Main Attributes:
```py
for sub_technique in attack.sub_techniques:
    print(sub_technique.id) # The human-readable ID
    print(sub_technique.mid) # The Mitre ID
    print(sub_technique.created) # Date created
    print(sub_technique.modified) # Date modified
    print(sub_technique.created_by_ref) # Whom created this
    print(sub_technique.object_marking_ref) # Copyright marking
    print(sub_technique.name) # Name of object
    print(sub_technique.type) # Type of object
    print(sub_technique.description) # Description of object
    print(sub_technique.references) # Online references to this object
    print(sub_technique.url) # URL to mitre attack page
    print(sub_technique.revoked) # Has this been merged into another object or not
    print(sub_technique.deprecated) # Has this object been deprecated from the framework
    print(sub_technique.x_mitre_data_sources) # Datasources associated with this sub technique
    print(sub_technique.detection) # A possible detection for this sub technique
```

## Extra Attributes:
```py
for sub_technique in attack.sub_techniques:
    for mitigation in sub_technique.mitigations:
        print(mitigation.name) # Mitigation name
        # Access all of the mitigation attributes...
    for group in sub_technique.groups:
        print(group.name) # Group name
        # Access all of the group attributes...
    for tactic in sub_technique.tactics:
        print(tactic.name) # Tactic name
        # Access all of the tactic attributes...
    for technique in sub_technique.techniques:
        print(technique.name) # Technique name
        # Access all of the technique attributes...
    for datasource in sub_technique.datasources:
        print(datasource.name) # Datasource name
        # Access all of the datasource attributes...
```

## Functions:

* to_json - Returns a dict of the object in json format:

```py
import enterpriseattack

attack = enterpriseattack.Attack()

sub_techniques = attack.sub_techniques

for sub_technique in sub_techniques:
    print(sub_technique.to_json())
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
    "deprecated": self.deprecated,
    "revoked": self.revoked,
    "platforms": self.platforms,
    "permissions_required": self.permissions_required,
    "references": self.references,
    "techniques": [technique.name for technique in self.techniques],
    "tactics": [tactic.name for tactic in self.tactics],
    "mitigations": [mitigation.name for mitigation in self.mitigations],
    "groups": [group.name for group in self.groups],
    "datasources": [datasource.name for datasource in self.datasources]
}
```

<p align="right">(<a href="#top">back to top</a>)</p>