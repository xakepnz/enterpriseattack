# Mitigations

Mitigations represent security concepts and classes of technologies that can be used to prevent a technique or sub-technique from being successfully executed. [Read more](https://attack.mitre.org/mitigations/enterprise/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
mitigations = attack.mitigations
```

## Main Attributes:
```py
for group in attack.mitigations:
    print(mitigation.id) # The human-readable ID
    print(mitigation.mid) # The Mitre ID
    print(mitigation.created) # Date created
    print(mitigation.modified) # Date modified
    print(mitigation.created_by_ref) # Whom created this
    print(mitigation.object_marking_ref) # Copyright marking
    print(mitigation.name) # Name of object
    print(mitigation.type) # Type of object
    print(mitigation.description) # Description of object
    print(mitigation.url) # URL to mitre attack page
    print(mitigation.revoked) # Has this been merged into another object or not
    print(mitigation.deprecated) # Has this object been deprecated from the framework
```

## Extra Attributes:
```py
for mitigation in attack.mitigations:
    for technique in mitigation.techniques:
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

mitigations = attack.mitigations

for mitigation in mitigations:
    print(mitigation.to_json())
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
    "techniques": [technique.name for technique in self.techniques],
    "deprecated": self.deprecated,
    "revoked": self.revoked
}
```

<p align="right">(<a href="#top">back to top</a>)</p>