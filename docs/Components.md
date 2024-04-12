# Components

Each data component represents activity and/or information generated within a network environment because of actions or behaviors performed by a potential adversary. [Read More](https://attack.mitre.org/datasources/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
components = attack.components
```

## Main Attributes:
```py
for component in attack.components:
    print(component.id) # The human-readable ID
    print(component.mid) # The Mitre ID
    print(component.created) # Date created
    print(component.modified) # Date modified
    print(component.created_by_ref) # Whom created this
    print(component.object_marking_ref) # Copyright marking
    print(component.name) # Name of object
    print(component.type) # Type of object
    print(component.tactics) # Tactics of a component
    print(component.techniques) # Techniques of a component
    print(component.sub_techniques) # Sub Techniques of a component
    print(component.description) # Description of object
    print(component.references) # Online references to this object
    print(component.url) # URL to mitre attack page
    print(component.contributors) # Who contributed to this object
    print(component.revoked) # Has this been merged into another object or not
    print(component.deprecated) # Has this object been deprecated from the framework
```

## Extra Attributes:
```py
for component in attack.components:
    for technique in component.techniques:
        print(technique.name) # Technique name
        # Access all of the techniques attributes...
    for sub_technique in component.sub_techniques:
        print(sub_technique.name) # Sub technique name
        # Access all of the sub techniques attributes...
    for tactics in component.tactics:
        print(tactic.name) # Sub technique name
        # Access all of the sub techniques attributes...
```

## Functions:

* to_json - Returns a dict of the object in json format:

```py
import enterpriseattack

attack = enterpriseattack.Attack()

components = attack.components

for component in components:
    print(component.to_json())
```

```json
{
    "id": self.id,
    "mid": self.mid,
    "created": self.created,
    "modified": self.modified,
    "created_by_ref": self.created_by_ref,
    "object_marking_ref": self.object_marking_ref,
    "techniques": [technique.name for technique in self.techniques],
    "sub_techniques": [sub_technique.name for sub_technique in self.sub_techniques],
    "tactics": [tactic.name for tactic in self.tactics],
    "name": self.name,
    "type": self.type,
    "description": self.description,
    "url": self.url,
    "references": self.references,
    "deprecated": self.deprecated,
    "revoked": self.revoked
}
```

<p align="right">(<a href="#top">back to top</a>)</p>
