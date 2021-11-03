# Tactics

Tactics represent the "why" of an ATT&CK technique or sub-technique. It is the adversary's tactical goal: the reason for performing an action. For example, an adversary may want to achieve credential access. [Read more](https://attack.mitre.org/tactics/enterprise/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
tactics = attack.tactics
```

## Main Attributes:
```py
for tactic in attack.tactics:
    print(tactic.id) # The human-readable ID
    print(tactic.mid) # The Mitre ID
    print(tactic.created) # Date created
    print(tactic.modified) # Date modified
    print(tactic.created_by_ref) # Whom created this
    print(tactic.object_marking_ref) # Copyright marking
    print(tactic.name) # Name of object
    print(tactic.type) # Type of object
    print(tactic.description) # Description of object
    print(tactic.url) # URL to mitre attack page
    print(tactic.revoked) # Has this been merged into another object or not
    print(tactic.deprecated) # Has this object been deprecated from the framework
    print(tactic.short_name) # lowercase string of tactic
```

## Extra Attributes:
```py
for tactic in attack.tactics:
    for technique in tactic.techniques:
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

tactics = attack.tactics

for tactic in tactics:
    print(tactic.to_json())
```

```json
{
    "id": self.id,
    "created": self.created,
    "modified": self.modified,
    "created_by_ref": self.created_by_ref,
    "object_marking_ref": self.object_marking_ref,
    "name": self.name,
    "type": self.type,
    "description": self.description,
    "url": self.url,
    "short_name": self.short_name,
    "techniques": [technique.name for technique in self.techniques],
    "deprecated": self.deprecated,
    "revoked": self.revoked
}
```

<p align="right">(<a href="#top">back to top</a>)</p>