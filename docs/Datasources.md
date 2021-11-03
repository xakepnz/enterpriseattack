# Datasources

Data sources represent the various subjects/topics of information that can be collected by sensors/logs. Data sources also include data components, which identify specific properties/values of a data source relevant to detecting a given ATT&CK technique or sub-technique. [Read More](https://attack.mitre.org/datasources/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
datasources = attack.datasources
```

## Main Attributes:
```py
for datasource in attack.datasources:
    print(datasource.id) # The human-readable ID
    print(datasource.mid) # The Mitre ID
    print(datasource.created) # Date created
    print(datasource.modified) # Date modified
    print(datasource.created_by_ref) # Whom created this
    print(datasource.object_marking_ref) # Copyright marking
    print(datasource.name) # Name of object
    print(datasource.type) # Type of object
    print(datasource.description) # Description of object
    print(datasource.platforms) # OS platforms this belongs to
    print(datasource.collection_layers) # The components this belongs to
    print(datasource.references) # Online references to this object
    print(datasource.url) # URL to mitre attack page
    print(datasource.contributors) # Who contributed to this object
    print(datasource.revoked) # Has this been merged into another object or not
    print(datasource.deprecated) # Has this object been deprecated from the framework
```

## Extra Attributes:
```py
for datasource in attack.datasources:
    for component in datasource.components:
        print(component.id) # mitre id of component
        print(component.created) # Date created
        print(component.modified) # Date modified
        print(component.created_by_ref) # Mitre's custom identity ID
        print(component.object_marking_ref) # Copyright marking
        print(component.name) # Name of object
        print(component.description) # Description of object
        print(component.type) # Type of object
        print(component.data_source_ref) # What datasources this belongs to
    for technique in datasource.techniques:
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

datasources = attack.datasources

for datasource in datasources:
    print(datasource.to_json())
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
    "typee": self.type,
    "description": self.description,
    "url": self.url,
    "platforms": self.platforms,
    "collection_layers": self.collection_layers,
    "references": self.references,
    "contributor": self.contributors,
    "techniques": [technique.name for technique in self.techniques],
    "components": [component.name for component in self.components],
    "deprecated": self.deprecated,
    "revoked": self.revoked
}
```

<p align="right">(<a href="#top">back to top</a>)</p>