# Campaigns

The security community tracks intrusion activity using various analytic methodologies and terms, such as operations, intrusion sets, and campaigns. Some intrusion activity may be referenced by a variety of names due to different organizations tracking similar activity, often from different vantage points; conversely other times reported activity is not given a designated name. [Read More](https://attack.mitre.org/campaigns/)

## Initialize:

```py
import enterpriseattack

attack = enterpriseattack.Attack()
for campaign in attack.campaigns:
    print(campaign)
```

## Main Attributes:
```py
for campaign in attack.campaigns:
    print(campaign.id) # The human-readable ID
    print(campaign.mid) # The Mitre ID
    print(campaign.created) # Date created
    print(campaign.modified) # Date modified
    print(campaign.created_by_ref) # Whom created this
    print(campaign.object_marking_ref) # Copyright marking
    print(campaign.name) # Name of object
    print(campaign.type) # Type of object
    print(campaign.tactics) # Tactics of a campaign
    print(campaign.techniques) # Techniques of a campaign
    print(campaign.sub_techniques) # Sub Techniques of a campaign
    print(campaign.description) # Description of object
    print(campaign.references) # Online references to this object
    print(campaign.url) # URL to mitre attack page
    print(campaign.contributors) # Who contributed to this object
    print(campaign.revoked) # Has this been merged into another object or not
    print(campaign.deprecated) # Has this object been deprecated from the framework
    print(campaign.attack_spec_version) # Mitre Spec version
    print(campaign.software) # Software pertaining to the campaign
    print(campaign.tools) # Tools pertaining to the campaign
    print(campaign.malware) # Malware pertaining to the campaign
    print(campaign.groups) # Threat Actor groups pertaining to the campaign
```

## Functions:

* to_json - Returns a dict of the object in json format:

```py
import enterpriseattack

attack = enterpriseattack.Attack()

campaigns = attack.campaigns

for campaign in campaigns:
    print(campaign.to_json())
```

```json
{
    "id": self.id,
    "mid": self.mid,
    "created": self.created,
    "modified": self.modified,
    "created_by_ref": self.created_by_ref,
    "last_seen": self.last_seen,
    "first_seen": self.first_seen,
    "object_marking_ref": self.object_marking_ref,
    "techniques": [
        technique.name for technique in self.techniques
    ],
    "sub_techniques": [
        sub_technique.name for sub_technique in self.sub_techniques
    ],
    "tactics": [tactic.name for tactic in self.tactics],
    "tools": [tool.name for tool in self.tools],
    "malware": [malware.name for malware in self.malware],
    "software": [software.name for software in self.software],
    "groups": [group.name for group in self.groups],
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
