# ----------------------------------------------------------------------------#

import logging

import enterpriseattack

# ----------------------------------------------------------------------------#
# Campaign class:
# ----------------------------------------------------------------------------#


class Campaign:
    def __init__(self, attack_objects, relationships, id_lookup, **kwargs):
        self.relationships = relationships
        self.id_lookup = id_lookup
        self.attack_objects = attack_objects

        self.id = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'),
            'external_id'
        )

        self.references = enterpriseattack.utils.obtain_sources(
            kwargs.get('external_references')
        )

        self.url = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'),
            'url'
        )

        self.mid = kwargs.get('id')
        self.created = kwargs.get('created')
        self.modified = kwargs.get('modified')
        self.name = kwargs.get('name')
        self.type = kwargs.get('type')
        self.description = kwargs.get('description')
        self.first_seen = kwargs.get('first_seen')
        self.last_seen = kwargs.get('last_seen')
        self.aliases = kwargs.get('aliases')
        self.created_by_ref = kwargs.get('created_by_ref')
        self.object_marking_ref = kwargs.get('object_marking_refs')
        self.data_source_ref = kwargs.get('x_mitre_data_source_ref')
        self.attack_spec_version = kwargs.get('x_mitre_attack_spec_version')
        self.revoked = kwargs.get('revoked')
        self.contributors = kwargs.get('x_mitre_contributors')
        self.deprecated = kwargs.get('x_mitre_deprecated')

    # ----------------------------------------------------------------------------#
    # Access Techniques for each Campaign object:
    # ----------------------------------------------------------------------------#

    @property
    def techniques(self):
        from .technique import Technique

        techniques_ = []

        if self.relationships.get(self.mid):
            for r_ in self.relationships.get(self.mid):
                if (r_.startswith('attack-pattern') and
                        not self.id_lookup[r_].get('x_mitre_is_subtechnique')):
                    techniques_.append(
                        Technique(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **self.id_lookup[r_]
                        )
                    )

        return techniques_

    # ----------------------------------------------------------------------------#
    # Access Sub Techniques for each Campaign object:
    # ----------------------------------------------------------------------------#

    @property
    def sub_techniques(self):
        from .sub_technique import SubTechnique

        sub_techniques_ = []

        if self.relationships.get(self.mid):
            for r_ in self.relationships.get(self.mid):
                if (r_.startswith('attack-pattern') and
                        self.id_lookup[r_].get('x_mitre_is_subtechnique')):
                    sub_techniques_.append(
                        SubTechnique(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **self.id_lookup[r_]
                        )
                    )

        return sub_techniques_

    # ----------------------------------------------------------------------------#
    # Access Tactics for each Campaign object:
    # ----------------------------------------------------------------------------#

    @property
    def tactics(self):

        tactics_ = []

        for technique in self.techniques:
            if technique.tactics:
                for tactic in technique.tactics:
                    tactics_.append(tactic)
        return tactics_

    # ----------------------------------------------------------------------------#
    # Access Software for each Campaign object:
    # ----------------------------------------------------------------------------#

    @property
    def software(self):
        from .software import Software

        softwares_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if self.id_lookup.get(r_id):
                    if (self.id_lookup.get(r_id).get('type') in
                            ['tool', 'malware']):
                        softwares_.append(
                            Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[r_id]
                            )
                        )

        return softwares_

    # ----------------------------------------------------------------------------#
    # Access Malware for each Campaign object:
    # ----------------------------------------------------------------------------#

    @property
    def malware(self):
        from .software import Software

        malware_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if self.id_lookup.get(r_id):
                    if self.id_lookup.get(r_id).get('type') == 'malware':
                        malware_.append(
                            Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[r_id]
                            )
                        )

        return malware_

    # ----------------------------------------------------------------------------#
    # Access Tools for each Campaign object:
    # ----------------------------------------------------------------------------#

    @property
    def tools(self):
        from .software import Software

        tools_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if self.id_lookup.get(r_id):
                    if self.id_lookup.get(r_id).get('type') == 'tool':
                        tools_.append(
                            Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[r_id]
                            )
                        )
        return tools_

    # ----------------------------------------------------------------------------#
    # Access Groups for each Campaign object:
    # ----------------------------------------------------------------------------#

    @property
    def groups(self):
        from .group import Group

        groups_ = []

        if self.relationships.get(self.mid):
            for target_id in self.relationships.get(self.mid):
                if target_id.startswith('intrusion-set'):
                    if self.id_lookup.get(target_id):
                        groups_.append(
                            Group(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[target_id]
                            )
                        )
        return groups_

    # ----------------------------------------------------------------------------#
    # Return a json dict of the object:
    # ----------------------------------------------------------------------------#

    def to_json(self):
        try:
            return {
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
        except Exception as e:
            logging.error(f'Failed to jsonify object, error was: {e}')
            raise enterpriseattack.Error(
                f'Failed to create json object, error was: {e}'
            )

    # ----------------------------------------------------------------------------#

    def __str__(self):
        return f'{self.name} Mitre Att&ck Campaign'

    def __repr__(self):
        return f'{self.__class__} {self.name}'
