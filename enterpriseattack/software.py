# ----------------------------------------------------------------------------#

import logging

import enterpriseattack

# ----------------------------------------------------------------------------#
# Software class:
# ----------------------------------------------------------------------------#


class Software:
    def __init__(self, attack_objects, relationships, id_lookup, **kwargs):
        self.relationships = relationships
        self.id_lookup = id_lookup
        self.attack_objects = attack_objects

        self.id = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'),
            'external_id'
        )
        self.mid = kwargs.get('id')
        self.created = kwargs.get('created')
        self.modified = kwargs.get('modified')
        self.created_by_ref = kwargs.get('created_by_ref')
        self.object_marking_ref = kwargs.get('object_marking_refs')
        self.name = kwargs.get('name')
        self.type = kwargs.get('type')
        self.description = kwargs.get('description')
        self.url = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'),
            'url'
        )
        self.references = enterpriseattack.utils.obtain_sources(
            kwargs.get('external_references')
        )
        self.labels = kwargs.get('labels')
        self.platforms = kwargs.get('x_mitre_platforms')
        self.revoked = kwargs.get('revoked')
        self.deprecated = kwargs.get('x_mitre_deprecated')

    # ----------------------------------------------------------------------------#
    # Access Techniques for each Software object:
    # ----------------------------------------------------------------------------#

    @property
    def techniques(self):
        from .technique import Technique

        techniques_ = []

        if self.relationships.get(self.mid):
            for target_id in self.relationships.get(self.mid):
                if target_id.startswith('attack-pattern') \
                    and not self.id_lookup.get(target_id).get(
                        'x_mitre_is_subtechnique'
                        ):
                    techniques_.append(
                        Technique(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **self.id_lookup[target_id]
                        )
                    )

        return techniques_

    # ----------------------------------------------------------------------------#
    # Access Sub Techniques for each Software object:
    # ----------------------------------------------------------------------------#

    @property
    def sub_techniques(self):
        from .sub_technique import SubTechnique

        sub_techniques_ = []

        if self.relationships.get(self.mid):
            for target_id in self.relationships.get(self.mid):
                if target_id.startswith('attack-pattern') \
                    and self.id_lookup.get(target_id).get(
                        'x_mitre_is_subtechnique'
                        ):
                    if self.id_lookup.get(target_id):
                        sub_techniques_.append(
                            SubTechnique(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[target_id]
                            )
                        )

        return sub_techniques_

    # ----------------------------------------------------------------------------#
    # Access Tactics for each Software object:
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
    # Access Groups for each Software object:
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
                "object_marking_ref": self.object_marking_ref,
                "name": self.name,
                "type": self.type,
                "description": self.description,
                "url": self.url,
                "references": self.references,
                "labels": self.labels,
                "groups": [group.name for group in self.groups],
                "techniques": [
                    technique.name for technique in self.techniques
                ],
                "tactics": [tactic.name for tactic in self.tactics],
                "platforms": self.platforms,
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
        return f'{self.name} Mitre Att&ck Software'

    def __repr__(self):
        return f'{self.__class__} {self.name}'
