# -----------------------------------------------------------------------------

from __future__ import annotations

import logging
from typing import Any, Dict

import enterpriseattack

# -----------------------------------------------------------------------------
# Group class:
# -----------------------------------------------------------------------------


class Group:

    # -------------------------------------------------------------------------

    def __init__(
        self,
        attack_objects: list,
        relationships: Dict,
        id_lookup: Dict,
        **kwargs: Any,
    ) -> Group:
        """
        Creates a Group Class object with all the relevant mappings.

        Args:
            - attack_objects: All the ATT&CK dataset objects
            - relationships: The source/target relationship mappings
            - id_lookup: Key/values of id's to objects
            - kwargs: Object to pass in, to create a group cls obj from

        Returns:
            Group class object

        Raises:
            enterpriseattack.Error: When failing to return the to_json() method
        """
        self.relationships = relationships
        self.id_lookup = id_lookup
        self.attack_objects = attack_objects

        self.id = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'), 'external_id'
        )
        self.mid = kwargs.get('id')
        self.created = kwargs.get('created')
        self.modified = kwargs.get('modified')
        self.name = kwargs.get('name')
        self.type = kwargs.get('type')
        self.description = kwargs.get('description')
        self.aliases = kwargs.get('aliases')
        self.created_by_ref = kwargs.get('created_by_ref')
        self.object_marking_ref = kwargs.get('object_marking_refs')
        self.references = enterpriseattack.utils.obtain_sources(
            kwargs.get('external_references')
        )
        self.url = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'), 'url'
        )
        self.revoked = kwargs.get('revoked')
        self.deprecated = kwargs.get('x_mitre_deprecated')

    # -------------------------------------------------------------------------

    @property
    def techniques(self) -> list:
        """Property to list techniques of the group object"""
        from .technique import Technique

        techniques_ = []

        if self.relationships.get(self.mid):
            for target_id in self.relationships.get(self.mid):
                if target_id.startswith(
                    'attack-pattern'
                ) and not self.id_lookup[target_id].get(
                    'x_mitre_is_subtechnique'
                ):
                    if self.id_lookup.get(target_id):
                        techniques_.append(
                            Technique(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[target_id],
                            )
                        )

        return techniques_

    # -------------------------------------------------------------------------

    @property
    def sub_techniques(self) -> list:
        """Property to list sub techniques of the group object"""
        from .sub_technique import SubTechnique

        sub_techniques_ = []

        if self.relationships.get(self.mid):
            for r_ in self.relationships.get(self.mid):
                if r_.startswith('attack-pattern') and self.id_lookup[r_].get(
                    'x_mitre_is_subtechnique'
                ):
                    sub_techniques_.append(
                        SubTechnique(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **self.id_lookup[r_],
                        )
                    )

        return sub_techniques_

    # -------------------------------------------------------------------------

    @property
    def tactics(self) -> list:
        """Property to list tactics of the group object"""
        tactics_ = []

        for technique in self.techniques:
            for tactic in technique.tactics:
                if tactic not in tactics_:
                    tactics_.append(tactic)

        return tactics_

    # -------------------------------------------------------------------------

    @property
    def software(self) -> list:
        """Property to list software of the group object"""
        from .software import Software

        softwares_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if self.id_lookup.get(r_id):
                    if self.id_lookup.get(r_id).get('type') in [
                        'tool',
                        'malware',
                    ]:
                        softwares_.append(
                            Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[r_id],
                            )
                        )

        return softwares_

    # -------------------------------------------------------------------------

    @property
    def malware(self) -> list:
        """Property to list malware of the group object"""
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
                                **self.id_lookup[r_id],
                            )
                        )

        return malware_

    # -------------------------------------------------------------------------

    @property
    def tools(self) -> list:
        """Property to list tools of the group object"""
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
                                **self.id_lookup[r_id],
                            )
                        )
        return tools_

    # -------------------------------------------------------------------------

    def to_json(self) -> Dict:
        """Return a dict of the group object"""
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
                "aliases": self.aliases,
                "tactics": [tactic.name for tactic in self.tactics],
                "techniques": [
                    technique.name for technique in self.techniques
                ],
                "sub_techniques": [sub.name for sub in self.sub_techniques],
                "software": [{tool.type: tool.name} for tool in self.software],
                "malware": [malware.name for malware in self.malware],
                "tools": [tool.name for tool in self.tools],
                "references": self.references,
                "deprecated": self.deprecated,
                "revoked": self.revoked,
            }
        except Exception as e:
            logging.error(f'Failed to jsonify object, error was: {e}')
            raise enterpriseattack.Error(
                f'Failed to create json object, error was: {e}'
            )

    # -------------------------------------------------------------------------

    def __str__(self) -> str:
        """Return string value of group name"""
        return f'{self.name} Mitre Att&ck Group'

    def __repr__(self) -> str:
        """Return raw group name"""
        return f'{self.__class__} {self.name}'
