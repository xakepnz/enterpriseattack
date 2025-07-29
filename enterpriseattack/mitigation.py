# -----------------------------------------------------------------------------

from __future__ import annotations

import logging
from typing import Any, Dict

import enterpriseattack

# -----------------------------------------------------------------------------
# Mitigation class:
# -----------------------------------------------------------------------------


class Mitigation:

    # -------------------------------------------------------------------------

    def __init__(
        self,
        attack_objects: list,
        relationships: Dict,
        id_lookup: Dict,
        **kwargs: Any,
    ) -> Mitigation:
        """
        Creates a Mitigation Class object with all the relevant mappings.

        Args:
            - attack_objects: All the ATT&CK dataset objects
            - relationships: The source/target relationship mappings
            - id_lookup: Key/values of id's to objects
            - kwargs: Object to pass in, to create a mitigation cls obj from

        Returns:
            Mitigation class object

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
        self.created_by_ref = kwargs.get('created_by_ref')
        self.object_marking_ref = kwargs.get('object_marking_refs')
        self.name = kwargs.get('name')
        self.type = kwargs.get('type')
        self.description = kwargs.get('description')
        self.url = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'), 'url'
        )
        self.revoked = kwargs.get('revoked')
        self.deprecated = kwargs.get('x_mitre_deprecated')

    # -------------------------------------------------------------------------

    @property
    def techniques(self) -> list:
        """Property to list techniques of the mitigation object"""
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
    def tactics(self) -> list:
        """Property to list tactics of the mitigation object"""

        tactics_ = []

        for technique in self.techniques:
            if technique.tactics:
                for tactic in technique.tactics:
                    tactics_.append(tactic)

        return tactics_

    # -------------------------------------------------------------------------

    def to_json(self) -> Dict:
        """Return a dict of the mitigation object"""
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
                "techniques": [
                    technique.name for technique in self.techniques
                ],
                "tactics": [tactic.name for tactic in self.tactics],
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
        """Return string value of mitigation name"""
        return f'{self.name} MITRE ATT&CK Mitigation'

    def __repr__(self) -> str:
        """Return raw mitigation name"""
        return f'{self.__class__} {self.name}'
