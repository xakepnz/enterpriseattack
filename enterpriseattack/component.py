# -----------------------------------------------------------------------------

from __future__ import annotations

import logging
from typing import Any, Dict

import enterpriseattack

# -----------------------------------------------------------------------------
# Component class:
# -----------------------------------------------------------------------------


class Component:

    # -------------------------------------------------------------------------

    def __init__(
        self,
        attack_objects: list,
        relationships: Dict,
        id_lookup: Dict,
        **kwargs: Any,
    ) -> Component:
        """
        Creates a Component Class object with all the relevant mappings.

        Args:
            - attack_objects: All the ATT&CK dataset objects
            - relationships: The source/target relationship mappings
            - id_lookup: Key/values of id's to objects
            - kwargs: Object to pass in, to create a component cls obj from

        Returns:
            Component class object

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
        self.data_source_ref = kwargs.get('x_mitre_data_source_ref')
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
        from .technique import Technique

        techniques_ = []

        if self.relationships.get(self.mid):
            for r_ in self.relationships.get(self.mid):
                if r_.startswith('attack-pattern') and not self.id_lookup[
                    r_
                ].get('x_mitre_is_subtechnique'):
                    techniques_.append(
                        Technique(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **self.id_lookup[r_],
                        )
                    )

        return techniques_

    # -------------------------------------------------------------------------

    @property
    def sub_techniques(self) -> list:
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

        tactics_ = []

        for technique in self.techniques:
            if technique.tactics:
                for tactic in technique.tactics:
                    tactics_.append(tactic)
        return tactics_

    # -------------------------------------------------------------------------

    def to_json(self) -> Dict:
        try:
            return {
                "id": self.id,
                "mid": self.mid,
                "created": self.created,
                "modified": self.modified,
                "created_by_ref": self.created_by_ref,
                "object_marking_ref": self.object_marking_ref,
                "techniques": [
                    technique.name for technique in self.techniques
                ],
                "sub_techniques": [
                    sub_technique.name for sub_technique in self.sub_techniques
                ],
                "tactics": [tactic.name for tactic in self.tactics],
                "name": self.name,
                "type": self.type,
                "description": self.description,
                "url": self.url,
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
        """Return string value of component name"""
        return f'{self.name} MITRE ATT&CK Data Component'

    def __repr__(self) -> str:
        """Return raw component name"""
        return f'{self.__class__} {self.name}'
