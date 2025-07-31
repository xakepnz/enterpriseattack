# -----------------------------------------------------------------------------

from __future__ import annotations

import logging
from typing import Any, Dict

import enterpriseattack

# -----------------------------------------------------------------------------
# Tactic class:
# -----------------------------------------------------------------------------


class Tactic:

    # -------------------------------------------------------------------------

    def __init__(
        self,
        attack_objects: list,
        relationships: Dict,
        id_lookup: Dict,
        **kwargs: Any,
    ) -> Tactic:
        """
        Creates a Tactic Class object with all the relevant mappings.

        Args:
            - attack_objects: All the ATT&CK dataset objects
            - relationships: The source/target relationship mappings
            - id_lookup: Key/values of id's to objects
            - kwargs: Object to pass in, to create a tactic cls obj from

        Returns:
            Tactic class object

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
        self.short_name = kwargs.get('x_mitre_shortname')
        self.deprecated = kwargs.get('x_mitre_deprecated')
        self.revoked = kwargs.get('revoked')

    # -----------------------------------------------------------------------------

    @property
    def techniques(self) -> list:
        """Property to list techniques of the tactic object"""
        from .technique import Technique

        techniques_ = []

        for attack_obj in self.attack_objects['objects']:

            if attack_obj.get(
                'type'
            ) == 'attack-pattern' and not attack_obj.get(
                'x_mitre_is_subtechnique'
            ):
                kill_chains = attack_obj.get('kill_chain_phases')

                if enterpriseattack.utils.match_tactics(
                    self.short_name, kill_chains
                ):
                    techniques_.append(
                        Technique(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )
                    )
        return techniques_

    # -----------------------------------------------------------------------------

    @property
    def sub_techniques(self) -> list:
        """Property to list sub_techniques of the tactic"""
        from .sub_technique import SubTechnique

        sub_techniques_ = []

        for attack_obj in self.attack_objects['objects']:

            if attack_obj.get('type') == 'attack-pattern' and attack_obj.get(
                'x_mitre_is_subtechnique'
            ):

                kill_chains = attack_obj.get('kill_chain_phases')

                if enterpriseattack.utils.match_tactics(
                    self.short_name, kill_chains
                ):
                    sub_techniques_.append(
                        SubTechnique(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )
                    )
        return sub_techniques_

    # -----------------------------------------------------------------------------

    def to_json(self) -> Dict:
        """Return a dict of the tactic object"""
        try:
            return {
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
                "techniques": [
                    technique.name for technique in self.techniques
                ],
                "sub_techniques": [
                    subTech.name for subTech in self.sub_techniques
                ],
                "deprecated": self.deprecated,
                "revoked": self.revoked,
            }
        except Exception as e:
            logging.error(f'Failed to jsonify object, error was: {e}')
            raise enterpriseattack.Error(
                f'Failed to create json object, error was: {e}'
            )

    # -----------------------------------------------------------------------------

    def __str__(self) -> str:
        """Return string value of tactic name"""
        return f'{self.name} MITRE ATT&CK Tactic'

    def __repr__(self) -> str:
        """Return raw tactic name"""
        return f'{self.__class__} {self.name}'
