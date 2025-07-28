# -----------------------------------------------------------------------------

from __future__ import annotations

import logging
from typing import Any, Dict

import enterpriseattack

# -----------------------------------------------------------------------------
# SubTechnique class:
# -----------------------------------------------------------------------------


class SubTechnique:

    # -------------------------------------------------------------------------

    def __init__(
        self,
        attack_objects: list,
        relationships: Dict,
        id_lookup: Dict,
        **kwargs: Any,
    ) -> SubTechnique:
        """
        Creates a SubTechnique Class object with all the relevant mappings.

        Args:
            - attack_objects: All the ATT&CK dataset objects
            - relationships: The source/target relationship mappings
            - id_lookup: Key/values of id's to objects
            - kwargs: Object to pass in, to create a subtechnique cls obj from

        Returns:
            SubTechnique class object

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
        self.created_by_ref = kwargs.get('created_by_ref')
        self.object_marking_ref = kwargs.get('object_marking_refs')
        self.url = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'), 'url'
        )
        self.permissions_required = kwargs.get('x_mitre_permissions_required')
        self.platforms = kwargs.get('x_mitre_platforms')
        self.references = enterpriseattack.utils.obtain_sources(
            kwargs.get('external_references')
        )
        self.revoked = kwargs.get('revoked')
        self.deprecated = kwargs.get('x_mitre_deprecated')
        self.x_mitre_data_sources = kwargs.get('x_mitre_data_sources')
        self.detection = kwargs.get('x_mitre_detection')

    # -------------------------------------------------------------------------

    @property
    def datasources(self) -> list:
        """Property to list datasources of the subtechnique object."""
        from .data_source import DataSource

        datasources_ = []

        if self.x_mitre_data_sources:
            for attack_obj in self.attack_objects['objects']:
                if attack_obj.get('type') == 'x-mitre-data-source':
                    ds_ = [
                        d_
                        for d_ in self.x_mitre_data_sources
                        if attack_obj.get('name') in d_
                    ]
                    if ds_:
                        datasources_.append(
                            DataSource(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
        return datasources_

    # -------------------------------------------------------------------------

    @property
    def techniques(self) -> list:
        """Property to list techniques of the subtechnique object."""
        from .technique import Technique

        techniques_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if self.id_lookup.get(r_id):
                    if self.id_lookup.get(r_id).get(
                        'type'
                    ) == 'attack-pattern' and not self.id_lookup.get(r_id).get(
                        'x_mitre_is_subtechnique'
                    ):
                        techniques_.append(
                            Technique(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[r_id],
                            )
                        )
        return techniques_

    # -------------------------------------------------------------------------

    @property
    def groups(self) -> list:
        """Property to list groups of the subtechnique object."""
        from .group import Group

        groups_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if (
                    self.id_lookup.get(r_id)
                    and self.id_lookup.get(r_id).get('type') == 'intrusion-set'
                ):
                    groups_.append(
                        Group(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **self.id_lookup[r_id],
                        )
                    )
        return groups_

    # -------------------------------------------------------------------------

    @property
    def tactics(self) -> list:
        """Property to list tactics of the subtechnique object."""

        tactics_ = []

        for technique in self.techniques:
            if technique.tactics:
                for tactic in technique.tactics:
                    tactics_.append(tactic)

        return tactics_

    # -------------------------------------------------------------------------

    @property
    def mitigations(self) -> list:
        """Property to list mitigations of the subtechnique object."""
        from .mitigation import Mitigation

        mitigations_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if (
                    self.id_lookup.get(r_id)
                    and self.id_lookup.get(r_id).get('type')
                    == 'course-of-action'
                ):
                    mitigations_.append(
                        Mitigation(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **self.id_lookup[r_id],
                        )
                    )

        return mitigations_

    # -------------------------------------------------------------------------

    @property
    def software(self) -> list:
        """Property to list software of the subtechnique object."""
        from .software import Software

        software_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') in ['tool', 'malware']:
                software_.append(
                    Software(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_],
                    )
                )

        return software_

    # -------------------------------------------------------------------------

    @property
    def tools(self) -> list:
        """Property to list tools of the subtechnique object."""
        from .software import Software

        tools_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') == 'tool':
                tools_.append(
                    Software(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_],
                    )
                )

        return tools_

    # -------------------------------------------------------------------------

    @property
    def malware(self) -> list:
        """Property to list malware of the subtechnique object."""
        from .software import Software

        malware_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') == 'malware':
                malware_.append(
                    Software(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_],
                    )
                )

        return malware_

    # -------------------------------------------------------------------------

    @property
    def components(self) -> list:
        """Property to list components of the subtechnique object."""
        from .component import Component

        components_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') == 'x-mitre-data-component':
                components_.append(
                    Component(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_],
                    )
                )

        return components_

    # -------------------------------------------------------------------------

    def to_json(self) -> Dict:
        """Return a dict of the subtechnique object"""
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
                "deprecated": self.deprecated,
                "revoked": self.revoked,
                "platforms": self.platforms,
                "permissions_required": self.permissions_required,
                "references": self.references,
                "techniques": [
                    technique.name for technique in self.techniques
                ],
                "tactics": [tactic.name for tactic in self.tactics],
                "mitigations": [
                    mitigation.name for mitigation in self.mitigations
                ],
                "groups": [group.name for group in self.groups],
                "datasources": [
                    datasource.name for datasource in self.datasources
                ],
                "software": [
                    {software.name: software.type}
                    for software in self.software
                ],
                "tools": [tool.name for tool in self.tools],
                "malware": [malware.name for malware in self.malware],
            }
        except Exception as e:
            logging.error(f'Failed to jsonify object, error was: {e}')
            raise enterpriseattack.Error(
                f'Failed to create json object, error was: {e}'
            )

    # -------------------------------------------------------------------------

    def __str__(self) -> str:
        """Return string value of subtechnique name"""
        return f'{self.name} MITRE ATT&CK Sub Technique'

    def __repr__(self) -> str:
        """Return raw sub technique name"""
        return f'{self.__class__} {self.name}'
