# -----------------------------------------------------------------------------

from __future__ import annotations

import logging
from typing import Any, Dict

import enterpriseattack

# -----------------------------------------------------------------------------
# Technique class:
# -----------------------------------------------------------------------------


class Technique:

    # -------------------------------------------------------------------------

    def __init__(
        self,
        attack_objects: list,
        relationships: Dict,
        id_lookup: Dict,
        **kwargs: Any,
    ) -> Technique:
        """
        Creates a Technique Class object with all the relevant mappings.

        Args:
            - attack_objects: All the ATT&CK dataset objects
            - relationships: The source/target relationship mappings
            - id_lookup: Key/values of id's to objects
            - kwargs: Object to pass in, to create a technique cls obj from

        Returns:
            Technique class object

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
        self.platforms = kwargs.get('x_mitre_platforms')
        self.permissions_required = kwargs.get('x_mitre_permissions_required')
        self.detection = kwargs.get('x_mitre_detection')
        self.deprecated = kwargs.get('x_mitre_deprecated')
        self.revoked = kwargs.get('revoked')
        self.x_mitre_data_sources = kwargs.get('x_mitre_data_sources')
        self.references = enterpriseattack.utils.obtain_sources(
            kwargs.get('external_references')
        )
        self.kill_chain_phases = kwargs.get('kill_chain_phases')

    # -----------------------------------------------------------------------------

    @property
    def groups(self) -> list:
        from .group import Group

        groups_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if self.id_lookup.get(r_id):
                    if self.id_lookup.get(r_id).get('type') == 'intrusion-set':
                        groups_.append(
                            Group(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[r_id],
                            )
                        )
        return groups_

    # -----------------------------------------------------------------------------

    @property
    def sub_techniques(self) -> list:
        from .sub_technique import SubTechnique

        sub_techniques_ = []

        if self.relationships.get(self.mid):
            for r_ in self.relationships.get(self.mid):
                if r_.startswith('attack-pattern'):
                    if self.id_lookup.get(r_).get('x_mitre_is_subtechnique'):
                        sub_techniques_.append(
                            SubTechnique(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **self.id_lookup[r_],
                            )
                        )

        return sub_techniques_

    # -----------------------------------------------------------------------------

    @property
    def datasources(self) -> list:
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

    # -----------------------------------------------------------------------------

    @property
    def components(self) -> list:
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

    # -----------------------------------------------------------------------------

    @property
    def tactics(self) -> list:
        from .tactic import Tactic

        tactics_ = []

        for attack_obj in self.attack_objects['objects']:
            if attack_obj.get('type') == 'x-mitre-tactic':
                if enterpriseattack.utils.match_tactics(
                    attack_obj.get('x_mitre_shortname'), self.kill_chain_phases
                ):
                    tactics_.append(
                        Tactic(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )
                    )
        return tactics_

    # -----------------------------------------------------------------------------

    @property
    def mitigations(self) -> list:
        from .mitigation import Mitigation

        mitigations_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') == 'course-of-action':
                mitigations_.append(
                    Mitigation(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_],
                    )
                )

        return mitigations_

    # -----------------------------------------------------------------------------

    @property
    def software(self) -> list:
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

    # -----------------------------------------------------------------------------

    @property
    def malware(self) -> list:
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

    # -----------------------------------------------------------------------------

    @property
    def tools(self) -> list:
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

    # -----------------------------------------------------------------------------

    def to_json(self) -> Dict:
        try:
            return {
                "id": self.id,
                "mid": self.mid,
                "created": self.created,
                "modified": self.modified,
                "created_by_ref": self.created_by_ref,
                "object_marking_ref": self.object_marking_ref,
                "permissions_required": self.permissions_required,
                "platforms": self.platforms,
                "name": self.name,
                "type": self.type,
                "description": self.description,
                "url": self.url,
                "detection": self.detection,
                "tactics": [tactic.name for tactic in self.tactics],
                "sub_techniques": [
                    sub_technique.name for sub_technique in self.sub_techniques
                ],
                "datasources": [
                    datasource.name for datasource in self.datasources
                ],
                "groups": [group.name for group in self.groups],
                "software": [software.name for software in self.software],
                "malware": [malware.name for malware in self.malware],
                "tools": [tool.name for tool in self.tools],
                "components": [
                    component.name for component in self.components
                ],
                "deprecated": self.deprecated,
                "revoked": self.revoked,
                "references": self.references,
                "kill_chain_phases": self.kill_chain_phases,
            }
        except Exception as e:
            logging.error(f'Failed to jsonify object, error was: {e}')
            raise enterpriseattack.Error(
                f'Failed to create json object, error was: {e}'
            )

    # -----------------------------------------------------------------------------

    def __str__(self):
        """Return string value of technique name"""
        return f'{self.name} MITRE ATT&CK Technique'

    def __repr__(self):
        """Return raw technique name"""
        return f'{self.__class__} {self.name}'
