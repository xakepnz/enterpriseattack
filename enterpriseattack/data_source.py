# -----------------------------------------------------------------------------

from __future__ import annotations

import logging
from typing import Any, Dict

import enterpriseattack

# -----------------------------------------------------------------------------
# DataSource class:
# -----------------------------------------------------------------------------


class DataSource:

    # -------------------------------------------------------------------------

    def __init__(
        self,
        attack_objects: list,
        relationships: Dict,
        id_lookup: Dict,
        **kwargs: Any,
    ) -> DataSource:
        """
        Creates a DataSource Class object with all the relevant mappings.

        Args:
            - attack_objects: All the ATT&CK dataset objects
            - relationships: The source/target relationship mappings
            - id_lookup: Key/values of id's to objects
            - kwargs: Object to pass in, to create a datasource cls obj from

        Returns:
            DataSource class object

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
        self.platforms = kwargs.get('x_mitre_platforms')
        self.collection_layers = kwargs.get('x_mitre_collection_layers')
        self.attack_spec_version = kwargs.get('x_mitre_attack_spec_version')
        self.domains = kwargs.get('x_mitre_domains')
        self.references = enterpriseattack.utils.obtain_sources(
            kwargs.get('external_references')
        )
        self.url = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'), 'url'
        )
        self.contributors = kwargs.get('x_mitre_contributors')
        self.revoked = kwargs.get('revoked')
        self.deprecated = kwargs.get('x_mitre_deprecated')

    # -------------------------------------------------------------------------

    @property
    def components(self) -> list:
        """Property to list components of the datasource"""
        from .component import Component

        components_ = []

        if self.relationships.get(self.mid):
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

    @property
    def techniques(self) -> list:
        """Property to list techniques of the datasource"""
        from .technique import Technique

        techniques_ = []

        if self.components:
            for component in self.components:
                if component.data_source_ref == self.mid:
                    if self.relationships.get(component.id):
                        for r_id in self.relationships.get(component.id):
                            if self.id_lookup.get(r_id):
                                if self.id_lookup.get(r_id).get(
                                    'type'
                                ) == 'attack-pattern' and not self.id_lookup.get(  # noqa: E501
                                    r_id
                                ).get(
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
    def sub_techniques(self) -> list:
        """Property to list sub_techniques of the data source"""
        from .sub_technique import SubTechnique

        sub_techniques_ = []

        if self.components:
            for component in self.components:
                if component.data_source_ref == self.mid:
                    if self.relationships.get(component.id):
                        for r_id in self.relationships.get(component.id):
                            if self.id_lookup.get(r_id):
                                if self.id_lookup.get(r_id).get(
                                    'type'
                                ) == 'attack-pattern' and self.id_lookup.get(
                                    r_id
                                ).get(
                                    'x_mitre_is_subtechnique'
                                ):
                                    sub_techniques_.append(
                                        SubTechnique(
                                            self.attack_objects,
                                            self.relationships,
                                            self.id_lookup,
                                            **self.id_lookup[r_id],
                                        )
                                    )

        return sub_techniques_

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
                "name": self.name,
                "type": self.type,
                "description": self.description,
                "url": self.url,
                "platforms": self.platforms,
                "collection_layers": self.collection_layers,
                "references": self.references,
                "contributor": self.contributors,
                "techniques": [
                    technique.name for technique in self.techniques
                ],
                "components": [
                    component.name for component in self.components
                ],
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
        """Return string value of data source name"""
        return f'{self.name} MITRE ATT&CK Data Source'

    def __repr__(self) -> str:
        """Return raw data source name"""
        return f'{self.__class__} {self.name}'
