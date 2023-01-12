# ----------------------------------------------------------------------------#

import logging

import enterpriseattack

# ----------------------------------------------------------------------------#
# DataSource class:
# ----------------------------------------------------------------------------#


class DataSource:
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
        self.platforms = kwargs.get('x_mitre_platforms')
        self.collection_layers = kwargs.get('x_mitre_collection_layers')
        self.attack_spec_version = kwargs.get('x_mitre_attack_spec_version')
        self.domains = kwargs.get('x_mitre_domains')
        self.references = enterpriseattack.utils.obtain_sources(
            kwargs.get('external_references')
        )
        self.url = enterpriseattack.utils.expand_external(
            kwargs.get('external_references'),
            'url'
        )
        self.contributors = kwargs.get('x_mitre_contributors')
        self.revoked = kwargs.get('revoked')
        self.deprecated = kwargs.get('x_mitre_deprecated')

    # ----------------------------------------------------------------------------#
    # Access Components for each Data Source object:
    # ----------------------------------------------------------------------------#

    @property
    def components(self):
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
                            **self.id_lookup[r_]
                        )
                    )

        return components_

    # ----------------------------------------------------------------------------#
    # Access Techniques for each Data Source object:
    # ----------------------------------------------------------------------------#

    @property
    def techniques(self):
        from .technique import Technique

        techniques_ = []

        if self.components:
            for component in self.components:
                if component.data_source_ref == self.mid:
                    if self.relationships.get(component.id):
                        for r_id in self.relationships.get(component.id):
                            if self.id_lookup.get(r_id):
                                if (
                                    self.id_lookup.get(r_id).get('type')
                                        == 'attack-pattern'
                                        and not self.id_lookup.get(r_id).get(
                                            'x_mitre_is_subtechnique'
                                            )
                                        ):
                                    techniques_.append(
                                        Technique(
                                            self.attack_objects,
                                            self.relationships,
                                            self.id_lookup,
                                            **self.id_lookup[r_id]
                                        )
                                    )

        return techniques_

    # ----------------------------------------------------------------------------#
    # Access Sub Techniques for each Data Source object:
    # ----------------------------------------------------------------------------#

    @property
    def sub_techniques(self):
        from .sub_technique import SubTechnique

        sub_techniques_ = []

        if self.components:
            for component in self.components:
                if component.data_source_ref == self.mid:
                    if self.relationships.get(component.id):
                        for r_id in self.relationships.get(component.id):
                            if self.id_lookup.get(r_id):
                                if (
                                    self.id_lookup.get(r_id).get('type')
                                        == 'attack-pattern'
                                        and self.id_lookup.get(r_id).get(
                                            'x_mitre_is_subtechnique'
                                            )
                                        ):
                                    sub_techniques_.append(
                                        SubTechnique(
                                            self.attack_objects,
                                            self.relationships,
                                            self.id_lookup,
                                            **self.id_lookup[r_id]
                                        )
                                    )

        return sub_techniques_

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
                "revoked": self.revoked
            }
        except Exception as e:
            logging.error(f'Failed to jsonify object, error was: {e}')
            raise enterpriseattack.Error(
                f'Failed to create json object, error was: {e}'
            )

    # ----------------------------------------------------------------------------#

    def __str__(self):
        return f'{self.name} Mitre Att&ck Data Source'

    def __repr__(self):
        return f'{self.__class__} {self.name}'
