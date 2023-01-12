# ----------------------------------------------------------------------------#

import logging

import enterpriseattack

# ----------------------------------------------------------------------------#
# Technique class:
# ----------------------------------------------------------------------------#


class Technique:
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

    # ----------------------------------------------------------------------------#
    # Return a list of sub techniques to every Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def groups(self):
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
                                **self.id_lookup[r_id]
                            )
                        )
        return groups_

    # ----------------------------------------------------------------------------#
    # Return a list of sub techniques to every Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def sub_techniques(self):
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
                                **self.id_lookup[r_]
                            )
                        )

        return sub_techniques_

    # ----------------------------------------------------------------------------#
    # Access Datasources for each Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def datasources(self):
        from .data_source import DataSource

        datasources_ = []

        if self.x_mitre_data_sources:
            for attack_obj in self.attack_objects['objects']:
                if attack_obj.get('type') == 'x-mitre-data-source':
                    ds_ = [
                        d_ for d_ in self.x_mitre_data_sources
                        if attack_obj.get('name') in d_
                    ]
                    if ds_:
                        datasources_.append(
                            DataSource(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
        return datasources_

    # ----------------------------------------------------------------------------#
    # Access Components for each Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def components(self):
        from .component import Component

        components_ = []

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
    # Access Tactics for each Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def tactics(self):
        from .tactic import Tactic

        tactics_ = []

        for attack_obj in self.attack_objects['objects']:
            if attack_obj.get('type') == 'x-mitre-tactic':
                if enterpriseattack.utils.match_tactics(
                        attack_obj.get('x_mitre_shortname'),
                        self.kill_chain_phases):
                    tactics_.append(
                        Tactic(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj))
        return tactics_

    # ----------------------------------------------------------------------------#
    # Access Mitigations for each Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def mitigations(self):
        from .mitigation import Mitigation

        mitigations_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') == 'course-of-action':
                mitigations_.append(
                    Mitigation(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_]
                    )
                )

        return mitigations_

    # ----------------------------------------------------------------------------#
    # Access Software for each Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def software(self):
        from .software import Software

        software_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') in ['tool', 'malware']:
                software_.append(
                    Software(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_]
                    )
                )

        return software_

    # ----------------------------------------------------------------------------#
    # Access Malware for each Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def malware(self):
        from .software import Software

        malware_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') == 'malware':
                malware_.append(
                    Software(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_]
                    )
                )

        return malware_

    # ----------------------------------------------------------------------------#
    # Access Tools for each Technique object:
    # ----------------------------------------------------------------------------#

    @property
    def tools(self):
        from .software import Software

        tools_ = []

        for r_ in self.relationships.get(self.mid):
            if self.id_lookup[r_].get('type') == 'tool':
                tools_.append(
                    Software(
                        self.attack_objects,
                        self.relationships,
                        self.id_lookup,
                        **self.id_lookup[r_]
                    )
                )

        return tools_

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
                "kill_chain_phases": self.kill_chain_phases
            }
        except Exception as e:
            logging.error(f'Failed to jsonify object, error was: {e}')
            raise enterpriseattack.Error(
                f'Failed to create json object, error was: {e}'
            )

    # ----------------------------------------------------------------------------#

    def __str__(self):
        return f'{self.name} Mitre Att&ck Technique'

    def __repr__(self):
        return f'{self.__class__} {self.name}'
