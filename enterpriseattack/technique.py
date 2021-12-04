#---------------------------------------------------------------------------------#

import enterpriseattack
import logging

#---------------------------------------------------------------------------------#
# Technique class:
#---------------------------------------------------------------------------------#

class Technique:
    def __init__(self, attack_objects, relationships, id_lookup, **kwargs):
        self.relationships = relationships
        self.id_lookup = id_lookup
        self.attack_objects = attack_objects

        self.id = enterpriseattack.utils.expand_external(kwargs.get('external_references'), 'external_id')
        self.mid = kwargs.get('id')
        self.created = kwargs.get('created')
        self.modified = kwargs.get('modified')
        self.created_by_ref = kwargs.get('created_by_ref')
        self.object_marking_ref = kwargs.get('object_marking_refs')
        self.name = kwargs.get('name')
        self.type = kwargs.get('type')
        self.description = kwargs.get('description')
        self.url = enterpriseattack.utils.expand_external(kwargs.get('external_references'), 'url')
        self.platforms = kwargs.get('x_mitre_platforms')
        self.permissions_required = kwargs.get('x_mitre_permissions_required')
        self.detection = kwargs.get('x_mitre_detection')
        self.deprecated = kwargs.get('x_mitre_deprecated')
        self.revoked = kwargs.get('revoked')
        self.x_mitre_data_sources = kwargs.get('x_mitre_data_sources')
        self.references = enterpriseattack.utils.obtain_sources(kwargs.get('external_references'))
        self.kill_chain_phases = kwargs.get('kill_chain_phases')

    #---------------------------------------------------------------------------------#
    # Return a list of sub techniques to every Technique object:
    #---------------------------------------------------------------------------------#

    @property
    def groups(self):
        from .group import Group

        groups_ = []

        if self.relationships.get(self.mid):
            for r_id in self.relationships.get(self.mid):
                if self.id_lookup.get(r_id):
                    if self.id_lookup.get(r_id).get('type') == 'intrusion-set':
                        groups_.append(Group(self.attack_objects, self.relationships, self.id_lookup, **self.id_lookup[r_id]))
        return groups_

    #---------------------------------------------------------------------------------#
    # Return a list of sub techniques to every Technique object:
    #---------------------------------------------------------------------------------#

    @property
    def sub_techniques(self):
        from .sub_technique import SubTechnique

        sub_techniques_ = []

        for r_ in self.relationships.get(self.mid):
            if r_.startswith('attack-pattern'):
                if self.id_lookup.get(r_).get('x_mitre_is_subtechnique'):
                    sub_techniques_.append(SubTechnique(self.attack_objects, self.relationships, self.id_lookup, **self.id_lookup[r_]))

        return sub_techniques_

    #---------------------------------------------------------------------------------#
    # Access Datasources for each Technique object:
    #---------------------------------------------------------------------------------#

    @property
    def datasources(self):
        from .data_source import DataSource

        datasources_ = []
        
        if self.x_mitre_data_sources:
            for attack_obj in self.attack_objects['objects']:
                if attack_obj.get('type') == 'x-mitre-data-source':
                    ds_ = [d_ for d_ in self.x_mitre_data_sources if attack_obj.get('name') in d_]
                    if ds_:
                        datasources_.append(DataSource(self.attack_objects, self.relationships, self.id_lookup, **attack_obj))
        return datasources_

    #---------------------------------------------------------------------------------#
    # Access Tactics for each Technique object:
    #---------------------------------------------------------------------------------#

    @property
    def tactics(self):
        from .tactic import Tactic

        tactics_ = []

        for attack_obj in self.attack_objects['objects']:
            if attack_obj.get('type') == 'x-mitre-tactic':
                if enterpriseattack.utils.match_tactics(attack_obj.get('x_mitre_shortname'), self.kill_chain_phases):
                    tactics_.append(Tactic(self.attack_objects, self.relationships, self.id_lookup, **attack_obj))
        return tactics_
    
    #---------------------------------------------------------------------------------#
    # Access Mitigations for each Technique object:
    #---------------------------------------------------------------------------------#

    @property
    def mitigations(self):
        from .mitigation import Mitigation

        mitigations_ = []

        for attack_obj in self.attack_objects['objects']:
            if attack_obj.get('type') == 'course-of-action':
                if self.relationships.get(attack_obj.get('id')):
                    for r_ in self.relationships.get(attack_obj.get('id')):
                        if self.id_lookup.get(r_):
                            mitigations_.append(Mitigation(self.attack_objects, self.relationships, self.id_lookup, **self.id_lookup[r_]))
        return mitigations_
    
    #---------------------------------------------------------------------------------#
    # Return a json dict of the object:
    #---------------------------------------------------------------------------------#

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
                "sub_techniques": [sub_technique.name for sub_technique in self.sub_techniques],
                "datasources": [datasource.name for datasource in self.datasources],
                "groups": [group.name for group in self.groups],
                "deprecated": self.deprecated,
                "revoked": self.revoked,
                "references": self.references,
                "kill_chain_phases": self.kill_chain_phases
            }
        except Exception as e:
            logging.error('Failed to jsonify object, error was: {}'.format(e))
            raise enterpriseattack.Error('Failed to create json object, error was: {}'.format(e))

    #---------------------------------------------------------------------------------#
    
    def __str__(self):
        return '{} Mitre Att&ck Technique'.format(self.name)
    
    def __repr__(self):
        return '{} {}'.format(self.__class__, self.name)