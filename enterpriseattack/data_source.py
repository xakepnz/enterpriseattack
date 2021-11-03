#---------------------------------------------------------------------------------#

import enterpriseattack
import logging

#---------------------------------------------------------------------------------#
# DataSource class:
#---------------------------------------------------------------------------------#

class DataSource:
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
        self.platforms = kwargs.get('x_mitre_platforms')
        self.collection_layers = kwargs.get('x_mitre_collection_layers')
        self.references = enterpriseattack.utils.obtain_sources(kwargs.get('external_references'))
        self.url = enterpriseattack.utils.expand_external(kwargs.get('external_references'), 'url')
        self.contributors = kwargs.get('x_mitre_contributors')
        self.revoked = kwargs.get('revoked')
        self.deprecated = kwargs.get('x_mitre_deprecated')

    #---------------------------------------------------------------------------------#
    # Access Components for each Data Source object:
    #---------------------------------------------------------------------------------#

    @property
    def components(self):

        components_ = []

        if self.relationships.get(self.mid):
            for target_id in self.relationships.get(self.mid):
                if target_id.startswith('x-mitre-data-component'):
                    if self.id_lookup.get(target_id):
                        components_.append(Component(self.id_lookup.get(target_id)))
        return components_

    #---------------------------------------------------------------------------------#
    # Access Techniques for each Data Source object:
    #---------------------------------------------------------------------------------#

    @property
    def techniques(self):
        from .technique import Technique

        techniques_ = []

        for component in self.components:
            if component.data_source_ref == self.mid:
                if self.relationships.get(component.id):
                    for r_id in self.relationships.get(component.id):
                        if self.id_lookup.get(r_id):
                            if self.id_lookup.get(r_id).get('type') == 'attack-pattern' and self.id_lookup.get(r_id).get('x_mitre_is_subtechnique') == False:
                                techniques_.append(Technique(self.attack_objects, self.relationships, self.id_lookup, **self.id_lookup[r_id]))
        return techniques_

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
                "name": self.name,
                "type": self.type,
                "description": self.description,
                "url": self.url,
                "platforms": self.platforms,
                "collection_layers": self.collection_layers,
                "references": self.references,
                "contributor": self.contributors,
                "techniques": [technique.name for technique in self.techniques],
                "components": [component.name for component in self.components],
                "deprecated": self.deprecated,
                "revoked": self.revoked
            }
        except Exception as e:
            logging.error('Failed to jsonify object, error was: {}'.format(e))
            raise enterpriseattack.Error('Failed to create json object, error was: {}'.format(e))
    
    #---------------------------------------------------------------------------------#

    def __str__(self):
        return '{} Mitre Att&ck Data Source'.format(self.name)
    
    def __repr__(self):
        return '{} {}'.format(self.__class__, self.name)

#---------------------------------------------------------------------------------#
# Data Source Component class:
#---------------------------------------------------------------------------------#

class Component:
    def __init__(self, component_obj):
        self.id = component_obj.get('id')
        self.created = component_obj.get('created')
        self.modified = component_obj.get('modified')
        self.created_by_ref = component_obj.get('created_by_ref')
        self.object_marking_ref = component_obj.get('object_marking_refs')
        self.name = component_obj.get('name')
        self.description = component_obj.get('description')
        self.type = component_obj.get('type')
        self.data_source_ref = component_obj.get('x_mitre_data_source_ref')

    #---------------------------------------------------------------------------------#

    def __str__(self):
        return '{} Mitre Att&ck Data Component'.format(self.name)
    
    def __repr__(self):
        return '{} {}'.format(self.__class__, self.name)