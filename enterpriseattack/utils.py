#---------------------------------------------------------------------------------#

import requests
import ujson

import logging

import enterpriseattack

#---------------------------------------------------------------------------------#
# Download Enterprise Attack Json from Mitre Att&ck Github:
#---------------------------------------------------------------------------------#

def download(url, local_enterprise_json, **kwargs):
    logging.debug(f'Downloading dataset: {url}')

    r = requests.get(
        url,
        headers={
            'Content-Type': 'application/json'
        },
        proxies=kwargs.get('proxies')
    )

    if r.ok:
        try:
            with open(local_enterprise_json, 'w') as f:
                ujson.dump(r.json(), f, indent=4)
                return True

        except (AttributeError, ValueError, TypeError) as e:
            logging.error(f'Did not receive json response from: {url}, error was: {e}')
            raise enterpriseattack.Error(f'Did not receive json response from: {url}')

        except FileNotFoundError as e:
            raise enterpriseattack.Error(
                f'File: "{local_enterprise_json}" was not found. - Unable to create file, change directory?'
            )

    raise enterpriseattack.Error(f'Failed to connect to: {url}')

#---------------------------------------------------------------------------------#
# Read local copy of Enterprise json or update the existing json:
#---------------------------------------------------------------------------------#

def read_json(enterprise_url, local_enterprise_json, update, **kwargs):
    # Read local copy if we have one:
    if not update:
        try:
            if not update:
                logging.debug(f'Attempting to read local json: {local_enterprise_json}')

                with open(local_enterprise_json,'r') as f:
                    attack_objects = ujson.load(f)
                    logging.debug('Successfully read local json')
                return attack_objects

        # Try to download the file, if we cannot find it:
        except FileNotFoundError as e:
            logging.warning(
                f'File: {local_enterprise_json} does not exist, attempting to download new dataset'
            )
            return read_json(
                enterprise_url,
                local_enterprise_json,
                update=True,
                **kwargs
            )
    
    # If update was true, re-download the json:
    downloaded = download(
        url=enterprise_url,
        local_enterprise_json=local_enterprise_json,
        **kwargs
    )

    if downloaded:
        return read_json(
            enterprise_url,
            local_enterprise_json,
            update=False,
            **kwargs
        )
    
    return None

#---------------------------------------------------------------------------------#
# Expand external:
#---------------------------------------------------------------------------------#

def expand_external(ext_list, key_name):
    if isinstance(ext_list, list):
        for obj in ext_list:
            if obj.get(key_name):
                return obj.get(key_name)
    return None

#---------------------------------------------------------------------------------#
# Obtain sources (references) from each object:
#---------------------------------------------------------------------------------#

def obtain_sources(ext_list):
    sources_ = []
    if isinstance(ext_list, list):
        for obj in ext_list:
            if obj.get('description'):
                sources_.append(obj)
        return sources_
    return None

#---------------------------------------------------------------------------------#
# Match all tactics for a given technique kill_chain_phases list:
#---------------------------------------------------------------------------------#

def match_tactics(short_name_to_match, kill_chain_phases):
    tactics_ = []
    if isinstance(kill_chain_phases, list):
        for obj in kill_chain_phases:
            if obj.get('phase_name') == short_name_to_match:
                return True
    return None

#---------------------------------------------------------------------------------#
# Set relationships:
#---------------------------------------------------------------------------------#

def set_relationships(attack_objects):
    relationships_ = {}
    id_lookup_ = {}

    # Check for bogus json:
    if not attack_objects.get('objects'):
        raise enterpriseattack.Error(
            'Unable to find enterprise objects, json seems invalid.'
        )
    
    # Map relationships from-to ID's:
    for attack_obj in attack_objects.get('objects'):
        if attack_obj.get('type') == 'relationship':
            if attack_obj.get('source_ref') not in relationships_:
                relationships_[attack_obj.get('source_ref')] = [attack_obj.get('target_ref')]
            else:
                relationships_[attack_obj.get('source_ref')].append(attack_obj.get('target_ref'))

            if attack_obj.get('target_ref') not in relationships_:
                relationships_[attack_obj.get('target_ref')] = [attack_obj.get('source_ref')]
            else:
                relationships_[attack_obj.get('target_ref')].append(attack_obj.get('source_ref'))
        
        # Map techniques to their ID's:
        if attack_obj.get('type') == 'attack-pattern':
            id_lookup_[attack_obj.get('id')] = attack_obj

        # Map software to their ID's:
        if attack_obj.get('type') == 'tool' or attack_obj.get('type') == 'malware':
            id_lookup_[attack_obj.get('id')] = attack_obj

        # Map mitigations to their ID's:
        if attack_obj.get('type') == 'course-of-action':
            id_lookup_[attack_obj.get('id')] = attack_obj

        # Map groups to their ID's:
        if attack_obj.get('type') == 'intrusion-set':
            id_lookup_[attack_obj.get('id')] = attack_obj

        # Map data components to their data source id's:
        if attack_obj.get('type') == 'x-mitre-data-component':
            if attack_obj.get('created_by_ref') not in relationships_:
                relationships_[attack_obj.get('id')] = [attack_obj.get('x_mitre_data_source_ref')]
            else:
                relationships_[attack_obj.get('id')].append(attack_obj.get('x_mitre_data_source_ref'))

            if attack_obj.get('x_mitre_data_source_ref') not in relationships_:
                relationships_[attack_obj.get('x_mitre_data_source_ref')] = [attack_obj.get('id')]
            else:
                relationships_[attack_obj.get('x_mitre_data_source_ref')].append(attack_obj.get('id'))

            # Append it to the id lookup:
            id_lookup_[attack_obj.get('id')] = attack_obj

    return relationships_, id_lookup_
