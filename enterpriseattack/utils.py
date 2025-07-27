# -----------------------------------------------------------------------------

import logging
from typing import Any, Dict, List, Tuple

import requests
import ujson

import enterpriseattack

# -----------------------------------------------------------------------------
# Download MITRE ATT&CK Dataset from GitHub:
# -----------------------------------------------------------------------------


def download(
    url: str, local_enterprise_json: str, **kwargs: Any
) -> True | None:
    """
    Downloads the MITRE ATT&CK Dataset from https://github.com/mitre/cti.

    Args:
        - url: The URL to the json dataset
        - local_enterprise_json: The name of the file to save locally
        - kwargs: Options for downloading (proxies etc)

    Returns:
        True if successful, otherwise None

    Raises:
        enterpriseattack.Error for: Invalid json reply, file did not write to
        disk or failed to connect to the URL
    """
    logging.debug(f'Downloading dataset: {url}')

    try:
        r = requests.get(
            url,
            headers={'Content-Type': 'application/json'},
            proxies=kwargs.get('proxies'),
        )

        if r.ok:
            try:
                with open(local_enterprise_json, 'w') as f:
                    ujson.dump(r.json(), f, indent=4)
                    return True

            except (AttributeError, ValueError, TypeError) as e:
                logging.error(
                    f'Did not receive json response from: {url}, '
                    f'error was: {e}'
                )
                raise enterpriseattack.Error(
                    f'Did not receive json response from: {url}'
                )

            except FileNotFoundError:
                raise enterpriseattack.Error(
                    f'File: "{local_enterprise_json}" was not found. '
                    '- Unable to create file, change directory?'
                )

        logging.error(f'Failed to connect to: {url}')
        raise enterpriseattack.Error(f'Failed to connect to: {url}')

    except Exception as e:
        logging.error(f'Failed to connect to: {url} error: {e}')
        raise enterpriseattack.Error(f'Failed to connect to: {url} error: {e}')


# -----------------------------------------------------------------------------
# Reads the local copy of ATT&CK dataset or updates it:
# -----------------------------------------------------------------------------


def read_json(
    enterprise_url: str,
    local_enterprise_json: str,
    update: bool,
    **kwargs: Any,
) -> dict:
    """
    Reads the local MITRE ATT&CK json dataset and optionally updates.

    Args:
        - enterprise_url: URL to the dataset to download if updating
        - local_enterprise_json: Name of the local dataset file
        - update: Optional update to download a fresh dataset
        - kwargs: Options for downloading (proxies etc)

    Returns:
        attack_objects (dict): The entire local MITRE ATT&CK dataset object

    Raises:
        FileNotFoundError: If local dataset was not found, it tries downloading
    """
    # Read local copy if we have one:
    if not update:
        try:
            logging.debug(
                f'Attempting to read local json: {local_enterprise_json}'
            )

            with open(local_enterprise_json, 'r') as f:
                attack_objects = ujson.load(f)
                logging.debug('Successfully read local json')

            return attack_objects

        # Try to download the file, if we cannot find it:
        except FileNotFoundError:
            logging.warning(
                f'File: {local_enterprise_json} does not exist, '
                'attempting to download new dataset'
            )
            return read_json(
                enterprise_url, local_enterprise_json, update=True, **kwargs
            )

    # If update was true, re-download the json:
    downloaded = download(
        url=enterprise_url,
        local_enterprise_json=local_enterprise_json,
        **kwargs,
    )

    if downloaded:
        return read_json(
            enterprise_url,
            local_enterprise_json,
            update=False,
            **kwargs,
        )

    return None


# -----------------------------------------------------------------------------


def expand_external(ext_list: list[dict] | None, key_name: str) -> Any | None:
    """
    Return the first matching value from a list of dicts.

    Args:
        - ext_list: List of dicts to search (or None)
        - key_name: Key to look up in each dict

    Returns:
        First found value for key_name, or None if not found
    """
    if not isinstance(ext_list, list):
        return None

    return next((obj[key_name] for obj in ext_list if key_name in obj), None)


# -----------------------------------------------------------------------------
# Obtain sources (references) from each object:
# -----------------------------------------------------------------------------


def obtain_sources(ext_list: list[dict] | None) -> list[dict] | None:
    """
    Filter a list of dicts to only return those with 'description' keys.

    Args:
        - ext_list: List of dicts to filter (or None)

    Returns:
        List of dicts containing 'description' keys, or None
    """
    if not isinstance(ext_list, list):
        return None

    return [obj for obj in ext_list if 'description' in obj]


# -----------------------------------------------------------------------------
# Match all tactics for a given technique kill_chain_phases list:
# -----------------------------------------------------------------------------


def match_tactics(
    short_name_to_match: str, kill_chain_phases: list[dict] | None
) -> bool | None:
    """
    Check if any kill chain phase matches the given short name.

    Args:
        short_name_to_match: The phase name to search for
        kill_chain_phases: List of kill chain phase dictionaries (or None)

    Returns:
        True if match found, None if no match or invalid input
    """
    if not isinstance(kill_chain_phases, list):
        return None

    for phase in kill_chain_phases:
        if phase.get('phase_name') == short_name_to_match:
            return True

    return None


# -----------------------------------------------------------------------------
# Set relationships:
# -----------------------------------------------------------------------------


def set_relationships(
    attack_objects: Dict[str, Any],
) -> Tuple[Dict[str, List[str]], Dict[str, Dict]]:
    """
    Set the relationship mappings and ID lookup from the attack objects.

    Args:
        attack_objects: Dict containing 'objects' list of attack objects

    Returns:
        Tuple of (relationships dict, id_lookup dict)

    Raises:
        enterpriseattack.Error: If input JSON structure is invalid
    """
    # Check for bogus json:
    if not attack_objects.get('objects'):
        raise enterpriseattack.Error(
            'Unable to find enterprise objects, json seems invalid.'
        )

    relationships = {}
    id_lookup = {}

    for obj in attack_objects['objects']:
        obj_id = obj.get('id')
        obj_type = obj.get('type')

        # Add to ID lookup if valid object
        if obj_id and obj_type != 'relationship':
            id_lookup[obj_id] = obj

        # Handle relationship objects
        if obj_type == 'relationship':
            source = obj.get('source_ref')
            target = obj.get('target_ref')
            if source and target:
                relationships.setdefault(source, []).append(target)
                relationships.setdefault(target, []).append(source)

        # Handle data components
        elif obj_type == 'x-mitre-data-component':
            component_id = obj_id
            data_source = obj.get('x_mitre_data_source_ref')
            if component_id and data_source:
                relationships.setdefault(component_id, []).append(data_source)
                relationships.setdefault(data_source, []).append(component_id)

    return relationships, id_lookup
