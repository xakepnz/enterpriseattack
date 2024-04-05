# ----------------------------------------------------------------------------#

import enterpriseattack

from pathlib import Path
import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)


def test_local_load():

    localJson = f'{Path(__file__).parent}/data/enterprise-attack.json'

    attack = enterpriseattack.Attack(enterprise_json=localJson)

    assert attack.attack_objects is not None
