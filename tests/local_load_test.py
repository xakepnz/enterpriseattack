# ----------------------------------------------------------------------------#

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)


def test_local_load(attack_local):
    assert attack_local.attack_objects is not None
