# ----------------------------------------------------------------------------#

import enterpriseattack
import pytest

from pathlib import Path

# ----------------------------------------------------------------------------#


@pytest.fixture
def attack_update_latest_subscript_deprecated(scope='module'):
    return enterpriseattack.Attack(
        mitre_version='latest',
        subscriptable=True,
        update=True,
        include_deprecated=True
    )

# ----------------------------------------------------------------------------#


@pytest.fixture
def attack_update_latest_nonSubscript_deprecated(scope='module'):
    return enterpriseattack.Attack(
        mitre_version='latest',
        subscriptable=False,
        update=True,
        include_deprecated=True
    )

# ----------------------------------------------------------------------------#


@pytest.fixture
def attack_local(scope='module'):
    localJson = f'{Path(__file__).parent}/data/enterprise-attack.json'
    return enterpriseattack.Attack(enterprise_json=localJson)
