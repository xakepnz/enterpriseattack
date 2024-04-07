# ----------------------------------------------------------------------------#

import logging

# from tests.conftest import attack_update_latest_subscript_deprecated

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)

# ----------------------------------------------------------------------------#


def test_campaign_malware(attack_update_latest_nonSubscript_deprecated):
    _found = False

    for campaign in attack_update_latest_nonSubscript_deprecated.campaigns:

        # not all campaigns have malware:
        if campaign.malware:
            _found = True

            assert len(campaign.malware) > 0

    # if we didn't find any malware, raise assertion error:
    if _found is False:
        raise AssertionError('No malware found')
