# ----------------------------------------------------------------------------#

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)

# ----------------------------------------------------------------------------#


def test_software_sub_techniques(attack_update_latest_nonSubscript_deprecated):
    _found = False

    for software in attack_update_latest_nonSubscript_deprecated.software:
        if software.sub_techniques:
            _found = True

            assert len(software.sub_techniques) > 0

    # if we didn't find any sub_techniques, raise assertion error:
    if _found is False:
        raise AssertionError('No sub_techniques found')
