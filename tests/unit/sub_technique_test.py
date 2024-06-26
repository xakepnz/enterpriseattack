# ----------------------------------------------------------------------------#

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)

# ----------------------------------------------------------------------------#


def test_sub_technique_groups(attack_update_latest_nonSubscript_deprecated):
    _found = False

    for sub_technique in \
            attack_update_latest_nonSubscript_deprecated.sub_techniques:
        if sub_technique.groups:
            _found = True

            assert len(sub_technique.groups) > 0

    # if we didn't find any groups, raise assertion error:
    if _found is False:
        raise AssertionError('No groups found')

# ----------------------------------------------------------------------------#


def test_sub_technique_tools(attack_update_latest_nonSubscript_deprecated):
    _found = False

    for sub_technique in \
            attack_update_latest_nonSubscript_deprecated.sub_techniques:
        if sub_technique.tools:
            _found = True

            assert len(sub_technique.tools) > 0

    # if we didn't find any tools, raise assertion error:
    if _found is False:
        raise AssertionError('No tools found')

# ----------------------------------------------------------------------------#


def test_sub_technique_components(
        attack_update_latest_nonSubscript_deprecated
        ):
    _found = False

    for sub_technique in \
            attack_update_latest_nonSubscript_deprecated.sub_techniques:
        if sub_technique.components:
            _found = True

            assert len(sub_technique.components) > 0

    # if we didn't find any components, raise assertion error:
    if _found is False:
        raise AssertionError('No components found')
