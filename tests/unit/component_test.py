# ----------------------------------------------------------------------------#

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)

# ----------------------------------------------------------------------------#


# def test_component_techniques(attack_update_latest_nonSubscript_deprecated):
#     _found = False

#     for component in attack_update_latest_nonSubscript_deprecated.components:

#         # not all components have techniques:
#         if component.techniques:
#             _found = True

#             assert len(component.techniques) > 0

#     # if we didn't find any techniques, raise assertion error:
#     if _found is False:
#         raise AssertionError('No techniques found')
