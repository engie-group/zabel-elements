# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""
...
"""

from zabel.commons.interfaces import Image
from zabel.commons.servers import ApiApp


########################################################################
# Interface


class UtilityApp(ApiApp, Image):
    """Abstract Utility API app."""
