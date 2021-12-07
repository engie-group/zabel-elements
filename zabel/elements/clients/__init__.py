# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""The low-level **clients** library.

The **zabel.elements.clients** library provides a wrapper class per
tool.

It relies on the **zabel-commons** library, using its
#::zabel.commons.exceptions module for the _ApiError_ exception class,
its #::zabel.commons.sessions module for HTTPS session handling,
and its #::zabel.commons.utils module that contains useful functions.

# Conventions

If an existing library already provides all the needed functionality,
there is no need to add it to this clients library.

If an existing library already provides some of the needed
functionality, a wrapper class can be written that will use this
existing library as a client.

Wrapper classes have two parts: (1) a _base_ part that implements single
API calls (and possibly pagination), and (2) a _regular_ part, that
inherits from the base part and possibly extends it.

The base part may not exist if an already existing library
provides wrappers for the needed low-level calls.  In such a
case, there is no need for a base class and the regular class may simply
use the existing library as a client, and inherit from `object`.

Similarly, the regular part may be empty, in that it may simply inherit
from the base class and contain no additional code.

At import time, wrapper classes should not import libraries not part of
the Python standard library or **requests** or modules part of the
**zabel-commons** library.  That way, projects not needing some tool do
not have to install its required dependencies.  Wrappers classes may
import libraries in their `__init__` methods, though.

If an API call is successful, it will return a value (possibly None).
If not, it will raise an _ApiError_ exception.

If a wrapper class method is called with an obviously invalid parameter
(wrong type, not a permitted value, ...), a _ValueError_ exception will
be raised.

!!! note
    Base classes do not try to provide features not offered by the
    tool API.

    Their methods closely match the underlying API

    They offer an uniform (or, at least, harmonized) naming convention,
    and may simplify technical details (pagination is automatically
    performed if needed).
"""

__all__ = [
    'Artifactory',
    'CloudBeesJenkins',
    'Confluence',
    'GitHub',
    'Jira',
    'Kubernetes',
    'Okta',
    'SonarQube',
    'SquashTM',
]


from .artifactory import Artifactory
from .jenkins import CloudBeesJenkins
from .confluence import Confluence
from .github import GitHub
from .jira import Jira
from .kubernetes import Kubernetes
from .sonarqube import SonarQube
from .squashtm import SquashTM
from .okta import Okta
