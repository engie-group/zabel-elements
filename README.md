# zabel-elements

## Overview

This is part of the Zabel platform.  The **zabel-elements** package
contains the standard _elements_ library for Zabel.

An element is an external service such as _Artifactory_ or _Jenkins_ or a
LDAP server that can be managed or used by Zabel.

This package provides the necessary wrappers for some elements commonly
found in many workplaces, namely:

- Artifactory
- CloudBeesJenkins
- Confluence
- GitHub
- Jira
- Kubernetes (in alpha)
- SonarQube
- SquashTM

Elements are of two kinds: _ManagedServices_, that represent services that are
managed by Zabel, and _Utilities_, that represent services that are used by Zabel.

Managed services host project resources.  They typically are the tools that project
members interact with directly.

Utilities may also host project resources, but they typically are not used directly
by project members.  They are either references or infrastructure services necessary
for the managed services to function, but otherwise not seen by project members.
A LDAP server would probably be a utility, used both as a reference and as an access
control tool.

In the above list, Kubernetes is a utility.  The other elements are managed services.

You can use this library independently of the Zabel platform, as it has no
specific dependencies on it.  In particular, the **zabel.elements.clients**
module may be of interest if you want to perform some configuration tasks
from your own Python code.

Contribution of new wrappers, or extensions of existing wrappers are welcomed.
But elements can be provided in their own packages too.

## Architecture

It contains two parts:

- The **zabel.elements.clients** module
- The **zabel.elements.images** base classes module

There is one _image_ per client (hence one image per element).  Images are
classes with a standardized constructor and a `run()` method, and are how
code is packaged so that it can be deployed on the Zabel platform.

## zabel.elements.clients

The **zabel.elements.clients** module provides a wrapper class per
tool.

It relies on the **zabel-commons** library, using its
_zabel.commons.exceptions_ module for the _ApiError_ exception class,
its _zabel.commons.sessions_ module for HTTPS session handling,
and its _zabel.commons.utils_ module that contains useful functions.

### Conventions for Clients

If an existing library already provides all the needed functionality,
there is no need to add it to this library.

If an existing library already provides some of the needed
functionality, a wrapper class can be written that will use this
existing library as a client.  Do not inherit from it.

Wrapper classes have two parts: a _base_ part that implements single
API calls (and possibly pagination), and a _regular_ part that
inherits from the base part and possibly extends it.

The base part may not exist if an already existing library
provides wrappers for the needed low-level calls.  In such a
case, there is no need for a base class and the regular class may simply
use the existing library as a client and inherit from `object`.

Similarly, the regular part may be empty, in that it may simply inherit
from the base class and contain no additional code.

At import time, wrapper classes should not import libraries not part of
the Python standard library or **requests** or modules part of the
**zabel-commons** library.  That way, projects not needing some tool do
not have to install its required dependencies.  Wrappers classes may
import libraries in their `__init__()` methods, though.

If an API call is successful, it will return a value (possibly None).
If not, it will raise an _ApiError_ exception.

If a wrapper class method is called with an obviously invalid parameter
(wrong type, not a permitted value, ...), a _ValueError_ exception will
be raised.

#### Note

Base classes do not try to provide features not offered by the tool API.

Their methods closely match the underlying API.

They offer a uniform (or, at least, harmonized) naming convention,
and may simplify technical details (pagination is automatically
performed if needed).

## zabel.elements.images

The **zabel.elements.images** module provides image wrappers for the
built-in clients classes (those defined in the **zabel.elements.clients**
module).

Those abstract image wrappers implement an `__init__()` constructor with
the following two parameters:

- `name`: a string, a name
- `env`: a dictionary, the image parameters

Managed services also implement at least the `list_members()` method of
the _ManagedService_ interface.  They may provide `get_member()` if a
fast implementation is available.

Concrete classes deriving those abstract managed services wrappers
should provide a `get_canonical_member_id()` method that takes a
parameter, a user from the wrapped API point of view, and returns the
canonical user ID, as well as a `get_internal_member_id()` method that
takes a canonical user ID and returns the internal key for that user.

They should also provide concrete implementations for the remaining
methods provided by the _ManagedService_ interface.

### Conventions for Images

Utilities must implement the _Utility_ interface and managed services
must implement the _ManagedService_ interface.

## License

```text
Copyright (c) 2019-2020 Martin Lafaix (martin.lafaix@external.engie.com) and others

This program and the accompanying materials are made
available under the terms of the Eclipse Public License 2.0
which is available at https://www.eclipse.org/legal/epl-2.0/

SPDX-License-Identifier: EPL-2.0
```
