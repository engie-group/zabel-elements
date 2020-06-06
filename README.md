# zabel-elements

The standard tools library for Zabel.

It contains two parts:

1. The **zabel.elements.clients** module
2. The **zabel.elements.services** base classes module

The tools handled in this library are:

- Artifactory
- Confluence
- GitHub
- CloudBeesJenkins
- Jira
- Kubernetes (in alpha)
- SonarQube
- SquashTM

## zabel.elements.clients

The **zabel.elements.clients** library provides a wrapper class per
tool.

It relies on the **zabel-commons** library, using its
_zabel.commons.exceptions_ module for the _ApiError_ exception class,
its _zabel.commons.sessions_ module for HTTPS session handling,
and its _zabel.commons.utils_ module that contains useful functions.

### Conventions

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

## zabel.elements.services

It provides wrappers for the built-in low-level clients classes (those
defined in the **zabel.elements.clients** module).

Those abstract service wrappers implement an `__init__` constructor with
the following two parameters:

- `name`: a string, the service name
- `env`: a dictionary, the service parameters

Managed services also implement at least the `list_members()` method of
the #::ManagedService interface.  They may provide `get_member()` if a
fast implementation is available.

Concrete classes deriving those abstract managed services wrappers
should provide a `get_canonical_member_id()` method that takes a
parameter, a user from the wrapped API point of view, and returns the
canonical user ID, as well as a `get_internal_member_id()` method that
takes a canonical user ID and returns the internal key for that user.

They should also provide concrete implementations for the remaining
methods provided by the #::ManagedService interface.

### Conventions

Utilities must implement the _Utility_ interface and managed services
must implement the _ManagedService_ interface.
