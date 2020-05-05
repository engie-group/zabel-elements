# Copyright (c) 2019 Martin Lafaix (martin.lafaix@external.engie.com)
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0

"""Kubernetes helpers.

A set of helpers for working with Kubernetes APIs.

This module depends on the public **kubernetes** library.  It also
depends on one **zabel-commons** module, #::zabel.commons.exceptions.
"""

from typing import Any, Callable, Dict, IO, Iterable, List, Mapping, Union

import io
import re

import yaml

from kubernetes import client as klient
from kubernetes.client.rest import ApiException

from zabel.commons.exceptions import ApiError


########################################################################
# Inspired from:
# <https://github.com/kubernetes-client/python/blob/master/kubernetes/utils/create_from_yaml.py>


def _map(
    func: Callable[..., Any],
    source: Union[str, IO[str]],
    client: klient.ApiClient,
    **kwargs: Any,
) -> None:
    if isinstance(source, str):
        with io.StringIO(source) as src:
            yml_document_all: Iterable[Dict[str, Any]] = list(
                d for d in yaml.safe_load_all(src)
            )
    else:
        yml_document_all = yaml.safe_load_all(source)

    failures: List[ApiException] = []
    for yml_document in yml_document_all:
        try:
            func(client, yml_document, **kwargs)
        except KubernetesError as failure:
            failures.extend(failure.api_exceptions)
    if failures:
        raise KubernetesError(failures)


def _create_from_dict(
    client: klient.ApiClient, data: Mapping[str, Any], **kwargs: Any
) -> None:
    """
    Perform a create action from a dictionary containing valid
    kubernetes API object (i.e. List, Service, etc).

    # Required parameters

    - client: an ApiClient object, initialized with the client args.
    - data: a dictionary holding valid kubernetes objects

    # Raised exceptions

    _FailToCreateError_ which holds list of `ApiException` instances for
    each object that failed to create.
    """
    # If it is a list type, will need to iterate its items
    api_exceptions = []

    command = 'create'
    if 'List' in data['kind']:
        # Could be "List" or "Pod/Service/...List"
        # This is a list type. iterate within its items
        kind = data['kind'].replace('List', '')
        for yml_object in data['items']:
            # Mitigate cases when server returns a xxxList object
            # See kubernetes-client/python#586
            if kind != '':
                yml_object['apiVersion'] = data['apiVersion']
                yml_object['kind'] = kind
            try:
                _do_for_yaml_single_item(command, client, yml_object, **kwargs)
            except ApiException as api_exception:
                api_exceptions.append(api_exception)
    else:
        # This is a single object. Call the single item method
        try:
            _do_for_yaml_single_item(command, client, data, **kwargs)
        except ApiException as api_exception:
            api_exceptions.append(api_exception)

    # In case we have exceptions waiting for us, raise them
    if api_exceptions:
        raise KubernetesError(api_exceptions)


def _apply_from_dict(
    client: klient.ApiClient, data: Mapping[str, Any], **kwargs: Any
) -> None:
    """
    Perform an apply action from a dictionary containing valid
    kubernetes API object (i.e. List, Service, etc).

    # Required parameters

    - client: an ApiClient object, initialized with the client args.
    - data: a dictionary holding valid kubernetes objects

    # Raised exceptions

    _FailToApplyError_ which holds list of `client.rest.ApiException`
    instances for each object that failed to apply.
    """
    # If it is a list type, will need to iterate its items
    api_exceptions: List[ApiException] = []

    if 'List' in data['kind']:
        # Could be "List" or "Pod/Service/...List"
        # This is a list type. iterate within its items
        kind = data['kind'].replace('List', '')
        for body in data['items']:
            # Mitigate cases when server returns a xxxList object
            # See kubernetes-client/python#586
            if kind != '':
                body['apiVersion'] = data['apiVersion']
                body['kind'] = kind
            _safe_apply_from_yaml_single_item(
                client, body, api_exceptions, **kwargs
            )
    else:
        # This is a single object. Call the single item method
        _safe_apply_from_yaml_single_item(
            client, data, api_exceptions, **kwargs
        )

    # In case we have exceptions waiting for us, raise them
    if api_exceptions:
        raise KubernetesError(api_exceptions)


def _safe_apply_from_yaml_single_item(
    client: klient.ApiClient,
    body: Mapping[str, Any],
    api_exceptions: List[Any],
    **kwargs: Any,
) -> None:
    """
    Perform an "apply" action (create if it does not exist, patch if it
    already does).
    """
    exists = False
    try:
        _do_for_yaml_single_item('read', client, body, **kwargs)
        exists = True
        _do_for_yaml_single_item('patch', client, body, **kwargs)
    except ApiException as api_exception1:
        if not exists:
            try:
                _do_for_yaml_single_item('create', client, body, **kwargs)
            except ApiException as api_exception2:
                api_exceptions.append(api_exception2)
        else:
            api_exceptions.append(api_exception1)


def _do_for_yaml_single_item(
    command: str,
    client: klient.ApiClient,
    body: Mapping[str, Any],
    **kwargs: Any,
) -> None:
    group, _, version = body['apiVersion'].partition('/')
    if version == '':
        version = group
        group = 'core'
    # Take care for the case e.g. api_type is "apiextensions.k8s.io"
    # Only replace the last instance
    group = ''.join(group.rsplit('.k8s.io', 1))
    # convert group name from DNS subdomain format to
    # python class name convention
    group = ''.join(word.capitalize() for word in group.split('.'))
    fcn_to_call = '{0}{1}Api'.format(group, version.capitalize())
    k8s_api = getattr(klient, fcn_to_call)(client)
    # Replace CamelCased action_type into snake_case
    kind = body['kind']
    kind = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', kind)
    kind = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', kind).lower()
    # Expect the user to create namespaced objects more often
    if hasattr(k8s_api, f'{command}_namespaced_{kind}'):
        # Decide which namespace we are going to put the object in,
        # if any
        if 'namespace' in body['metadata']:
            namespace = body['metadata']['namespace']
            kwargs['namespace'] = namespace
        getattr(k8s_api, f'{command}_namespaced_{kind}')(body=body, **kwargs)
    else:
        kwargs.pop('namespace', None)
        getattr(k8s_api, f'{command}_{kind}')(body=body, **kwargs)


class KubernetesError(ApiError):
    """
    An exception class for handling error if an error occurred when
    handling a YAML file.
    """

    def __init__(self, api_exceptions: List[ApiException]) -> None:
        self.api_exceptions = api_exceptions

    def __str__(self) -> str:
        msg = ''
        for api_exception in self.api_exceptions:
            msg += 'Error from server ({0}): {1}'.format(
                api_exception.reason, api_exception.body
            )
        return msg
