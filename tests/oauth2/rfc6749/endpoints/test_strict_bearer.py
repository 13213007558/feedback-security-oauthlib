"""Strict Bearer token extraction for the resource endpoint.

These tests drive the public :meth:`ResourceEndpoint.verify_request` entry
point. A call ledger on the request validator proves that requests rejected by
the strict extraction policy never reach the business
``validate_bearer_token`` method.
"""
import json
from unittest import mock

from oauthlib.oauth2 import (
    BackendApplicationServer, WebApplicationServer,
)
from oauthlib.oauth2.rfc6749 import errors, tokens
from oauthlib.oauth2.rfc6749.endpoints.resource import ResourceEndpoint

from tests.unittest import TestCase


FORM_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}
TOKEN = 'vF9dft4qmT'


class StrictBearerEndpointTest(TestCase):

    def setUp(self):
        # The ledger records every token handed to the business validation
        # method, allowing each test to assert whether authorization logic
        # was entered at all.
        self.mock_validator = mock.MagicMock()
        self.mock_validator.validate_bearer_token.side_effect = \
            lambda token, scopes, request: bool(token)
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        bearer = tokens.BearerToken(request_validator=self.mock_validator)
        self.endpoint = ResourceEndpoint(
            default_token='Bearer',
            token_types={'Bearer': bearer},
            strict_bearer=True,
        )
        self.lenient = ResourceEndpoint(
            default_token='Bearer',
            token_types={'Bearer': tokens.BearerToken(
                request_validator=self.mock_validator)},
        )

    def _assert_rejected_before_validation(self, **kwargs):
        with self.assertRaises(errors.InvalidRequestError) as ctx:
            self.endpoint.verify_request(**kwargs)
        self.assertEqual(ctx.exception.error, 'invalid_request')
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(json.loads(ctx.exception.json),
                         {'error': 'invalid_request',
                          'error_description': ctx.exception.description})
        self.mock_validator.validate_bearer_token.assert_not_called()
        return ctx.exception

    # -- single, legal carrier reaches the validator ----------------------

    def test_single_header_token_is_validated(self):
        valid, request = self.endpoint.verify_request(
            'https://example.com/resource',
            headers={'Authorization': 'Bearer ' + TOKEN},
        )
        self.assertTrue(valid)
        self.assertEqual(request.token_type, 'Bearer')
        self.mock_validator.validate_bearer_token.assert_called_once_with(
            TOKEN, None, request)

    def test_single_query_token_is_validated(self):
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource?access_token=' + TOKEN,
        )
        self.assertTrue(valid)
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][0], TOKEN)

    def test_single_form_body_token_is_validated(self):
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource',
            http_method='POST',
            body='access_token=' + TOKEN,
            headers=dict(FORM_HEADERS),
        )
        self.assertTrue(valid)
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][0], TOKEN)

    def test_bearer_scheme_is_case_insensitive(self):
        for header in ('bearer ' + TOKEN, 'BEARER ' + TOKEN,
                       'bEaReR ' + TOKEN):
            self.mock_validator.reset_mock()
            valid, _request = self.endpoint.verify_request(
                'https://example.com/resource',
                headers={'Authorization': header},
            )
            self.assertTrue(valid)
            self.assertEqual(
                self.mock_validator.validate_bearer_token.call_args[0][0],
                TOKEN)

    def test_repeated_whitespace_in_header_still_supported(self):
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource',
            headers={'Authorization': 'Bearer  ' + TOKEN},
        )
        self.assertTrue(valid)

    # -- multiple carriers conflict ----------------------------------------

    def test_header_and_query_conflict(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource?access_token=query-token',
            headers={'Authorization': 'Bearer ' + TOKEN},
        )

    def test_header_and_form_body_conflict(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource',
            http_method='POST',
            body='access_token=body-token',
            headers={'Authorization': 'Bearer ' + TOKEN, **FORM_HEADERS},
        )

    def test_query_and_form_body_conflict(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource?access_token=query-token',
            http_method='POST',
            body='access_token=body-token',
            headers=dict(FORM_HEADERS),
        )

    def test_all_three_carriers_conflict(self):
        exc = self._assert_rejected_before_validation(
            uri='https://example.com/resource?access_token=query-token',
            http_method='POST',
            body='access_token=body-token',
            headers={'Authorization': 'Bearer ' + TOKEN, **FORM_HEADERS},
        )
        self.assertIn('header', exc.description)
        self.assertIn('query', exc.description)
        self.assertIn('body', exc.description)

    def test_identical_token_in_two_carriers_still_conflicts(self):
        # Two carriers carrying the very same token value are still two
        # distinct credential carriers and must be rejected.
        self._assert_rejected_before_validation(
            uri='https://example.com/resource?access_token=' + TOKEN,
            headers={'Authorization': 'Bearer ' + TOKEN},
        )

    # -- duplicate parameter within a single carrier -----------------------

    def test_duplicate_query_parameter_is_not_collapsed(self):
        # A dict view would keep only one value; the raw query keeps both.
        exc = self._assert_rejected_before_validation(
            uri='https://example.com/resource?access_token=a&access_token=b',
        )
        self.assertIn('query', exc.description)

    def test_duplicate_form_body_parameter_string_is_not_collapsed(self):
        exc = self._assert_rejected_before_validation(
            uri='https://example.com/resource',
            http_method='POST',
            body='access_token=a&access_token=b',
            headers=dict(FORM_HEADERS),
        )
        self.assertIn('body', exc.description)

    def test_duplicate_form_body_parameter_tuples_are_not_collapsed(self):
        # Frameworks that pass parsed multi-value form fields as tuples must
        # not have the duplicate folded away upstream or internally.
        exc = self._assert_rejected_before_validation(
            uri='https://example.com/resource',
            http_method='POST',
            body=[('access_token', 'a'), ('access_token', 'b')],
            headers=dict(FORM_HEADERS),
        )
        self.assertIn('body', exc.description)

    def test_duplicate_query_with_same_value_rejected(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource?access_token=x&access_token=x',
        )

    # -- form carrier restrictions ------------------------------------------

    def test_form_body_on_get_is_rejected(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource',
            http_method='GET',
            body='access_token=' + TOKEN,
            headers=dict(FORM_HEADERS),
        )

    def test_form_body_on_delete_is_rejected(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource',
            http_method='DELETE',
            body='access_token=' + TOKEN,
            headers=dict(FORM_HEADERS),
        )

    def test_form_body_with_wrong_content_type_is_rejected(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource',
            http_method='POST',
            body='access_token=' + TOKEN,
            headers={'Content-Type': 'text/plain'},
        )

    def test_content_type_parameters_are_allowed(self):
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource',
            http_method='POST',
            body='access_token=' + TOKEN,
            headers={'Content-Type':
                     'application/x-www-form-urlencoded; charset=utf-8'},
        )
        self.assertTrue(valid)

    def test_json_body_is_not_a_form_carrier(self):
        # A JSON field named access_token is not a form credential; no carrier
        # is detected, so the validator receives None and denies access.
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource',
            http_method='POST',
            body='{"access_token": "%s"}' % TOKEN,
            headers={'Content-Type': 'application/json'},
        )
        self.assertFalse(valid)
        self.mock_validator.validate_bearer_token.assert_called_once()
        self.assertIsNone(
            self.mock_validator.validate_bearer_token.call_args[0][0])

    def test_json_body_does_not_conflict_with_header(self):
        # The JSON field is ignored, leaving the header as the sole carrier.
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource',
            http_method='POST',
            body='{"access_token": "%s"}' % TOKEN,
            headers={'Authorization': 'Bearer ' + TOKEN,
                     'Content-Type': 'application/json'},
        )
        self.assertTrue(valid)
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][0], TOKEN)

    # -- header edge cases --------------------------------------------------

    def test_empty_bearer_header_is_rejected(self):
        for header in ('Bearer', 'Bearer ',):
            self._assert_rejected_before_validation(
                uri='https://example.com/resource',
                headers={'Authorization': header},
            )

    def test_malformed_bearer_header_with_extra_token_is_rejected(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource',
            headers={'Authorization': 'Bearer one two'},
        )

    def test_other_scheme_is_not_a_bearer_carrier(self):
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource',
            headers={'Authorization': 'Basic ' + TOKEN},
        )
        self.assertFalse(valid)
        self.mock_validator.validate_bearer_token.assert_called_once()
        self.assertIsNone(
            self.mock_validator.validate_bearer_token.call_args[0][0])

    def test_other_scheme_does_not_conflict_with_query(self):
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource?access_token=' + TOKEN,
            headers={'Authorization': 'Basic abc'},
        )
        self.assertTrue(valid)
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][0], TOKEN)

    # -- token type selection and scope validation --------------------------

    def test_still_selects_bearer_token_type(self):
        _valid, request = self.endpoint.verify_request(
            'https://example.com/resource?access_token=' + TOKEN,
            scopes=['photos'],
        )
        self.assertEqual(request.token_type, 'Bearer')
        self.assertEqual(request.scopes, ['photos'])
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][1],
            ['photos'])

    def test_validator_denial_propagates(self):
        self.mock_validator.validate_bearer_token.side_effect = None
        self.mock_validator.validate_bearer_token.return_value = False
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource',
            headers={'Authorization': 'Bearer ' + TOKEN},
        )
        self.assertFalse(valid)
        self.mock_validator.validate_bearer_token.assert_called_once()

    # -- no credential at all -----------------------------------------------

    def test_missing_token_passes_none_to_validator(self):
        valid, _request = self.endpoint.verify_request(
            'https://example.com/resource')
        self.assertFalse(valid)
        self.mock_validator.validate_bearer_token.assert_called_once_with(
            None, None, mock.ANY)

    def test_empty_query_value_is_rejected(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource?access_token=',
        )

    def test_empty_form_value_is_rejected(self):
        self._assert_rejected_before_validation(
            uri='https://example.com/resource',
            http_method='POST',
            body='access_token=',
            headers=dict(FORM_HEADERS),
        )


class StrictBearerConfigurationTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.mock_validator.validate_bearer_token.side_effect = \
            lambda token, scopes, request: bool(token)
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())

    def _conflict_kwargs(self):
        return {
            'uri': 'https://example.com/resource?access_token=query-token',
            'headers': {'Authorization': 'Bearer header-token'},
        }

    def test_default_is_lenient(self):
        endpoint = ResourceEndpoint(
            default_token='Bearer',
            token_types={'Bearer': tokens.BearerToken(self.mock_validator)},
        )
        self.assertFalse(endpoint.strict_bearer)
        # Lenient mode picks the header token instead of rejecting.
        valid, _request = endpoint.verify_request(**self._conflict_kwargs())
        self.assertTrue(valid)
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][0],
            'header-token')

    def test_flag_can_be_toggled_at_runtime(self):
        endpoint = ResourceEndpoint(
            default_token='Bearer',
            token_types={'Bearer': tokens.BearerToken(self.mock_validator)},
        )
        endpoint.strict_bearer = True
        self.assertTrue(endpoint.strict_bearer)
        with self.assertRaises(errors.InvalidRequestError):
            endpoint.verify_request(**self._conflict_kwargs())
        self.mock_validator.validate_bearer_token.assert_not_called()

        endpoint.strict_bearer = False
        valid, _request = endpoint.verify_request(**self._conflict_kwargs())
        self.assertTrue(valid)

    def test_preconfigured_servers_default_to_lenient(self):
        for server_cls in (WebApplicationServer, BackendApplicationServer):
            server = server_cls(self.mock_validator)
            self.assertFalse(server.strict_bearer)
            valid, _request = server.verify_request(**self._conflict_kwargs())
            self.assertTrue(valid)

    def test_preconfigured_server_enables_strict_mode(self):
        server = WebApplicationServer(self.mock_validator, strict_bearer=True)
        self.assertTrue(server.strict_bearer)
        with self.assertRaises(errors.InvalidRequestError):
            server.verify_request(**self._conflict_kwargs())
        self.mock_validator.validate_bearer_token.assert_not_called()

    def test_backend_application_server_strict_mode(self):
        server = BackendApplicationServer(
            self.mock_validator, strict_bearer=True)
        with self.assertRaises(errors.InvalidRequestError):
            server.verify_request(
                'https://example.com/resource?access_token=a&access_token=b')
        self.mock_validator.validate_bearer_token.assert_not_called()


class LenientCompatibilityTest(TestCase):
    """The default mode must preserve the historical extraction behaviour."""

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.mock_validator.validate_bearer_token.side_effect = \
            lambda token, scopes, request: bool(token)
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        self.endpoint = ResourceEndpoint(
            default_token='Bearer',
            token_types={'Bearer': tokens.BearerToken(self.mock_validator)},
        )

    def test_header_takes_precedence_over_query(self):
        self.endpoint.verify_request(
            'https://example.com/resource?access_token=query-token',
            headers={'Authorization': 'Bearer header-token'},
        )
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][0],
            'header-token')

    def test_present_but_malformed_header_returns_none_token(self):
        # Historical get_token_from_header only falls back to the query/body
        # when there is no Authorization header at all; a present but
        # malformed header yields None rather than picking another carrier.
        for header in ('Bearer', 'Beaver header-token'):
            self.mock_validator.reset_mock()
            self.endpoint.verify_request(
                'https://example.com/resource?access_token=query-token',
                headers={'Authorization': header},
            )
            self.assertIsNone(
                self.mock_validator.validate_bearer_token.call_args[0][0])

    def test_no_header_falls_back_to_query(self):
        self.endpoint.verify_request(
            'https://example.com/resource?access_token=query-token')
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][0],
            'query-token')

    def test_duplicate_query_uses_last_dict_value(self):
        self.endpoint.verify_request(
            'https://example.com/resource?access_token=a&access_token=b')
        # Historical behaviour: request.access_token keeps the last value.
        self.assertEqual(
            self.mock_validator.validate_bearer_token.call_args[0][0], 'b')
