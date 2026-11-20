"""Manual import HTTP contract with synthetic credentials and isolated SQLite."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from tests.helpers import make_client
from tests.test_credential_import import record


class CredentialImportApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.context = make_client(Path(self.tmp.name))
        self.client = self.context.__enter__()

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.tmp.cleanup()

    def login(self):
        self.assertEqual(self.client.post('/auth/login', json={
            'username': 'hixz12', 'password': 'test-password',
        }).status_code, 200)

    def assert_private(self, response):
        self.assertEqual(response.headers.get('cache-control'), 'no-store')
        self.assertEqual(response.headers.get('pragma'), 'no-cache')

    def test_admin_required_and_errors_are_private(self):
        for method, path in [('POST', '/api/credential-import/preview'),
                             ('POST', '/api/credential-import/commit'),
                             ('DELETE', '/api/credential-import/preview/unknown')]:
            response = self.client.request(method, path)
            self.assertEqual(response.status_code, 401)
            self.assert_private(response)
        self.login()
        response = self.client.post('/api/credential-import/preview', json={'content': 42})
        self.assertEqual(response.status_code, 400)
        self.assert_private(response)

    def test_exact_origin_and_fetch_metadata_are_required_for_browser_requests(self):
        self.login()
        with patch('app.application.credential_import.preview_import', AsyncMock(return_value={'ok': True})) as preview:
            for origin in ['https://testserver', 'http://testserver:81', 'http://testserver/path',
                           'http://testserver?', 'http://testserver#', 'null', '']:
                response = self.client.post('/api/credential-import/preview',
                    json={'content': '{}'}, headers={'origin': origin})
                self.assertEqual(response.status_code, 403)
                self.assert_private(response)
            for site in ['cross-site', 'same-site']:
                response = self.client.post('/api/credential-import/preview',
                    json={'content': '{}'}, headers={'sec-fetch-site': site})
                self.assertEqual(response.status_code, 403)
            preview.assert_not_awaited()
            for origin in ['http://testserver', 'http://testserver:80']:
                response = self.client.post('/api/credential-import/preview',
                    json={'content': '{}'}, headers={'origin': origin, 'sec-fetch-site': 'same-origin'})
                self.assertEqual(response.status_code, 200)

    def test_preview_then_explicit_commit_and_no_duplicate_submission(self):
        self.login()
        source = record()
        preview = self.client.post('/api/credential-import/preview', json={'content': json.dumps(source)})
        self.assertEqual(preview.status_code, 200)
        self.assert_private(preview)
        self.assertNotIn(source['access_token'], preview.text)
        self.assertNotIn(source['refresh_token'], preview.text)
        payload = preview.json()
        self.assertTrue(payload['candidates'][0]['allowed'])
        selection = {'draft_id': payload['draft_id'], 'selected_ids': [payload['candidates'][0]['id']]}
        with patch('app.application.quota.quota_service.enqueue', AsyncMock()) as enqueue:
            saved = self.client.post('/api/credential-import/commit', json=selection)
            self.assertEqual(saved.status_code, 200)
            self.assertEqual(saved.json()['count'], 1)
            self.assertEqual(saved.json()['imported'][0]['verification'], 'pending')
            enqueue.assert_not_awaited()
        self.assert_private(saved)
        listing = self.client.get('/api/accounts/portfolio')
        self.assertEqual(listing.status_code, 200)
        self.assertIn('member@example.com', listing.text)
        repeated = self.client.post('/api/credential-import/commit', json=selection)
        self.assertEqual(repeated.status_code, 409)
        self.assert_private(repeated)

    def test_discard_invalidates_preview(self):
        self.login()
        preview = self.client.post('/api/credential-import/preview', json={'content': record()}).json()
        response = self.client.delete('/api/credential-import/preview/' + preview['draft_id'])
        self.assertEqual(response.status_code, 200)
        rejected = self.client.post('/api/credential-import/commit', json={
            'draft_id': preview['draft_id'], 'selected_ids': [preview['candidates'][0]['id']]})
        self.assertEqual(rejected.status_code, 410)

    def test_invalid_json_and_oversized_requests_never_echo_secrets(self):
        self.login()
        sentinel = 'DO-NOT-ECHO-PRIVATE-DATA'
        response = self.client.post('/api/credential-import/preview', content='{'+sentinel,
                                    headers={'content-type': 'application/json'})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(sentinel, response.text)
        with patch('app.web.routes.credential_import.MAX_BODY_BYTES', 16):
            response = self.client.post('/api/credential-import/preview', json={'content': sentinel})
        self.assertEqual(response.status_code, 413)
        self.assertNotIn(sentinel, response.text)
        self.assert_private(response)

    def test_automated_account_routes_are_not_registered(self):
        paths = {route.path for route in self.client.app.routes if hasattr(route, 'path')}
        self.assertFalse(any(path.startswith('/api/auth-bridge') for path in paths))
        self.assertEqual(self.client.get('/health').status_code, 200)

    def test_ambiguous_json_is_rejected_before_business_logic(self):
        self.login()
        with patch('app.application.credential_import.preview_import', AsyncMock()) as preview:
            for raw in ['{"content":{},"content":[]}',
                        '{"content":{"email":"first@example.com","email":"second@example.com"}}',
                        '{"content":[{"expires":NaN}]}']:
                response = self.client.post('/api/credential-import/preview', content=raw,
                                            headers={'content-type': 'application/json'})
                self.assertEqual(response.status_code, 400)
                self.assert_private(response)
            preview.assert_not_awaited()
