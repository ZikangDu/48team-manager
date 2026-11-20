"""Credential integration keeps email-provider hints separate from official roles."""

import unittest
from types import SimpleNamespace

from app.domain.identity.audit import audit_account


class ImportedIdentityTests(unittest.TestCase):
    def account(self, *, purpose='standby'):
        return SimpleNamespace(id=1, email='child.fixture@gmail.com', local_purpose=purpose,
                               official_user_id=None, official_account_id=None,
                               official_plan='unknown', operational_state='available')

    def check(self, account, memberships=(), workspaces=None):
        return audit_account(account, memberships=memberships, bindings=[], remote_owners={},
                             workspaces_by_id=workspaces or {})

    def test_gmail_unassigned_is_not_assumed_to_be_an_owner(self):
        result = self.check(self.account())
        self.assertNotEqual(result['result'], 'conflict')
        self.assertFalse(any('Gmail' in reason for reason in result['reasons']))

    def test_mother_still_requires_owner_membership(self):
        result = self.check(self.account(purpose='mother'))
        self.assertEqual(result['result'], 'conflict')
        self.assertIn('本地用途是母号，但没有 owner membership', result['reasons'])
