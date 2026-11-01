import sqlite3
import unittest

from login_system import AuthError, EmailCodeAuth, SCHEMA


class LoginSystemTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript(SCHEMA)
        self.auth = EmailCodeAuth(self.db, 1000, 'example.edu', demo=True)

    def tearDown(self):
        self.db.close()

    def test_user_sessions_and_code_are_scoped(self):
        code = self.auth.issue_code({'email': 'A@example.edu'})['demoCode']
        with self.assertRaises(AuthError):
            self.auth.verify_code({'email': 'b@example.edu', 'code': code})
        user_id = self.auth.verify_code({'email': 'a@example.edu', 'code': code})
        token = self.auth.sign_in(user_id)
        self.assertEqual(self.auth.user_for_session(token)['email'], 'a@example.edu')
        self.assertIsNone(EmailCodeAuth(self.db, 1000 + 7 * 86400, 'example.edu').user_for_session(token))
        self.auth.logout(token)
        self.assertIsNone(self.auth.user_for_session(token))

    def test_bad_codes_are_limited_and_domain_is_checked(self):
        with self.assertRaises(AuthError):
            self.auth.issue_code({'email': 'a@example.edu.evil'})
        self.auth.issue_code({'email': 'a@example.edu'})
        for _ in range(5):
            with self.assertRaises(AuthError):
                self.auth.verify_code({'email': 'a@example.edu', 'code': 'wrong'})
        with self.assertRaises(AuthError) as error:
            self.auth.verify_code({'email': 'a@example.edu', 'code': 'wrong'})
        self.assertEqual(error.exception.status, 429)

    def test_production_sender_and_cooldown(self):
        auth = EmailCodeAuth(self.db, 1000, 'example.edu')
        sent = []
        self.assertNotIn('demoCode', auth.issue_code({'email': 'a@example.edu'}, lambda email, code: sent.append((email, code))))
        self.assertEqual(sent[0][0], 'a@example.edu')
        with self.assertRaises(AuthError) as error:
            auth.issue_code({'email': 'a@example.edu'}, lambda *_: None)
        self.assertEqual(error.exception.status, 429)


if __name__ == '__main__':
    unittest.main()
