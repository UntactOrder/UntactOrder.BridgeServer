import unittest
from unittest import mock
import mock_settings

with mock.patch.dict('sys.modules', settings=mock_settings):
    from src.main.api.sso_provider import SSOProvider


class TestSSOLogin(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, True)  # add assertion here
        self.assertEqual(SSOProvider.get_user_by_token("", "kakao"), "")


if __name__ == '__main__':
    unittest.main()
