import unittest
from unittest import mock


class MockSettings(object):
    from configparser import ConfigParser

    API_KEY_FILE = "../main/data/api.bridgesetting"
    api_config = ConfigParser()
    api_config.read(API_KEY_FILE)


with mock.patch.dict('sys.modules', settings=MockSettings):
    from src.main.api.sso_provider import SSOProvider


class TestSSOLogin(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, True)  # add assertion here
        self.assertEqual(SSOProvider.get_user_by_token("", "kakao"), "")


if __name__ == '__main__':
    unittest.main()
