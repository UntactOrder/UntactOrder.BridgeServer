# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.sso_provider & Last Modded : 2022.07.06. ###
Coded with Python 3.10 Grammar by Yaminyam
Description : Social Login Service(OAuth2.0) Admin for BridgeServer.
Reference : ??
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
from __future__ import annotations

from settings import api_config


class SSOProvider(object):
    """ Social Login Service(OAuth2.0) Admin """
    provider = None
    config_prefix = "SSO_"

    provider_list = []

    @classmethod
    def add_to_provider_list(cls, provider: str):
        """ Add provider to provider_list """
        cls.provider_list.append(cls.config_prefix + provider.upper())

    @classmethod
    @property
    def is_offered(cls):
        return api_config.getboolean(cls.config_prefix + cls.provider.upper(), 'is_offered')

    @staticmethod
    def check_status(func):
        def inner(*args, **kwargs):
            if not func.__self__.is_offered:
                raise NotImplementedError("This provider is not offered.")
            return func(*args, **kwargs)
        return inner

    @classmethod
    @property
    def __client_id__(cls):
        return api_config[cls.config_prefix + cls.provider.upper()]['client_id']

    @classmethod
    @property
    def __client_secret__(cls):
        return api_config[cls.config_prefix + cls.provider.upper()]['client_secret']

    @staticmethod
    def get_user_by_token(token: str, provider: str) -> dict:
        """ Get User Info by Token
        :param token: Token
        :param provider: Provider - "kakao" => KakaoSSOAdmin, "naver" => NaverSSOAdmin
        """
        match provider:
            case KakaoSSOAdmin.provider:
                return KakaoSSOAdmin.get_user_by_token(token)
            case NaverSSOAdmin.provider:
                return NaverSSOAdmin.get_user_by_token(token)
            case _:
                raise KeyError("Unknown Provider")


class KakaoSSOAdmin(SSOProvider):
    """ Kakao SSO Admin """
    provider = "kakao"
    SSOProvider.add_to_provider_list(provider)

    @classmethod
    @SSOProvider.check_status
    def get_user_by_token(cls, token: str) -> dict:
        """ Get User Info by Token
        :param token: Kakao Access Token
        :return: User Info {
            'unique_id': "0000000000",
            'nickname': "user nickname",
            'profile_image': "user profile image url",
            'email': "user email",
            'gender': "user gender",
            'age': "user age range"
        }
        :reference: https://developers.kakao.com/docs/latest/ko/kakaologin/common
        """
        #pass
        print(cls.__client_id__, cls.__client_secret__)  # test


class NaverSSOAdmin(SSOProvider):
    """ Naver SSO Admin """
    provider = "naver"
    SSOProvider.add_to_provider_list(provider)

    @classmethod
    @SSOProvider.check_status
    def get_user_by_token(cls, token: str) -> dict:
        """ Get User Info by Token
        :param token: Naver Access Token
        :return: User Info {
            'unique_id': "00000000",
            'nickname': "user nickname",
            'profile_image': "user profile image url",
            'email': "user email",
            'gender': "user gender",
            'age': "user age range",
            'name': "user legal name",
            'birthday': "user birthday",
            'birthyear': "user birthday year",
            'mobile': "user phone number"
        }
        :reference: https://developers.naver.com/docs/login/profile/profile.md
        """
        pass
