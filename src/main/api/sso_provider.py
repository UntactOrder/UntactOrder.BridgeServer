# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.sso_provider & Last Modded : 2022.02.27. ###
Coded with Python 3.10 Grammar by IRACK000
Description : Social Login Service(OAuth2.0) Admin for BridgeServer.
Reference : ??
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""


class SSOProvider(object):
    """ Social Login Service(OAuth2.0) Admin """

    @staticmethod
    def get_user_by_token(token: str, provider: str) -> dict:
        """ Get User Info by Token
        :param token: Token
        :param provider: Provider - "kakao" => KakaoSSOAdmin, "naver" => NaverSSOAdmin
        """
        match provider:
            case "kakao":
                return KakaoSSOAdmin.get_user_by_token(token)
            case "naver":
                return NaverSSOAdmin.get_user_by_token(token)
            case _:
                raise KeyError("Unknown Provider")


class KakaoSSOAdmin(SSOProvider):
    """ Kakao SSO Admin """

    @classmethod
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
        pass


class NaverSSOAdmin(SSOProvider):
    """ Naver SSO Admin """

    @classmethod
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
