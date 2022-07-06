# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.store_informator & Last Modded : 2022.03.03. ###
Coded with Python 3.10 Grammar by IRACK000
Description : A Open API which can get information about the store.
Reference : [korea api] https://www.data.go.kr/data/15081808/openapi.do
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import requests
import json

from settings import api_config


def get_business_info(business_registration_number: str, iso4217: str) -> dict:
    """ Get information about the store.
    :param business_registration_number:
    :param iso4217: Currency code.
    :NotImplementedError: Currency code is not supported yet.
    """
    match iso4217:
        case "KRW":
            return get_business_info_krw(business_registration_number)
        case _:
            NotImplementedError(f"This Currency code {iso4217} is not supported yet.")


def get_business_info_krw(business_registration_number: str) -> dict:
    """ Get information about the store.
        The OpenAPI's key must be renewed every two years.
    :param business_registration_number:  store's business registration number
    """
    encoding = api_config['KOR_BIZ']['encoding']
    url = "https://api.odcloud.kr/api/nts-businessman/v1/status?serviceKey=" + encoding

    header = {'Content-Type': "application/json; charset=utf-8"}
    data = {'title': 'dummy title', 'id': 1, 'message': 'hello world!'}
    res = requests.post(url, data=json.dumps(data), headers=header)
    if res.status_code == 200:
        return res.json()
    else:
        return {}
