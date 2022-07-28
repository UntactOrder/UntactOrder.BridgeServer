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

_CONF_PREFIX = "BIZ_"

iso4272_list = [_CONF_PREFIX + "KRW"]  # Supported Currency code list


def __check_status(iso4217):
    is_offered = api_config.getboolean(_CONF_PREFIX + iso4217.upper(), 'is_offered')
    __client_id__ = api_config[_CONF_PREFIX + iso4217.upper()]['client_id']
    __client_secret__ = api_config[_CONF_PREFIX + iso4217.upper()]['client_secret']

    if iso4217 not in iso4272_list:
        NotImplementedError(f"API is not initialized for Currency Code {iso4217}.")

    def inner(func):
        if not is_offered:
            raise NotImplementedError(f"The Currency Code {iso4217} is not offered.")

        def deeper(*args, **kwargs):
            return func(__client_id__, __client_secret__, *args, **kwargs)
        return deeper
    return inner


def get_business_info(business_registration_number: str, iso4217: str) -> dict:
    """ Get information about the store.
    :param business_registration_number:
    :param iso4217: Currency code.
    :NotImplementedError: Currency code is not supported yet.
    """
    match iso4217:
        # When you add a new currency code, you should also add it to the iso4272_list.
        case "KRW":
            return get_business_info_krw(business_registration_number)
        case _:
            NotImplementedError(f"This Currency code {iso4217} is not supported yet.")


@__check_status("KRW")
def get_business_info_krw(client_id, client_secret, business_registration_number: str) -> dict:
    """ Get information about the store.
        The OpenAPI's key must be renewed every two years.
    :param client_id: automatically referenced by __check_status decorator
    :param client_secret: automatically referenced by __check_status decorator
    :param business_registration_number:  store's business registration number
    """
    url = "https://api.odcloud.kr/api/nts-businessman/v1/status?serviceKey=" + client_id

    header = {'Content-Type': "application/json; charset=utf-8"}
    data = {'title': 'dummy title', 'id': 1, 'message': 'hello world!'}
    res = requests.post(url, data=json.dumps(data), headers=header)
    if res.status_code == 200:
        return res.json()
    else:
        return {}
