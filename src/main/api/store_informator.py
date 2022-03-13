# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : BridgeServer.api.store_informator & Last Modded : 2022.03.03. ###
Coded with Python 3.10 Grammar by IRACK000
Description : A Open API which can get information about the store.
Reference : [korea api] https://www.data.go.kr/data/15081808/openapi.do
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""


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
    :param business_registration_number:
    """
    pass
