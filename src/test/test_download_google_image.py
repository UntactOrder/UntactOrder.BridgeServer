# -*- coding: utf-8 -*-
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
### Alias : CertServer.test_download_google_image & Last Modded : 2022.03.09. ###
Coded with Python 3.10 Grammar by IRACK000
Description : cert validation check
Reference : [gdrive] https://stackoverflow.com/questions/38511444/python-download-files-from-google-drive-using-url
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import os
import requests


def download_file_from_google_drive(id, destination):
    URL = "https://docs.google.com/uc?export=download"

    session = requests.Session()

    response = session.get(URL, params={'id': id}, stream=True)
    token = get_confirm_token(response)

    if token:
        params = {'id': id, 'confirm': token}
        response = session.get(URL, params=params, stream=True)

    save_response_content(response, destination)    


def get_confirm_token(response):
    for key, value in response.cookies.items():
        if key.startswith('download_warning'):
            return value

    return None


def save_response_content(response, destination):
    CHUNK_SIZE = 32768

    ext = ""
    with open(destination, "wb+") as f:
        for chunk in response.iter_content(CHUNK_SIZE):
            if chunk: # filter out keep-alive new chunks
                if not ext:
                    if b"PNG" in chunk:
                        ext = ".png"
                    elif b"JFIF" in chunk:
                        ext = ".jpg"
                    else:
                        ext = ".img"
                f.write(chunk)
    os.rename(destination, destination+ext)


if __name__ == '__main__':
    try:
        shareable_link = "https://drive.google.com/file/d/1NQBy0ZOeU-C5uAay8H7n9j1225DxxKve/view"
        splited = (shareable_link+'/').split('/')
        file_id = splited[splited.index("d")+1]
        destination = 'image'
        download_file_from_google_drive(file_id, destination)
    except Exception as e:
        print(e)
    input()
