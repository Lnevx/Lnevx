from json import dump
from os import getenv
from urllib.parse import urlparse

from requests import Session

ACCESS_TOKEN = getenv('YANDEX_METRIKA_TOKEN')
HOST = 'https://api-metrika.yandex.net/stat/v1/data'
LANGS = ['ru', 'en']

s = Session()
s.headers.update({
    'Authorization': f'OAuth {ACCESS_TOKEN}'
})

res = s.get(HOST, params={
    'ids': 97809000,
    'metrics': 'ym:pv:pageviews',
    'dimensions': 'ym:pv:URLHash',
    'date1': '2024-08-13',
    'accuracy': 'full',
    'limit': 100000,
    'proposed_accuracy': False,
    'access_token': ACCESS_TOKEN
}).json()

data = {}

# Combine all langs in one stat
for entry in res['data']:
    path = urlparse(entry['dimensions'][0]['name']).path[3:]
    data[path] = int(data.get(path, 0) + entry['metrics'][0])

# Copy this stat to each lang
for lang in LANGS:
    for path, value in dict(data).items():
        data['/' + lang + path] = value

with open('data/views.json', 'w', encoding='utf-8') as file:
    dump(data, file)
