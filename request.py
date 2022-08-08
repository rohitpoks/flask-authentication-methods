import requests

BASE = "http://127.0.0.1:5000/"
#
response = requests.post(BASE + '/customers/login', {"username": "Rohit", "password": "hello"})
print(response.json())
response = requests.get(BASE + '/customers/0')
print(response.json())