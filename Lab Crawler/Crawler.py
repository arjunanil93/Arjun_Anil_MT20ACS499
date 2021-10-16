import requests
import re

url = "https://bazaar.abuse.ch/browse/"
page = requests.get(url)
#print(page.text)
hash_sha = re.findall("[A-Fa-f0-9]{64}", page.text)
#print(hash_sha)
sha_list = open("Sha_list.txt","w")
sha_list.write(str(hash_sha))
sha_list.close()