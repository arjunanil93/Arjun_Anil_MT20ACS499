import requests
import os
import time
import csv

def fileexists(filepath):
    try:
        if os.path.isfile(filepath):
            return filepath
        else:
            print("There is no file at:" + filepath)
            exit()
    except Exception as e:
        print(e)

def VT_Request(key, hash):
    params = {'apikey': key, 'resource': hash}
    url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response = url.json()
    #print(json_response)
    response = int(json_response.get('response_code'))
    #print(response)
    if response == 0:
        print(hash + ' is not in Virus Total')
        file = open("output.txt", 'a')
        file.write(hash + ' is not in Virus Total')
        file.write('\n')
        file.close()
    elif response == 1:
        positives = int(json_response.get('positives'))
        scan_date= json_response.get('scan_date')
        sha256=json_response.get('sha256')
        if positives == 0:
            print(hash + ' is not malicious')
        else:
            print(hash + " file is malicious, added to output csv file...")
            with open('malware.csv', 'a', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['File', 'Positives', 'Scan_Date', 'SHA256']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow({'File': hash, 'Positives': str(positives), 'Scan_Date': str(scan_date), 'SHA256': str(sha256)})
    else:
        print(hash + ' could not be searched. Please try again later.')

def Read_Hash():
    file_name=input("Enter the file with hash list: ")
    hash_file=open(file_name,'r')
    fileexists(file_name)
    hash_list=hash_file.readlines()
    key='b6b2ad110a16db444901ca9405d7eab313db793eafa90c0f149b3371d7593f1b'
    with open(file_name, 'a', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['File', 'Positives', 'Scan_Date', 'SHA256']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    for hash in hash_list:
        VT_Request(key, hash)
        time.sleep(15)

Read_Hash()
