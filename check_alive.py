# -*- coding: utf-8 -*-
import requests 
 
url = "http://testphp.vulnweb.com" 
try: 
    response = requests.get(url, timeout=5) 
    print(f"[+] ״̬��: {response.status_code}") 
except Exception as e: 
    print(f"[-] ʧ��: {e}") 
