# Logical Vulnerability in AC Series Routers  

This vulnerability has been confirmed through real-world testing on AC8v4 V16.03.34.06.  
Firmware download link: https://tenda.com.cn/material/show/3518  


## Example of Vulnerability Impact  
In scenarios where multiple users simultaneously log in to an AC series router with this vulnerability, a malicious user can exploit it to:  
1. Change the router from a password-protected mode to an open (password-free) connection state.  
2. Disconnect all devices connected to the router.  


## Vulnerability Analysis  
In the `/goform/WifiBasicSet` endpoint, the `formWifiBasicSet` function calls `sub_45F3E8`, which proceeds through the following functions:  
`sub_45F3E8 -> sub_45E1C4 -> sub_45DC58`  

When accessing `/goform/WifiBasicSet` without setting any parameters, the `security` parameter defaults to "none". This triggers the `else` statement at line 28, setting `bss_security` to "none". As a result:  
- The router becomes accessible without a password.  
- All connected devices are disconnected and need to reconnect.  


```c
int _fastcall sub_45DC58(int a1, int a2, const char *a3) {
    size_t v3; // $v0
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
    if (!strcmp(src, "wpapsk") || !strcmp(src, "wpa2psk") || !strcmp(src, "wpawpa2psk"))
        SetValue(v9, "wpapsk");
    else
        SetValue(v9, src);  // When src is "none", sets bss_security to "none"
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


## Vulnerability Reproduction  
To reproduce the vulnerability:  
1. Connect to any AC series router with this vulnerability.  
2. Access the Tenda router management interface.  
3. Visit the following POC link in a browser:  
   `http://tendawifi.com/goform/WifiBasicSet`
