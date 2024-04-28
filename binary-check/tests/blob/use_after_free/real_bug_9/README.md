* `r2/Routers/done/openwrt/04bb8037d53eb447380f9dc901acd21b9c71e2f1.bin.extracted/squashfs-root-0/usr/sbin/dnsmasq` 
* 鬼知道是为什么，但是好像确实有问题，找不到代码从哪来的- - 
```c
int __fastcall sub_405758(int a1, int a2, int a3, int a4) {
          free(v25);
          fdata = v27;
          dword_43AEB8 = v24;
          v20 = v24 + v20 - v25;
          v6 = (_BYTE *)(v20 - 1);
          v22 = snprintf(v20, v20 - v24 + v27, "%s#%d %u %u", *(const char **)(dword_43AE48 + 1156), v28, v18, v17);
}
```
