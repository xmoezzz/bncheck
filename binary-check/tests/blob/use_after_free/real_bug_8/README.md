* `r2/Routers/done/asus/d2093584d66ab93dda0c6dbac931267d1d576cf1/squashfs-root/usr/sbin/igmp`
* 函数地址`0x4056f8`

```c
bool __fastcall igmp_group_handle_isex(int a1, int a2, _DWORD *a3, int a4, _DWORD *a5) //004056F8 
{
	...
	igmp_src_cleanup(v6, v20); //v20 freed 
	k_proxy_del_mfc(*(_DWORD *)(v7 + 28), *v20, *v6);
	...
}
```

