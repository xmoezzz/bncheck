* `dji/300E/GL300E_v1410_20180412.bin.extracted/system-root/lib/libril-rk29-dataonly.so`

```c
const char *__fastcall sub_B7E4(int a1, int a2, int a3)
{
  void *v3; // r4
  const char *result; // r0
  int v5; // [sp+4h] [bp-14h]
  int v6; // [sp+8h] [bp-10h]

  v5 = a2;
  v6 = a3;
  v3 = (void *)j_modem_cmp(1478, 36901, 0);
  if ( v3 )
  {
    result = sub_B6E0((int)"AT+CGMM", "GMM:", 6);
    if ( !result )
      result = sub_B6E0((int)"AT+GMM", "GMM:", 5);
  }
  else
  {
    v5 = 0;
    if ( j_at_send_command_singleline("AT+CGMM", &unk_14AEA, &v5) >= 0 )
    {
      v3 = *(void **)v5;
      if ( *(_DWORD *)v5 )
        v3 = *(void **)(*(_DWORD *)(v5 + 8) + 4);
    }
    free(v3); //FREE
    result = (const char *)v3;
  }
  return result; //USE...
}
```
