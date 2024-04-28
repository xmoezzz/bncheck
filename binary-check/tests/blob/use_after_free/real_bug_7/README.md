* `Routers/done/phicomm/1c9952f42b94db4d84ed91ff4263692156b3cf6b.bin.extracted/squashfs-root-0/usr/bin/wifidog`
```c
int __fastcall sub_415E78(int a1)
{
  int v1; // s1
  int v2; // s2
  _DWORD *v3; // s0
  _DWORD *v4; // s3

  v1 = a1;
  v2 = a1 + 36;
  v3 = *(_DWORD **)(a1 + 36);
  pthread_mutex_lock();
  while ( v3 != (_DWORD *)v2 )
  {
    v4 = (_DWORD *)*v3;
    free(v3);
    *(_DWORD *)(*v3 + 4) = v3[1];
    *(_DWORD *)v3[1] = *v3;
    *v3 = 0;
    v3[1] = 0;
    v3 = v4;
  }
  pthread_mutex_unlock(v1);
  pthread_mutex_destroy(v1);
  return free(v1);
```
