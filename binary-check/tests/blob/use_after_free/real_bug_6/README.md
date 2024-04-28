* `Autel/900M/X3P_GROUND_v1.01.32_20160226.img.extracted/jffs2-root-0/aoa_server`
* 函数地址`0xafe4`

```c
int libaoa_quit() //0x0AFE4
{
  _DWORD *ptr; // [sp+4h] [bp-8h]

  abort_request = 1;
  pthread_join(hotplug_tid, 0);
  for ( ptr = (_DWORD *)first_device; ptr; ptr = (_DWORD *)ptr[5] )
  {
    ptr[1] = 1;
    pthread_join(ptr[2], 0);
    if ( ptr[3] )
      dword_202F4(ptr[3]);
    free(ptr);
  }
  abort_request = 0;
  return 0;
}
```
