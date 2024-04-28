* 似乎使用来测试mitigation程序?
* `new/Parrot/Bebop2/bebop2_update_4.7.1.plf.extracted/fs-root/usr/bin/crashdump_test`
```c
int __fastcall sub_11560(int a1)
{
  void *v1; // r0
  void *v2; // r5
  int v4; // [sp+0h] [bp-90h]

  snprintf((char *)&v4, 0x80u, "crash_thread_%d", a1);
  prctl(15, &v4, 0);
  v1 = malloc(0x400u);
  v2 = v1;
  double_free_ptr = (int)v1;
  memset(v1, 240, 0x400u);
  free(v2);
  free(v2);
  return 0;
}
```
