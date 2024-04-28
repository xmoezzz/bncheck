* `new/Parrot/Bebop2/bebop2_update_4.7.1.plf.extracted/fs-root/usr/bin/media-ctl`
* TODO: 查找代码来源
```c
char *__fastcall sub_133BC(const char *a1, int a2, int a3)
{
  if ( v8 < 0 )
  {
    sub_13340((int *)v7); //sub_13340内函数一定被free
    (*((void (**)(_DWORD, const char *, ...))v7 + 67))(
      *((_DWORD *)v7 + 68),
      "%s: Can't open media device %s\n",
      "media_open_debug",
      v64);
    return 0;
  }
}
```
