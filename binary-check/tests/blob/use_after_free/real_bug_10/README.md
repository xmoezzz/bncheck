* `https://github.com/ghostecoli/lrzsz/blob/675e6964ef0a417dcfecac5beb969b355ad5704b/src/lsz.c#L841`
* `new/Cameras/ezviz/CS-C6P-7A3WFR.dav.extracted/ubifs-root/usr/bin/sz`

```c
int __fastcall sub_E844(const char *a1, const char *a2) {
      if ( ++v8 == 11 )
      {
        free(v6);
        v10 = (FILE *)stderr;
        v14 = (const char *)gettext("send_pseudo %s: cannot open tmpfile %s: %s", v11, v12, v13);
        v15 = _errno_location();
        v16 = strerror(*v15);
        fprintf(v10, v14, v2, v6, v16);
        fputs("\r\n", (FILE *)stderr);
        return 1;
      }
}
```
