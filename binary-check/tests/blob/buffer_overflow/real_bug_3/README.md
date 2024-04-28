* `r2/Routers/done/netgear/0802598e8a452337ac2f3d884b23e36a1f41ac35/ReadyNASOS-6.7.1-arm.img.extracted/root-fs/usr/lib/librddclient.so.0`
```C
int __fastcall process_auth_request_broker(char *a1, char *a2, const char *a3, const char *a4, void **a5)
{
  ...
    v20 = malloc(4u); // HERE is the BUG....
    if ( !v20 )
      exit(1);
    v6 = strdup("REQUEST_METHOD=POST");
    *v20 = v6;
    if ( !*v20 )
      exit(1);
    v7 = (void **)(v20 + 1);
    v8 = snprintf(0, 0, "REMOTE_USER=%s", v14);
    *v7 = malloc(v8 + 1);
    if ( !v20[1] )
      exit(1);
    sprintf((char *)v20[1], "REMOTE_USER=%s", v14);
    v9 = (void **)(v20 + 2);
    v10 = snprintf(0, 0, "CONTENT_LENGTH=%d", n);
    *v9 = malloc(v10 + 1);
    if ( !v20[2] )
      exit(1);
    sprintf((char *)v20[2], "CONTENT_LENGTH=%d", n);
    v20[3] = 0;
    execle(path, arg, 0, v20);
    v11 = _errno_location();
    exit(*v11);
  ...
}
```
