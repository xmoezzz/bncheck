* `zhao/r1/done/2ecf5e3366e4b4a640752091a2304cbffa6467f3/WN3000RPv2-V1.0.0.56.img.extracted/squashfs-root-1/bin/busybox`
```
int __fastcall push_error_list(int **a1, int a2) //0x004151C4
{
  int **v2; // s1
  int v3; // v0
  int v4; // s0
  int v5; // a0
  int result; // v0
  int *v7; // s0
  int v8; // v1

  v2 = a1;
  v4 = a2;
  v3 = off_4AD73C(4);                           // malloc(sizeof(struct XX *))
  v5 = v4;
  v7 = (int *)v3;
  result = off_4AD254(v5);
  v8 = (int)*v2;
  *v2 = v7;
  *v7 = result;
  v7[1] = v8;                                   // overflow
  return result;
}
```
