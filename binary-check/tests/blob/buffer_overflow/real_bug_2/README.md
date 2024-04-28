* `r2/Routers/done/netgear/6b7d91379f5f63b757a98c3ccbc17db507213c0c/ReadyNASOS-V6.0.1/ReadyNASOS-6.0.1-x86_64.img.extracted/root-fs/lib/x86_64-linux-gnu/libgssglue.so.1.0.0`
* `http://www.citi.umich.edu/projects/nfsv4/linux/libgssglue/libgssglue-0.4.tar.gz`
```c
OM_uint32 __gss_copy_namebuf(src, dest)
    gss_buffer_t   src;
    gss_buffer_t   *dest;
{
    gss_buffer_t   temp = NULL;

    if (dest == NULL)
        return (GSS_S_BAD_NAME);

    temp = (gss_buffer_t) malloc (sizeof(gss_buffer_t)); //Here is the bug...
    if (!temp) {
    return(GSS_S_FAILURE);
    }
    temp->value = (void *) malloc (src->length + 1);
    if (temp->value == NULL) {
        free(temp);
    return(GSS_S_FAILURE);
    }

    memcpy(temp->value, src->value, src->length);
    temp->length = src->length;

    *dest = temp;
    return (GSS_S_COMPLETE);
}
```

