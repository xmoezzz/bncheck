* `r2/Routers/done/netgear/0802598e8a452337ac2f3d884b23e36a1f41ac35/ReadyNASOS-6.7.1-arm.img.extracted/root-fs/sbin/insserv`
```
.text:00009548                 PUSH    {R4-R11,LR}
.text:0000954C                 ADD     R11, SP, #0x20
.text:00009550                 SUB     SP, SP, #0x2180
.text:00009554                 SUB     SP, SP, #0xC
.text:00009558                 MOV     R4, R0
...
.text:00009FCC                 MOV     R0, R5
.text:00009FD0                 MOV     R1, R5
.text:00009FD4                 MOV     R2, R10
.text:00009FD8                 BL      sub_E0C0
.text:00009FDC                 LDRH    R3, [R5,#0x10]
.text:00009FE0                 CMP     R6, R4
.text:00009FE4                 BIC     R3, R3, #1
.text:00009FE8                 STRH    R3, [R5,#0x10]
.text:00009FEC                 LDR     R3, [R4]
.text:00009FF0                 BNE     loc_9F9C
```

* 另一处：
```
.text:0000E1D0                 MOV     R0, R5
.text:0000E1D4                 STRH    R3, [R5,#0x10]
.text:0000E1D8                 MOV     R2, R6
.text:0000E1DC                 MOV     R1, R8
...
.text:0000E1D0                 MOV     R0, R5
.text:0000E1D4                 STRH    R3, [R5,#0x10]
.text:0000E1D8                 MOV     R2, R6
.text:0000E1DC                 MOV     R1, R8
.text:0000E1E0                 BL      sub_E0C0			// R0 is freed
.text:0000E1E4                 LDRH    R2, [R5,#0x10]
.text:0000E1E8                 LDR     R3, [R6]
.text:0000E1EC                 BIC     R2, R2, #1
.text:0000E1F0                 SUB     R3, R3, #1
.text:0000E1F4                 CMP     R7, R4
.text:0000E1F8                 STRH    R2, [R5,#0x10]
.text:0000E1FC                 STR     R3, [R6]
.text:0000E200                 LDR     R2, [R4]
.text:0000E204                 BNE     loc_E194
```
