* `zhao/new/Cameras/hikvision/DS-7804.extracted/cramfs-root/sys_app/exec/mkntfs`
* 在`sub_13E90`
	* 有两处一处是:

		.text:00015228                 MOV             R6, #0
		.text:0001522C                 BL              free
		.text:00015230                 LDRSB           R2, [R5,#0x44]
		.text:00015234                 MOV             R3, #0x41BC
		.text:00015238                 STR             R6, [SP,#0xC8+var_C8]
		.text:0001523C                 MOVT            R3, #5
		.text:00015240                 STR             R2, [SP,#0xC8+var_C0]
		.text:00015244                 MOV             R1, #0x36FC
		.text:00015248                 STR             R3, [SP,#0xC8+var_C8+4]
		.text:0001524C                 MOVT            R1, #5
		.text:00015250                 LDR             R0, =aMkntfsCreateRo ; "mkntfs_create_root_structures"
		.text:00015254                 MOV             R3, #0x80
		.text:00015258                 MOV             R2, #0x1232
		.text:0001525C                 BL              sub_3A774
		.text:00015260                 B               loc_16A50

	* 另一处是:

		.text:000151A4                 MOV             R0, R5  ; ptr
		.text:000151A8                 MOV             R6, R8
		.text:000151AC                 BL              free
		.text:000151B0                 LDRSB           R2, [R5,#0x40]
		.text:000151B4                 MOV             R3, #0x4180
		.text:000151B8                 STR             R8, [SP,#0xC8+var_C8]
		.text:000151BC                 MOVT            R3, #5
		.text:000151C0                 STR             R2, [SP,#0xC8+var_C0]
		.text:000151C4                 MOV             R1, #0x36FC
		.text:000151C8                 STR             R3, [SP,#0xC8+var_C8+4]
		.text:000151CC                 MOVT            R1, #5
		.text:000151D0                 LDR             R0, =aMkntfsCreateRo ; "mkntfs_create_root_structures"
		.text:000151D4                 MOV             R3, #0x80
		.text:000151D8                 MOV             R2, #0x1220
		.text:000151DC                 BL              sub_3A774
		.text:000151E0                 B               loc_16A50

