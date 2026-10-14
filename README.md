
重要：由于系统版本的差别部分系统偏移需要自己手动替换！如果可以也可以自己写一个符号解析工具供驱动使用！

基于ARK方式的内核回调摘除

ACE-BOOT.sys会在系统注册：

0xFFFFF8012F422940	ProcessObCallback PRE	C:\Program Files\AntiCheatExpert\ACE-BOOT.sys	ANTICHEATEXPERT.COM	1.0.2606.17242	0xFFFFC802E66D0EB0	ACE-BOOT64 NT Driver

0xFFFFF8012F40C4A0	CreateProcessEx	C:\Program Files\AntiCheatExpert\ACE-BOOT.sys	ANTICHEATEXPERT.COM	1.0.2606.17242	0xFFFFF8018A7047B0	ACE-BOOT64 NT Driver

0xFFFFF8012F40AC80	LoadImage	C:\Program Files\AntiCheatExpert\ACE-BOOT.sys	ANTICHEATEXPERT.COM	1.0.2606.17242	0xFFFFF8018A704980	ACE-BOOT64 NT Driver

0xFFFFF8012F419CA0	CmpCallback	C:\Program Files\AntiCheatExpert\ACE-BOOT.sys	ANTICHEATEXPERT.COM	1.0.2606.17242	0xFFFFC802EE99D980	ACE-BOOT64 NT Driver

0xFFFFF8012F40A2F0	Shutdown	C:\Program Files\AntiCheatExpert\ACE-BOOT.sys	ANTICHEATEXPERT.COM	1.0.2606.17242	0xFFFF808E95FE3B80	ACE-BOOT64 NT Driver

前面的回调入口每次会变动所以不能用作固定的数值

本版本放弃了直接改ACE代码段，ACE回调在.text页，而页权限为只读

需要清除CR0.WP才能写

我测试了下我系统的CR4.CET=1

CET把CR0.WP锁位了fixed=1

mov cr0清wp一定会触发0xC0000096

所以本版本走的是改回调函数指针

回调结构处于EX_CALLBACK_ROUTINE_BLOCK 分配在内核pool此页可写，修改它并不动任何只读页

经测试只禁用或卸载LoadImage即可让黑签正常加载

本项目同时处理了LoadImage CreateProcessEx CreateThread

此外这次本次测试的部分结果

ACE 回调RVA
ProcessObCallback(PRE)   0x22940
CreateProcessEx          0x0C4A0
LoadImage                0x0AC80
CmpCallback              0x19C40
Shutdown                 0x0A2F0
