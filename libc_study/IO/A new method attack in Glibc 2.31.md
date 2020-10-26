# A new method to use _IO_FILE in Glibc 2.31 

这里我们介绍一种使用 `_IO_FILE` 在 libc 2.31 的环境下实现 `orw` 的方法

其实该方法下 glibc 2.29 下就已经出现，只不过 glibc2.29 下还有一种方法可以绕过沙箱（禁用 execve）所以就没太关注。知道 glibc 2.31 时突然发现 2.29 的方法不可用了（提出了 