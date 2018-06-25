# glibc源码学习 #
# malloc.c #
# \_int\_free()函数 #
\_int\_free()函数的参数如下所示：

	_int_free (mstate av, mchunkptr p, int have_lock)
其中av表示当前释放chunk所在的arena，p为当前要释放的chunk，have\_lock为一个锁变量。
## free check ##
在对chunk进行真正的free操作前，首先会进行一系列检查操作。
### free\_check1 ###
![free_check1](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/free_check1.PNG)  
首先检查当前chunk p的地址是否在一个合法字段（由于比较是一个无符号数比较，因此-size会是一个非常大的值），然后看当前chunk p的地址是否对齐（64bit下为16字节对齐，32bit下为8字节对齐）。
### free\_check2 ###
