# Linux IO机制 学习记录 #
详细讲述glibc中关于IO机制的实现过程
## 1. 标准IO缓存，不带缓存IO ##
在谈什么是标准IO（带缓存）和什么是不带缓存IO前，首先需要明确系统调用这个概念和一些相关知识。  
系统调用：操作系统提供给用户程序调用的一组接口--获取内核提供的服务。  

在实际中程序员使用的通常不是系统调用，而是用户编程接口API，也称为系统调用编程接口。它是遵循Posix标准（Portable operation system interface），API函数可能要一个或者几个系统调用才能完成函数功能，此函数通过c库（libc）实现，如read，open。  

与IO相关的两条汇编指令：  
**fsync：把内核缓冲刷到磁盘上**  
**fflush：把C库中的缓冲（其实就是标准IO的缓冲），调用write函数写到磁盘上（这里有一个误区，其实真正写到的是内核缓冲区）。**  

linux系统中对于IO文件操作的分类：不带缓冲的IO，标准IO（带缓存）  
### 1.1 不带缓存的IO ###
open，read函数。posix标准（read，open函数均属于此标准），在用户空间没有缓冲，在内核空间还是进行了缓存的。  

**数据流：数据---->内核缓存区---->磁盘**  

举例如下：  
假设内核缓存区长度为100字节，当调用write进行写操作时，每次写入10字节，那么要调用10次write函数才能把内核缓存区写满，没写满时数据还是在内核缓冲区中，并没有写入到磁盘中。只有当内核缓存区满了之后或者执行了fsync（强制写入硬盘）之后，才进行实际的IO操作，把数据写入磁盘上。
### 1.2 标准IO（带缓存） ###
带缓存区：fopen，fwrite，fget等，是c标准库中定义的。
  
**数据流：数据---->流缓存区---->内核缓存区---->磁盘**  

举例如下：  
假设流缓存区长度为50字节，内核缓存区100字节，我们用标准c库函数fwrite()将数据写入到这个流缓存中，每次写10字节，需要写5次将流缓存区写满后，再调用write()(或调用fflush())，将数据写到内核缓存区，直到内核缓存区满了之后或者执行了fsync（强制写入硬盘）之后，才进行实际的IO操作，把数据写入磁盘上。标准IO操作fwrite()最后还是要掉用无缓存IO操作write。  
### 1.3 标准IO（带缓存）的意义 ###
其主要目的还是为了减少系统调用的次数，提升程序性能。以fgetc/fputc函数为例，当程序第一次调用fgetc函数从输入流（可以是终端也可以是某个文件流）读入一个字节时，用户可能在终端（或文件流）中实际输入的字符远超过一个字符。此时如果按照实际用多少就读多少，那么会反复进行系统调用，程序性能将大大损失。  

一个可以考虑的方法就是：使用带有缓存的IO流  
假设内核缓冲区有1K字节，流缓冲区有512字节。  

1. 当调用fgetc函数时，先进行系统调用从终端（或磁盘）中读入1K字节（少于无所谓）充满内核缓冲区。  
2. 然后再将读取512字节的数据到流缓存中。  
3. 最后返回一个字节给fgetc函数，并将标志当前读到位置的指针指向流缓存区中下一个要读的字符。  
4. 直到流缓存区中的数据全部读完。  
5. 再读时再从内核缓冲区中取出512字节，重复上述过程（2-4）直至内核缓冲区也被读完，此时会再次进行系统调用，读取1K字节的数据到内核缓冲区中。

有时候用户程序希望把I/O缓冲区中的数据立刻传给内核,让内核写回设备或磁盘,这称为Flush操作,对应的库函数是fflush,fclose函数在关闭文件之前也会做Flush操作。

## 2. \_IO\_FILE，\_IO\_FILE_plus结构 ##
谈到标准IO就不得不提glibc中关于\_IO\_FILE和\_IO\_FILE\_plus两个结构体的定义。
<pre class = "prettyprint lang-javascript">
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
</pre>
可以看到\_IO\_FILE\_plus结构体就是\_IO\_FILE结构体再加上一个\_IO\_jump\_t类型的结构体指针。  
## 2.1 \_IO\_FILE结构体解析 ##
其中\_IO\_FILE结构体定义如下：
<pre class = "prettyprint lang-javascript">
struct _IO_FILE {
	  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
	#define _IO_file_flags _flags
	
	  /* The following pointers correspond to the C++ streambuf protocol. */
	  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
	  char* _IO_read_ptr;	/* Current read pointer */
	  char* _IO_read_end;	/* End of get area. */
	  char* _IO_read_base;	/* Start of putback+get area. */
	  char* _IO_write_base;	/* Start of put area. */
	  char* _IO_write_ptr;	/* Current put pointer. */
	  char* _IO_write_end;	/* End of put area. */
	  char* _IO_buf_base;	/* Start of reserve area. */
	  char* _IO_buf_end;	/* End of reserve area. */

	  /* The following fields are used to support backing up and undo. */
	  char *_IO_save_base; /* Pointer to start of non-current get area. */
	  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
	  char *_IO_save_end; /* Pointer to end of non-current get area. */
	
	  struct _IO_marker *_markers;
	
	  struct _IO_FILE *_chain;		//保存文件指针的链表结构，链表头保存在\_IO\_list\_all全局变量中
	
	  int _fileno;		//文件描述符，是sys_open返回值（stdin为0，stdout为1，stderr为2）
	#if 0
	  int _blksize;
	#else
	  int _flags2;
	#endif
	  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */
	
	#define __HAVE_COLUMN /* temporary */
	  /* 1+column number of pbase(); 0 is unknown. */
	  unsigned short _cur_column;
	  signed char _vtable_offset;
	  char _shortbuf[1];
	
	  /*  char* _save_gptr;  char* _save_egptr; */
	
	  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
struct _IO_FILE_complete
{
	struct _IO_FILE _file;
#endif
	#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  		_IO_off64_t _offset;
		# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  			/* Wide character stream stuff.  */
  			struct _IO_codecvt *_codecvt;
  			struct _IO_wide_data *_wide_data;
  			struct _IO_FILE *_freeres_list;
  			void *_freeres_buf;
		# else
  			void *__pad1;
  			void *__pad2;
  			void *__pad3;
  			void *__pad4;
		# endif
  		size_t __pad5;
  		int _mode;
  		/* Make sure we don't get into trouble again.  */
  		char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
	#endif
};
</pre>
其中有如下几个关键字段与文本所要讲述的内容密切相关。
<pre class = "prettyprint lang-javascript">
1. read buf
char* _IO_read_ptr;		//指向"读缓冲区"中下一个要读入的数据的位置
char* _IO_read_end;		//指向"读缓冲区"末尾
char* _IO_read_base;		//指向"读缓冲区"
_IO_read_end - _IO_read_base	//读缓冲区的长度
2. write buf
char* _IO_write_base;		//指向"写缓冲区"
char* _IO_write_ptr;		//指向"写缓冲区"中下一个要写入的数据的位置
char* _IO_write_end;		//指向"写缓冲区"末尾
3. buf 
char* _IO_buf_base;		//指向"缓冲区"
char* _IO_buf_end;		//指向"缓冲区"末尾
4. backup buf
char * _IO_save_base;		//指向非当前获取区域的开始
char * _IO_backup_base;		//指向备份区域的第一个有效字符
char * _IO_save_end;		//指向非当前获取区域结束的指针

</pre>
其中\_IO\_read\_base，\_IO\_write\_base，\_IO\_buf\_base都指向了同一缓冲区。  

这里有一点十分有意思，如果当前标准输入输出流为无缓冲流，也就是说我们不用为上述几个指针分配堆块作为临时缓冲区时，这几个指针指向何处呢？当然这几个指针不可能为NULL，因为此时至少也需要1个byte的缓冲区，不可能直接将数据读到目的地址（以读为例）。其实，此时上述几个指针都指向了\_shortbuf字段（偏移+0x83），该字段为一个5字节的临时buff区域，足够作为一个临时缓冲存放数据了。  

附上64bit模式下各字段的偏移：

    0x0   _flags
    0x8   _IO_read_ptr
    0x10  _IO_read_end
    0x18  _IO_read_base
    0x20  _IO_write_base
    0x28  _IO_write_ptr
    0x30  _IO_write_end
    0x38  _IO_buf_base
    0x40  _IO_buf_end
    0x48  _IO_save_base
    0x50  _IO_backup_base
    0x58  _IO_save_end
    0x60  _markers
    0x68  _chain
    0x70  _fileno
    0x74  _flags2
    0x78  _old_offset
    0x80  _cur_column
    0x82  _vtable_offset
    0x83  _shortbuf
    0x88  _lock
    0x90  _offset
    0x98  _codecvt
    0xa0  _wide_data
    0xa8  _freeres_list
    0xb0  _freeres_buf
    0xb8  __pad5
    0xc0  _mode
    0xc4  _unused2
    0xd8  vtable
## 2.2 \_IO\_jump\_t vtable结构体（vtable） ##
<pre class = "prettyprint lang-javascript">
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};

//关于JUMP_FIELD的宏定义如下所示：
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
</pre>
从中我们可以看到\_IO\_jump\_t结构体就是一个保存函数指针的列表，其中定义了各种文件流会用到的函数。其中有几个重要的函数，作用如下：  
1. \_\_xsgetn，fread实际调用的函数  
2. \_\_xsputn，fwrite实际调用的函数  
3. \_\_finish，fclose最终会调用的函数  
4. \_\_overflow，发生内存错误时会调用该函数  
5. \_\_read，\_IO\_SYSREAD最终会调用的函数指针（如果当前缓冲区中已无数据，则会调用该函数）  
6. \_\_write，与\_\_read相似  
7. \_\_doallocate，当流缓冲区buff为空时，调用该分配函数  
未完待续。。。。。。。。。。。。。。
## 3. C标准库的I/O缓存 ##
C标准库的I/O缓冲主要有以下三种类型：  
全缓冲，行缓冲，无缓冲  
### 3.1 全缓冲 ###
全缓冲：如果缓冲区写满了就写回内核。  
常规文件通常是全缓冲的。  

### 3.2 行缓冲 ###
行缓冲：如果用户程序写的数据中有换行符就把这一行写回内核,或者如果缓冲区写满了就写回内核。  
标准输入（stdin）和标准输出（stdout）对应终端设备时通常是行缓冲的。  

以下两种情况也会导致行缓冲的Flush。  
1. 用户程序调用库函数从无缓冲的文件中读取。  
2. 或者从行缓冲的文件中读取,并且这次读操作会引发系统调用从内核读取数据

如下面程序所示（stdin行缓冲）：
<pre class = "prettyprint lang-javascript">
#include "stdlib.h"
#include "stdio.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "fcntl.h"

int main(void)
{
  char buf[5];
  FILE *myfile =stdin;
  printf("before reading\n");
  printf("read buffer base %p\n", myfile->_IO_read_base);
  printf("read buffer end %p\n",myfile->_IO_read_end);
  printf("read buffer ptr %p\n",myfile->_IO_read_ptr);
  printf("read buffer length %d\n", myfile->_IO_read_end - myfile->_IO_read_base);
  
  printf("write buffer base %p\n", myfile->_IO_write_base);
  printf("write buffer end %p\n",myfile->_IO_write_end);
  printf("write buffer ptr %p\n",myfile->_IO_write_ptr);
  printf("write buffer length %d\n", myfile->_IO_write_end - myfile->_IO_write_base);
  

  printf("buf buffer base %p\n", myfile->_IO_buf_base);
  printf("buf buffer end %d\n",myfile->_IO_buf_end);
  printf("buf buffer length %d\n", myfile->_IO_buf_end - myfile->_IO_buf_base);
  
  printf("\n");
  fgets(buf, 5, myfile);
  fputs(buf, myfile);	//这里需要注意，stdin流是只能从中读入内容而无法写入（fp->flag & _IO_NO_WRITES == 1)
  printf("\n");
  
  printf("after reading\n");
  printf("read buffer base %p\n", myfile->_IO_read_base);
  printf("read buffer end %p\n",myfile->_IO_read_end);
  printf("read buffer ptr %p\n",myfile->_IO_read_ptr);
  printf("read buffer length %d\n", myfile->_IO_read_end - myfile->_IO_read_base);

  printf("write buffer base %p\n", myfile->_IO_write_base);
  printf("write buffer end %p\n",myfile->_IO_write_end);
  printf("write buffer ptr %p\n",myfile->_IO_write_ptr);
  printf("write buffer length %d\n", myfile->_IO_write_end - myfile->_IO_write_base);
    
  printf("buf buffer base %p\n", myfile->_IO_buf_base);
  printf("buf buffer end %p\n",myfile->_IO_buf_end);
  printf("buf buffer length %d\n", myfile->_IO_buf_end - myfile->_IO_buf_base);
  
  return 0;
}
</pre>
运行结果如下所示：  
![stdin_result](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/io0.JPG)

### 3.3 无缓冲 ###
无缓冲：用户程序每次调库函数做写操作都要通过系统调用写回内核。  
标准错误（stderr）输出通常是无缓冲的,这样用户程序产生的错误信息可以尽快输出到设备。


当我们调用fgets、fread函数执行读操作时，会初始化读缓冲区(\_IO\_read\_base,\_IO\_read\_end,\_IO\_read\_ptr均为0)。然后调用系统调用冲内核缓冲区中读入数据到流缓冲区（即以上指针所表示的缓冲区）
