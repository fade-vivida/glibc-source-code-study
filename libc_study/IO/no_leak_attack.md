# How to Exploit in no_leak Challenge

我们经常会在一些题目里面遇到没有 leak 的情况。此时，一般有两种方法可以使用：

1. 利用预留信息。一般这种题目都是结合堆利用进行考察，而我们知道在堆中是有 libc 地址的（释放 `chunk` 到 `unsortedbin` 中），那么我们就可以利用这些预留的地址，采用部分覆写的方法来利用达到我们的目的。
2. 虽然程序本身没有实现类似 `show` 功能的函数，但程序只要有和用户的交互，那么必然会在运行过程中使用诸如 `puts`，`printf` 等这样的标准输出函数。那么我们是否可以利用这些带有输出功能的函数来泄露一些信息呢？答案是可以！，我们下面就来看看如何利用 `stdout` 来泄露 libc 地址信息。

# 1. _IO_FILE 结构体

不展开讲解各个字段的具体含义，只是为了方便查看

```c++
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
```

## 1.1 _IO_FILE flags 字段

下面是关于 `_IO_FILE` 的 `_flags` 字段的一些常量宏

```c++
/* Magic numbers and bits for the _flags field.
   The magic numbers use the high-order bits of _flags;
   the remaining bits are available for variable flags.
   Note: The magic numbers must all be negative if stdio
   emulation is desired. */

#define _IO_MAGIC 0xFBAD0000 /* Magic number */
#define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
#define _IO_UNBUFFERED 2
#define _IO_NO_READS 4 /* Reading not allowed */
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
#define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/
#define _IO_IN_BACKUP 0x100
#define _IO_LINE_BUF 0x200
#define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
#define _IO_BAD_SEEN 0x4000
```

正常情况下 `_IO_2_1_stdin_->_flags = 0xfbad208b`，`_IO_2_1_stdout_->_flags = 0xfbad2887`。

其中我们需要重点关注的宏常量有以下几个

- `_IO_IS_APPENDING` 
- `_IO_CURRENTLY_PUTTING`。
- `_IO_LINE_BUF`

至于这样宏常量是用来干什么的，我们后面再说

# 2. puts() 函数

我们以 `puts` 函数为例来进行具体分析。下面是 `puts` 函数的实现代码（`libio\ioputs.c`）

```c++
int _IO_puts (const char *str)
{
  int result = EOF;
  _IO_size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);

  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (_IO_stdout);
  return result;
}

weak_alias (_IO_puts, puts)
```

其中会进行一些判断我们先不用管，我们需要重点关注的是他的真正实现例程 `_IO_sputn`。

## 2.1 _IO_sputn()

```c++
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)

#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
```

`_IO_sputn()` 函数使用宏来实现，具体来看就是调用了 `_IO_FILE->vtable` 中的 `__xsputn` 函数指针（参数有两个，一个指向数据的指针和数据长度）。那么下面我们就需要找到 `__xsputn` 函数指针的具体实例

## 2.2 _IO_new_file_xsputn()

该函数就是 `__xsputn` 的一个实现实例（针对不同类型的文件描述符，glibc 实现了不同的 xsputn）。该实例我们可以认为是标准输出 `stdout` 对于 `xsputn` 的实现过程。 

```c++
_IO_size_t _IO_new_file_xsputn(_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *)data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
  {
    count = f->_IO_buf_end - f->_IO_write_ptr;
    if (count >= n)
    {
      const char *p;
      for (p = s + n; p > s;)
      {
        if (*--p == '\n')
        {
          count = p - s + 1;
          must_flush = 1;
          break;
        }
      }
    }
  }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
  {
    if (count > to_do)
      count = to_do;
    f->_IO_write_ptr = __mempcpy(f->_IO_write_ptr, s, count);
    s += count;
    to_do -= count;
  }
  if (to_do + must_flush > 0)
  {
    _IO_size_t block_size, do_write;
    /* Next flush the (full) buffer. */
    if (_IO_OVERFLOW(f, EOF) == EOF)
      /* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
      return to_do == 0 ? EOF : n - to_do;

    /* Try to maintain alignment: write a whole number of blocks.  */
    block_size = f->_IO_buf_end - f->_IO_buf_base;
    do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

    if (do_write)
    {
      count = new_do_write(f, s, do_write);
      to_do -= count;
      if (count < do_write)
        return n - to_do;
    }

    /* Now write out the remainder.  Normally, this will fit in the
	 buffer, but it's somewhat messier for line-buffered files,
	 so we let _IO_default_xsputn handle the general case. */
    if (to_do)
      to_do -= _IO_default_xsputn(f, s + do_write, to_do);
  }
  return n - to_do;
}
libc_hidden_ver(_IO_new_file_xsputn, _IO_file_xsputn)
```

主要流程如下：

1. 得到当前剩余缓冲区空间（`_IO_write_buff`）大小。此时分为两种情况：
   - 该 `FILE_IO` 为行缓冲（`_IO_LINE_BUF`，0x200）且设置了立即输出标识（`_IO_CURRENTLY_PUTTING`，0x800），通俗点讲就是遇到 `\n` 立即输出。那么首先计算缓冲区剩余空间 `count = f->_IO_buf_end - f->_IO_write_ptr`。
     - 如果 `count >= n`，由于我们设置了行缓冲，那么我们在遇到 `\n` 时应该停止写入并输出此时缓冲区中的内容。因此，我们修正 `count` 值为遇到 `\n` 后的字符串长度，并设置 `must_flush` 为 1，表示后面需要刷新一次缓冲区。
     - 否则，表示当前剩余空间不足以写入本次数据，本次写入最多只能有 `count` 个字节。
   - `FILE_IO` 不是行缓冲，且也没有设置立即输出，那么计算剩余空间大小 `count = f->_IO_write_end - f->_IO_write_ptr `。
2. 如果 `count > 0`，表示缓冲区中还有剩余空间，那么调用 `memcpy` 向缓冲区中拷贝一次数据（长度为 `min(to_do,count)`），并修正指向数据的指针 `s` 和数据长度 `to_do`。这里之所以修正是因为存在当前剩余空间大小小于数据长度的情况，即没有办法一次完全拷贝。
3. 如果 `to_do + must_flush > 0`，也就是说要么遇到了行缓冲且输出数据中有换行符，要么当前缓冲区不足以容纳此次输出数据。无论是以上哪种情况，都需要进行一次流刷新处理（将数据写回内核），即调用 `_IO_OVERFLOW`。
4. 如果 `_IO_OVERFLOW` 返回不为 `EOF`，那么说明此次刷新成功，当前缓冲区中的数据已被输出到对应设备中。那么此时我们需要考虑的就是剩余的数据应该怎么办？
5. glibc 给出的解决方法为首先使用



## 2.3 _IO_default_xsputn()

理解了上面的流程后在看该函数就很简单了。该函数就是不断往 `_IO_write_buff` 中填充数据，每当填充满后（`_IO_write_ptr == _IO_write_end`），就调用一次 `_IO_OVERFLOW` 刷新一次输出缓冲，知道所有的数据都写回内核为止。

```c++
_IO_size_t _IO_default_xsputn(_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (char *)data;
  _IO_size_t more = n;
  if (more <= 0)
    return 0;
  for (;;)
  {
    /* Space available. */
    if (f->_IO_write_ptr < f->_IO_write_end)
    {
      _IO_size_t count = f->_IO_write_end - f->_IO_write_ptr;
      if (count > more)
        count = more;
      if (count > 20)
      {
        f->_IO_write_ptr = __mempcpy(f->_IO_write_ptr, s, count);
        s += count;
      }
      else if (count)
      {
        char *p = f->_IO_write_ptr;
        _IO_ssize_t i;
        for (i = count; --i >= 0;)
          *p++ = *s++;
        f->_IO_write_ptr = p;
      }
      more -= count;
    }
    if (more == 0 || _IO_OVERFLOW(f, (unsigned char)*s++) == EOF)
      break;
    more--;
  }
  return n - more;
}
libc_hidden_def(_IO_default_xsputn)
```



## 2.4 _IO_new_file_overflow()

我们可以将该函数理解为如果输出缓冲区已满，那么就需要调用一次 `_IO_new_file_overflow()` 来对缓冲区进行刷新，将数据写回内核。

既然要写回内核，那么我们就需要函数能够走到后面 `_IO_do_write()` 的位置，因此我们就需要绕过一些验证条件。

- 验证条件 1：`_flags` 字段不能设置 `_IO_NO_WRITES` 标志（8）
- 验证条件 2：`_flags` 字段需要设置 `_IO_CURRENTLY_PUTTING` 标志（0x800），这么做的目的是为了不进入第二个 `if` 条件判断语句。因为如果进入该判断，最后将会设置 `f->_IO_write_ptr = f->_IO_write_base = f->_IO_read_ptr`，那么我们在下面调用 `_IO_do_write()` 写回内核的数据字节数（`_IO_write_ptr - _IO_write_base`）就为 0，不会输出任何内容

当我们正确走到 `_IO_do_write (f, f->_IO_write_base,f->_IO_write_ptr - f->_IO_write_base)` 的位置，就会将从 `_IO_write_base` 开始，`_IO_write_ptr - _IO_write_base` 这么长的数据写回内核（其实就是输出到控制台中）。

```c++
int _IO_new_file_overflow (_IO_FILE *f, int ch)
{
	if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
	{
		f->_flags |= _IO_ERR_SEEN;
		__set_errno (EBADF);
		return EOF;
	}
	/* If currently reading or no buffer allocated. */
	if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
	{
		//通过置f->_flags 为 0x800，从而绕过该检查。
		/* Allocate a buffer if needed. */
		if (f->_IO_write_base == NULL)
		{
			_IO_doallocbuf (f);
			_IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
		}
		/* Otherwise must be currently reading.
		If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
		logically slide the buffer forwards one block (by setting the
		read pointers to all point at the beginning of the block).  This
		makes room for subsequent output.
		Otherwise, set the read pointers to _IO_read_end (leaving that
		alone, so it can continue to correspond to the external position). */
		if (__glibc_unlikely (_IO_in_backup (f)))
		{
			//如果 f 设置了备份缓存，则替换该备份缓存区为主缓存区，并滑动读入缓冲区为写缓冲空出位置
			size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
			_IO_free_backup_area (f);
			f->_IO_read_base -= MIN (nbackup,f->_IO_read_base - f->_IO_buf_base);
			f->_IO_read_ptr = f->_IO_read_base;
		}
	
		if (f->_IO_read_ptr == f->_IO_buf_end)
			f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
		f->_IO_write_ptr = f->_IO_read_ptr;
		f->_IO_write_base = f->_IO_write_ptr;
		f->_IO_write_end = f->_IO_buf_end;
		f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;
		
		f->_flags |= _IO_CURRENTLY_PUTTING;
		if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
			f->_IO_write_end = f->_IO_write_ptr;
	}
	if (ch == EOF)
		return _IO_do_write (f, f->_IO_write_base,f->_IO_write_ptr - f->_IO_write_base); //能够进行信息泄露的关键点，经常在无 leak 的堆题中出现
	if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
		if (_IO_do_flush (f) == EOF)	//其实就是根据 mode 看是调用 _IO_do_write 还是 _IO_wdo_write
			return EOF;
	*f->_IO_write_ptr++ = ch;
	if ((f->_flags & _IO_UNBUFFERED) || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
		if (_IO_do_write (f, f->_IO_write_base,f->_IO_write_ptr - f->_IO_write_base) == EOF)
		return EOF;
	return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```

这里我们再来看看几种会调用 `_IO_do_write()` 的情况分别是什么：

- 当 `ch == EOF`，即下一个字符为 `EOF`，表示本次输出已经结束，可以进行一次写回操作了

- 当 `f->_IO_write_ptr == f->_IO_buf_end`，即写缓冲指针已经移动到缓冲区末尾了，那么此时需要调用一次 `_IO_do_flush()`。

  `_IO_do_flush()` 的实现如下所示：

  ```c++
  #define _IO_do_flush(_f) \
    ((_f)->_mode <= 0							      \
     ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
  		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
     : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
  		   ((_f)->_wide_data->_IO_write_ptr			      \
  		    - (_f)->_wide_data->_IO_write_base)))
  ```

  此时不难发现，就是根据当前文件流的模式（`_mode`），来判断是调用单字节流的写回函数 `_IO_do_write()`，还是宽字节流的写回函数 `_IO_wdo_write()`。

- 当 `f->_flags` 设置了 `_IO_UNBUFFERED` 标志（2），表明该文件流是无缓冲模式，需要立即将数据写回内核

- 当 `f->_flags` 设置了 `_IO_LINE_BUF` 标志（0x200）且下一个要写入缓冲区的字节为 `\n`，表明该文件流为行缓冲且遇到了换行符，那么需要调用 `_IO_do_write()` 进行一次写回操作。

## 2.5 _IO_new_do_write()

```c++
int _IO_new_do_write(_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0 || (_IO_size_t)new_do_write(fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver(_IO_new_do_write, _IO_do_write)
```

`_IO_new_do_write()` 函数是对 `new_do_write()` 函数的封装，我们直接来看 `new_do_write()` 函数

```c++


static _IO_size_t new_do_write(_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
  {
    _IO_off64_t new_pos = _IO_SYSSEEK(fp, fp->_IO_write_base - fp->_IO_read_end, 1);
    if (new_pos == _IO_pos_BAD)
      return 0;
    fp->_offset = new_pos;
  }
  count = _IO_SYSWRITE(fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column(fp->_cur_column - 1, data, count) + 1;
  _IO_setg(fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0 && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
                           ? fp->_IO_buf_base
                           : fp->_IO_buf_end);
  return count;
}
```

