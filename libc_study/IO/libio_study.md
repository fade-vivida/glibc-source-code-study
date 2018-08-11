# Glibc文件流函数的实现机制 #
glibc中关于文件流函数（fopen，fread，fwrite等）的实现源代码位于libio目录下。  
# 1. fopen #
**iofopen.c** 是fopen函数实现的关键代码，其中包含以下两个关键函数。

	_IO_FILE *
	_IO_new_fopen (const char *filename, const char *mode)
	{
	  	return __fopen_internal (filename, mode, 1);
	}
当我们平时在写C程序调用fopen函数时，实际调用的函数就是\_IO\_new\_fopen函数（在iofopen.c中可以看到关于fopen与该函数的链接及符号对应）。然后该函数又会调用\_\_fopen\_internal实现真正的函数功能。

## 1.1 \_\_fopen\_internal函数关键代码如下所示 ##

	_IO_FILE * __fopen_internal (const char *filename, const char *mode, int is32)
	{
	  	struct locked_FILE
	  	{
	    	struct _IO_FILE_plus fp;
			#ifdef _IO_MTSAFE_IO
	    		_IO_lock_t lock;
			#endif
	    	struct _IO_wide_data wd;
	  	} *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
		//在该函数中又定义了一个结构体，该结构体其实主要包含3个元素，(struct _IO_FILE_plus)fp，_IO_lock_t lock，(struct _IO_wide_data)wd
	  	if (new_f == NULL)
	    	return NULL;
		#ifdef _IO_MTSAFE_IO
	  		new_f->fp.file._lock = &new_f->lock;
		#endif
<a href = "#1">

	  	_IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);	//调用_IO_old_init函数进行初始化
</a>
	  	
		_IO_JUMPS (&new_f->fp) = &_IO_file_jumps;	//设置fp的vtable字段，虚函数表
<a href = "#2">

		_IO_new_file_init_internal (&new_f->fp);	//再次调用初始化函数（该函数完成其他的初始化功能）
</a>

		#if  !_IO_UNIFIED_JUMPTABLES
	  		new_f->fp.vtable = NULL;
		#endif
	  	if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)		//该函数在源代码中无法找到定义，目前悬而未解。。。。
	    	return __fopen_maybe_mmap (&new_f->fp.file);
<a href = "#3">

		_IO_un_link (&new_f->fp);	//从_IO_list_all链表上拆下刚new_f->fp
</a>

		//如果程序运行到这里，说明打开文件失败，此时将文件指针从链表上拆下，并释放该堆块。
		free (new_f);
	  	return NULL;
	}
从源代码中可以看出，该函数功能为创建一个locked\_FILE类型的结构体new\_f（该结构体包含3个元素fp，lock，wd）,然后对new\_f进行一系列初始化（包括初始化\_IO\_FILE\_plus结构体各个字段，将fp加入\_IO\_list\_all链表等），最后调用\_IO\_file\_fopen函数打开该文件流指针。
<a name = "1">
## 1.2 \_IO\_no\_init函数实现源代码 ##
</a>

	void _IO_no_init (_IO_FILE *fp, int flags, int orientation,struct _IO_wide_data *wd, const struct _IO_jump_t *jmp)
	{
		_IO_old_init (fp, flags);
		fp->_mode = orientation;	//初始化时，fp->_mode = 0
		if (orientation >= 0)
		{
			//对（struct _IO_FILE)fp的_wide_data字段进行初始化
			fp->_wide_data = wd;
			fp->_wide_data->_IO_buf_base = NULL;
			fp->_wide_data->_IO_buf_end = NULL;
			fp->_wide_data->_IO_read_base = NULL;
			fp->_wide_data->_IO_read_ptr = NULL;
			fp->_wide_data->_IO_read_end = NULL;
			fp->_wide_data->_IO_write_base = NULL;
			fp->_wide_data->_IO_write_ptr = NULL;
			fp->_wide_data->_IO_write_end = NULL;
			fp->_wide_data->_IO_save_base = NULL;
			fp->_wide_data->_IO_backup_base = NULL;
			fp->_wide_data->_IO_save_end = NULL;
			
			fp->_wide_data->_wide_vtable = jmp;
		}
		else
			/* Cause predictable crash when a wide function is called on a byte stream.  */
			fp->_wide_data = (struct _IO_wide_data *) -1L;
		fp->_freeres_list = NULL;
	}


## 1.3 \_IO\_old\_init函数实现代码 ##

	void _IO_old_init (_IO_FILE *fp, int flags)
	{
		fp->_flags = _IO_MAGIC|flags;	//_IO_MAGIC = 0xFBAD0000 魔数
		fp->_flags2 = 0;
		if (stdio_needs_locking)
		fp->_flags2 |= _IO_FLAGS2_NEED_LOCK;	//_IO_FLAGS2_NEED_LOCK = 128
		fp->_IO_buf_base = NULL;
		fp->_IO_buf_end = NULL;
		fp->_IO_read_base = NULL;
		fp->_IO_read_ptr = NULL;
		fp->_IO_read_end = NULL;
		fp->_IO_write_base = NULL;
		fp->_IO_write_ptr = NULL;
		fp->_IO_write_end = NULL;
		fp->_chain = NULL; /* Not necessary. */
		
		fp->_IO_save_base = NULL;
		fp->_IO_backup_base = NULL;
		fp->_IO_save_end = NULL;
		fp->_markers = NULL;
		fp->_cur_column = 0;
		#if _IO_JUMPS_OFFSET
			fp->_vtable_offset = 0;
		#endif
		#ifdef _IO_MTSAFE_IO
		  if (fp->_lock != NULL)
			_IO_lock_init (*fp->_lock);
		#endif
	}

<a name="2">
## 1.4 \_IO\_new\_file\_init\_internal函数实现代码 ##
</a>

	void _IO_new_file_init_internal (struct _IO_FILE_plus *fp)
	{
		/* POSIX.1 allows another file handle to be used to change the position of our file descriptor. 
		Hence we actually don't know the actual position before we do the first fseek (and until a 
		following fflush). */
	  	fp->file._offset = _IO_pos_BAD;		//_IO_pos_BAD = -1
	  	fp->file._IO_file_flags |= CLOSED_FILEBUF_FLAGS;	
		
<a href = "#4"> 

		_IO_link_in (fp);	//将fp插入_IO_list_all链表中，插入位置为链表头部
</a>	
  	
		fp->file._fileno = -1;
	}

CLOSED\_FILEBUF\_FLAGS定义如下：

	#define CLOSED_FILEBUF_FLAGS \
  		(_IO_IS_FILEBUF+_IO_NO_READS+_IO_NO_WRITES+_IO_TIED_PUT_GET)	
		//_IO_IS_FILEBUF = 0x2000, _IO_NO_READ = 0x4, _IO_NO_WRITES = 0x8, _IO_TIED_PUT_GET = 0x400
可以看到\_IO\_NO\_WRITES = 0x8,\_IO\_NO\_READ = 0x4。以stdin和stdout为例，stdin为标准输入，stdout为标准输出，理论上stdin文件流标识符中应该包含\_IO\_NO\_READ，stdout文件流标识符中应该包含\_IO\_NO\_WRITES。  

实际情况如下所示：  
![test](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/io1.JPG)  
实际结果与猜想一致。

<a name="3">
## 1.5 \_IO\_un\_link函数实现代码 ##
</a>
该函数功能为从\_IO\_list\_all链表上拆下fp指针。

	_IO_un_link (struct _IO_FILE_plus *fp)
	{
		if (fp->file._flags & _IO_LINKED)	//_IO_LINKED = 0x80
	    {
			struct _IO_FILE **f;
			#ifdef _IO_MTSAFE_IO
				_IO_cleanup_region_start_noarg (flush_cleanup);
	      		_IO_lock_lock (list_all_lock);
	      		run_fp = (_IO_FILE *) fp;
	      		_IO_flockfile ((_IO_FILE *) fp);
			#endif
	      	if (_IO_list_all == NULL);
	      	else if (fp == _IO_list_all)
				_IO_list_all = (struct _IO_FILE_plus *) _IO_list_all->file._chain;
	      	else
				for (f = &_IO_list_all->file._chain; *f; f = &(*f)->_chain)
		  			if (*f == (_IO_FILE *) fp)
		    		{
		      			*f = fp->file._chain;
		      			break;
		    		}
	      	fp->file._flags &= ~_IO_LINKED;
			#ifdef _IO_MTSAFE_IO
	      		_IO_funlockfile ((_IO_FILE *) fp);
	      		run_fp = NULL;
	      		_IO_lock_unlock (list_all_lock);
	      		_IO_cleanup_region_end (0);
			#endif
	   }
	}

<a name = "4">
## 1.6 \_IO\_link\_in函数实现代码 ##
</a>
该函数功能为将fp标志的文件流指针插入\_IO\_list\_all链表中。

	void _IO_link_in (struct _IO_FILE_plus *fp)
	{
		if ((fp->file._flags & _IO_LINKED) == 0)
	    {
			fp->file._flags |= _IO_LINKED;
			#ifdef _IO_MTSAFE_IO
				_IO_cleanup_region_start_noarg (flush_cleanup);
	      		_IO_lock_lock (list_all_lock);
	      		run_fp = (_IO_FILE *) fp;
	      		_IO_flockfile ((_IO_FILE *) fp);
			#endif
	      	
			fp->file._chain = (_IO_FILE *) _IO_list_all;	
	      	_IO_list_all = fp;
			//将fp插入到链表头部
		
			#ifdef _IO_MTSAFE_IO
	      		_IO_funlockfile ((_IO_FILE *) fp);
	      		run_fp = NULL;
	      		_IO_lock_unlock (list_all_lock);
	      		_IO_cleanup_region_end (0);
			#endif
	    }
	}

# 2. fread #
	_IO_size_t _IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
	{
		_IO_size_t bytes_requested = size * count;	//读入的总字节数
	  	_IO_size_t bytes_read;
	  	CHECK_FILE (fp, 0);		//对文件指针进行检查
	  	if (bytes_requested == 0)
	    	return 0;
	  	_IO_acquire_lock (fp);
<a href = "#5">
	  	
		bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);	//调用_IO_sgetn 函数从fp文流中读入bytes_requested字节的数据到buf中	
</a>

	  	_IO_release_lock (fp);
	  	return bytes_requested == bytes_read ? count : bytes_read / size;
	}

## 2.1 CHECK\_FILE宏 ##
该宏定义的功能为检查fp指针是否合法，如果当前为调试模式，则检查fp是否为NULL。若为NULL，则返回0。否则，检查fp指针的\_IO\_file\_flags字段的高word是否为\_IO\_MAGIC(0xfbad)。

	#ifdef IO_DEBUG
	# define CHECK_FILE(FILE, RET) \
		if ((FILE) == NULL) 
		{ 
			MAYBE_SET_EINVAL; 
			return RET; 
		}
		else 
		{ 
			COERCE_FILE(FILE); 
		    if (((FILE)->_IO_file_flags & _IO_MAGIC_MASK) != _IO_MAGIC)		//_IO_MAGIC_MASK = 0xffff0000,_IO_MAGIC = 0xfbad0000
		  	{ 
				MAYBE_SET_EINVAL; 
				return RET; 
			}
		}
	#else
		#define CHECK_FILE(FILE, RET) COERCE_FILE (FILE)
	#endif

	# define COERCE_FILE(FILE) /* Nothing */
<a name = "5">
## 2.2 \_IO\_sgetn函数 ##
</a>
可以看到该函数只是单纯的调用了\_IO\_XSGETN宏。

	_IO_size_t
	_IO_sgetn (_IO_FILE *fp, void *data, _IO_size_t n)
	{
	  /* FIXME handle putback buffer here! */
	  return _IO_XSGETN (fp, data, n);
	}
该宏定义如下所示：  
	
	#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)	//实际调用函数为__xsgetn
	#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
该宏再次调用了JUMP2宏，可以看出JUMP2宏的功能是一个函数调用列表，且该函数有两个参数。

	
	# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
	static inline const struct _IO_jump_t *
	IO_validate_vtable (const struct _IO_jump_t *vtable)
	{
	  /* Fast path: The vtable pointer is within the __libc_IO_vtables
	     section.  */
	  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
	  const char *ptr = (const char *) vtable;
	  uintptr_t offset = ptr - __start___libc_IO_vtables;
	  if (__glibc_unlikely (offset >= section_length))
	    /* The vtable pointer is not in the expected section.  Use the
	       slow path, which will terminate the process if necessary.  */
	    _IO_vtable_check ();
	  return vtable;
	}
