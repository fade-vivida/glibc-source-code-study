# Glibc文件流函数的实现机制 #
源代码库版本为：glibc2.27

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
**注：通过下面的分析可以知道其实fread函数在实现功能时，真正调用的时函数列表中的\_\_xsgetn函数**

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
函数的返回值为实际读入的数据项的个数（之所以这么说是因为fread函数的第二个参数为读入数据类型，第三个参数为该类型数据的个数）。
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
该宏及相关宏定义代码如下所示：  
	
	#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)	//实际调用函数为__xsgetn
	#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
该宏再次调用了JUMP2宏，可以看出JUMP2宏的功能为调用一个函数列表中的函数（函数有两个参数）。  

在调用函数前还会对该函数指针列表的合法性进行检查，相关代码如下所示：

	#if _IO_JUMPS_OFFSET	//如果使用了老版本的的_IO_FILE结构体，_IO_JUMPS_OFFSET为1，否则为0
		# define _IO_JUMPS_FUNC(THIS) \
			(IO_validate_vtable                                                   \
			(*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS) + (THIS)->_vtable_offset)))	
			//也就是说如果是老版本，还修改vtable后，还需要将_vtable_offset字段置0
		# define _IO_vtable_offset(THIS) (THIS)->_vtable_offset
	#else
		# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
		# define _IO_vtable_offset(THIS) 0
	#endif
	
	#define _IO_JUMPS_FILE_plus(THIS) _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
	
	/* Type of MEMBER in struct type TYPE.  */
	#define _IO_MEMBER_TYPE(TYPE, MEMBER) __typeof__ (((TYPE){}).MEMBER)
	//返回成员变量的类型	

	/* Essentially ((TYPE *) THIS)->MEMBER, but avoiding the aliasing violation in case THIS has a different pointer type.  */
	#define _IO_CAST_FIELD_ACCESS(THIS, TYPE, MEMBER) \
	(*(_IO_MEMBER_TYPE (TYPE, MEMBER) *)(((char *) (THIS)) + offsetof(TYPE, MEMBER)))
	//返回THIS所标志的结构体中成员MEMBER的地址
进一步分析其调用的宏定义，可以看出程序首先通过固定偏移找到vtable成员变量，然后调用IO\_validata\_vtable函数检查该vtable变量的合法性。如果vtable函数指针列表合法，则调用该函数（\_\_xsgetn)。  

\_IO\_file\_plus结构体的vtable字段示意图：  
![vtable](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/io_jump.JPG)

## 2.3 vtable指针合法性检查 ##
IO\_validata\_vtable函数代码如下所示：

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
glibc默认的文件流函数指针调用列表位于一个固定的节中，因此一个快速的检查方法就是看vtable是否在该区间内，如果不是就必须采用较慢的更为细致的检测方法（\_IO\_vtable\_check)。  

\_IO\_vtable\_check函数代码如下：

	void attribute_hidden _IO_vtable_check (void)
	{
		#ifdef SHARED
	  		/* Honor the compatibility flag.  */
	  		void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
		#ifdef PTR_DEMANGLE
	  		PTR_DEMANGLE (flag);
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
	    	if (!rtld_active ()
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
该函数看不懂，大体意思应该是定义了共享模式和非共享模式下文件流vtable字段的检测方法。从实际应用中发现，在libc2.24之前可以在堆中放置一个vtable函数指针列表（伪造\_IO\_FILE结构），但在libc2.24之后该方法不可用，还有新的利用方法，未完待续。。。。。。。
# 3. fwrite #
**注：最终调用vtable中的\_\_xsputn**

	_IO_size_t _IO_fwrite (const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
	{
		_IO_size_t request = size * count;
	  	_IO_size_t written = 0;
	  	CHECK_FILE (fp, 0);
	  	if (request == 0)
	    	return 0;
	  	_IO_acquire_lock (fp);
	  	if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
	    	written = _IO_sputn (fp, (const char *) buf, request);		//最终调用_IO_sputn
	  	_IO_release_lock (fp);
	  	/* We have written all of the input in case the return value indicates
	    this or EOF is returned.  The latter is a special case where we
	    simply did not manage to flush the buffer.  But the data is in the
	    buffer and therefore written as far as fwrite is concerned.  */
	  	if (written == request || written == EOF)
			//这里需要注意written返回EOF是因为数据已经被写入到了内核缓冲中，但由于没有fflush，所以返回EOF
	    	return count;
	  	else
	    	return written / size;
	}
fwrite函数与fread函数逻辑相似，fwrite函数最终调用的vtable函数链表中的函数为\_\_xsputn。
# 4. fclose #
**注：调用vtable列表中的\_\_finish函数指针**

	int _IO_new_fclose (_IO_FILE *fp)
	{
		int status;
		CHECK_FILE(fp, EOF);	//fp->flag & 0xffff0000 = 0xfdab0000
		
		#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
	  	/* We desperately try to help programs which are using streams in a
	    strange way and mix old and new functions.  Detect old streams here.  */
	  	//该段代码的意义在于检测是否当前程序使用了老的文件流，如果是（fp->_vtable_off !=0)则调用_IO_old_fclose函数
			if (_IO_vtable_offset (fp) != 0)
	    		return _IO_old_fclose (fp);
		#endif
		/* First unlink the stream.  */
	 	if (fp->_IO_file_flags & _IO_IS_FILEBUF)	//_IO_IS_FILEBUF = 0x2000，表示当前fp文件流被打开过
	    	_IO_un_link ((struct _IO_FILE_plus *) fp);
		//将fp从_IO_list_all链表上拆下
	  	_IO_acquire_lock (fp);
	  	if (fp->_IO_file_flags & _IO_IS_FILEBUF)
	    	status = _IO_file_close_it (fp);	//调用_IO_file_close_it函数关闭文件流
	  	else
	    	status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
	  	_IO_release_lock (fp);
	  	_IO_FINISH (fp);	//调用vtable函数列表的__finish函数
	  	if (fp->_mode > 0)
	    {
			/* This stream has a wide orientation.  This means we have to free
		 	the conversion functions.  */
			//宽字节流的转换功能的释放
	      	struct _IO_codecvt *cc = fp->_codecvt;
	
	      	__libc_lock_lock (__gconv_lock);
	      	__gconv_release_step (cc->__cd_in.__cd.__steps);
	      	__gconv_release_step (cc->__cd_out.__cd.__steps);
	      	__libc_lock_unlock (__gconv_lock);
	    }
	  	else
	    {
			//是否有备份
			if (_IO_have_backup (fp))	//_IO_save_base字段
				_IO_free_backup_area (fp);
	    }
	  	if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
	    {
			fp->_IO_file_flags = 0;
	      	free(fp);
	    }
		return status;
	}
该函数功能为：  
1. 首先判断是否使用了旧的文件流指针，如果是则直接调用\_IO\_old_fclose函数。  
2. 判断当前文件流指针是否被打开过（\_IO\_IS\_FILEBUF标志），如果是则进行拆链和关闭文件流（实际调用了\_IO\_file\_close\_it函数）。  
3. 调用vtable中\_\_finish函数指针。  
4. 宽字节流相关处理（通过\_mode字段判断）。  
5. 流备份（\_IO\_save\_base字段）相关处理。  
6. 如果fp指针不是标准流（stdin，stdoub，stderr），则释放该文件流。
# 5. FSOP利用技术 #
**注：由于在libc2.24版本开始加入了关于vtable的检查，且在2.27版本中无\_IO\_flush\_all\_lockp函数（使用了其他函数代替）。因此关于该技术的讨论我们建立在libc2.24版本。**  

FSOP（File Stream Oriented Programming）是一种劫持\_IO\_list\_all（libc中全局变量）的方法。通过伪造的\_IO\_FILE\_plus结构体并修改\_IO\_list\_all链表使其指向伪造的\_IO\_FILE\_plus结构体。然后通过调用\_IO\_flush\_all\_lockp函数来调用伪造的vtable函数列表中的函数指针，达到控制程序流的目的。  

## 5.1 基于overflow的FSOP利用技术 ##
\_IO\_flush\_all\_lockp函数会在以下3中情况下被调用：  
1. 当发生内存错误的时候（此时会调用malloc\_printerr函数）  
2. 在执行exit函数时  
3. main函数返回时  
这里给出当libc检测到内存错误时该函数的调用路径：  
malloc\_printerr -> libc\_message -> abort（\_GI\_abort与abort强链接） -> fflush（\_IO\_flush\_all\_lockp的宏定义) -> \_IO\_flush\_all\_lockp

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
			if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)		//这里是一个很重要的判断条件，在下文会有说明
				#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
		   		|| (_IO_vtable_offset (fp) == 0
		       	&& fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
					> fp->_wide_data->_IO_write_base))
				#endif
		   		) && _IO_OVERFLOW (fp, EOF) == EOF)		//调用vtable函数列表中的\_\_overflow函数
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
触发\_\_overflow函数的5个条件：  
1. fp -> \_mode < 0  
2. fp -> \_IO\_write\_ptr > fp -> \_IO\_write\_base，表示还有数据没有写入内核缓冲区  
3. fp -> \_vtable\_offset = 0  
4. fp -> \_mode > 0  
5. fp -> \_wide\_data -> \_IO\_write\_ptr > fp -> \_wide\_data -> \_IO\_write\_base  
**注：这5个条件中1、2必须同时成立，或者3、4、5必须同时成立。**  

fp -> \_mode 字段是用来判断当前文件流指针是否使用了宽字节数据，fp -> \_mode < 0 表示未使用，因此接下来只需要判断\_IO\_write\_ptr 是否大于\_IO\_write\_base（是否还有数据没有写入）。如果fp -> \_mode >= 0 表示使用了宽字节数据，此时需要检查是\_wide\_data结构体中是否还有未写入的数据，并且fp -> \_vtable\_offset字段必须为0。
## 5.2 基于finish的FSOP利用技术 ##
该利用方法其实就是利用了在关闭文件流指针时（调用\_IO\_new\_fclose），最终会调用vtable函数列表中\_\_finish函数这一特性，具体源代码在章节4，这里不再赘述。
## 5.3 FSOP防御机制 ##
