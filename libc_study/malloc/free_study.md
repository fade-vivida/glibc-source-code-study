# glibc源码学习 #
# malloc.c #
# \_int\_free()函数 #
\_int\_free()函数的参数如下所示：

	_int_free (mstate av, mchunkptr p, int have_lock)
其中av表示当前释放chunk所在的arena，p为当前要释放的chunk，have\_lock为一个锁变量。
## 1. free check ##
在对chunk进行真正的free操作前，首先会进行一系列检查操作。
### 1.1 free\_check1 ###
![free_check1](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/free_check1.PNG)  
首先检查当前chunk p的地址是否在一个合法字段（由于比较是一个无符号数比较，因此-size会是一个非常大的值），然后看当前chunk p的地址是否对齐（64bit下为16字节对齐，32bit下为8字节对齐）。
### 1.2 free\_check2 ###
![free_check2](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/free_check2.PNG)  
对要释放chunk p的size进行检查。首先该chunk的size必须大于最小值（64bit：0x20,32bit：0x10），其次其大小必须也要对齐（与地址对齐方式一致）。
### 1.3 free\_check3 ###
调用check\_inuse\_chunk(av,p)函数进行检查。  
#### 1.3.1 do\_check\_inuse\_check()函数 ####
其中check\_inuse\_chunk()函数将调用do\_check\_inuse\_chunk()函数，该函数具体定义及相关解释如下所示：  
**注：一个十分有趣且重要的事情，在实际运行程序时可以发现对于大多数程序而言assert断言的判断好像并未实现，后经过查询资料发现assert语句只有在定义了DEBUG宏（也就是调试版本中）才会执行，在发行版本中（release版）assert语句没有实际意义。**
<pre class="prettyprint lang-javascript"> 
static void do_check_inuse_chunk (mstate av, mchunkptr p)
{
	mchunkptr next;
	do_check_chunk (av, p);		//调用do_check_chunk函数对chunk p进行检查
	if (chunk_is_mmapped (p))
		return; /* mmapped chunks have no next/prev */
	//检查chunk p的IS_MMAPPED字段是否设置，如果已经设置，则直接返回。
	/* Check whether it claims to be in use ... */
  	assert (inuse (p));		//检查p的是否处于inuse状态，检查方式为：看next chunk的pre_inuse字段是否为1
	next = next_chunk (p);
	/* ... and is surrounded by OK chunks.Since more things can be checked with free chunks than inuse ones,
	if an inuse chunk borders them and debug is on, it's worth doing them.*/
  	if (!prev_inuse (p))
	{
		/* Note that we cannot even look at prev unless it is not inuse */
		//如果前一块也是处于free状态，则必须对其也进行相应检查
		mchunkptr prv = prev_chunk (p);
		assert (next_chunk (prv) == p);		//pre chunk的next chunk必须为当前chunk p，该检查在release版本失效
		do_check_free_chunk (av, prv);		//对prv进行free chunk的检查
	}
	if (next == av->top)
	{
		assert (prev_inuse (next));
		assert (chunksize (next) >= MINSIZE);
		//如果next chunk为top chunk，其prev_inuse字段必须设置为1，且其size大小必须大于MINSIZE	
	}
	else if (!inuse (next))
		do_check_free_chunk (av, next);		//如果后一块也是处于free状态，则对其也进行free chunk检查
}
</pre>
#### 1.3.2 do\_check\_free\_chunk()函数 ####
**注：其中的所有assert检查在release版本失效。**
<pre class="prettyprint lang-javascript"> 
static void do_check_free_chunk (mstate av, mchunkptr p)
{
	INTERNAL_SIZE_T sz = chunksize_nomask (p) & ~(PREV_INUSE | NON_MAIN_ARENA);
	//这里的sz是去除标志位PREV_INUSE和NON_MAIN_ARENA，但没有去除IS_MMAPPED
  	mchunkptr next = chunk_at_offset (p, sz);
	do_check_chunk (av, p);		//检查chunk p的合法性
	
	/* Chunk must claim to be free ... */
  	assert (!inuse (p));		//chunk p必须是free状态
	assert (!chunk_is_mmapped (p));		//chunk p不是通过MMAP得到的
	
	/* Unless a special marker, must have OK fields */
  	if ((unsigned long) (sz) >= MINSIZE)
	{
		assert ((sz & MALLOC_ALIGN_MASK) == 0);		//sz大小对齐检查
		assert (aligned_OK (chunk2mem (p)));		//用户输入数据起始地址对齐检查（本质与chunk p起始地址对齐检查一致）
      	
		/* ... matching footer field */
		assert (prev_size (next_chunk (p)) == sz);		//next chunk的pre size必须等于当前块的size
      	
		/* ... and is fully consolidated */
		assert (prev_inuse (p));		//chunk p的prev_inuse字段必须为1，即不允许出现两个相邻且处于free状态的块（未合并）
		assert (next == av->top || inuse (next));		//next chunk要么是top chunk，要不是处于inuse状态的chunk，检查本质也是不允许出现两个相邻且处于free状态的块
		
		/* ... and has minimally sane links */
		assert (p->fd->bk == p);
		assert (p->bk->fd == p);
		//双向链表指针检查
	}
	else /* markers are always of size SIZE_SZ */
		assert (sz == SIZE_SZ);
}
</pre>
#### 1.3.3 do\_check\_chunk()函数 ####
**注：这里有一点需要注意，就是关于contiguous宏，由于main\_arena是采用brk分配，因此通过main\_arena得到的chunk地址均为连续分配。而MMAP则是通过映射一块大内存，然后模仿brk的分配方式进行分配，理论上分配到的chunk地址是不连续的。**  
**注：其中所有的assert检查在release版本失效。**
<pre class="prettyprint lang-javascript"> 
static void do_check_chunk (mstate av, mchunkptr p)
{
	unsigned long sz = chunksize (p);
  	/* min and max possible addresses assuming contiguous allocation */
  	char *max_address = (char *) (av->top) + chunksize (av->top);
  	char *min_address = max_address - av->system_mem;
	if (!chunk_is_mmapped (p))
	{
		//chunk p是通过brk分配得到，而不是MMAP分配得到
		/* Has legal address ... */
		if (p != av->top)
		{
			//如果p不是top chunk
			if (contiguous (av))
			{
				//表示chunk所在的arena是main_arena，地址连续，则其地址应大于最小地址，小于top chunk地址
				assert (((char *) p) >= min_address);
				assert (((char *) p + sz) <= ((char *) (av->top)));
			}
		}
		else
		{
			//如果p是top chunk，则其大小要大于MINSIZE，且其prev_inuse字段置1
			/* top size is always at least MINSIZE */
			assert ((unsigned long) (sz) >= MINSIZE);
			/* top predecessor always marked inuse */
			assert (prev_inuse (p));
		}
	}
	else if (!DUMPED_MAIN_ARENA_CHUNK (p))
	{
		//如果该chunk是通过MMAP分配得到的，且其不在一个固定范围内（方便调试的地址？）
		/* address is outside main heap  */
		if (contiguous (av) && av->top != initial_top (av))
		{
			//如果当前arena top chunk字段与初始top chunk不同（即MMAP了一块新内存）
			assert (((char *) p) < min_address || ((char *) p) >= max_address);
		}
		/* chunk is page-aligned */
		assert (((prev_size (p) + sz) & (GLRO (dl_pagesize) - 1)) == 0);		//页对齐
		/* mem is aligned */
		assert (aligned_OK (chunk2mem (p)));
		}
}
</pre>

## 2. 放入fastbin链表##
<pre class="prettyprint lang-javascript"> 
/* If eligible, place chunk on a fastbin so it can be found and used quickly in malloc. */   //如果符合下列条件则将chunk放在fastbin上，以便加快释放与分配
if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())\
	#if TRIM_FASTBINS 	/* If TRIM_FASTBINS set, don't place chunks bordering top into fastbins */
  	&& (chunk_at_offset(p, size) != av->top)
	#endif
    ) 
</pre>
如果符合以下2个条件，则考虑将该chunk加入fastbin链表。  
条件1：释放chunk的size小于等于get\_max\_fast()宏定义值（64bit:0x80,32bit:0x40)  
条件2：如果定义了 TRIM\_FASTBINS 宏，则chunk p不能紧挨着top chunk（否则，将其合并到top chunk中）
<pre class="prettyprint lang-javascript"> 
{
	if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ, 0)
		|| __builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0))
	{
		bool fail = true;
		/* We might not have a lock at this point and concurrent modifications of system_mem might result in a false positive.  Redo the test after getting the lock.  */
		if (!have_lock)
		{
			__libc_lock_lock (av->mutex);
			fail = (chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
			__libc_lock_unlock (av->mutex);
		}
		if (fail)
			malloc_printerr ("free(): invalid next size (fast)");	//next chunk size必须大于2*SIZE_SZ且小于av->system_mem
		//以上操作为检查next chunk的size字段是否符合要求（大于2*SIZE\_SZ，且小于av->system\_mem)。
	}
	free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);		//如果定义了填充字节，则在free时将其填充
	atomic_store_relaxed (&av->have_fastchunks, true);		//将arena的have_fastchunks字段值1，表示当前fastbin链表中有空闲chunk

	unsigned int idx = fastbin_index(size);
	fb = &fastbin (av, idx);
	
	/* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
	mchunkptr old = *fb, old2;
	if (SINGLE_THREAD_P)
	{
		/* Check that the top of the bin is not the record we are going to add (i.e., double free).  */
		if (__builtin_expect (old == p, 0))
			malloc_printerr ("double free or corruption (fasttop)");
		p->fd = old;
		*fb = p;
	}
</pre>
这里有一个重要检查：当前要加入的chunk是否为fastbin中已经记录的top chunk。  
**因此，针对这条检查规则，产生了一个重要的绕过方法（即在double free时，针对需要double free的chunk A，可以采用free(A),free(B),free(A)的方式进行绕过）。**  
<pre class="prettyprint lang-javascript"> 
	else
		do
		{
			/* Check that the top of the bin is not the record we are going to add (i.e., double free).  */
			if (__builtin_expect (old == p, 0))
				malloc_printerr ("double free or corruption (fasttop)");
			p->fd = old2 = old;
		} while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);
		/* Check that size of fastbin chunk at the top is the same as size of the chunk that we are adding.  
			We can dereference OLD only if we have the lock, otherwise it might have already been allocated again.  */
		if (have_lock && old != NULL && __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
			malloc_printerr ("invalid fastbin entry (free)");
}
</pre>
多线程的加入操作，然后检查顶部fastbin chunk的大小是否与我们添加的chunk的大小相同。

## 3. 放入unsortedbin链表 ##
### 3.1 待释放chunk不是通过mmap分配的 ###
<pre class="prettyprint lang-javascript"> 
/*Consolidate other non-mmapped chunks as they arrive.*/
else if (!chunk_is_mmapped(p)) 
{
	/* If we're single-threaded, don't lock the arena.  */
	if (SINGLE_THREAD_P)
  		have_lock = true;
	if (!have_lock)
  		__libc_lock_lock (av->mutex);
	nextchunk = chunk_at_offset(p, size);
	/* Lightweight tests: check whether the block is already the top block.  */
	if (__glibc_unlikely (p == av->top))
		malloc_printerr ("double free or corruption (top)");
	/* Or whether the next chunk is beyond the boundaries of the arena.  */
	if (__builtin_expect (contiguous (av) && (char *) nextchunk 
		>= ((char *) av->top + chunksize(av->top)), 0))
		malloc_printerr ("double free or corruption (out)");
	/* Or whether the block is actually not marked used.  */
	if (__glibc_unlikely (!prev_inuse(nextchunk)))
		malloc_printerr ("double free or corruption (!prev)");
	nextsize = chunksize(nextchunk);
	if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0) || __builtin_expect (nextsize >= av->system_mem, 0))
		malloc_printerr ("free(): invalid next size (normal)");
</pre>
再次进行一些轻量级的测试，主要测试内容有以下3个方面：  
test 1：当前释放的chunk p是否为top chunk  
test 2：next chunk是否超出了aren中规定的chunk范围  
test 3：再次检查当前chunk是否为inuse  
test 4：next chunk的size字段必须大于 2*SIZE\_SZ 且小于 av->system\_mem（av->sytem\_mem就是heap段的大小）
<pre class="prettyprint lang-javascript">
	free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);		//进行字段填充

	/* consolidate backward */		//如果pre chunk处于free状态，则前向合并（unlink操作）。
	if (!prev_inuse(p)) 
	{
		prevsize = prev_size (p);
		size += prevsize;
		p = chunk_at_offset(p, -((long) prevsize));
		unlink(av, p, bck, fwd);
	}
	if (nextchunk != av->top)
	{
		/* get and clear inuse bit */
		nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
		/* consolidate forward */
		if (!nextinuse)
		{
			unlink(av, nextchunk, bck, fwd);
			size += nextsize;
		}
		else
			clear_inuse_bit_at_offset(nextchunk, 0);
		/* 如果next chunk不为top chunk且处于free状态，则后向合并。否则修改next chunk的preinuse字段为0，
		标志当前chunk已被释放。*/
		
		/*
		Place the chunk in unsorted chunk list. Chunks are not placed into regular bins until after they 
		have been given one chance to be used in malloc.
		*/
		
		bck = unsorted_chunks(av);
		fwd = bck->fd;
		if (__glibc_unlikely (fwd->bk != bck))
			malloc_printerr ("free(): corrupted unsorted chunks");
		p->fd = fwd;
		p->bk = bck;
		if (!in_smallbin_range(size))
		{
			p->fd_nextsize = NULL;
			p->bk_nextsize = NULL;
			//largebin chunk有相应的fd_nextsize和bk_nextsize字段，需要将其清0
		}
		bck->fd = p;
		fwd->bk = p;
		set_head(p, size | PREV_INUSE);		//设置chunk p的PREV_INUSE字段为1
		set_foot(p, size);		//设置next chunk的presize字段为当前chunk p的size
		check_free_chunk(av, p);
		/*
		然后将chunk p加入unsortedbin链表中，并修改当前unsortedbin链表指针及chunk p相应链表指针，
		设置chunk p相应字段值，然后调用check_free_chunk()对chunk p进行检查。
		*/
	}
	/*If the chunk borders the current high end of memory,consolidate into top*/
	else
	{
		//如果next chunk是top chunk，就将chunk直接并入即可
		size += nextsize;
		set_head(p, size | PREV_INUSE);
		av->top = p;
		check_chunk(av, p);
	}
</pre>
**注：这里需要注意的一个点是：unsortedbin是先入先出的，即最先放入的chunk会被最先遍历到**  
<pre class="prettyprint lang-javascript">
	/*
	If freeing a large space, consolidate possibly-surrounding
	chunks. Then, if the total unused topmost memory exceeds trim
	threshold, ask malloc_trim to reduce top.
	
	Unless max_fast is 0, we don't know if there are fastbins
	bordering top, so we cannot tell for sure whether threshold
	has been reached unless fastbins are consolidated.  But we
	don't want to consolidate on each free.  As a compromise,
	consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
	is reached.
	*/
	
	if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD)
	{
		if (atomic_load_relaxed (&av->have_fastchunks))
			malloc_consolidate(av);
		if (av == &main_arena)
		{
			#ifndef MORECORE_CANNOT_TRIM
			if ((unsigned long)(chunksize(av->top)) >= (unsigned long)(mp_.trim_threshold))
				systrim(mp_.top_pad, av);
			#endif
		}
		else
		{
			/* Always try heap_trim(), even if the top chunk is not large, 
			because the corresponding heap might go away.  */
			heap_info *heap = heap_for_ptr(top(av));
			assert(heap->ar_ptr == av);
			heap_trim(heap, mp_.top_pad);
		}
	}
	if (!have_lock)
		__libc_lock_unlock (av->mutex);
}
</pre>

如果释放了一个很大的chunk，导致当前某个空闲chunk的size大于一个阈值（FASTBIN\_CONSOLIDATION\_THRESHOLD=0x10000），则对当前fastbin中的chunk进行合并（调用malloc\_consolidate()函数），并对top chunk进行剪枝。  
**注：一个重要的只是点，即释放一个大于0x10000的chunk时，能够导致fastbin链表中的chunk进行合并**
### 3.2 如果待释放chunk是通过mmap分配的 ###
很简单，调用munmap\_chunk即可。
<pre class="prettyprint lang-javascript">
/*If the chunk was allocated via mmap, release via munmap().*/

	else {
    	munmap_chunk (p);
	}
其中munmap\_chunk的定义如下所示：

	static void munmap_chunk (mchunkptr p)
	{
		INTERNAL_SIZE_T size = chunksize (p);
		assert (chunk_is_mmapped (p));
		
		/* Do nothing if the chunk is a faked mmapped chunk in the dumped
	   	main arena.  We never free this memory.  */
	  	if (DUMPED_MAIN_ARENA_CHUNK (p))
	    	return;
到底什么是DUMPED\_MAIN\_ARENA\_CHUNK?

		uintptr_t block = (uintptr_t) p - prev_size (p);
	  	size_t total_size = prev_size (p) + size;

	  	/* Unfortunately we have to do the compilers job by hand here.  Normally
	    we would test BLOCK and TOTAL-SIZE separately for compliance with the
	    page size.  But gcc does not recognize the optimization possibility
	    (in the moment at least) so we combine the two values into one before
	    the bit test.  */
	  	if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
	    	malloc_printerr ("munmap_chunk(): invalid pointer");
		//检查是否页对齐
		atomic_decrement (&mp_.n_mmaps);
	  	atomic_add (&mp_.mmapped_mem, -total_size);
当前mmap出来的区域减1，mmap出来的总大小减去total\_size

		/* If munmap failed the process virtual memory address space is in a
	    bad shape.  Just leave the block hanging around, the process will
	    terminate shortly anyway since not much can be done.  */
	  	__munmap ((char *) block, total_size);
	}	
</pre>