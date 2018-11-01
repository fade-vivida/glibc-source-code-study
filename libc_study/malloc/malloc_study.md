# Ptmalloc 源码学习 #
**注：在不经过特殊说明的情况下，以下研究结果均针对64-bit操作系统。**
# malloc.c #
# unlink宏 #
## 1.函数功能 ##
unlink()为双向链表的拆链函数，在ptmalloc中以宏的形式进行了定义，其具体定义如下所示：  
![unlink](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/unlink.PNG)  
## 2.拆链前的检查操作 ##
首先对要进行拆链的堆块P进行一系列的安全检查。
### 1）check 1 ###
检查表达式：

    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))  \
      malloc_printerr ("corrupted size vs. prev_size");			  \
check当前拆链的chunk_p的size字段，是否和下一个chunk的presize字段相等。其中\_\_builtin\_expect是GNU C特有的编译器的优化用法，作用为假设其第一个参数（或者是表达式的值）很大可能上与第二个参数相等，目的是为了加快流水线的执行速度。  

对应错误信息：  
![error1](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/error1.PNG)
### 2）check 2 ###
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		  \
      malloc_printerr ("corrupted double-linked list");			  \
经典的双向链表拆链前的验证操作，查看  
FD->bk == chunk\_P?  
BK->fd == chunk\_P?  
其中FD = chunk\_P->fd，BK = chunk\_P->bk  
对应错误信息：  
![error2](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/error2.PNG)
### 3）check 3 ###
检查当前chunk的size是否在smallbin的范围内，在64-bit下smallbin的大小最大为1008byte。如果chunk\_size>=1024，则该chunk属于largebin，判断其fd\_nextsize字段是否为NULL（其中fd\_nextsize和bk\_nextsize字段是largebin特有的）。

    if (!in_smallbin_range (chunksize_nomask (P))			 \
    && __builtin_expect (P->fd_nextsize != NULL, 0)) {		  \
    	if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	  \
    		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))\
    	  malloc_printerr ("corrupted double-linked list (not small)");   \
若fd\_nextsize字段不为NULL，则判断largebin的双向链表是否完整（判断方法与smallbin相同，即chunk\_P->fd\_nextsize->bk\_nextsize == chunk\_P? &&  
chunk\_P->bk\_nextsize->fd\_nextsize == chunk\_P?)  
对应错误信息：  
![error3](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/error3.PNG)
## 3.unlink操作 ##
完成这一系列check后，则进行双向链表的拆链操作。  
### 1.chunk大小为smallbin ###
经典的拆链操作（其中FD = chunk\_P->fd，BK = chunk\_P->bk）：  
FD->bk = BK  
BK->fd = FD  
### 2.chunk大小为largebin ###
    if (FD->fd_nextsize == NULL) {				  \
    	if (P->fd_nextsize == P)				  \
      		FD->fd_nextsize = FD->bk_nextsize = FD;		  \
    	else {							  \
    		FD->fd_nextsize = P->fd_nextsize;			  \
    		FD->bk_nextsize = P->bk_nextsize;			  \
    		P->fd_nextsize->bk_nextsize = FD;			  \
    		P->bk_nextsize->fd_nextsize = FD;			  \
      	}							  \
    } 
	else {							  \
    	P->fd_nextsize->bk_nextsize = P->bk_nextsize;		  \
    	P->bk_nextsize->fd_nextsize = P->fd_nextsize;		  \
	}								  \

动态调试结果：  
![largebin](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/largebin.PNG)  
由于fd\_nextsize和bk\_nextsize是链接同一个largebin中不同size的指针，因此首先通过判断FD->fd\_nextsize==NULL？可以得知在当前链表中是否存在相同大小的chunk，然后对两个链表都进行拆链。  
**疑问点：如果largebin链表中存在相同大小的chunk，则每次拆下的也是第二个chunk，并不会影响fd\_nextsize，bk\_nextsize组成的链表啊**

# malloc_consolidate函数 #
## 1.函数功能 ##
    malloc_consolidate is a specialized version of free() that tears
	down chunks held in fastbins.  Free itself cannot be used for this
    purpose since, among other things, it might place chunks back onto
    fastbins.  So, instead, we need to use a minor variant of the same
    code.
Free()函数的特殊变种，可以实现对于fastbin链表中的chunk的回收处理，将其加入到unsortedbin中。Free()函数本身无法完成这项工作。因为使用free()函数释放一个原本属于fastbin大小的chunk时，只会将该chunk加入到fastbin链表中。
## 2.合并fastbin chunk，将其加入unsortedbin ##

    static void malloc_consolidate(mstate av)
    {
      	mfastbinptr*fb; /* current fastbin being consolidated */
      	mfastbinptr*maxfb;  /* last fastbin (for loop control) */
      	mchunkptr   p;  /* current chunk being consolidated */
      	mchunkptr   nextp;  /* next chunk to consolidate */
      	mchunkptr   unsorted_bin;   /* bin header */
      	mchunkptr   first_unsorted; /* chunk to link to */
    
      	/* These have same use as in free() */
      	mchunkptr   nextchunk;
      	INTERNAL_SIZE_T size;
      	INTERNAL_SIZE_T nextsize;
      	INTERNAL_SIZE_T prevsize;
      	int nextinuse;
      	mchunkptr   bck;
      	mchunkptr   fwd;
    
      	atomic_store_relaxed (&av->have_fastchunks, false);    
      	unsorted_bin = unsorted_chunks(av);
设置当前arena的fastchunk字段为null，标志当前arena无可用的fastbin。然后调用unsorted\_chunk宏，得到unsortbin起始地址。

      	/*
      	Remove each chunk from fast bin and consolidate it, placing it
      	then in unsorted bin. Among other reasons for doing this,
      	placing in unsorted bin avoids needing to calculate actual bins
      	until malloc is sure that chunks aren't immediately going to be
      	reused anyway.
      	*/
     	maxfb = &fastbin (av, NFASTBINS - 1);
		//NFASTBINS = 10
		//maxfb保存了最后一个fastbin数组元素的地址（即&fastbinsY[9]）
      	fb = &fastbin (av, 0);
		//fb保存了fastbin数组第一个元素的地址（即&fastbinsY[0]）
      	do {
    		p = atomic_exchange_acq (fb, NULL);
    		if (p != 0) {
      			do {
					unsigned int idx = fastbin_index (chunksize (p));
	    	  		if ((&fastbin (av, idx)) != fb)
	    				malloc_printerr ("malloc_consolidate(): invalid chunk size");
对从fastbin链表中取下的chunk进行size字段检验，看其是否属于当前fastbin链表。  
错误信息：  
![malloc_consolidata()error](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/malloc_consolidata.PNG)    				

    				check_inuse_chunk(av, p);
    				nextp = p->fd;
    				/* Slightly streamlined version of consolidation code in free() */
    				之后的操作为对fastbin chunk的合并操作，与free()函数不同的是，在free()中fastbin chunk不合并。
					size = chunksize (p);
    				nextchunk = chunk_at_offset(p, size);
    				nextsize = chunksize(nextchunk);
    				
			    	if (!prev_inuse(p)) {
			    	  	prevsize = prev_size (p);
			    	  	size += prevsize;
						//合并后的大小
			    	  	p = chunk_at_offset(p, -((long) prevsize));
						//得到前一个chunk的地址
			    	  	unlink(av, p, bck, fwd);
			    	}
如果当前的chunk的前一个chunk为free状态（pre_inuse(p)==0)，则对前一个chunk进行unlink操作。

    				if (nextchunk != av->top) {
    	  				nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
						//标志下一个chunk是否处于free状态		    			
						if (!nextinuse) {
    						size += nextsize;
    						unlink(av, nextchunk, bck, fwd);
    	  				}
如果下一个chunk（即nextchunk）也是free状态，将该chunk也从其所属的双向链表中拆下，进行合并。
 
						else
    						clear_inuse_bit_at_offset(nextchunk, 0);
							//由于free函数中，fastbin不合并的原因，因此标志fastbin chunk是否使用的pre_inuse一直为1，在这需对其进行清0，以表示新合并的chunk p处于free状态。
	    				first_unsorted = unsorted_bin->fd;
				    	unsorted_bin->fd = p;
				    	first_unsorted->bk = p;
    					if (!in_smallbin_range (size)) {
    						p->fd_nextsize = NULL;
    						p->bk_nextsize = NULL;
    	  				}
如果合并后的chunk size不在smallbin的范围内，则将新chunk的fd\_nextsize和bk\_nextsize字段清0。

    					set_head(p, size | PREV_INUSE);
						//设置chunk p的size字段，并标志chunk p的前一个chunk为使用状态
			    	  	p->bk = unsorted_bin;
			    	  	p->fd = first_unsorted;
以下4条语句的功能就为把新合并的chunk p加入到unsortedbin中。  
unsorted\_bin->fd = p  
p->fd = first\_unsorted  
first\_unsorted->bk = p  
p->bk = unsorted\_bin

			    	  	set_foot(p, size);
然后设置下一个chunk的presize字段为当前chunk p的size。

    				}
    				else {
		    	  		size += nextsize;
		    	  		set_head(p, size | PREV_INUSE);
		    	  		av->top = p;
    				}
如果新合并的chunk p的下一个chunk为top\_chunk，则将其整个合并到top\_chunk中。

    			} while ( (p = nextp) != 0);
循环对当前fastbin链表中的chunk进行同样的操作。    

    		}
      } while (fb++ != maxfb);
	}
循环对所有的fastbin链表进行同样的操作。



# \_int\_malloc(mstate av,size_t bytes)函数 #
## 1.函数功能 ##
用户申请size到实际分配chunk的管理。  
## 2.Fastbin分配机制 ##
### 1. 调用checked\_request2size(bytes,nb)得到真正的chunk大小 ###
其中req为用户请求申请的chunk大小（也即用户可输入的数据大小），sz为进行规范化后chunk的实际大小（即malloc\_chunk中的size字段），其中REQUEST\_OUT\_OF\_RANGE宏定义为

    #define REQUEST_OUT_OF_RANGE(req) ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))
	//计算得到可申请的最大堆块大小为0xFFFFFFC0（即3.9G）     
![request2size](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/checked_request2size.PNG)  
可以看到，在check_request2size()中，又继续调用request2size()来得到实际chunk的size。  
request2size()的实现代码如下所示：  

    #define request2size(req) \
      (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ? \
       MINSIZE :  \
       ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
其中MINSIZE定义如下：

    #define MINSIZE  \
      (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
	  //其中 MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1，MALLOC_ALIGNMENT定义如下，反推可以得到MALLOC_ALIGN_MASK=0xF
	
	#define MALLOC_ALIGNMENT = (2*SIZE_T < __alignof__(long double) ? __alignof__(long double):(2*SIZE_T)
	//__alignof__为一个宏定义，即得到对应数据类型的对齐值，在64-bit下__alignof__(long double)=16，也即MALLOC_ALIGNMENT=0x10
  
MIN\_CHUNK\_SIZE定义为：

    #define MIN_CHUNK_SIZE(offsetof(struct malloc_chunk, fd_nextsize))
	//其中offsetof为一个宏定义，功能为计算得到fd_nextsize在malloc\_chunk结构体中的偏移（即宏定义返回值为0x20，64-bit）。
	//因此我们从这可以看出对于ptmalloc机制而言，最小分配的chunk大小为0x20（32-bit下最小chunk大小为0x10）。 
反推回去得知，MINSIZE = (0x20 + 0xF) & 0xFFFFFFF0 = 0x20 （64-bits），32位下MINSZIE按照同样的计算方法为0x10。  
至此，我们得到了request2size(req)函数的计算方法，代码如下所示：

    if(req + 8 + 0xf < 0x20)
		return 0x20;
	else
		return (req + 0x8 + 0xf) & 0xfffffff0		//增加8byte字节后，对于16byte进行取整
**注：从这我们可以得到在ptmalloc机制中堆块重叠使用的根本原理所在，即如果当前堆块不为空，下一个堆块的presize字段可被当前堆块作为数据区使用。**
### 2.计算得到fastbin数组索引，进行拆链操作 ###
首先查看当前arena是否可用（多线程下除main\_arnea外，还存在其他arnea，具体数目为处理器内核数*2+1)，其中\_\_glibc\_unlikely宏实际调用的还是\_\_builtin\_expect()宏，功能为进行编译器优化，将最可能的执行结构放在跳转指令后，加大分支预测的成功率。这里\_\_glibc\_unlikely就为之后表达式不成功的概率较大。

    /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
      if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
    	alloc_perturb (p, bytes);
      return p;
    }
然后判断当前申请chunk size(nb)是否满足fastbin大小，其中get\_max\_fast()函数在32-bit下返回值为0x40，在64-bit为下返回值为0x80。  
**注：该值有global\_max\_fast变量控制**

    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ())) //get max_size of fastbin:64(0x40,32-bit),128byte(0x80,64-bit)
	{
		idx = fastbin_index (nb);
		mfastbinptr *fb = &fastbin (av, idx);
      	mchunkptr pp;
      	victim = *fb;
然后使用fastbin\_index计算当前chunk size所属的fastbin数组的索引，计算方法如下：
    
	#define fastbin_index(sz) ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
由于计算结果采用了不精确的计算方法，这其实就是为什么可以利用fastbin attack攻击的原理所在。  
然后调用fastbin(av,idx)宏，得到当前chunk size所属fastbin数组元素的地址（fb），victim就为fastbin[idx]链表中第一个chunk节点。其中fastbin宏定义如下：

    #define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
如果victime==NULL，表明当前fastbin链表为空，则无法使用fastbin进行分配，需要采用后续解决方法。如果victim!=NULL，首先判断当前程序是否为单线程。若是，取出fastbin链表中的第一个元素，也即最后加入的元素（因此，fastbi链表采用先进后出FILO原则)

	if (victim != NULL)
	{
		if (SINGLE_THREAD_P)
			*fb = victim->fd;
			//FILO
	  	else
			REMOVE_FB (fb, pp, victim);
				
如过当前程序为多线程，则使用REMOVE_FB宏进行fastbin链表的拆链操作。具体操作如下所示： 

    #define REMOVE_FB(fb, victim, pp)			
	do							
    {
		victim = pp;					
		if (victim == NULL)				
    		break;						
    }							
    while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))!= victim);					
其中catomic\_compare\_and\_exchange\_val\_acq(mem,new\_val,old\_val)为一个原子比较交换操作，具体含义如下：
    
	if(*mem == old_val){
		*mem = new_val;
	}
	//返回值为new_val
**疑惑点：多线程下的REMOVE\_FB操作是要讲所有的fastbin都从链表中拆除？**


	if (__glibc_likely (victim != NULL))
    {
		size_t victim_idx = fastbin_index (chunksize (victim));
		//#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))
		if (__builtin_expect (victim_idx != idx, 0))
    		malloc_printerr ("malloc(): memory corruption (fast)");
		check_remalloced_chunk (av, victim, nb);
然后调用chunksize()得到当前从fastbin链表中取下的victim chunk的大小，并计算得到其所属的fastbin数组的索引值（victim_idx)，并与当前该chunk所在的fastbin数组的索引下标作比较，看是否相等。  

**注：这里引入了很重要的一点，即为什么我们在采用fastbin attack时，需要将fd指向一个符合当前fastbinY[idx]数组大小的位置（可以错位，且比较时是将size转化为一个unsigned int（32-bit））**


### 3.对从fastbin数组链表中获取到的victim，进行更为严格的检查 ###
在对victim的size字段进行检查后，又调用了check\_remalloced\_chunk()对victim进行了更为细致的检查。check\_remalloced_chunk()函数的定义如下所示：

    do_check_remalloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
    {
		INTERNAL_SIZE_T sz = chunksize_nomask (p) & ~(PREV_INUSE | NON_MAIN_ARENA);
		//去除PREV_INUSE和NON_MAIN_ARENA字段
		if (!chunk_is_mmapped (p))
    	{
			//如果该chunk不是mmap分配，而是调用brk分配的。
			assert (av == arena_for_chunk (p));
			//调用arena_for_chunk宏，根据当前chunk的地址及size字段得到其所属的arnea
			//arena_for_chunk(p)，如果p->size & NON_MAIN_ARENA == 0,则返回&main_arean
			//否则返回(p&(~(0x400*0x400-1)))->ar_ptr字段
      		if (chunk_main_arena (p))
    			assert (av == &main_arena);
      		else
    			assert (av != &main_arena);
    	}
    	do_check_inuse_chunk (av, p);
    	/* Legal size ... */
      	assert ((sz & MALLOC_ALIGN_MASK) == 0);
      	assert ((unsigned long) (sz) >= MINSIZE);
      	/* ... and alignment */
      	assert (aligned_OK (chunk2mem (p)));
      	/* chunk is less than MINSIZE more than request */
      	assert ((long) (sz) - (long) (s) >= 0);
      	assert ((long) (sz) - (long) (s + MINSIZE) < 0);
    } 
函数功能大体分析如下：  
1. 检查该chunk所在的arena是否与之前传入函数的av相等。**（注意点：使用fastbin attack攻击时，在构造伪chunk时，其size字段的IS_MAPPED(0x2)必须为1，这样才能绕过对于arean的检查）**  
2. 调用do\_check\_inuse\_chunk(av,p)，在do\_check\_inuse\_chunk()函数中，还会调用do\_check\_chunk()函数首先对victim块进行相关检查，然后检查下一个chunk的PRE\_INUSE是否置1（fastbin不合并，因此与其相邻的下一个chunk的PRE\_INUSE字段永远为1）；并检查当前chunk的相邻chunk是否处于free状态，如果是，调用do\_check\_free\_chunk对其进行检查。**（注：当fastbin的IS\_MAPPED被置位时，不进行2上述检查，直接返回）**  
3. 对申请chunk的大小进行检查，对victim的地址进行对齐检查。

**注：综上所述，伪造fastbin时，其size字段的IS\_MAPPED最好置1，这样可以绕过很多检查**  
对取下的victim chunk进行检查后，是一些关于TCACHE机制的使用方法，具体会在之后的文章中进行分析。

	#if USE_TCACHE
	/* While we're here, if we see other chunks of the same size, stash them in the tcache.  */
	size_t tc_idx = csize2tidx (nb);
	if (tcache && tc_idx < mp_.tcache_bins)
	{
		mchunkptr tc_victim;
		/* While bin not empty and tcache not full, copy chunks.  */
  		while (tcache->counts[tc_idx] < mp_.tcache_count
	 		&& (tc_victim = *fb) != NULL)
		{
  			if (SINGLE_THREAD_P)
				*fb = tc_victim->fd;
  			else
			{
	  			REMOVE_FB (fb, pp, tc_victim);
	  			if (__glibc_unlikely (tc_victim == NULL))
					break;
			}
  			tcache_put (tc_victim, tc_idx);
		}
	}
	#endif
TCACHE机制后，如果设置了perturb\_byte，则调用alloc\_pertrub对chunk的数据区进行填充。

	void *p = chunk2mem (victim);
	alloc_perturb (p, bytes);
	return p;
	}}}
alloc\_perturb()函数定义如下：

    static void alloc_perturb (char *p, size_t n)
    {
		if (__glibc_unlikely (perturb_byte))
    	memset (p, perturb_byte ^ 0xff, n);
    }
至此，在\_int\_malloc()函数中fastbin部分的分析结束。

## 3.SmallBin分配机制 ##

	#define NSMALLBINS 64
    #define SMALLBIN_WIDTHMALLOC_ALIGNMENT
    #define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
    #define MIN_LARGE_SIZE((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
    #define in_smallbin_range(sz) ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)


	if (in_smallbin_range (nb))
    {	
		idx = smallbin_index (nb);
      	bin = bin_at (av, idx);
    	if ((victim = last (bin)) != bin)
    	{
      		bck = victim->bk;
    	  	if (__glibc_unlikely (bck->fd != victim))
    			malloc_printerr ("malloc(): smallbin double linked list corrupted");
      		set_inuse_bit_at_offset (victim, nb);
      		bin->bk = bck;
      		bck->fd = bin;
    		if (av != &main_arena)
    			set_non_main_arena (victim);
      		check_malloced_chunk (av, victim, nb);
### 1.计算Smallbin数组索引 ###
首先调用in\_smallbin\_range宏检查申请size是否在smallbin范围内。  
**注：重要结论！！！**    
**64-bit: < 1024 byte，即最大的smallbin为1008（0x3f0）**  
**32-bit: < 512  byte，即最大的smallbin为504（0x1f8）**  

	#define NBINS             128
	#define NSMALLBINS         64
	#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
	#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
	#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
    #define in_smallbin_range(sz)  \
      ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
然后计算得到所属Smallbin的索引号，计算方法如下所示（即在64-bit下，idx = size/16 + SMALLBIN\_CORRECTION；32-bit下，idx = size/8 + SMALLBIN_CORRECTION）：

    #define smallbin_index(sz) ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3)) + SMALLBIN_CORRECTION)
然后根据索引号idx，计算得到该bin数组的地址。

    #define bin_at(m, i) \
      (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))	- offsetof (struct malloc_chunk, fd))
      //之所以要减去0x10，是因为smallbin是以双向链表的形式存在，fd指针在malloc_chunk结构中的偏移就是0x10
	  //因此如果把bin数组也当做一个malloc_chunk结构的话，则该chunk的地址就为fd指针地址减去0x10。
### 2.检查链表完整性，并进行拆链操作 ###
然后调用last(bin)检查当前bin链表中是否存在空闲的chunk。如果存在，取下最先放入该链表的chunk（FIFO，先入先出规则），并对链表的完整新进行检验（victim->bk->fd==victim?）。如果链表被破坏，打印出错误信息。  
![smallbin double linked list corrupted](https://raw.githubusercontent.com/fade-vivida/libc-linux-source-code-study/master/libc_study/picture/small_double_linklist_corrupt.PNG)  
然后调用set\_inuse\_bit\_at\_offset()函数，标志当前chunk已被使用。

    #define set_inuse_bit_at_offset(p, s) (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)
然后进行双向链表的拆链操作  
bin->bk=bck  
bck->fd=bin  
如果当前arena不是main\_arena，则设置victim的NON\_MAIN_ARENA位。

	bin->bk = bck;
    bck->fd = bin;
    if (av != &main_arena)
    	set_non_main_arena (victim);
### 3.对取下的chunk进行检查 ###
然后调用check\_malloced\_chunk()对victim进行一系列检查（check\_malloced\_chunk()会再次调用check\_remalloced\_chunk()，然后为TCACHE机制。

	check_malloced_chunk (av, victim, nb);
	#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;
	
	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;
	
		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
	#endif 

之后调用alloc\_perturb()对分配chunk内容进行填充。
  
    void *p = chunk2mem (victim);
	alloc_perturb (p, bytes);
至此SmallBin分配机制结束。
## 4.LargeBin分配机制 ##
对于不满足fastbin和smallbin需求的chunk size，则会调用largebin分配机制。具体实现代码如下所示：  
**注：这里其实并没有进行真正的分配，只是计算了当前申请大小所在的largebin数组下标。真正的分配的第5部分，对unsortedbin进行整理后。**

 	else
    {
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }
其中largebin\_index()的计算方法如下：

    #define largebin_index(sz) (SIZE_SZ == 8 ? largebin_index_64 (sz) : MALLOC_ALIGNMENT == 16 ? 	largebin_index_32_big (sz) : largebin_index_32 (sz))

	#define largebin_index_32(sz)                                                \
	  	(((((unsigned long) (sz)) >> 6) <= 38) ?  56 + (((unsigned long) (sz)) >> 6) :\
	   	((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
	   	((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
	   	((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
	   	((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
	   	126)

	#define largebin_index_32_big(sz)                                            \
	  	(((((unsigned long) (sz)) >> 6) <= 45) ?  49 + (((unsigned long) (sz)) >> 6) :\
	   	((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
	   	((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
	   	((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
	   	((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
	   	126)

	#define largebin_index_64(sz)                                                \
  		(((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   		((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   		((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   		((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   		((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   		126)
**注：重要结论！！！**  
**32bit下，largebin的下限范围为：512 byte**  
**64bit下，largebin的下限范围为：1024 byte**  
**64bit下，largebin又分为33个区间大小都为64byte，15个区间大小为512byte,9个区间大小为4096byte等等的小区间**  
</br>
</br>
**注：CTF中的一个重要考点！！！**  
**如果分配的size最后需要调用largebin来满足，且当前fastbin链表中存在fastbin chunk（即arena的have\_fastchunks字段为1，则会调用malloc\_consolidata()函数对fastbin chunk进行合并，并加入到unsorted_bin中。**

## 5.UnsortedBin整理分配机制 ##
### 1）. malloc源码关于unsortedbin分配的说明 ###
	 Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
	for (;; )
    {
      	int iters = 0;
大概意思为：unsortedbin分配处理事例是唯一能够将chunk从unsortedbin中放入其他bin的方法，并且使用unsortedbin分配时不是精确匹配，而是大于等于当前需求大小nb的最小值。同时外层的循环的必要性是为了在最后对fastbin进行合并后，重新寻找适合的chunk。（之多循环一次）。

### 2）. 使用last\_remainder进行分配 ###
    while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
    {
		bck = victim->bk;
      	if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
      		|| __builtin_expect (chunksize_nomask (victim)
    				   > av->system_mem, 0))
    		malloc_printerr ("malloc(): memory corruption");
首先获取当前unsorted\_bin中最先加入的chunk，对其大小进行检查，看是否符合规范。

      	size = chunksize (victim);
    	/*
     	If a small request, try to use last remainder if it is the
     	only chunk in unsorted bin.  This helps promote locality for
     	runs of consecutive small requests. This is the only
     	exception to best-fit, and applies only when there is
     	no exact fit for a small chunk.
       	*/
如果当前申请chunk大小在smallbin范围内（即32bit小于512byte，64bit小于1024byte），且unsorted\_bin中只有一个chunk就为last\_remainder，同时满足该chunk的大小大于申请大小（nb）加上最小chunk的大小（32bit为0x10,64bit为0x20）。

    	if (in_smallbin_range (nb) &&
      		bck == unsorted_chunks (av) &&
      		victim == av->last_remainder &&
      		(unsigned long) (size) > (unsigned long) (nb + MINSIZE))
    	{
      		/* split and reattach remainder */
      		remainder_size = size - nb;
      		remainder = chunk_at_offset (victim, nb);
      		unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
      		av->last_remainder = remainder;
      		remainder->bk = remainder->fd = unsorted_chunks (av);
然后将切分后剩余大小的chunk放入unsorted\_bin中，并修改对应chunk的fd和bk指针。

      		if (!in_smallbin_range (remainder_size))
    		{
      			remainder->fd_nextsize = NULL;
      			remainder->bk_nextsize = NULL;
    		}
			//如果剩余chunk size大于smallbin范围，对其fd_nextsize和bk_nextsize指针进行清0
    		set_head (victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      		set_head (remainder, remainder_size | PREV_INUSE);
      		set_foot (remainder, remainder_size);
			//对victime chunk和remainder chunk的size字段进行修改
    		check_malloced_chunk (av, victim, nb);
      		void *p = chunk2mem (victim);
      		alloc_perturb (p, bytes);
      		return p;
    	}
然后对分配的victim chunk进行检查后，返回victim。

### 3）. 对unsorted\_bin中的chunk进行整理 ###

     	/* remove from unsorted list */
      	unsorted_chunks (av)->bk = bck;
      	bck->fd = unsorted_chunks (av);
		//把victim从unsorted_bin链表上取下
    	/* Take now instead of binning if exact fit */
    	if (size == nb)
    	{
      		set_inuse_bit_at_offset (victim, size);
      		if (av != &main_arena)
    			set_non_main_arena (victim);
			check_malloced_chunk (av, victim, nb);
			void *p = chunk2mem (victim);
			alloc_perturb (p, bytes);
			return p;
		}
一种特殊情况，如果victim chunk的size大小正好满足申请size（nb），则对victim chunk进行一系列初始化及检查后返回该chunk。  

**注：这里其实也就是对smallbin的分配时机。因为smallbin是严格按照0x10大小递增的，因此如果不存在一个chunk的大小刚好满足申请大小，则肯定也能推出整理后的smallbin中不存在chunk满足分配**

#### 3.1） 对smallbin chunk进行整理 ####
		/* place chunk in bin */
		if (in_smallbin_range (size))
		{
			victim_index = smallbin_index (size);
			bck = bin_at (av, victim_index);
			fwd = bck->fd;
		}
		......
		......
		mark_bin (av, victim_index);
		victim->bk = bck;
		victim->fd = fwd;
		fwd->bk = victim;
		bck->fd = victim;
如果victim size在smallbin的范围内，将victim chunk加入到对应的smallbin中，然后调用mark\_bin()函数。mark\_bin()函数的作用为标记对应的bin不为空，其定义如下所示。  

	#define BINMAPSHIFT      5
	#define BITSPERMAP       (1U << BINMAPSHIFT)
	#define BINMAPSIZE       (NBINS / BITSPERMAP)
	#define idx2block(i)     ((i) >> BINMAPSHIFT)
	#define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))
    
	#define mark_bin(m, i)		((m)->binmap[idx2block (i)] |= idx2bit (i))
	//malloc_state的binmap字段为一个unsigned int型数组，该数组总共包含4个元素，刚好为128bit。
	//用来表示对应的bins指针数组对应链表是否为空

#### 3.2） 对largebin chunk进行整理 ####
如果victim size不在smallbin范围内，则将其加入对应的largebin链表中，并维持同一个largbin链表中chunk大小的有序性（从大到小的顺序）。在这里需要注意的一点是，fd\_nextsize和bk\_nextsize两个指针的含义，这两个指针用来链接在同一个largebin链表中不同size的chunk，这一个链表也是有序的，顺序也是从大到小。  
即假设存在5个chunk，A0,A1,A2,B0,C0（其中A0=A1=A2，C0>B0>A0）  
则由fd、bk组成的链表为：C0 || B0 || A0 || A1 || A2  
有fd\_nextsize、bk\_nextsize组成链表为：C0 || B0 || A0

		else
		{
			victim_index = largebin_index (size);
			bck = bin_at (av, victim_index);
			fwd = bck->fd;
			/* maintain large bins in sorted order */
			if (fwd != bck)
			{
				/* Or with inuse bit to speed comparisons */
				size |= PREV_INUSE;
				/* if smaller than smallest, bypass loop below */
				assert (chunk_main_arena (bck->bk));
				if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))
				{
					fwd = bck;
					bck = bck->bk;
					victim->fd_nextsize = fwd->fd;
					victim->bk_nextsize = fwd->fd->bk_nextsize;
					fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
					//如果victim的size小于链表中最小的chunk，则不用再进行遍历链表，直接将其加到最后即可
				}
				else
				{
					assert (chunk_main_arena (fwd));
					while ((unsigned long) size < chunksize_nomask (fwd))
					{
						fwd = fwd->fd_nextsize;
						assert (chunk_main_arena (fwd));
					}
					//遍历链表，寻找小于等于victim的chunk
					if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
						/* Always insert in the second position.  */
						fwd = fwd->fd;
						//由于当前链表中已经存在该大小的chunk，因此不再将victim chunk链入fd_nextsize和bk_nextsize组成的链表中
					else
					{
						victim->fd_nextsize = fwd;
						victim->bk_nextsize = fwd->bk_nextsize;
						fwd->bk_nextsize = victim;
						victim->bk_nextsize->fd_nextsize = victim;
					}
					bck = fwd->bk;
				}
			}
			else
				victim->fd_nextsize = victim->bk_nextsize = victim;
		}
		mark_bin (av, victim_index);
		victim->bk = bck;
		victim->fd = fwd;
		fwd->bk = victim;
		bck->fd = victim;
		
		#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }
		//如果累计处理的unsorted_bin中chunk大于10000个，则退出，避免浪费过多时间

#### 3.3） 尝试使用当前largebin链表进行分配 ####
**即本次分配主要是在nb大小所对应的largebin链表中尝试进行分配，之所以要有此步骤是因为同一个largebin链表中的chunk size是不同的，这一点与smallbin不相同**  

当把unsorted\_bin中的chunk都移动到smallbin或largebin中后，如果当前请求大小大于1024（不在smallbin范围内），则使用对应的largebin链表进行分配，遍历largebin链表寻找满足分配size（nb）的最小的chunk。由于相同size的chunk不链入fd\_nextsize,bk\_nextsize组成的链表中，因此如果找到的满足条件的chunk，其在fd,bk组成的链表中还有相同大小的chunk，则取位置第二的chunk，避免破坏fd\_nextsize,bk\_nextsize组成的链表。
	
		/*
    	If a large request, scan through the chunks of current bin in
    	sorted order to find smallest that fits.  Use the skip list for this.
       	*/
    
      	if (!in_smallbin_range (nb))
    	{
      		bin = bin_at (av, idx);
    		/* skip scan if empty or largest chunk is too small */
      		if ((victim = first (bin)) != bin && (unsigned long) chunksize_nomask (victim) >= (unsigned long)(nb))
    		{
      			victim = victim->bk_nextsize;
      			while (((unsigned long) (size = chunksize (victim)) < (unsigned long) (nb)))
    				victim = victim->bk_nextsize;
    			/* Avoid removing the first entry for a size so that the skip
     			list does not have to be rerouted.  */
      			if (victim != last (bin) && chunksize_nomask (victim) == chunksize_nomask (victim->fd))
    				victim = victim->fd;
				//避免破坏fd_nextsize,bk_nextsize组成的链表
    			remainder_size = size - nb;
      			unlink (av, victim, bck, fwd);
    			/* Exhaust */
      			if (remainder_size < MINSIZE)
    			{
      				set_inuse_bit_at_offset (victim, size);
      				if (av != &main_arena)
    					set_non_main_arena (victim);
					//如果剩余chunk大小小于最小的chunk size值（32bit：0x10，64bit：0x20），则将该chunk都分配给申请者
    			}
      			/* Split */
如果从largebin链表上取下的chunk size大于（nb+MINSIZE），则将剩余remainder chunk（从victim chunk中切下nb大小的空间）加入到unsorted\_bin链表中，并对victim chunk和remainder chunk进行初始化；否则返回整个chunk。

      			else
    			{
      				remainder = chunk_at_offset (victim, nb);
      				/* We cannot assume the unsorted list is empty and therefore
     				have to perform a complete insert here.  */
      				bck = unsorted_chunks (av);
      				fwd = bck->fd;
    		  		if (__glibc_unlikely (fwd->bk != bck))
    					malloc_printerr ("malloc(): corrupted unsorted chunks");
      				remainder->bk = bck;
      				remainder->fd = fwd;
      				bck->fd = remainder;
      				fwd->bk = remainder;
      				if (!in_smallbin_range (remainder_size))
    				{
      					remainder->fd_nextsize = NULL;
      					remainder->bk_nextsize = NULL;
    				}
      				set_head (victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      				set_head (remainder, remainder_size | PREV_INUSE);
      				set_foot (remainder, remainder_size);
    			}
      			check_malloced_chunk (av, victim, nb);
      			void *p = chunk2mem (victim);
      			alloc_perturb (p, bytes);
      			return p;
    		}
    	}
#### 3.4） 遍历bin数组，寻找满足分配大小的chunk ####
**如果程序运行到了这里，说明nb所对应的bin链表中（包括smallbin和largebin）没有满足分配条件的chunk，因此不得不在更大的bin中寻找满足条件的chunk**  

     	++idx;、
		//这里的idx++表示在nb大小所属的bin链表（包括smallbin和largebin）中没有符合条件的chunk，则需要去更大的bin链表中继续进行寻找。
      	bin = bin_at (av, idx);
      	block = idx2block (idx);
      	map = av->binmap[block];
      	bit = idx2bit (idx);
    	for (;; )
    	{
      		/* Skip rest of block if there are no more set bits in this block.  */

      		if (bit > map || bit == 0)
    		{
				//如果bit>map，表示当前block所表示的bin中，无满足条件的空闲块，则查看下一个block所表示的bin是否有符合条件的空闲chunk。
      			do
    			{
      				if (++block >= BINMAPSIZE) /* out of bins */
    					goto use_top;
    			}
      			while ((map = av->binmap[block]) == 0);
    
      			bin = bin_at (av, (block << BINMAPSHIFT));
      			bit = 1;
    		}
			//可以认为当前if是对block的检查，看当前block中是否有满足条件的bin链表，如果没有则无需再遍历当前block所包含的每个bin链表中的chunk（具体实现就是使用bitmap加快分配的速度）

    
      		/* Advance to bin with set bit. There must be one. */
      		while ((bit & map) == 0)
    		{
      			bin = next_bin (bin);
      			bit <<= 1;
      			assert (bit != 0);
    		}
    		//遍历当前block所能表示的bin，寻找一个非空闲的最小的bin链表。

      		/* Inspect the bin. It is likely to be non-empty */
      		victim = last (bin);
    		//取bin链表中的最后一个元素（即smallbin中最先加入的chunk或者largebin中size最小的chunk）
      		/*  If a false alarm (empty bin), clear the bit. */
      		if (victim == bin)
    		{
      			av->binmap[block] = map &= ~bit; /* Write through */
      			bin = next_bin (bin);
      			bit <<= 1;
				//当前bin链表为空
    		}
之后的操作与之前对largebin链表进行的操作相同，只不过此时不需要再对链表中的chunk进行遍历。直接选择该链表中的最后一个chunk即可（对于smallbin所有chunk大小相同，对于largebin最后一个chunk最小且肯定满足需求大小nb）。

      		else
    		{
      			size = chunksize (victim);
    
      			/*  We know the first chunk in this bin is big enough to use. */
      			assert ((unsigned long) (size) >= (unsigned long) (nb));
    
      			remainder_size = size - nb;
    
      			/* unlink */
      			unlink (av, victim, bck, fwd);
    
      			/* Exhaust */
      			if (remainder_size < MINSIZE)
    			{
      				set_inuse_bit_at_offset (victim, size);
      				if (av != &main_arena)
    					set_non_main_arena (victim);
    			}
    
      			/* Split */
      			else
    			{
      				remainder = chunk_at_offset (victim, nb);
    
      				/* We cannot assume the unsorted list is empty and therefore
     				have to perform a complete insert here.  */
      				bck = unsorted_chunks (av);
      				fwd = bck->fd;
    		  		if (__glibc_unlikely (fwd->bk != bck))
    					malloc_printerr ("malloc(): corrupted unsorted chunks 2");
      				remainder->bk = bck;
      				remainder->fd = fwd;
      				bck->fd = remainder;
      				fwd->bk = remainder;
    
      				/* advertise as last remainder */
      				if (in_smallbin_range (nb))
    					av->last_remainder = remainder;
**注：一个不同之处，如果当前申请的size在smallbin范围内，则改写av->last\_remainder字段为remainder chunk。**  
**疑问点：这么做的好处是利用局部性原理，下次分配有很大可能也是smallbin？**

      				if (!in_smallbin_range (remainder_size))
    				{
      					remainder->fd_nextsize = NULL;
      					remainder->bk_nextsize = NULL;
    				}
      				set_head (victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      				set_head (remainder, remainder_size | PREV_INUSE);
      				set_foot (remainder, remainder_size);
    			}
      			check_malloced_chunk (av, victim, nb);
      			void *p = chunk2mem (victim);
      			alloc_perturb (p, bytes);
      			return p;
    		}
    	}
## 6.Top chunk分配机制 ##
如果fastbin，smallbin，largebin，unsortedbin中都不存在满足分配条件的chunk，则使用top chunk进行分配。

    	use_top:
      	/*
     	If large enough, split off the chunk bordering the end of memory
     	(held in av->top). Note that this is in accord with the best-fit
     	search rule.  In effect, av->top is treated as larger (and thus
     	less well fitting) than any other available chunk since it can
     	be extended to be as large as necessary (up to system
     	limitations).
    
     	We require that av->top always exists (i.e., has size >=
     	MINSIZE) after initialization, so if it would otherwise be
     	exhausted by current request, it is replenished. (The main
     	reason for ensuring it exists is that we may need MINSIZE space
     	to put in fenceposts in sysmalloc.)
       	*/
    	
		victim = av->top;
      	size = chunksize (victim);
    	if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    	{
      		remainder_size = size - nb;
      		remainder = chunk_at_offset (victim, nb);
      		av->top = remainder;
      		set_head (victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      		set_head (remainder, remainder_size | PREV_INUSE);
    
      		check_malloced_chunk (av, victim, nb);
      		void *p = chunk2mem (victim);
      		alloc_perturb (p, bytes);
      		return p;
			//对top chunk进行拆分
    	}
如果当前top_chunk的大小不满足分配大小，且当前fastbin链表中存在空闲chunk，则调用malloc\_consolidate对fastbin中的chunk进行合并（碎片化导致分配空间不足）。

      	/* When we are using atomic ops to free fast chunks we can get
     	here for all block sizes.  */
      	else if (atomic_load_relaxed (&av->have_fastchunks))
    	{
      		malloc_consolidate (av);
      		/* restore original bin index */
      		if (in_smallbin_range (nb))
    			idx = smallbin_index (nb);
      		else
    			idx = largebin_index (nb);
    	}
否则调用系统sysmalloc进行分配。
    
      	/*
     	Otherwise, relay to handle system-dependent cases
       	*/
      	else
    	{
      		void *p = sysmalloc (nb, av);
      		if (p != NULL)
    			alloc_perturb (p, bytes);
      		return p;
    	}
    }
  }
    
## 7.总结 ##
至此，对于\_int\_malloc()函数的分析结束。对\_int\_malloc()函数的分配机制做一下总结：  
1.


