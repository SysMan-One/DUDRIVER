#define	__MODULE__	"DUDRIVER"
#define	__IDENT__	"X.00-01"

#ifdef	__GNUC__
	#ident			__IDENT__
#endif

#pragma GCC diagnostic ignored  "-Wparentheses"
#pragma	GCC diagnostic ignored	"-Wdate-time"
#pragma	GCC diagnostic ignored	"-Wunused-variable"
#pragma	GCC diagnostic ignored	"-Wunused-function"

/*
**++
**
**  FACILITY:  DUDriver - Disk Unit driver
**
**  ABSTRACT: LDD is supposed to be placed on top of targed block deice driver - to performs transparent interception of the data.
**
**
**  DESCRIPTION: For demonstration purpose only - use it on u own risk and to study of Block I/O real live.
**		Not all resources can be correctly deallocated on unload this module.
**
**  DESIGN ISSUE:
**      This module implement replacement of make_request_fn () to intercept and processing WRITE requests, and bio_endio() to process READ request.
**      Also there is a small piece of code to demonstrate a external control function is implemented by IOCTL do "du$ctl" pseudo-device.
**
**      Enjoy!
**
**      Inspired by:
**
**		"With UNIX, if you're looking for something, you can easily and quickly check that small manual and find out it's not there.
**		With VMS, no matter what you look for - it's literally a five-foot shelf of documentation - if you look long enough it's there.
**		That's the difference - the beauty of UNIX is that it's simple; and the beauty of VMS is that it's all there."
**						- Ken Olsen, President of DEC, 1984.
**
**  AUTHORS: Ruslan R. Laishev (RRL)
**
**  CREATION DATE:   5-SEP-2018
**
**  BUILD:
**	make <Makefile>
**
**  INSTALL:
**
**	$ insmod dudriver.ko dudriver_backend=/dev/sda<Enter>
**
**  DEBUG:
**	$ dmesg | grep DUDRIVER
**
**  MODIFICATION HISTORY:
**
**	 7-SEP-2018	RRL	Added iob->bi_opf |= REQ_NOMERGE into the make_request_fn() to prevent possible unsolicited 
**				concurrent access to the buffers during decrypting. 
**
**--
*/


#ifdef	__x86_64__
	#define	__ARCH__NAME__	"x86_64"
#else
#ifdef	__i386
	#define	__ARCH__NAME__	"i386"
#endif
#endif

#include	<linux/version.h>	/* #if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,16) */
#include	<linux/module.h>
#include	<linux/moduleparam.h>
#include	<linux/init.h>

#include	<linux/sched.h>
#include	<linux/kernel.h>	/* printk() */
#include	<linux/slab.h>		/* kmalloc() */
#include	<linux/fs.h>		/* everything... */
#include	<linux/errno.h>		/* error codes */
#include	<linux/timer.h>
#include	<linux/types.h>		/* size_t */
#include	<linux/fcntl.h>		/* O_ACCMODE */
#include	<linux/hdreg.h>		/* HDIO_GETGEO */
#include	<linux/kdev_t.h>
#include	<linux/vmalloc.h>
#include	<linux/genhd.h>
#include	<linux/blkdev.h>
#include	<linux/blk_types.h>
#include	<linux/buffer_head.h>	/* invalidate_bdev */
#include	<linux/bio.h>
#include	<linux/ioctl.h>
#include	<linux/list.h>		/* Double linked lists	*/
#include	<linux/miscdevice.h>
#include	<linux/mutex.h>

#define	LOOKUP_BDEV2ARGS	2	/* lookup_bdev(const char *) - default	*/

#ifdef	_DEBUG				/* A macros to perform addition debug output */
	#pragma	message		"$TRACE macro will be defined!"
	#define $TRACE(fmt, ...)	{ if (dudrv_trace) printk(KERN_DEBUG  "[ %#x " __MODULE__ "\\%s:%d] " fmt "\n", current->tgid, __FUNCTION__,  __LINE__ , ## __VA_ARGS__); }
#else
	#define	$TRACE(fmt, ...)	{}
#endif

#define $SHOW_PARM(name, value, format) $TRACE(": " #name " = " format, (value))
#define $SHOW_PTR(var)                  $SHOW_PARM(var, var, "%p")
#define $SHOW_STR(var)                  $SHOW_PARM(var, (var ? var : "UNDEF(NULL)"), "'%s'")
#define $SHOW_INT(var)                  $SHOW_PARM(var, ((int) var), "%d")
#define $SHOW_UINT(var)                 $SHOW_PARM(var, ((unsigned) var), "%u")
#define $SHOW_ULL(var)                  $SHOW_PARM(var, ((unsigned long long) var), "%llu")
#define $SHOW_UNSIGNED(var)             $SHOW_PARM(var, var, "0x%08x")
#define $SHOW_BOOL(var)                 $SHOW_PARM(var, (var ? "ENABLED(TRUE)" : "DISABLED(FALSE)"), "%s");

MODULE_VERSION( __IDENT__ );

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("A skeleton of block's device filter-driver with enc/dec-ryptor stubs");
MODULE_AUTHOR("Ruslan R. Laishev (AKA Darth BMF SysMan, <aaa.vms@gmail.com>");

#define	DUDRV$K_CTLDEV	"du$ctl"	/* A device name is supposed to be used for control functions */

#define	DUDRV$K_SECTORSZ	512	/* Size of the disk sector		*/

#define	DUDRV$K_ENCRYPT		1
#define	DUDRV$K_DECRYPT		0


#define	DUDRV$K_BCKEND	"/dev/sdX"
static	char dudrv_bckends[DISK_NAME_LEN] = {DUDRV$K_BCKEND},
	*dudrv_bckend = dudrv_bckends;
module_param( dudrv_bckend, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dudrv_bckend, "Back end device name (eg, /dev/sda, dev/hda)");

static int dudrv_trace = 1;
module_param( dudrv_trace, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(dudrv_trace, "Extensible diagnostic output ([0] = Disabled, 1 = Enabled)");

#define	$DELAY(__secs__)	{$TRACE("sleep for %d seconds ...", __secs__); \
				set_current_state(TASK_UNINTERRUPTIBLE); \
				schedule_timeout(HZ * __secs__); }


/* Shit portion from blkdev.h:
 *
 * The basic unit of block I/O is a sector. It is used in a number of contexts
 * in Linux (blk, bio, genhd). The size of one sector is 512 = 2**9
 * bytes. Variables of type sector_t represent an offset or size that is a
 * multiple of 512 bytes. Hence these two constants.
 */
#ifndef SECTOR_SHIFT
	#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
	#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif


/* Macros to return minimal/maximum value from two given integers		*/
inline static int __min_2int (int x, int y)
{
	return	(x < y) ? x : y;
}
#define	$MIN_2INT(x, y)	__min_2int((int) (x), (int) (y))

/*
 * Save pointers to :
 */
struct block_device *backend_bdev;	/* A reference to the backed device	*/
					/* A entry for submiting I/O requests	*/
make_request_fn	*backend_make_request_fn;

static struct miscdevice misc_dua;	/* Pseudo-device to accept IOCTL control requests */


#define	$DUMPHEX(s, l)	{char __out__[128]; __dumphex16 (s, l, __out__); $TRACE(": %s", __out__);}

void	__dumphex16	(
		void *		src,
		unsigned short	srclen,
		void *		dst
			)
{
unsigned char *srcp = (unsigned char *) src, low, high, *dstp = dst;

	srclen = (srclen > 32) ? 32 : srclen;

	for (; srclen; srcp++, srclen--)
		{
		high = (*srcp) >> 4;
		low = (*srcp) & 0x0f;

		*(dstp++) = high + ((high < 10) ? '0' : 'a' - 10);
		*(dstp++) = low + ((low < 10) ? '0' : 'a' - 10);
		*(dstp++) = ' ';
		}

	*(dstp++) = 0;
}

/* Set of statistic counters */
atomic_t		curoutio ,	/* Current outstanding I/O-ops		*/
			maxoutio;	/* Max outstanding I/O counter		*/

unsigned long long	enc_count,	/* Encrypted blocks count		*/
			dec_count,	/* Decrypted blocks count		*/
			req_write_count,/* Requested I/O counters		*/
			req_read_count,

			write_count,	/* Completed I/O counters		*/
			read_count;


/*
 * Completion I/O routine argument block to be carried in the bio.bi_private field
 */
typedef struct  __iob_args__ {
//	union	{
		struct {	/* READ request	*/
		void	*bi_private,	/* A value of the original bi_private	*/
			*bi_end_io;	/*  ... bi_end_io() routine		*/


					/* Original iterator			*/
		struct bvec_iter bi_iter;

		unsigned int bi_opf;	/* BIO's original flags set		*/
			};


				/* WRITE request*/
		struct bio	*bio;	/* An address to the original BIO	*/

//		};

	sector_t bi_sector;	/* A logical disk sector number			*/
}         IOB_ARGS;

struct kmem_cache *iob_args_cache;
struct mempool_s *iob_args_pool;

/**
 * @brief __atomic64_inc - increment 64-bit integer
 * @param v	- an addreees of the 64-bit value to be incremented
 * @return -	- a value before changes
 */
static inline unsigned long long	__atomic64_inc	(
			unsigned long long	*v
	)
{
	return	__sync_fetch_and_add (v, 1);
}


/**
 * @brief __atomic64_dec - decrement 64-bit integer
 * @param v	- an addreees of the 64-bit value to be decremented
 * @return -	- a value before changes
 */
static inline unsigned long long	__atomic64_read	(
			unsigned long long	*v
	)
{
	return	__sync_fetch_and_add (v, 0);
}


/**
 * @brief __init_iob_args - initialize a memory pool for IOB's Arguments block
 * @param defnum - a default/minimum number of preallocated blocks
 * @return -	0 - Success
 *		-errno
 */
static inline int	__init_iob_args	(
				int	defnum
					)
{

	/*
	 * Initialize a I/O arguments list
	 * cat  /sys/kernel/slab/dudrv_iob_args/  *
	 */
	if ( !(iob_args_cache = kmem_cache_create( "dudrv_iob_args", sizeof(IOB_ARGS), 0, 0, NULL)) )
		{
		printk(KERN_ERR __MODULE__ ": kmem_cache_create() failed\n");

		return	-ENOMEM;
		}

	if ( !(iob_args_pool =  mempool_create_slab_pool( defnum, iob_args_cache)) )
		{
		printk(KERN_ERR __MODULE__ ": mempool_init_slab_pool() failed\n");

		return	-ENOMEM;
		}

	return	0;

}

/**
 * @brief __free_iob_args - return has been allocated (by __get_iob_args)  IOB Args block into the memory pool
 */
static inline	void __free_iob_args	(void)
{
	mempool_destroy(iob_args_pool);

	kmem_cache_destroy(iob_args_cache);
}


/**
 * @brief __get_iob_args - Allocate a IOB Args block from free pool. The block is zeroing before return.
 *
 * @param iob_args - an allocated block to be returned
 *
 * @return	- 0 : SUCCESS
 *		- EBUSY : Buffered I/O limit quota has been exhausted
 */
static inline int	__get_iob_args	(
		IOB_ARGS *	*iob_args
			)
{
	/* Get from memory pool */
	if ( !(*iob_args = mempool_alloc(iob_args_pool, GFP_NOIO)) )
		{
		printk(KERN_ERR __MODULE__ ": Error allocation memory for IOB ARGs\n");
		return -ENOMEM;
		}

	/* Zeroing new block, adjust statistic counter	*/
	memset(*iob_args, 0, sizeof(IOB_ARGS));

	atomic_inc(&curoutio);

	return	0;
}


/**
 * @brief __ret_iob_args - Release IOB Args block and put it to free pool.
 *
 * @param iob_args - an IOB Arguments block to be released
 *
 * @return	- 0 : Allway SUCCESS
 */
static inline int	__ret_iob_args	(
		IOB_ARGS	*iob_args
			)
{
	mempool_free(iob_args, iob_args_pool);

	atomic_dec(&curoutio);

	return	0;
}


/**
 * @brief __dua_show_bio - show a content of sensitive BIO fields, show BVECs additionlay if 'bvf' is non-zero;
 *			this routine is suppoed to be used for debug purpose only.
 * @param m	- __MODULE__
 * @param f	- __FUNCTION__
 * @param l	- __LINE__
 * @param iob	- BIO, by reference
 * @param bvf	- a flag to display BVECs
 */

#define $SHOW_BIO(bio, f)	{ if (dudrv_trace) __dua_show_bio(__MODULE__, __FUNCTION__, __LINE__, bio, f); }

static	void	__dua_show_bio	(
		const char	*m,
		const char	*f,
		int		l,
		struct bio	*iob,
		int		bvf
				)
{
struct bvec_iter src_iter;
struct bio_vec src_bv;
sector_t sector = iob->bi_iter.bi_sector;
unsigned int len, segno = 0;

	/* Print main BIO fields */
	printk(KERN_DEBUG  "[ %#x %s\\%s:%d]"  "%s BIO=%p (op=%#x, opf=%#x, flags=%#x), sector=%lu, .bi_vcnt=%u, .bi_status=%d\n",
	       current->tgid, m, f, l,
	       bio_data_dir(iob) == WRITE ? "WRITE" : "READ",
	       iob,
	       bio_op(iob), iob->bi_opf, iob->bi_flags, sector, iob->bi_vcnt, iob->bi_status);

	if ( !bvf )
		return;

	/* Run over BVEC-s and show fields ... */
	bio_for_each_segment (src_bv, iob, src_iter)
		{
		printk(KERN_DEBUG  "[ %#x %s\\%s:%d]"  "BIO=%p, bvec[segno=%3.3u]: page/len/offset : %p/%u/%u\n",
		       current->tgid, m, f, l,
		       iob, segno, src_bv.bv_page, src_bv.bv_len, src_bv.bv_offset);

		len = src_bv.bv_len;
		sector += len >> SECTOR_SHIFT;
		segno++;
		}

	if ( !segno )
		printk(KERN_DEBUG  "[ %#x %s\\%s:%d]"  "BIO=%p, bvec - empty\n",
			current->tgid, m, f, l,
			iob);
}


/**
 * @brief __iob_enc_dec - Performs a en/dec-cryption of the disk data block has been carried by BIO,
 *	a kind of processing is depend by 'bio_data_dir(iob)'.
 *
 * @param iob	- a BIO context structure to be processed
 * @param lbn	- disk block start sector logical number
 * @param rw	- DUDRV$K_ENCRYPT/DUDRV$K_DECRYPT
 */
static	void	__dua_bio_enc_dec	(
		struct bio *	iob,
		sector_t	lbn,
			int	enc_dec
			)
{
sector_t	nlbn = 0;
unsigned 	vcnt = 0;

struct bvec_iter src_iter = {0};
struct bio_vec	src_bv = {0};
void *src_p = NULL, *bv_page = NULL;

	/*
	 * A portion of the bio_copy_data() ...
	 */
	for (vcnt = 0, src_iter = iob->bi_iter; ; vcnt++)
		{
		if ( !src_iter.bi_size)
			{
			if ( !(iob = iob->bi_next) )
				break;

			src_iter = iob->bi_iter;
			}

		src_bv = bio_iter_iovec(iob, src_iter);

		BUG_ON(src_bv.bv_len % DUDRV$K_SECTORSZ);

		/* A number of 512-sectors in current buffer */
		nlbn	= src_bv.bv_len/DUDRV$K_SECTORSZ;

		src_p = bv_page = kmap_atomic(src_bv.bv_page);
		src_p += src_bv.bv_offset;

		for ( ; nlbn--; lbn++ , src_p += DUDRV$K_SECTORSZ )
			{
#if	0
		$TRACE("%scrypting src_p=%p, vcnt=%02u: lbn=%lu, nlbn=%lu",
		       enc_dec == DUDRV$K_ENCRYPT ? "En" : "De", src_p, vcnt, lbn, nlbn);
#endif

			{
			/* Simulate a processing of data in the I/O buffer */
			char *srcp = src_p, *dstp = src_p;
			int	count = DUDRV$K_SECTORSZ;

			while ( count--)
				{
				*(dstp++) = ~ (*(srcp++));
				}
			}

			(enc_dec == DUDRV$K_ENCRYPT) ? __atomic64_inc (&enc_count) : __atomic64_inc(&dec_count);
			}

		kunmap_atomic(bv_page);
		bio_advance_iter(iob, &src_iter, src_bv.bv_len);
		}
}

/**
 * @brief dua_bio_endio - A completion I/O routine is supposed to be called after READ/WRITE completion
 *	by block layered driver.
 *
 * @param iob	- A BIO (be advised it's cloned BIO)
 */
static	void	__dua_bio_endio	(
			struct bio *	iob
				)
{
IOB_ARGS *iob_args = NULL;
struct bio *orig_bio = NULL;
struct bvec_iter bvec_iter_tmp;
blk_status_t iosts;

	iosts = iob->bi_status;
	iob_args = iob->bi_private;

#if	0
	$SHOW_BIO(iob, 1);
#endif

	if ( bio_data_dir(iob) == READ )
		{
		/* Restore has been replaced fields ... */
		iob->bi_end_io = iob_args->bi_end_io;
		iob->bi_private = iob_args->bi_private;

		//$SHOW_BIO(iob, 1);

		bvec_iter_tmp = iob->bi_iter;
		iob->bi_iter = iob_args->bi_iter;

		//$SHOW_BIO(iob, 1);

		/*
		 * In case of READ request - we getting original READ BIO,
		 * so we should decrypt data buffer right now at the place
		 */
		__dua_bio_enc_dec(iob, iob_args->bi_sector, DUDRV$K_DECRYPT);

		iob->bi_iter = bvec_iter_tmp;

		/* Decrement reference count to original BIO	*/
		bio_put(iob);

		/* Call Complete I/O for original BIO */
		bio_endio (iob);
		}
	else if ( bio_data_dir(iob) == WRITE )
		{
		orig_bio = iob_args->bio;

		/* Release Cloned BIO	*/
		{ /* bio_free_pages(iob); */
		struct bio_vec *bvec;
		int i;

		bio_for_each_segment_all(bvec, iob, i)
			__free_page(bvec->bv_page);
		}

		bio_put(iob);

		/* Call Complete I/O for original BIO */
		bio_endio (orig_bio);
		}
	else	{
		printk(KERN_ERR  __MODULE__ ": Skip unhandled request \n");
		}

	if ( __ret_iob_args (iob_args) )
		printk(KERN_ERR  __MODULE__ ": Error return IOB Arg block into to the free pool\n");

	/* Adjust statistic counters ... */
	(bio_data_dir(iob) == WRITE) ? __atomic64_inc(&write_count) : __atomic64_inc(&read_count);
}


/**
 * @brief __dua_bio_clone - make a copy of the BIO structure, includes source buffers.
 *
 * @param src		- source BIO
 * @param src		-  BIO to be created and accept data from source BIO
 * @return
 */
static int __dua_bio_clone	(
		struct bio	*src,
		struct bio	**dst
			)
{
int	status;

	/* Allocate a memory for a new 'bio' structure */
	if ( !(*dst = bio_clone_bioset(src, GFP_KERNEL /* GFP_NOIO */, src->bi_pool /* NULL*/)) )
		{
		printk(KERN_ERR  __MODULE__ ": bio_clone_bioset() -> NULL\n");

		return	-ENOMEM;
		}

	if ( status = bio_alloc_pages(*dst , GFP_KERNEL) )
		{
		printk(KERN_ERR  __MODULE__ ": bio_alloc_pages() -> %d\n", status);

		return	status;
		}

	/* Copy data from source bio_vec-s to a new bio_vec-s set */
	bio_copy_data(*dst, src);

	return	0;
}

/**
 * @brief dua_make_request_fn - a block device interface routine (between kernel and block device driver) is supposed to be called
 *	when kernel issuing I/O request on a block device.
 *
 * @param ioq	- an I/O queue
 * @param iob	- BIO context structure
 *
 * @return	- 0 :  Success
 *		- errno
 */
static blk_qc_t dua_make_request_fn	(
		struct request_queue *	ioq,
			struct bio *	iob
				)
{
int	status = 0;
IOB_ARGS *iob_args = NULL;
struct bio *dua_bio =  NULL;

	/* Catch  firstly Block I/O requests is not handled by this driver: fsync/flush for example ,
	 * we transparently requeing those requests to driver of the backend volume
	 */
	if ( (!bio_has_data(iob))  )
		{
		status = backend_make_request_fn(ioq, iob);

		return	status;
		}

	//$SHOW_BIO(iob, 0);

	/* Get from pool IOB Arguments block */
	if ( __get_iob_args (&iob_args) )
		{
		printk(KERN_ERR __MODULE__ ": Error allocating IOB Args\n");
		printk(KERN_ERR __MODULE__ ": Requested I/O=%llu/%llu, completed I/O=%llu/%llu, usage of the IOB Args=%d.\n",
		       req_read_count, req_write_count, read_count, write_count, atomic_read(&curoutio) );

		#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 17)
			iob->bi_error = -EBUSY;
			bio_endio(iob);
		#else
			bio_io_error(iob);
		#endif

		return	-EBUSY;
		}

	/*
	 * Be advised that in the cloned BIO bi_sector is not valid,
	 * so we need to carring it with the iob_args.
	 */
	iob_args->bi_sector = iob->bi_iter.bi_sector;

	if ( bio_data_dir(iob) == READ )
		{

		/* Save original fields to be accessed/restored in the bi_end_io() routine */
		iob_args->bi_end_io = iob->bi_end_io;
		iob_args->bi_private = iob->bi_private;
		iob_args->bi_iter = iob->bi_iter;
		iob_args->bi_opf = iob->bi_opf;

		/*
		 * Set this flags to prevent BVECs sharing at low level I/O stack,
		 * it will be restored before BIO will be returned to up level caller
		*/
		iob->bi_opf |= REQ_NOMERGE_FLAGS;

		/*
		 * Replace an address of the Completion I/O routine for 'read/write' operation.
		 */
		iob->bi_end_io = __dua_bio_endio;
		iob->bi_private = iob_args;

		/* Increment references count for this BIO READ */
		bio_get(iob);

		/* Adjust performance counters and
		 * call original make_reques_fn() to performs a main work ...
		 */
		__atomic64_inc(&req_read_count);

		return	status = backend_make_request_fn(ioq, iob);
		}

	/*
	 * Assume that is WRITE request !
	 * In case of WRITE request - we can encrypt data buffer right now
	 *
	 * To keep original data in the cache buffer untouchable we need
	 * to clone BIO and BVECs in our own and encrypt our copy of the data buffers
	 */
	if ( status = __dua_bio_clone (iob, &dua_bio) )
		{
		printk(KERN_ERR  __MODULE__ ": '%s', __dua_bvec_clone() -> %d\n", dudrv_bckends, status);

		return	status;
		}

	/* Save original BIO WRITE pointer */
	iob_args->bio = iob;

	/* Set Completion I/O routine	*/
	dua_bio->bi_private = iob_args;
	dua_bio->bi_end_io = __dua_bio_endio;
	//dua_bio->bi_iter.bi_sector = iob->bi_iter.bi_sector;
	dua_bio->bi_iter = iob->bi_iter;

	__dua_bio_enc_dec(dua_bio, dua_bio->bi_iter.bi_sector, DUDRV$K_ENCRYPT);

	/*
	 * Adjust performance counters and
	 * call original make_reques_fn() to performs a main work ...
	 */
	__atomic64_inc(&req_write_count);

	status = backend_make_request_fn(ioq, dua_bio);

	return	status;
}

/*
 * The ioctl() implementation to performs control functions.
 * Example of using at user level program:
 ^
 *	struct __desc__ {
 *		char	len,
 *		char	data[512];
 *		} statblk = [0};
 *
 *
 *	fd = open("/dev/du$ctl");
 *	ioctl(fd, DUDRV$K_GETSTAT, &statblk);
 *	close(fd);
 *
 */

#define	DUDRV$K_GETSTAT		1	/* Initialize a key context for the given disk drive	*/
#define	DUDRV$K_TRACE		2	/* Set dudrvr_trace flag to 0/1				*/

#define	IOCTL$K_GETSTAT		_IOWR(135, DUDRV$K_GETSTAT, char *)
#define	IOCTL$K_TRACE		_IO(135, DUDRV$K_TRACE, int)


static struct miscdevice misc_dua;

/**
 * @brief dua_ioctl - controling the DU-driver
 *
 * @param fp	- file pointer
 *
 * @param cmd	- request code
 * @param arg	- request's specific argument
 *
 * @return
 */
static long	dua_ioctl(
		struct file *	fp,
		unsigned int	cmd,
		unsigned long	arg
			)
{
unsigned char *argp, *cp;
unsigned status, opcode = _IOC_NR(cmd);

	$TRACE(": fp = %p, cmd = %#x, arg = %#lx, opcode = %#x", fp, cmd, arg, opcode);

	switch (opcode)
		{
		case	DUDRV$K_TRACE:
			dudrv_trace = (arg == 0);
			printk(KERN_NOTICE __MODULE__ ": arg = %lu, set TRACE mode to = %s\n", arg, arg ? "ON" : "OFF");

			return	0;

		case	DUDRV$K_GETSTAT:
			{
			struct stblock {unsigned long long rqw, rqr, cw, cr, enc, dec; unsigned ioq; }
				       __attribute__((packed))
					* stblock;

			cp = argp  = (unsigned char *) arg;
			printk(KERN_NOTICE __MODULE__ ": Got request for counters for '%.*s'\n", *argp, argp + 1);

			cp++;
			stblock = (struct stblock *) (cp);

			stblock->rqr = __atomic64_read(&req_read_count);
			stblock->rqw = __atomic64_read(&req_write_count);
			stblock->cr = __atomic64_read(&read_count);
			stblock->cw = __atomic64_read(&write_count);
			stblock->enc = __atomic64_read(&enc_count);
			stblock->dec = __atomic64_read(&dec_count);

			stblock->ioq = atomic_read(&curoutio);

			*argp = (unsigned char) sizeof(struct stblock);

			printk(KERN_NOTICE __MODULE__ ": '%s' - requested I/O=%llu/%llu, completed I/O=%llu/%llu, en/de-crypted=%llu/%llu, usage of the IOB Args=%d.\n",
				dudrv_bckends, stblock->rqr, stblock->rqw, stblock->cr, stblock->cw, stblock->enc, stblock->dec, stblock->ioq);

			return	0;
			}
		}

	printk(KERN_NOTICE __MODULE__ ": Illegal or illformed IOCTL request = %#x, arg = %#x\n", cmd, (unsigned int) arg);

	return	-EOPNOTSUPP;
}

struct file_operations misc_fops = {
	.unlocked_ioctl = dua_ioctl,
	.owner = THIS_MODULE,
	.mmap = NULL
};



static int __init dua_init(void)
{
int	status, i = 0;
size_t	bcnt;
struct super_block *sb = NULL;
char	buf[2048] = {0};

	printk(KERN_NOTICE __MODULE__ ": " __IDENT__  "/"  __ARCH__NAME__   ", Starting ... (built  at "
#ifdef	_DEBUG
		__DATE__ " " __TIME__
#endif

		" with CC " __VERSION__ ")");

	printk(KERN_NOTICE __MODULE__ ": Context has been initialized for %s!\n", dudrv_bckend);

	/* Initialize counters with zeros */
	atomic_set( &curoutio, 0 );
	atomic_set( &maxoutio, 0 );

	/*
	 *
	 */
	printk(KERN_NOTICE __MODULE__ ": Initializing the DUDRIVER on %s, TRACE=%s ...\n",
		dudrv_bckend, dudrv_trace ? "ON" : "OFF");

	if ( dudrv_bckend != dudrv_bckends )
		strncpy(dudrv_bckends, dudrv_bckend, sizeof(dudrv_bckends));

	/* Initialize a stuff to handling control function */
	misc_dua.minor = MISC_DYNAMIC_MINOR;
	misc_dua.name = DUDRV$K_CTLDEV;
	misc_dua.fops = &misc_fops;

	if ( status  = misc_register(&misc_dua) )
		{
		printk(KERN_NOTICE __MODULE__ ": Registerind 'misc' device failed (name=%s, minor=%d) ->%d\n",
		       misc_dua.name, misc_dua.minor, status);

		return	status;
		}

	printk(KERN_NOTICE __MODULE__ ": Registered 'misc' device (name=%s, minor=%d)\n", misc_dua.name, misc_dua.minor);


	/* Initialize a SLAB memory pools for IOB Arguments */
	if ( status = __init_iob_args(32) )
		return	status;

	printk(KERN_NOTICE __MODULE__ ": IOB Args pool has been initialized\n");

	/*
	 * We exclude follows piece of code because we cannot freeze_bdev() on volume (like /dev/sda)
	 * only on partition like /dev/sda1 ...
	 *
	 * we expect that the driver will be initialized *before* any real I/o will be started on the protected volume!
	 *
	 */
#if	(LOOKUP_BDEV2ARGS==2)
	if ( IS_ERR(backend_bdev = lookup_bdev(dudrv_bckends, FMODE_READ | FMODE_WRITE)) )
#else
	if ( IS_ERR(backend_bdev = lookup_bdev(dudrv_bckends)) )
#endif
		{
		status = PTR_ERR(backend_bdev);
		printk(KERN_ERR __MODULE__ ": lookup_bdev(%s) -> %d\n", dudrv_bckends, status);
		return	status;
		}

	if ( sb = freeze_bdev(backend_bdev) )
		$TRACE(": freeze I/O on block device %s ...", dudrv_bckends);

	$DELAY(1);

	if ( backend_make_request_fn != backend_bdev->bd_queue->make_request_fn )
		{
		backend_make_request_fn = backend_bdev->bd_queue->make_request_fn;
		backend_bdev->bd_queue->make_request_fn = dua_make_request_fn;

		$TRACE(": Change for %s make_request_fn = %p -> %p, ", dudrv_bckends, backend_make_request_fn, backend_bdev->bd_queue->make_request_fn);
		}
	else	{
		printk(KERN_NOTICE __MODULE__ ": I/O request process has been set.\n");
		}

	/* unlock filesystem */

	$DELAY(1);

	if ( sb )
		if (status = thaw_bdev(backend_bdev, sb))
			printk(KERN_NOTICE __MODULE__ ": thaw_bdev() -> %d\n", status);


	printk(KERN_NOTICE __MODULE__ ": The driver has been initialized.\n");

	return 0;
}

/**
 * @brief dua_exit - this routine should never to be called on the life disk volume
 *
 */
static void dua_exit(void)
{
int	status;
struct super_block *sb = NULL;

	printk(KERN_NOTICE __MODULE__ ": Shuting down the driver ...\n");

	printk(KERN_NOTICE __MODULE__ ": Deregistering 'misc' device (name=%s, minor=%d)\n", misc_dua.name, misc_dua.minor);
	misc_deregister(&misc_dua);

	printk(KERN_NOTICE __MODULE__ ": Freeze I/O on '%s' (@%p)\n", dudrv_bckends, backend_bdev);

	if ( sb = freeze_bdev(backend_bdev) )
			printk(KERN_NOTICE __MODULE__ ": freeze I/O on block device %s ...", dudrv_bckends);

	printk(KERN_NOTICE __MODULE__ ": Accounting: requested I/O=%llu/%llu, completed I/O=%llu/%llu, outstanding I/O count=%d.\n",
	       req_read_count, req_write_count, read_count, write_count, atomic_read(&curoutio) );

	$DELAY(1);

	$SHOW_PTR( backend_bdev->bd_queue->make_request_fn );

	backend_bdev->bd_queue->make_request_fn = backend_make_request_fn;

	printk(KERN_NOTICE __MODULE__ ": Unfreeze I/O on '%s' (@%p)\n", dudrv_bckend, backend_bdev);

	if ( sb )
		if (status = thaw_bdev(backend_bdev, sb))
			printk(KERN_NOTICE __MODULE__ ": thaw_bdev() -> %d\n", status);

	printk(KERN_NOTICE __MODULE__ ": The driver shutdown complete.\n");
}

module_init(dua_init);
module_exit(dua_exit);
