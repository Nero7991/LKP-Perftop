#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
//Path in the linux kernel location
#include <../../linux/kernel/sched/sched.h>
#include <linux/jhash.h>
#include <linux/stacktrace.h>
#include <linux/sched.h>


#define MAX 32
#define FALSE 0
#define TRUE 1


//#define CONFIG_ARM64
#define DEBUG_ENABLE 0
#define COMPILE_UNUSED_FUNCTIONS 0

/* Declare hash table */
DECLARE_HASHTABLE(htb1, 16);

static DEFINE_SPINLOCK(kprobe_lock);

#define PROC_PERFTOP_KEY 0


/* Declare details about the module */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oren Collaco (orenrc@vt.edu)");
MODULE_DESCRIPTION("LKP Project 3");
MODULE_INFO(intree, "Y");

struct hash_entry
{
	int count;
	int pid;
	unsigned long long sched_time;
	unsigned long long total_time;
	unsigned long *st_ptr;
	struct hlist_node node;
};

/* red black tree */
struct rb_root maintree = RB_ROOT;

struct my_rb
{
	struct rb_node node;
	u64 val;
	u32 stack_hash;
	unsigned long *st_ptr;
};

typedef unsigned int (*stack_trace_save_user_t)(unsigned long *store, unsigned int size);
stack_trace_save_user_t stack_trace_save_user_ptr;

// static char symbol[] = "proc_reg_open";
static char symbol[] = "pick_next_task_fair";
static char symbol_st[] = "stack_trace_save_user";


/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= symbol,

};

// https://stackoverflow.com/questions/40454157/is-there-an-equivalent-instruction-to-rdtsc-in-arm
// SPDX-License-Identifier: GPL-2.0

/* 
 * Based on  https://cpufun.substack.com/p/fun-with-timers-and-cpuid, this should work
 */
static u64 rdtsc(void)
{
    u64 val;

    /*
     * According to ARM DDI 0487F.c, from Armv8.0 to Armv8.5 inclusive, the
     * system counter is at least 56 bits wide; from Armv8.6, the counter
     * must be 64 bits wide.  So the system counter could be less than 64
     * bits wide and it is attributed with the flag 'cap_user_time_short'
     * is true.
     */
    asm volatile("mrs %0, cntvct_el0" : "=r" (val));

    return val;
}

static int insert_rbtree(struct rb_root *root, struct my_rb *entry)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct my_rb *curr;
	int left;
	/* Decide the location to put the new node */
	while (*new)
	{
		parent = *new;
		curr = container_of(*new, struct my_rb, node);
		left = entry->val - curr->val;
		if (left < 0)
		{
			new = &((*new)->rb_left);
		}
		else if (left > 0)
		{
			new = &((*new)->rb_right);
		}
		else
		{
			/* Not inserted, return as error */
			return -1;
		}
	}
	/* Now add the new node */
	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, root);

	return 0;
}

static struct my_rb *search_rbtree(struct rb_root *root, u64 key)
  {
  	struct rb_node *node = root->rb_node;
	struct my_rb *curr;
	int left;
  	while (node) {
  		curr = container_of(node, struct my_rb, node);
		/* Check if go left or right */
		left = key - curr->val;

		if (left < 0)
  			node = node->rb_left;
		else if (left > 0)
  			node = node->rb_right;
		else 
  			return curr;
	}
	return NULL;
  }

static struct my_rb *store_value_rbtree(int val)
{
	struct my_rb *new;
	new = kmalloc(sizeof(struct my_rb), GFP_ATOMIC);
	if (!new)
		/* If kmalloc returns null pointer, return with -ENOMEM */
		return NULL;
	new->val = val;
	/* Add new entry to the red-back tree  */
	insert_rbtree(&maintree, new);
	return new;
}

/* Store passed value to hash */
static struct hash_entry* create_hash(int key)
{
	struct hash_entry *new;
	/* kmalloc should not sleep since its called from kprobe handler, thus, using GFP_ATOMIC */
	new = kmalloc(sizeof(struct hash_entry), GFP_ATOMIC);
	if (!new)
		/* If kmalloc returns null pointer, return with -ENOMEM */
		return NULL;
	
	/* Add new entry to the hash table */
	hash_add(htb1, &new->node, key);
	new->total_time = 0;
	new->st_ptr = NULL;
	return new;
}

/* Get already inserted hash entry count from key*/
static struct hash_entry* get_hash(int key)
{
	struct hash_entry *ptr;
	
	/* Return the count for key, else -1  */
	hash_for_each_possible(htb1, ptr, node, key)
	{
		return ptr;
	}
	return NULL;
}

#if COMPILE_UNUSED_FUNCTIONS
/* Check all hash values, compare and return if exists else return -1 */
static int check_get_hash(int key)
{
	struct hash_entry *ptr;
	unsigned bucket;

	/* Return the count for key, else -1  */
	hash_for_each(htb1, bucket, ptr, node)
	{
		if(ptr->pid == key){
			return ptr->count;
		}
	}
	return -1;
}
#endif

#if COMPILE_UNUSED_FUNCTIONS
static void update_hash(int count, int key)
{
	struct hash_entry *ptr;
	
	hash_for_each_possible(htb1, ptr, node, key)
	{
		ptr->count = count;
	}
}
#endif

#define STORED_STACK_TRACE_LENGTH	(unsigned int)4

#if COMPILE_UNUSED_FUNCTIONS
static void print_hash_table(struct seq_file *m)
{
	struct hash_entry *ptr;
	unsigned bucket;
	char st_buf[100];
#if DEBUG_ENABLE
	printk(KERN_INFO "Printing all the entries in hash table...");
#endif

	/* Go through all the entries in the hash table and print */
	hash_for_each(htb1, bucket, ptr, node)
	{
		stack_trace_snprint(st_buf, 100, ptr->st_ptr, STORED_STACK_TRACE_LENGTH, 1);
		//seq_printf(m, "Stack trace\t\t\tPID %05d \t: %d, time = %llu ticks\n %s", ptr->pid, ptr->count, ptr->total_time, st_buf);
		/* Don't print the */
		seq_printf(m, "Stack trace\t\t\t\tTotal time: %llu\n%s", ptr->total_time, st_buf);

		seq_printf(m, "\n");
	}
	
}
#endif

static void print_rbtree_rev(struct seq_file *m){
	/* Go through all the entries in the rb tree and print */
	struct rb_node *node;
	struct my_rb *this;
	int i = 1;
	char st_buf[100];
	for (node = rb_last(&maintree); node; node = rb_prev(node))
	{
		this = rb_entry(node, struct my_rb, node);
		printk(KERN_CONT "%llu, ", this->val);
		//seq_printf(m, "%d, ", this->val);
		stack_trace_snprint(st_buf, 100, this->st_ptr, STORED_STACK_TRACE_LENGTH, 1);
		seq_printf(m, "\nStack trace\t\t\t\tRank: %d, Jenkins hash: %d, Total time: %llu ticks\n%s", i, this->stack_hash, this->val, st_buf);
		i += 1;
		if (i > 20)
			break;
	}
}

#if COMPILE_UNUSED_FUNCTIONS
static void print_rbtree(struct seq_file *m)
{
/*
 * Print out value of all entries in rb tree.
 */
struct my_rb *this;
struct rb_node *node;
#if DEBUG_ENABLE
	printk(KERN_INFO "Printing all the entries in rb tree...");
#endif
	printk(KERN_INFO "Red-back tree: ");
	seq_printf(m, "Red-back tree: ");

	/* Go through all the entries in the rb tree and print */
	
	for (node = rb_first(&maintree); node; node = rb_next(node))
	{
		this = rb_entry(node, struct my_rb, node);
		printk(KERN_CONT "%llu, ", this->val);
		seq_printf(m, "%llu, ", this->val);
	}
	seq_printf(m, "\n");

}
#endif


static void destroy_hash_table_and_free(void)
{
	struct hash_entry *ptr;
	struct hlist_node *temp;
	unsigned int i;
#if DEBUG_ENABLE
	printk(KERN_INFO "Deleting all the entries in hash table...");
#endif
	/* Go through all the entries in the hash table and delete */
	hash_for_each_safe(htb1, i, temp, ptr, node)
	{
#if DEBUG_ENABLE
		printk(KERN_INFO "val %d freed\n", ptr->count);
#endif
		hash_del(&ptr->node);
		kfree(ptr);
	}
}

static void destroy_rbtree_and_free(void)
{
#if DEBUG_ENABLE
	printk(KERN_INFO "Freeing all the entries in rb tree...");
#endif

	/* Go through all the entries in the hash table and print */
	struct rb_node *node;
	for (node = rb_first(&maintree); node; node = rb_next(node))
	{
		struct my_rb *this = rb_entry(node, struct my_rb, node);
#if DEBUG_ENABLE
		printk(KERN_INFO "val %d freed\n", this->val);
#endif

		rb_erase(&this->node, &maintree);
		kfree(this);
	}
}

/* Called when proc/perftop is accessed */
static int render_proc_text(struct seq_file *m, void *v)
{

	#if DEBUG_ENABLE
	printk(KERN_INFO "In render_proc_text");
	//seq_printf(m, "Hello proc!\n");
	#endif
	
	//seq_printf(m, "Hello World\n");
	/* Print all the entries in the hash table which contain the counts for process scheduled */
	//print_hash_table(m);
	print_rbtree_rev(m);
	return 0;
}


static void cleanup(void)
{
/* Destroy the structures and free its memory */
#if DEBUG_ENABLE
	printk(KERN_INFO "\nCleaning up...\n");
#endif

	destroy_hash_table_and_free();
	destroy_rbtree_and_free();
}

#define PROC_INVOKE_MONITOR_FILE "perftop"
#define GET_NAME(x) x->f_path.dentry->d_name.name
/* Set length of stack trace to be saved */

int stack_stored_flag;
unsigned long **stored_stack_cpu;
/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *ts;
	struct rq *rq;
	struct my_rb *rb_entry_ptr = NULL;
	int pid, saved_entries, cpu;
	u32 stack_hash;
	unsigned long *stored_stack;
	struct hash_entry *entry_ptr;
	unsigned long flags;

      spin_lock_irqsave(&kprobe_lock, flags);
#ifdef CONFIG_ARM64
	/* Use the pointer to the rq struct passed as first argument available in r0 register (arm64) */
	rq = (struct rq*)regs->regs[0];
	/* Use the pointer to the task_struct passed as second argument present in r1 register (arm64)*/
	ts = (struct task_struct*)regs->regs[1];
	
	#if DEBUG_ENABLE
	pr_info("<%s> p->addr = 0x%p, pc = 0x%lx, pstate = 0x%lx\n",
		p->symbol_name, p->addr, (long)regs->pc, (long)regs->pstate);
	#endif
	if (ts != NULL){
		/* A new task ts was just scheduled, find the cpu/core it was scheduled on  */
		cpu = rq->cpu;
		#if DEBUG_ENABLE
		pr_info("Core: %d", rq->cpu);
		#endif
		/* Use core number to index to the last stored_stack for that core */
		stored_stack = stored_stack_cpu[cpu];
		/* Get the hash_entry for the previous scheduled task, if stored_stack not NULL*/
		if (stored_stack != NULL){
			/* Get hash based on the stack trace, using PID as arbitary value */
			stack_hash = jhash2((unsigned int*)stored_stack, STORED_STACK_TRACE_LENGTH, 0);
			/* Get hash entry using stack hash */
			entry_ptr = get_hash(stack_hash);
			/* Check if total_time is non-zero */
			if(entry_ptr->total_time > 0 || 1){
				/* Check if rb tree has this time as key */
				rb_entry_ptr = search_rbtree(&maintree, entry_ptr->total_time);
				if(rb_entry_ptr != NULL){
					#if DEBUG_ENABLE
					pr_info("Deleting entry in rb tree... %d, %d", entry_ptr->total_time, rb_entry_ptr->val);
					#endif
					/* rb tree has this time, delete and free memory */
					rb_erase(&rb_entry_ptr->node, &maintree);
  					kfree(rb_entry_ptr);
				}
			}
			/* Compute the time the task was scheduled for and add to total*/
			entry_ptr->total_time += rdtsc() - entry_ptr->sched_time;
			/* Check if total_time is non-zero */
			if(entry_ptr->total_time > 0 || 1){
				/* Check if rb tree has this time as key */
				rb_entry_ptr = search_rbtree(&maintree, entry_ptr->total_time);
				if(rb_entry_ptr != NULL){
					/* rb tree has this time, delete and free memory */
					#if DEBUG_ENABLE
					pr_info("Deleting entry in rb tree... %d, %d", entry_ptr->total_time, rb_entry_ptr->val);
					#endif
					rb_erase(&rb_entry_ptr->node, &maintree);
  					kfree(rb_entry_ptr);
				}
				else{
					/* Add to the tree */
					#if DEBUG_ENABLE
					pr_info("Adding entry in rb tree...");
					#endif
					rb_entry_ptr = store_value_rbtree(entry_ptr->total_time);
					if(rb_entry_ptr != NULL){
						rb_entry_ptr->stack_hash = stack_hash;
						rb_entry_ptr->st_ptr = entry_ptr->st_ptr;
					}
				}
			}
			
			
		}
		pid = ts->pid;
		/* Allocated data for stack trace */
		stored_stack = kmalloc(sizeof(unsigned long)*STORED_STACK_TRACE_LENGTH, GFP_ATOMIC);
		/* Check if kernel task or user task using the mm pointer in task_struct. mm points to an mm_struct structure that tracks user task address space
		It is null for kernel tasks*/
		
		if(ts->mm != NULL){
			/* mm not NULL, this is a user task */
			if(stack_trace_save_user_ptr != NULL)
			saved_entries = stack_trace_save_user_ptr(stored_stack, STORED_STACK_TRACE_LENGTH);
			else
			pr_info("user save pointer null!");
		}
		else{
			/* mm is NULL, this is a kernel task */
			saved_entries = stack_trace_save(stored_stack, STORED_STACK_TRACE_LENGTH, 0);
		}
		#if DEBUG_ENABLE
		pr_info("Trace: ");
		stack_trace_print(stored_stack, STORED_STACK_TRACE_LENGTH, 1);
		#endif
		/* Get hash based on the stack trace, using PID as arbitary value */
		stack_hash = jhash2((unsigned int*)stored_stack, STORED_STACK_TRACE_LENGTH, 0);

		entry_ptr = get_hash(stack_hash);
		#if DEBUG_ENABLE
		pr_info("in PID: %d, hash: %d", pid, stack_hash);
		#endif
		/* Check if hash entry exists for pid */
		if(entry_ptr != NULL ){
			#if DEBUG_ENABLE
			pr_info("Updating entry...");
			pr_info("PID: %d, count: %d", entry_ptr->pid, entry_ptr->count);
			#endif
			/* Entry exists, increment count */
			entry_ptr->count += 1;
			entry_ptr->sched_time = rdtsc();
			kfree(stored_stack);
			stored_stack = entry_ptr->st_ptr;
			//update_hash(++count, stack_hash);
		}
		else{
			#if DEBUG_ENABLE
			pr_info("Creating entry...");
			#endif
			/* kmalloc call in create_hash should not sleep since called from kprobe handler, so using GFP_ATOMIC flag. 
			Entry does not exist, create new entry */
			entry_ptr = create_hash(stack_hash);
			entry_ptr->count = 1;
			/* Save current ticks */
			entry_ptr->sched_time = rdtsc();
			entry_ptr->pid = pid;
			entry_ptr->st_ptr = stored_stack;
		}
		stored_stack_cpu[cpu] = stored_stack;
	}
#endif
	#if DEBUG_ENABLE
	pr_info("In handler pre");
	#endif
	spin_unlock_irqrestore(&kprobe_lock, flags);
	/* A dump_stack() here will give a stack backtrace */
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
#ifdef CONFIG_ARM64
	#if DEBUG_ENABLE
	printk(KERN_INFO "posthandler");
	#endif
#endif

}

static int perftop_open(struct inode *inode, struct  file *file) {
	#if DEBUG_ENABLE
	printk(KERN_INFO "proc/perftop called");
	pr_info("%s", file->f_path.dentry->d_iname);
	#endif
	return single_open(file, render_proc_text, NULL);
}

static const struct proc_ops perftop_fops = {
  .proc_open = perftop_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* Module initialization function. Called on module load */
static int __init perftop_init(void)
{
	int err = 0;
	stack_trace_save_user_ptr = NULL;
	/* Creates a pseudo-file in the proc file system */
	proc_create("perftop", 0, NULL, &perftop_fops);

	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	/* Set is stack stored flag to 0 */
	stack_stored_flag = 0;
	/* Allocate memory for array that points to the address of stack stored for each CPU */
	stored_stack_cpu = kmalloc(num_online_cpus(), GFP_KERNEL);
	for (int i = 0; i<num_online_cpus(); i++){
		stored_stack_cpu[i] = NULL;
	}
	pr_info("Online CPU count: %d\n", num_online_cpus());
	kp.symbol_name = symbol_st;
	err = register_kprobe(&kp);
	if (err < 0) {
		pr_err("register_kprobe failed, returned %d\n", err);
		/* For some reason, kprope could not find the stack_trace_save_user function (seems like an arm issue) */
		//return err;
	}
	stack_trace_save_user_ptr = (stack_trace_save_user_t) kp.addr;
	unregister_kprobe(&kp);
	kp.symbol_name = symbol;
	err = register_kprobe(&kp);
	if (err < 0) {
		pr_err("register_kprobe failed, returned %d\n", err);
		return err;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);
	
	return err;
}

static void __exit perftop_exit(void)
{
	/* Called when unloading the module. Ideally, performs house keeping related to module unloading  */
	//cleanup();

	unregister_kprobe(&kp);

	/* Remove perftop from proc file sytem */
	remove_proc_entry("perftop", NULL);
	return;
}

/*
 * perftop_init is called on module loading
 */
module_init(perftop_init);

/*
 * perftop_exit is called on module unloading
 */
module_exit(perftop_exit);
