#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/types.h>
#include <linux/list.h>

struct info_list_unit{
    pid_t item_pid;
    struct list_head list;
};

#define NAME_STR_LENTH 64

struct hide_module_unit{
	struct list_head list;
	char module_name[NAME_STR_LENTH];
};


LIST_HEAD(hide_module_list_head);
LIST_HEAD(monitor_syscall_list_head);
LIST_HEAD(hide_filename_list_head);
LIST_HEAD(hide_port_list_head);


#define DEBUG 1
#define SIGNSTR "*** reanmate special kernel *** "

struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
        {
			return p;
        }
        if(DEBUG)
        {
            printk(SIGNSTR "find %d \n", p->pid);
        }
	}
	return NULL;
}

#define HIDE_COMMAND 0x1
#define MONITOR_COMMAND 0x2
#define PRINT_COMMAND 0x3
#define CLEAR_COMMAND 0x4
#define HIDE_PORT 0x5
#define HIDE_MODULE 0x6
#define PF_INVISIBLE 0x10000000


#define COMMAND_FAILED 0xFFFFFFFF
#define COMMAND_SUCCESS 0


int init_ops = 0;

int
hide_port_func(int port)
{
	struct info_list_unit *temp_m= kmalloc(sizeof(struct info_list_unit), GFP_ATOMIC);
    if(temp_m == NULL)
    {
        return COMMAND_FAILED;
    }
    temp_m->item_pid = port;
    list_add(&temp_m->list, &hide_port_list_head);
	return COMMAND_SUCCESS;
}

int
hide_pid_func(int pid)
{
	struct info_list_unit *temp_h = kmalloc(sizeof(struct info_list_unit), GFP_ATOMIC);
    if(temp_h == NULL)
    {
        return COMMAND_FAILED;
    }
    temp_h->item_pid = pid;
    list_add(&temp_h->list, &hide_filename_list_head);
	return COMMAND_SUCCESS;
}

int
hide_module_func(char *name)
{
	char temp_str_name[NAME_STR_LENTH] = {0};
	struct hide_module_unit *item_p = kmalloc(sizeof(struct hide_module_unit), GFP_ATOMIC);
	memset((void *)temp_str_name, 0, NAME_STR_LENTH);
	// HIDE_MOUDLE pid which will as an pointer
	memcpy((void *)temp_str_name, (const void *)name, strlen(name));
	if(DEBUG) printk(SIGNSTR " from user space is %s \n", temp_str_name);
	if(item_p == NULL)
	{
		return COMMAND_FAILED;
	}
	memset((void *)item_p->module_name, 0, NAME_STR_LENTH);
	memcpy((void *)item_p->module_name, (const void *)temp_str_name, NAME_STR_LENTH);
	list_add(&item_p->list, &hide_module_list_head);
	return COMMAND_SUCCESS;
}

int 
hacktool_init(void)
{
    init_ops = 1;
    if(DEBUG) printk(SIGNSTR "hacktool start init. \n");
    // init to hide some modules and hide ports
	hide_module_func("/data/local/tmp");
	hide_module_func("frida");
	hide_module_func("ida");
	hide_module_func("xposed");
	hide_module_func("adb");
	hide_module_func("magisk");

	//
	hide_port_func(27042);
	hide_port_func(23946);
	hide_port_func(5037);
    return 0;
}


SYSCALL_DEFINE3(hacktool, int, cmd, pid_t, pid, char *, input_str)
{
    struct list_head *current_s = NULL;
    struct info_list_unit *current_s_u = NULL;
    struct info_list_unit *current_s_h = NULL;
	struct hide_module_unit *current_s_m = NULL;
    
    

    if(DEBUG) printk(SIGNSTR "enter my syscall correct! command %d, pid %d. \n", cmd, pid);
    if(init_ops == 0)
    {
        hacktool_init();
        return COMMAND_SUCCESS;
    }
    if(HIDE_COMMAND == cmd)
    {
        struct info_list_unit *temp_h = kmalloc(sizeof(struct info_list_unit), GFP_ATOMIC);
        if(temp_h == NULL)
        {
            return COMMAND_FAILED;
        }
        temp_h->item_pid = pid;
        list_add(&temp_h->list, &hide_filename_list_head);
        if(DEBUG) printk(SIGNSTR " hide process pid %d \n", pid);
    }else if(MONITOR_COMMAND == cmd)
    {
        struct info_list_unit *temp_m= kmalloc(sizeof(struct info_list_unit), GFP_ATOMIC);
        if(temp_m == NULL)
        {
            return COMMAND_FAILED;
        }
        temp_m->item_pid = pid;
        list_add(&temp_m->list, &monitor_syscall_list_head);
        if(DEBUG) printk(SIGNSTR " add monitor syscall pid %d \n", pid);
    }else if(HIDE_PORT == cmd)
	{
		int port = pid;
		struct info_list_unit *temp_m= kmalloc(sizeof(struct info_list_unit), GFP_ATOMIC);
        if(temp_m == NULL)
        {
            return COMMAND_FAILED;
        }
        temp_m->item_pid = port;
        list_add(&temp_m->list, &hide_port_list_head);
        if(DEBUG) printk(SIGNSTR " add hide port %d \n", port);
	}else if(HIDE_MODULE == cmd)
	{
		char temp_str_name[NAME_STR_LENTH] = {0};
		char * user_str_p = NULL;
		int copy_fail_num = 0;
		struct hide_module_unit *item_p = kmalloc(sizeof(struct hide_module_unit), GFP_ATOMIC);
		memset((void *)temp_str_name, 0, NAME_STR_LENTH);
		// HIDE_MOUDLE pid which will as an pointer
		user_str_p = (char *)input_str;
		copy_fail_num = copy_from_user((void *)temp_str_name, (const void *)user_str_p, NAME_STR_LENTH);
		if(copy_fail_num) return COMMAND_FAILED;
		if(DEBUG) printk(SIGNSTR " from user space is %s \n", temp_str_name);
		if(item_p == NULL)
		{
			return COMMAND_FAILED;
		}
		memset((void *)item_p->module_name, 0, NAME_STR_LENTH);
		memcpy((void *)item_p->module_name, (const void *)temp_str_name, NAME_STR_LENTH);
		list_add(&item_p->list, &hide_module_list_head);
	}else if(PRINT_COMMAND == cmd)
    {
        list_for_each(current_s, &monitor_syscall_list_head)
        {
            current_s_u = list_entry(current_s, struct info_list_unit, list);
            printk(SIGNSTR " monitor pid is %d \n", current_s_u->item_pid);
        }
        if(DEBUG) printk(SIGNSTR " running at %s %d \n", __FUNCTION__, __LINE__);

        list_for_each(current_s, &hide_filename_list_head)
        {
            current_s_h = list_entry(current_s, struct info_list_unit, list);
            printk(SIGNSTR " hide process pid is %d \n", current_s_h->item_pid);
        }

        list_for_each(current_s, &hide_port_list_head)
        {
            current_s_h = list_entry(current_s, struct info_list_unit, list);
            printk(SIGNSTR " hide port is %d \n", current_s_h->item_pid);
        }

		list_for_each(current_s, &hide_module_list_head)
		{
			current_s_m = list_entry(current_s, struct hide_module_unit, list);
			printk(SIGNSTR " hide module name is  %s \n", current_s_m->module_name);
		}

    }
    else if(CLEAR_COMMAND == cmd)
    {
        struct list_head * q = NULL;
        struct info_list_unit *tm = NULL;
        struct info_list_unit *th = NULL;
		struct hide_module_unit *thm = NULL;

        list_for_each_safe(current_s, q, &monitor_syscall_list_head)
        {
            current_s_u = list_entry(current_s, struct info_list_unit, list);
            tm = current_s_u;
            list_del(&current_s_u->list);
            kfree(tm);
        }
        if(DEBUG) printk(SIGNSTR " running at %s %d \n", __FUNCTION__, __LINE__);

        list_for_each_safe(current_s, q, &hide_filename_list_head)
        {
            current_s_h = list_entry(current_s, struct info_list_unit, list);
            th = current_s_h;
            list_del(&current_s_h->list);
            kfree(th);
        }

        list_for_each_safe(current_s, q, &hide_port_list_head)
        {
            current_s_h = list_entry(current_s, struct info_list_unit, list);
            th = current_s_h;
            list_del(&current_s_h->list);
            kfree(th);
        }

		list_for_each_safe(current_s, q, &hide_module_list_head)
		{
			current_s_m = list_entry(current_s, struct hide_module_unit, list);
			thm = current_s_m;
			list_del(&current_s_m->list);
			kfree(thm);
		}

    }
    return COMMAND_SUCCESS;
}



long check_pid_syscall_trace(char *name)
{
	struct task_struct *this_task = current;
	struct list_head *current_s = NULL;
	struct info_list_unit *current_s_s = NULL;
	list_for_each(current_s, &monitor_syscall_list_head)
	{
		current_s_s = list_entry(current_s, struct info_list_unit, list);
		if(this_task->pid == current_s_s->item_pid)
		{
			printk(SIGNSTR " pid %d process is using %s \n", this_task->pid, name);
			return 1;
		}
	}
	return 0;
}


long check_file_name_hide(pid_t pid)
{

	struct list_head *current_s = NULL;
	struct info_list_unit *current_s_s = NULL;
	list_for_each(current_s, &hide_filename_list_head)
	{
		current_s_s = list_entry(current_s, struct info_list_unit, list);
		if(pid == current_s_s->item_pid)
		{
			return 1;
		}
	}
	return 0;
}


#define TMPSZ 150

long operate_on_seq_file_seq_show(struct seq_file *seq)
{
	char needle[256] = {0};
	struct list_head *current_s = NULL;
	struct info_list_unit *current_s_s = NULL;
	list_for_each(current_s, &hide_port_list_head)
	{
		current_s_s = list_entry(current_s, struct info_list_unit, list);
		memset((void *)needle, 0, 256);
		snprintf(needle, 256, ":%04X", current_s_s->item_pid);
		if(strnstr(seq->buf + seq->count - TMPSZ, needle, TMPSZ))
		{
			printk(SIGNSTR " hide port is %d \n", current_s_s->item_pid);
			seq->count -= TMPSZ;
		}
	}
	return 0;
}