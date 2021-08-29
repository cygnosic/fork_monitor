from bcc import BPF
from ctypes import c_int
from time import sleep, strftime

b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
enum stat_types {
    S_COUNT = 1,
    S_MAXSTAT
};

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    
};
BPF_PERF_OUTPUT(events);

BPF_ARRAY(stats, u64, S_MAXSTAT);
static void stats_increment(int key) {
    u64 *leaf = stats.lookup(&key);
    if (leaf) (*leaf)++;
}

void do_count(struct pt_regs *ctx) { 
stats_increment(S_COUNT); 
struct data_t data = {};
data.pid = bpf_get_current_pid_tgid();
bpf_get_current_comm(&data.comm, sizeof(data.comm));
events.perf_submit(ctx, &data, sizeof(data));
}
""")

b.attach_kprobe(event="sched_fork", fn_name="do_count")
S_COUNT = c_int(1)

def print_event(cpu,data,size):
    event = b["events"].event(data)
    
    
    if(b["stats"][S_COUNT].value==1):
    	
        print(b"fork called by pid: %d" % ((event.pid)))
    b["stats"].clear()
print("Tracing... Ctrl-C to end.")
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
