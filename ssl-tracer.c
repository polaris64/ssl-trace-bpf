#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

// Maximum capturable data length
#define MAX_DATA_SIZE 4096

enum ssl_event_type { SSLRead, SSLWrite };

// Struct emitted by perf events
struct ssl_event_t {
  enum ssl_event_type type;
  u64 timestamp_ns;
  u32 pid;
  u32 tid;
  char comm[TASK_COMM_LEN];
  char data[MAX_DATA_SIZE];
  u32 data_len;
};

// Define perf event output ring buffer
BPF_PERF_OUTPUT(tls_events);

// Hashes to map PID/TID (u64) to a data buffer pointer for both read
// and write operations
BPF_HASH(ssl_read_buffer_map, u64, const char*);
BPF_HASH(ssl_write_buffer_map, u64, const char*);

// Define a per-CPU array to hold captured events. This is needed
// otherwise the data needs to be stored on the stack, which is
// limited to 512 bytes.
BPF_PERCPU_ARRAY(data_buffer_heap, struct ssl_event_t, 1);


/**
 * Lookup the heap-allocated ssl_event_t struct and initialise it.
 */
static struct ssl_event_t* create_ssl_event(u64 id) {
  u32 zero = 0;
  struct ssl_event_t *event = data_buffer_heap.lookup(&zero);
  if (event == NULL) {
    return NULL;
  }

  event->timestamp_ns = bpf_ktime_get_ns();
  event->pid = id >> 32;
  event->tid = id & 0xffffffff;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  return event;
}

/**
 * Handle an SSL read/write event for a PID/TID (id) by reading from
 * the SSL data buffer, filling the ssl_event_t fields and submitting
 * a perf event.
 */
static int process_SSL_data(struct pt_regs *ctx, u64 id, enum ssl_event_type type, const char *buf) {
  int len = (int)PT_REGS_RC(ctx);
  if (len < 0) {
    return 0;
  }

  // Retrieve the heap-allocated event struct
  struct ssl_event_t *event = create_ssl_event(id);
  if (event == NULL) {
    return 0;
  }

  event->type = type;

  // Read as much data as possible/necessary from the SSL data buffer
  event->data_len = (len < MAX_DATA_SIZE ? (len & (MAX_DATA_SIZE - 1)) : MAX_DATA_SIZE);
  bpf_probe_read(event->data, event->data_len, buf);

  // Submit the perf event
  tls_events.perf_submit(ctx, event, sizeof(struct ssl_event_t));

  return 0;
}

/**
 * Handle the SSL read function uprobe.
 */
int ssl_read_entry(struct pt_regs *ctx) {
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;

  // Store the data buffer pointer in the read map for this PID/TID
  const char *buf = (const char*)PT_REGS_PARM2(ctx);
  ssl_read_buffer_map.update(&current_pid_tgid, &buf);

  return 0;
};

/**
 * Handle the SSL read function uretprobe.
 */
int ssl_read_return(struct pt_regs *ctx) {
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;

  // Fetch the buffer pointer for this PID/TID and process it if found
  const char **buf = ssl_read_buffer_map.lookup(&current_pid_tgid);
  if (buf != NULL) {
    process_SSL_data(ctx, current_pid_tgid, SSLRead, *buf);
  }

  // Remove the entry from the hash table
  ssl_read_buffer_map.delete(&current_pid_tgid);

  return 0;
}

/**
 * Handle the SSL write function uprobe.
 */
int ssl_write_entry(struct pt_regs *ctx) {
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;

  // Store the data buffer pointer in the write map for this PID/TID
  const char *buf = (const char*)PT_REGS_PARM2(ctx);
  ssl_write_buffer_map.update(&current_pid_tgid, &buf);

  return 0;
};

/**
 * Handle the SSL write function uretprobe.
 */
int ssl_write_return(struct pt_regs *ctx) {
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;

  // Fetch the buffer pointer for this PID/TID and process it if found
  const char **buf = ssl_write_buffer_map.lookup(&current_pid_tgid);
  if (buf != NULL) {
    process_SSL_data(ctx, current_pid_tgid, SSLWrite, *buf);
  }

  // Remove the entry from the hash table
  ssl_write_buffer_map.delete(&current_pid_tgid);

  return 0;
}
