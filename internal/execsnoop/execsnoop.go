package execsnoop

import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"

	"github.com/terrycain/ssh-audit/internal/events"
)

type execveEvent struct {
	Pid       uint64
	ParentPid uint64
	UID       uint32
	SessionID uint32
	Command   [16]byte
	Argv      [128]byte
}

const source string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#define ARGSIZE  128

struct data_t {
    u64 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
	u64 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
	u32 uid; // UID
    u32 sessionid; // Login session ID (i.e. task_>loginuid.val)
    char comm[TASK_COMM_LEN];
    char argv[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;
    // Get task info
    task = (struct task_struct *)bpf_get_current_task();
	// Populate vars
    data.pid = bpf_get_current_pid_tgid() >> 32;
	data.ppid = task->real_parent->tgid;
	data.uid = bpf_get_current_uid_gid();  // Will get the lower 32bits as gid is in the upper 32
    data.sessionid = task->sessionid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    __submit_arg(ctx, (void *)filename, &data);
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAX_ARGS; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) {
			char empty[] = "....";
		    __submit_arg(ctx, (void *)empty, &data);
		    goto out;
		}
	}
	char ellipsis[] = "...";
	__submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}
`

// ExecSnooper Internal data
type ExecSnooper struct {
	StopChannel chan bool
}

// NewExecSnooper Creates a new event store
func NewExecSnooper() *ExecSnooper {
	obj := ExecSnooper{
		StopChannel: make(chan bool),
	}

	return &obj
}

// Close Closes filewatcher
func (e ExecSnooper) Close() {
	log.Debug("Stopping execsnooper")
	e.StopChannel <- true
	// Wait for BPF to be closed
	select {
	case <-e.StopChannel:
		break
	case <-time.After(10 * time.Second):
		log.Warning("Execsnooper failed to stop gracefully ")
		break
	}
	log.Debug("Stopped execsnooper")
}

// Run Runs filewatcher
func (e ExecSnooper) Run(matchChannel chan<- string) {
	go e.run(matchChannel)
}

// Run Runs execsnoop
func (e ExecSnooper) run(matchChannel chan<- string) {
	log.Debug("Starting Exec BPF")
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Set maximum number of args we want to look for
	updatedSource := strings.Replace(source, "MAX_ARGS", "10", -1)
	bpfModule := bpf.NewModule(updatedSource, []string{})
	defer bpfModule.Close()

	// Converts function name to something like __x64_sys_execve
	bpfFunctionName := bpf.GetSyscallFnName("execve")

	kprobe, err := bpfModule.LoadKprobe("syscall__execve")
	if err != nil {
		log.WithError(err).Error("Failed to load syscall_execve")
		os.Exit(1)
	}

	// passing -1 for maxActive signifies to use the default
	// according to the kernel kprobes documentation
	if err := bpfModule.AttachKprobe(bpfFunctionName, kprobe, -1); err != nil {
		log.WithError(err).Error("Failed to attach syscall_execve")
		os.Exit(1)
	}

	// Creates BPF table
	table := bpf.NewTable(bpfModule.TableId("events"), bpfModule)
	channel := make(chan []byte, 1000)

	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		log.WithError(err).Error("Failed to init perf map")
		os.Exit(1)
	}

	go EBPFDataHandler(channel, hostname, matchChannel)

	// Start perfmap, the stop perfmap is inside the goroutine
	perfMap.Start()
	log.Debug("Waiting for stop")
	<-e.StopChannel
	log.Debug("Stopping BPF")
	perfMap.Stop()
	log.Debug("Stopped BPF")
	e.StopChannel <- true
	log.Debug("End of BPF Func")
}

func EBPFDataHandler(channel chan[]byte, hostname string, matchChannel chan<- string) {
	log.Info("Started goroutine to get BPF events")

	// Map of PID => [arg1, arg2, arg3]
	pidMap := make(map[uint64][]string)

	for {
		data := <-channel

		// Convert bytes into event struct
		var event execveEvent
		err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
		if err != nil {
			log.WithError(err).Error("Failed to decode received data from BPF")
			continue
		}

		argv := C.GoString((*C.char)(unsafe.Pointer(&event.Argv)))
		// comm := C.GoString((*C.char)(unsafe.Pointer(&event.Command)))

		// If we get .... then its the last arg
		// If we get ... then there were more args than we have recorded but is a final event
		if argv != "...." {
			// Part of args
			argSlice, keyExists := pidMap[event.Pid]
			if !keyExists {
				argSlice = make([]string, 0)
			}

			argSlice = append(argSlice, argv)
			pidMap[event.Pid] = argSlice

			// If the arg is not a final event, then loop again
			if argv != "..." && argv != "...." {
				continue
			}
		}

		argSlice, keyExists := pidMap[event.Pid]
		if !keyExists {
			log.Debug("Somehow process argv doesnt exist, should not happen")
			argSlice = make([]string, 0)
		}

		username := "unknown"
		if userobj, err := user.LookupId(strconv.FormatUint(uint64(event.UID), 10)); err == nil {
			username = userobj.Username
		}

		// By now we should emit json blob
		jsonEvent := events.CommandEvent{
			Time:      time.Now().UnixNano(),
			Event:     "session.command",
			Hostname:  hostname,
			Username:  username,
			UID:       int64(event.UID),
			SessionID: int64(event.SessionID),
			// Command:   "(" + comm + ") " + strings.Join(argSlice, " "),
			Command:   strings.Join(argSlice, " "),
			Pid:       event.Pid,
			ParentPid: event.ParentPid,
		}
		jsonString, err := json.Marshal(jsonEvent)

		if err != nil {
			log.WithError(err).Error(fmt.Sprintf("Failed to convert SSH Stop Event: %#v", jsonEvent))
		} else {
			select {
			case matchChannel <- string(jsonString):
				log.Debug("Command: " + string(jsonString))
			case <-time.After(5 * time.Second):
				log.Warn("Failed to emit event for 5 seconds, giving up")
			}

		}

		// We're done with this PID now, get rid
		delete(pidMap, event.Pid)
	}
}
