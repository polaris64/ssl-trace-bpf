#!/usr/bin/python

import argparse
import base64
from bcc import BPF
import json
import os

start_ns = 0


def get_cfg():
    """Return runtime configuration from CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        dest="filter_comm",
        required=False,
        help="Filter captures by command name "
        "(regardless of PID unless -p is also specified)"
    )
    parser.add_argument(
        "-e",
        dest="encoding",
        required=False,
        default="repr",
        choices=["base64", "repr"],
        help="Encoding of captured data for JSON output"
    )
    parser.add_argument(
        "-o",
        dest="output_path",
        required=False,
        help="Output captured data to specified file "
        "(stdout if not specified)"
    )
    parser.add_argument(
        "-p",
        dest="filter_pid",
        required=False,
        help="Filter captures by PID"
    )
    args = parser.parse_args()

    return {
        "encoding": args.encoding,
        "filter_comm": args.filter_comm,
        "filter_pid": int(args.filter_pid) if args.filter_pid else None,
        "out_path": os.path.abspath(args.output_path)
        if args.output_path else None,
    }


def setup_bpf():
    """Compile BPF from ssl-tracer.c and attach uprobes. Return BPF."""
    try:
        b = BPF(src_file="ssl-tracer.c")
        b.attach_uprobe(
            name="ssl",
            sym="SSL_read",
            fn_name="ssl_read_entry"
        )
        b.attach_uretprobe(
            name="ssl",
            sym="SSL_read",
            fn_name="ssl_read_return"
        )
        b.attach_uprobe(
            name="ssl",
            sym="SSL_write",
            fn_name="ssl_write_entry"
        )
        b.attach_uretprobe(
            name="ssl",
            sym="SSL_write",
            fn_name="ssl_write_return"
        )
        return b
    except Exception as ex:
        print("ERROR: {}".format(str(ex)))
        return None


def get_event_type(type):
    """Return the event type string from the C enum value."""
    if type == 0:
        return "R"
    elif type == 1:
        return "W"
    else:
        return "-"


def write_output(cfg, state):
    """Write all captured data to the configured output file (if necessary)."""
    if cfg["out_path"]:
        print(
            "Writing output for {} processes to {}...".format(
                len(state["capture"].keys()),
                cfg["out_path"]
            )
        )
        with open(cfg["out_path"], "tw") as fh:
            json.dump(state["capture"], fh)


def perf_loop(cfg, bpf):
    """Initiate perf event capture and enter polling loop."""
    def handle_event(cpu, data, size):
        """Handle a single perf event from BPF"""
        global start_ns

        # Fetch event struct
        event = bpf["tls_events"].event(data)

        # Get source PID and command name and filter if necessary
        e_pid = event.pid
        e_comm = bytes(event.comm).decode("utf-8")
        if cfg["filter_pid"] is not None and e_pid != cfg["filter_pid"]:
            return
        if cfg["filter_comm"] is not None and e_comm != cfg["filter_comm"]:
            return

        # Set the start point for relative timestamps if necessary
        if start_ns == 0:
            start_ns = event.timestamp_ns

        # Get relevant event fields
        time_s = (float(event.timestamp_ns - start_ns)) / 1000000000
        e_tid = event.tid
        e_type = get_event_type(event.type)
        e_len = event.data_len

        # Print event log
        print(
            "%-18.9f %-16s %-6d %-6d %-5s %-6d" % (
                time_s,
                e_comm,
                e_pid,
                e_tid,
                e_type,
                e_len
            )
        )

        # Encode data for output
        enc_data = None
        if cfg["encoding"] == "base64":
            enc_data = base64.b64encode(
                event.data[:event.data_len]
            ).decode("utf-8")
        else:
            enc_data = repr(event.data[:event.data_len])

        # If an "out_path" has been specified then collect the event
        # ready for writing later. Otherwise simply log repr(data) to
        # stdout.
        if cfg["out_path"]:

            # Create a dict for this PID if necessary
            if e_pid not in state["capture"]:
                state["capture"][e_pid] = {
                    "comm": e_comm,
                    "threads": {},
                }

            # Create an event list for this TID if necessary
            if e_tid not in state["capture"][e_pid]["threads"]:
                state["capture"][e_pid]["threads"][e_tid] = []

            # Write this event to the PID/TID list
            state["capture"][e_pid]["threads"][e_tid].append({
                "ts": time_s,
                "type": e_type,
                "data": enc_data,
            })

        else:
            print(enc_data)

    # Open the BPF perf buffer and pass events to handle_event()
    bpf["tls_events"].open_perf_buffer(handle_event)

    state = {
        "capture": {},
    }

    # Poll the buffer for events. On KeyboardInterrupt call
    # write_output() to save captures to a file if necessary.
    while 1:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            write_output(cfg, state)
            break


def main():
    cfg = get_cfg()
    b = setup_bpf()
    if b is None:
        return

    if cfg["filter_comm"] is not None:
        print("Filtering on command name == \"{}\"".format(cfg["filter_comm"]))
    if cfg["filter_pid"] is not None:
        print("Filtering on PID == {}".format(cfg["filter_pid"]))

    # Print output header
    print(
        "%-18s %-16s %-6s %-6s %-5s %-6s" % (
            "TIME(s)",
            "COMM",
            "PID",
            "TID",
            "TYPE",
            "LEN(b)"
        )
    )

    # Start capture
    perf_loop(cfg, b)


if __name__ == '__main__':
    main()
