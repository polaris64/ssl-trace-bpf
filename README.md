# Linux `uprobe` SSL/TLS tracer

This Python script allows for system-wide tracing of plaintext SSL/TLS traffic.

## Usage

Run the `ssl-trace.py` script to start tracing.

Use `ssl-trace.py --help` to see command-line options.

## Requirements

  - Python 3
  - [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc)
  - Linux kernel supporting BPF uprobes

## Limitations

The script adds uprobes to `libssl` (`SSL_read` and `SSL_write`) and `libgnutls` (`gnutls_record_recv` and `gnutls_record_send`), meaning that any process using these shared library symbols will be traced. However if a program statically links to OpenSSL or GnuTLS then these calls will *not* be traced.
