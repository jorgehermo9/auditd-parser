// Wrapper header for bindgen to generate Rust bindings from Linux kernel headers

// Signal constants from Linux kernel
#include <signal.h>

// Architecture and audit constants from Linux kernel
#include <linux/elf-em.h>
#include <linux/audit.h>

// Socket address family constants
// Note: AF_* constants are defined in bits/socket.h which is included by sys/socket.h
#include <sys/socket.h>

// File mode and stat constants
#include <sys/stat.h>
