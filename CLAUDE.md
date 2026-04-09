# libtpa

Fork of [bytedance/libtpa](https://github.com/bytedance/libtpa) — DPDK-based userspace TCP stack with added dedicated UDP queue support and zero-copy receive for Rust FFI consumers (QUIC, Solana shreds, etc.).

## Build

```bash
# Dependencies (Debian/Ubuntu)
./buildtools/install-dep.deb.sh --with-meson

# Default build (DPDK v20.11.3, Mellanox, release)
make

# Override DPDK version or NIC type
DPDK_VERSION=v22.11 make
NIC_TYPE=mlnx make            # default; adds -DNIC_MLNX

# Debug / AddressSanitizer
BUILD_MODE=debug make
BUILD_MODE=asan  make

# Install (libs → /usr/share/tpa/, bins → /usr/bin/)
make install
```

Output artifacts: `libtpa.a`, `libtpa.so`, `libtpa.pc` in `build/`.

## Tests

```bash
make -C test/unit              # compile unit tests (131 programs)
cd test/rj && ./rj             # Ruby integration runner
```

## Architecture

```
src/
  dpdk.c          DPDK EAL init, port/queue setup, mempool allocation
  tpa.c           tpa_init() entry point, orchestrates full init sequence
  dev.c           Device state, rxq/txq array allocation
  worker.c        Per-thread worker loop: RX → TCP input → TCP output → UDP input
  offload.c       RTE Flow rules (RSS, single-queue, TCP socket offload)
  udp.c           UDP send/recv (worker-based) + dedicated queue zero-copy recv
  tcp/
    tcp_input.c   Packet classification, TCP state machine input
    tcp_output.c  TCP header construction, zero-copy TX, TSO
  sock.c          Socket table, connection lifecycle
  neigh.c         ARP/NDP neighbor resolution
include/
  api/tpa.h       Public C API (single header, FFI-friendly)
  cfg.h           struct tpa_cfg — global config (nr_worker, nr_udp_queue, ...)
  dev.h           Inline TX/RX queue ops (dev_port_txq_enqueue, rte_eth_tx_burst)
  packet.h        struct packet wrapping rte_mbuf, parse_udp_packet, packet_alloc/free
  worker.h        struct tpa_worker, udp_rx_enqueue
  offload.h       Offload function declarations
  sock.h          struct tcp_sock, eth_ip_hdr, init_tpa_ip_from_pkt
  udp.h           struct udp_rxq (64 slots), udp_input/output declarations
```

## Key Design Constraints

- **One DPDK EAL per process** — `rte_eal_init()` called once in `dpdk.c:612`. Cannot create a second instance.
- **Flow isolation enabled** — `rte_flow_isolate(port, 1)` in `dpdk.c:249`. Packets without a matching RTE Flow rule are dropped.
- **Worker ↔ queue 1:1 mapping** — `worker->queue = worker->id` (`worker.c:35`). Workers [0, nr_worker) own DPDK queues [0, nr_worker).
- **RSS distributes only to worker queues** — `add_rss_action()` in `offload.c:345` uses `tpa_cfg.nr_worker` as queue count, never includes dedicated queues.
- **tpa_worker_run() is the only RX path for workers** — drives `rte_eth_rx_burst`, classifies TCP vs UDP, enqueues to udp_rxq.
- **`struct packet` embeds `rte_mbuf` at offset 0** — cast between `struct packet *` and `struct rte_mbuf *` is safe.
- **BATCH_SIZE = 64** — hard limit for TX/RX batch operations (`dev.h:21`).
- **UDP_RXQ_SIZE = 64** — per-worker UDP receive queue depth (`udp.h:13`). Drain frequently.

## Fork Additions

### Dedicated UDP Queues (zero-copy RX)

DPDK queues [nr_worker, nr_worker + nr_udp_queue) are independent of workers. Each has its own RTE Flow rules (single-queue, not RSS) and a direct `rte_eth_rx_burst` poll path that bypasses TCP processing entirely.

Changed files and what they do:

| File | Change |
|------|--------|
| `cfg.h` | `nr_udp_queue` field in `struct tpa_cfg` |
| `tpa.c` | `tpa_init_with_udp_queues()` passes `nr_worker + nr_udp_queue` to `dpdk_init()` |
| `dev.c` | `dev_port_init()` sizes rxq/txq arrays for total queue count |
| `offload.c` | `udp_offload_init_queue()` creates single-queue UDP flow rules. Uses module-level `udp_queue_offload_lists[]` with monotonic `udp_queue_offload_next` counter (safe across multiple calls) |
| `udp.c` | `tpa_udp_queue_init()`, `tpa_udp_queue_recv()`, `tpa_udp_pkt_zc_free()` |
| `tpa.h` | `struct tpa_udp_pkt_zc`, all new API declarations |

### Queue Index Layout

```
DPDK queues:  [0] [1] ... [N-1]  [N] [N+1] ... [N+M-1]
              ├── workers ──────┤ ├── dedicated UDP ────┤
              RSS for TCP+QUIC    single-queue flow rules
```

### Zero-Copy Contract

`tpa_udp_queue_recv()` returns `tpa_udp_pkt_zc.payload` pointing directly into the DPDK mbuf DMA buffer. The mbuf is held until `tpa_udp_pkt_zc_free()` is called. Holding mbufs too long starves the mempool and causes packet drops.

## Rust FFI Bindings

### Types

```rust
use std::ffi::c_void;
use std::os::raw::c_int;

#[repr(C)]
pub struct TpaIp {
    pub bytes: [u8; 16],
}

impl TpaIp {
    pub fn ipv4(addr: std::net::Ipv4Addr) -> Self {
        let mut ip = TpaIp { bytes: [0; 16] };
        ip.bytes[8..12].copy_from_slice(&0xffff0000u32.to_ne_bytes());
        ip.bytes[12..16].copy_from_slice(&addr.octets());
        ip
    }
}

#[repr(C)]
pub struct TpaWorker {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct TpaUdpPkt {
    pub buf: *mut c_void,
    pub len: u16,
    pub remote_ip: TpaIp,
    pub remote_port: u16, // network byte order
    pub local_port: u16,  // network byte order
}

#[repr(C)]
pub struct TpaUdpPktZc {
    pub payload: *const c_void,
    pub len: u16,
    pub remote_ip: TpaIp,
    pub remote_port: u16, // network byte order
    pub local_port: u16,  // network byte order
    pub _opaque: *mut c_void,
}

#[repr(C, packed)]
pub struct TpaSockOpts {
    pub listen_scaling: u64, // bitfield: bit 0 = listen_scaling
    pub data: *mut c_void,
    pub local_port: u16,
    pub _reserved: [u8; 110],
}
```

### Extern Functions

```rust
extern "C" {
    // Init
    pub fn tpa_init(nr_worker: c_int) -> c_int;
    pub fn tpa_init_with_udp_queues(nr_worker: c_int, nr_udp_queue: c_int) -> c_int;

    // Workers
    pub fn tpa_worker_init() -> *mut TpaWorker;
    pub fn tpa_worker_run(worker: *mut TpaWorker);

    // TCP
    pub fn tpa_connect_to(server: *const i8, port: u16, opts: *const TpaSockOpts) -> c_int;
    pub fn tpa_listen_on(local: *const i8, port: u16, opts: *const TpaSockOpts) -> c_int;
    pub fn tpa_accept_burst(worker: *mut TpaWorker, sid: *mut c_int, nr_sid: c_int) -> c_int;
    pub fn tpa_write(sid: c_int, buf: *const c_void, count: usize) -> isize;
    pub fn tpa_close(sid: c_int);

    // UDP (worker-based, copies payload)
    pub fn tpa_udp_init(ports: *mut u16, nr_port: c_int) -> c_int;
    pub fn tpa_udp_send_batch(
        worker: *mut TpaWorker, pkts: *const TpaUdpPkt, count: c_int,
    ) -> c_int;
    pub fn tpa_udp_recv_batch(
        worker: *mut TpaWorker, pkts: *mut TpaUdpPkt, max_count: c_int,
    ) -> c_int;

    // Dedicated UDP queue (zero-copy)
    pub fn tpa_udp_queue_init(queue_idx: c_int, ports: *mut u16, nr_port: c_int) -> c_int;
    pub fn tpa_udp_queue_recv(
        queue_idx: c_int, pkts: *mut TpaUdpPktZc, max_count: c_int,
    ) -> c_int;
    pub fn tpa_udp_pkt_zc_free(pkts: *mut TpaUdpPktZc, count: c_int);

    // Memory registration (for zero-copy TX with Mellanox)
    pub fn tpa_extmem_register(
        virt_addr: *mut c_void, len: usize, phys_addrs: *mut u64,
        nr_page: c_int, page_size: usize,
    ) -> c_int;
}
```

### Example: Solana Shreds + QUIC + HTTP

```rust
use std::mem::MaybeUninit;
use std::slice;

const MAX_BATCH: usize = 64;

unsafe {
    // 8 workers + 1 dedicated UDP queue for shreds
    assert_eq!(tpa_init_with_udp_queues(8, 1), 0);

    // QUIC port 443 → RSS across workers 0..7
    let mut quic_ports = [443u16.to_be()];
    tpa_udp_init(quic_ports.as_mut_ptr(), 1);

    // Solana shreds port 8001 → dedicated queue 0 (DPDK queue 8)
    let mut shred_ports = [8001u16.to_be()];
    tpa_udp_queue_init(0, shred_ports.as_mut_ptr(), 1);

    // Shred receiver thread (dedicated queue, zero-copy)
    std::thread::spawn(|| {
        let mut pkts = [MaybeUninit::<TpaUdpPktZc>::zeroed(); MAX_BATCH];
        loop {
            let n = tpa_udp_queue_recv(0, pkts.as_mut_ptr().cast(), MAX_BATCH as _);
            if n > 0 {
                for i in 0..n as usize {
                    let pkt = pkts[i].assume_init_ref();
                    let shred = slice::from_raw_parts(
                        pkt.payload as *const u8,
                        pkt.len as usize,
                    );
                    process_shred(shred);
                }
                tpa_udp_pkt_zc_free(pkts.as_mut_ptr().cast(), n);
            }
        }
    });

    // QUIC + HTTP worker threads
    for _ in 0..8 {
        std::thread::spawn(|| {
            let worker = tpa_worker_init();
            assert!(!worker.is_null());

            let mut rx = [MaybeUninit::<TpaUdpPkt>::zeroed(); MAX_BATCH];
            loop {
                tpa_worker_run(worker);

                // Receive QUIC packets
                let n = tpa_udp_recv_batch(worker, rx.as_mut_ptr().cast(), MAX_BATCH as _);
                for i in 0..n as usize {
                    let pkt = rx[i].assume_init_ref();
                    handle_quic_packet(pkt);
                }

                // TCP (HTTP) via tpa_accept_burst / tpa_write / tpa_close
            }
        });
    }
}
```

### Linking (build.rs)

```rust
fn main() {
    println!("cargo:rustc-link-search=/usr/share/tpa");
    println!("cargo:rustc-link-lib=static=tpa");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=numa");
    println!("cargo:rustc-link-lib=pcap");
    // Mellanox only:
    println!("cargo:rustc-link-lib=ibverbs");
    println!("cargo:rustc-link-lib=mlx5");
}
```

## Gotchas

- **All ports in network byte order** — `tpa_udp_pkt`, `tpa_udp_pkt_zc`, and port arrays passed to `tpa_udp_init`/`tpa_udp_queue_init` use `u16::to_be()`.
- **`tpa_worker_run()` is mandatory** — without it, RX queues for worker-based UDP/TCP are never polled. Dedicated queue `tpa_udp_queue_recv()` is the exception (polls directly).
- **Do not hold zero-copy mbufs** — process `tpa_udp_pkt_zc` and call `tpa_udp_pkt_zc_free()` in the same loop iteration. At 200K pps with 100us hold time, ~20 mbufs in flight is fine. 50ms hold → pool exhaustion.
- **Hugepages required** — DPDK needs hugepages allocated before launch (`echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`).
- **Mellanox NICs only** — flow bifurcation (coexistence with kernel stack) requires hardware flow steering. Currently only MLX5 NICs are supported.
- **Max 64 UDP listen ports** per `tpa_udp_init()` or `tpa_udp_queue_init()` call — enforced in `offload.c`.
- **`NIC_MLNX` compile flag** — controls checksum offload path. With Mellanox, NIC computes checksums automatically; without, pseudo-header checksum is pre-calculated in software (`udp.c:167-175`).
- **`tpa_init` acquires process-wide flock** — only one libtpa instance per process. Second call fails.

## Configuration

Set `TPA_CFG` environment variable or point to a config file:

```
net {
    name = eth0
    ip = 192.168.1.10
    mask = 255.255.255.0
    gw = 192.168.1.1
}
dpdk {
    pci = 0000:00:05.0
}
```

Key env vars: `TPA_CFG`, `TPA_ETH_DEV`, `TPA_ID`.
