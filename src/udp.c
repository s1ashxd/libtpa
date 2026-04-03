/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024, libtpa contributors
 *
 * UDP transport path for external QUIC stacks.
 */
#include <stdio.h>

#include <rte_udp.h>
#include <rte_ip.h>

#include "tpa.h"
#include "worker.h"
#include "neigh.h"
#include "log.h"
#include "offload.h"

/*
 * Process buffered UDP packets from the per-worker UDP RX queue.
 * Called from tpa_worker_run after tcp_input_process.
 */
int udp_input(struct tpa_worker *worker)
{
	struct udp_rxq *rxq = &worker->udp_rxq;
	int count = rxq->count;
	int i;

	for (i = 0; i < count; i++) {
		struct packet *pkt = rxq->pkts[i];

		WORKER_STATS_INC(worker, UDP_PKT_RECV);
		WORKER_STATS_ADD(worker, UDP_BYTE_RECV, pkt->l5_len);
	}

	/* packets stay in rxq until tpa_udp_recv_batch drains them */
	return count;
}

/*
 * Flush any pending UDP TX. Currently a no-op since tpa_udp_send_batch
 * enqueues directly to dev_txq and flushes inline.
 */
int udp_output(struct tpa_worker *worker)
{
	(void)worker;
	return 0;
}

static inline void build_udp_hdr(struct eth_ip_hdr *net_hdr,
				 struct rte_udp_hdr *uh,
				 uint16_t src_port, uint16_t dst_port,
				 uint16_t payload_len, int is_ipv6)
{
	uint16_t udp_len = payload_len + sizeof(struct rte_udp_hdr);

	uh->src_port = src_port;
	uh->dst_port = dst_port;
	uh->dgram_len = htons(udp_len);
	uh->dgram_cksum = 0;

	if (!is_ipv6) {
		net_hdr->ip4.total_length = htons(sizeof(struct rte_ipv4_hdr) + udp_len);
		net_hdr->ip4.next_proto_id = IPPROTO_UDP;
		net_hdr->ip4.packet_id = 0;
		net_hdr->ip4.hdr_checksum = 0;
	} else {
		net_hdr->ip6.payload_len = htons(udp_len);
		net_hdr->ip6.proto = IPPROTO_UDP;
	}
}

static inline void set_udp_mbuf_offload(struct packet *pkt, int is_ipv6)
{
	struct rte_mbuf *m = &pkt->mbuf;

	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l4_len = sizeof(struct rte_udp_hdr);
	m->ol_flags = 0;

	if (!is_ipv6) {
		m->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
		m->l3_len = sizeof(struct rte_ipv4_hdr);
		m->packet_type = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
	} else {
		m->ol_flags = PKT_TX_IPV6 | PKT_TX_UDP_CKSUM;
		m->l3_len = sizeof(struct rte_ipv6_hdr);
		m->packet_type = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
	}
}

int tpa_udp_send_batch(struct tpa_worker *worker,
		       const struct tpa_udp_pkt *pkts, int count)
{
	struct packet *pkt;
	struct eth_ip_hdr *net_hdr;
	struct rte_udp_hdr *uh;
	struct rte_ether_hdr eth;
	struct tpa_ip local_ip;
	struct tpa_ip remote_ip;
	uint16_t port_id;
	int is_ipv6;
	int hdr_len;
	int sent = 0;
	int i;

	if (unlikely(count <= 0))
		return 0;

	count = RTE_MIN(count, BATCH_SIZE);
	port_id = dev_port_id_get();

	for (i = 0; i < count; i++) {
		const struct tpa_udp_pkt *upkt = &pkts[i];

		is_ipv6 = !tpa_ip_is_ipv4(&upkt->remote_ip);
		remote_ip = upkt->remote_ip;

		/* resolve dst MAC via ARP/NDP */
		if (eth_lookup(worker, &remote_ip, &eth) < 0) {
			WORKER_STATS_INC(worker, ERR_UDP_SEND_FAIL);
			continue;
		}

		/* set local IP from device */
		if (!is_ipv6)
			tpa_ip_set_ipv4(&local_ip, dev.ip4);
		else
			local_ip = dev.ip6.ip;

		/* allocate from generic pool (has full MTU data room) */
		pkt = packet_alloc(generic_pkt_pool);
		if (unlikely(!pkt)) {
			WORKER_STATS_INC(worker, ERR_UDP_ALLOC_FAIL);
			continue;
		}

		/* calculate header size and check fit */
		if (!is_ipv6)
			hdr_len = sizeof(struct rte_ether_hdr) +
				  sizeof(struct rte_ipv4_hdr) +
				  sizeof(struct rte_udp_hdr);
		else
			hdr_len = sizeof(struct rte_ether_hdr) +
				  sizeof(struct rte_ipv6_hdr) +
				  sizeof(struct rte_udp_hdr);

		/* build network headers */
		net_hdr = (struct eth_ip_hdr *)rte_pktmbuf_mtod(&pkt->mbuf, char *);
		init_net_hdr(net_hdr, &eth, &local_ip, &remote_ip);

		/* build UDP header */
		uh = (struct rte_udp_hdr *)((char *)net_hdr + hdr_len -
					    sizeof(struct rte_udp_hdr));
		build_udp_hdr(net_hdr, uh, upkt->local_port, upkt->remote_port,
			      upkt->len, is_ipv6);

		/* copy payload after headers */
		memcpy((char *)net_hdr + hdr_len, upkt->buf, upkt->len);

		/* set mbuf lengths */
		pkt->mbuf.data_len = hdr_len + upkt->len;
		pkt->mbuf.pkt_len  = hdr_len + upkt->len;

		/* set offload flags for NIC checksum */
		set_udp_mbuf_offload(pkt, is_ipv6);

#ifndef NIC_MLNX
		/* pseudo-header checksum for NIC offload */
		if (!is_ipv6)
			uh->dgram_cksum = rte_ipv4_phdr_cksum(&net_hdr->ip4,
							       pkt->mbuf.ol_flags);
		else
			uh->dgram_cksum = rte_ipv6_phdr_cksum(&net_hdr->ip6,
							       pkt->mbuf.ol_flags);
#endif

		/* enqueue to TX */
		if (dev_port_txq_enqueue(port_id, worker->queue, pkt) < 0) {
			WORKER_STATS_INC(worker, ERR_UDP_SEND_FAIL);
			packet_free(pkt);
			continue;
		}

		WORKER_STATS_INC(worker, UDP_PKT_XMIT);
		WORKER_STATS_ADD(worker, UDP_BYTE_XMIT, upkt->len);
		sent++;
	}

	/* flush TX immediately for low latency */
	dev_port_txq_flush(port_id, worker->queue);

	return sent;
}

int tpa_udp_recv_batch(struct tpa_worker *worker,
		       struct tpa_udp_pkt *pkts, int max_count)
{
	struct udp_rxq *rxq = &worker->udp_rxq;
	int count;
	int i;

	count = RTE_MIN(rxq->count, max_count);

	for (i = 0; i < count; i++) {
		struct packet *pkt = rxq->pkts[i];
		struct tpa_udp_pkt *upkt = &pkts[i];
		struct tpa_ip local_ip_tmp;
		uint16_t copy_len;

		/* extract remote address from IP header */
		init_tpa_ip_from_pkt(pkt, &upkt->remote_ip, &local_ip_tmp);
		upkt->remote_port = pkt->src_port;
		upkt->local_port  = pkt->dst_port;

		/* copy payload into user buffer */
		copy_len = RTE_MIN(pkt->l5_len, upkt->len);
		memcpy(upkt->buf, udp_payload_addr(pkt), copy_len);
		upkt->len = copy_len;

		packet_free(pkt);
	}

	/* shift remaining packets to front */
	if (count < rxq->count) {
		memmove(&rxq->pkts[0], &rxq->pkts[count],
			(rxq->count - count) * sizeof(struct packet *));
	}
	rxq->count -= count;

	return count;
}

int tpa_udp_init(uint16_t *listen_ports, int nr_port)
{
	return udp_offload_init(listen_ports, nr_port);
}

int tpa_udp_init_per_worker(uint16_t *ports, int nr_port, uint16_t worker_queue)
{
	return udp_offload_init_queue(ports, nr_port, worker_queue);
}

/* ------------------------------------------------------------------ */
/*  Dedicated UDP queue: zero-copy receive path                       */
/* ------------------------------------------------------------------ */

int tpa_udp_queue_init(int queue_idx, uint16_t *ports, int nr_port)
{
	uint16_t dpdk_queue;

	if (queue_idx < 0 || (uint32_t)queue_idx >= tpa_cfg.nr_udp_queue) {
		LOG_ERR("udp queue index %d out of range [0, %u)",
			queue_idx, tpa_cfg.nr_udp_queue);
		return -1;
	}

	dpdk_queue = tpa_cfg.nr_worker + queue_idx;
	return udp_offload_init_queue(ports, nr_port, dpdk_queue);
}

int tpa_udp_queue_recv(int queue_idx,
		       struct tpa_udp_pkt_zc *pkts, int max_count)
{
	uint16_t dpdk_queue;
	struct packet *rx_pkts[BATCH_SIZE];
	struct tpa_ip local_ip_tmp;
	uint16_t port;
	uint16_t nb_rx;
	int count = 0;
	uint16_t i;

	if (unlikely(queue_idx < 0 ||
		     (uint32_t)queue_idx >= tpa_cfg.nr_udp_queue))
		return -1;

	dpdk_queue = tpa_cfg.nr_worker + queue_idx;
	max_count = RTE_MIN(max_count, BATCH_SIZE);

	for (port = 0; port < dev.nr_port && count < max_count; port++) {
		nb_rx = rte_eth_rx_burst(port, dpdk_queue,
					 (struct rte_mbuf **)rx_pkts,
					 max_count - count);
		if (unlikely(nb_rx == 0))
			continue;

		uint64_t batch_tsc = rte_rdtsc();

		for (i = 0; i < nb_rx; i++) {
			struct packet *pkt = rx_pkts[i];

			packet_init(pkt);

			if (unlikely(parse_udp_packet(pkt) != 0)) {
				packet_free(pkt);
				continue;
			}

			init_tpa_ip_from_pkt(pkt, &pkts[count].remote_ip,
					     &local_ip_tmp);
			pkts[count].payload     = udp_payload_addr(pkt);
			pkts[count].len         = pkt->l5_len;
			pkts[count].remote_port = pkt->src_port;
			pkts[count].local_port  = pkt->dst_port;
			pkts[count]._opaque     = pkt;
			pkts[count].recv_tsc     = batch_tsc;
			count++;
		}
	}

	return count;
}

void tpa_udp_pkt_zc_free(struct tpa_udp_pkt_zc *pkts, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (pkts[i]._opaque) {
			packet_free((struct packet *)pkts[i]._opaque);
			pkts[i]._opaque = NULL;
		}
	}
}

int tpa_udp_queue_recv_raw(int queue_idx,
			    struct tpa_raw_pkt *pkts, int max_count)
{
	uint16_t dpdk_queue;
	struct rte_mbuf *rx_mbufs[BATCH_SIZE];
	uint16_t port;
	uint16_t nb_rx;
	int count = 0;
	uint16_t i;

	if (unlikely(queue_idx < 0 ||
		     (uint32_t)queue_idx >= tpa_cfg.nr_udp_queue))
		return -1;

	dpdk_queue = tpa_cfg.nr_worker + queue_idx;
	max_count = RTE_MIN(max_count, BATCH_SIZE);

	for (port = 0; port < dev.nr_port && count < max_count; port++) {
		nb_rx = rte_eth_rx_burst(port, dpdk_queue,
					 rx_mbufs, max_count - count);
		if (unlikely(nb_rx == 0))
			continue;

		uint64_t batch_tsc = rte_rdtsc();

		for (i = 0; i < nb_rx; i++) {
			struct rte_mbuf *m = rx_mbufs[i];
			if (i + 1 < nb_rx)
				rte_prefetch0(rte_pktmbuf_mtod(rx_mbufs[i + 1],
							       void *));
			pkts[count].data     = rte_pktmbuf_mtod(m, const void *);
			pkts[count].data_len = m->data_len;
			pkts[count]._opaque  = m;
			pkts[count].recv_tsc  = batch_tsc;
			count++;
		}
	}

	return count;
}

void tpa_raw_pkt_free(struct tpa_raw_pkt *pkts, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (pkts[i]._opaque) {
			rte_pktmbuf_free((struct rte_mbuf *)pkts[i]._opaque);
			pkts[i]._opaque = NULL;
		}
	}
}

void tpa_raw_pkt_free_one(void *opaque)
{
	if (opaque)
		rte_pktmbuf_free((struct rte_mbuf *)opaque);
}
