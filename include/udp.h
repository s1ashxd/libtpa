/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024, libtpa contributors
 */
#ifndef _UDP_H_
#define _UDP_H_

#include <stdint.h>

#include "dev.h"
#include "packet.h"

#define UDP_RXQ_SIZE		BATCH_SIZE

struct udp_rxq {
	uint16_t count;
	struct packet *pkts[UDP_RXQ_SIZE];
};

struct tpa_worker;
struct tpa_udp_pkt;

static inline void udp_rxq_init(struct udp_rxq *rxq)
{
	rxq->count = 0;
}

int udp_input(struct tpa_worker *worker);
int udp_output(struct tpa_worker *worker);

int udp_offload_init(uint16_t *ports, int nr_port);

#endif
