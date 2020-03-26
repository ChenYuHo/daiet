/**
 * DAIET project
 * author: amedeo.sapio@kaust.edu.sa
 */

#include "ps.hpp"
#include "common.hpp"
#include "utils.hpp"
#include "params.hpp"
#include "stats.hpp"

#ifdef TIMERS
#include <unordered_map>
#endif

using namespace std;

namespace daiet {

    struct mac_ip_pair {
        struct rte_ether_addr mac;
        uint32_t be_ip;
    };

    thread_local static uint32_t num_updates;
    thread_local static mac_ip_pair* ps_workers_ip_to_mac;
    thread_local static uint32_t known_workers = 0;

    thread_local static int32_t** ps_aggregated_messages;
    thread_local static int16_t* ps_aggregated_exp;
    thread_local static uint32_t* ps_received_message_counters;

    thread_local static uint16_t ps_port_be;

#ifdef TIMERS
    thread_local static unordered_map<uint32_t, uint32_t> ip_to_worker_idx;
#endif

    thread_local static uint16_t ps_id;
    thread_local static struct rte_mempool *pool;
    thread_local static struct rte_mbuf** clone_burst;
    thread_local static struct rte_mbuf* cache_packet = NULL;
    thread_local static uint64_t ps_tx = 0;

#ifdef DEBUG
    __rte_always_inline struct daiet_hdr * is_daiet_pkt_to_ps(struct rte_ether_hdr* eth_hdr, uint16_t size) {

        int idx;
        uint16_t etherType;
        struct rte_ipv4_hdr* ip_hdr;
        struct rte_udp_hdr* rte_udp_hdr;

        idx = sizeof(struct rte_ether_hdr);
        etherType = rte_be_to_cpu_16(eth_hdr->ether_type);

        if (etherType == RTE_ETHER_TYPE_IPV4 && size >= idx + sizeof(struct rte_ipv4_hdr)) {

            idx += sizeof(struct rte_ipv4_hdr);
            ip_hdr = (struct rte_ipv4_hdr *) (eth_hdr + 1);

            if (ip_hdr->next_proto_id == IPPROTO_UDP && size >= idx + sizeof(struct rte_udp_hdr)) {
                idx += sizeof(struct rte_udp_hdr);
                rte_udp_hdr = (struct rte_udp_hdr *) (ip_hdr + 1);

                if (rte_udp_hdr->dst_port == ps_port_be && size >= idx + sizeof(struct daiet_hdr)) {

                    return (struct daiet_hdr *) (rte_udp_hdr + 1);
                }
            }
        }
        return NULL;
    }
#endif

    __rte_always_inline void ps_msg_setup(struct daiet_hdr * daiet, uint16_t set_pool_index) {

        struct entry_hdr *entry;
        struct exp_hdr * exp = (struct exp_hdr *) (((struct entry_hdr *) (daiet + 1)) + num_updates);
        exp->exp = rte_cpu_to_be_16((uint16_t) ps_aggregated_exp[set_pool_index]);
        ps_aggregated_exp[set_pool_index] = -126;
        int32_t* base_ptr = ps_aggregated_messages[set_pool_index];

        entry = (struct entry_hdr *) (daiet + 1);
        for (uint32_t i = 0; i < num_updates; i++, entry++) {
            entry->upd = rte_cpu_to_be_32(base_ptr[i]);
            base_ptr[i] = 0;
        }
    }

    __rte_always_inline void register_worker(uint32_t be_src_ip, struct rte_ether_addr src_mac) {

        bool found = false;
        for (uint32_t i = 0; i < known_workers && !found; i++) {
            if (ps_workers_ip_to_mac[i].be_ip==be_src_ip)
                found = true;
        }
        if (!found) {
            // New worker
            char ipstring[INET_ADDRSTRLEN];
            if (unlikely(inet_ntop(AF_INET, &be_src_ip, ipstring, INET_ADDRSTRLEN) == NULL)) {
                LOG_FATAL("Wrong IP: error " + to_string(errno));
            }
            LOG_INFO("Worker "+to_string(known_workers)+" : "+ to_string(be_src_ip) + " " + string(ipstring) + " " + mac_to_str(src_mac));
            ps_workers_ip_to_mac[known_workers].mac = src_mac;
            ps_workers_ip_to_mac[known_workers].be_ip = be_src_ip;

#ifdef TIMERS
            ip_to_worker_idx.insert(make_pair(be_src_ip, known_workers));
#endif

            known_workers++;
        }
    }

    /* Returns true if the aggregation for the offset is complete */
    __rte_always_inline bool ps_aggregate_message(struct daiet_hdr* daiet, uint16_t set_pool_index, uint16_t num_workers) {

        struct entry_hdr * entry = (struct entry_hdr *) (daiet + 1);
        struct exp_hdr * exp = (struct exp_hdr *) (((struct entry_hdr *) (daiet + 1)) + num_updates);
        int32_t* base_ptr = ps_aggregated_messages[set_pool_index];
        ps_aggregated_exp[set_pool_index] = max((int16_t)rte_be_to_cpu_16(exp->exp), ps_aggregated_exp[set_pool_index]);

        for (uint32_t i = 0; i < num_updates; i++, entry++) {
            base_ptr[i] += rte_be_to_cpu_32(entry->upd);
        }

        ps_received_message_counters[set_pool_index]--;

        if (unlikely(ps_received_message_counters[set_pool_index]==0)) {
            ps_received_message_counters[set_pool_index] = num_workers;
            return true;
        }

        return false;
    }

    __rte_always_inline void send_updates(uint16_t set_pool_index, uint32_t tsi, uint16_t original_pool_index, uint16_t num_workers) {

        rte_prefetch0 (rte_pktmbuf_mtod(cache_packet, void *));
        struct rte_ether_hdr* eth = rte_pktmbuf_mtod(cache_packet, struct rte_ether_hdr *);
        struct rte_ipv4_hdr* ip;
        struct daiet_hdr* daiet = (struct daiet_hdr *) ((uint8_t *) (eth+1) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));

        ps_msg_setup(daiet, set_pool_index);

        daiet->tsi = tsi;
        daiet->pool_index = original_pool_index;

        // Allocate pkt burst
        if (unlikely(rte_pktmbuf_alloc_bulk(pool, clone_burst, num_workers) < 0))
            LOG_FATAL("Cannot allocate clone burst");

        for (unsigned i = 0; i < num_workers; i++) {

            // We need to deep copy as we will send different packets at the same time
            deep_copy_single_segment_pkt(clone_burst[i], cache_packet);

            eth = rte_pktmbuf_mtod(clone_burst[i], struct rte_ether_hdr *);

            // Set dst MAC
            rte_ether_addr_copy(&(ps_workers_ip_to_mac[i].mac), &(eth->d_addr));

            // Set dst IP
            ip = (struct rte_ipv4_hdr *) (eth + 1);
            ip->dst_addr = ps_workers_ip_to_mac[i].be_ip;
        }

        unsigned sent = 0;
        do {
            sent += rte_eth_tx_burst(dpdk_par.portid, ps_id, clone_burst, num_workers);
        } while (sent < num_workers);
        ps_tx += num_workers;
    }

#ifdef TIMERS
    __rte_always_inline void resend_update(uint32_t be_src_ip, uint32_t worker_idx, uint16_t set_pool_index, uint32_t tsi, uint16_t original_pool_index) {

        rte_prefetch0 (rte_pktmbuf_mtod(cache_packet, void *));
        struct rte_ether_hdr* eth = rte_pktmbuf_mtod(cache_packet, struct rte_ether_hdr *);
        struct rte_ipv4_hdr* ip;
        struct daiet_hdr* daiet = (struct daiet_hdr *) ((uint8_t *) (eth+1) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));

        ps_msg_setup(daiet, set_pool_index);

        daiet->tsi = tsi;
        daiet->pool_index = original_pool_index;

        rte_mbuf_refcnt_update(cache_packet,1);

        // Set dst MAC
        rte_ether_addr_copy(&(ps_workers_ip_to_mac[worker_idx].mac), &(eth->d_addr));

        // Set dst IP
        ip = (struct rte_ipv4_hdr *) (eth + 1);
        ip->dst_addr = be_src_ip;

        while (rte_eth_tx_burst(dpdk_par.portid, ps_id, &cache_packet, 1)==0)
            ;

        LOG_DEBUG("Retransmission: sent tsi: " +to_string(tsi) +" to worker "+to_string(worker_idx));
        ps_tx += 1;
    }
#endif

    void ps_setup() {
    }

    void ps_cleanup() {
    }

    int ps(void*) {

        unsigned lcore_id;
        unsigned nb_rx = 0, j = 0, i = 0;

        const uint16_t num_workers = daiet_par.getNumWorkers();
        const uint32_t max_num_pending_messages = daiet_par.getMaxNumPendingMessages();

        num_updates = daiet_par.getNumUpdates();
        uint64_t ps_rx = 0;

        string pool_name = "ps_pool";
        struct rte_mbuf** pkts_burst;
        struct rte_mbuf* m;

        struct rte_ether_hdr* eth;
        struct rte_ipv4_hdr * ip;
        struct rte_udp_hdr * udp;
        struct daiet_hdr* daiet;

        uint16_t pool_index = 0, start_pool_index = 0, set_pool_index = 0, set = 0;

#ifdef TIMERS
        const uint32_t monoset_bitmap_size = max_num_pending_messages * num_workers;
        uint32_t bitmap_index = 0, bitmap_shadow_index = 0, worker_idx = 0;

        // Bitmap
        void* bitmap_mem;
        uint32_t bitmap_size;
        struct rte_bitmap *bitmap;
#endif

        // Get core ID
        lcore_id = rte_lcore_id();
        ps_id = dpdk_data.core_to_thread_id[lcore_id];
        LOG_DEBUG("PS core: " + to_string(lcore_id) + " PS id: " + to_string(ps_id));

        start_pool_index = ps_id * max_num_pending_messages;
        ps_port_be = rte_cpu_to_be_16(daiet_par.getBasePsPort() + ps_id);


#ifdef TIMERS
        ps_aggregated_exp = (int16_t*) rte_zmalloc_socket(NULL, 2 * max_num_pending_messages * sizeof(int16_t), RTE_CACHE_LINE_SIZE, rte_socket_id());
        if (ps_aggregated_exp == NULL)
            LOG_FATAL("Failed PS aggregated exponent allocation!");
        memset(ps_aggregated_exp, -126, 2 * max_num_pending_messages * sizeof(int16_t));

        ps_aggregated_messages = (int32_t**) rte_malloc_socket(NULL, 2 * max_num_pending_messages * sizeof(int32_t*), RTE_CACHE_LINE_SIZE, rte_socket_id());
#else
        ps_aggregated_exp = (int16_t*) rte_zmalloc_socket(NULL, max_num_pending_messages * sizeof(int16_t), RTE_CACHE_LINE_SIZE, rte_socket_id());
        if (ps_aggregated_exp == NULL)
            LOG_FATAL("Failed PS aggregated exponent allocation!");
        memset(ps_aggregated_exp, -126, max_num_pending_messages * sizeof(int16_t));

        ps_aggregated_messages = (int32_t**) rte_malloc_socket(NULL, max_num_pending_messages * sizeof(int32_t*), RTE_CACHE_LINE_SIZE, rte_socket_id());
#endif

        if (ps_aggregated_messages == NULL)
            LOG_FATAL("Failed PS aggregated messages allocation!");

#ifdef TIMERS
        for (i = 0; i < 2 * max_num_pending_messages; i++) {
#else
        for (i = 0; i < max_num_pending_messages; i++) {
#endif
            ps_aggregated_messages[i] = (int32_t*) rte_zmalloc_socket(NULL, num_updates * sizeof(int32_t), RTE_CACHE_LINE_SIZE, rte_socket_id());
            if (ps_aggregated_messages[i] == NULL)
                LOG_FATAL("Failed PS aggregated messages allocation: element " + to_string(i));
        }

#ifdef TIMERS
        ps_received_message_counters = (uint32_t*) rte_zmalloc_socket(NULL, 2 * max_num_pending_messages * sizeof(uint32_t), RTE_CACHE_LINE_SIZE, rte_socket_id());
#else
        ps_received_message_counters = (uint32_t*) rte_zmalloc_socket(NULL, max_num_pending_messages * sizeof(uint32_t), RTE_CACHE_LINE_SIZE, rte_socket_id());
#endif

        if (ps_received_message_counters == NULL)
            LOG_FATAL("Failed PS aggregated messages allocation!");

#ifdef TIMERS
        for (i = 0; i < 2 * max_num_pending_messages; i++) {
#else
        for (i = 0; i < max_num_pending_messages; i++) {
#endif
            ps_received_message_counters[i] = num_workers;
        }

        ps_workers_ip_to_mac = (mac_ip_pair*) rte_zmalloc_socket(NULL, num_workers * sizeof(struct mac_ip_pair), RTE_CACHE_LINE_SIZE, rte_socket_id());
        if (ps_workers_ip_to_mac == NULL)
            LOG_FATAL("PS thread: cannot allocate ps_workers_ip_to_mac");

        pkts_burst = (rte_mbuf **) rte_malloc_socket(NULL, dpdk_par.burst_rx * sizeof(struct rte_mbuf*), RTE_CACHE_LINE_SIZE, rte_socket_id());
        if (pkts_burst == NULL)
            LOG_FATAL("PS thread: cannot allocate pkts burst");

        clone_burst = (rte_mbuf **) rte_malloc_socket(NULL, num_workers * sizeof(struct rte_mbuf*), RTE_CACHE_LINE_SIZE, rte_socket_id());
        if (clone_burst == NULL)
            LOG_FATAL("PS thread: cannot allocate clone burst");

        // Init the buffer pool
        pool_name = pool_name + to_string(ps_id);
        pool = rte_pktmbuf_pool_create(pool_name.c_str(), dpdk_par.pool_size, dpdk_par.pool_cache_size, 0, dpdk_data.pool_buffer_size, rte_socket_id());
        if (pool == NULL)
            LOG_FATAL("Cannot init mbuf pool: " + string(rte_strerror(rte_errno)));

#ifdef TIMERS
        // Initialize bitmap
        bitmap_size = rte_bitmap_get_memory_footprint(2 * monoset_bitmap_size);
        if (unlikely(bitmap_size == 0)) {
            LOG_FATAL("Bitmap failed");
        }

        bitmap_mem = rte_zmalloc_socket("bitmap", bitmap_size, RTE_CACHE_LINE_SIZE, rte_socket_id());
        if (unlikely(bitmap_mem == NULL)) {
            LOG_FATAL("Cannot allocate bitmap");
        }

        bitmap = rte_bitmap_init(2 * monoset_bitmap_size, (uint8_t*) bitmap_mem, bitmap_size);
        if (unlikely(bitmap == NULL)) {
            LOG_FATAL("Failed to init bitmap");
        }
        rte_bitmap_reset(bitmap);
#endif

        while (!force_quit) {

            nb_rx = rte_eth_rx_burst(dpdk_par.portid, ps_id, pkts_burst, dpdk_par.burst_rx);

            for (j = 0; j < nb_rx; j++) {

                m = pkts_burst[j];

                rte_prefetch0 (rte_pktmbuf_mtod(m, void *));
                eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

#ifdef DEBUG
                daiet = is_daiet_pkt_to_ps(eth, m->data_len);
                if (likely(daiet != NULL)) {
#else
                    daiet = (struct daiet_hdr *) ((uint8_t *) (eth+1) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
#endif

                    ps_rx++;
                    ip = (struct rte_ipv4_hdr *) (eth + 1);

                    if (unlikely(known_workers < num_workers)) {
                        register_worker(ip->src_addr, eth->s_addr);
                    }

                    udp = (struct rte_udp_hdr *) (ip + 1);

                    pool_index = rte_be_to_cpu_16(daiet->pool_index);
                    set = ((pool_index >> 15) & 1);
                    pool_index = (pool_index & 0x7FFF) - start_pool_index;

#ifndef TIMERS
                    set_pool_index = pool_index;
#else
                    set_pool_index = (set == 0) ? pool_index : pool_index + max_num_pending_messages;
                    worker_idx = ip_to_worker_idx.find(ip->src_addr)->second;

                    if (set == 0) {
                        bitmap_index = pool_index + worker_idx * max_num_pending_messages;
                        bitmap_shadow_index = bitmap_index + monoset_bitmap_size;
                    } else {
                        bitmap_shadow_index = pool_index + worker_idx * max_num_pending_messages;
                        bitmap_index = bitmap_shadow_index + monoset_bitmap_size;
                    }

                    if (rte_bitmap_get(bitmap, bitmap_index) == 0) {

                        rte_bitmap_set(bitmap, bitmap_index);
                        rte_bitmap_clear(bitmap, bitmap_shadow_index);
#endif

                        if (unlikely(cache_packet == NULL)) {
                            // Checksum offload
                            m->l2_len = sizeof(struct rte_ether_hdr);
                            m->l3_len = sizeof(struct rte_ipv4_hdr);
                            m->ol_flags |= daiet_par.getTxFlags();
                            // Set src MAC
                            rte_ether_addr_copy(&(eth->d_addr), &(eth->s_addr));
                            // Set src IP
                            ip->hdr_checksum = 0;
                            ip->src_addr = ip->dst_addr;
                            // Swap ports
                            swap((uint16_t&) (udp->dst_port), (uint16_t&) (udp->src_port));
                            udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, m->ol_flags);
                            cache_packet = rte_pktmbuf_clone(m, pool);
                            if (unlikely(cache_packet == NULL))
                                LOG_FATAL("failed to allocate cache packet");
                        }

                        if (ps_aggregate_message(daiet, set_pool_index, num_workers)) {
                            // Done aggregating
                            send_updates(set_pool_index, daiet->tsi, daiet->pool_index, num_workers);
                        }
#ifdef TIMERS
                    } else {
                        // check if needed to send the shadow buffer
                        if (ps_received_message_counters[set_pool_index] == num_workers) {
                            resend_updates(ip->src_addr, worker_idx, set_pool_index, daiet->tsi, daiet->pool_index);
                        }
                    }
#endif

#ifdef DEBUG
                }
#endif
                rte_pktmbuf_free(m);
            }
        }

        // Set stats
        pkt_stats.set_ps(ps_id, ps_tx, ps_rx);

        // Cleanup

        rte_pktmbuf_free(cache_packet);
        rte_free(clone_burst);
        rte_free(pkts_burst);
        rte_free(ps_workers_ip_to_mac);

#ifdef TIMERS
        rte_bitmap_free(bitmap);
        rte_free(bitmap_mem);
#endif

        rte_free(ps_received_message_counters);

#ifdef TIMERS
        for (uint32_t i = 0; i < 2 * max_num_pending_messages; i++) {
#else
        for (uint32_t i = 0; i < max_num_pending_messages; i++) {
#endif
            rte_free(ps_aggregated_messages[i]);
        }

        rte_free(ps_aggregated_messages);
        rte_free(ps_aggregated_exp);

        return 0;
    }
}
