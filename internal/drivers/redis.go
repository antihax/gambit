package drivers

import (
	"bufio"
	"log"
	"net"
	"strings"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/secmask/go-redisproto"
)

type redis struct {
	INFO string
}

func init() {
	s := &redis{}
	AddDriver(s)
}

func (s *redis) Patterns() [][]byte {
	return [][]byte{
		{0x2A, 0x31, 0x0D, 0x0A, 0x24},
		{0x2A, 0x32, 0x0D, 0x0A, 0x24},
	}
}

func (s *redis) out(sr string) string {
	return strings.Replace(sr, "\n", "\r\r\n", -1)
}

// [TODO] add fake command responses
func (s *redis) ServeTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("failed accept")
		}
		if mux, ok := c.(*muxconn.MuxConn); ok {
			glob := gctx.GetGlobalFromContext(mux.Context, "redis")

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()

				parser := redisproto.NewParser(conn)
				writer := redisproto.NewWriter(bufio.NewWriter(conn))
				for {
					conn.SetDeadline(time.Now().Add(time.Second * 5))
					command, err := parser.ReadCommand()

					l := glob.NewSession(conn.Sequence(), StoreHash(conn.Snapshot(), glob.Store))
					l.Logger.Info().Msg("redis knock")
					if err != nil {
						_, ok := err.(*redisproto.ProtocolError)
						if ok {
							writer.WriteError(err.Error())
							glob.LogError(err)
							return
						}
						return
					} else {
						cmd := strings.ToUpper(string(command.Get(0)))
						l.TriedActiveProbe(gctx.Value{Key: "opCode", Value: cmd})
						switch cmd {
						case "AUTH":
							l.TriedPassword("redis", string(command.Get(1)))
							writer.WriteBulkString("OK")
						case "CLIENT":
							switch strings.ToUpper(string(command.Get(1))) {
							case "LIST":
								writer.WriteBulkString(s.out(REDIS_CLIENT_LIST))
							default:
								writer.WriteBulkString("OK")
							}
						case "CONFIG":
							switch strings.ToUpper(string(command.Get(1))) {
							case "SET":
								writer.WriteBulkString("OK")
							default:
								writer.WriteBulkString("OK")
							}
						case "PING":
							writer.WriteBulkString("PONG")
						case "INFO":
							writer.WriteBulkString(s.out(REDIS_INFO))
						case "NONEXISTENT":
							writer.WriteError("ERR unknown command `NONEXISTENT`, with args beginning with:")
						default:
							writer.WriteBulkString("OK")
						}
					}
					if command.IsLast() {
						writer.Flush()
					}
				}
			}(mux)
		}
	}
}

const (
	REDIS_INFO = `redis_version:6.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:95eb037379d5f3f8
redis_mode:standalone
os:Linux 5.4.0-40-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:8.3.0
process_id:1
run_id:db625fae6f7f8d73d44d1f724f0635ec4ff91651
tcp_port:6379
uptime_in_seconds:3
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:5311634
executable:/data/redis-server
config_file:
io_threads_active:0

# Clients
connected_clients:1
client_recent_max_input_buffer:8
client_recent_max_output_buffer:0
blocked_clients:0
tracking_clients:0
clients_in_timeout_table:0

# Memory
used_memory:4962632
used_memory_human:4.73M
used_memory_rss:11755520
used_memory_rss_human:11.21M
used_memory_peak:5019320
used_memory_peak_human:4.79M
used_memory_peak_perc:98.87%
used_memory_overhead:825016
used_memory_startup:803152
used_memory_dataset:4137616
used_memory_dataset_perc:99.47%
allocator_allocated:5205216
allocator_active:5513216
allocator_resident:8429568
total_system_memory:16394342400
total_system_memory_human:15.27G
used_memory_lua:37888
used_memory_lua_human:37.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.06
allocator_frag_bytes:308000
allocator_rss_ratio:1.53
allocator_rss_bytes:2916352
rss_overhead_ratio:1.39
rss_overhead_bytes:3325952
mem_fragmentation_ratio:2.39
mem_fragmentation_bytes:6835400
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:20496
mem_aof_buffer:0
mem_allocator:jemalloc-5.1.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1632701583
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0
module_fork_in_progress:0
module_fork_last_cow_size:0

# Stats
total_connections_received:1
total_commands_processed:1
instantaneous_ops_per_sec:0
total_net_input_bytes:31
total_net_output_bytes:18609
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
expire_cycle_cpu_milliseconds:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0
tracking_total_keys:0
tracking_total_items:0
tracking_total_prefixes:0
unexpected_error_replies:0
total_reads_processed:2
total_writes_processed:1
io_threaded_reads_processed:0
io_threaded_writes_processed:0

# Replication
role:master
connected_slaves:0
master_replid:0f1bf39fce3b7c46e23c92bae22c59b53a31ecd0
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.037211
used_cpu_user:0.048442
used_cpu_sys_children:0.002745
used_cpu_user_children:0.004038

# Modules

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=27,expires=0,avg_ttl=0
127.0.0.1:6379>
root@empyrion:~# docker exec -it redis redis-cli INFO
# Server
redis_version:6.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:95eb037379d5f3f8
redis_mode:standalone
os:Linux 5.4.0-40-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:8.3.0
process_id:1
run_id:db625fae6f7f8d73d44d1f724f0635ec4ff91651
tcp_port:6379
uptime_in_seconds:17
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:5311648
executable:/data/redis-server
config_file:
io_threads_active:0

# Clients
connected_clients:1
client_recent_max_input_buffer:8
client_recent_max_output_buffer:0
blocked_clients:0
tracking_clients:0
clients_in_timeout_table:0

# Memory
used_memory:4962632
used_memory_human:4.73M
used_memory_rss:11755520
used_memory_rss_human:11.21M
used_memory_peak:5019320
used_memory_peak_human:4.79M
used_memory_peak_perc:98.87%
used_memory_overhead:804520
used_memory_startup:803152
used_memory_dataset:4158112
used_memory_dataset_perc:99.97%
allocator_allocated:5245152
allocator_active:5574656
allocator_resident:8491008
total_system_memory:16394342400
total_system_memory_human:15.27G
used_memory_lua:37888
used_memory_lua_human:37.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.06
allocator_frag_bytes:329504
allocator_rss_ratio:1.52
allocator_rss_bytes:2916352
rss_overhead_ratio:1.38
rss_overhead_bytes:3264512
mem_fragmentation_ratio:2.40
mem_fragmentation_bytes:6856344
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:0
mem_aof_buffer:0
mem_allocator:jemalloc-5.1.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1632701583
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0
module_fork_in_progress:0
module_fork_last_cow_size:0

# Stats
total_connections_received:2
total_commands_processed:2
instantaneous_ops_per_sec:0
total_net_input_bytes:45
total_net_output_bytes:22264
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
expire_cycle_cpu_milliseconds:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0
tracking_total_keys:0
tracking_total_items:0
tracking_total_prefixes:0
unexpected_error_replies:0
total_reads_processed:4
total_writes_processed:2
io_threaded_reads_processed:0
io_threaded_writes_processed:0

# Replication
role:master
connected_slaves:0
master_replid:0f1bf39fce3b7c46e23c92bae22c59b53a31ecd0
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.057938
used_cpu_user:0.055346
used_cpu_sys_children:0.002745
used_cpu_user_children:0.004038

# Modules

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=27,expires=0,avg_ttl=0
root@empyrion:~# docker exec -it redis redis-cli INFO > info.txt
root@empyrion:~# cat info
cat: info: No such file or directory
root@empyrion:~# cat info.txt
# Server
redis_version:6.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:95eb037379d5f3f8
redis_mode:standalone
os:Linux 5.4.0-40-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:8.3.0
process_id:1
run_id:db625fae6f7f8d73d44d1f724f0635ec4ff91651
tcp_port:6379
uptime_in_seconds:25
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:5311656
executable:/data/redis-server
config_file:
io_threads_active:0

# Clients
connected_clients:1
client_recent_max_input_buffer:8
client_recent_max_output_buffer:0
blocked_clients:0
tracking_clients:0
clients_in_timeout_table:0

# Memory
used_memory:4962632
used_memory_human:4.73M
used_memory_rss:11755520
used_memory_rss_human:11.21M
used_memory_peak:5019320
used_memory_peak_human:4.79M
used_memory_peak_perc:98.87%
used_memory_overhead:804520
used_memory_startup:803152
used_memory_dataset:4158112
used_memory_dataset_perc:99.97%
allocator_allocated:5245152
allocator_active:5574656
allocator_resident:8491008
total_system_memory:16394342400
total_system_memory_human:15.27G
used_memory_lua:37888
used_memory_lua_human:37.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.06
allocator_frag_bytes:329504
allocator_rss_ratio:1.52
allocator_rss_bytes:2916352
rss_overhead_ratio:1.38
rss_overhead_bytes:3264512
mem_fragmentation_ratio:2.40
mem_fragmentation_bytes:6856344
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:0
mem_aof_buffer:0
mem_allocator:jemalloc-5.1.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1632701583
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0
module_fork_in_progress:0
module_fork_last_cow_size:0

# Stats
total_connections_received:3
total_commands_processed:3
instantaneous_ops_per_sec:0
total_net_input_bytes:59
total_net_output_bytes:25916
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
expire_cycle_cpu_milliseconds:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0
tracking_total_keys:0
tracking_total_items:0
tracking_total_prefixes:0
unexpected_error_replies:0
total_reads_processed:6
total_writes_processed:3
io_threaded_reads_processed:0
io_threaded_writes_processed:0

# Replication
role:master
connected_slaves:0
master_replid:0f1bf39fce3b7c46e23c92bae22c59b53a31ecd0
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.068201
used_cpu_user:0.060623
used_cpu_sys_children:0.002745
used_cpu_user_children:0.004038

# Modules

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=27,expires=0,avg_ttl=0
`

	REDIS_CLIENT_LIST = `id=13 addr=127.0.0.1:52210 fd=8 name= age=1526 idle=1015 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=0 argv-mem=0 obl=0 oll=0 omem=0 tot-mem=20504 events=r cmd=client user=default
id=30 addr=127.0.0.1:60482 fd=9 name= age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=26 qbuf-free=32742 argv-mem=10 obl=0 oll=0 omem=0 tot-mem=61466 events=r cmd=client user=default
`
)
