#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace netguard {
struct Options {
  std::size_t workers = 4;
  std::size_t scan_ports = 20;
  std::size_t scan_hosts = 30;
  std::size_t dns_queries = 8;
  double window_seconds = 60;
  double dns_entropy = 3.5;
  std::uint64_t exfil_bytes = 1048576;
  std::vector<std::string> deny_ips;
  std::vector<std::string> deny_domains;
};
// Classic Ethernet PCAP, IPv4 TCP/UDP; throws on invalid capture/limits/I/O.
// Reports are returned only after ordered filtered output is fully written.
nlohmann::json analyze(const std::string& input, const std::string& filtered,
                       const Options& options = {});
void validate(const Options& options);
}
