#include "netguard.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <exception>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>

namespace netguard {
using Json=nlohmann::json;
using Bytes=std::vector<unsigned char>;
namespace {
constexpr std::size_t MAX_PACKETS=100000, MAX_BYTES=32*1024*1024;
template<class T> class Queue {
  std::mutex m;std::condition_variable cv;std::deque<T> q;bool closed=false;
public:
  bool push(T value){std::unique_lock<std::mutex> l(m);cv.wait(l,[&]{return closed||q.size()<64;});if(closed)return false;q.push_back(std::move(value));cv.notify_all();return true;}
  bool pop(T& value){std::unique_lock<std::mutex> l(m);cv.wait(l,[&]{return closed||!q.empty();});if(q.empty())return false;value=std::move(q.front());q.pop_front();cv.notify_all();return true;}
  void close(){std::lock_guard<std::mutex> l(m);closed=true;cv.notify_all();}
};
unsigned u16(const Bytes& b,std::size_t p){return (unsigned(b.at(p))<<8)|b.at(p+1);}
std::uint32_t u32(const Bytes& b,std::size_t p,bool little){std::uint32_t n=0;for(int i=0;i<4;++i)n|=std::uint32_t(b.at(p+i))<<(little?8*i:8*(3-i));return n;}
std::string ip(const Bytes& b,std::size_t p){return std::to_string(b.at(p))+"."+std::to_string(b.at(p+1))+"."+std::to_string(b.at(p+2))+"."+std::to_string(b.at(p+3));}
std::string lower(std::string s){for(auto& c:s)if(c>='A'&&c<='Z')c+=32;return s;}
bool valid_ip(const std::string& s){std::istringstream in(s);std::string part;int count=0;while(std::getline(in,part,'.')){if(part.empty()||part.size()>3||part.find_first_not_of("0123456789")!=std::string::npos)return false;if(part.size()>1&&part[0]=='0')return false;if(std::stoi(part)>255)return false;++count;}return count==4&&!s.empty()&&s.back()!='.';}
bool valid_domain(const std::string& s){if(s.empty()||s.size()>253||s.back()=='.')return false;std::istringstream in(s);std::string label;while(std::getline(in,label,'.'))if(label.empty()||label.size()>63||label.front()=='-'||label.back()=='-'||label.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-")!=std::string::npos)return false;return true;}
bool suffix(const std::string& name,const std::string& rule){return name==rule||(name.size()>rule.size()&&name.compare(name.size()-rule.size(),rule.size(),rule)==0&&name[name.size()-rule.size()-1]=='.');}
struct Packet {
  Bytes header,data;double time=0;bool parsed=false,syn=false,dns=false,malformed_dns=false;
  std::string src,dst,domain,key;unsigned sport=0,dport=0,protocol=0;double entropy=0;std::size_t label_length=0;int policy=-1;
};
// Bounded RFC 1035 name decoding; compressed names cannot escape this DNS message.
std::string dns_name(const Bytes& b,std::size_t base,std::size_t end,std::size_t& cursor){
  std::size_t pos=cursor;bool jumped=false;std::set<std::size_t> seen;std::string result;
  for(unsigned steps=0;steps<128;++steps){if(pos>=end||!seen.insert(pos).second)throw std::runtime_error("DNS name bounds");unsigned n=b[pos++];
    if(n==0){if(!jumped)cursor=pos;return lower(result);}
    if((n&0xc0)==0xc0){if(pos>=end)throw std::runtime_error("DNS pointer");std::size_t target=base+((n&63)<<8)+b[pos++];if(!jumped)cursor=pos;jumped=true;pos=target;continue;}
    if((n&0xc0)||n>63||pos+n>end)throw std::runtime_error("DNS label");
    if(!result.empty())result+='.';for(unsigned i=0;i<n;++i){unsigned c=b[pos++];if(c<33||c>126||c=='.')throw std::runtime_error("DNS label character");result+=static_cast<char>(c);}if(result.size()>253)throw std::runtime_error("DNS name length");
  }throw std::runtime_error("DNS pointer depth");
}
void parse(Packet& p){
  const auto& b=p.data;if(b.size()<14)return;std::size_t off=14;unsigned ether=u16(b,12);
  for(int tag=0;tag<2&&(ether==0x8100||ether==0x88a8);++tag){if(b.size()<off+4)return;ether=u16(b,off+2);off+=4;}
  if(ether!=0x0800||b.size()<off+20||(b[off]>>4)!=4)return;
  auto ihl=std::size_t(b[off]&15)*4;unsigned total=u16(b,off+2);if(ihl<20||total<ihl||off+total>b.size()||off+ihl>b.size())return;
  if(u16(b,off+6)&0x3fff)return; // Fragment reassembly is deliberately unsupported.
  unsigned proto=b[off+9];auto start=off+ihl,end=off+total;
  if(proto==6){if(start+20>end)return;auto th=std::size_t(b[start+12]>>4)*4;if(th<20||start+th>end)return;p.syn=(b[start+13]&0x12)==2;}
  else if(proto==17){if(start+8>end)return;auto len=u16(b,start+4);if(len<8||start+len>end)return;end=start+len;}
  else return;
  p.src=ip(b,off+12);p.dst=ip(b,off+16);p.sport=u16(b,start);p.dport=u16(b,start+2);p.protocol=proto;p.parsed=true;
  std::string a=p.src+":"+std::to_string(p.sport),z=p.dst+":"+std::to_string(p.dport);p.key=std::to_string(proto)+"/"+std::min(a,z)+"/"+std::max(a,z);
  if(proto==17&&p.dport==53){auto base=start+8;try{if(base+12>end)throw std::runtime_error("DNS header");if(b[base+2]&0x80)return;if(u16(b,base+4)!=1)throw std::runtime_error("DNS question count");auto cursor=base+12;p.domain=dns_name(b,base,end,cursor);if(cursor+4>end)throw std::runtime_error("DNS question");p.dns=true;auto label=p.domain.substr(0,p.domain.find('.'));p.label_length=label.size();std::array<unsigned,256> counts{};for(unsigned char c:label)++counts[c];for(auto n:counts)if(n){double f=double(n)/label.size();p.entropy-=f*std::log2(f);}}
    catch(const std::exception&){p.malformed_dns=true;p.domain.clear();}
  }
}
struct Flow {std::string src,dst,domain;unsigned sport=0,dport=0,protocol=0;std::uint64_t packets=0,bytes=0,first=0,reverse=0,dropped=0;double first_time=0,last_time=0;};
struct Event{double time;std::string target;double entropy=0;std::size_t length=0;};
}
void validate(const Options& o){
  if(o.workers<1||o.workers>8||o.scan_ports<2||o.scan_ports>65535||o.scan_hosts<2||o.scan_hosts>100000||o.dns_queries<2||o.dns_queries>100000||!std::isfinite(o.window_seconds)||o.window_seconds<1||o.window_seconds>3600||!std::isfinite(o.dns_entropy)||o.dns_entropy<0||o.dns_entropy>6||o.exfil_bytes<1||o.exfil_bytes>MAX_BYTES||o.deny_ips.size()>100||o.deny_domains.size()>100)throw std::runtime_error("Invalid analysis options");
  for(const auto& s:o.deny_ips)if(!valid_ip(s))throw std::runtime_error("Invalid deny IP");
  for(const auto& s:o.deny_domains)if(!valid_domain(s))throw std::runtime_error("Invalid deny domain (use lowercase ASCII)");
}
Json analyze(const std::string& input,const std::string& filtered,const Options& o){
  validate(o);if(input==filtered)throw std::runtime_error("Input and output must differ");auto begin=std::chrono::steady_clock::now();
  std::ifstream in(input,std::ios::binary);if(!in)throw std::runtime_error("Cannot open capture");Bytes global(24);if(!in.read(reinterpret_cast<char*>(global.data()),24))throw std::runtime_error("Truncated PCAP header");
  auto magic=u32(global,0,true);bool little=magic==0xa1b2c3d4||magic==0xa1b23c4d;bool nano=magic==0xa1b23c4d||magic==0x4d3cb2a1;
  if(!little&&magic!=0xd4c3b2a1&&magic!=0x4d3cb2a1)throw std::runtime_error("Only classic PCAP is supported; PCAPNG is unsupported");
  auto word=[&](std::size_t p){return little?unsigned(global[p])+(unsigned(global[p+1])<<8):u16(global,p);};
  unsigned snap=u32(global,16,little);if(word(4)!=2||word(6)!=4||u32(global,20,little)!=1||snap==0||snap>262144)throw std::runtime_error("Expected PCAP 2.4 Ethernet capture with bounded snaplen");
  std::ofstream out(filtered,std::ios::binary|std::ios::trunc);if(!out)throw std::runtime_error("Cannot create filtered capture");out.write(reinterpret_cast<const char*>(global.data()),24);
  Queue<Packet> intake;Queue<std::size_t> order;std::vector<std::unique_ptr<Queue<Packet>>> work,done;std::vector<std::map<std::string,Flow>> flows(o.workers);
  for(std::size_t i=0;i<o.workers;++i){work.emplace_back(std::make_unique<Queue<Packet>>());done.emplace_back(std::make_unique<Queue<Packet>>());}
  std::atomic<bool> stopped{false};std::exception_ptr failure;std::mutex failure_mutex;
  auto cancel=[&]{stopped=true;intake.close();order.close();for(auto& q:work)q->close();for(auto& q:done)q->close();};
  auto fail=[&]{ {std::lock_guard<std::mutex> lock(failure_mutex);if(!failure)failure=std::current_exception();}cancel();};
  std::vector<std::thread> threads;
  Json alerts=Json::array(),ledger=Json::array();for(auto& s:o.deny_ips)ledger.push_back({{"type","IP deny"},{"rule",s},{"dropped",0},{"description","First matching rule; parsed source or destination IPv4"}});for(auto& s:o.deny_domains)ledger.push_back({{"type","Domain deny"},{"rule",s},{"dropped",0},{"description","First matching rule; unencrypted UDP DNS query suffix only"}});
  std::map<std::string,std::deque<Event>> scans,hosts,dns;std::set<std::string> emitted;std::uint64_t packets=0,parsed=0,bytes=0,dropped=0,malformed_dns=0;
  auto emit=[&](const Packet& p,const std::string& detector,const std::string& key,const std::string& text,Json evidence){if(!emitted.insert(detector+"/"+key).second)return;alerts.push_back({{"id",alerts.size()+1},{"detector",detector},{"severity","high"},{"score",detector=="data_exfiltration"?45:40},{"source_ip",p.src},{"destination_ip",p.dst},{"destination_port",p.dport},{"domain",p.domain},{"explanation",text},{"evidence",evidence}});};
  auto expire=[&](std::deque<Event>& q,double t){while(!q.empty()&&q.front().time<t-o.window_seconds)q.pop_front();};
  try{
    threads.emplace_back([&]{try{std::size_t n=0,total=24;double last=-1;while(!stopped){Packet p;p.header.resize(16);in.read(reinterpret_cast<char*>(p.header.data()),16);if(in.gcount()==0&&in.eof())break;if(in.gcount()!=16)throw std::runtime_error("Truncated PCAP record");unsigned len=u32(p.header,8,little),original=u32(p.header,12,little),fraction=u32(p.header,4,little);if(len>snap||len>original||fraction>=(nano?1000000000U:1000000U))throw std::runtime_error("Invalid PCAP record lengths or timestamp");if(++n>MAX_PACKETS||(total+=16+len)>MAX_BYTES)throw std::runtime_error("Capture exceeds 100000 packets or 32 MiB");p.time=u32(p.header,0,little)+double(fraction)/(nano?1e9:1e6);if(p.time<last)throw std::runtime_error("Capture timestamps must be nondecreasing");last=p.time;p.data.resize(len);if(len&&!in.read(reinterpret_cast<char*>(p.data.data()),len))throw std::runtime_error("Truncated packet data");if(!intake.push(std::move(p)))break;}intake.close();}catch(...){fail();}});
    threads.emplace_back([&]{try{Packet p;while(!stopped&&intake.pop(p)){parse(p);std::size_t id=p.parsed?std::hash<std::string>{}(p.key)%o.workers:0;if(!work[id]->push(std::move(p))||!order.push(id))break;}for(auto& q:work)q->close();order.close();}catch(...){fail();}});
    for(std::size_t id=0;id<o.workers;++id)threads.emplace_back([&,id]{try{Packet p;while(!stopped&&work[id]->pop(p)){
      if(p.parsed){for(std::size_t i=0;i<o.deny_ips.size();++i)if(p.src==o.deny_ips[i]||p.dst==o.deny_ips[i]){p.policy=static_cast<int>(i);break;}if(p.policy<0&&!p.domain.empty())for(std::size_t i=0;i<o.deny_domains.size();++i)if(suffix(p.domain,o.deny_domains[i])){p.policy=static_cast<int>(o.deny_ips.size()+i);break;}
        auto& f=flows[id][p.key];if(f.packets==0){f.src=p.src;f.dst=p.dst;f.sport=p.sport;f.dport=p.dport;f.protocol=p.protocol;f.first_time=p.time;}++f.packets;f.bytes+=p.data.size();f.last_time=p.time;if(p.src==f.src&&p.sport==f.sport)f.first+=p.data.size();else f.reverse+=p.data.size();if(p.policy>=0)++f.dropped;if(!p.domain.empty())f.domain=p.domain;
      }if(!done[id]->push(std::move(p)))break;}done[id]->close();}catch(...){fail();}});
    std::size_t id;while(!stopped&&order.pop(id)){Packet p;if(!done[id]->pop(p))break;++packets;bytes+=p.data.size();if(p.parsed)++parsed;if(p.malformed_dns)++malformed_dns;
      if(p.policy>=0){++dropped;auto index=static_cast<std::size_t>(p.policy);ledger[index]["dropped"]=ledger[index]["dropped"].get<unsigned>()+1;}else{out.write(reinterpret_cast<const char*>(p.header.data()),16);if(!p.data.empty())out.write(reinterpret_cast<const char*>(p.data.data()),p.data.size());if(!out)throw std::runtime_error("Filtered PCAP write failed");}
      if(p.syn){auto key=p.src+"/"+p.dst;auto& q=scans[key];expire(q,p.time);q.push_back({p.time,std::to_string(p.dport),0,0});std::set<std::string> ports;for(auto& e:q)ports.insert(e.target);if(ports.size()>=o.scan_ports)emit(p,"port_scan",key,"Source probed distinct TCP ports within the observation window.",{{"unique_ports",ports.size()},{"threshold",o.scan_ports},{"window_seconds",o.window_seconds},{"tcp_syn_packets",q.size()}});
        auto& h=hosts[p.src];expire(h,p.time);h.push_back({p.time,p.dst,0,0});std::set<std::string> targets;for(auto& e:h)targets.insert(e.target);if(targets.size()>=o.scan_hosts)emit(p,"host_scan",p.src,"Source probed distinct IPv4 hosts within the observation window.",{{"unique_hosts",targets.size()},{"threshold",o.scan_hosts},{"window_seconds",o.window_seconds},{"tcp_syn_packets",h.size()}});
      }
      if(p.dns&&p.label_length>=16&&p.entropy>=o.dns_entropy){auto& q=dns[p.src];expire(q,p.time);q.push_back({p.time,p.domain,p.entropy,p.label_length});if(q.size()>=o.dns_queries){double e=0,l=0;for(auto& v:q){e+=v.entropy;l+=v.length;}emit(p,"dns_tunneling",p.src,"Repeated long, high-entropy UDP DNS query labels; heuristic requires analyst review.",{{"queries",q.size()},{"average_label_entropy",e/q.size()},{"average_label_length",l/q.size()},{"entropy_threshold",o.dns_entropy},{"window_seconds",o.window_seconds}});}}
    }
  }catch(...){fail();}
  for(auto& t:threads)if(t.joinable())t.join();if(failure)std::rethrow_exception(failure);out.close();if(!out)throw std::runtime_error("Filtered PCAP close failed");
  std::map<std::string,Flow> sorted;for(auto& table:flows)sorted.insert(table.begin(),table.end());Json flow_json=Json::array();
  for(auto& entry:sorted){auto& f=entry.second;bool flagged=f.first>=o.exfil_bytes;if(flagged){Packet p;p.src=f.src;p.dst=f.dst;p.sport=f.sport;p.dport=f.dport;p.domain=f.domain;emit(p,"data_exfiltration",entry.first,"First-observed direction exceeded captured-frame byte threshold; this does not prove outbound exfiltration.",{{"bytes_first_direction",f.first},{"bytes_reverse_direction",f.reverse},{"threshold_bytes",o.exfil_bytes},{"flow_packets",f.packets}});}
    flow_json.push_back({{"source",f.src+":"+std::to_string(f.sport)},{"destination",f.dst+":"+std::to_string(f.dport)},{"protocol",f.protocol==6?"TCP":"UDP"},{"packets",f.packets},{"bytes",f.bytes},{"bytes_first_direction",f.first},{"bytes_reverse_direction",f.reverse},{"domain",f.domain},{"app",f.protocol==17&&f.dport==53?"DNS":"Unknown"},{"state",f.dropped?"Blocked":flagged?"Flagged":"Allowed"},{"dropped_packets",f.dropped},{"first_seen",f.first_time},{"last_seen",f.last_time}});
  }
  double elapsed=std::max(1e-9,std::chrono::duration<double>(std::chrono::steady_clock::now()-begin).count());
  return {{"schema_version",1},{"summary",{{"input_packets",packets},{"parsed_packets",parsed},{"unsupported_packets",packets-parsed},{"malformed_dns_packets",malformed_dns},{"forwarded_packets",packets-dropped},{"dropped_packets",dropped},{"total_bytes",bytes},{"active_flows",flow_json.size()},{"alerts",alerts.size()},{"elapsed_seconds",elapsed},{"packets_per_second",packets/elapsed},{"megabytes_per_second",bytes/1e6/elapsed}}},{"alerts",alerts},{"flows",flow_json},{"policies",ledger},{"configuration",{{"workers",o.workers},{"scan_ports",o.scan_ports},{"scan_hosts",o.scan_hosts},{"dns_queries",o.dns_queries},{"window_seconds",o.window_seconds},{"dns_entropy",o.dns_entropy},{"exfil_bytes",o.exfil_bytes}}},{"limitations",Json::array({"Classic Ethernet PCAP, IPv4 TCP/UDP only; no fragment/TCP stream reassembly or checksum validation.","Unsupported/truncated protocol packets are counted and forwarded; policies apply only to parsed IPv4 packets.","Domain filtering applies only to observed unencrypted UDP DNS queries, not subsequent connections or encrypted DNS.","Transfer bytes are captured Ethernet frame bytes in first-observed direction, not verified outbound application bytes.","At most one alert per detector and source/group per run; risk scores are heuristic, not probabilities.","Input limit: 32 MiB and 100000 packets; timestamps must be nondecreasing."})}};
}
}
