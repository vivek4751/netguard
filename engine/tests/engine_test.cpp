#include "netguard.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <chrono>
using Bytes = std::vector<unsigned char>;
void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
void le(Bytes& b, unsigned v, int n) { for (int i=0;i<n;++i) b.push_back((v>>(i*8))&255); }
void be(Bytes& b, std::size_t p, unsigned v) { b[p]=v>>8; b[p+1]=v&255; }
Bytes tcp(unsigned port, unsigned host=2, bool reverse=false) {
  Bytes p(54,0); p[12]=8; p[14]=0x45; be(p,16,40); p[22]=64; p[23]=6;
  p[26]=10; p[29]=reverse?host:1; p[30]=10; p[33]=reverse?1:host;
  be(p,34,reverse?port:40000); be(p,36,reverse?40000:port); p[46]=0x50; p[47]=reverse?0x10:2; return p;
}
Bytes dns(const std::string& label, const std::string& suffix="example") {
  Bytes p(54,0); p[12]=8; p[14]=0x45; p[22]=64; p[23]=17; p[26]=10; p[29]=1; p[30]=8; p[31]=8; p[32]=8; p[33]=8;
  be(p,34,42000); be(p,36,53); p[47]=1;
  p.push_back(static_cast<unsigned char>(label.size())); p.insert(p.end(),label.begin(),label.end());
  p.push_back(static_cast<unsigned char>(suffix.size())); p.insert(p.end(),suffix.begin(),suffix.end()); p.push_back(0);
  p.insert(p.end(),{0,1,0,1}); be(p,16,p.size()-14); be(p,38,p.size()-34); return p;
}
void capture(const std::filesystem::path& path,const std::vector<Bytes>& packets,bool nano=false) {
  Bytes b; le(b,nano?0xa1b23c4d:0xa1b2c3d4,4); le(b,2,2);le(b,4,2);le(b,0,4);le(b,0,4);le(b,65535,4);le(b,1,4);
  for(std::size_t i=0;i<packets.size();++i){le(b,1+i,4);le(b,0,4);le(b,packets[i].size(),4);le(b,packets[i].size(),4);b.insert(b.end(),packets[i].begin(),packets[i].end());}
  std::ofstream f(path,std::ios::binary);f.write(reinterpret_cast<const char*>(b.data()),b.size());
}
bool has(const nlohmann::json& r,const std::string& detector) {for(const auto& a:r.at("alerts"))if(a.at("detector")==detector)return true;return false;}
int main(){
  auto dir=std::filesystem::temp_directory_path()/("netguard-test-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directory(dir);
  try{
    auto in=(dir/"in.pcap").string(),out=(dir/"out.pcap").string();
    netguard::Options o; o.scan_ports=3;o.scan_hosts=3;o.exfil_bytes=100;o.dns_queries=2;o.dns_entropy=3;
    capture(in,{tcp(80),tcp(80,2,true)});auto r=netguard::analyze(in,out,o);
    check(r["flows"].size()==1,"bidirectional flow not merged");check(r["flows"][0]["packets"]==2,"flow packet accounting");check(r["alerts"].empty(),"benign traffic alerted");
    capture(in,{tcp(80),tcp(81),tcp(82),tcp(80,3),tcp(80,4),dns("abcdefghijklmnop"),dns("abcdefghijklmnop")});
    r=netguard::analyze(in,out,o);check(has(r,"port_scan"),"port scan missing across workers");check(has(r,"host_scan"),"host scan missing");check(has(r,"dns_tunneling"),"DNS entropy detection missing");
    o.workers=1;auto one=netguard::analyze(in,out,o);check(one["alerts"]==r["alerts"],"worker count changes detections");check(one["flows"]==r["flows"],"worker count changes flows");
    capture(in,{tcp(443),tcp(443),tcp(443)},true);r=netguard::analyze(in,out,o);check(has(r,"data_exfiltration"),"transfer threshold missing");
    o.deny_ips={"10.0.0.2"};capture(in,{tcp(80),tcp(80,3)});r=netguard::analyze(in,out,o);check(r["summary"]["dropped_packets"]==1,"IP filtering");
    auto filtered=netguard::analyze(out,(dir/"second.pcap").string());check(filtered["summary"]["input_packets"]==1,"filtered capture invalid");check(filtered["flows"][0]["destination"]=="10.0.0.3:80","filtered ordering/content");
    o.deny_domains={"example"};capture(in,{dns("test"),dns("test","notexample")});r=netguard::analyze(in,out,o);check(r["summary"]["dropped_packets"]==1,"domain boundary matching");
    capture(in,{Bytes(14,0)});r=netguard::analyze(in,out,o);check(r["summary"]["unsupported_packets"]==1,"unsupported count");
    capture(in,{});r=netguard::analyze(in,out,o);check(r["summary"]["input_packets"]==0,"empty capture");
    {std::ofstream f(in,std::ios::binary);f<<"bad";}bool rejected=false;try{netguard::analyze(in,out,o);}catch(const std::exception&){rejected=true;}check(rejected,"truncated capture accepted");
    capture(in,{tcp(80)});std::filesystem::resize_file(in,std::filesystem::file_size(in)-1);rejected=false;try{netguard::analyze(in,out,o);}catch(const std::exception&){rejected=true;}check(rejected,"truncated packet accepted");
    std::filesystem::remove_all(dir);std::cout<<"Engine tests passed\n";return 0;
  }catch(const std::exception& e){std::filesystem::remove_all(dir);std::cerr<<e.what()<<'\n';return 1;}
}
