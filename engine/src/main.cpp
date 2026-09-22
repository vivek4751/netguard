#include "netguard.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
int main(int argc,char** argv){
  std::string report,filtered;
  try{
    if(argc==2&&std::string(argv[1])=="--help"){std::cout<<"netguard analyze INPUT --report REPORT --filtered OUTPUT [--config OPTIONS.json]\n";return 0;}
    if(argc<7||std::string(argv[1])!="analyze")throw std::runtime_error("Usage: netguard analyze INPUT --report REPORT --filtered OUTPUT [--config OPTIONS.json]");
    std::string input=argv[2],config;
    for(int i=3;i<argc;i+=2){if(i+1>=argc)throw std::runtime_error("Missing option value");std::string key=argv[i];if(key=="--report"&&report.empty())report=argv[i+1];else if(key=="--filtered"&&filtered.empty())filtered=argv[i+1];else if(key=="--config"&&config.empty())config=argv[i+1];else throw std::runtime_error("Unknown or duplicate option");}
    if(report.empty()||filtered.empty())throw std::runtime_error("Report and filtered output paths required");
    auto canonical=[](const std::string& s){return std::filesystem::weakly_canonical(s);};
    if(canonical(input)==canonical(filtered)||canonical(input)==canonical(report)||canonical(filtered)==canonical(report))throw std::runtime_error("Input, report and filtered paths must be distinct");
    netguard::Options o;
    if(!config.empty()){
      if(canonical(config)==canonical(report)||canonical(config)==canonical(filtered))throw std::runtime_error("Config must not be an output");
      if(std::filesystem::file_size(config)>65536)throw std::runtime_error("Config exceeds 64 KiB");std::ifstream c(config);if(!c)throw std::runtime_error("Cannot open config");auto j=nlohmann::json::parse(c);
      if(!j.is_object())throw std::runtime_error("Config must be an object");
      for(auto it=j.begin();it!=j.end();++it){const auto& k=it.key();const auto& v=it.value();if(k=="workers")o.workers=v.get<std::size_t>();else if(k=="scan_ports")o.scan_ports=v.get<std::size_t>();else if(k=="scan_hosts")o.scan_hosts=v.get<std::size_t>();else if(k=="dns_queries")o.dns_queries=v.get<std::size_t>();else if(k=="window_seconds")o.window_seconds=v.get<double>();else if(k=="dns_entropy")o.dns_entropy=v.get<double>();else if(k=="exfil_bytes")o.exfil_bytes=v.get<std::uint64_t>();else if(k=="deny_ips")o.deny_ips=v.get<std::vector<std::string>>();else if(k=="deny_domains")o.deny_domains=v.get<std::vector<std::string>>();else throw std::runtime_error("Unknown config key");}
    }
    auto result=netguard::analyze(input,filtered,o);std::ofstream file(report);if(!file)throw std::runtime_error("Cannot create JSON report");file<<result.dump(2)<<'\n';file.close();if(!file)throw std::runtime_error("Cannot write JSON report");return 0;
  }catch(const std::exception& e){std::cerr<<"NetGuard: "<<e.what()<<'\n';return 1;}
}
