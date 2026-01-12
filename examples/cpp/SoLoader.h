// Protected .so Loader - Runtime Deobfuscation
#pragma once
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

namespace _so{namespace _p{
static void*_h0=nullptr;
static std::string _k0;
static std::string _e0;
static const char*_c0="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string _f0(const std::string&d,const std::string&k){std::string r;for(size_t i=0;i<d.size();i++)r+=d[i]^k[i%k.size()];return r;}
inline std::string _f1(const std::string&d){std::string r;for(size_t i=0;i<d.size();i++){unsigned char b=d[i];b^=i%256;b^=((i*7+13)&0xFF);r+=b;}return r;}
inline std::string _f2(const std::string&d,const std::string&k){unsigned char s[256];int j=0;for(int i=0;i<256;i++)s[i]=i;for(int i=0;i<256;i++){j=(j+s[i]+k[i%k.size()])%256;unsigned char t=s[i];s[i]=s[j];s[j]=t;}int i=0;j=0;std::string r;for(size_t x=0;x<d.size();x++){i=(i+1)%256;j=(j+s[i])%256;unsigned char t=s[i];s[i]=s[j];s[j]=t;r+=d[x]^s[(s[i]+s[j])%256];}return r;}
inline std::string _f3(const std::string&d){std::string r;for(size_t i=0;i<d.size();i+=4){uint32_t v=0;for(size_t j=0;j<4&&i+j<d.size();j++)v|=((unsigned char)d[i+j])<<(j*8);v^=0xDEADBEEF;v^=i;for(size_t j=0;j<4&&i+j<d.size();j++)r+=(v>>(j*8))&0xFF;}return r;}
inline std::string _f4(const std::string&d,const std::string&m){if(d.size()<64)return d;std::string h=d.substr(0,64);std::string p=d.substr(64);std::string nh;for(size_t i=0;i<64;i++){if(i>=16&&i<32){nh+=((unsigned char)h[i])^0xAA^i;}else{nh+=h[i];}}std::string np;for(size_t i=0;i<p.size();i++){unsigned char b=p[i];b^=m[i%m.size()];b^=((i*13+7)&0xFF);np+=b;}return nh+np;}
inline std::string _f5(const std::string&d,const std::string&k){if(d.size()<96)return"";std::string iv=d.substr(0,64);std::string h=d.substr(64,32);std::string e=d.substr(96);return _f2(e,k+iv);}
inline std::string _f6(){time_t n=time(nullptr);struct tm*t=gmtime(&n);char b[32];strftime(b,sizeof(b),"%Y%m%d%H",t);std::string r=std::string(b)+"so_protect";while(r.size()<32)r+="x";return r.substr(0,32);}
inline std::string _f7(const std::string&f,const std::string&k=""){FILE*fp=fopen(f.c_str(),"rb");if(!fp)return"";fseek(fp,0,SEEK_END);size_t sz=ftell(fp);fseek(fp,0,SEEK_SET);std::string d(sz,0);fread(&d[0],1,sz,fp);fclose(fp);if(d.size()<9||d.substr(0,9)!=std::string("\x00PROTECT\x00",9))return d;d=d.substr(9);if(d.size()<12)return"";uint32_t osz=*(uint32_t*)&d[0];uint32_t ocrc=*(uint32_t*)&d[4];d=d.substr(12);std::string dk=k.empty()?_f6():k;std::string d0=_f5(d,dk);std::string d1=_f4(d0,dk);std::string d2=_f2(d1,dk);std::string d3=_f3(d2);std::string d4=_f0(d3,dk);return d4;}
}

class ProtectedLoader{
public:
    static void*LoadProtected(const std::string&path,const std::string&key=""){
        std::string data=_p::_f7(path,key);
        if(data.empty()||data.size()<4)return nullptr;
        if(data.substr(0,4)!="\x7FELF")return nullptr;
        char tpl[]="/data/local/tmp/.soXXXXXX";
        int fd=mkstemp(tpl);
        if(fd<0)return nullptr;
        write(fd,data.c_str(),data.size());
        close(fd);
        chmod(tpl,0700);
        void*h=dlopen(tpl,RTLD_NOW);
        unlink(tpl);
        _p::_h0=h;
        return h;
    }
    static void*LoadFromMemory(const unsigned char*data,size_t size,const std::string&key=""){
        std::string d((char*)data,size);
        if(d.size()<9||d.substr(0,9)!=std::string("\x00PROTECT\x00",9)){
            char t[]="/data/local/tmp/.soXXXXXX";
            int f=mkstemp(t);
            if(f<0)return nullptr;
            write(f,data,size);
            close(f);
            chmod(t,0700);
            void*h=dlopen(t,RTLD_NOW);
            unlink(t);
            return h;
        }
        d=d.substr(9);
        if(d.size()<12)return nullptr;
        d=d.substr(12);
        std::string dk=key.empty()?_p::_f6():key;
        std::string d0=_p::_f5(d,dk);
        std::string d1=_p::_f4(d0,dk);
        std::string d2=_p::_f2(d1,dk);
        std::string d3=_p::_f3(d2);
        std::string d4=_p::_f0(d3,dk);
        if(d4.size()<4||d4.substr(0,4)!="\x7FELF")return nullptr;
        char t[]="/data/local/tmp/.soXXXXXX";
        int f=mkstemp(t);
        if(f<0)return nullptr;
        write(f,d4.c_str(),d4.size());
        close(f);
        chmod(t,0700);
        void*h=dlopen(t,RTLD_NOW);
        unlink(t);
        _p::_h0=h;
        return h;
    }
    static void*GetSymbol(const std::string&name){
        if(!_p::_h0)return nullptr;
        return dlsym(_p::_h0,name.c_str());
    }
    static void Unload(){
        if(_p::_h0){dlclose(_p::_h0);_p::_h0=nullptr;}
    }
    static bool LoadFromApi(const std::string&apiUrl,const std::string&libName,const std::string&key=""){
        std::string url=apiUrl+"?connect="+libName;
        if(!key.empty())url+="&key="+key;
        // Use curl or custom HTTP to download protected lib
        // Then call LoadFromMemory
        return false;
    }
};
}

#define SO_LOAD_PROTECTED(p) _so::ProtectedLoader::LoadProtected(p)
#define SO_LOAD_PROTECTED_KEY(p,k) _so::ProtectedLoader::LoadProtected(p,k)
#define SO_LOAD_MEMORY(d,s) _so::ProtectedLoader::LoadFromMemory(d,s)
#define SO_LOAD_MEMORY_KEY(d,s,k) _so::ProtectedLoader::LoadFromMemory(d,s,k)
#define SO_GET_FUNC(n) _so::ProtectedLoader::GetSymbol(n)
#define SO_UNLOAD() _so::ProtectedLoader::Unload()
