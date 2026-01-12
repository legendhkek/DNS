// Copyright Epic Games, Inc. All Rights Reserved.
// UE4 Network Config Module

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
#pragma comment(lib, "ws2_32.lib")
#define PLATFORM_CLOSE closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#define PLATFORM_CLOSE close
#endif

// UE4 Style Naming
namespace UE4Network
{
    // Forward declarations
    class FNetworkConfig;
    struct FConfigResponse;
    
    namespace Private
    {
        static std::string GServiceEndpoint;
        static std::string GEncryptionKey;
        static bool bIsInitialized = false;
        static std::vector<std::string> GFilterPatterns;
        
        // Encoded filter data
        static const char* GEncodedFilters[] = {
            "ZG91YmxlY2xpY2s=", "Z29vZ2xlc3luZGljYXRpb24=", "Z29vZ2xlYWRzZXJ2aWNlcw==",
            "YWRtb2I=", "YWRzZW5zZQ==", "YWRueHM=", "bW9wdWI=", "dW5pdHlhZHM=",
            "YXBwbG92aW4=", "dnVuZ2xl", "Y2hhcnRib29zdA==", "aXJvbnNyYw==",
            "aW5tb2Jp", "dGFwam95", "YW4uZmFjZWJvb2s=", "cGl4ZWwuZmFjZWJvb2s=",
            "YW5hbHl0aWNz", "dHJhY2tlcg==", "dHJhY2tpbmc=", "dGVsZW1ldHJ5",
            "bWl4cGFuZWw=", "YWRqdXN0", "YXBwc2ZseWVy", "cG9wYWRz", "dGFib29sYQ==",
            "Y3Jhc2hseXRpY3M=", "Zmx1cnJ5", "Z29vZ2xlLWFuYWx5dGljcw==",
            "Z29vZ2xldGFnbWFuYWdlcg==", "YWRzZXJ2aWNl", "cGFnZWFk", "YWR2ZXJ0aXNpbmc=",
            nullptr
        };
        
        // Base64 decode
        static const char* B64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        inline std::string Base64Decode(const std::string& InEncoded)
        {
            std::string Result;
            std::vector<int> DecodeTable(256, -1);
            for (int i = 0; i < 64; i++) DecodeTable[(int)B64Chars[i]] = i;
            
            int Val = 0, Bits = -8;
            for (char c : InEncoded)
            {
                if (DecodeTable[(int)(unsigned char)c] == -1) break;
                Val = (Val << 6) + DecodeTable[(int)(unsigned char)c];
                Bits += 6;
                if (Bits >= 0) { Result += char((Val >> Bits) & 0xFF); Bits -= 8; }
            }
            return Result;
        }
        
        inline std::string Base64Encode(const std::string& InData)
        {
            std::string Result;
            int Val = 0, Bits = -6;
            for (unsigned char c : InData)
            {
                Val = (Val << 8) + c;
                Bits += 8;
                while (Bits >= 0) { Result += B64Chars[(Val >> Bits) & 0x3F]; Bits -= 6; }
            }
            if (Bits > -6) Result += B64Chars[((Val << 8) >> (Bits + 8)) & 0x3F];
            while (Result.size() % 4) Result += '=';
            return Result;
        }
        
        // XOR cipher
        inline std::string XORCipher(const std::string& InData, const std::string& InKey)
        {
            std::string Result;
            for (size_t i = 0; i < InData.size(); i++)
                Result += InData[i] ^ InKey[i % InKey.size()];
            return Result;
        }
        
        // Encrypt data for transmission
        inline std::string EncryptPayload(const std::string& InJson, const std::string& InKey)
        {
            return Base64Encode(XORCipher(InJson, InKey));
        }
        
        // Decrypt received data
        inline std::string DecryptPayload(const std::string& InEncrypted, const std::string& InKey)
        {
            std::string Decoded = Base64Decode(InEncrypted);
            return XORCipher(Decoded, InKey);
        }
        
        // Normalize hostname
        inline std::string NormalizeHostname(const std::string& InHost)
        {
            std::string Result = InHost;
            if (Result.find("http://") == 0) Result = Result.substr(7);
            if (Result.find("https://") == 0) Result = Result.substr(8);
            size_t SlashPos = Result.find('/');
            if (SlashPos != std::string::npos) Result = Result.substr(0, SlashPos);
            std::transform(Result.begin(), Result.end(), Result.begin(), ::tolower);
            return Result;
        }
        
        // JSON helpers
        inline std::string JsonGetString(const std::string& InJson, const std::string& InKey)
        {
            std::string Search = "\"" + InKey + "\":\"";
            size_t Pos = InJson.find(Search);
            if (Pos == std::string::npos) return "";
            Pos += Search.size();
            size_t End = InJson.find("\"", Pos);
            return (End != std::string::npos) ? InJson.substr(Pos, End - Pos) : "";
        }
        
        inline int32_t JsonGetInt(const std::string& InJson, const std::string& InKey)
        {
            std::string Search = "\"" + InKey + "\":";
            size_t Pos = InJson.find(Search);
            if (Pos == std::string::npos) return 0;
            Pos += Search.size();
            return atoi(InJson.c_str() + Pos);
        }
        
        // HTTP Request
        inline std::string HttpRequest(const std::string& InURL, const std::string& InBody = "")
        {
            std::string Result;
            
            bool bUseSSL = (InURL.find("https://") == 0);
            size_t Start = bUseSSL ? 8 : (InURL.find("http://") == 0 ? 7 : 0);
            size_t PathStart = InURL.find('/', Start);
            std::string HostPort = (PathStart != std::string::npos) ? InURL.substr(Start, PathStart - Start) : InURL.substr(Start);
            std::string Path = (PathStart != std::string::npos) ? InURL.substr(PathStart) : "/";
            
            std::string Host = HostPort;
            int32_t Port = bUseSSL ? 443 : 80;
            size_t ColonPos = HostPort.find(':');
            if (ColonPos != std::string::npos)
            {
                Host = HostPort.substr(0, ColonPos);
                Port = atoi(HostPort.c_str() + ColonPos + 1);
            }
            
            if (bUseSSL) return Result;
            
            #ifdef _WIN32
            WSADATA WsaData;
            WSAStartup(MAKEWORD(2, 2), &WsaData);
            #endif
            
            struct addrinfo Hints = {}, *AddrResult = nullptr;
            Hints.ai_family = AF_UNSPEC;
            Hints.ai_socktype = SOCK_STREAM;
            
            char PortStr[16];
            snprintf(PortStr, sizeof(PortStr), "%d", Port);
            
            if (getaddrinfo(Host.c_str(), PortStr, &Hints, &AddrResult) != 0) return Result;
            
            int Socket = socket(AddrResult->ai_family, AddrResult->ai_socktype, AddrResult->ai_protocol);
            if (Socket < 0) { freeaddrinfo(AddrResult); return Result; }
            
            #ifdef _WIN32
            DWORD Timeout = 5000;
            setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&Timeout, sizeof(Timeout));
            #else
            struct timeval Timeout = {5, 0};
            setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, &Timeout, sizeof(Timeout));
            #endif
            
            if (connect(Socket, AddrResult->ai_addr, AddrResult->ai_addrlen) < 0)
            {
                PLATFORM_CLOSE(Socket);
                freeaddrinfo(AddrResult);
                return Result;
            }
            freeaddrinfo(AddrResult);
            
            std::string Request;
            if (InBody.empty())
            {
                Request = "GET " + Path + " HTTP/1.1\r\n";
            }
            else
            {
                Request = "POST " + Path + " HTTP/1.1\r\n";
                Request += "Content-Length: " + std::to_string(InBody.size()) + "\r\n";
                Request += "Content-Type: application/octet-stream\r\n";
            }
            Request += "Host: " + Host + "\r\n";
            Request += "User-Agent: UE4Client/4.27.2\r\n";
            Request += "X-UE4-Version: 4.27.2\r\n";
            Request += "Connection: close\r\n\r\n";
            Request += InBody;
            
            send(Socket, Request.c_str(), Request.size(), 0);
            
            std::string Response;
            char Buffer[4096];
            int BytesRead;
            while ((BytesRead = recv(Socket, Buffer, sizeof(Buffer) - 1, 0)) > 0)
            {
                Buffer[BytesRead] = 0;
                Response += Buffer;
            }
            
            PLATFORM_CLOSE(Socket);
            #ifdef _WIN32
            WSACleanup();
            #endif
            
            size_t BodyStart = Response.find("\r\n\r\n");
            if (BodyStart != std::string::npos)
            {
                Result = Response.substr(BodyStart + 4);
            }
            
            return Result;
        }
        
        // Initialize filter patterns
        inline void InitializeFilters()
        {
            if (!GFilterPatterns.empty()) return;
            for (int32_t i = 0; GEncodedFilters[i]; i++)
            {
                std::string Decoded = Base64Decode(GEncodedFilters[i]);
                if (!Decoded.empty()) GFilterPatterns.push_back(Decoded);
            }
        }
        
        // Check against local filters
        inline bool CheckLocalFilters(const std::string& InHostname)
        {
            InitializeFilters();
            std::string Normalized = NormalizeHostname(InHostname);
            for (const auto& Pattern : GFilterPatterns)
            {
                if (Normalized.find(Pattern) != std::string::npos) return true;
            }
            return false;
        }
        
        // Extract config from response
        inline std::string ExtractConfigData(const std::string& InResponse)
        {
            std::string Search = "\"ConfigData\":\"";
            size_t Pos = InResponse.find(Search);
            if (Pos == std::string::npos) return "";
            Pos += Search.size();
            size_t End = InResponse.find("\"", Pos);
            return (End != std::string::npos) ? InResponse.substr(Pos, End - Pos) : "";
        }
    }
    
    // FNetworkConfig - Main class
    class FNetworkConfig
    {
    public:
        // Initialize with backend endpoint
        static bool Initialize(const std::string& InEndpoint)
        {
            Private::GServiceEndpoint = InEndpoint;
            if (!Private::GServiceEndpoint.empty() && Private::GServiceEndpoint.back() == '/')
                Private::GServiceEndpoint.pop_back();
            
            Private::InitializeFilters();
            srand(time(nullptr));
            
            // Get encryption key from backend
            std::string Response = Private::HttpRequest(Private::GServiceEndpoint + "/?c=i");
            if (!Response.empty())
            {
                std::string ConfigData = Private::ExtractConfigData(Response);
                if (!ConfigData.empty())
                {
                    // Generate time-based key
                    time_t Now = time(nullptr);
                    struct tm* TimeInfo = gmtime(&Now);
                    char TimeBuf[32];
                    strftime(TimeBuf, sizeof(TimeBuf), "%Y%m%d%H", TimeInfo);
                    Private::GEncryptionKey = std::string(TimeBuf) + "ue4";
                    Private::GEncryptionKey = Private::GEncryptionKey.substr(0, 32);
                    while (Private::GEncryptionKey.size() < 32) Private::GEncryptionKey += "x";
                    
                    // Decrypt and get server key
                    std::string Decrypted = Private::DecryptPayload(ConfigData, Private::GEncryptionKey);
                    std::string ServerKey = Private::JsonGetString(Decrypted, "k");
                    if (!ServerKey.empty()) Private::GEncryptionKey = ServerKey;
                }
            }
            
            Private::bIsInitialized = true;
            return true;
        }
        
        // Check if hostname should be filtered
        static bool ShouldFilter(const std::string& InHostname)
        {
            if (!Private::bIsInitialized) Initialize(Private::GServiceEndpoint);
            
            // Fast local check
            if (Private::CheckLocalFilters(InHostname)) return true;
            
            // Remote check
            if (!Private::GServiceEndpoint.empty() && !Private::GEncryptionKey.empty())
            {
                std::string Normalized = Private::NormalizeHostname(InHostname);
                std::string Payload = "{\"c\":\"c\",\"t\":\"" + Normalized + "\"}";
                std::string Encrypted = Private::EncryptPayload(Payload, Private::GEncryptionKey);
                std::string Response = Private::HttpRequest(Private::GServiceEndpoint, Encrypted);
                
                if (!Response.empty())
                {
                    std::string ConfigData = Private::ExtractConfigData(Response);
                    if (!ConfigData.empty())
                    {
                        std::string Decrypted = Private::DecryptPayload(ConfigData, Private::GEncryptionKey);
                        if (Private::JsonGetInt(Decrypted, "f") == 1) return true;
                    }
                }
            }
            
            return false;
        }
        
        // Local filter check only (no network)
        static bool ShouldFilterLocal(const std::string& InHostname)
        {
            Private::InitializeFilters();
            return Private::CheckLocalFilters(InHostname);
        }
        
        // Resolve hostname
        static std::string ResolveHostname(const std::string& InHostname)
        {
            if (ShouldFilterLocal(InHostname)) return "0.0.0.0";
            
            if (!Private::GServiceEndpoint.empty() && !Private::GEncryptionKey.empty())
            {
                std::string Normalized = Private::NormalizeHostname(InHostname);
                std::string Payload = "{\"c\":\"q\",\"t\":\"" + Normalized + "\"}";
                std::string Encrypted = Private::EncryptPayload(Payload, Private::GEncryptionKey);
                std::string Response = Private::HttpRequest(Private::GServiceEndpoint, Encrypted);
                
                if (!Response.empty())
                {
                    std::string ConfigData = Private::ExtractConfigData(Response);
                    if (!ConfigData.empty())
                    {
                        std::string Decrypted = Private::DecryptPayload(ConfigData, Private::GEncryptionKey);
                        if (Private::JsonGetInt(Decrypted, "f") == 1) return "0.0.0.0";
                        std::string IP = Private::JsonGetString(Decrypted, "v");
                        if (!IP.empty()) return IP;
                    }
                }
            }
            
            return "";
        }
        
        // Add custom filter
        static void AddFilter(const std::string& InPattern)
        {
            Private::InitializeFilters();
            std::string Normalized = Private::NormalizeHostname(InPattern);
            if (!Normalized.empty()) Private::GFilterPatterns.push_back(Normalized);
        }
        
        // Set endpoint
        static void SetEndpoint(const std::string& InEndpoint)
        {
            Private::GServiceEndpoint = InEndpoint;
            if (!Private::GServiceEndpoint.empty() && Private::GServiceEndpoint.back() == '/')
                Private::GServiceEndpoint.pop_back();
        }
        
        // Check if initialized
        static bool IsInitialized() { return Private::bIsInitialized; }
    };
}

// Shorthand macros (UE4 style)
#define UE_NET_INIT(url) UE4Network::FNetworkConfig::Initialize(url)
#define UE_NET_FILTER(host) UE4Network::FNetworkConfig::ShouldFilter(host)
#define UE_NET_FILTER_LOCAL(host) UE4Network::FNetworkConfig::ShouldFilterLocal(host)
#define UE_NET_RESOLVE(host) UE4Network::FNetworkConfig::ResolveHostname(host)
#define UE_NET_ADD_FILTER(pattern) UE4Network::FNetworkConfig::AddFilter(pattern)
