#ifndef SNMK_FAST_SCANNER_HPP
#define SNMK_FAST_SCANNER_HPP

#include <string>
#include <vector>
#include <chrono>
#include <memory>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define SOCKET_ERR SOCKET_ERROR
    #define CLOSE_SOCKET(s) closesocket(s)
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <poll.h>
    typedef int socket_t;
    #define INVALID_SOCKET_VAL (-1)
    #define SOCKET_ERR (-1)
    #define CLOSE_SOCKET(s) close(s)
#endif

namespace snmk {

struct PortResult {
    int port{0};
    std::string state{"closed"}; // "open", "closed", "filtered"
    std::string service{"unknown"};
    std::string banner{""};
    double latency_ms{0.0};
};

struct SubdomainResult {
    std::string subdomain;
    std::vector<std::string> ips;
    int status_code{0};
    std::string server_banner;
    std::string title;
    double latency_ms{0.0};
    bool is_live{false};
};

struct PathResult {
    std::string path;
    int status_code{0};
    size_t content_length{0};
    std::string content_type;
    std::string title;
    bool exists{false};
};

struct ScanSummary {
    std::string target;
    std::string resolved_ip;
    double total_duration_ms{0.0};
    std::vector<PortResult> open_ports;
    std::vector<SubdomainResult> subdomains;
    std::vector<PathResult> paths;
};

class FastScannerEngine {
public:
    FastScannerEngine();
    ~FastScannerEngine();

    bool initialize();
    void shutdown();

    std::vector<std::string> resolve_dns(const std::string& hostname);

    std::vector<PortResult> scan_ports(
        const std::string& target_ip,
        const std::vector<int>& ports,
        int timeout_ms = 400,
        int max_threads = 64
    );

    std::vector<SubdomainResult> probe_subdomains(
        const std::string& base_domain,
        const std::vector<std::string>& prefixes,
        int timeout_ms = 800,
        int max_threads = 32
    );

    std::vector<PathResult> probe_paths(
        const std::string& host,
        const std::vector<std::string>& paths,
        int port = 80,
        bool use_ssl = false,
        int timeout_ms = 600,
        int max_threads = 16
    );

    std::string serialize_json(const ScanSummary& summary);

private:
    bool set_nonblocking(socket_t sock);
    bool check_socket_connected(socket_t sock, int timeout_ms);
    std::string grab_banner(socket_t sock, int port, int timeout_ms);
};

} // namespace snmk

#endif // SNMK_FAST_SCANNER_HPP
