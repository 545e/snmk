#include "fast_scanner.hpp"

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <future>
#include <queue>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <iomanip>

namespace snmk {

FastScannerEngine::FastScannerEngine() {
    initialize();
}

FastScannerEngine::~FastScannerEngine() {
    shutdown();
}

bool FastScannerEngine::initialize() {
#ifdef _WIN32
    WSADATA wsa_data;
    int res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    return (res == 0);
#else
    return true;
#endif
}

void FastScannerEngine::shutdown() {
#ifdef _WIN32
    WSACleanup();
#endif
}

bool FastScannerEngine::set_nonblocking(socket_t sock) {
#ifdef _WIN32
    u_long mode = 1;
    return (ioctlsocket(sock, FIONBIO, &mode) == 0);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return false;
    return (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
}

bool FastScannerEngine::check_socket_connected(socket_t sock, int timeout_ms) {
    fd_set write_fds, err_fds;
    FD_ZERO(&write_fds);
    FD_ZERO(&err_fds);
    FD_SET(sock, &write_fds);
    FD_SET(sock, &err_fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel_res = select((int)(sock + 1), nullptr, &write_fds, &err_fds, &tv);
    if (sel_res > 0 && FD_ISSET(sock, &write_fds) && !FD_ISSET(sock, &err_fds)) {
        int opt_val = 0;
        socklen_t opt_len = sizeof(opt_val);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&opt_val, &opt_len) == 0 && opt_val == 0) {
            return true;
        }
    }
    return false;
}

std::string FastScannerEngine::grab_banner(socket_t sock, int port, int timeout_ms) {
    std::string banner = "";
    if (port == 80 || port == 8080 || port == 3000 || port == 5000 || port == 8000) {
        std::string req = "HEAD / HTTP/1.0\r\nUser-Agent: SNMK-FastScan/2.3\r\n\r\n";
        send(sock, req.c_str(), (int)req.length(), 0);
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select((int)(sock + 1), &read_fds, nullptr, nullptr, &tv) > 0) {
        char buf[512] = {0};
        int bytes = recv(sock, buf, sizeof(buf) - 1, 0);
        if (bytes > 0) {
            banner = std::string(buf, bytes);
            // Clean up to first newline or Server header
            size_t s_pos = banner.find("Server: ");
            if (s_pos != std::string::npos) {
                size_t e_pos = banner.find("\r\n", s_pos);
                if (e_pos != std::string::npos) {
                    banner = banner.substr(s_pos + 8, e_pos - (s_pos + 8));
                }
            } else {
                size_t n_pos = banner.find("\r\n");
                if (n_pos != std::string::npos) banner = banner.substr(0, n_pos);
            }
        }
    }
    return banner;
}

std::vector<std::string> FastScannerEngine::resolve_dns(const std::string& hostname) {
    std::vector<std::string> ips;
    struct addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) == 0 && res) {
        for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
            char ip_str[INET_ADDRSTRLEN] = {0};
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            if (inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN)) {
                std::string ip(ip_str);
                if (std::find(ips.begin(), ips.end(), ip) == ips.end()) {
                    ips.push_back(ip);
                }
            }
        }
        freeaddrinfo(res);
    }
    return ips;
}

std::vector<PortResult> FastScannerEngine::scan_ports(
    const std::string& target_ip,
    const std::vector<int>& ports,
    int timeout_ms,
    int max_threads
) {
    std::vector<PortResult> results;
    std::mutex mtx;
    std::queue<int> port_queue;

    for (int p : ports) {
        port_queue.push(p);
    }

    auto identify_service = [](int port) -> std::string {
        switch (port) {
            case 21: return "ftp";
            case 22: return "ssh";
            case 23: return "telnet";
            case 25: return "smtp";
            case 53: return "dns";
            case 80: return "http";
            case 110: return "pop3";
            case 143: return "imap";
            case 443: return "https";
            case 445: return "smb";
            case 3000: return "http-dev";
            case 3306: return "mysql";
            case 5000: return "http-api";
            case 5432: return "postgresql";
            case 6379: return "redis";
            case 8000: return "http-alt";
            case 8080: return "http-proxy";
            case 8443: return "https-alt";
            case 8888: return "http-admin";
            case 9000: return "sonarqube/fastapi";
            case 27017: return "mongodb";
            default: return "unknown";
        }
    };

    auto worker = [&]() {
        while (true) {
            int port = 0;
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (port_queue.empty()) break;
                port = port_queue.front();
                port_queue.pop();
            }

            auto start_t = std::chrono::high_resolution_clock::now();
            socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET_VAL) continue;

            set_nonblocking(sock);

            struct sockaddr_in target_addr;
            std::memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(port);
            inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);

            int conn_res = connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr));
            bool is_open = false;
            double latency_ms = 0.0;

            if (conn_res == 0) {
                is_open = true;
            } else {
                is_open = check_socket_connected(sock, timeout_ms);
            }

            auto end_t = std::chrono::high_resolution_clock::now();
            latency_ms = std::chrono::duration<double, std::milli>(end_t - start_t).count();

            if (is_open) {
                std::string banner = grab_banner(sock, port, 150);
                PortResult r;
                r.port = port;
                r.state = "open";
                r.service = identify_service(port);
                r.banner = banner;
                r.latency_ms = latency_ms;

                std::lock_guard<std::mutex> lock(mtx);
                results.push_back(r);
            }

            CLOSE_SOCKET(sock);
        }
    };

    int actual_threads = std::min((int)ports.size(), max_threads);
    if (actual_threads < 1) actual_threads = 1;

    std::vector<std::thread> thread_pool;
    for (int i = 0; i < actual_threads; ++i) {
        thread_pool.emplace_back(worker);
    }

    for (auto& t : thread_pool) {
        if (t.joinable()) t.join();
    }

    std::sort(results.begin(), results.end(), [](const PortResult& a, const PortResult& b) {
        return a.port < b.port;
    });

    return results;
}

std::vector<SubdomainResult> FastScannerEngine::probe_subdomains(
    const std::string& base_domain,
    const std::vector<std::string>& prefixes,
    int timeout_ms,
    int max_threads
) {
    std::vector<SubdomainResult> results;
    std::mutex mtx;
    std::queue<std::string> sub_queue;

    for (const auto& p : prefixes) {
        sub_queue.push(p);
    }

    auto worker = [&]() {
        while (true) {
            std::string prefix = "";
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (sub_queue.empty()) break;
                prefix = sub_queue.front();
                sub_queue.pop();
            }

            std::string sub = prefix + "." + base_domain;
            auto start_t = std::chrono::high_resolution_clock::now();
            std::vector<std::string> ips = resolve_dns(sub);

            if (!ips.empty()) {
                SubdomainResult sr;
                sr.subdomain = sub;
                sr.ips = ips;
                sr.is_live = true;

                // Fast HTTP test on port 80/443
                socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s != INVALID_SOCKET_VAL) {
                    set_nonblocking(s);
                    struct sockaddr_in addr;
                    std::memset(&addr, 0, sizeof(addr));
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(80);
                    inet_pton(AF_INET, ips[0].c_str(), &addr.sin_addr);

                    connect(s, (struct sockaddr*)&addr, sizeof(addr));
                    if (check_socket_connected(s, timeout_ms / 2)) {
                        sr.status_code = 200;
                        sr.server_banner = grab_banner(s, 80, 200);
                    }
                    CLOSE_SOCKET(s);
                }

                auto end_t = std::chrono::high_resolution_clock::now();
                sr.latency_ms = std::chrono::duration<double, std::milli>(end_t - start_t).count();

                std::lock_guard<std::mutex> lock(mtx);
                results.push_back(sr);
            }
        }
    };

    int actual_threads = std::min((int)prefixes.size(), max_threads);
    if (actual_threads < 1) actual_threads = 1;

    std::vector<std::thread> thread_pool;
    for (int i = 0; i < actual_threads; ++i) {
        thread_pool.emplace_back(worker);
    }

    for (auto& t : thread_pool) {
        if (t.joinable()) t.join();
    }

    return results;
}

std::vector<PathResult> FastScannerEngine::probe_paths(
    const std::string& host,
    const std::vector<std::string>& paths,
    int port,
    bool use_ssl,
    int timeout_ms,
    int max_threads
) {
    (void)use_ssl;
    std::vector<PathResult> results;
    std::vector<std::string> ips = resolve_dns(host);
    if (ips.empty()) return results;

    std::string target_ip = ips[0];
    std::mutex mtx;
    std::queue<std::string> path_queue;
    for (const auto& p : paths) path_queue.push(p);

    auto worker = [&]() {
        while (true) {
            std::string path = "";
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (path_queue.empty()) break;
                path = path_queue.front();
                path_queue.pop();
            }

            socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET_VAL) continue;

            set_nonblocking(sock);
            struct sockaddr_in addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);

            connect(sock, (struct sockaddr*)&addr, sizeof(addr));
            if (check_socket_connected(sock, timeout_ms)) {
                std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
                send(sock, req.c_str(), (int)req.length(), 0);

                fd_set rset;
                FD_ZERO(&rset);
                FD_SET(sock, &rset);
                struct timeval tv;
                tv.tv_sec = timeout_ms / 1000;
                tv.tv_usec = (timeout_ms % 1000) * 1000;

                if (select((int)(sock + 1), &rset, nullptr, nullptr, &tv) > 0) {
                    char buf[1024] = {0};
                    int n = recv(sock, buf, sizeof(buf) - 1, 0);
                    if (n > 0) {
                        std::string resp(buf, n);
                        int sc = 0;
                        if (resp.find("HTTP/1.") != std::string::npos && resp.length() > 12) {
                            try {
                                sc = std::stoi(resp.substr(9, 3));
                            } catch (...) {}
                        }
                        if (sc == 200 || sc == 301 || sc == 302 || sc == 401 || sc == 403) {
                            PathResult pr;
                            pr.path = path;
                            pr.status_code = sc;
                            pr.content_length = n;
                            pr.exists = true;

                            std::lock_guard<std::mutex> lock(mtx);
                            results.push_back(pr);
                        }
                    }
                }
            }
            CLOSE_SOCKET(sock);
        }
    };

    int actual_threads = std::min((int)paths.size(), max_threads);
    if (actual_threads < 1) actual_threads = 1;

    std::vector<std::thread> thread_pool;
    for (int i = 0; i < actual_threads; ++i) {
        thread_pool.emplace_back(worker);
    }
    for (auto& t : thread_pool) {
        if (t.joinable()) t.join();
    }
    return results;
}

std::string FastScannerEngine::serialize_json(const ScanSummary& summary) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"engine\": \"SNMK C++ Fast Scanner v2.3-NATIVE\",\n";
    ss << "  \"target\": \"" << summary.target << "\",\n";
    ss << "  \"resolved_ip\": \"" << summary.resolved_ip << "\",\n";
    ss << "  \"total_duration_ms\": " << std::fixed << std::setprecision(2) << summary.total_duration_ms << ",\n";

    // Ports
    ss << "  \"open_ports\": [\n";
    for (size_t i = 0; i < summary.open_ports.size(); ++i) {
        const auto& p = summary.open_ports[i];
        ss << "    {\"port\": " << p.port
           << ", \"state\": \"" << p.state << "\""
           << ", \"service\": \"" << p.service << "\""
           << ", \"banner\": \"" << p.banner << "\""
           << ", \"latency_ms\": " << p.latency_ms << "}";
        if (i + 1 < summary.open_ports.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ],\n";

    // Subdomains
    ss << "  \"subdomains\": [\n";
    for (size_t i = 0; i < summary.subdomains.size(); ++i) {
        const auto& s = summary.subdomains[i];
        ss << "    {\"subdomain\": \"" << s.subdomain << "\""
           << ", \"ip\": \"" << (s.ips.empty() ? "" : s.ips[0]) << "\""
           << ", \"status\": " << s.status_code
           << ", \"banner\": \"" << s.server_banner << "\""
           << ", \"latency_ms\": " << s.latency_ms << "}";
        if (i + 1 < summary.subdomains.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ],\n";

    // Paths
    ss << "  \"paths\": [\n";
    for (size_t i = 0; i < summary.paths.size(); ++i) {
        const auto& p = summary.paths[i];
        ss << "    {\"path\": \"" << p.path << "\""
           << ", \"status\": " << p.status_code
           << ", \"content_length\": " << p.content_length << "}";
        if (i + 1 < summary.paths.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ]\n";
    ss << "}\n";
    return ss.str();
}

} // namespace snmk

int main(int argc, char* argv[]) {
    std::string target = "127.0.0.1";
    std::string mode = "ports";
    int threads = 32;
    int timeout_ms = 400;
    bool json_output = true;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--version" || arg == "-v" || arg == "version") {
            std::cout << "v2.3.0 (C++17 Native Acceleration)" << std::endl;
            return 0;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "SNMK C++ High-Speed Scanner Engine v2.3.0\n"
                      << "Usage: snmk_fast_scan [options]\n"
                      << "  --target <host>       Target domain or IP\n"
                      << "  --mode <mode>         ports|subdomains|paths|all\n"
                      << "  --threads <n>         Worker thread count (default: 32)\n"
                      << "  --timeout-ms <ms>     Socket timeout (default: 400)\n"
                      << "  --json                Emit JSON output\n";
            return 0;
        } else if (arg == "--target" && i + 1 < argc) target = argv[++i];
        else if (arg == "--mode" && i + 1 < argc) mode = argv[++i];
        else if (arg == "--threads" && i + 1 < argc) threads = std::stoi(argv[++i]);
        else if (arg == "--timeout-ms" && i + 1 < argc) timeout_ms = std::stoi(argv[++i]);
        else if (arg == "--text") json_output = false;
        else if (arg == "--json") json_output = true;
    }

    snmk::FastScannerEngine engine;
    auto start_all = std::chrono::high_resolution_clock::now();

    snmk::ScanSummary summary;
    summary.target = target;

    // Resolve IP
    std::vector<std::string> ips = engine.resolve_dns(target);
    summary.resolved_ip = ips.empty() ? target : ips[0];

    // Standard high-value pentest ports
    std::vector<int> ports = {
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3000, 3306,
        3389, 5000, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017
    };

    if (mode == "ports" || mode == "all") {
        summary.open_ports = engine.scan_ports(summary.resolved_ip, ports, timeout_ms, threads);
    }

    if (mode == "subdomains" || mode == "all") {
        std::vector<std::string> prefixes = {
            "api", "dev", "admin", "staging", "test", "app", "portal", "mail",
            "vpn", "auth", "backend", "docs", "beta", "cdn", "status", "dashboard",
            "corp", "secure", "login", "internal", "gateway", "billing", "cloud"
        };
        summary.subdomains = engine.probe_subdomains(target, prefixes, timeout_ms * 2, threads);
    }

    if (mode == "paths" || mode == "all") {
        std::vector<std::string> paths = {
            "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
            "/openapi.json", "/swagger.json", "/api-docs", "/actuator/health",
            "/config.json", "/backup.sql", "/server-status"
        };
        summary.paths = engine.probe_paths(target, paths, 80, false, timeout_ms, 16);
    }

    auto end_all = std::chrono::high_resolution_clock::now();
    summary.total_duration_ms = std::chrono::duration<double, std::milli>(end_all - start_all).count();

    if (json_output) {
        std::cout << engine.serialize_json(summary) << std::endl;
    } else {
        std::cout << "Target: " << summary.target << " (" << summary.resolved_ip << ")\n";
        std::cout << "Duration: " << summary.total_duration_ms << " ms\n";
        std::cout << "Open Ports (" << summary.open_ports.size() << "):\n";
        for (const auto& p : summary.open_ports) {
            std::cout << "  - " << p.port << " [" << p.service << "] (" << p.latency_ms << "ms)\n";
        }
    }

    return 0;
}
