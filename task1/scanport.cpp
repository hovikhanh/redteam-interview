// =====================================================================
// scanport.exe - Multi-threaded TCP Port Scanner
// Tác giả: Red Team Assessment
// Ngôn ngữ: C++17
// Nền tảng: Windows (Winsock2)
//
// Cú pháp:
//   scanport.exe -h <hosts> -p <ports> -n <threads> -t <timeout_ms>
//
// Ví dụ:
//   scanport.exe -h 192.168.1.0/24 -p 80,443,445 -n 5 -t 3000
//   scanport.exe -h 192.168.1.10-100 -p 80,443,445 -n 5 -t 3000
//   scanport.exe -h 192.168.1.10,192.168.1.25,10.10.1.0/24 -p 80,443 -n 5 -t 3000
//
// Biên dịch (MSVC):
//   cl /EHsc /std:c++17 /O2 scanport.cpp /link Ws2_32.lib
// Biên dịch (MinGW):
//   g++ -std=c++17 -O2 scanport.cpp -o scanport.exe -lws2_32
// =====================================================================

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <iomanip>

#pragma comment(lib, "Ws2_32.lib")

// ----------------------------------------------------------------------
// Cấu trúc chứa kết quả scan của một host:port
// ----------------------------------------------------------------------
struct ScanResult {
    std::string ip;
    int         port;
    bool        open;
};

// ----------------------------------------------------------------------
// Cấu trúc cấu hình chương trình
// ----------------------------------------------------------------------
struct Config {
    std::vector<std::string> hosts;   // Danh sách IP đã expand ra dạng phẳng
    std::vector<int>         ports;   // Danh sách port cần scan
    int                      threads     = 5;     // Số luồng đồng thời
    int                      timeoutMs   = 3000;  // Timeout cho connect (ms)
    int                      hostDelayMs = 50;    // Nghỉ giữa các host (ms) - mặc định 50ms
};

// ----------------------------------------------------------------------
// Mutex bảo vệ I/O ra console (cho output đẹp khi đa luồng)
// ----------------------------------------------------------------------
std::mutex g_coutMutex;

// ----------------------------------------------------------------------
// Tiện ích: tách chuỗi theo ký tự phân cách
// ----------------------------------------------------------------------
static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

// ----------------------------------------------------------------------
// Tiện ích: trim khoảng trắng đầu/cuối chuỗi
// ----------------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return s.substr(a, b - a + 1);
}

// ----------------------------------------------------------------------
// Chuyển IP dạng string "a.b.c.d" -> uint32_t (host byte order)
// ----------------------------------------------------------------------
static bool ipToUint32(const std::string& ip, uint32_t& out) {
    auto parts = split(ip, '.');
    if (parts.size() != 4) return false;
    uint32_t v = 0;
    for (auto& p : parts) {
        try {
            int n = std::stoi(p);
            if (n < 0 || n > 255) return false;
            v = (v << 8) | (uint32_t)n;
        } catch (...) {
            return false;
        }
    }
    out = v;
    return true;
}

// ----------------------------------------------------------------------
// Chuyển uint32_t (host byte order) -> string IP "a.b.c.d"
// ----------------------------------------------------------------------
static std::string uint32ToIp(uint32_t v) {
    std::ostringstream os;
    os << ((v >> 24) & 0xFF) << "."
       << ((v >> 16) & 0xFF) << "."
       << ((v >>  8) & 0xFF) << "."
       << ( v        & 0xFF);
    return os.str();
}

// ----------------------------------------------------------------------
// Expand một token host thành danh sách IP cụ thể
// Hỗ trợ:
//   - IP đơn:        "192.168.1.10"
//   - CIDR:          "192.168.1.0/24"
//   - Range:         "192.168.1.10-100" (chỉ đổi octet cuối)
//                    hoặc đầy đủ "192.168.1.10-192.168.1.100"
// ----------------------------------------------------------------------
static std::vector<std::string> expandHostToken(const std::string& token) {
    std::vector<std::string> result;
    std::string t = trim(token);
    if (t.empty()) return result;

    // ----- Trường hợp CIDR -----
    if (t.find('/') != std::string::npos) {
        auto parts = split(t, '/');
        if (parts.size() != 2) return result;
        uint32_t base;
        if (!ipToUint32(parts[0], base)) return result;
        int prefix = 0;
        try { prefix = std::stoi(parts[1]); } catch (...) { return result; }
        if (prefix < 0 || prefix > 32) return result;

        // Mask theo prefix
        uint32_t mask    = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
        uint32_t network = base & mask;
        uint32_t broad   = network | (~mask);

        // Với /31 và /32 thì duyệt hết, ngược lại bỏ network & broadcast
        uint32_t start = (prefix >= 31) ? network : network + 1;
        uint32_t end   = (prefix >= 31) ? broad   : broad   - 1;
        for (uint32_t ip = start; ip <= end; ++ip) {
            result.push_back(uint32ToIp(ip));
            if (ip == 0xFFFFFFFFu) break; // tránh tràn
        }
        return result;
    }

    // ----- Trường hợp Range -----
    if (t.find('-') != std::string::npos) {
        auto parts = split(t, '-');
        if (parts.size() != 2) return result;

        uint32_t startIp = 0, endIp = 0;
        if (!ipToUint32(parts[0], startIp)) return result;

        // "192.168.1.10-100" => parts[1] = "100", lấy 3 octet đầu của startIp
        if (parts[1].find('.') == std::string::npos) {
            int last = 0;
            try { last = std::stoi(parts[1]); } catch (...) { return result; }
            if (last < 0 || last > 255) return result;
            endIp = (startIp & 0xFFFFFF00u) | (uint32_t)last;
        } else {
            if (!ipToUint32(parts[1], endIp)) return result;
        }

        if (endIp < startIp) std::swap(startIp, endIp);
        for (uint32_t ip = startIp; ip <= endIp; ++ip) {
            result.push_back(uint32ToIp(ip));
            if (ip == 0xFFFFFFFFu) break;
        }
        return result;
    }

    // ----- Trường hợp IP đơn -----
    uint32_t v;
    if (ipToUint32(t, v)) result.push_back(t);
    return result;
}

// ----------------------------------------------------------------------
// Parse tham số host (chuỗi có thể chứa nhiều token ngăn bởi ',')
// ----------------------------------------------------------------------
static std::vector<std::string> parseHosts(const std::string& s) {
    std::vector<std::string> all;
    auto tokens = split(s, ',');
    for (auto& tk : tokens) {
        auto exp = expandHostToken(tk);
        all.insert(all.end(), exp.begin(), exp.end());
    }
    // Loại trùng nhưng vẫn giữ thứ tự
    std::vector<std::string> dedup;
    dedup.reserve(all.size());
    for (auto& ip : all) {
        if (std::find(dedup.begin(), dedup.end(), ip) == dedup.end())
            dedup.push_back(ip);
    }
    return dedup;
}

// ----------------------------------------------------------------------
// Parse tham số port
// ----------------------------------------------------------------------
static std::vector<int> parsePorts(const std::string& s) {
    std::vector<int> out;
    auto tokens = split(s, ',');
    for (auto& tk : tokens) {
        try {
            int p = std::stoi(trim(tk));
            if (p > 0 && p <= 65535) out.push_back(p);
        } catch (...) {}
    }
    return out;
}

// ----------------------------------------------------------------------
// Kiểm tra một (ip, port) có mở hay không bằng non-blocking connect + select
// Trả về true nếu kết nối TCP thành công trong khoảng timeoutMs
// ----------------------------------------------------------------------
static bool checkPort(const std::string& ip, int port, int timeoutMs) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    // Chuyển socket sang chế độ non-blocking
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    bool isOpen = false;
    int  ret    = connect(sock, (sockaddr*)&addr, sizeof(addr));

    if (ret == 0) {
        isOpen = true; // kết nối được ngay (loopback chẳng hạn)
    } else {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            // Đợi bằng select với timeout cấu hình
            fd_set writeSet, errSet;
            FD_ZERO(&writeSet);
            FD_ZERO(&errSet);
            FD_SET(sock, &writeSet);
            FD_SET(sock, &errSet);

            timeval tv{};
            tv.tv_sec  =  timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;

            int sel = select(0, nullptr, &writeSet, &errSet, &tv);
            if (sel > 0 && FD_ISSET(sock, &writeSet)) {
                // Kiểm tra lỗi socket sau khi select trả về
                int       soErr   = 0;
                int       len     = sizeof(soErr);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                               (char*)&soErr, &len) == 0 && soErr == 0) {
                    isOpen = true;
                }
            }
        }
    }

    closesocket(sock);
    return isOpen;
}

// ----------------------------------------------------------------------
// Cấu trúc job được đẩy vào hàng đợi: scan toàn bộ port của 1 host
// ----------------------------------------------------------------------
struct HostJob {
    std::string ip;
};

// ----------------------------------------------------------------------
// Hàng đợi an toàn cho đa luồng (thread-safe FIFO)
// ----------------------------------------------------------------------
class JobQueue {
public:
    void push(const HostJob& j) {
        std::lock_guard<std::mutex> lk(m_);
        q_.push(j);
    }
    bool pop(HostJob& j) {
        std::lock_guard<std::mutex> lk(m_);
        if (q_.empty()) return false;
        j = q_.front();
        q_.pop();
        return true;
    }
    size_t size() {
        std::lock_guard<std::mutex> lk(m_);
        return q_.size();
    }
private:
    std::mutex            m_;
    std::queue<HostJob>   q_;
};

// ----------------------------------------------------------------------
// Biến đếm dùng chung cho tiến độ
// ----------------------------------------------------------------------
static std::atomic<int> g_hostsDone{0};
static std::atomic<int> g_openFound{0};

// ----------------------------------------------------------------------
// Worker function - mỗi luồng chạy hàm này, lấy job từ queue và scan
// ----------------------------------------------------------------------
static void workerThread(JobQueue& queue,
                         const Config& cfg,
                         std::vector<ScanResult>& results,
                         std::mutex& resultsMutex,
                         int totalHosts) {
    HostJob job;
    while (queue.pop(job)) {
        // Scan từng port của host này
        for (int port : cfg.ports) {
            bool open = checkPort(job.ip, port, cfg.timeoutMs);
            {
                std::lock_guard<std::mutex> lk(resultsMutex);
                results.push_back({job.ip, port, open});
            }
            if (open) {
                g_openFound.fetch_add(1);
                std::lock_guard<std::mutex> lk(g_coutMutex);
                std::cout << "  [+] OPEN  " << std::setw(15) << std::left
                          << job.ip << " : " << port << "\n";
            }
        }

        int done = g_hostsDone.fetch_add(1) + 1;
        {
            std::lock_guard<std::mutex> lk(g_coutMutex);
            std::cout << "  [.] Tiến độ: " << done << "/" << totalHosts
                      << " host (" << (done * 100 / totalHosts) << "%)\r"
                      << std::flush;
        }

        // Nghỉ giữa các host theo yêu cầu đề bài (ms)
        if (cfg.hostDelayMs > 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(cfg.hostDelayMs));
        }
    }
}

// ----------------------------------------------------------------------
// In hướng dẫn sử dụng
// ----------------------------------------------------------------------
static void printUsage() {
    std::cout <<
    "scanport.exe - Multi-threaded TCP Port Scanner\n"
    "\n"
    "Cú pháp:\n"
    "  scanport.exe -h <hosts> -p <ports> -n <threads> -t <timeout_ms> [-d <delay_ms>]\n"
    "\n"
    "Tham số:\n"
    "  -h   Danh sách host. Hỗ trợ:\n"
    "         + IP đơn:  192.168.1.10\n"
    "         + Range:   192.168.1.10-100\n"
    "         + CIDR:    192.168.1.0/24\n"
    "         + Hỗn hợp: 192.168.1.10,10.10.0.0/24,192.168.2.5-50\n"
    "  -p   Danh sách port, ngăn cách bởi ',' (ví dụ: 80,443,445)\n"
    "  -n   Số luồng quét đồng thời (mặc định 5)\n"
    "  -t   Timeout cho mỗi connect, đơn vị mili giây (mặc định 3000)\n"
    "  -d   (Tùy chọn) Khoảng nghỉ giữa các host của mỗi luồng (ms, mặc định 50)\n"
    "\n"
    "Ví dụ:\n"
    "  scanport.exe -h 192.168.1.0/24 -p 80,443,445 -n 10 -t 2000\n"
    "  scanport.exe -h 192.168.1.10-100 -p 22,80,443 -n 5 -t 3000 -d 100\n";
}

// ----------------------------------------------------------------------
// Parse argv -> Config
// ----------------------------------------------------------------------
static bool parseArgs(int argc, char** argv, Config& cfg) {
    std::string hostsStr, portsStr;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "-h" || a == "--hosts")   && i + 1 < argc) hostsStr = argv[++i];
        else if ((a == "-p" || a == "--ports")   && i + 1 < argc) portsStr = argv[++i];
        else if ((a == "-n" || a == "--threads") && i + 1 < argc) cfg.threads     = std::atoi(argv[++i]);
        else if ((a == "-t" || a == "--timeout") && i + 1 < argc) cfg.timeoutMs   = std::atoi(argv[++i]);
        else if ((a == "-d" || a == "--delay")   && i + 1 < argc) cfg.hostDelayMs = std::atoi(argv[++i]);
        else if (a == "-?" || a == "--help") { printUsage(); return false; }
    }

    if (hostsStr.empty() || portsStr.empty()) {
        std::cerr << "[!] Thiếu tham số -h hoặc -p\n\n";
        printUsage();
        return false;
    }

    cfg.hosts = parseHosts(hostsStr);
    cfg.ports = parsePorts(portsStr);

    if (cfg.hosts.empty()) { std::cerr << "[!] Không có host hợp lệ\n"; return false; }
    if (cfg.ports.empty()) { std::cerr << "[!] Không có port hợp lệ\n"; return false; }
    if (cfg.threads     < 1) cfg.threads     = 1;
    if (cfg.timeoutMs   < 1) cfg.timeoutMs   = 1000;
    if (cfg.hostDelayMs < 0) cfg.hostDelayMs = 0;

    // Giới hạn số luồng không vượt quá số host (lãng phí)
    if (cfg.threads > (int)cfg.hosts.size())
        cfg.threads = (int)cfg.hosts.size();

    return true;
}

// ======================================================================
// MAIN
// ======================================================================
int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);  // Hiển thị tiếng Việt trên console

    Config cfg;
    if (!parseArgs(argc, argv, cfg)) return 1;

    // ----- Khởi tạo Winsock -----
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "[!] WSAStartup thất bại\n";
        return 1;
    }

    // ----- In thông tin cấu hình -----
    std::cout << "==========================================================\n";
    std::cout << " Multi-threaded TCP Port Scanner\n";
    std::cout << "==========================================================\n";
    std::cout << " Số host         : " << cfg.hosts.size() << "\n";
    std::cout << " Số port         : " << cfg.ports.size() << "  (";
    for (size_t i = 0; i < cfg.ports.size(); ++i) {
        std::cout << cfg.ports[i];
        if (i + 1 < cfg.ports.size()) std::cout << ",";
    }
    std::cout << ")\n";
    std::cout << " Số luồng        : " << cfg.threads     << "\n";
    std::cout << " Timeout         : " << cfg.timeoutMs   << " ms\n";
    std::cout << " Nghỉ giữa host  : " << cfg.hostDelayMs << " ms\n";
    std::cout << "==========================================================\n";
    std::cout << "[*] Bắt đầu scan...\n\n";

    // ----- Đẩy job vào queue -----
    JobQueue queue;
    for (auto& ip : cfg.hosts) queue.push({ip});

    // ----- Khởi động worker threads -----
    auto t0 = std::chrono::steady_clock::now();

    std::vector<ScanResult> results;
    std::mutex              resultsMutex;
    std::vector<std::thread> workers;
    workers.reserve(cfg.threads);

    int totalHosts = (int)cfg.hosts.size();
    for (int i = 0; i < cfg.threads; ++i) {
        workers.emplace_back(workerThread,
                             std::ref(queue), std::cref(cfg),
                             std::ref(results), std::ref(resultsMutex),
                             totalHosts);
    }
    for (auto& th : workers) th.join();

    auto t1   = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();

    // ----- In tổng kết -----
    std::cout << "\n\n==========================================================\n";
    std::cout << " TỔNG KẾT\n";
    std::cout << "==========================================================\n";
    std::cout << " Tổng số kiểm tra : " << results.size() << "\n";
    std::cout << " Cổng mở tìm thấy : " << g_openFound.load() << "\n";
    std::cout << " Thời gian        : " << std::fixed << std::setprecision(2)
              << sec << " giây\n";

    // ----- Liệt kê các máy có ít nhất một port mở -----
    std::cout << "\n Các máy có port mở:\n";
    std::vector<std::string> hostsWithOpen;
    for (auto& r : results) {
        if (r.open &&
            std::find(hostsWithOpen.begin(), hostsWithOpen.end(), r.ip)
            == hostsWithOpen.end()) {
            hostsWithOpen.push_back(r.ip);
        }
    }
    if (hostsWithOpen.empty()) {
        std::cout << "  (không có)\n";
    } else {
        for (auto& ip : hostsWithOpen) {
            std::cout << "  " << ip << "  -> ports: ";
            bool first = true;
            for (auto& r : results) {
                if (r.ip == ip && r.open) {
                    if (!first) std::cout << ",";
                    std::cout << r.port;
                    first = false;
                }
            }
            std::cout << "\n";
        }
    }
    std::cout << "==========================================================\n";

    WSACleanup();
    return 0;
}
