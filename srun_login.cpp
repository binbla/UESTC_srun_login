/*============================================================
 *   > File Name : srun_login.cpp
 * > Author : binbla
 * > Mail : admin@binbla.com
 * > Created Time : 2025年08月28日 星期四 19时27分00秒
 * > Description : 深澜认证登录程序 适配版本SRunCGIAuthIntfSvr V1.18 B20181212
 * > Usage:
 * ./srun_login                                      # 使用默认配置
 * ./srun_login username:password                    # 指定用户名密码
 * ./srun_login username:password server_ip          # 指定用户名密码和服务器IP
 * ./srun_login username:password server_ip interface #
 *指定用户名密码、服务器IP和网卡 > Config: 配置文件: 程序同目录下的
 *srun_login.conf (可选) 默认服务器: 10.253.0.237 默认用户名:
 * 20240000000@dx-uestc 默认密码: 00000000000 默认网卡: enp2s0 IP地址:
 * 自动从指定网卡获取，失败则使用0.0.0.0 > Parameters: argv[1]:
 *username:password (可选，格式：用户名:密码，默认使用配置值) argv[2]: server_ip
 *(可选，服务器IP地址，默认10.253.0.237) argv[3]: interface
 *(可选，网卡名称，默认enp2s0) >
 * Config File Format (srun_login.conf):
 * 注释行以 # 或 ; 开头
 * server_host=10.253.0.237
 * default_username=20240000000
 * default_password=00000000000
 * default_interface=enp2s0
 * # 更多配置项见示例文件
 *==========================================================*/
#include <arpa/inet.h>
#include <curl/curl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>  // 添加这个头文件以支持std::setw和std::setfill
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

// ---------- URL编码 ----------
std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (std::string::const_iterator i = value.begin(), n = value.end(); i != n;
         ++i) {
        std::string::value_type c = (*i);

        // 保留字母数字字符和一些安全字符
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // 对其他字符进行percent编码
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char)c);
        escaped << std::nouppercase;
    }

    return escaped.str();
}

// ---------- HTTP ----------
struct MemoryStruct {
    char *memory;
    size_t size;
    MemoryStruct() : memory(nullptr), size(0) {}
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                  void *userp) {
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;
    char *ptr = (char *)realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

// ---------- Base64 ----------
class Base64 {
   private:
    static const char _PADCHAR = '=';
    static const std::string _ALPHA;

    static int _getbyte64(const std::string &s, int i) {
        size_t idx = _ALPHA.find(s[i]);
        if (idx == std::string::npos) {
            throw std::runtime_error("Cannot decode base64");
        }
        return static_cast<int>(idx);
    }

    static int _getbyte(const std::string &s, int i) {
        int x = static_cast<unsigned char>(s[i]);
        if (x > 255) {
            throw std::runtime_error("INVALID_CHARACTER_ERR: DOM Exception 5");
        }
        return x;
    }

   public:
    static std::string encode(const std::string &s) {
        if (s.empty()) return s;

        std::vector<std::string> x;
        int i, b10;
        int imax = s.length() - (s.length() % 3);

        for (i = 0; i < imax; i += 3) {
            b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) |
                  _getbyte(s, i + 2);
            x.push_back(std::string(1, _ALPHA[b10 >> 18]));
            x.push_back(std::string(1, _ALPHA[(b10 >> 12) & 63]));
            x.push_back(std::string(1, _ALPHA[(b10 >> 6) & 63]));
            x.push_back(std::string(1, _ALPHA[b10 & 63]));
        }

        switch (s.length() - imax) {
            case 1:
                b10 = _getbyte(s, i) << 16;
                x.push_back(std::string(1, _ALPHA[b10 >> 18]) +
                            std::string(1, _ALPHA[(b10 >> 12) & 63]) +
                            _PADCHAR + _PADCHAR);
                break;
            case 2:
                b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8);
                x.push_back(std::string(1, _ALPHA[b10 >> 18]) +
                            std::string(1, _ALPHA[(b10 >> 12) & 63]) +
                            std::string(1, _ALPHA[(b10 >> 6) & 63]) + _PADCHAR);
                break;
        }

        std::string result;
        for (const auto &part : x) {
            result += part;
        }
        return result;
    }
};

const std::string Base64::_ALPHA =
    "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

std::string base64_encode(const unsigned char *input, int length) {
    std::string s(reinterpret_cast<const char *>(input), length);
    return Base64::encode(s);
}

// ---------- HMAC-MD5 ----------
std::string hmac_md5_hex(const std::string &data, const std::string &key) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    HMAC(EVP_md5(), key.c_str(), key.length(),
         (const unsigned char *)data.c_str(), data.length(), result,
         &result_len);

    std::ostringstream sout;
    for (unsigned int i = 0; i < result_len; i++)
        sout << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    return sout.str();
}

// ---------- SHA1 ----------
std::string sha1_hex(const std::string &str) {
    unsigned char result[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)str.c_str(), str.size(), result);
    std::ostringstream sout;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sout << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    return sout.str();
}

// ---------- 获取指定网卡的IPv4地址 ----------
std::string get_local_ip(const std::string &interface_name = "enp2s0") {
    struct ifaddrs *ifaddr, *ifa;
    std::string ip = "";
    if (getifaddrs(&ifaddr) == -1) return ip;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (strcmp(ifa->ifa_name, interface_name.c_str()) == 0 &&
            ifa->ifa_addr->sa_family == AF_INET) {
            ip = inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);
            break;
        }
    }
    freeifaddrs(ifaddr);
    return ip;
}

// ---------- xEncode ----------
uint32_t u32(uint32_t x) { return x & 0xFFFFFFFF; }

// JavaScript版本的s函数 - 字符串转uint32数组
std::vector<uint32_t> s(const std::string &a, bool b) {
    int c = a.length();
    std::vector<uint32_t> v;

    // 按4字节为单位转换
    for (int i = 0; i < c; i += 4) {
        uint32_t val = 0;
        if (i < c) val |= (unsigned char)a[i];
        if (i + 1 < c) val |= ((unsigned char)a[i + 1]) << 8;
        if (i + 2 < c) val |= ((unsigned char)a[i + 2]) << 16;
        if (i + 3 < c) val |= ((unsigned char)a[i + 3]) << 24;
        v.push_back(val);
    }

    if (b) {
        v.push_back(c);  // 如果b为true，添加字符串长度
    }

    return v;
}

// JavaScript版本的l函数 - uint32数组转字符串
std::string l(std::vector<uint32_t> &a, bool b) {
    int d = a.size();
    int c = (d - 1) << 2;

    if (b) {
        uint32_t m = a[d - 1];
        if (m < c - 3 || m > c) return "";
        c = m;
    }

    std::string result;
    for (int i = 0; i < d; i++) {
        result += (char)(a[i] & 0xff);
        result += (char)((a[i] >> 8) & 0xff);
        result += (char)((a[i] >> 16) & 0xff);
        result += (char)((a[i] >> 24) & 0xff);
    }

    if (b) {
        return result.substr(0, c);
    } else {
        return result;
    }
}

std::string xEncode(const std::string &str, const std::string &key) {
    if (str.empty()) return "";

    std::vector<uint32_t> v = s(str, true);
    std::vector<uint32_t> k = s(key, false);

    if (k.size() < 4) {
        k.resize(4, 0);
    }

    int n = v.size() - 1;
    uint32_t z = v[n];
    uint32_t y = v[0];
    uint32_t c = 0x86014019 | 0x183639a0;
    uint32_t m, e, p;
    int q = 6 + 52 / (n + 1);  // JavaScript中的Math.floor
    uint32_t d = 0;

    while (0 < q--) {
        d = (d + c) & (0x8ce0d9bf | 0x731f2640);
        e = (d >> 2) & 3;

        for (p = 0; p < n; p++) {
            y = v[p + 1];
            m = (z >> 5) ^ (y << 2);
            m += (y >> 3) ^ (z << 4) ^ (d ^ y);
            m += k[(p & 3) ^ e] ^ z;
            z = v[p] = (v[p] + m) & (0xefb8d130 | 0x10472ecf);
        }

        y = v[0];
        m = (z >> 5) ^ (y << 2);
        m += (y >> 3) ^ (z << 4) ^ (d ^ y);
        m += k[(p & 3) ^ e] ^ z;
        z = v[n] = (v[n] + m) & (0xbb390742 | 0x44c6f8bd);
    }

    return l(v, false);
}

// ---------- encode info ----------
std::string encode_info(const ordered_json &info_data,
                        const std::string &challenge) {
    std::string x = xEncode(info_data.dump(), challenge);
    return "{SRBX1}" +
           base64_encode((const unsigned char *)x.c_str(), x.size());
}

// ---------- 发起 GET 请求 ----------
std::string http_get(const std::string &url, const std::string &params,
                     const std::string &user_agent = "") {
    CURL *curl = curl_easy_init();
    MemoryStruct chunk;
    if (curl) {
        std::string full_url = url + "?" + params;
        std::cout << "GET Request URL: " << full_url << std::endl;

        // 设置HTTP headers
        struct curl_slist *headers = nullptr;
        std::string ua_header =
            "User-Agent: " +
            (user_agent.empty()
                 ? "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, "
                   "like Gecko) Chrome/120.0.0.0 Safari/537.36"
                 : user_agent);
        headers = curl_slist_append(headers, ua_header.c_str());
        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers,
                                    "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        headers = curl_slist_append(headers, "Cache-Control: no-cache");

        curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            std::cerr << "CURL Error: " << curl_easy_strerror(res) << std::endl;

        // 清理headers
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    std::string ret = chunk.memory ? std::string(chunk.memory, chunk.size) : "";
    if (chunk.memory) free(chunk.memory);
    return ret;
}

// ---------- 配置变量 ----------
struct LoginConfig {
    std::string server_host = "10.253.0.237";
    std::string username_suffix = "@dx-uestc";
    std::string default_username = "202400000000";
    std::string default_password = "00000000";
    std::string default_ip = "0.0.0.0";
    std::string default_interface = "enp2s0";
    std::string user_agent =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/120.0.0.0 Safari/537.36";
    std::string fake_callback_prefix = "jQuery1124011346170079978446_";
    std::string acid = "1";
    std::string enc_ver = "srun_bx1";
    std::string n = "200";
    std::string type = "1";
    std::string os = "Linux";
    std::string name = "Linux";
    std::string double_stack = "0";
};

// ---------- 配置文件读取 ----------
std::string get_program_dir(const char *argv0) {
    std::string program_path = argv0;
    size_t last_slash = program_path.find_last_of('/');
    if (last_slash != std::string::npos) {
        return program_path.substr(0, last_slash + 1);
    }
    return "./";  // 如果没有路径分隔符，说明在当前目录
}

void show_help(const char *program_name) {
    std::cout << "\n========== 深澜认证登录程序 ==========" << std::endl;
    std::cout << "作者: binbla <admin@binbla.com>" << std::endl;
    std::cout << "版本: 1.0.0" << std::endl;
    std::cout << "\n用法:" << std::endl;
    std::cout << "  " << program_name << " [选项] [参数...]" << std::endl;
    std::cout << "\n参数:" << std::endl;
    std::cout << "  " << program_name
              << "                                      # 使用默认配置"
              << std::endl;
    std::cout << "  " << program_name
              << " username:password                    # 指定用户名密码"
              << std::endl;
    std::cout
        << "  " << program_name
        << " username:password server_ip          # 指定用户名密码和服务器IP"
        << std::endl;
    std::cout << "  " << program_name
              << " username:password server_ip interface # "
                 "指定用户名密码、服务器IP和网卡"
              << std::endl;
    std::cout << "\n选项:" << std::endl;
    std::cout
        << "  -h, --help                                显示此帮助信息并退出"
        << std::endl;
    std::cout
        << "  -v, --version                             显示版本信息并退出"
        << std::endl;
    std::cout << "\n参数说明:" << std::endl;
    std::cout << "  username:password  用户名:密码格式，默认使用配置文件中的值"
              << std::endl;
    std::cout << "  server_ip          服务器IP地址，默认: 10.253.0.237"
              << std::endl;
    std::cout << "  interface          网卡名称，默认: enp2s0" << std::endl;
    std::cout << "\n配置文件:" << std::endl;
    std::cout << "  程序会自动加载同目录下的 srun_login.conf 配置文件"
              << std::endl;
    std::cout << "  配置文件格式: key=value，支持 # 或 ; 开头的注释行"
              << std::endl;
    std::cout << "\n默认配置:" << std::endl;
    std::cout << "  服务器: 10.253.0.237" << std::endl;
    std::cout
        << "  用户名: 202400000000@dx-uestc，后缀是自动添加的，输入学号就行"
        << std::endl;
    std::cout << "  密码: 000000000000" << std::endl;
    std::cout << "  网卡: enp2s0" << std::endl;
    std::cout << "  IP获取: 自动从指定网卡获取，最后则使用服务器返回的client_ip"
              << std::endl;
    std::cout << "\n示例:" << std::endl;
    std::cout << "  " << program_name
              << "                                      # 使用默认配置登录"
              << std::endl;
    std::cout << "  " << program_name
              << " myuser:mypass                        # 使用自定义用户名密码"
              << std::endl;
    std::cout << "  " << program_name
              << " myuser:mypass 192.168.1.1            # 指定服务器IP"
              << std::endl;
    std::cout << "  " << program_name
              << " myuser:mypass 192.168.1.1 eth0       # 指定网卡"
              << std::endl;
    std::cout << "======================================\n" << std::endl;
}

void show_version() {
    std::cout << "深澜认证登录程序 v1.0.0" << std::endl;
    std::cout << "作者: binbla <admin@binbla.com>" << std::endl;
    std::cout << "编译时间: " << __DATE__ << " " << __TIME__ << std::endl;
}

void load_config_file(LoginConfig &config, const std::string &config_path) {
    std::ifstream config_file(config_path);
    if (!config_file.is_open()) {
        std::cout << "Config file not found: " << config_path
                  << ", using default config." << std::endl;
        return;
    }

    std::cout << "Loading config from: " << config_path << std::endl;
    std::string line;
    while (std::getline(config_file, line)) {
        // 跳过空行和注释行
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        // 查找等号分隔符
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        // 去除前后空格
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        // 设置配置值
        if (key == "server_host") config.server_host = value;
        else if (key == "username_suffix") config.username_suffix = value;
        else if (key == "default_username") config.default_username = value;
        else if (key == "default_password") config.default_password = value;
        else if (key == "default_ip") config.default_ip = value;
        else if (key == "default_interface") config.default_interface = value;
        else if (key == "user_agent") config.user_agent = value;
        else if (key == "fake_callback_prefix")
            config.fake_callback_prefix = value;
        else if (key == "acid") config.acid = value;
        else if (key == "enc_ver") config.enc_ver = value;
        else if (key == "n") config.n = value;
        else if (key == "type") config.type = value;
        else if (key == "os") config.os = value;
        else if (key == "name") config.name = value;
        else if (key == "double_stack") config.double_stack = value;
        else {
            std::cout << "Unknown config key: " << key << std::endl;
        }
    }
    config_file.close();
    std::cout << "Config loaded successfully." << std::endl;
}

// ---------- 主程序 ----------
int main(int argc, char **argv) {
    // 检查帮助和版本参数
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            show_help(argv[0]);
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            show_version();
            return 0;
        }
    }

    std::cout << "Program started!" << std::endl;
    std::cout.flush();

    LoginConfig config;

    // 尝试加载配置文件
    std::string program_dir = get_program_dir(argv[0]);
    std::string config_file_path = program_dir + "srun_login.conf";
    load_config_file(config, config_file_path);

    std::string username, password, local_ip, interface_name;

    // 处理命令行参数
    if (argc >= 2) {
        std::string arg = argv[1];
        // 跳过帮助和版本参数
        if (arg == "-h" || arg == "--help" || arg == "-v" ||
            arg == "--version") {
            // 这些参数已经在上面处理过了
            return 0;
        }

        size_t colon_pos = arg.find(':');
        if (colon_pos != std::string::npos) {
            username = arg.substr(0, colon_pos) + config.username_suffix;
            password = arg.substr(colon_pos + 1);
        } else {
            std::cerr << "错误: 用户名密码格式无效。请使用: username:password"
                      << std::endl;
            std::cerr << "使用 " << argv[0] << " --help 查看帮助信息"
                      << std::endl;
            return 1;
        }
    } else {
        // 使用默认值
        username = config.default_username + config.username_suffix;
        password = config.default_password;
    }

    // 处理服务器地址参数
    if (argc >= 3) {
        config.server_host = argv[2];
    }

    // 处理网卡名称参数
    if (argc >= 4) {
        interface_name = argv[3];
    } else {
        interface_name = config.default_interface;
    }

    // 从指定网卡获取IP地址
    local_ip = get_local_ip(interface_name);
    if (local_ip.empty()) {
        local_ip = config.default_ip;
        std::cout << "Cannot get IP from interface " << interface_name
                  << ", using default: " << local_ip << std::endl;
    } else {
        std::cout << "Got IP " << local_ip << " from interface "
                  << interface_name << std::endl;
    }

    std::cout << "Username: " << username << std::endl;
    std::cout << "Password: " << password << std::endl;
    std::cout << "Using IP: " << local_ip << std::endl;
    std::cout << "Interface: " << interface_name << std::endl;
    std::cout << "Server: " << config.server_host << std::endl;

    // ---------- Step1: get_challenge ----------
    std::string callback =
        config.fake_callback_prefix + std::to_string(time(nullptr) * 1000);
    std::string params = "callback=" + url_encode(callback) +
                         "&username=" + url_encode(username) +
                         "&ip=" + url_encode(local_ip) +
                         "&_=" + std::to_string(time(nullptr) * 1000);
    std::string challenge_url =
        "http://" + config.server_host + "/cgi-bin/get_challenge";
    std::string resp = http_get(challenge_url, params, config.user_agent);
    std::cout << "Get Challenge response: " << resp << std::endl;

    // 提取challenge
    size_t pos1 = resp.find("\"challenge\":\"");
    if (pos1 == std::string::npos) {
        std::cerr << "Cannot find challenge" << std::endl;
        return 1;
    }
    size_t challenge_start = pos1 + strlen("\"challenge\":\"");
    size_t pos2 = resp.find("\"", challenge_start);
    if (pos2 == std::string::npos) {
        std::cerr << "Cannot find end of challenge" << std::endl;
        return 1;
    }
    std::string challenge =
        resp.substr(challenge_start, pos2 - challenge_start);
    std::cout << "Challenge: " << challenge << std::endl;

    // 提取服务器返回的client_ip
    size_t pos3 = resp.find("\"client_ip\":\"");
    if (pos3 == std::string::npos) {
        std::cerr << "Cannot find client_ip" << std::endl;
        return 1;
    }
    size_t start_pos = pos3 + strlen("\"client_ip\":\"");
    size_t pos4 = resp.find("\"", start_pos);
    if (pos4 == std::string::npos) {
        std::cerr << "Cannot find end of client_ip" << std::endl;
        return 1;
    }
    std::string client_ip = resp.substr(start_pos, pos4 - start_pos);
    std::cout << "Client IP: " << client_ip << std::endl;

    // 在get_challenge请求传参会传送本机地址，但实测发现传0.0.0.0的话服务器也能返回本机地址。
    // 也就是说在get_challenge阶段，本地IP是非必要的
    // 不想改动上面的代码了，所以这里直接用服务器返回的地址替换
    // 应该没啥影响
    local_ip = client_ip;  // 使用服务器返回的IP地址

    // DEBUG：检查计算结果
    // Use the preset challenge value instead of getting it from the server
    // challenge =
    //     "389893ff06136ed273377fc26284f188cbd16e1cff5569f54fdae8b30c8efd1f";
    // std::cout << "Using preset challenge: " << challenge << std::endl;

    // ---------- Step2: 构造 info ----------
    // 使用ordered_json来保持字段顺序，按照JS代码的顺序
    ordered_json info_data;
    info_data["username"] = username;
    info_data["password"] = password;
    info_data["ip"] = local_ip;
    info_data["acid"] = config.acid;
    info_data["enc_ver"] = config.enc_ver;
    std::cout << "Info data JSON: " << info_data.dump() << std::endl;
    std::string info = encode_info(info_data, challenge);
    std::cout << "Encoded info: " << info << std::endl;

    // ---------- Step3: 构造 hmd5 ----------
    std::string hmd5 = hmac_md5_hex(password, challenge);
    std::cout << "Password: " << password << std::endl;
    std::cout << "Challenge (key): " << challenge << std::endl;
    std::cout << "HMAC-MD5: " << hmd5 << std::endl;

    // ---------- Step4: 构造 chksum ----------
    std::string chkstr = challenge + username + challenge + hmd5 + challenge +
                         config.acid + challenge + local_ip + challenge +
                         config.n + challenge + config.type + challenge + info;
    std::cout << "Checksum string: " << chkstr << std::endl;
    std::string chksum = sha1_hex(chkstr);
    std::cout << "Checksum (SHA1): " << chksum << std::endl;

    // ---------- Step5: login ----------
    params = "callback=" + url_encode(callback) +
             "&action=login&username=" + url_encode(username) +
             "&password={MD5}" + url_encode(hmd5) + "&ac_id=" + config.acid +
             "&ip=" + url_encode(local_ip) + "&chksum=" + url_encode(chksum) +
             "&info=" + url_encode(info) + "&n=" + config.n +
             "&type=" + config.type + "&os=" + url_encode(config.os) +
             "&name=" + url_encode(config.name) +
             "&double_stack=" + config.double_stack +
             "&_=" + std::to_string(time(nullptr) * 1000);
    std::cout << "Login parameters: " << params << std::endl;
    std::string login_url =
        "http://" + config.server_host + "/cgi-bin/srun_portal";
    std::string login_resp = http_get(login_url, params, config.user_agent);
    std::cout << "Login response: " << login_resp << std::endl;

    return 0;
}
