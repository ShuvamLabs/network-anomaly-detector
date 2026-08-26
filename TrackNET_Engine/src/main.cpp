#include <iostream>
#include <pcap.h>
#include <winsock2.h> 

#pragma pack(push, 1) // Disable C++ memory padding

#include <unordered_map>
#include <chrono>
#include <onnxruntime_cxx_api.h>
#include <vector>
#include <deque>
#include <string>

// 1. The Key: Normalized to ensure bidirectional traffic hashes to the same flow
struct FlowKey {
    uint32_t ip1; // Always the smaller IP
    uint32_t ip2; // Always the larger IP
    uint16_t port1;
    uint16_t port2;
    uint8_t  protocol;

    bool operator==(const FlowKey& other) const {
        return ip1 == other.ip1 && ip2 == other.ip2 &&
            port1 == other.port1 && port2 == other.port2 &&
            protocol == other.protocol;
    }
};

// 2. Custom Hash Function for FlowKey
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const {
        return std::hash<uint32_t>()(k.ip1) ^ std::hash<uint32_t>()(k.ip2) ^
            std::hash<uint16_t>()(k.port1) ^ std::hash<uint16_t>()(k.port2);
    }
};

// 3. The Value: UNSW-NB15 Flow Features
struct FlowStats {
    uint32_t initiator_ip = 0; // Actual initiator

    // Time tracking for 'dur'
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_time;

    // TCP Handshake Timestamps
    std::chrono::steady_clock::time_point syn_time;
    std::chrono::steady_clock::time_point synack_time;
    bool has_syn = false;
    bool has_synack = false;

    // UNSW-NB15 Base Features
    float spkts = 0.0f;
    float dpkts = 0.0f;
    float sbytes = 0.0f;
    float dbytes = 0.0f;
    float sttl = 0.0f;
    float dttl = 0.0f;

    // TCP RTT Features
    float tcprtt = 0.0f;
    float synack = 0.0f;
    float ackdat = 0.0f;
};

// 4. Flow Table Map
std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flow_table;

// --- HISTORICAL RING BUFFER ---
struct PastConnection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dport;
    std::chrono::steady_clock::time_point end_time;
};

std::deque<PastConnection> history_buffer;
const int MAX_HISTORY_SIZE = 100;

// --- ML ENGINE GLOBALS ---
const float SCALER_MEANS[40] = {
    30528.973f, 11234.938f, 0.665228f, 4320.729f, 36459.259f, 62.787798f, 30.77548f, 36994481.25f, 2448548.63f,
    33.2869f, 42.7493f, 150.127f, 149.788f, 1262547038.28f, 1262347668.45f, 124.274f, 276.656f, 0.08323f,
    4244.997f, 1594.469f, 728.525f, 1423260858.68f, 1423260859.45f, 192.209f, 78.0007f, 0.006212f, 0.00331f,
    0.002901f, 0.001641f, 0.261138f, 0.10995f, 0.017373f, 0.020598f, 9.208554f, 8.99077f, 6.44090f, 6.90217f,
    4.64418f, 3.59322f, 6.84807f
};

const float SCALER_SCALES[40] = {
    20441.034f, 18439.401f, 15.47065f, 54107.394f, 160982.095f, 74.6249f, 42.8740f, 118794697.62f, 4222341.40f,
    75.3330f, 121.3835f, 125.4754f, 125.5363f, 1422293446.27f, 1422287033.74f, 151.9056f, 335.7083f, 0.345228f,
    47589.807f, 17036.134f, 3302.869f, 1134427.50f, 1134427.30f, 2768.376f, 1420.030f, 0.046986f, 0.026627f,
    0.024192f, 0.040478f, 0.683128f, 0.553182f, 0.133472f, 0.184531f, 10.83509f, 10.82113f, 8.16319f, 8.20662f,
    8.47863f, 6.17334f, 11.2581f
};

Ort::Env* ort_env = nullptr;
Ort::Session* ort_session = nullptr;
Ort::MemoryInfo ort_mem_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

// Category Outputs
std::string attack_labels[] = {
    "Normal",
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms"
};

// IPv4 Address format
struct ip_address {
    u_char byte1, byte2, byte3, byte4;
};

// 14-Byte Ethernet Header
struct ethernet_header {
    u_char  dest_mac[6];
    u_char  src_mac[6];
    u_short type;
};

// 20-Byte IPv4 Header
struct ip_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    ip_address saddr;
    ip_address daddr;
};

// 20-Byte TCP Header
struct tcp_header {
    u_short sport;
    u_short dport;
    u_int   seq;
    u_int   ack;
    u_char  data_offset;
    u_char  flags;
    u_short window;
    u_short checksum;
    u_short urp;
};

#pragma pack(pop)

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main() {
    const char* app_banner = R"(
  _______             _    _   _ ______ _______ 
 |__   __|           | |  | \ | |  ____|__   __|
    | |_ __ __ _  ___| | _|  \| | |__     | |   
    | | '__/ _` |/ __| |/ / . ` |  __|    | |   
    | | | | (_| | (__|   <| |\  | |____   | |   
    |_|_|  \__,_|\___|_|\_\_| \_|______|  |_|   
 =================================================
  TrackNET - Real-Time AI Network Intrusion Engine
  Authors : Farhan Khan & Shuvam Chatterjee
 =================================================
)";
    std::cout << app_banner << "\n";

    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum;
    int i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[-] Error finding devices: " << errbuf << "\n";
        return 1;
    }

    for (device = alldevs; device != nullptr; device = device->next) {
        std::cout << ++i << ". " << device->name;
        if (device->description) {
            std::cout << " (" << device->description << ")";
        }
        std::cout << "\n";
    }

    if (i == 0) {
        std::cerr << "\n[-] No interfaces found! Make sure Npcap is installed.\n";
        return 1;
    }

    std::cout << "\nEnter the interface number to sniff (1-" << i << "): ";
    std::cin >> inum;

    if (inum < 1 || inum > i) {
        std::cerr << "[-] Interface number out of range.\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    device = alldevs;
    for (int j = 0; j < inum - 1; j++) {
        device = device->next;
    }

    std::cout << "\n[*] Opening " << device->description << "...\n";

    pcap_t* adhandle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);

    if (adhandle == nullptr) {
        std::cerr << "[-] Unable to open the adapter: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_freealldevs(alldevs);

    std::cout << "[*] Listening for traffic...\n";
    std::cout << "[*] Initializing Machine Learning Engine...\n";

    ort_env = new Ort::Env(ORT_LOGGING_LEVEL_WARNING, "TrackNET");

    Ort::SessionOptions session_options;
    session_options.SetIntraOpNumThreads(4);
    session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_DISABLE_ALL);

    try {
        std::cout << "[*] Loading ONNX model into memory...(wait for 2 minutes)...\n";
        ort_session = new Ort::Session(*ort_env, L"network_anomaly_detector.onnx", session_options);
        std::cout << "[+] ONNX Model loaded successfully!\n\n";
    }
    catch (const Ort::Exception& e) {
        std::cerr << "\n========================================\n";
        std::cerr << "[!!! FATAL ONNX RUNTIME ERROR !!!]\n";
        std::cerr << e.what() << "\n";
        std::cerr << "========================================\n\n";
        delete ort_env;
        return 1;
    }

    pcap_loop(adhandle, 0, packet_handler, nullptr);

    pcap_close(adhandle);
    delete ort_session;
    delete ort_env;

    return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    ethernet_header* eth = (ethernet_header*)pkt_data;
    if (ntohs(eth->type) != 0x0800) return;

    ip_header* ih = (ip_header*)(pkt_data + 14);
    if (ih->proto != 6) return;

    int ip_len = (ih->ver_ihl & 0xf) * 4;
    tcp_header* th = (tcp_header*)((u_char*)ih + ip_len);

    u_short source_port = ntohs(th->sport);
    u_short dest_port = ntohs(th->dport);

    // --- BIDIRECTIONAL FLOW TRACKER ---
    uint32_t raw_src_ip = *(uint32_t*)&ih->saddr;
    uint32_t raw_dst_ip = *(uint32_t*)&ih->daddr;

    FlowKey key;
    if (raw_src_ip < raw_dst_ip) {
        key.ip1 = raw_src_ip;
        key.ip2 = raw_dst_ip;
        key.port1 = source_port;
        key.port2 = dest_port;
    }
    else {
        key.ip1 = raw_dst_ip;
        key.ip2 = raw_src_ip;
        key.port1 = dest_port;
        key.port2 = source_port;
    }
    key.protocol = ih->proto;

    auto now = std::chrono::steady_clock::now();

    if (flow_table.find(key) == flow_table.end()) {
        flow_table[key].initiator_ip = raw_src_ip;
        flow_table[key].start_time = now;
    }

    flow_table[key].last_time = now;

    bool is_client = (raw_src_ip == flow_table[key].initiator_ip);

    if (is_client) {
        flow_table[key].spkts += 1.0f;
        flow_table[key].sbytes += ntohs(ih->tlen);
        if (flow_table[key].sttl == 0) flow_table[key].sttl = ih->ttl;
    }
    else {
        flow_table[key].dpkts += 1.0f;
        flow_table[key].dbytes += ntohs(ih->tlen);
        if (flow_table[key].dttl == 0) flow_table[key].dttl = ih->ttl;
    }

    // --- TCP HANDSHAKE TRACKING ---
    uint8_t syn_ack_flags = th->flags & 0x12;

    if (syn_ack_flags == 0x02 && !flow_table[key].has_syn) {
        flow_table[key].syn_time = now;
        flow_table[key].has_syn = true;
    }
    else if (syn_ack_flags == 0x12 && flow_table[key].has_syn && !flow_table[key].has_synack) {
        flow_table[key].synack_time = now;
        flow_table[key].has_synack = true;

        std::chrono::duration<float> synack_dur = now - flow_table[key].syn_time;
        flow_table[key].synack = synack_dur.count();
    }
    else if (syn_ack_flags == 0x10 && flow_table[key].has_synack && flow_table[key].ackdat == 0.0f) {
        std::chrono::duration<float> ackdat_dur = now - flow_table[key].synack_time;
        flow_table[key].ackdat = ackdat_dur.count();
        flow_table[key].tcprtt = flow_table[key].synack + flow_table[key].ackdat;
    }

    // --- CONNECTION TEARDOWN EVALUATION ---
    if (th->flags & 0x01 || th->flags & 0x04) {

        // Math Calculations
        std::chrono::duration<float> duration = flow_table[key].last_time - flow_table[key].start_time;
        float dur = duration.count();
        if (dur <= 0.0f) dur = 0.0001f;

        float sload = (flow_table[key].sbytes * 8.0f) / dur;
        float dload = (flow_table[key].dbytes * 8.0f) / dur;
        float smeansz = flow_table[key].spkts > 0 ? (flow_table[key].sbytes / flow_table[key].spkts) : 0;
        float dmeansz = flow_table[key].dpkts > 0 ? (flow_table[key].dbytes / flow_table[key].dpkts) : 0;

        // Sliding Window Calculations
        float ct_srv_src = 0.0f;
        float ct_dst_ltm = 0.0f;
        float ct_src_dport_ltm = 0.0f;

        for (const auto& past : history_buffer) {
            if (past.src_ip == raw_src_ip && past.dport == dest_port) {
                ct_srv_src += 1.0f;
                ct_src_dport_ltm += 1.0f;
            }
            if (past.dst_ip == raw_dst_ip) {
                ct_dst_ltm += 1.0f;
            }
        }

        // --- MACHINE LEARNING INFERENCE ---
        std::vector<float> input_features(64, 0.0f);

        input_features[0] = (float)key.port1;
        input_features[1] = (float)key.port2;
        input_features[2] = dur;
        input_features[3] = flow_table[key].sbytes;
        input_features[4] = flow_table[key].dbytes;
        input_features[5] = flow_table[key].sttl;
        input_features[6] = flow_table[key].dttl;
        input_features[7] = sload;
        input_features[8] = dload;
        input_features[9] = flow_table[key].spkts;
        input_features[10] = flow_table[key].dpkts;
        input_features[15] = smeansz;
        input_features[16] = dmeansz;
        input_features[25] = flow_table[key].tcprtt;
        input_features[26] = flow_table[key].synack;
        input_features[27] = flow_table[key].ackdat;
        input_features[33] = ct_srv_src;
        input_features[34] = 0.0f;
        input_features[35] = ct_dst_ltm;
        input_features[36] = 0.0f;
        input_features[37] = ct_src_dport_ltm;
        input_features[38] = 0.0f;
        input_features[39] = 0.0f;

        // Apply StandardScaler Math
        for (int i = 0; i < 40; i++) {
            input_features[i] = (input_features[i] - SCALER_MEANS[i]) / SCALER_SCALES[i];
        }

        // One-Hot Encoded Features
        if (key.protocol == 6) input_features[45] = 1.0f;
        else if (key.protocol == 17) input_features[46] = 1.0f;
        else input_features[43] = 1.0f;

        if (th->flags & 0x01) input_features[51] = 1.0f;
        else if (th->flags & 0x04) input_features[54] = 1.0f;
        else input_features[49] = 1.0f;

        if (dest_port == 80 || source_port == 80 || dest_port == 443 || source_port == 443) {
            input_features[59] = 1.0f;
        }
        else if (dest_port == 53 || source_port == 53) {
            input_features[56] = 1.0f;
        }
        else if (dest_port == 22 || source_port == 22) {
            input_features[62] = 1.0f;
        }
        else {
            input_features[63] = 1.0f;
        }

        std::vector<int64_t> input_shape = { 1, 64 };

        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            ort_mem_info, input_features.data(), input_features.size(),
            input_shape.data(), input_shape.size()
        );

        const char* input_names[] = { "X" };
        const char* output_names[] = { "predictions" };

        auto output_tensors = ort_session->Run(
            Ort::RunOptions{ nullptr },
            input_names,
            &input_tensor,
            1,
            output_names,
            1
        );

        auto tensor_info = output_tensors.front().GetTensorTypeAndShapeInfo();
        size_t element_count = tensor_info.GetElementCount();

        int64_t* pred_data = output_tensors.front().GetTensorMutableData<int64_t>();

        int64_t is_attack = pred_data[0];
        int64_t attack_category = 0;

        if (element_count > 1) {
            attack_category = pred_data[1];
        }

        // --- ACTIONABLE THREAT LOGGING ---
        if (is_attack == 1) {
            std::cout << "\n[!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]\n";
            std::cout << "[!!!] MALICIOUS NETWORK ANOMALY DETECTED [!!!]\n";
            std::cout << "[!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]\n";

            struct in_addr src_addr;
            src_addr.s_addr = raw_src_ip;
            std::string src_ip_str = inet_ntoa(src_addr);

            struct in_addr dst_addr;
            dst_addr.s_addr = raw_dst_ip;
            std::string dst_ip_str = inet_ntoa(dst_addr);

            std::cout << "--> Attacker (Source): " << src_ip_str << "\n";
            std::cout << "--> Victim (Target)  : " << dst_ip_str << " (Port: " << dest_port << ")\n";

            if (attack_category >= 0 && attack_category < 10) {
                std::cout << "--> Attack Type      : " << attack_labels[attack_category] << " (Index: " << attack_category << ")\n";
            }
            else {
                std::cout << "--> Attack Type      : Unknown (Index: " << attack_category << ")\n";
            }
            std::cout << "\n";
        }
        else {
            std::cout << "[+] Traffic Safe (Classified as: Normal)\n\n";
        }

        // Save to History Buffer
        PastConnection finished_flow;
        finished_flow.src_ip = raw_src_ip;
        finished_flow.dst_ip = raw_dst_ip;
        finished_flow.dport = dest_port;
        finished_flow.end_time = now;

        history_buffer.push_back(finished_flow);

        if (history_buffer.size() > MAX_HISTORY_SIZE) {
            history_buffer.pop_front();
        }

        flow_table.erase(key);
    }
}