#include <iostream>
#include <pcap.h>
#include <winsock2.h> 

#pragma pack(push, 1) // Disable C++ memory padding

#include <unordered_map>
#include <chrono>
#include <onnxruntime_cxx_api.h>
#include <vector>
#include <deque>

// --- NETWORK STRUCTS ---

struct ip_address {
    u_char byte1, byte2, byte3, byte4;
};

struct ethernet_header {
    u_char  dest_mac[6];
    u_char  src_mac[6];
    u_short type;
};

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

struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
};

#pragma pack(pop) 

// --- STATE TRACKING STRUCTS ---

struct FlowKey {
    uint32_t ip1;
    uint32_t ip2;
    uint16_t port1;
    uint16_t port2;
    uint8_t  protocol;

    bool operator==(const FlowKey& other) const {
        return ip1 == other.ip1 && ip2 == other.ip2 &&
            port1 == other.port1 && port2 == other.port2 &&
            protocol == other.protocol;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const {
        return std::hash<uint32_t>()(k.ip1) ^ std::hash<uint32_t>()(k.ip2) ^
            std::hash<uint16_t>()(k.port1) ^ std::hash<uint16_t>()(k.port2) ^
            std::hash<uint8_t>()(k.protocol);
    }
};

struct FlowStats {
    uint32_t initiator_ip = 0;

    uint16_t initiator_port = 0;
    uint16_t responder_port = 0;

    // Prevent "Ghost Flow" ML triggers
    bool inference_done = false;

    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_time;

    std::chrono::steady_clock::time_point syn_time;
    std::chrono::steady_clock::time_point synack_time;
    bool has_syn = false;
    bool has_synack = false;

    float spkts = 0.0f;
    float dpkts = 0.0f;
    float sbytes = 0.0f;
    float dbytes = 0.0f;
    float sttl = 0.0f;
    float dttl = 0.0f;

    float tcprtt = 0.0f;
    float synack = 0.0f;
    float ackdat = 0.0f;
};

std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flow_table;

struct PastConnection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;
    std::chrono::steady_clock::time_point end_time;
};

std::deque<PastConnection> history_buffer;

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

Ort::Env* ort_env;
Ort::Session* ort_session;

// --- PROTOTYPES ---
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void process_flow_inference(const FlowKey& key, FlowStats& stats, uint8_t final_tcp_flags);

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum;
    int i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return 1;
    }

    for (device = alldevs; device != nullptr; device = device->next) {
        std::cout << ++i << ". " << device->name;
        if (device->description) std::cout << " (" << device->description << ")";
        std::cout << "\n";
    }

    if (i == 0) return 1;

    std::cout << "Enter interface (1-" << i << "): ";
    std::cin >> inum;

    if (inum < 1 || inum > i) {
        pcap_freealldevs(alldevs);
        return 1;
    }

    device = alldevs;
    for (int j = 0; j < inum - 1; j++) device = device->next;

    std::cout << "\nOpening " << device->description << "...\n";
    pcap_t* adhandle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);

    if (adhandle == nullptr) return 1;

    std::cout << "Listening for traffic...\n";
    ort_env = new Ort::Env(ORT_LOGGING_LEVEL_WARNING, "NetworkAnomaly");
    Ort::SessionOptions session_options;
    session_options.SetIntraOpNumThreads(1);

    ort_session = new Ort::Session(*ort_env, L"anomaly_detector.onnx", session_options);

    pcap_loop(adhandle, 0, packet_handler, nullptr);

    pcap_close(adhandle);
    delete ort_env;
    return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (header->caplen < sizeof(ethernet_header)) return;

    ethernet_header* eth = (ethernet_header*)pkt_data;
    if (ntohs(eth->type) != 0x0800) return;

    if (header->caplen < sizeof(ethernet_header) + sizeof(ip_header)) return;
    ip_header* ih = (ip_header*)(pkt_data + 14);

    if (ih->proto != 6 && ih->proto != 17) return;

    int ip_len = (ih->ver_ihl & 0xf) * 4;
    // Guaranteed memory bound safety
    if (ip_len < 20 || header->caplen < 14 + ip_len) return;

    u_short source_port = 0;
    u_short dest_port = 0;
    uint8_t tcp_flags = 0;

    if (ih->proto == 6) {
        if (header->caplen < 14 + ip_len + sizeof(tcp_header)) return;
        tcp_header* th = (tcp_header*)((u_char*)ih + ip_len);
        source_port = ntohs(th->sport);
        dest_port = ntohs(th->dport);
        tcp_flags = th->flags;
    }
    else if (ih->proto == 17) {
        if (header->caplen < 14 + ip_len + sizeof(udp_header)) return;
        udp_header* uh = (udp_header*)((u_char*)ih + ip_len);
        source_port = ntohs(uh->sport);
        dest_port = ntohs(uh->dport);
    }

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
        flow_table[key].initiator_port = source_port;
        flow_table[key].responder_port = dest_port;
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

    if (ih->proto == 6) {
        uint8_t syn_ack_flags = tcp_flags & 0x12;
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
    }

    // --- FLOW TERMINATION TRIGGERS ---
    bool is_tcp_closed = (ih->proto == 6 && (tcp_flags & 0x01 || tcp_flags & 0x04));

    // Ghost flow fix: run inference once, let GC erase it later
    if (is_tcp_closed && !flow_table[key].inference_done) {
        process_flow_inference(key, flow_table[key], tcp_flags);
        flow_table[key].inference_done = true;
    }

    // Periodic Garbage Collection
    static int packet_count = 0;
    if (++packet_count % 1000 == 0) {
        for (auto it = flow_table.begin(); it != flow_table.end(); ) {
            std::chrono::duration<float> idle_time = now - it->second.last_time;
            if (idle_time.count() > 120.0f) {
                if (!it->second.inference_done) {
                    process_flow_inference(it->first, it->second, 0);
                }
                it = flow_table.erase(it);
            }
            else {
                ++it;
            }
        }
    }
}

void process_flow_inference(const FlowKey& key, FlowStats& stats, uint8_t final_tcp_flags) {
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<float> duration = stats.last_time - stats.start_time;
    float dur = duration.count();
    if (dur <= 0.0f) dur = 0.0001f;

    float sload = (stats.sbytes * 8.0f) / dur;
    float dload = (stats.dbytes * 8.0f) / dur;
    float smeansz = stats.spkts > 0 ? (stats.sbytes / stats.spkts) : 0;
    float dmeansz = stats.dpkts > 0 ? (stats.dbytes / stats.dpkts) : 0;

    while (!history_buffer.empty()) {
        std::chrono::duration<float> age = now - history_buffer.front().end_time;
        if (age.count() > 100.0f) {
            history_buffer.pop_front();
        }
        else {
            break;
        }
    }

    float ct_srv_src = 0.0f, ct_srv_dst = 0.0f;
    float ct_dst_ltm = 0.0f, ct_src_ltm = 0.0f;
    float ct_src_dport_ltm = 0.0f, ct_dst_sport_ltm = 0.0f;
    float ct_dst_src_ltm = 0.0f;

    uint32_t dest_ip_check = (stats.initiator_ip == key.ip1) ? key.ip2 : key.ip1;

    for (const auto& past : history_buffer) {
        if (past.src_ip == stats.initiator_ip) {
            ct_src_ltm += 1.0f;
            if (past.dport == stats.responder_port) {
                ct_srv_src += 1.0f;
                ct_src_dport_ltm += 1.0f;
            }
            if (past.dst_ip == dest_ip_check) {
                ct_dst_src_ltm += 1.0f;
            }
        }
        if (past.dst_ip == dest_ip_check) {
            ct_dst_ltm += 1.0f;
            if (past.dport == stats.responder_port) ct_srv_dst += 1.0f;
            if (past.sport == stats.initiator_port) ct_dst_sport_ltm += 1.0f;
        }
    }

    std::cout << "\n[!] FLOW ENDED! Sending to ML Engine...\n";
    std::cout << "Proto: " << (int)key.protocol << " | Port: " << stats.responder_port << " | Duration: " << dur << "s\n";
    std::cout << "------------------------------------\n";

    std::vector<float> input_features(64, 0.0f);

    input_features[0] = (float)stats.initiator_port;
    input_features[1] = (float)stats.responder_port;
    input_features[2] = dur;
    input_features[3] = stats.sbytes;
    input_features[4] = stats.dbytes;
    input_features[5] = stats.sttl;
    input_features[6] = stats.dttl;
    input_features[7] = sload;
    input_features[8] = dload;
    input_features[9] = stats.spkts;
    input_features[10] = stats.dpkts;
    input_features[15] = smeansz;
    input_features[16] = dmeansz;
    input_features[25] = stats.tcprtt;
    input_features[26] = stats.synack;
    input_features[27] = stats.ackdat;
    input_features[33] = ct_srv_src;
    input_features[34] = ct_srv_dst;
    input_features[35] = ct_dst_ltm;
    input_features[36] = ct_src_ltm;
    input_features[37] = ct_src_dport_ltm;
    input_features[38] = ct_dst_sport_ltm;
    input_features[39] = ct_dst_src_ltm;

    for (int i = 0; i < 40; i++) {
        input_features[i] = (input_features[i] - SCALER_MEANS[i]) / SCALER_SCALES[i];
    }

    if (key.protocol == 6) input_features[45] = 1.0f;
    else if (key.protocol == 17) input_features[46] = 1.0f;
    else input_features[43] = 1.0f;

    if (final_tcp_flags & 0x01) input_features[51] = 1.0f;
    else if (final_tcp_flags & 0x04) input_features[54] = 1.0f;
    else input_features[49] = 1.0f;

    if (stats.responder_port == 80 || stats.initiator_port == 80 || stats.responder_port == 443 || stats.initiator_port == 443) {
        input_features[59] = 1.0f;
    }
    else if (stats.responder_port == 53 || stats.initiator_port == 53) {
        input_features[56] = 1.0f;
    }
    else if (stats.responder_port == 22 || stats.initiator_port == 22) {
        input_features[62] = 1.0f;
    }
    else {
        input_features[63] = 1.0f;
    }

    std::vector<int64_t> input_shape = { 1, 64 };
    Ort::MemoryInfo memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
        memory_info, input_features.data(), input_features.size(),
        input_shape.data(), input_shape.size()
    );

    // --- 5. EXECUTE ML INFERENCE ---

    const char* input_names[] = { "X" };
    const char* output_names[] = { "label" };
    
    auto output_tensors = ort_session->Run(Ort::RunOptions{nullptr}, input_names, &input_tensor, 1, output_names, 1);

    // Assuming the model returns a 2-element array: [is_attack, category_index]
    int64_t* prediction = output_tensors.front().GetTensorMutableData<int64_t>();

    int is_attack = (int)prediction[0];      // 0 = Safe, 1 = Attack
    int category_id = (int)prediction[1];    // 0 to 9 matching your dictionary

    // --- 6. MULTI-CLASS MAPPING DICTIONARY ---
    const char* ATTACK_CATEGORIES[10] = {
        "Analysis",       // 0
        "Backdoor",       // 1
        "DoS",            // 2
        "Exploits",       // 3
        "Fuzzers",        // 4
        "Generic",        // 5
        "Normal",         // 6
        "Reconnaissance", // 7
        "Shellcode",      // 8
        "Worms"           // 9
    };

    // --- 7. ALERT LOGIC BASED ON THE [0/1] FLAG ---
    if (is_attack == 0) {
        std::cout << "[+] Traffic Safe (Classified as: "
                  << (category_id >= 0 && category_id <= 9 ? ATTACK_CATEGORIES[category_id] : "Unknown")
                  << ")\n";
    } else {
        std::cout << "\n[!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]\n";
        std::cout << "[!!!] MALICIOUS NETWORK ANOMALY DETECTED [!!!]\n";
        std::cout << "[!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]\n";

        std::string attack_name = (category_id >= 0 && category_id <= 9) ? ATTACK_CATEGORIES[category_id] : "Unknown Attack";
        std::cout << "--> Attack Type: " << attack_name << " (Index: " << category_id << ")\n";
        std::cout << "--> Target Port: " << stats.responder_port << "\n\n";
    }
    

    PastConnection finished_flow;
    finished_flow.src_ip = stats.initiator_ip;
    finished_flow.dst_ip = dest_ip_check;
    finished_flow.sport = stats.initiator_port;
    finished_flow.dport = stats.responder_port;
    finished_flow.end_time = now;
    history_buffer.push_back(finished_flow);
}