#define NOMINMAX

#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <winsock2.h>
#include <unordered_map>
#include <chrono>
#include <onnxruntime_cxx_api.h>
#include <vector>
#include <deque>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

#pragma pack(push, 1)

// ============================================================
// FLOW KEY
// ============================================================

struct FlowKey {
	uint32_t ip1;
	uint32_t ip2;
	uint16_t port1;
	uint16_t port2;
	uint8_t protocol;

	bool operator==(const FlowKey& other) const {
		return ip1 == other.ip1 &&
			ip2 == other.ip2 &&
			port1 == other.port1 &&
			port2 == other.port2 &&
			protocol == other.protocol;
	}
};

// ============================================================
// FLOW KEY HASH
// ============================================================

struct FlowKeyHash {
	std::size_t operator()(const FlowKey& k) const {
		return std::hash<uint32_t>()(k.ip1) ^
			std::hash<uint32_t>()(k.ip2) ^
			std::hash<uint16_t>()(k.port1) ^
			std::hash<uint16_t>()(k.port2) ^
			std::hash<uint8_t>()(k.protocol);
	}
};

// ============================================================
// FLOW STATISTICS
// ============================================================

struct FlowStats {
	uint32_t initiator_ip = 0;
	uint16_t initiator_port = 0;
	uint32_t responder_ip = 0;
	uint16_t responder_port = 0;

	std::chrono::system_clock::time_point start_wall_time;
	std::chrono::system_clock::time_point last_wall_time;

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

// ============================================================
// FLOW TABLE
// ============================================================

std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flow_table;

// ============================================================
// HISTORICAL CONNECTION BUFFER
// ============================================================

struct PastConnection {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t sport;
	uint16_t dport;
	uint8_t protocol;
	std::chrono::steady_clock::time_point end_time;
};

std::deque<PastConnection> history_buffer;
const int MAX_HISTORY_SIZE = 100;

// ============================================================
// STANDARD SCALER
// ============================================================

const float SCALER_MEANS[40] = {
	30528.973f, 11234.938f, 0.665228f, 4320.729f, 36459.259f, 62.787798f, 30.77548f, 36994481.25f, 2448548.63f, 33.2869f,
	42.7493f, 150.127f, 149.788f, 1262547038.28f, 1262347668.45f, 124.274f, 276.656f, 0.08323f, 4244.997f, 1594.469f,
	728.525f, 1423260858.68f, 1423260859.45f, 192.209f, 78.0007f, 0.006212f, 0.00331f, 0.002901f, 0.001641f, 0.261138f,
	0.10995f, 0.017373f, 0.020598f, 9.208554f, 8.99077f, 6.44090f, 6.90217f, 4.64418f, 3.59322f, 6.84807f
};

const float SCALER_SCALES[40] = {
	20441.034f, 18439.401f, 15.47065f, 54107.394f, 160982.095f, 74.6249f, 42.8740f, 118794697.62f, 4222341.40f, 75.3330f,
	121.3835f, 125.4754f, 125.5363f, 1422293446.27f, 1422287033.74f, 151.9056f, 335.7083f, 0.345228f, 47589.807f, 17036.134f,
	3302.869f, 1134427.50f, 1134427.30f, 2768.376f, 1420.030f, 0.046986f, 0.026627f, 0.024192f, 0.040478f, 0.683128f,
	0.553182f, 0.133472f, 0.184531f, 10.83509f, 10.82113f, 8.16319f, 8.20662f, 8.47863f, 6.17334f, 11.2581f
};

// ============================================================
// ONNX GLOBALS
// ============================================================

Ort::Env* ort_env = nullptr;
Ort::Session* ort_session = nullptr;
Ort::MemoryInfo ort_mem_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

// ============================================================
// ATTACK LABELS
// ============================================================

std::string attack_labels[] = {
	"Normal", "Analysis", "Backdoor", "DoS", "Exploits",
	"Fuzzers", "Generic", "Reconnaissance", "Shellcode", "Worms"
};

// ============================================================
// PACKET STRUCTURES
// ============================================================

struct ip_address {
	u_char byte1, byte2, byte3, byte4;
};

struct ethernet_header {
	u_char dest_mac[6];
	u_char src_mac[6];
	u_short type;
};

struct ip_header {
	u_char ver_ihl, tos;
	u_short tlen, identification, flags_fo;
	u_char ttl, proto;
	u_short crc;
	ip_address saddr, daddr;
};

struct tcp_header {
	u_short sport, dport;
	u_int seq, ack;
	u_char data_offset, flags;
	u_short window, checksum, urp;
};

#pragma pack(pop)

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

// ============================================================
// MAIN
// ============================================================

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
	int inum, i = 0;

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		std::cerr << "[-] Error finding devices: " << errbuf << "\n";
		return 1;
	}

	for (device = alldevs; device != nullptr; device = device->next) {
		std::cout << ++i << ". " << device->name;
		if (device->description) std::cout << " (" << device->description << ")";
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
	for (int j = 0; j < inum - 1; j++) device = device->next;

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

	try {
		std::cout << "[*] Loading ONNX model into memory...(wait for 20 sec)...\n";
		ort_session = new Ort::Session(*ort_env, L"network_anomaly_detector.onnx", session_options);
		std::cout << "[+] ONNX Model loaded successfully!\n\n";
	}
	catch (const Ort::Exception& e) {
		std::cerr << "\n========================================\n"
			<< "[!!! FATAL ONNX RUNTIME ERROR !!!]\n"
			<< e.what() << "\n"
			<< "========================================\n\n";
		delete ort_env;
		return 1;
	}

	std::cout << "=============================================================\n"
		<< " TrackNET is now monitoring network traffic\n"
		<< "=============================================================\n\n";

	pcap_loop(adhandle, 0, packet_handler, nullptr);

	pcap_close(adhandle);
	delete ort_session;
	delete ort_env;
	return 0;
}

// ============================================================
// PACKET HANDLER
// ============================================================

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	if (header->caplen < sizeof(ethernet_header)) return;
	ethernet_header* eth = (ethernet_header*)pkt_data;
	if (ntohs(eth->type) != 0x0800) return;

	if (header->caplen < 14 + sizeof(ip_header)) return;
	ip_header* ih = (ip_header*)(pkt_data + 14);
	int ip_len = (ih->ver_ihl & 0x0F) * 4;
	if (ip_len < 20 || header->caplen < 14 + ip_len) return;
	if (ih->proto != IPPROTO_TCP) return;

	if (header->caplen < 14 + ip_len + sizeof(tcp_header)) return;
	tcp_header* th = (tcp_header*)((u_char*)ih + ip_len);
	int tcp_header_len = ((th->data_offset >> 4) & 0x0F) * 4;
	if (tcp_header_len < 20 || header->caplen < 14 + ip_len + tcp_header_len) return;

	uint16_t source_port = ntohs(th->sport);
	uint16_t dest_port = ntohs(th->dport);
	uint32_t raw_src_ip = *(uint32_t*)&ih->saddr;
	uint32_t raw_dst_ip = *(uint32_t*)&ih->daddr;

	FlowKey key;
	if (raw_src_ip < raw_dst_ip) {
		key.ip1 = raw_src_ip; key.ip2 = raw_dst_ip; key.port1 = source_port; key.port2 = dest_port;
	}
	else if (raw_src_ip > raw_dst_ip) {
		key.ip1 = raw_dst_ip; key.ip2 = raw_src_ip; key.port1 = dest_port; key.port2 = source_port;
	}
	else {
		if (source_port <= dest_port) {
			key.ip1 = raw_src_ip; key.ip2 = raw_dst_ip; key.port1 = source_port; key.port2 = dest_port;
		}
		else {
			key.ip1 = raw_dst_ip; key.ip2 = raw_src_ip; key.port1 = dest_port; key.port2 = source_port;
		}
	}
	key.protocol = ih->proto;

	auto now_steady = std::chrono::steady_clock::now();
	auto now_wall = std::chrono::system_clock::now();

	auto it = flow_table.find(key);
	if (it == flow_table.end()) {
		FlowStats new_flow;
		new_flow.initiator_ip = raw_src_ip;
		new_flow.initiator_port = source_port;
		new_flow.responder_ip = raw_dst_ip;
		new_flow.responder_port = dest_port;
		new_flow.start_time = now_steady;
		new_flow.last_time = now_steady;
		new_flow.start_wall_time = now_wall;
		new_flow.last_wall_time = now_wall;
		flow_table.emplace(key, new_flow);
		it = flow_table.find(key);
	}

	FlowStats& flow = it->second;
	flow.last_time = now_steady;
	flow.last_wall_time = now_wall;

	bool is_client = (raw_src_ip == flow.initiator_ip && source_port == flow.initiator_port);
	uint16_t ip_total_length = ntohs(ih->tlen);

	if (is_client) {
		flow.spkts += 1.0f;
		flow.sbytes += (float)ip_total_length;
		if (flow.sttl == 0.0f) flow.sttl = (float)ih->ttl;
	}
	else {
		flow.dpkts += 1.0f;
		flow.dbytes += (float)ip_total_length;
		if (flow.dttl == 0.0f) flow.dttl = (float)ih->ttl;
	}

	uint8_t flags = th->flags;
	bool syn = (flags & 0x02) != 0;
	bool ack = (flags & 0x10) != 0;
	bool fin = (flags & 0x01) != 0;
	bool rst = (flags & 0x04) != 0;

	if (syn && !ack && !flow.has_syn) {
		flow.syn_time = now_steady;
		flow.has_syn = true;
	}
	else if (syn && ack && flow.has_syn && !flow.has_synack) {
		flow.synack_time = now_steady;
		flow.has_synack = true;
		std::chrono::duration<float> elapsed = now_steady - flow.syn_time;
		flow.synack = (elapsed.count() < 0.0f) ? 0.0f : elapsed.count();
	}
	else if (ack && !syn && flow.has_synack && flow.ackdat == 0.0f) {
		std::chrono::duration<float> elapsed = now_steady - flow.synack_time;
		flow.ackdat = (elapsed.count() < 0.0f) ? 0.0f : elapsed.count();
		flow.tcprtt = flow.synack + flow.ackdat;
	}

	if (!(fin || rst)) return;

	float dur = std::chrono::duration<float>(flow.last_time - flow.start_time).count();
	if (dur <= 0.0f) dur = 0.000001f;

	float sload = (flow.sbytes * 8.0f) / dur;
	float dload = (flow.dbytes * 8.0f) / dur;
	float smeansz = (flow.spkts > 0.0f) ? flow.sbytes / flow.spkts : 0.0f;
	float dmeansz = (flow.dpkts > 0.0f) ? flow.dbytes / flow.dpkts : 0.0f;

	float ct_srv_src = 0.0f, ct_srv_dst = 0.0f, ct_dst_ltm = 0.0f, ct_src_ltm = 0.0f;
	float ct_src_dport_ltm = 0.0f, ct_dst_sport_ltm = 0.0f, ct_dst_src_ltm = 0.0f;

	for (const auto& past : history_buffer) {
		if (past.src_ip == raw_src_ip && past.dport == dest_port) ct_srv_src++;
		if (past.dst_ip == raw_dst_ip && past.dport == dest_port) ct_srv_dst++;
		if (past.dst_ip == raw_dst_ip) ct_dst_ltm++;
		if (past.src_ip == raw_src_ip) ct_src_ltm++;
		if (past.src_ip == raw_src_ip && past.dport == dest_port) ct_src_dport_ltm++;
		if (past.dst_ip == raw_dst_ip && past.sport == source_port) ct_dst_sport_ltm++;
		if (past.src_ip == raw_src_ip && past.dst_ip == raw_dst_ip) ct_dst_src_ltm++;
	}

	float is_sm_ips_ports = (raw_src_ip == raw_dst_ip && source_port == dest_port) ? 1.0f : 0.0f;

	std::vector<float> input_features(64, 0.0f);
	input_features[0] = (float)flow.initiator_port;
	input_features[1] = (float)flow.responder_port;
	input_features[2] = dur;
	input_features[3] = flow.sbytes;
	input_features[4] = flow.dbytes;
	input_features[5] = flow.sttl;
	input_features[6] = flow.dttl;
	input_features[7] = sload;
	input_features[8] = dload;
	input_features[9] = flow.spkts;
	input_features[10] = flow.dpkts;
	input_features[11] = 0.0f; // swin
	input_features[12] = 0.0f; // dwin
	input_features[13] = 0.0f; // stcpb
	input_features[14] = 0.0f; // dtcpb
	input_features[15] = smeansz;
	input_features[16] = dmeansz;
	input_features[17] = 0.0f; // trans_depth
	input_features[18] = 0.0f; // response_body_len
	input_features[19] = 0.0f; // sjit
	input_features[20] = 0.0f; // djit

	auto start_epoch = std::chrono::duration_cast<std::chrono::duration<double>>(flow.start_wall_time.time_since_epoch()).count();
	auto last_epoch = std::chrono::duration_cast<std::chrono::duration<double>>(flow.last_wall_time.time_since_epoch()).count();
	input_features[21] = (float)start_epoch;
	input_features[22] = (float)last_epoch;

	input_features[23] = 0.0f; // sinpkt
	input_features[24] = 0.0f; // dinpkt
	input_features[25] = flow.tcprtt;
	input_features[26] = flow.synack;
	input_features[27] = flow.ackdat;
	input_features[28] = 0.0f; // ct_state_ttl
	input_features[29] = 0.0f; // ct_flw_http_mthd
	input_features[30] = 0.0f; // is_ftp_login
	input_features[31] = 0.0f; // ct_ftp_cmd
	input_features[32] = ct_srv_src;
	input_features[33] = ct_srv_dst;
	input_features[34] = ct_dst_ltm;
	input_features[35] = ct_src_ltm;
	input_features[36] = ct_src_dport_ltm;
	input_features[37] = ct_dst_sport_ltm;
	input_features[38] = ct_dst_src_ltm;
	input_features[39] = is_sm_ips_ports;

	for (int i = 0; i < 40; ++i) {
		input_features[i] = (input_features[i] - SCALER_MEANS[i]) / SCALER_SCALES[i];
	}

	if (key.protocol == IPPROTO_TCP) input_features[45] = 1.0f;
	else if (key.protocol == IPPROTO_UDP) input_features[46] = 1.0f;
	else input_features[43] = 1.0f;

	if (fin) input_features[51] = 1.0f;
	else if (rst) input_features[54] = 1.0f;
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
		Ort::RunOptions{ nullptr }, input_names, &input_tensor, 1, output_names, 1
	);

	auto tensor_info = output_tensors.front().GetTensorTypeAndShapeInfo();
	size_t element_count = tensor_info.GetElementCount();
	int64_t* pred_data = output_tensors.front().GetTensorMutableData<int64_t>();

	int64_t is_attack = pred_data[0];
	int64_t attack_category = (element_count > 1) ? pred_data[1] : 0;

	if (is_attack == 1) {
		std::cout << "\n[!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]\n"
			<< "[!!!] MALICIOUS NETWORK ANOMALY DETECTED [!!!]\n"
			<< "[!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]\n";

		struct in_addr src_addr; src_addr.s_addr = raw_src_ip;
		struct in_addr dst_addr; dst_addr.s_addr = raw_dst_ip;

		std::cout << "--> Attacker (Source): " << inet_ntoa(src_addr) << ":" << source_port << "\n";
		std::cout << "--> Victim (Target)  : " << inet_ntoa(dst_addr) << " (Port: " << dest_port << ")\n";

		if (attack_category >= 0 && attack_category < 10) {
			std::cout << "--> Attack Type      : " << attack_labels[attack_category] << " (Index: " << attack_category << ")\n";
		}
		else {
			std::cout << "--> Attack Type      : Unknown (Index: " << attack_category << ")\n";
		}
		std::cout << "\n";
	}
	else {
		std::cout << "[+] Traffic Safe (Classified as: Normal)\n\n";
	}

	PastConnection finished_flow;
	finished_flow.src_ip = flow.initiator_ip;
	finished_flow.dst_ip = flow.responder_ip;
	finished_flow.sport = flow.initiator_port;
	finished_flow.dport = flow.responder_port;
	finished_flow.protocol = key.protocol;
	finished_flow.end_time = now_steady;

	history_buffer.push_back(finished_flow);
	if (history_buffer.size() > MAX_HISTORY_SIZE) {
		history_buffer.pop_front();
	}

	flow_table.erase(key);
}