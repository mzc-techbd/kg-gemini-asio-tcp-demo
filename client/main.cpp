#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include <thread>
#include <chrono>
#include <numeric>   // For std::accumulate
#include <limits>    // For std::numeric_limits
#include <atomic>    // For std::atomic
#include <mutex>     // For std::mutex, std::unique_lock
#include <condition_variable> // For std::condition_variable
#include <future>    // For std::async, std::future
#include <algorithm> // For std::min_element, std::max_element
#include <memory>    // For std::shared_ptr
#include <iomanip>   // For std::fixed, std::setprecision, std::put_time
#include <sstream>   // For std::stringstream

#include <asio.hpp>
#include <asio/read_until.hpp>
#include "common/constants.h"
#include "common/logger.h"

using asio::ip::tcp;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

// --- Runtime Configuration Variables ---
int num_connections = common::client::MAX_CONCURRENT_CONNECTIONS;
int interval_ms = common::client::DEFAULT_INTERVAL_MS;
int epoch = common::client::DEFAULT_EPOCH;

// --- Synchronization Primitives ---
std::atomic<int> connected_clients{0};
std::atomic<int> completed_clients{0};
std::mutex start_mutex;
std::mutex stats_mutex;
std::condition_variable start_cv;
std::condition_variable completion_cv;
bool all_connected_flag = false;
bool all_completed_flag = false;

// --- Global Sentence Storage ---
std::vector<std::string> g_sentences;
std::mutex sentences_mutex;

// --- Utility Functions ---
// Generate a timestamp string for filenames
std::string generate_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
        
    std::tm tm_now;
    #ifdef _WIN32
        localtime_s(&tm_now, &time_t_now);
    #else
        localtime_r(&time_t_now, &tm_now);
    #endif
    
    std::ostringstream oss;
    oss << std::put_time(&tm_now, "%Y%m%d_%H%M%S") << "_" << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

// --- Statistics Structure ---
struct ThreadStats {
    int thread_id = 0;
    bool connection_successful = false;
    int requests_attempted = 0;
    int requests_succeeded = 0;
    int requests_failed = 0;
    std::vector<long long> rtts_ms;
    std::vector<std::string> responses; // Added to store response texts
    std::vector<std::string> sent_messages; // Added to store sent messages
    
    std::pair<double, double> get_rtt_stats() const {
        if (rtts_ms.empty()) {
            return {0.0, 0.0}; // avg, stddev
        }
        
        double sum = 0.0;
        for (const auto& rtt : rtts_ms) {
            sum += rtt;
        }
        double avg = sum / rtts_ms.size();
        
        double variance_sum = 0.0;
        for (const auto& rtt : rtts_ms) {
            double diff = rtt - avg;
            variance_sum += diff * diff;
        }
        double stddev = std::sqrt(variance_sum / rtts_ms.size());
        
        return {avg, stddev};
    }

    std::pair<long long, long long> get_min_max_rtt() const {
        if (rtts_ms.empty()) {
            return {0, 0}; // min, max
        }
        
        auto [min_it, max_it] = std::minmax_element(rtts_ms.begin(), rtts_ms.end());
        return {*min_it, *max_it};
    }
};

// Function to read sentences from the Korean text file
std::vector<std::string> read_sentences(const std::string& filename) {
    std::vector<std::string> sentences;
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        LOG_CRITICAL("Failed to open sentence file: {}", filename);
        return sentences;
    }
    
    // Check for UTF-8 BOM and skip if present
    char bom[3];
    file.read(bom, 3);
    if (!(bom[0] == (char)0xEF && bom[1] == (char)0xBB && bom[2] == (char)0xBF)) {
        file.seekg(0);
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty() && line.find_first_not_of(" \t") != std::string::npos) {
             sentences.push_back(line);
        }
    }
    
    if (sentences.empty()) {
        LOG_WARN("Sentence file '{}' is empty or contains no valid sentences.", filename);
    } else {
        LOG_INFO("Successfully read {} sentences from {}", sentences.size(), filename);
    }
    
    return sentences;
}

// Function to send a message and wait for response
bool send_and_receive(tcp::socket& socket, 
                     const std::string& message, 
                     long long& rtt_ms,
                     asio::streambuf& response_buf,
                     std::string& response_text) {
    try {
        // Sanitize the message to ensure it contains valid characters
        std::string sanitized_message;
        sanitized_message.reserve(message.size());
        
        // Only keep valid text characters - this helps prevent JSON parsing errors on server side
        for (size_t i = 0; i < message.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(message[i]);
            
            // Handle Korean UTF-8 characters (Hangul)
            if (i + 2 < message.size() && 
                (c >= common::UTF8_LEAD_BYTE_MIN && c <= common::UTF8_LEAD_BYTE_MAX)) {
                // This could be a Korean character (3-byte UTF-8)
                sanitized_message.push_back(message[i]);
                sanitized_message.push_back(message[i+1]);
                sanitized_message.push_back(message[i+2]);
                i += 2; // Skip the next 2 bytes as we've included them
            }
            // Include ASCII printable characters
            else if (c >= 32 && c <= 126) {
                sanitized_message.push_back(message[i]);
            }
            // Include whitespace
            else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                sanitized_message.push_back(message[i]);
            }
            // Skip all other characters
        }
        
        // Make sure the message doesn't exceed buffer size
        if (sanitized_message.size() > common::BUFFER_SIZE - 10) { // Leave some space for safety
            sanitized_message.resize(common::BUFFER_SIZE - 10);
            LOG_WARN("Message truncated to fit buffer size");
        }

        // Ensure we send a newline delimiter if not already present
        if (!sanitized_message.empty() && sanitized_message.back() != common::MESSAGE_DELIMITER) {
            sanitized_message.push_back(common::MESSAGE_DELIMITER);
        }

        // Check if socket is connected before attempting to write
        if (!socket.is_open()) {
            LOG_ERROR("Socket is not open");
            return false;
        }
        
        // Start timing before write operation
        auto start_time = steady_clock::now();

        // Send the message with error handling
        std::error_code error;
        asio::write(socket, asio::buffer(sanitized_message), error);
        if (error) {
            if (error == asio::error::broken_pipe || error == asio::error::connection_reset) {
                LOG_ERROR("Connection lost during send: {}", error.message());
            } else {
                LOG_ERROR("Send failed: {}", error.message());
            }
            return false;
        }

        // Log the sent message
        std::stringstream ss;
        ss << std::this_thread::get_id();
        LOG_INFO("[Thread {}] Sent message: {}", ss.str(), sanitized_message.substr(0, 50) + (sanitized_message.size() > 50 ? "..." : ""));

        try {
            // Use read_until to read until delimiter
            std::size_t bytes_transferred = asio::read_until(socket, response_buf, common::MESSAGE_DELIMITER, error);
            
            if (error) {
                if (error == asio::error::eof) {
                    LOG_ERROR("Connection closed by server");
                } else {
                    LOG_ERROR("Read failed: {}", error.message());
                }
                return false;
            }
            
            // Calculate RTT
            auto end_time = steady_clock::now();
            rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
            
            // Extract the response from the buffer
            response_text = std::string(asio::buffers_begin(response_buf.data()), 
                                asio::buffers_begin(response_buf.data()) + bytes_transferred);
            
            // Consume the data that was read
            response_buf.consume(bytes_transferred);
            
            // Log the response (truncated if too long)
            if (response_text.size() > 100) {
                LOG_INFO("[Thread {}] Received response: {}... ({}ms)", 
                        ss.str(), response_text.substr(0, 100), rtt_ms);
            } else {
                LOG_INFO("[Thread {}] Received response: {} ({}ms)", 
                        ss.str(), response_text, rtt_ms);
            }
            
            return true;
        } catch (const std::exception& e) {
            LOG_ERROR("Exception during read: {}", e.what());
            return false;
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception during send_and_receive: {}", e.what());
        return false;
    }
}

// Client thread function - handles one connection
ThreadStats client_thread_func(int thread_id) {
    ThreadStats stats;
    stats.thread_id = thread_id;
    
    try {
        // Create io_context, resolver and socket
        asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::socket socket(io_context);
        
        // Resolve endpoints
        std::string host = std::string(common::HOST.data());
        auto endpoints = resolver.resolve(host, std::to_string(common::PORT));
        
        // Attempt to connect to the server
        std::error_code ec;
        asio::connect(socket, endpoints, ec);
        
        if (ec) {
            LOG_ERROR("[Thread {}] Failed to connect: {}", thread_id, ec.message());
            stats.connection_successful = false;
            return stats;
        }
        
        // Successfully connected
        LOG_INFO("[Thread {}] Connected to server", thread_id);
        stats.connection_successful = true;
        
        // Increment connected clients count and check if all are connected
        connected_clients++;
        if (connected_clients == num_connections) {
            LOG_INFO("All {} clients connected to server", num_connections);
            std::unique_lock<std::mutex> lock(start_mutex);
            all_connected_flag = true;
            start_cv.notify_all(); // Signal that all clients are connected
        }
        
        // Wait for the signal to start sending messages
        {
            std::unique_lock<std::mutex> lock(start_mutex);
            start_cv.wait(lock, [] { return all_connected_flag; });
        }
        
        // Setup random number generator for selecting sentences
        std::random_device rd;
        std::mt19937 gen(rd());
        
        // Create a buffer for the responses
        asio::streambuf response_buf;
        
        // Get local copy of sentences
        std::vector<std::string> sentences;
        {
            std::lock_guard<std::mutex> lock(sentences_mutex);
            sentences = g_sentences;
        }
        
        if (sentences.empty()) {
            LOG_ERROR("[Thread {}] No sentences available", thread_id);
            stats.connection_successful = false;
            return stats;
        }
        
        std::uniform_int_distribution<> sentence_dist(0, sentences.size() - 1);
        
        // Wait for 5 seconds as per requirement - use constant
        std::this_thread::sleep_for(std::chrono::seconds(common::client::WAIT_BEFORE_SENDING_SEC));
        
        LOG_INFO("[Thread {}] Starting to send messages", thread_id);
        
        // Send 'epoch' number of messages
        for (int i = 0; i < epoch; ++i) {
            // Select a random sentence
            std::string message = sentences[sentence_dist(gen)];
            long long rtt_ms = 0;
            
            stats.requests_attempted++;
            
            // Send the message and wait for response
            std::string response_text;
            bool success = send_and_receive(socket, message, rtt_ms, response_buf, response_text);
            
            if (success) {
                stats.requests_succeeded++;
                stats.rtts_ms.push_back(rtt_ms);
                stats.responses.push_back(response_text);
                stats.sent_messages.push_back(message);
            } else {
                stats.requests_failed++;
                LOG_ERROR("[Thread {}] Failed to send/receive message {}", thread_id, i + 1);
            }
            
            // Respect the interval between messages
            if (i < epoch - 1) {  // Don't wait after the last message
                std::this_thread::sleep_for(milliseconds(interval_ms));
            }
        }
        
        // Log completion
        LOG_INFO("[Thread {}] Completed sending {} messages", thread_id, epoch);
        
        // Mark this client as completed
        completed_clients++;
        if (completed_clients == num_connections) {
            std::unique_lock<std::mutex> lock(start_mutex);
            all_completed_flag = true;
            completion_cv.notify_all();
        }
        
        // Gracefully close the socket
        socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close(ec);
        
    } catch (const std::exception& e) {
        LOG_ERROR("[Thread {}] Exception: {}", thread_id, e.what());
        stats.connection_successful = false;
    }
    
    return stats;
}

// Function to generate comprehensive summary report
void generate_summary_report(const std::vector<ThreadStats>& all_stats, const std::string& timestamp) {
    LOG_INFO("Generating comprehensive summary report...");
    
    // 종합 보고서 파일 생성
    std::string summary_filename = "client_summary_" + timestamp + ".txt";
    std::ofstream summary_file(summary_filename);
    
    if (!summary_file.is_open()) {
        LOG_ERROR("Failed to open summary report file for writing: {}", summary_filename);
        return;
    }
    
    // 헤더 작성
    summary_file << "========================================================\n";
    summary_file << "           TCP CLIENT PERFORMANCE SUMMARY           \n";
    summary_file << "========================================================\n";
    summary_file << "Generated: " << timestamp << "\n\n";
    
    // 클라이언트 구성 정보
    summary_file << "------ CLIENT CONFIGURATION ------\n";
    summary_file << "Max Concurrent Connections: " << num_connections << "\n";
    summary_file << "Request Interval (ms): " << interval_ms << "\n";
    summary_file << "Requests per Connection: " << epoch << "\n";
    summary_file << "Target host: " << std::string(common::HOST.data()) << "\n";
    summary_file << "Target port: " << common::PORT << "\n\n";
    
    // 연결 통계
    size_t total_connections = all_stats.size();
    size_t successful_connections = 0;
    
    for (const auto& stats : all_stats) {
        if (stats.connection_successful) {
            successful_connections++;
        }
    }
    
    summary_file << "------ CONNECTION STATISTICS ------\n";
    summary_file << "Total connections: " << total_connections << "\n";
    summary_file << "Successful connections: " << successful_connections << " (" 
               << (total_connections > 0 ? (successful_connections * 100.0 / total_connections) : 0.0) << "%)\n\n";
    
    // 요청 통계
    size_t total_requests_attempted = 0;
    size_t total_requests_succeeded = 0;
    size_t total_requests_failed = 0;
    
    std::vector<long long> all_rtts;
    
    for (const auto& stats : all_stats) {
        total_requests_attempted += stats.requests_attempted;
        total_requests_succeeded += stats.requests_succeeded;
        total_requests_failed += stats.requests_failed;
        
        // Collect all rtts for aggregate stats
        all_rtts.insert(all_rtts.end(), 
                        stats.rtts_ms.begin(), 
                        stats.rtts_ms.end());
    }
    
    summary_file << "------ REQUEST STATISTICS ------\n";
    summary_file << "Total requests attempted: " << total_requests_attempted << "\n";
    summary_file << "Total requests succeeded: " << total_requests_succeeded << " (" 
               << (total_requests_attempted > 0 ? (total_requests_succeeded * 100.0 / total_requests_attempted) : 0.0) << "%)\n";
    summary_file << "Total requests failed: " << total_requests_failed << " (" 
               << (total_requests_attempted > 0 ? (total_requests_failed * 100.0 / total_requests_attempted) : 0.0) << "%)\n\n";
    
    // RTT 통계
    if (!all_rtts.empty()) {
        double sum = 0.0;
        for (const auto& rtt : all_rtts) {
            sum += rtt;
        }
        double avg = sum / all_rtts.size();
        
        double variance_sum = 0.0;
        for (const auto& rtt : all_rtts) {
            double diff = rtt - avg;
            variance_sum += diff * diff;
        }
        double stddev = std::sqrt(variance_sum / all_rtts.size());
        
        auto [min_it, max_it] = std::minmax_element(all_rtts.begin(), all_rtts.end());
        
        // 백분위수 계산
        std::vector<long long> sorted_rtts = all_rtts;
        std::sort(sorted_rtts.begin(), sorted_rtts.end());
        
        auto p50_index = static_cast<size_t>(sorted_rtts.size() * 0.5);
        auto p90_index = static_cast<size_t>(sorted_rtts.size() * 0.9);
        auto p95_index = static_cast<size_t>(sorted_rtts.size() * 0.95);
        auto p99_index = static_cast<size_t>(sorted_rtts.size() * 0.99);
        
        summary_file << "------ RTT STATISTICS ------\n";
        summary_file << "Total RTT Measurements: " << all_rtts.size() << "\n";
        summary_file << "RTT (ms):\n";
        summary_file << "  Average: " << avg << "\n";
        summary_file << "  StdDev: " << stddev << "\n";
        summary_file << "  Min: " << *min_it << "\n";
        summary_file << "  Max: " << *max_it << "\n";
        summary_file << "  P50: " << sorted_rtts[p50_index] << "\n";
        summary_file << "  P90: " << sorted_rtts[p90_index] << "\n";
        summary_file << "  P95: " << sorted_rtts[p95_index] << "\n";
        summary_file << "  P99: " << sorted_rtts[p99_index] << "\n";
    } else {
        summary_file << "------ RTT STATISTICS ------\n";
        summary_file << "No RTT measurements available.\n";
    }
    
    summary_file << "\n========================================================\n";
    summary_file << "             END OF PERFORMANCE SUMMARY             \n";
    summary_file << "========================================================\n";
    
    summary_file.close();
    LOG_INFO("Saved comprehensive client performance summary to {}", summary_filename);
}

// Function to aggregate and log statistics
void log_aggregate_stats(const std::vector<ThreadStats>& all_stats, const std::string& timestamp = std::string()) {
    size_t total_connections = all_stats.size();
    size_t successful_connections = 0;
    
    size_t total_requests_attempted = 0;
    size_t total_requests_succeeded = 0;
    size_t total_requests_failed = 0;
    
    std::vector<long long> all_rtts;
    
    for (const auto& stats : all_stats) {
        if (stats.connection_successful) {
            successful_connections++;
        }
        
        total_requests_attempted += stats.requests_attempted;
        total_requests_succeeded += stats.requests_succeeded;
        total_requests_failed += stats.requests_failed;
        
        // Collect all rtts for aggregate stats
        all_rtts.insert(all_rtts.end(), 
                            stats.rtts_ms.begin(), 
                            stats.rtts_ms.end());
    }
    
    // Calculate aggregate statistics
    LOG_INFO("=== Aggregate Statistics ===");
    LOG_INFO("Total connections: {}", total_connections);
    LOG_INFO("Successful connections: {} ({}%)", 
             successful_connections, 
             (total_connections > 0) ? (successful_connections * 100.0 / total_connections) : 0.0);
    
    LOG_INFO("Total requests attempted: {}", total_requests_attempted);
    LOG_INFO("Total requests succeeded: {} ({}%)", 
             total_requests_succeeded, 
             (total_requests_attempted > 0) ? (total_requests_succeeded * 100.0 / total_requests_attempted) : 0.0);
    LOG_INFO("Total requests failed: {} ({}%)", 
             total_requests_failed, 
             (total_requests_attempted > 0) ? (total_requests_failed * 100.0 / total_requests_attempted) : 0.0);
    
    // Calculate RTT statistics
    if (!all_rtts.empty()) {
        double sum = 0.0;
        for (const auto& rtt : all_rtts) {
            sum += rtt;
        }
        double avg = sum / all_rtts.size();
        
        double variance_sum = 0.0;
        for (const auto& rtt : all_rtts) {
            double diff = rtt - avg;
            variance_sum += diff * diff;
        }
        double stddev = std::sqrt(variance_sum / all_rtts.size());
        
        auto [min_it, max_it] = std::minmax_element(all_rtts.begin(), all_rtts.end());
        
        LOG_INFO("RTT statistics:");
        LOG_INFO("  Count: {}", all_rtts.size());
        LOG_INFO("  Min: {} ms", *min_it);
        LOG_INFO("  Max: {} ms", *max_it);
        LOG_INFO("  Avg: {:.2f} ms", avg);
        LOG_INFO("  StdDev: {:.2f} ms", stddev);
        
        // Calculate percentiles
        std::vector<long long> sorted_rtts = all_rtts;
        std::sort(sorted_rtts.begin(), sorted_rtts.end());
        
        auto p50_index = static_cast<size_t>(sorted_rtts.size() * 0.5);
        auto p95_index = static_cast<size_t>(sorted_rtts.size() * 0.95);
        auto p99_index = static_cast<size_t>(sorted_rtts.size() * 0.99);
        
        LOG_INFO("  P50: {} ms", sorted_rtts[p50_index]);
        LOG_INFO("  P95: {} ms", sorted_rtts[p95_index]);
        LOG_INFO("  P99: {} ms", sorted_rtts[p99_index]);
        
        // Generate timestamped filename for latency statistics
        std::string current_timestamp = timestamp.empty() ? generate_timestamp() : timestamp;
        std::string filename = "client_rtt_stats_" + current_timestamp + ".csv";
        LOG_INFO("Generating RTT statistics file: {}", filename);
        std::ofstream rtt_file(filename);
        if (rtt_file.is_open()) {
            rtt_file << "request_id,rtt_ms,message,response\n";
            
            // Collect all responses along with their RTTs
            std::vector<std::pair<long long, std::string>> rtt_responses;
            int req_id = 1;
            
            for (const auto& stats : all_stats) {
                for (size_t i = 0; i < stats.rtts_ms.size(); ++i) {
                    // Clean up response string for CSV format
                    std::string clean_response = "";
                    if (i < stats.responses.size()) {
                        clean_response = stats.responses[i];
                        // Remove newlines and commas for CSV compatibility
                        std::replace(clean_response.begin(), clean_response.end(), '\n', ' ');
                        std::replace(clean_response.begin(), clean_response.end(), '\r', ' ');
                        std::replace(clean_response.begin(), clean_response.end(), ',', ' ');
                    }
                    
                    // Clean up message string for CSV format
                    std::string clean_message = "";
                    if (i < stats.sent_messages.size()) {
                        clean_message = stats.sent_messages[i];
                        // Remove newlines and commas for CSV compatibility
                        std::replace(clean_message.begin(), clean_message.end(), '\n', ' ');
                        std::replace(clean_message.begin(), clean_message.end(), '\r', ' ');
                        std::replace(clean_message.begin(), clean_message.end(), ',', ' ');
                    }
                    
                    rtt_file << req_id++ << "," << stats.rtts_ms[i] << ",\"" 
                           << clean_message << "\",\"" << clean_response << "\"\n";
                }
            }
            
            LOG_INFO("Saved RTT statistics to {}", filename);
        } else {
            LOG_ERROR("Failed to open RTT statistics file for writing");
        }
        
        // Generate connection statistics file
        std::string conn_filename = "client_connection_stats_" + current_timestamp + ".csv";
        std::ofstream conn_file(conn_filename);
        if (conn_file.is_open()) {
            conn_file << "thread_id,connection_successful,requests_attempted,requests_succeeded,requests_failed,avg_rtt_ms\n";
            for (const auto& stats : all_stats) {
                auto [avg_rtt, _] = stats.get_rtt_stats();
                conn_file << stats.thread_id << ","
                        << (stats.connection_successful ? "1" : "0") << ","
                        << stats.requests_attempted << ","
                        << stats.requests_succeeded << ","
                        << stats.requests_failed << ","
                        << avg_rtt << "\n";
            }
            LOG_INFO("Saved connection statistics to {}", conn_filename);
        } else {
            LOG_ERROR("Failed to open connection statistics file for writing");
        }
    } else {
        LOG_WARN("No RTT data available");
    }
    
    // 종합 보고서 생성
    generate_summary_report(all_stats, timestamp);
}

int main(int argc, char* argv[]) {
    try {
        // Initialize logger
        common::Logger::Init();
        
        // Process command line arguments
        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);
            
            if (arg == "--connections" && i + 1 < argc) {
                int val = std::stoi(argv[++i]);
                if (val > 0) {
                    num_connections = val;
                    LOG_INFO("Set connections to {}", num_connections);
                }
            }
            else if (arg == "--interval" && i + 1 < argc) {
                int val = std::stoi(argv[++i]);
                if (val > 0) {
                    interval_ms = val;
                    LOG_INFO("Set interval to {}ms", interval_ms);
                }
            }
            else if (arg == "--epoch" && i + 1 < argc) {
                int val = std::stoi(argv[++i]);
                if (val > 0) {
                    epoch = val;
                    LOG_INFO("Set epoch to {}", epoch);
                }
            }
            else if (arg == "--help") {
                std::cout << "Usage: " << argv[0] << " [options]\n"
                          << "Options:\n"
                          << "  --connections N    Number of concurrent connections (default: " << common::client::MAX_CONCURRENT_CONNECTIONS << ")\n"
                          << "  --interval N       Interval between messages in ms (default: " << common::client::DEFAULT_INTERVAL_MS << ")\n"
                          << "  --epoch N          Number of messages per connection (default: " << common::client::DEFAULT_EPOCH << ")\n"
                          << "  --help             Show this help message\n";
                return 0;
            }
        }
        
        // Load sentences
        LOG_INFO("Starting TCP client test with {} connections, {} epochs, {}ms interval", 
                num_connections, epoch, interval_ms);
        
        {
            std::lock_guard<std::mutex> lock(sentences_mutex);
            g_sentences = read_sentences(std::string(common::client::SENTENCE_FILE.data()));
            
            if (g_sentences.empty()) {
                LOG_CRITICAL("No sentences loaded, exiting");
                return 1;
            }
        }
        
        // Generate timestamp for this test run - do this early to use across all files
        std::string timestamp = generate_timestamp();
        
        // Save test configuration to a summary file
        std::string config_filename = "client_test_config_" + timestamp + ".txt";
        std::ofstream config_file(config_filename);
        if (config_file.is_open()) {
            config_file << "Test Configuration Summary\n";
            config_file << "========================\n";
            config_file << "Max Concurrent Connections: " << num_connections << "\n";
            config_file << "Request Interval (ms): " << interval_ms << "\n";
            config_file << "Requests per Connection: " << epoch << "\n";
            config_file << "Timestamp: " << timestamp << "\n";
            config_file << "Target host: " << std::string(common::HOST.data()) << "\n";
            config_file << "Target port: " << common::PORT << "\n";
            config_file << "========================\n";
            LOG_INFO("Saved test configuration to {}", config_filename);
        } else {
            LOG_ERROR("Failed to open test configuration file for writing");
        }
        
        // Create and start client threads
        std::vector<std::future<ThreadStats>> futures;
        for (int i = 0; i < num_connections; ++i) {
            futures.push_back(std::async(std::launch::async, client_thread_func, i));
        }
        
        // Wait for all connections to be established
        {
            std::unique_lock<std::mutex> lock(start_mutex);
            if (!all_connected_flag) {
                LOG_INFO("Waiting for all {} clients to connect...", num_connections);
                start_cv.wait(lock, [] { return all_connected_flag; });
            }
        }
        
        // Wait for all clients to complete
        {
            std::unique_lock<std::mutex> lock(start_mutex);
            if (!all_completed_flag) {
                LOG_INFO("Waiting for all clients to complete their messages...");
                completion_cv.wait(lock, [] { return all_completed_flag; });
            }
        }
        
        // Collect results and log statistics
        std::vector<ThreadStats> all_stats;
        for (auto& future : futures) {
            all_stats.push_back(future.get());
        }
        
        // Pass timestamp to log_aggregate_stats for consistent filenames
        log_aggregate_stats(all_stats, timestamp);
        
        LOG_INFO("TCP client test completed successfully");
        return 0;
        
    } catch (const std::exception& e) {
        LOG_CRITICAL("Fatal error: {}", e.what());
        return 1;
    }
}