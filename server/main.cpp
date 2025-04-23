#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>
#include <functional>
#include <deque>
#include <condition_variable>
#include <fstream>
#include <algorithm>
#include <sstream>   // For std::stringstream
#include <future>    // For std::promise/std::future
#include <map>
#include <iomanip>   // For std::put_time and std::setfill

#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <asio/signal_set.hpp>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "common/logger.h"
#include "common/constants.h"

using json = nlohmann::json;
using asio::ip::tcp;

// Replace the hardcoded API_ENDPOINT with a direct function call
const std::string API_ENDPOINT = common::server::get_api_endpoint();

// Simple semaphore for limiting concurrent operations
class Semaphore {
public:
    std::mutex mutex_;
    std::condition_variable cv_;
    int count_;

public:
    explicit Semaphore(int count) : count_(count) {}

    void acquire() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return count_ > 0; });
        --count_;
    }

    bool try_acquire() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (count_ > 0) {
            --count_;
            return true;
        }
        return false;
    }

    void release() {
        std::unique_lock<std::mutex> lock(mutex_);
        ++count_;
        cv_.notify_one();
    }
};

// Utility functions for authorization and encoding
namespace util {
    // Base64 URL encoding implementation
    std::string base64url_encode(const std::string &input) {
        static const char* base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::string encoded;
        int i = 0, j = 0;
        unsigned char char_array_3[3], char_array_4[4];
        size_t input_len = input.length();
        
        while (input_len--) {
            char_array_3[i++] = input[j++];
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++)
                    encoded += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (j = 0; j < i + 1; j++)
                encoded += base64_chars[char_array_4[j]];

            while (i++ < 3)
                encoded += '=';
        }
        
        // URL-safe modifications
        for (char &c : encoded) {
            if (c == '+') c = '-';
            else if (c == '/') c = '_';
        }
        
        // Remove padding
        encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
        
        return encoded;
    }

    // Load private key from PEM string
    EVP_PKEY* load_private_key(const std::string& private_key_pem) {
        BIO* bio = BIO_new_mem_buf(private_key_pem.c_str(), -1);
        if (!bio) {
            LOG_ERROR("Failed to create BIO for private key");
            return nullptr;
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        if (!pkey) {
            char err_buf[common::server::CURL_ERROR_BUFFER_SIZE];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            LOG_ERROR("Failed to load private key: {}", err_buf);
        }

        BIO_free(bio);
        return pkey;
    }
    
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
}

// Authentication for Google API
class GoogleAuth {
public:
    std::string access_token_;
    std::chrono::time_point<std::chrono::system_clock> token_expiry_;
    std::mutex token_mutex_;
    const std::string key_path_;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* buffer) {
        size_t real_size = size * nmemb;
        buffer->append(static_cast<char*>(contents), real_size);
        return real_size;
    }

    std::pair<std::string, int> fetch_access_token() {
        std::string access_token;
        
        std::ifstream key_file(key_path_);
        if (!key_file.is_open()) {
            LOG_ERROR("Could not open key file: {}", key_path_);
            return {"", 0};
        }

        json key_json;
        try {
            key_file >> key_json;
        } catch (const json::parse_error& e) {
            LOG_ERROR("Failed to parse key file JSON: {}", e.what());
            return {"", 0};
        }

        std::string private_key_pem;
        std::string client_email;
        std::string token_uri;

        try {
            private_key_pem = key_json.at("private_key").get<std::string>();
            client_email = key_json.at("client_email").get<std::string>();
            token_uri = key_json.at("token_uri").get<std::string>();
        } catch (const json::out_of_range& e) {
            LOG_ERROR("Missing required field in key file: {}", e.what());
            return {"", 0};
        } catch (const json::type_error& e) {
            LOG_ERROR("Incorrect type for field in key file: {}", e.what());
            return {"", 0};
        }

        LOG_INFO("Acquiring new Google API token");

        // 1. Create JWT Header
        json header = {
            {"alg", "RS256"},
            {"typ", "JWT"}
        };
        std::string encoded_header = util::base64url_encode(header.dump());

        // 2. Create JWT Payload (Claims)
        auto now = std::chrono::system_clock::now();
        auto iat = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        auto exp = iat + 3600; // Expires in 1 hour

        json payload = {
            {"iss", client_email},
            {"sub", client_email},
            {"aud", token_uri},
            {"iat", iat},
            {"exp", exp},
            {"scope", "https://www.googleapis.com/auth/cloud-platform"}
        };
        std::string encoded_payload = util::base64url_encode(payload.dump());

        // 3. Prepare data to sign
        std::string unsigned_token = encoded_header + "." + encoded_payload;

        // 4. Sign using OpenSSL RS256
        std::string signature;
        EVP_PKEY* pkey = util::load_private_key(private_key_pem);
        if (!pkey) {
            LOG_ERROR("Error loading private key for JWT signing.");
            return {"", 0};
        }

        // Use unique_ptr for automatic cleanup of OpenSSL resources
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!md_ctx) {
            LOG_ERROR("Error creating EVP_MD_CTX.");
            EVP_PKEY_free(pkey); // Manually free pkey as md_ctx failed
            return {"", 0};
        }

        // Initialize signing operation with SHA256
        if (EVP_DigestSignInit(md_ctx.get(), NULL, EVP_sha256(), NULL, pkey) <= 0) {
            LOG_ERROR("Error initializing digest sign.");
            char err_buf[common::server::CURL_ERROR_BUFFER_SIZE];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            LOG_ERROR("OpenSSL Error: {}", err_buf);
            EVP_PKEY_free(pkey);
            return {"", 0};
        }

        // Provide the data to be signed
        if (EVP_DigestSignUpdate(md_ctx.get(), unsigned_token.c_str(), unsigned_token.length()) <= 0) {
            LOG_ERROR("Error updating digest sign.");
            char err_buf[common::server::CURL_ERROR_BUFFER_SIZE];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            LOG_ERROR("OpenSSL Error: {}", err_buf);
            EVP_PKEY_free(pkey);
            return {"", 0};
        }

        // Determine buffer size for signature
        size_t sig_len;
        if (EVP_DigestSignFinal(md_ctx.get(), NULL, &sig_len) <= 0) {
            LOG_ERROR("Error determining signature length.");
            char err_buf[common::server::CURL_ERROR_BUFFER_SIZE];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            LOG_ERROR("OpenSSL Error: {}", err_buf);
            EVP_PKEY_free(pkey);
            return {"", 0};
        }

        // Allocate buffer and finalize signing
        std::vector<unsigned char> sig_buf(sig_len);
        if (EVP_DigestSignFinal(md_ctx.get(), sig_buf.data(), &sig_len) <= 0) {
            LOG_ERROR("Error finalizing digest sign.");
            char err_buf[common::server::CURL_ERROR_BUFFER_SIZE];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            LOG_ERROR("OpenSSL Error: {}", err_buf);
            EVP_PKEY_free(pkey);
            return {"", 0};
        }

        signature.assign(reinterpret_cast<char*>(sig_buf.data()), sig_len);

        // md_ctx is cleaned up by unique_ptr
        EVP_PKEY_free(pkey); // Free the key after use

        // 5. Base64 URL Encode Signature
        std::string encoded_signature = util::base64url_encode(signature);

        // 6. Assemble the final JWT
        std::string jwt = unsigned_token + "." + encoded_signature;

        // 7. Exchange JWT for Access Token using libcurl
        CURL *curl = curl_easy_init();
        int expires_in = 0;
        
        if (curl) {
            std::string readBuffer;
            std::string post_fields = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt;

            curl_easy_setopt(curl, CURLOPT_URL, token_uri.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, common::server::OAUTH_TIMEOUT_SECONDS);

            CURLcode res = curl_easy_perform(curl);
            if (res == CURLE_OK) {
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                if (http_code == 200) {
                    try {
                        json token_response = json::parse(readBuffer);
                        access_token = token_response.at("access_token").get<std::string>();
                        expires_in = token_response.value("expires_in", 3600);
                        LOG_INFO("Successfully acquired access token");
                    } catch (const std::exception& e) {
                        LOG_ERROR("Error parsing access token response: {}", e.what());
                        LOG_DEBUG("Access token response body: {}", readBuffer);
                    }
                } else {
                    LOG_ERROR("Failed to get access token, HTTP status: {}", http_code);
                    LOG_DEBUG("Access token response body: {}", readBuffer);
                }
            } else {
                LOG_ERROR("curl_easy_perform() failed for token request: {}", curl_easy_strerror(res));
            }
            curl_easy_cleanup(curl);
        } else {
            LOG_ERROR("Failed to initialize curl easy handle for token request.");
        }

        return {access_token, expires_in};
    }

public:
    explicit GoogleAuth(const std::string& key_path) : key_path_(key_path) {
        refresh_token();
    }

    void refresh_token() {
        std::lock_guard<std::mutex> lock(token_mutex_);
        try {
            auto [token, expires_in] = fetch_access_token();
            
            if (!token.empty()) {
                access_token_ = token;
                token_expiry_ = std::chrono::system_clock::now() + std::chrono::seconds(expires_in - common::server::TOKEN_EXPIRY_MARGIN_SECONDS);
                LOG_INFO("Token refreshed successfully");
            } else {
                LOG_ERROR("Failed to refresh token: empty token received");
                throw std::runtime_error("Failed to refresh token: empty token received");
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to refresh token: {}", e.what());
            throw;
        }
    }

    std::string get_token() {
        std::lock_guard<std::mutex> lock(token_mutex_);
        auto now = std::chrono::system_clock::now();
        if (access_token_.empty() || now >= token_expiry_) {
            auto [token, expires_in] = fetch_access_token();
            if (!token.empty()) {
                access_token_ = token;
                token_expiry_ = now + std::chrono::seconds(expires_in - common::server::TOKEN_EXPIRY_MARGIN_SECONDS);
            } else {
                LOG_ERROR("Failed to get new token and current token is expired or empty");
                throw std::runtime_error("Failed to get valid access token");
            }
        }
        return access_token_;
    }
};

// Handles API requests to Gemini
class GeminiClient {
public:
    GoogleAuth& auth_;
    asio::io_context& io_context_;
    Semaphore request_semaphore_;
    std::mutex queue_mutex_;
    std::deque<std::pair<std::string, std::function<void(bool, std::string)>>> request_queue_;
    std::atomic<size_t> total_requests_{0};
    std::atomic<size_t> successful_requests_{0};
    std::atomic<size_t> failed_requests_{0};
    std::vector<long long> latencies_ms_; // Store latencies in milliseconds
    std::vector<std::pair<long long, long>> latencies_with_status_; // Store latencies with status codes
    std::mutex latencies_mutex_;
    std::atomic<bool> shutting_down_{false};
    
    // curl_multi related members
    CURLM* multi_handle_{nullptr};
    std::mutex multi_mutex_;
    
    // RequestData struct definition
    struct RequestData {
        std::string response_buffer;
        std::chrono::time_point<std::chrono::steady_clock> start_time;
        std::function<void(bool, std::string)> callback;
        curl_slist* headers;
        GeminiClient* client;
        bool request_completed{false};
        std::string prompt;
        char error_buffer[common::server::CURL_ERROR_BUFFER_SIZE];
        long status_code{0}; // HTTP status code
    };
    
    std::map<CURL*, std::shared_ptr<RequestData>> active_requests_;
    
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* buffer) {
        size_t real_size = size * nmemb;
        buffer->append(static_cast<char*>(contents), real_size);
        return real_size;
    }
    
    void process_queue() {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        
        while (!request_queue_.empty() && request_semaphore_.try_acquire()) {
            // Get the front item in the queue
            std::string prompt = request_queue_.front().first;
            std::function<void(bool, std::string)> callback = request_queue_.front().second;
            request_queue_.pop_front();
            
            // Execute the request without blocking this thread
            asio::post(io_context_, [this, prompt, callback]() {
                execute_request(prompt, callback);
            });
        }
    }
    
    void execute_request(const std::string& prompt, std::function<void(bool, std::string)> callback) {
        if (shutting_down_) {
            callback(false, "Service is shutting down");
            request_semaphore_.release();
            return;
        }
        
        total_requests_++;
        
        try {
            std::string token = auth_.get_token();
            
            if (token.empty()) {
                LOG_ERROR("Failed to get auth token");
                callback(false, "Authentication failed");
                failed_requests_++;
                request_semaphore_.release();
                return;
            }
            
            // Use constants from common::server namespace
            json request_json = {
                {"contents", {
                    {
                        {"role", "user"},
                        {"parts", {
                            {"text", prompt}
                        }}
                    }
                }},
                {"systemInstruction", {{"parts", {
                    {{"text", common::server::SYSTEM_INSTRUCTION}}
                }}}},
                {"generationConfig", {
                    {"temperature", common::server::TEMPERATURE},
                    {"topP", common::server::TOP_P},
                    {"topK", common::server::TOP_K},
                    {"maxOutputTokens", common::server::MAX_OUTPUT_TOKENS}
                }}
            };
            
            std::string request_payload = request_json.dump();
            
            // Create request data
            auto request_data = std::make_shared<RequestData>();
            request_data->start_time = std::chrono::steady_clock::now();
            request_data->callback = callback;
            request_data->client = this;
            request_data->prompt = prompt;
            // Initialize error buffer
            request_data->error_buffer[0] = 0;
            
            // Create CURL handle for this request
            CURL* easy_handle = curl_easy_init();
            if (!easy_handle) {
                LOG_ERROR("Failed to initialize CURL handle");
                callback(false, "CURL initialization failed");
                failed_requests_++;
                request_semaphore_.release();
                return;
            }
            
            // Set up HTTP headers
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            std::string auth_header = "Authorization: Bearer " + token;
            headers = curl_slist_append(headers, auth_header.c_str());
            request_data->headers = headers;
            
            // Set up CURL options
            curl_easy_setopt(easy_handle, CURLOPT_URL, API_ENDPOINT.c_str());
            curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(easy_handle, CURLOPT_POST, 1L);
            curl_easy_setopt(easy_handle, CURLOPT_COPYPOSTFIELDS, request_payload.c_str());
            curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, &request_data->response_buffer);
            curl_easy_setopt(easy_handle, CURLOPT_PRIVATE, request_data.get());
            curl_easy_setopt(easy_handle, CURLOPT_TIMEOUT, common::server::GEMINI_API_TIMEOUT);
            curl_easy_setopt(easy_handle, CURLOPT_ERRORBUFFER, request_data->error_buffer);
            
            // Add to multi handle with lock
            {
                std::lock_guard<std::mutex> lock(multi_mutex_);
                curl_multi_add_handle(multi_handle_, easy_handle);
                active_requests_[easy_handle] = request_data;
            }
            
            // Start polling if not already started
            if (active_requests_.size() == 1) {
                asio::post(io_context_, [this]() { poll_multi_handle(); });
            }
            
        } catch (const std::exception& e) {
            LOG_ERROR("Exception in execute_request: {}", e.what());
            callback(false, std::string("Internal error: ") + e.what());
            failed_requests_++;
            request_semaphore_.release();
        }
    }
    
    void poll_multi_handle() {
        std::lock_guard<std::mutex> lock(multi_mutex_);
        
        int still_running = 0;
        
        // Use curl_multi_poll instead of curl_multi_perform with timer
        CURLMcode mc = curl_multi_poll(multi_handle_, NULL, 0, common::server::CURL_POLL_INTERVAL_MS, &still_running);
        
        if (mc != CURLM_OK) {
            LOG_ERROR("curl_multi_poll failed: {}", curl_multi_strerror(mc));
            // Schedule another poll immediately
            asio::post(io_context_, [this]() { poll_multi_handle(); });
            return;
        }
        
        // Perform any pending actions
        mc = curl_multi_perform(multi_handle_, &still_running);
        if (mc != CURLM_OK) {
            LOG_ERROR("curl_multi_perform failed: {}", curl_multi_strerror(mc));
            // Schedule another poll
            asio::post(io_context_, [this]() { poll_multi_handle(); });
            return;
        }
        
        // Check for completed transfers
        int msgs_left = 0;
        CURLMsg* msg = nullptr;
        while ((msg = curl_multi_info_read(multi_handle_, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE) {
                CURL* easy_handle = msg->easy_handle;
                CURLcode result = msg->data.result;
                
                // Find this handle in our active requests
                auto it = active_requests_.find(easy_handle);
                if (it != active_requests_.end()) {
                    auto request_data = it->second;
                    
                    // Calculate latency
                    auto end_time = std::chrono::steady_clock::now();
                    auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                        end_time - request_data->start_time).count();
                    
                    // Record latency
                    {
                        std::lock_guard<std::mutex> latency_lock(latencies_mutex_);
                        latencies_ms_.push_back(latency);
                        long http_code = 0;
                        curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &http_code);
                        request_data->status_code = http_code;
                        latencies_with_status_.push_back({latency, http_code});
                    }
                    
                    bool success = (result == CURLE_OK);
                    std::string response;
                    
                    if (success) {
                        try {
                            // Parse the JSON response
                            json response_json = json::parse(request_data->response_buffer);
                            
                            // Extract text from the response
                            if (response_json.contains("candidates") && 
                                !response_json["candidates"].empty() && 
                                response_json["candidates"][0].contains("content") &&
                                response_json["candidates"][0]["content"].contains("parts") &&
                                !response_json["candidates"][0]["content"]["parts"].empty() &&
                                response_json["candidates"][0]["content"]["parts"][0].contains("text")) {
                                
                                response = response_json["candidates"][0]["content"]["parts"][0]["text"];
                                successful_requests_++;
                                
                                LOG_INFO("Gemini API request successful, latency: {}ms", latency);
                            } else {
                                LOG_ERROR("Unexpected JSON structure: {}", request_data->response_buffer);
                                response = "Error: Unexpected response format";
                                failed_requests_++;
                                success = false;
                            }
                        } catch (const json::parse_error& e) {
                            LOG_ERROR("JSON parse error: {}", e.what());
                            LOG_ERROR("Response was: {}", request_data->response_buffer);
                            response = "Error: Could not parse response";
                            failed_requests_++;
                            success = false;
                        }
                    } else {
                        // Use the error buffer directly
                        const char* error_description = 
                            (request_data->error_buffer[0] != '\0') ? 
                            request_data->error_buffer : curl_easy_strerror(result);
                        
                        LOG_ERROR("Gemini API request failed: {}", error_description);
                        response = std::string("Error: ") + error_description;
                        failed_requests_++;
                    }
                    
                    // Release semaphore to allow another request
                    request_semaphore_.release();
                    
                    // Call the callback
                    try {
                        request_data->callback(success, response);
                    } catch (const std::exception& e) {
                        LOG_ERROR("Exception in callback: {}", e.what());
                    }
                    
                    // Clean up
                    curl_slist_free_all(request_data->headers);
                    curl_multi_remove_handle(multi_handle_, easy_handle);
                    curl_easy_cleanup(easy_handle);
                    active_requests_.erase(it);
                }
            }
        }
        
        // If we still have active transfers, schedule another poll
        if (still_running > 0) {
            asio::post(io_context_, [this]() { poll_multi_handle(); });
        }
    }

public:
    GeminiClient(GoogleAuth& auth, asio::io_context& io_context) 
    : auth_(auth), 
      io_context_(io_context), 
      request_semaphore_(common::server::MAX_CONCURRENT_API_REQUESTS) {
        // Initialize curl_multi handle
        multi_handle_ = curl_multi_init();
        if (!multi_handle_) {
            throw std::runtime_error("Failed to initialize curl_multi handle");
        }
        
        // Set curl_multi options
        curl_multi_setopt(multi_handle_, CURLMOPT_MAXCONNECTS, 
                         common::server::MAX_CONCURRENT_API_REQUESTS);
    }
    
    ~GeminiClient() {
        if (multi_handle_) {
            // Clean up any active requests
            std::lock_guard<std::mutex> lock(multi_mutex_);
            for (auto& [handle, data] : active_requests_) {
                curl_multi_remove_handle(multi_handle_, handle);
                curl_easy_cleanup(handle);
                curl_slist_free_all(data->headers);
            }
            active_requests_.clear();
            
            curl_multi_cleanup(multi_handle_);
            multi_handle_ = nullptr;
        }
    }
    
    void shutdown() {
        shutting_down_ = true;
        
        // Wait a bit for pending requests to complete
        LOG_INFO("Shutting down Gemini client, waiting for pending requests...");
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            // Clear the queue
            request_queue_.clear();
        }
    }
    
    void request(const std::string& prompt, std::function<void(bool, std::string)> callback) {
        if (shutting_down_) {
            callback(false, "Service is shutting down");
            return;
        }
        
        // Check if we've reached the maximum queue size
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (request_queue_.size() >= common::server::MAX_REQUEST_QUEUE_SIZE) {
                LOG_WARN("Request queue full, rejecting request");
                callback(false, "Server is too busy, please try again later");
                return;
            }
        }
        
        if (request_semaphore_.try_acquire()) {
            // Semaphore acquired, execute immediately
            asio::post(io_context_, [this, prompt, callback]() {
                execute_request(prompt, callback);
            });
        } else {
            // Semaphore not available, queue the request
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                request_queue_.push_back({prompt, callback});
                LOG_INFO("Request queued (queue size: {})", request_queue_.size());
            }
        }
    }
    
    size_t get_queue_size() {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return request_queue_.size();
    }
    
    void get_statistics(size_t& total, size_t& succeeded, size_t& failed) {
        total = total_requests_.load();
        succeeded = successful_requests_.load();
        failed = failed_requests_.load();
    }
    
    std::tuple<double, double, long long, long long> get_latency_stats() {
        std::lock_guard<std::mutex> lock(latencies_mutex_);
        if (latencies_with_status_.empty()) {
            return {0.0, 0.0, 0, 0}; // avg, stddev, min, max
        }
        
        // Calculate average
        double sum = 0.0;
        for (const auto& [latency, status_code] : latencies_with_status_) {
            sum += latency;
        }
        double avg = sum / latencies_with_status_.size();
        
        // Calculate standard deviation
        double variance_sum = 0.0;
        for (const auto& [latency, status_code] : latencies_with_status_) {
            double diff = latency - avg;
            variance_sum += diff * diff;
        }
        double stddev = std::sqrt(variance_sum / latencies_with_status_.size());
        
        // Find min and max
        auto min_latency = std::numeric_limits<long long>::max();
        auto max_latency = std::numeric_limits<long long>::min();
        
        for (const auto& [latency, status_code] : latencies_with_status_) {
            min_latency = std::min(min_latency, latency);
            max_latency = std::max(max_latency, latency);
        }
        
        return {avg, stddev, min_latency, max_latency};
    }
    
    size_t get_latency_count() {
        std::lock_guard<std::mutex> lock(latencies_mutex_);
        return latencies_with_status_.size();
    }
    
    void print_latency_statistics() {
        auto [avg, stddev, min, max] = get_latency_stats();
        size_t count = get_latency_count();
        
        LOG_INFO("=== API Latency Statistics ===");
        LOG_INFO("Total measurements: {}", count);
        
        if (count > 0) {
            LOG_INFO("Average latency: {:.2f} ms", avg);
            LOG_INFO("Standard deviation: {:.2f} ms", stddev);
            LOG_INFO("Min latency: {} ms", min);
            LOG_INFO("Max latency: {} ms", max);
            
            // Calculate percentiles
            {
                std::lock_guard<std::mutex> lock(latencies_mutex_);
                if (!latencies_with_status_.empty()) {
                    std::vector<long long> sorted_latencies;
                    sorted_latencies.reserve(latencies_with_status_.size());
                    for (const auto& [latency, status_code] : latencies_with_status_) {
                        sorted_latencies.push_back(latency);
                    }
                    std::sort(sorted_latencies.begin(), sorted_latencies.end());
                    
                    size_t p50_idx = sorted_latencies.size() * 0.5;
                    size_t p90_idx = sorted_latencies.size() * 0.9;
                    size_t p95_idx = sorted_latencies.size() * 0.95;
                    size_t p99_idx = sorted_latencies.size() * 0.99;
                    
                    LOG_INFO("50th percentile: {} ms", sorted_latencies[p50_idx]);
                    LOG_INFO("90th percentile: {} ms", sorted_latencies[p90_idx]);
                    LOG_INFO("95th percentile: {} ms", sorted_latencies[p95_idx]);
                    LOG_INFO("99th percentile: {} ms", sorted_latencies[p99_idx]);
                }
            }
        }
    }
    
    void analyze_gemini_performance() {
        std::lock_guard<std::mutex> lock(latencies_mutex_);
        if (latencies_with_status_.empty()) {
            LOG_INFO("No Gemini API data available for analysis");
            return;
        }

        // Count by status code
        std::map<long, int> status_counts;
        for (const auto& [latency, status_code] : latencies_with_status_) {
            status_counts[status_code]++;
        }

        // Calculate success rate
        int success_count = status_counts[common::server::HTTP_OK];
        double success_rate = (double)success_count / latencies_with_status_.size() * 100.0;

        // Calculate latency percentiles for successful requests (HTTP 200)
        std::vector<long long> success_latencies;
        for (const auto& [latency, status_code] : latencies_with_status_) {
            if (status_code == common::server::HTTP_OK) {
                success_latencies.push_back(latency);
            }
        }

        std::sort(success_latencies.begin(), success_latencies.end());
        long long p50 = 0, p95 = 0, p99 = 0;
        
        if (!success_latencies.empty()) {
            p50 = success_latencies[success_latencies.size() * 0.5];
            p95 = success_latencies[success_latencies.size() * 0.95];
            p99 = success_latencies[success_latencies.size() * 0.99];
        }

        // Log summary
        LOG_INFO("===== Gemini API Performance Analysis =====");
        LOG_INFO("Total requests: {}", latencies_with_status_.size());
        LOG_INFO("Success rate: {:.2f}%", success_rate);
        LOG_INFO("Status code distribution:");
        
        for (const auto& [status, count] : status_counts) {
            double percentage = (double)count / latencies_with_status_.size() * 100.0;
            LOG_INFO("  HTTP {}: {} requests ({:.2f}%)", status, count, percentage);
        }

        LOG_INFO("Latency for successful requests (HTTP 200):");
        LOG_INFO("  P50: {} ms", p50);
        LOG_INFO("  P95: {} ms", p95);
        LOG_INFO("  P99: {} ms", p99);
        LOG_INFO("=========================================");
    }
    
    void save_latency_statistics(const std::string& filename = std::string()) {
        std::lock_guard<std::mutex> lock(latencies_mutex_);
        if (latencies_with_status_.empty()) {
            LOG_WARN("No latency data to save");
            return;
        }
        
        // Generate filename with timestamp if not provided
        std::string output_filename = filename;
        if (output_filename.empty()) {
            std::string timestamp = util::generate_timestamp();
            output_filename = "gemini_api_latency_" + timestamp + ".csv";
        }
        
        std::ofstream report(output_filename);
        if (!report.is_open()) {
            LOG_ERROR("Failed to open file for writing: {}", output_filename);
            return;
        }
        
        report << "request_id,latency_ms,status_code,success\n";
        for (size_t i = 0; i < latencies_with_status_.size(); ++i) {
            // HTTP 200 is success, anything else is an error
            bool success = (latencies_with_status_[i].second == common::server::HTTP_OK);
            report << i + 1 << "," 
                   << latencies_with_status_[i].first << "," 
                   << latencies_with_status_[i].second << ","
                   << (success ? "1" : "0") << "\n";
        }
        
        LOG_INFO("Saved {} latency measurements to {}", latencies_with_status_.size(), output_filename);
    }

    void generate_summary_report(const std::string& timestamp) {
        LOG_INFO("Generating Gemini API summary report...");
        
        // Create summary report file
        std::string summary_filename = "performance_summary_" + timestamp + ".txt";
        std::ofstream summary_file(summary_filename);
        
        if (!summary_file.is_open()) {
            LOG_ERROR("Failed to open summary report file for writing: {}", summary_filename);
            return;
        }
        
        // Write header
        summary_file << "========================================================\n";
        summary_file << "           GEMINI API PERFORMANCE SUMMARY                \n";
        summary_file << "========================================================\n";
        summary_file << "Generated: " << timestamp << "\n\n";
        
        // Configuration information
        summary_file << "------ API CONFIGURATION ------\n";
        summary_file << "API Endpoint: " << API_ENDPOINT << "\n";
        summary_file << "Max Concurrent API Requests: " << common::server::MAX_CONCURRENT_API_REQUESTS << "\n";
        summary_file << "Gemini Model: " << std::string(common::server::MODEL_ID.data()) << "\n";
        summary_file << "Temperature: " << common::server::TEMPERATURE << "\n\n";
        
        // Gemini API performance statistics
        summary_file << "------ GEMINI API PERFORMANCE ------\n";
        size_t total_api_requests, successful_api_requests, failed_api_requests;
        get_statistics(total_api_requests, successful_api_requests, failed_api_requests);
        
        auto [avg_api_latency, stddev_api_latency, min_api_latency, max_api_latency] = get_latency_stats();
        
        summary_file << "Total API Requests: " << total_api_requests << "\n";
        summary_file << "Successful API Requests: " << successful_api_requests << " (" 
                    << (total_api_requests > 0 ? (successful_api_requests * 100.0 / total_api_requests) : 0) << "%)\n";
        summary_file << "Failed API Requests: " << failed_api_requests << " (" 
                    << (total_api_requests > 0 ? (failed_api_requests * 100.0 / total_api_requests) : 0) << "%)\n";
        summary_file << "API Latency (ms):\n";
        summary_file << "  Average: " << avg_api_latency << "\n";
        summary_file << "  StdDev: " << stddev_api_latency << "\n";
        summary_file << "  Min: " << min_api_latency << "\n";
        summary_file << "  Max: " << max_api_latency << "\n\n";
        
        // Status code distribution
        summary_file << "------ STATUS CODE DISTRIBUTION ------\n";
        
        // Count by status code
        std::map<long, int> status_counts;
        {
            std::lock_guard<std::mutex> lock(latencies_mutex_);
            for (const auto& [latency, status_code] : latencies_with_status_) {
                status_counts[status_code]++;
            }
        }
        
        for (const auto& [status, count] : status_counts) {
            double percentage = (double)count / total_api_requests * 100.0;
            summary_file << "HTTP " << status << ": " << count << " requests (" << percentage << "%)\n";
        }
        summary_file << "\n";
        
        // Latency percentiles for successful requests
        summary_file << "------ LATENCY PERCENTILES (HTTP 200 ONLY) ------\n";
        std::vector<long long> success_latencies;
        {
            std::lock_guard<std::mutex> lock(latencies_mutex_);
            for (const auto& [latency, status_code] : latencies_with_status_) {
                if (status_code == common::server::HTTP_OK) {
                    success_latencies.push_back(latency);
                }
            }
        }
        
        if (!success_latencies.empty()) {
            std::sort(success_latencies.begin(), success_latencies.end());
            long long p50 = success_latencies[success_latencies.size() * 0.5];
            long long p90 = success_latencies[success_latencies.size() * 0.9];
            long long p95 = success_latencies[success_latencies.size() * 0.95];
            long long p99 = success_latencies[success_latencies.size() * 0.99];
            
            summary_file << "P50: " << p50 << " ms\n";
            summary_file << "P90: " << p90 << " ms\n";
            summary_file << "P95: " << p95 << " ms\n";
            summary_file << "P99: " << p99 << " ms\n\n";
        } else {
            summary_file << "No successful requests to analyze.\n\n";
        }
        
        summary_file << "========================================================\n";
        LOG_INFO("Summary report saved to {}", summary_filename);
    }
};

// Handles a single client connection
class Session : public std::enable_shared_from_this<Session> {
public:
    tcp::socket socket_;
    GeminiClient& gemini_client_;
    std::vector<char> buffer_;
    std::mutex write_mutex_;
    std::atomic<bool> processing_{false};
    const std::atomic<bool>& running_;
    
    struct PendingRequest {
        std::chrono::time_point<std::chrono::steady_clock> start_time;
        std::promise<std::pair<bool, std::string>> response_promise;
    };
    
    std::map<int, std::shared_ptr<PendingRequest>> pending_request_map_;
    std::mutex request_map_mutex_;
    std::atomic<int> request_id_counter_{0};
    
    void read() {
        auto self(shared_from_this());
        
        socket_.async_read_some(asio::buffer(buffer_),
            [this, self](std::error_code ec, std::size_t length) {
                if (!ec) {
                    processing_ = true;
                    
                    // Process the received data
                    std::string message(buffer_.data(), length);
                    process_message(message);
                    
                    // Continue reading
                    if (socket_.is_open()) {
                        read();
                    } else {
                        processing_ = false;
                    }
                } else if (ec == asio::error::eof) {
                    // Client closed connection - normal behavior
                    LOG_DEBUG("Client disconnected");
                    close();
                } else if (ec != asio::error::operation_aborted) {
                    LOG_ERROR("Read error: {}", ec.message());
                    close();
                }
            });
    }
    
    void process_message(const std::string& message) {
        auto start_time = std::chrono::steady_clock::now();
        
        auto self(shared_from_this());
        
        if (message.empty()) {
            LOG_WARN("Received empty message, ignoring");
            return;
        }
        
        // Trim whitespace from the message
        auto s = std::make_shared<std::string>(message);
        if (!s->empty()) {
            s->erase(s->begin(), std::find_if(s->begin(), s->end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
            s->erase(std::find_if(s->rbegin(), s->rend(), [](unsigned char ch) {
                return !std::isspace(ch);
            }).base(), s->end());
        }
        
        std::string cleaned_message = *s;
        
        if (cleaned_message.empty()) {
            LOG_WARN("Message contained only whitespace, ignoring");
            return;
        }
        
        // Assign an ID to this request for tracking
        int request_id;
        {
            std::lock_guard<std::mutex> lock(request_map_mutex_);
            request_id = ++request_id_counter_;
            
            // Create a new pending request
            auto pending_request = std::make_shared<PendingRequest>();
            pending_request->start_time = start_time;
            pending_request_map_[request_id] = pending_request;
        }
        
        // Send the request to the Gemini API
        gemini_client_.request(cleaned_message, [this, self, request_id, start_time](bool success, std::string response) {
            auto end_time = std::chrono::steady_clock::now();
            auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
            
            {
                std::lock_guard<std::mutex> lock(request_map_mutex_);
                auto it = pending_request_map_.find(request_id);
                if (it != pending_request_map_.end()) {
                    auto& pending_request = it->second;
                    pending_request->response_promise.set_value(std::make_pair(success, response));
                    pending_request_map_.erase(it);
                }
            }
            
            // Write the response back to the client
            if (socket_.is_open()) {
                // Add a newline to the response for better client reading
                if (!response.empty() && response.back() != '\n') {
                    response += '\n';
                }
                write(response);
            }
            
            // Log completion of the request
            if (success) {
                LOG_INFO("Request {} completed in {} ms", request_id, latency);
            } else {
                LOG_ERROR("Request {} failed after {} ms: {}", request_id, latency, response);
            }
        });
    }
    
    void write(const std::string& message) {
        auto self(shared_from_this());
        
        std::lock_guard<std::mutex> lock(write_mutex_);
        asio::async_write(socket_, asio::buffer(message),
            [this, self](std::error_code ec, std::size_t /*length*/) {
                if (ec && ec != asio::error::operation_aborted) {
                    LOG_ERROR("Write error: {}", ec.message());
                    close();
                }
            });
    }
    
public:
    Session(tcp::socket socket, GeminiClient& client, const std::atomic<bool>& running)
        : socket_(std::move(socket)), gemini_client_(client), buffer_(common::BUFFER_SIZE), running_(running) {}
    
    void start() {
        read();
    }
    
    bool is_processing() const {
        return processing_.load();
    }
    
    void close() {
        if (socket_.is_open()) {
            try {
                socket_.close();
            } catch (const std::exception& e) {
                LOG_ERROR("Error closing socket: {}", e.what());
            }
        }
        
        processing_ = false;
    }
    
    ~Session() {
        close();
    }
};

// Main TCP server class
class TcpServer {
public:
    asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    GeminiClient& gemini_client_;
    
    Semaphore connection_semaphore_;
    std::vector<std::shared_ptr<Session>> active_sessions_;
    std::mutex sessions_mutex_;
    std::atomic<bool> running_{true};
    asio::steady_timer stats_timer_;
    asio::steady_timer shutdown_check_timer_;
    
    std::atomic<bool> gemini_service_healthy_{true};
    asio::steady_timer health_check_timer_;
    
    std::atomic<bool> reports_generated_{false};
    std::mutex reports_mutex_;

    void generate_reports() {
        std::lock_guard<std::mutex> lock(reports_mutex_);
        if (reports_generated_.load()) {
            LOG_INFO("Reports already generated, skipping generation");
            return;
        }
        
        std::string timestamp = util::generate_timestamp();
        gemini_client_.save_latency_statistics("gemini_api_latency_" + timestamp + ".csv");
        gemini_client_.generate_summary_report(timestamp);
        reports_generated_.store(true);
        
        LOG_INFO("Reports generated successfully");
    }

    void start_accept() {
        acceptor_.async_accept(
            [this](std::error_code ec, tcp::socket socket) {
                if (!ec) {
                    LOG_INFO("New connection from {}", socket.remote_endpoint().address().to_string());
                    
                    if (connection_semaphore_.try_acquire()) {
                        // Create and start new session
                        auto session = std::make_shared<Session>(std::move(socket), gemini_client_, running_);
                        {
                            std::lock_guard<std::mutex> lock(sessions_mutex_);
                            active_sessions_.push_back(session);
                        }
                        session->start();
                    } else {
                        LOG_WARN("Connection limit reached, rejecting connection");
                        try {
                            socket.close();
                        } catch (const std::exception& e) {
                            LOG_ERROR("Error closing rejected socket: {}", e.what());
                        }
                    }
                } else if (ec != asio::error::operation_aborted) {
                    LOG_ERROR("Accept error: {}", ec.message());
                }
                
                // Continue accepting if still running
                if (running_) {
                    start_accept();
                }
            });
    }
    
    void start_stats_timer() {
        stats_timer_.expires_after(std::chrono::seconds(common::server::STATS_INTERVAL_SECONDS));
        stats_timer_.async_wait([this](const asio::error_code& ec) {
            if (!ec) {
                // Get Gemini API statistics
                size_t total_requests, successful_requests, failed_requests;
                gemini_client_.get_statistics(total_requests, successful_requests, failed_requests);
                
                // Log current statistics
                LOG_INFO("=== Current System Status ===");
                LOG_INFO("Active connections: {}", active_sessions_.size());
                LOG_INFO("Gemini API stats - Total: {}, Success: {}, Failed: {}", 
                         total_requests, successful_requests, failed_requests);
                
                // Get and log API latency statistics
                gemini_client_.print_latency_statistics();
                
                // Analyze API performance if we have enough data
                if (total_requests > 10) {
                    gemini_client_.analyze_gemini_performance();
                }
                
                // Continue the timer if still running
                if (running_) {
                    start_stats_timer();
                }
            }
        });
    }
    
    void start_health_check_timer() {
        health_check_timer_.expires_after(std::chrono::seconds(common::server::HEALTH_CHECK_INTERVAL_SECONDS));
        health_check_timer_.async_wait([this](const asio::error_code& ec) {
            if (!ec) {
                // Check if Gemini API is responding properly
                std::string health_check_message = "health check";
                
                gemini_client_.request(health_check_message, [this](bool success, std::string response) {
                    // Update health status based on response
                    bool previous_health = gemini_service_healthy_.load();
                    gemini_service_healthy_.store(success);
                    
                    if (success && !previous_health) {
                        LOG_INFO("Gemini API service recovered");
                    } else if (!success && previous_health) {
                        LOG_ERROR("Gemini API service is down: {}", response);
                    }
                });
                
                // Continue the timer if still running
                if (running_) {
                    start_health_check_timer();
                }
            }
        });
    }
    
    void start_shutdown_check_timer() {
        shutdown_check_timer_.expires_after(std::chrono::seconds(1));
        shutdown_check_timer_.async_wait([this](const asio::error_code& ec) {
            if (!ec) {
                if (!running_) {
                    // Check if all sessions are done
                    bool all_done = true;
                    {
                        std::lock_guard<std::mutex> lock(sessions_mutex_);
                        for (const auto& session : active_sessions_) {
                            if (session->is_processing()) {
                                all_done = false;
                                break;
                            }
                        }
                    }
                    
                    if (all_done) {
                        LOG_INFO("All sessions completed, generating final reports");
                        generate_reports();
                        io_context_.stop();
                    } else {
                        // Check again later
                        start_shutdown_check_timer();
                    }
                } else {
                    // Continue checking
                    start_shutdown_check_timer();
                }
            }
        });
    }
    
    TcpServer(asio::io_context& io_context, GeminiClient& client, int port = common::PORT)
    : io_context_(io_context),
      acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
      gemini_client_(client),
      connection_semaphore_(common::server::MAX_CONCURRENT_CONNECTIONS),
      stats_timer_(io_context),
      shutdown_check_timer_(io_context),
      health_check_timer_(io_context) {
        LOG_INFO("Starting TCP server on port {}", port);
        
        // Start accepting connections
        start_accept();
        
        // Start various timers
        start_stats_timer();
        start_health_check_timer();
        start_shutdown_check_timer();
    }
    
    void stop() {
        if (running_.exchange(false) == true) {
            LOG_INFO("Stopping server, waiting for active sessions to complete...");
            
            try {
                // Stop accepting new connections
                acceptor_.close();
                
                // Close all inactive sessions
                {
                    std::lock_guard<std::mutex> lock(sessions_mutex_);
                    for (auto& session : active_sessions_) {
                        if (!session->is_processing()) {
                            session->close();
                        }
                    }
                }
                
                // Note: We don't stop the io_context here.
                // The shutdown_check_timer will stop it when all sessions complete.
            } catch (const std::exception& e) {
                LOG_ERROR("Error during server shutdown: {}", e.what());
            }
        }
    }
};

int main(int argc, char* argv[]) {
    // Parse command line arguments
    std::string key_path = std::string(common::server::DEFAULT_KEY_PATH.data());
    int port = common::PORT;
    int workers = std::thread::hardware_concurrency();
    bool debug_mode = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--key" && i + 1 < argc) {
            key_path = argv[++i];
        } 
        else if (arg == "--port" && i + 1 < argc) {
            try {
                port = std::stoi(argv[++i]);
                if (port <= 0 || port > 65535) {
                    LOG_ERROR("Invalid port number: {}", port);
                    return 1;
                }
            } catch (const std::exception& e) {
                LOG_ERROR("Error parsing port: {}", e.what());
                return 1;
            }
        }
        else if (arg == "--threads" && i + 1 < argc) {
            try {
                workers = std::stoi(argv[++i]);
                if (workers <= 0) {
                    LOG_ERROR("Invalid number of threads: {}", workers);
                    return 1;
                }
            } catch (const std::exception& e) {
                LOG_ERROR("Error parsing threads: {}", e.what());
                return 1;
            }
        }
        else if (arg == "--debug") {
            debug_mode = true;
        }
        else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n\n"
                      << "Options:\n"
                      << "  --key PATH         Path to Google service account key (default: service-account-key.json)\n"
                      << "  --port PORT        Port to listen on (default: " << common::PORT << ")\n"
                      << "  --threads N        Number of worker threads (default: " << std::thread::hardware_concurrency() << ")\n"
                      << "  --debug            Enable debug logging\n"
                      << "  --help             Display this help message\n";
            return 0;
        }
    }
    
    // Initialize logger with appropriate level
    if (debug_mode) {
        common::Logger::Init(spdlog::level::debug);
        LOG_INFO("Debug logging enabled");
    } else {
        common::Logger::Init();
    }

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    LOG_INFO("Starting TCP Server with {} worker threads", workers);
    
    try {
        // Create io_context with multiple threads
        asio::io_context io_context(workers);
        
        // Create authentication handler for Google API
        LOG_INFO("Using service account key from: {}", key_path);
        GoogleAuth auth(key_path);
        
        // Refresh token right away to check if auth works
        auth.refresh_token();
        
        // Create Gemini client
        GeminiClient gemini_client(auth, io_context);
        
        // Create and start the server
        TcpServer server(io_context, gemini_client, port);
        
        // Set up signal handling for graceful shutdown
        asio::io_context io_context_signals;
        
        // Set up a timer to force exit after a certain period (5 minutes)
        asio::steady_timer force_exit_timer(io_context);
        
        // Set up signal handling
        asio::signal_set signals(io_context_signals, SIGINT, SIGTERM);
        
        // Start to handle the signals
        signals.async_wait([&server, &gemini_client, &force_exit_timer, &signals](const asio::error_code& ec, int signal_number) {
            if (!ec) {
                LOG_INFO("Received signal {} ({}), initiating graceful shutdown...", 
                        signal_number, 
                        signal_number == SIGINT ? "SIGINT" : 
                        signal_number == SIGTERM ? "SIGTERM" : "Unknown");
                
                // Stop accepting new connections/requests
                server.stop();
                
                // Set a timer to force exit after 5 minutes (300 seconds) if graceful shutdown takes too long
                force_exit_timer.expires_after(std::chrono::seconds(common::server::FORCE_EXIT_TIMEOUT_SECONDS));
                force_exit_timer.async_wait([&](const asio::error_code& timer_ec) {
                    if (!timer_ec) {
                        LOG_WARN("Graceful shutdown timed out after {} seconds. Generating reports before exit.", 
                                common::server::FORCE_EXIT_TIMEOUT_SECONDS);
                        
                        // Generate reports before forced exit
                        server.generate_reports();
                        
                        LOG_INFO("Forcing exit now.");
                        exit(0);
                    }
                });
                
                // Reset signal handler to force immediate exit on subsequent signals
                signals.async_wait([&server, &signals](const asio::error_code& ec2, int sig_num) {
                    LOG_WARN("Received second signal, forcing immediate exit");
                    
                    // Only generate reports if they haven't been generated already
                    server.generate_reports();
                    
                    LOG_INFO("Exiting now.");
                    exit(0);
                });
            }
        });
        
        // Start the signal handling thread
        std::thread signal_thread([&io_context_signals]() {
            io_context_signals.run();
        });
        
        // Start worker threads
        std::vector<std::thread> threads;
        for (int i = 1; i < workers; ++i) { // -1 because we'll use the main thread too
            threads.emplace_back([&io_context]() {
                io_context.run();
            });
        }
        
        // Use the main thread as a worker too
        io_context.run();
        
        // Wait for all threads to complete
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        
        // Wait for the signal thread to complete
        if (signal_thread.joinable()) {
            signal_thread.join();
        }
        
        LOG_INFO("Server shutdown complete");
    } 
    catch (const std::exception& e) {
        LOG_CRITICAL("Unhandled exception: {}", e.what());
        return 1;
    }
    
    // Clean up global resources
    EVP_cleanup();
    ERR_free_strings();
    curl_global_cleanup();
    
    return 0;
}
