#include "logger.h"
#include <spdlog/sinks/basic_file_sink.h> // Include for file sink
#include <spdlog/sinks/stdout_color_sinks.h> // Ensure this is included
#include <vector>
#include <iostream> // Include for std::cerr
#include <iterator> // Include for std::begin, std::end

namespace common {

// Define the static member
std::shared_ptr<spdlog::logger> Logger::s_Logger;

// Initialize the logger with the specified level and optional filename
// Default arguments should only be in the header declaration
void Logger::Init(spdlog::level::level_enum level, const std::string& filename) {
    std::vector<spdlog::sink_ptr> sinks;

    // Create and add the console sink
    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern("%^[%Y-%m-%d %H:%M:%S.%e] %n: %v%$"); // Updated pattern with full timestamp
        sinks.push_back(console_sink);
    } catch (const spdlog::spdlog_ex& ex) {
         std::cerr << "Console sink creation failed: " << ex.what() << std::endl;
         // If console fails, we probably can't log anything usefully
         throw; // Rethrow or handle critically
    }


    // Create and add the file sink if a filename is provided
    if (!filename.empty()) {
        try {
            // Create logs directory if it doesn't exist (optional, requires <filesystem>)
            // std::filesystem::create_directories("logs");
            // auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/" + filename, true);

            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(filename, true); // true = truncate file
            file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %n: %v"); // Updated pattern with full timestamp
            sinks.push_back(file_sink);
        } catch (const spdlog::spdlog_ex& ex) {
            // Use std::cerr for logging errors during logger setup
            std::cerr << "Log file sink creation failed for '" << filename << "': " << ex.what() << std::endl;
            // Continue with console logging only if it was successful
            if (sinks.empty()) {
                 throw std::runtime_error("Failed to create any log sinks.");
            }
        }
    }

    // Create a logger named "APP" with the configured sinks
    // Use std::begin and std::end for iterators
    s_Logger = std::make_shared<spdlog::logger>("APP", std::begin(sinks), std::end(sinks));

    // Register the logger - this allows finding it globally if needed, but we use the static member
    try {
        spdlog::register_logger(s_Logger);
    } catch (const spdlog::spdlog_ex& ex) {
        // Handle cases where logger name might already be registered (e.g., multiple Init calls)
        std::cerr << "Logger registration failed (might already exist): " << ex.what() << std::endl;
        // Optionally retrieve the existing logger if registration fails
        s_Logger = spdlog::get("APP");
        if (!s_Logger) { // Check if retrieval also failed
             throw std::runtime_error("Failed to register or retrieve logger 'APP'.");
        }
    }


    s_Logger->set_level(level); // Set the log level for all sinks
    s_Logger->flush_on(spdlog::level::warn); // Flush on warning and above for safety
}

std::shared_ptr<spdlog::logger>& Logger::GetLogger() {
    // Add a check in case GetLogger is called before Init
    if (!s_Logger) {
        // Option 1: Throw an exception
         throw std::runtime_error("Logger has not been initialized. Call Logger::Init() first.");
        // Option 2: Initialize with defaults here (less ideal as it hides the explicit Init call)
        // Init();
    }
    return s_Logger;
}

} // namespace common