#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>

namespace common {

class Logger {
public:
    // Initialize the logger with an optional level and optional filename
    static void Init(spdlog::level::level_enum level = spdlog::level::info, const std::string& filename = "");
    static std::shared_ptr<spdlog::logger>& GetLogger();

private:
    static std::shared_ptr<spdlog::logger> s_Logger;
};

} // namespace common

// Define convenient macros for logging
#define LOG_TRACE(...)    ::common::Logger::GetLogger()->trace(__VA_ARGS__)
#define LOG_DEBUG(...)    ::common::Logger::GetLogger()->debug(__VA_ARGS__)
#define LOG_INFO(...)     ::common::Logger::GetLogger()->info(__VA_ARGS__)
#define LOG_WARN(...)     ::common::Logger::GetLogger()->warn(__VA_ARGS__)
#define LOG_ERROR(...)    ::common::Logger::GetLogger()->error(__VA_ARGS__)
#define LOG_CRITICAL(...) ::common::Logger::GetLogger()->critical(__VA_ARGS__)