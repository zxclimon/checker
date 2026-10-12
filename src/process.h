#pragma once

#include "rules.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace checker {

struct ScanOptions {
    std::chrono::milliseconds timeout{15000};
    std::uint64_t max_bytes{2ULL * 1024 * 1024 * 1024};
};

struct Finding {
    std::uintptr_t allocation{};
    std::string memory_type;
    std::string module_path;
    bool listed_module{};
    std::vector<RuleMatch> matches;
};

struct ScanReport {
    std::uint32_t pid{};
    std::string image_path;
    bool complete{true};
    std::uint64_t bytes_read{};
    std::uint64_t unreadable_bytes{};
    std::size_t candidate_allocations{};
    std::size_t scanned_allocations{};
    std::size_t private_executable_allocations{};
    std::uint64_t elapsed_ms{};
    std::vector<Finding> findings;
};

std::vector<std::uint32_t> find_minecraft();
ScanReport scan_process(std::uint32_t pid, const Rules& rules, const ScanOptions& options,
                        bool require_minecraft);
std::string utf8(std::wstring_view text);
std::string address_string(std::uintptr_t address);

}
