#pragma once

#include "process.h"

namespace checker {

struct FileTarget {
    std::wstring path;
    std::vector<std::uint32_t> pids;
};

struct FileTargets {
    std::vector<FileTarget> files;
    std::size_t unavailable_processes{};
    bool complete{true};
};

struct FileReport {
    std::string path;
    std::vector<std::uint32_t> pids;
    bool complete{};
    std::uint64_t bytes_read{};
    std::vector<RuleMatch> matches;
};

struct FileScan {
    bool complete{true};
    std::size_t candidate_files{};
    std::size_t scanned_files{};
    std::size_t unavailable_processes{};
    std::uint64_t bytes_read{};
    std::uint64_t elapsed_ms{};
    std::vector<FileReport> files;
};

FileTargets find_running_images(std::span<const std::uint32_t> excluded_pids);
FileScan scan_files(const FileTargets& targets, const Rules& rules, const ScanOptions& options);

}
