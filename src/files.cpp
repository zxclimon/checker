#include "files.h"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>

namespace checker {
namespace {

using Clock = std::chrono::steady_clock;
constexpr std::size_t chunk_size = 1024 * 1024;
constexpr std::uint64_t file_limit = 256ULL * 1024 * 1024;

struct CloseHandleDeleter {
    void operator()(HANDLE handle) const noexcept {
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};
using Handle = std::unique_ptr<void, CloseHandleDeleter>;

bool pe_image(std::span<const std::uint8_t> data) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    IMAGE_DOS_HEADER header{};
    std::memcpy(&header, data.data(), sizeof(header));
    if (header.e_magic != IMAGE_DOS_SIGNATURE || header.e_lfanew < static_cast<LONG>(sizeof(header))) {
        return false;
    }
    const auto offset = static_cast<std::size_t>(header.e_lfanew);
    if (offset > data.size() || data.size() - offset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) {
        return false;
    }
    DWORD signature = 0;
    std::memcpy(&signature, data.data() + offset, sizeof(signature));
    return signature == IMAGE_NT_SIGNATURE;
}

FileReport scan_file(const FileTarget& target, const Rules& rules, Clock::time_point deadline,
                     std::uint64_t byte_budget) {
    FileReport report;
    report.path = utf8(target.path);
    report.pids = target.pids;
    if (Clock::now() >= deadline || byte_budget == 0) {
        return report;
    }
    const Handle file(CreateFileW(target.path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    LARGE_INTEGER size{};
    if (file.get() == INVALID_HANDLE_VALUE || !GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0) {
        return report;
    }
    const auto length = static_cast<std::uint64_t>(size.QuadPart);
    const auto limit = static_cast<std::size_t>(std::min({length, byte_budget, file_limit}));
    MemoryBlock block;
    block.data.resize(limit);
    std::size_t read = 0;
    while (read < limit && Clock::now() < deadline) {
        const auto requested = static_cast<DWORD>(std::min(chunk_size, limit - read));
        DWORD received = 0;
        if (!ReadFile(file.get(), block.data.data() + read, requested, &received, nullptr) || received == 0) {
            break;
        }
        read += received;
    }
    block.data.resize(read);
    report.bytes_read = read;
    if (!pe_image(block.data) || Clock::now() >= deadline) {
        return report;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
    auto scan = rules.scan(std::span<MemoryBlock>(&block, 1),
        static_cast<int>(std::max<std::int64_t>(1, (remaining.count() + 999) / 1000)));
    report.matches = std::move(scan.matches);
    LARGE_INTEGER current_size{};
    report.complete = read == length && scan.complete && Clock::now() <= deadline &&
        GetFileSizeEx(file.get(), &current_size) && current_size.QuadPart == size.QuadPart;
    return report;
}

}

FileTargets find_running_images(std::span<const std::uint32_t> excluded_pids) {
    FileTargets result;
    const Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (snapshot.get() == INVALID_HANDLE_VALUE || !Process32FirstW(snapshot.get(), &entry)) {
        result.complete = false;
        return result;
    }
    do {
        const auto pid = entry.th32ProcessID;
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId() ||
            std::find(excluded_pids.begin(), excluded_pids.end(), pid) != excluded_pids.end()) {
            continue;
        }
        const Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        std::array<wchar_t, 32768> path{};
        DWORD length = static_cast<DWORD>(path.size());
        if (!process || !QueryFullProcessImageNameW(process.get(), 0, path.data(), &length)) {
            ++result.unavailable_processes;
            result.complete = false;
            continue;
        }
        const auto existing = std::find_if(result.files.begin(), result.files.end(), [&](const FileTarget& file) {
            return _wcsicmp(file.path.c_str(), path.data()) == 0;
        });
        if (existing != result.files.end()) {
            existing->pids.push_back(pid);
        } else {
            result.files.push_back({std::wstring(path.data(), length), {pid}});
        }
    } while (Process32NextW(snapshot.get(), &entry));
    result.complete &= GetLastError() == ERROR_NO_MORE_FILES;
    return result;
}

FileScan scan_files(const FileTargets& targets, const Rules& rules, const ScanOptions& options) {
    const auto started = Clock::now();
    const auto deadline = started + options.timeout;
    FileScan result;
    result.complete = targets.complete;
    result.unavailable_processes = targets.unavailable_processes;
    result.candidate_files = targets.files.size();
    for (const auto& target : targets.files) {
        if (Clock::now() >= deadline || result.bytes_read >= options.max_bytes) {
            result.complete = false;
            break;
        }
        auto report = scan_file(target, rules, deadline, options.max_bytes - result.bytes_read);
        result.bytes_read += report.bytes_read;
        result.scanned_files += report.complete ? 1u : 0u;
        result.complete &= report.complete;
        result.files.push_back(std::move(report));
    }
    result.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
    return result;
}

}
