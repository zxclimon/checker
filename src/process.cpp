#include "process.h"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <sstream>

namespace checker {
namespace {

using Clock = std::chrono::steady_clock;
constexpr std::size_t chunk_size = 1024 * 1024;
constexpr std::uint64_t allocation_limit = 512ULL * 1024 * 1024;

struct CloseHandleDeleter {
    void operator()(HANDLE handle) const noexcept {
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};
using Handle = std::unique_ptr<void, CloseHandleDeleter>;

bool game_name(std::wstring_view name) {
    const std::wstring value(name);
    return _wcsicmp(value.c_str(), L"Minecraft.Windows.exe") == 0;
}

bool process_running(HANDLE process, ScanReport& report) {
    const bool running = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    report.complete &= running;
    return running;
}

bool limit_reached(Clock::time_point deadline, const ScanOptions& options, ScanReport& report) {
    if (Clock::now() >= deadline || report.bytes_read >= options.max_bytes) {
        report.complete = false;
        return true;
    }
    return false;
}

bool executable(DWORD protection) {
    const DWORD access = protection & 0xff;
    return access == PAGE_EXECUTE || access == PAGE_EXECUTE_READ ||
           access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY;
}

bool readable(DWORD protection) {
    if (protection & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
    const DWORD access = protection & 0xff;
    return access == PAGE_READONLY || access == PAGE_READWRITE || access == PAGE_WRITECOPY ||
           executable(protection);
}

struct Range {
    std::uintptr_t begin{};
    std::uintptr_t end{};
};

struct Allocation {
    std::uintptr_t base{};
    DWORD type{};
    bool executable{};
    std::uint64_t unreadable_bytes{};
    std::vector<Range> ranges;
};

std::vector<Allocation> collect_allocations(HANDLE process, Clock::time_point deadline, ScanReport& report) {
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    const auto maximum = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
    std::map<std::uintptr_t, Allocation> allocations;
    for (std::uintptr_t address = 0; address <= maximum;) {
        if (Clock::now() >= deadline) {
            report.complete = false;
            break;
        }
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) != sizeof(info)) {
            report.complete &= GetLastError() == ERROR_INVALID_PARAMETER;
            break;
        }
        const auto begin = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        if (!info.RegionSize || info.RegionSize > std::numeric_limits<std::uintptr_t>::max() - begin) {
            report.complete = false;
            break;
        }
        const auto end = begin + info.RegionSize;
        if (end <= address) {
            report.complete = false;
            break;
        }
        if (info.State == MEM_COMMIT && info.AllocationBase) {
            const auto base = reinterpret_cast<std::uintptr_t>(info.AllocationBase);
            auto& allocation = allocations[base];
            allocation.base = base;
            allocation.type = info.Type;
            allocation.executable |= executable(info.Protect);
            if (readable(info.Protect)) {
                if (!allocation.ranges.empty() && allocation.ranges.back().end == begin) {
                    allocation.ranges.back().end = end;
                } else {
                    allocation.ranges.push_back({begin, end});
                }
            } else {
                allocation.unreadable_bytes += info.RegionSize;
            }
        }
        address = end;
    }
    std::vector<Allocation> candidates;
    for (auto& entry : allocations) {
        auto& allocation = entry.second;
        if (allocation.executable) {
            candidates.push_back(std::move(allocation));
        }
    }
    return candidates;
}

std::map<std::uintptr_t, std::string> module_paths(HANDLE process, Clock::time_point deadline, ScanReport& report) {
    std::vector<HMODULE> modules(256);
    DWORD required = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        if (Clock::now() >= deadline) {
            report.complete = false;
            return {};
        }
        const auto capacity = static_cast<DWORD>(modules.size() * sizeof(HMODULE));
        if (!EnumProcessModulesEx(process, modules.data(), capacity, &required, LIST_MODULES_ALL)) {
            report.complete = false;
            return {};
        }
        if (required <= capacity) {
            modules.resize(required / sizeof(HMODULE));
            std::map<std::uintptr_t, std::string> paths;
            std::vector<wchar_t> path(32768);
            for (HMODULE module : modules) {
                if (Clock::now() >= deadline) {
                    report.complete = false;
                    break;
                }
                const DWORD length = GetModuleFileNameExW(process, module, path.data(), static_cast<DWORD>(path.size()));
                if (!length || length >= path.size()) {
                    report.complete = false;
                }
                paths.emplace(reinterpret_cast<std::uintptr_t>(module),
                    length && length < path.size() ? utf8({path.data(), length}) : std::string{});
            }
            return paths;
        }
        modules.resize(required / sizeof(HMODULE) + 64);
    }
    report.complete = false;
    return {};
}

std::vector<MemoryBlock> read_allocation(HANDLE process, const Allocation& allocation,
    std::size_t overlap, Clock::time_point deadline, const ScanOptions& options, ScanReport& report) {
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    const std::size_t page_size = system.dwPageSize;
    std::vector<MemoryBlock> blocks;
    for (const auto& range : allocation.ranges) {
        std::vector<std::uint8_t> tail;
        for (auto cursor = range.begin; cursor < range.end;) {
            if (limit_reached(deadline, options, report)) {
                return blocks;
            }
            const auto wanted = static_cast<std::size_t>(std::min<std::uint64_t>(
                {chunk_size, range.end - cursor, options.max_bytes - report.bytes_read}));
            MemoryBlock block{cursor - tail.size(), std::vector<std::uint8_t>(tail.size() + wanted)};
            std::copy(tail.begin(), tail.end(), block.data.begin());
            SIZE_T received = 0;
            auto* destination = block.data.data() + tail.size();
            const auto page_remaining = std::min(wanted, page_size - cursor % page_size);
            if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(cursor), destination, wanted, &received) &&
                received == 0 && wanted > page_remaining) {
                // A changed page must not hide the rest of a readable region.
                ReadProcessMemory(process, reinterpret_cast<LPCVOID>(cursor), destination, page_remaining, &received);
            }
            if (received > wanted) {
                report.complete = false;
                return blocks;
            }
            if (received == 0) {
                const auto skipped = std::min<std::uintptr_t>(page_size - cursor % page_size, range.end - cursor);
                report.unreadable_bytes += skipped;
                report.complete = false;
                if (!process_running(process, report)) {
                    return blocks;
                }
                cursor += skipped;
                tail.clear();
                continue;
            }
            block.data.resize(tail.size() + received);
            report.bytes_read += received;
            cursor += received;
            const auto retained = std::min(overlap, block.data.size());
            tail.assign(block.data.end() - static_cast<std::ptrdiff_t>(retained), block.data.end());
            blocks.push_back(std::move(block));
        }
    }
    return blocks;
}

std::string mapping_path(HANDLE process, std::uintptr_t base) {
    std::vector<wchar_t> path(32768);
    const DWORD length = GetMappedFileNameW(process, reinterpret_cast<LPVOID>(base),
        path.data(), static_cast<DWORD>(path.size()));
    return length && length < path.size() ? utf8({path.data(), length}) : std::string{};
}

}

std::string utf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return {};
    }
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(length), '\0');
    const int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
        result.data(), length, nullptr, nullptr);
    result.resize(static_cast<std::size_t>(written));
    return result;
}

std::string address_string(std::uintptr_t address) {
    std::ostringstream text;
    text << "0x" << std::hex << address;
    return text.str();
}

std::vector<std::uint32_t> find_minecraft() {
    const Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) {
        return {};
    }
    std::vector<std::uint32_t> processes;
    do {
        if (game_name(entry.szExeFile)) {
            processes.push_back(entry.th32ProcessID);
        }
    } while (Process32NextW(snapshot.get(), &entry));
    return processes;
}

ScanReport scan_process(std::uint32_t pid, const Rules& rules, const ScanOptions& options,
                        bool require_minecraft) {
    const auto started = Clock::now();
    const auto deadline = started + options.timeout;
    ScanReport report;
    report.pid = pid;
    const Handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid));
    std::vector<wchar_t> path(32768);
    DWORD path_length = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process.get(), 0, path.data(), &path_length)) {
        report.complete = false;
        return report;
    }
    const std::wstring image(path.data(), path_length);
    report.image_path = utf8(image);
    if (require_minecraft && !game_name(std::filesystem::path(image).filename().wstring())) {
        report.complete = false;
        return report;
    }
    USHORT machine = 0;
    USHORT native_machine = 0;
    if (!IsWow64Process2(process.get(), &machine, &native_machine)) {
        report.complete = false;
        return report;
    }
    if ((machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine : machine) != IMAGE_FILE_MACHINE_AMD64) {
        report.complete = false;
        return report;
    }

    const auto modules = module_paths(process.get(), deadline, report);
    const auto allocations = collect_allocations(process.get(), deadline, report);
    report.candidate_allocations = allocations.size();
    for (const auto& allocation : allocations) {
        if (allocation.type == MEM_PRIVATE) {
            ++report.private_executable_allocations;
        }
        report.unreadable_bytes += allocation.unreadable_bytes;
        if (allocation.unreadable_bytes) {
            report.complete = false;
        }
    }
    for (const auto& allocation : allocations) {
        if (limit_reached(deadline, options, report)) {
            break;
        }
        if (!process_running(process.get(), report)) {
            break;
        }
        std::uint64_t readable_size = 0;
        for (const auto& range : allocation.ranges) {
            readable_size += range.end - range.begin;
        }
        if (readable_size > allocation_limit) {
            report.complete = false;
            continue;
        }
        const auto bytes_before = report.bytes_read;
        auto blocks = read_allocation(process.get(), allocation, rules.overlap(), deadline, options, report);
        if (blocks.empty()) {
            continue;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (remaining <= 0) {
            report.complete = false;
            break;
        }
        auto scan = rules.scan(blocks, static_cast<int>((remaining + 999) / 1000));
        report.complete &= scan.complete;
        if (scan.complete && report.bytes_read - bytes_before == readable_size && allocation.unreadable_bytes == 0) {
            ++report.scanned_allocations;
        }
        if (!scan.matches.empty()) {
            const auto module = modules.find(allocation.base);
            Finding finding;
            finding.allocation = allocation.base;
            finding.memory_type = allocation.type == MEM_IMAGE ? "image" :
                allocation.type == MEM_PRIVATE ? "private_executable" : "mapped_executable";
            finding.listed_module = module != modules.end();
            finding.module_path = finding.listed_module ? module->second : mapping_path(process.get(), allocation.base);
            finding.matches = std::move(scan.matches);
            report.findings.push_back(std::move(finding));
        }
    }
    process_running(process.get(), report);
    if (Clock::now() >= deadline) {
        report.complete = false;
    }
    report.elapsed_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count());
    return report;
}

}
