#include "files.h"

#include <windows.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <iostream>
#include <optional>

namespace {

using nlohmann::json;

std::uint64_t number(std::wstring_view text, std::uint64_t maximum) {
    const auto value = checker::utf8(text);
    std::uint64_t parsed = 0;
    const auto [end, status] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (status != std::errc{} || end != value.data() + value.size() || parsed == 0 || parsed > maximum) {
        return 0;
    }
    return parsed;
}

const char* status(bool features, bool review, bool complete) {
    return features ? "feature_matches" : review ? "review_required" : complete ? "no_matches" : "incomplete";
}

bool feature_matches(std::span<const checker::RuleMatch> matches) {
    return std::any_of(matches.begin(), matches.end(), [](const auto& match) { return !match.review_required; });
}

json matches_json(std::span<const checker::RuleMatch> matches, bool file_offsets = false) {
    json result = json::array();
    for (const auto& match : matches) {
        json evidence = json::array();
        for (const auto& item : match.evidence) {
            evidence.push_back({{"pattern", item.pattern},
                {file_offsets ? "offset" : "address", checker::address_string(item.address)}});
        }
        result.push_back({{"rule", match.rule}, {"description", match.description},
            {"review_required", match.review_required}, {"evidence", evidence}});
    }
    return result;
}

json report_json(const checker::ScanReport& report) {
    json findings = json::array();
    bool features = false;
    for (const auto& finding : report.findings) {
        features |= feature_matches(finding.matches);
        findings.push_back({{"allocation", checker::address_string(finding.allocation)},
            {"memory_type", finding.memory_type}, {"module_path", finding.module_path},
            {"listed_module", finding.listed_module}, {"matches", matches_json(finding.matches)}});
    }
    return {{"pid", report.pid}, {"image_path", report.image_path}, {"complete", report.complete},
        {"status", status(features, !report.findings.empty(), report.complete)},
        {"bytes_read", report.bytes_read}, {"unreadable_bytes", report.unreadable_bytes},
        {"candidate_allocations", report.candidate_allocations}, {"scanned_allocations", report.scanned_allocations},
        {"private_executable_allocations", report.private_executable_allocations},
        {"elapsed_ms", report.elapsed_ms}, {"findings", findings}};
}

json files_json(const checker::FileScan& scan) {
    json files = json::array();
    bool features = false;
    bool found = false;
    for (const auto& file : scan.files) {
        const bool matched = feature_matches(file.matches);
        features |= matched;
        found |= !file.matches.empty();
        files.push_back({{"path", file.path}, {"pids", file.pids},
            {"source", file.pids.empty() ? "file" : "process_image_file"},
            {"complete", file.complete}, {"bytes_read", file.bytes_read},
            {"status", status(matched, !file.matches.empty(), file.complete)},
            {"matches", matches_json(file.matches, true)}});
    }
    return {{"complete", scan.complete}, {"status", status(features, found, scan.complete)},
        {"candidate_files", scan.candidate_files}, {"scanned_files", scan.scanned_files},
        {"unavailable_processes", scan.unavailable_processes}, {"bytes_read", scan.bytes_read},
        {"elapsed_ms", scan.elapsed_ms}, {"files", files}};
}

void print_matches(std::span<const checker::RuleMatch> matches) {
    for (const auto& match : matches) {
        std::cout << "    " << match.rule << (match.review_required ? " — требует проверки" : "") << '\n';
        for (const auto& evidence : match.evidence) {
            std::cout << "      " << evidence.pattern << " @ " << checker::address_string(evidence.address) << '\n';
        }
    }
}

void print_report(const checker::ScanReport& report) {
    std::cout << "\nPID " << report.pid << ": " << report.image_path << '\n';
    for (const auto& finding : report.findings) {
        std::cout << "  Совпадение в памяти " << checker::address_string(finding.allocation)
                  << " [" << finding.memory_type << "]\n";
        if (!finding.module_path.empty()) {
            std::cout << "  " << finding.module_path << '\n';
        }
        print_matches(finding.matches);
    }
    if (report.findings.empty()) {
        std::cout << (report.complete ? "  Признаки по текущим правилам не найдены.\n" :
            "  Совпадений нет, но проверка неполная.\n");
    } else if (!report.complete) {
        std::cout << "  Найдены совпадения; часть памяти проверить не удалось.\n";
    }
    std::cout << "  Проверено областей: " << report.scanned_allocations << '/' << report.candidate_allocations
              << ", прочитано: " << report.bytes_read / (1024 * 1024)
              << " МБ, время: " << report.elapsed_ms << " мс.\n";
}

void print_files(const checker::FileScan& scan) {
    bool found = false;
    for (const auto& file : scan.files) {
        if (file.matches.empty()) {
            continue;
        }
        found = true;
        std::cout << "\nСовпадение в файле: " << file.path << '\n';
        if (!file.pids.empty()) {
            std::cout << "  EXE запущенных процессов, PID:";
            for (const auto pid : file.pids) {
                std::cout << ' ' << pid;
            }
            std::cout << '\n';
        }
        print_matches(file.matches);
    }
    if (!found) {
        std::cout << "\nВ проверенных файлах совпадений нет.\n";
    }
    std::cout << "  Проверено файлов: " << scan.scanned_files << '/' << scan.candidate_files
              << ", прочитано: " << scan.bytes_read / (1024 * 1024)
              << " МБ, время: " << scan.elapsed_ms << " мс.\n";
    if (!scan.complete) {
        std::cout << "  Проверка файлов неполная.\n";
    }
}

}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    bool json_output = false;
    for (int index = 1; index < argc; ++index) {
        json_output |= std::wstring_view(argv[index]) == L"--json";
    }
    DWORD console_processes[2]{};
    DWORD mode = 0;
    const bool pause_at_end = !json_output && GetConsoleProcessList(console_processes, 2) == 1 &&
        GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
    std::optional<std::uint32_t> pid;
    checker::ScanOptions options;
    checker::FileTargets file_targets;
    for (int index = 1; index < argc; ++index) {
        const std::wstring_view arg(argv[index]);
        if (arg == L"--json") {
            continue;
        }
        if (arg == L"--file") {
            if (index + 1 >= argc) {
                return 2;
            }
            file_targets.files.push_back({argv[++index], {}});
            continue;
        }
        if (!arg.empty() && arg.front() != L'-') {
            file_targets.files.push_back({std::wstring(arg), {}});
            continue;
        }
        if ((arg != L"--pid" && arg != L"--timeout-ms" && arg != L"--max-mb") || index + 1 >= argc) {
            return 2;
        }
        const auto maximum = arg == L"--pid" ? UINT32_MAX : arg == L"--timeout-ms" ? 120000u : 16384u;
        const auto value = number(argv[++index], maximum);
        if (value == 0) {
            return 2;
        }
        if (arg == L"--pid") {
            pid = static_cast<std::uint32_t>(value);
        } else if (arg == L"--timeout-ms") {
            options.timeout = std::chrono::milliseconds(value);
        } else {
            options.max_bytes = value * 1024 * 1024;
        }
    }
    const bool automatic = !pid && file_targets.files.empty();
    const auto processes = pid ? std::vector<std::uint32_t>{*pid} :
        automatic ? checker::find_minecraft() : std::vector<std::uint32_t>{};
    bool incomplete = automatic && processes.empty();
    bool found = false;
    checker::Rules rules;
    json reports = json::array();
    for (const auto target : processes) {
        const auto report = checker::scan_process(target, rules, options, !pid.has_value());
        incomplete |= !report.complete;
        found |= !report.findings.empty();
        if (json_output) {
            reports.push_back(report_json(report));
        } else {
            print_report(report);
        }
    }
    std::optional<checker::FileScan> files;
    if (automatic || !file_targets.files.empty()) {
        if (automatic) {
            file_targets = checker::find_running_images(processes);
        }
        files = checker::scan_files(file_targets, rules, options);
        incomplete |= !files->complete;
        found |= std::any_of(files->files.begin(), files->files.end(), [](const auto& file) {
            return !file.matches.empty();
        });
        if (!json_output) {
            print_files(*files);
        }
    }
    if (json_output) {
        json result{{"schema_version", 2}, {"processes", reports}, {"complete", !incomplete}};
        result["file_scan"] = files ? files_json(*files) : json(nullptr);
        std::cout << result.dump(2) << '\n';
    }
    if (pause_at_end) {
        std::cout << "\nНажмите Enter для выхода." << std::endl;
        std::cin.get();
    }
    return incomplete ? 2 : found ? 1 : 0;
}
