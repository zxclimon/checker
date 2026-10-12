#include "process.h"

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

json report_json(const checker::ScanReport& report) {
    json findings = json::array();
    for (const auto& finding : report.findings) {
        json rules = json::array();
        for (const auto& match : finding.matches) {
            json evidence = json::array();
            for (const auto& item : match.evidence) {
                evidence.push_back({{"pattern", item.pattern}, {"address", checker::address_string(item.address)}});
            }
            rules.push_back({{"rule", match.rule}, {"description", match.description}, {"evidence", evidence}});
        }
        findings.push_back({{"allocation", checker::address_string(finding.allocation)},
            {"memory_type", finding.memory_type}, {"module_path", finding.module_path},
            {"listed_module", finding.listed_module}, {"matches", rules}});
    }
    return {{"pid", report.pid}, {"image_path", report.image_path}, {"complete", report.complete},
        {"status", !report.findings.empty() ? "feature_matches" : report.complete ? "no_matches" : "incomplete"},
        {"bytes_read", report.bytes_read}, {"unreadable_bytes", report.unreadable_bytes},
        {"candidate_allocations", report.candidate_allocations}, {"scanned_allocations", report.scanned_allocations},
        {"private_executable_allocations", report.private_executable_allocations},
        {"elapsed_ms", report.elapsed_ms}, {"findings", findings}};
}

void print_report(const checker::ScanReport& report) {
    std::cout << "\nPID " << report.pid << ": " << report.image_path << '\n';
    for (const auto& finding : report.findings) {
        std::cout << "  Совпадение в памяти " << checker::address_string(finding.allocation)
                  << " [" << finding.memory_type << "]\n";
        if (!finding.module_path.empty()) {
            std::cout << "  " << finding.module_path << '\n';
        }
        for (const auto& match : finding.matches) {
            std::cout << "    " << match.rule << '\n';
            for (const auto& evidence : match.evidence) {
                std::cout << "      " << evidence.pattern << " @ " << checker::address_string(evidence.address) << '\n';
            }
        }
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

}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    bool json_output = false;
    for (int index = 1; index < argc; ++index) {
        json_output |= std::wstring_view(argv[index]) == L"--json";
    }
    DWORD console_processes[2]{};
    DWORD mode = 0;
    const bool pause_at_end = argc == 1 && GetConsoleProcessList(console_processes, 2) == 1 &&
        GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
    std::optional<std::uint32_t> pid;
    checker::ScanOptions options;
    for (int index = 1; index < argc; ++index) {
        const std::wstring_view arg(argv[index]);
        if (arg == L"--json") {
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
    const auto processes = pid ? std::vector<std::uint32_t>{*pid} : checker::find_minecraft();
    int exit_code = processes.empty() ? 2 : 0;
    checker::Rules rules;
    json reports = json::array();
    for (const auto target : processes) {
        const auto report = checker::scan_process(target, rules, options, !pid.has_value());
        if (!report.complete) {
            exit_code = 2;
        } else if (!report.findings.empty()) {
            exit_code = std::max(exit_code, 1);
        }
        if (json_output) {
            reports.push_back(report_json(report));
        } else {
            print_report(report);
        }
    }
    if (json_output) {
        std::cout << json({{"schema_version", 1}, {"processes", reports}}).dump(2) << '\n';
    }
    if (pause_at_end) {
        std::cout << "\nНажмите Enter для выхода." << std::endl;
        std::cin.get();
    }
    return exit_code;
}
