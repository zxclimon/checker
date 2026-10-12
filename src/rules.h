#pragma once

#include <yara.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace checker {

struct MemoryBlock {
    std::uintptr_t address{};
    std::vector<std::uint8_t> data;
};

struct Evidence {
    std::string pattern;
    std::uintptr_t address{};
};

struct RuleMatch {
    std::string rule;
    std::string description;
    bool review_required{};
    std::vector<Evidence> evidence;
};

struct RuleScan {
    std::vector<RuleMatch> matches;
    bool complete{true};
};

class Rules {
public:
    Rules();
    Rules(const Rules&) = delete;
    Rules& operator=(const Rules&) = delete;
    std::size_t overlap() const noexcept { return overlap_; }
    RuleScan scan(std::span<MemoryBlock> blocks, int timeout_seconds) const;

private:
    struct Runtime {
        Runtime();
        ~Runtime();
    } runtime_;
    std::unique_ptr<YR_RULES, decltype(&yr_rules_destroy)> rules_{nullptr, yr_rules_destroy};
    std::size_t overlap_{};
};

}
