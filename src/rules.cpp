#include "rules.h"
#include "rules_embedded.h"

#include <algorithm>
#include <string_view>

namespace checker {
namespace {

struct BlockIterator {
    std::span<MemoryBlock> blocks;
    std::size_t index{};
    YR_MEMORY_BLOCK current{};

    YR_MEMORY_BLOCK* get() noexcept {
        if (index >= blocks.size()) {
            return nullptr;
        }
        auto& block = blocks[index];
        current.size = block.data.size();
        current.base = block.address;
        current.context = &block;
        current.fetch_data = [](YR_MEMORY_BLOCK* item) -> const std::uint8_t* {
            return static_cast<MemoryBlock*>(item->context)->data.data();
        };
        return &current;
    }
};

int collect_match(YR_SCAN_CONTEXT* context, int message, void* data, void* user) noexcept {
    if (message == CALLBACK_MSG_TOO_MANY_MATCHES) {
        return CALLBACK_ERROR;
    }
    if (message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;
    }
    auto& scan = *static_cast<RuleScan*>(user);
    auto* rule = static_cast<YR_RULE*>(data);
    RuleMatch result;
    result.rule = rule->identifier;
    YR_META* meta = nullptr;
    yr_rule_metas_foreach(rule, meta) {
        if (meta->type == META_TYPE_STRING && std::string_view(meta->identifier) == "description") {
            result.description = meta->string;
        }
    }
    YR_STRING* string = nullptr;
    yr_rule_strings_foreach(rule, string) {
        YR_MATCH* match = nullptr;
        yr_string_matches_foreach(context, string, match) {
            result.evidence.push_back({string->identifier,
                static_cast<std::uintptr_t>(match->base + match->offset)});
            break;
        }
    }
    scan.matches.push_back(std::move(result));
    return CALLBACK_CONTINUE;
}

}

Rules::Runtime::Runtime() {
    yr_initialize();
}

Rules::Runtime::~Runtime() {
    yr_finalize();
}

Rules::Rules() {
    YR_COMPILER* raw = nullptr;
    yr_compiler_create(&raw);
    if (!raw) {
        return;
    }
    const std::unique_ptr<YR_COMPILER, decltype(&yr_compiler_destroy)> compiler(raw, yr_compiler_destroy);
    yr_compiler_set_include_callback(raw, nullptr, nullptr, nullptr);
    if (yr_compiler_add_string(raw, embedded_rules, nullptr) != 0) {
        return;
    }
    YR_RULES* compiled = nullptr;
    yr_compiler_get_rules(raw, &compiled);
    if (!compiled) {
        return;
    }
    rules_.reset(compiled);
    YR_RULE* rule = nullptr;
    yr_rules_foreach(compiled, rule) {
        YR_STRING* string = nullptr;
        yr_rule_strings_foreach(rule, string) {
            // Chunk overlap is exact for these literal-only rules, including UTF-16.
            if (!STRING_IS_LITERAL(string) || STRING_IS_REGEXP(string) || STRING_IS_HEX(string)) {
                rules_.reset();
                return;
            }
            const auto length = static_cast<std::size_t>(string->length) * (STRING_IS_WIDE(string) ? 2u : 1u);
            if (length == 0 || length > 4096) {
                rules_.reset();
                return;
            }
            overlap_ = std::max(overlap_, length - 1);
        }
    }
}

RuleScan Rules::scan(std::span<MemoryBlock> blocks, int timeout_seconds) const {
    if (!rules_) {
        return {{}, false};
    }
    if (blocks.empty()) {
        return {};
    }
    BlockIterator state{blocks};
    YR_MEMORY_BLOCK_ITERATOR iterator{};
    iterator.context = &state;
    iterator.first = [](YR_MEMORY_BLOCK_ITERATOR* self) -> YR_MEMORY_BLOCK* {
        auto& cursor = *static_cast<BlockIterator*>(self->context);
        cursor.index = 0;
        return cursor.get();
    };
    iterator.next = [](YR_MEMORY_BLOCK_ITERATOR* self) -> YR_MEMORY_BLOCK* {
        auto& cursor = *static_cast<BlockIterator*>(self->context);
        ++cursor.index;
        return cursor.get();
    };
    RuleScan result;
    result.complete = yr_rules_scan_mem_blocks(rules_.get(), &iterator,
        SCAN_FLAGS_FAST_MODE | SCAN_FLAGS_REPORT_RULES_MATCHING | SCAN_FLAGS_PROCESS_MEMORY,
        collect_match, &result, timeout_seconds) == ERROR_SUCCESS;
    return result;
}

}
