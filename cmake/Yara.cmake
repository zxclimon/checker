FetchContent_Declare(yara
    URL https://codeload.github.com/VirusTotal/yara/tar.gz/refs/tags/v4.5.8
    URL_HASH SHA256=c322414975ff6f701149856613afdcd92a7e6939c284c798ae3c85618197efaa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(yara)

set(yara_core
    ahocorasick arena atoms base64 bitmask compiler endian exec exefiles filemap
    grammar hash hex_grammar hex_lexer lexer libyara mem modules notebook object
    parser proc re re_grammar re_lexer rules scan scanner simple_str sizedstr stack
    stopwatch stream strutils threading)
set(yara_sources)
foreach(source IN LISTS yara_core)
    list(APPEND yara_sources "${yara_SOURCE_DIR}/libyara/${source}.c")
endforeach()
foreach(source IN ITEMS
    proc/none modules/tests/tests modules/pe/pe modules/pe/pe_utils
    modules/elf/elf modules/math/math modules/time/time modules/console/console
    modules/string/string tlshc/tlsh tlshc/tlsh_impl tlshc/tlsh_util)
    list(APPEND yara_sources "${yara_SOURCE_DIR}/libyara/${source}.c")
endforeach()
add_library(yara STATIC ${yara_sources})
target_include_directories(yara SYSTEM PUBLIC "${yara_SOURCE_DIR}/libyara/include")
target_include_directories(yara PRIVATE "${yara_SOURCE_DIR}/libyara")
target_compile_definitions(yara PRIVATE USE_NO_PROC _CRT_SECURE_NO_WARNINGS BUCKETS_128 CHECKSUM_1B)
target_compile_definitions(yara PUBLIC YR_BUILDING_STATIC_LIB)
target_link_libraries(yara PRIVATE advapi32 bcrypt)
