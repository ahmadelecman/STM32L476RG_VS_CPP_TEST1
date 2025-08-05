#ifndef LOGGER_LOGGER_HPP_
#define LOGGER_LOGGER_HPP_

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <type_traits>

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((weak)) uint32_t HAL_GetTick(void);
#ifdef __cplusplus
}
#endif

#define LOGGER_MAX_PARAMETERS     6
#define LOGGER_BUFFER_SIZE        1024  // Must be power of 2 for optimal performance
#define LOGGER_BUFFER_MASK        (LOGGER_BUFFER_SIZE - 1)  // Bit mask for fast modulo
#define LOGGER_MAX_PUSH_RETRIES   100
#define LOGGER_MAX_DATA_SIZE      128    // Maximum data per single log entry

// Uncomment for development debugging of oversized entries
// #define LOGGER_DEBUG

namespace Logger {

class ILogOutput {
public:
    virtual void write(const uint8_t* data, size_t length) = 0;
    virtual ~ILogOutput() = default;
};

enum class LogLevel : uint8_t {
    Debug = 0,
    Info,
    Warn,
    Error,
    Fatal
};

struct ParamHeader {
    uint8_t index;
    uint8_t type;
    uint8_t size;
    uint8_t _padding;
} __attribute__((packed));

// Only used for in-memory buffer, not for serialization
struct LogEntry {
    uint16_t entry_length;
    uint16_t _padding;
    uint32_t timestamp;
    uint32_t string_hash;
    uint8_t level;
    uint8_t num_params;
    uint8_t reserved[2];
    ParamHeader params[LOGGER_MAX_PARAMETERS];
    uint8_t data[LOGGER_MAX_DATA_SIZE];
};

// For serialization and parsing
struct SerializedLogEntry {
    uint16_t entry_length;
    uint16_t _padding;
    uint32_t timestamp;
    uint32_t string_hash;
    uint8_t level;
    uint8_t num_params;
    uint8_t reserved[2];
} __attribute__((packed));

static constexpr size_t LOG_ENTRY_HEADER_BASE_SIZE = 16; // header without params
static constexpr size_t LOG_ENTRY_MAX_SIZE = LOG_ENTRY_HEADER_BASE_SIZE + sizeof(ParamHeader) * LOGGER_MAX_PARAMETERS + LOGGER_MAX_DATA_SIZE;

static_assert(LOG_ENTRY_MAX_SIZE <= LOGGER_BUFFER_SIZE,
              "LogEntry max size exceeds buffer size - reduce LOGGER_MAX_DATA_SIZE or increase LOGGER_BUFFER_SIZE");
static_assert(LOGGER_MAX_DATA_SIZE >= 32,
              "LOGGER_MAX_DATA_SIZE too small - should be at least 32 bytes for typical log entries");
static_assert(LOGGER_BUFFER_SIZE >= 256,
              "LOGGER_BUFFER_SIZE too small - should be at least 256 bytes for reasonable buffering");
static_assert((LOGGER_BUFFER_SIZE & (LOGGER_BUFFER_SIZE - 1)) == 0,
              "LOGGER_BUFFER_SIZE must be power of 2 for optimal performance");

class LogManager {
public:
    explicit LogManager(ILogOutput* output)
        : head_(0), tail_(0), logging_enabled_(true),
          dropped_entries_(0), total_entries_(0), output_(output) {}

    void enable(bool enabled) {
        logging_enabled_.store(enabled, std::memory_order_release);
    }

    uint32_t getDroppedCount() const {
        return dropped_entries_.load(std::memory_order_acquire);
    }

    uint32_t getTotalCount() const {
        return total_entries_.load(std::memory_order_acquire);
    }

    void resetStats() {
        dropped_entries_.store(0, std::memory_order_release);
        total_entries_.store(0, std::memory_order_release);
    }

    uint8_t getBufferUtilization() const {
        size_t current_head = head_.load(std::memory_order_acquire);
        size_t current_tail = tail_.load(std::memory_order_acquire);
        size_t used = current_head - current_tail;
        return static_cast<uint8_t>((used * 100) / LOGGER_BUFFER_SIZE);
    }

    void setOutput(ILogOutput* output) {
        output_ = output;
    }

    void flush() {
        process();
    }

    template <typename... Args>
    void log(LogLevel level, uint32_t string_hash, Args&&... args) {
        if (!logging_enabled_.load(std::memory_order_acquire)) return;
        total_entries_.fetch_add(1, std::memory_order_relaxed);

        constexpr size_t num_args = sizeof...(args);
        if constexpr (num_args > LOGGER_MAX_PARAMETERS) {
            dropped_entries_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        size_t headers_size = num_args * sizeof(ParamHeader);
        alignas(4) uint8_t temp_buffer[sizeof(ParamHeader) * LOGGER_MAX_PARAMETERS + 128];
        ParamHeader* headers = reinterpret_cast<ParamHeader*>(temp_buffer);
        uint8_t* data_start = temp_buffer + headers_size;
        uint8_t* data_ptr = data_start;
        size_t param_index = 0;

        if constexpr (num_args > 0) {
            packParams(headers, data_ptr, param_index, std::forward<Args>(args)...);
        }

        size_t data_size = static_cast<size_t>(data_ptr - data_start);
        size_t total_entry_size = LOG_ENTRY_HEADER_BASE_SIZE + headers_size + data_size;

        if (total_entry_size > LOG_ENTRY_MAX_SIZE || total_entry_size > LOGGER_BUFFER_SIZE) {
            dropped_entries_.fetch_add(1, std::memory_order_relaxed);
#ifdef LOGGER_DEBUG
            // Debug hook for oversized entries
#endif
            return;
        }

        for (int retry = 0; retry < LOGGER_MAX_PUSH_RETRIES; ++retry) {
            size_t current_head = head_.load(std::memory_order_acquire);
            size_t current_tail = tail_.load(std::memory_order_acquire);
            size_t used = current_head - current_tail;

            if ((used + total_entry_size) > LOGGER_BUFFER_SIZE) {
                dropped_entries_.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            size_t new_head = current_head + total_entry_size;

            if (head_.compare_exchange_weak(current_head, new_head, std::memory_order_acq_rel)) {
                writeEntry(current_head, level, string_hash, static_cast<uint16_t>(total_entry_size),
                           headers, data_start, param_index, data_size);
                return;
            }
        }

        dropped_entries_.fetch_add(1, std::memory_order_relaxed);
    }

    size_t serializeEntry(const uint8_t* entry_data, uint8_t* output_buffer, size_t max_size) {
        const SerializedLogEntry* entry = reinterpret_cast<const SerializedLogEntry*>(entry_data);

        if (sizeof(SerializedLogEntry) > max_size) return 0;

        // Copy header
        std::memcpy(output_buffer, entry_data, sizeof(SerializedLogEntry));
        size_t offset = sizeof(SerializedLogEntry);

        // Copy param headers
        uint8_t num_params = entry->num_params;
        if (offset + num_params * sizeof(ParamHeader) > max_size) return 0;
        std::memcpy(output_buffer + offset, entry_data + offset, num_params * sizeof(ParamHeader));
        offset += num_params * sizeof(ParamHeader);

        // Copy data
        size_t data_size = entry->entry_length - sizeof(SerializedLogEntry) - num_params * sizeof(ParamHeader);
        if (offset + data_size > max_size) return 0;
        std::memcpy(output_buffer + offset, entry_data + offset, data_size);
        offset += data_size;

        return offset;
    }

    void process() {
        alignas(32) uint8_t dma_buffer[512];

        while (true) {
            size_t current_tail = tail_.load(std::memory_order_acquire);
            size_t current_head = head_.load(std::memory_order_acquire);

            if (current_tail >= current_head) break;

            size_t read_pos = current_tail & LOGGER_BUFFER_MASK;
            uint16_t entry_length;

            if (read_pos + sizeof(uint16_t) <= LOGGER_BUFFER_SIZE) {
                std::memcpy(&entry_length, &buffer_[read_pos], sizeof(uint16_t));
            } else {
                size_t first_part = LOGGER_BUFFER_SIZE - read_pos;
                std::memcpy(&entry_length, &buffer_[read_pos], first_part);
                std::memcpy(reinterpret_cast<uint8_t*>(&entry_length) + first_part,
                            &buffer_[0], sizeof(uint16_t) - first_part);
            }

            if (entry_length == 0 || entry_length > LOGGER_BUFFER_SIZE) {
                tail_.store(current_head, std::memory_order_release);
                break;
            }

            alignas(4) uint8_t entry_buffer[LOG_ENTRY_MAX_SIZE];
            readFromCircularBuffer(current_tail, entry_buffer, entry_length);

            size_t serialized_size = serializeEntry(entry_buffer, dma_buffer, sizeof(dma_buffer));
            if (output_ && serialized_size > 0) {
                output_->write(dma_buffer, serialized_size);
            }

            size_t expected_tail = current_tail;
            if (!tail_.compare_exchange_weak(expected_tail, current_tail + entry_length,
                                             std::memory_order_acq_rel)) {
                continue;
            }
        }
    }

private:
    void writeEntry(size_t write_pos, LogLevel level, uint32_t string_hash,
                    uint16_t entry_length, ParamHeader* headers, uint8_t* data_start,
                    size_t num_params, size_t data_size) {
        // Use a temporary buffer to assemble the entry
        alignas(4) uint8_t entry_buffer[LOG_ENTRY_MAX_SIZE];
        size_t offset = 0;

        // Write header
        SerializedLogEntry header;
        header.entry_length = entry_length;
        header._padding = 0;
        header.timestamp = getTimestamp();
        header.string_hash = string_hash;
        header.level = static_cast<uint8_t>(level);
        header.num_params = static_cast<uint8_t>(num_params);
        header.reserved[0] = 0;
        header.reserved[1] = 0;

        std::memcpy(entry_buffer + offset, &header, sizeof(header));
        offset += sizeof(header);

        // Write only used ParamHeaders
        if (num_params > 0) {
            std::memcpy(entry_buffer + offset, headers, num_params * sizeof(ParamHeader));
            offset += num_params * sizeof(ParamHeader);
        }

        // Write only used data
        if (data_size > 0) {
            std::memcpy(entry_buffer + offset, data_start, data_size);
            offset += data_size;
        }

        // Write to circular buffer
        writeToCircularBuffer(write_pos, entry_buffer, entry_length);
    }

    void writeToCircularBuffer(size_t pos, const uint8_t* data, size_t length) {
        size_t write_pos = pos & LOGGER_BUFFER_MASK;

        if (write_pos + length <= LOGGER_BUFFER_SIZE) {
            std::memcpy(&buffer_[write_pos], data, length);
        } else {
            size_t first_part = LOGGER_BUFFER_SIZE - write_pos;
            std::memcpy(&buffer_[write_pos], data, first_part);
            std::memcpy(&buffer_[0], data + first_part, length - first_part);
        }
    }

    void readFromCircularBuffer(size_t pos, uint8_t* data, size_t length) {
        size_t read_pos = pos & LOGGER_BUFFER_MASK;

        if (read_pos + length <= LOGGER_BUFFER_SIZE) {
            std::memcpy(data, &buffer_[read_pos], length);
        } else {
            size_t first_part = LOGGER_BUFFER_SIZE - read_pos;
            std::memcpy(data, &buffer_[read_pos], first_part);
            std::memcpy(data + first_part, &buffer_[0], length - first_part);
        }
    }

    template <typename T, typename... Rest>
    void packParams(ParamHeader* headers, uint8_t*& data_ptr, size_t& index, T&& arg, Rest&&... rest) {
        static_assert(std::is_trivially_copyable_v<std::decay_t<T>>,
                      "Only trivially copyable types are supported");

        using U = std::decay_t<T>;

        headers[index].index = static_cast<uint8_t>(index);
        headers[index].type = typeToCode<U>();
        headers[index].size = sizeof(U);
        headers[index]._padding = 0;

        std::memcpy(data_ptr, &arg, sizeof(U));
        data_ptr += sizeof(U);
        ++index;

        if constexpr (sizeof...(rest) > 0) {
            packParams(headers, data_ptr, index, std::forward<Rest>(rest)...);
        }
    }

    template <typename T>
    constexpr uint8_t typeToCode() const {
        using U = std::decay_t<T>;
        if constexpr (std::is_same_v<U, int32_t>) return 1;
        else if constexpr (std::is_same_v<U, uint32_t>) return 2;
        else if constexpr (std::is_same_v<U, float>) return 3;
        else if constexpr (std::is_same_v<U, int16_t>) return 4;
        else if constexpr (std::is_same_v<U, uint16_t>) return 5;
        else if constexpr (std::is_same_v<U, int8_t>) return 6;
        else if constexpr (std::is_same_v<U, uint8_t>) return 7;
        else static_assert(sizeof(U) == 0, "Unsupported type.");
    }

    inline uint32_t getTimestamp() const {
        return HAL_GetTick ? HAL_GetTick() : 0;
    }

    alignas(32) uint8_t buffer_[LOGGER_BUFFER_SIZE];
    std::atomic<size_t> head_;
    std::atomic<size_t> tail_;
    std::atomic<bool> logging_enabled_;
    std::atomic<uint32_t> dropped_entries_;
    std::atomic<uint32_t> total_entries_;
    ILogOutput* output_;
};

} // namespace Logger

// Hash function for string literals
constexpr uint32_t hash_string(const char* str, size_t len, uint32_t hash = 2166136261u) {
    return len == 0 ? hash : hash_string(str + 1, len - 1, (hash ^ static_cast<uint32_t>(*str)) * 16777619u);
}

#define CONST_STRLEN(s) (sizeof(s) - 1)

// Global logger instance - declared before macros!
inline Logger::LogManager g_logger(nullptr);

// Logger macros - defined after g_logger is declared
#define LOG_PROCESS() g_logger.process()
#define LOG_FLUSH() g_logger.flush()
#define LOG_INIT(output) g_logger.setOutput(output)

// Statistics macros for easy monitoring
#define LOG_GET_DROPPED_COUNT() g_logger.getDroppedCount()
#define LOG_GET_TOTAL_COUNT() g_logger.getTotalCount()
#define LOG_GET_BUFFER_USAGE() g_logger.getBufferUtilization()
#define LOG_RESET_STATS() g_logger.resetStats()

#define LOG_STATS_IF_NEEDED() do { \
    static uint32_t last_check = 0; \
    extern "C" __attribute__((weak)) uint32_t HAL_GetTick(void); \
    uint32_t now = HAL_GetTick ? HAL_GetTick() : 0; \
    if (now > last_check && (now - last_check) > 10000) { \
        last_check = now; \
        uint32_t dropped = LOG_GET_DROPPED_COUNT(); \
        uint32_t total = LOG_GET_TOTAL_COUNT(); \
        uint8_t usage = LOG_GET_BUFFER_USAGE(); \
        if (dropped > 0) { \
            LOG_WARN("Logger stats - Dropped: %lu/%lu, Buffer: %u%%", \
                     dropped, total, usage); \
        } \
    } \
} while(0)

// Logging macros
#define LOG_DEBUG(format, ...) \
    g_logger.log(Logger::LogLevel::Debug, hash_string(format, CONST_STRLEN(format)), ##__VA_ARGS__)
#define LOG_INFO(format, ...) \
    g_logger.log(Logger::LogLevel::Info, hash_string(format, CONST_STRLEN(format)), ##__VA_ARGS__)
#define LOG_WARN(format, ...) \
    g_logger.log(Logger::LogLevel::Warn, hash_string(format, CONST_STRLEN(format)), ##__VA_ARGS__)
#define LOG_ERROR(format, ...) \
    g_logger.log(Logger::LogLevel::Error, hash_string(format, CONST_STRLEN(format)), ##__VA_ARGS__)
#define LOG_FATAL(format, ...) \
    g_logger.log(Logger::LogLevel::Fatal, hash_string(format, CONST_STRLEN(format)), ##__VA_ARGS__)

#endif /* LOGGER_LOGGER_HPP_ */