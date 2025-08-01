/*
 * Logger.hpp
 *
 *  Created on: Aug 1, 2025
 *      Author: ahmad.shokati
 */

#ifndef LOGGER_LOGGER_HPP_
#define LOGGER_LOGGER_HPP_

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <atomic>
#include <type_traits>
#include <string_view>
#include <array>

// =======================
// ==== CONFIGURATION ====
// =======================

// The main buffer size. Must be a power of 2 for efficiency.
#ifndef LOG_BUFFER_SIZE
#define LOG_BUFFER_SIZE 1024
#endif

// The maximum supported length for a logged string literal.
#ifndef LOG_MAX_STRING_LENGTH
#define LOG_MAX_STRING_LENGTH 127
#endif

// The maximum size of a single log entry (header + all arguments).
#ifndef LOG_MAX_ENTRY_SIZE
#define LOG_MAX_ENTRY_SIZE 64
#endif

// The compile-time log level. Messages below this level are compiled out.
#ifndef LOG_COMPILE_TIME_LEVEL
#define LOG_COMPILE_TIME_LEVEL logger::LogLevel::Debug
#endif

// Static checks for configuration
static_assert((LOG_BUFFER_SIZE & (LOG_BUFFER_SIZE - 1)) == 0, "LOG_BUFFER_SIZE must be a power of 2");
static_assert(LOG_MAX_ENTRY_SIZE < 256, "LOG_MAX_ENTRY_SIZE must be less than 256");

// ===============================
// ==== Compile-time FNV-1a Hash ====
// ===============================

// Efficient single-pass constexpr FNV-1a hash for C-strings.
constexpr uint32_t fnv1a(const char* str, uint32_t hash = 0x811c9dc5) noexcept {
    return (*str) ? fnv1a(str + 1, (hash ^ static_cast<uint8_t>(*str)) * 0x01000193) : hash;
}

constexpr uint32_t fnv1a(std::string_view sv) noexcept {
    uint32_t hash = 0x811c9dc5;
    for (char c : sv) {
        hash = (hash ^ static_cast<uint8_t>(c)) * 0x01000193;
    }
    return hash;
}

// =================
// ==== Logger ====
// =================

namespace logger {

// LogLevel enum for compile-time filtering.
enum class LogLevel : uint8_t {
    None,
    Error,
    Warning,
    Info,
    Debug
};

enum class LogResult : uint8_t {
    Success,
    BufferFull,
    NoCallback,
    StringTooLong,
    EntryTooLarge,
    WouldBlock
};

// A thread-safe (for single-core ISRs) ring buffer implementation.
class RingBuffer {
private:
    std::atomic<uint32_t> write_index_{0};
    std::atomic<uint32_t> read_index_{0};
    std::array<uint8_t, LOG_BUFFER_SIZE> buffer_{};

    static constexpr uint32_t MASK = LOG_BUFFER_SIZE - 1;

public:
    // Public access to read index for advanced manipulation (like dropping messages).
    std::atomic<uint32_t>& get_read_index() { return read_index_; }

    uint32_t available_space() const noexcept {
        uint32_t write_idx = write_index_.load(std::memory_order_relaxed);
        uint32_t read_idx = read_index_.load(std::memory_order_acquire);
        return LOG_BUFFER_SIZE - 1 - ((write_idx - read_idx) & MASK);
    }

    uint32_t available_data() const noexcept {
        uint32_t write_idx = write_index_.load(std::memory_order_acquire);
        uint32_t read_idx = read_index_.load(std::memory_order_relaxed);
        return (write_idx - read_idx) & MASK;
    }

    bool write(const void* data, uint32_t size) noexcept {
        if (size == 0) [[likely]] return true;

        // Cache the indices to avoid multiple atomic loads
        uint32_t write_idx = write_index_.load(std::memory_order_relaxed);
        uint32_t read_idx = read_index_.load(std::memory_order_acquire);
        uint32_t available = LOG_BUFFER_SIZE - 1 - ((write_idx - read_idx) & MASK);

        if (size > available) [[unlikely]] return false;

        const uint8_t* src = static_cast<const uint8_t*>(data);

        uint32_t first_part_size = LOG_BUFFER_SIZE - write_idx;
        if (size <= first_part_size) {
            std::memcpy(&buffer_[write_idx], src, size);
        } else {
            std::memcpy(&buffer_[write_idx], src, first_part_size);
            std::memcpy(&buffer_[0], src + first_part_size, size - first_part_size);
        }

        write_index_.store((write_idx + size) & MASK, std::memory_order_release);
        return true;
    }

    uint32_t read(void* data, uint32_t max_size) noexcept {
        uint32_t available = available_data();
        if (available == 0) return 0;

        uint32_t to_read = (max_size < available) ? max_size : available;
        uint32_t read_idx = read_index_.load(std::memory_order_relaxed);
        uint8_t* dst = static_cast<uint8_t*>(data);

        uint32_t first_part_size = LOG_BUFFER_SIZE - read_idx;
        if (to_read <= first_part_size) {
            std::memcpy(dst, &buffer_[read_idx], to_read);
        } else {
            std::memcpy(dst, &buffer_[read_idx], first_part_size);
            std::memcpy(dst + first_part_size, &buffer_[0], to_read - first_part_size);
        }

        read_index_.store((read_idx + to_read) & MASK, std::memory_order_release);
        return to_read;
    }

    // Peek allows reading without advancing the read pointer. Needed for safe dropping.
    uint32_t peek(void* data, uint32_t size, uint32_t offset = 0) const noexcept {
        uint32_t available = available_data();
        if (size + offset > available) return 0;

        uint32_t read_idx = (read_index_.load(std::memory_order_relaxed) + offset) & MASK;
        const uint8_t* src = &buffer_[read_idx];
        uint8_t* dst = static_cast<uint8_t*>(data);

        uint32_t first_part_size = LOG_BUFFER_SIZE - read_idx;
        if (size <= first_part_size) {
            std::memcpy(dst, src, size);
        } else {
            std::memcpy(dst, src, first_part_size);
            std::memcpy(dst + first_part_size, &buffer_[0], size - first_part_size);
        }
        return size;
    }

    void reset() noexcept {
        read_index_.store(0, std::memory_order_relaxed);
        write_index_.store(0, std::memory_order_relaxed);
    }

    bool is_nearly_full(uint32_t threshold_percent = 75) const noexcept {
        return available_space() < (LOG_BUFFER_SIZE * (100 - threshold_percent)) / 100;
    }
};

// Global instances
inline RingBuffer ring_buffer;
using FlushCallback = void(*)(const uint8_t* data, size_t size);
inline FlushCallback flush_callback = nullptr;

inline void set_flush_callback(FlushCallback cb) noexcept {
    flush_callback = cb;
}

// --- Serialization ---
namespace internal {
    template <typename T>
    inline bool serialize_to_buffer(uint8_t* buffer, uint32_t& offset, const T& val) noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
        if (offset + sizeof(T) > LOG_MAX_ENTRY_SIZE) [[unlikely]] return false;
        std::memcpy(buffer + offset, &val, sizeof(T));
        offset += sizeof(T);
        return true;
    }

    inline bool serialize_to_buffer(uint8_t* buffer, uint32_t& offset, const char* str) noexcept {
        if (!str) [[unlikely]] {
            return serialize_to_buffer(buffer, offset, uint8_t{0});
        }

        // Fast path for short strings (avoid strlen)
        const char* end = str;
        uint8_t len = 0;
        while (*end && len < LOG_MAX_STRING_LENGTH) {
            ++end;
            ++len;
        }

        if (len > LOG_MAX_STRING_LENGTH) [[unlikely]] return false;
        if (offset + sizeof(len) + len > LOG_MAX_ENTRY_SIZE) [[unlikely]] return false;

        serialize_to_buffer(buffer, offset, len);
        std::memcpy(buffer + offset, str, len);
        offset += len;
        return true;
    }

    inline bool serialize_to_buffer(uint8_t* buffer, uint32_t& offset, std::string_view sv) noexcept {
        if (sv.size() > LOG_MAX_STRING_LENGTH) [[unlikely]] return false;
        uint8_t len_u8 = static_cast<uint8_t>(sv.size());
        if (offset + sizeof(len_u8) + sv.size() > LOG_MAX_ENTRY_SIZE) [[unlikely]] return false;

        serialize_to_buffer(buffer, offset, len_u8);
        std::memcpy(buffer + offset, sv.data(), sv.size());
        offset += sv.size();
        return true;
    }

    // Using C++17 fold expression for more concise variadic serialization.
    template<typename... Ts>
    inline bool serialize_all_to_buffer(uint8_t* buffer, uint32_t& offset, const Ts&... args) noexcept {
        return (serialize_to_buffer(buffer, offset, args) && ...);
    }

    // Internal implementation of emit. Serializes to a self-contained packet.
    template<uint32_t MsgId, typename... Args>
    inline LogResult emit_internal(Args&&... args) noexcept {
        uint8_t temp_buffer[LOG_MAX_ENTRY_SIZE];
        uint32_t offset = 0;

        // Reserve space for total length, to be written later.
        offset += sizeof(uint8_t);

        // Serialize message ID and all arguments.
        if (!serialize_all_to_buffer(temp_buffer, offset, MsgId, std::forward<Args>(args)...)) {
            return LogResult::EntryTooLarge;
        }

        // Go back and write the total length at the beginning of the buffer.
        uint8_t total_length = static_cast<uint8_t>(offset);
        std::memcpy(temp_buffer, &total_length, sizeof(total_length));

        // Write the complete, self-contained packet to the ring buffer.
        if (ring_buffer.write(temp_buffer, total_length)) {
            return LogResult::Success;
        } else {
            return LogResult::BufferFull;
        }
    }
} // namespace internal

// --- Public API ---

// Main entry point for macros, performs compile-time level checking.
template<logger::LogLevel Level, uint32_t MsgId, typename... Args>
inline LogResult emit_level(Args&&... args) noexcept {
    if constexpr (Level <= LOG_COMPILE_TIME_LEVEL && Level != logger::LogLevel::None) {
        return internal::emit_internal<MsgId>(std::forward<Args>(args)...);
    } else {
        return LogResult::Success; // Do nothing, message is compiled out.
    }
}

inline LogResult flush() noexcept {
    if (!flush_callback) return LogResult::NoCallback;

    uint8_t temp_buffer[128]; // Read in chunks
    uint32_t bytes_read;

    while ((bytes_read = ring_buffer.read(temp_buffer, sizeof(temp_buffer))) > 0) {
        flush_callback(temp_buffer, bytes_read);
    }

    return LogResult::Success;
}

// Drops the oldest message by reading its length prefix. Much safer.
inline bool drop_oldest_message() noexcept {
    uint8_t length_prefix = 0;
    if (ring_buffer.peek(&length_prefix, sizeof(length_prefix)) == sizeof(length_prefix)) [[likely]] {
        if (length_prefix > 0 && length_prefix <= LOG_MAX_ENTRY_SIZE) [[likely]] {
            // Atomically advance the read pointer by the message length.
            uint32_t current_read = ring_buffer.get_read_index().load(std::memory_order_relaxed);
            uint32_t next_read = (current_read + length_prefix) & (LOG_BUFFER_SIZE - 1);
            ring_buffer.get_read_index().store(next_read, std::memory_order_release);
            return true;
        }
    }
    return false; // Buffer was empty or contained invalid data
}

inline uint32_t get_buffer_usage() noexcept {
    return ring_buffer.available_data();
}

inline uint32_t get_buffer_free_space() noexcept {
    return ring_buffer.available_space();
}

inline bool is_buffer_nearly_full(uint32_t threshold_percent = 75) noexcept {
    return ring_buffer.is_nearly_full(threshold_percent);
}

inline void reset() noexcept {
    ring_buffer.reset();
}

inline LogResult try_auto_flush(uint32_t threshold_percent = 75) noexcept {
    if (is_buffer_nearly_full(threshold_percent)) {
        return flush();
    }
    return LogResult::Success;
}

} // namespace logger

// ==================================
// ==== User Log Macros ====
// ==================================

#define LOG_ERROR(msg, ...)   logger::emit_level<logger::LogLevel::Error,   fnv1a(msg)>(__VA_ARGS__)
#define LOG_WARN(msg, ...)    logger::emit_level<logger::LogLevel::Warning, fnv1a(msg)>(__VA_ARGS__)
#define LOG_INFO(msg, ...)    logger::emit_level<logger::LogLevel::Info,    fnv1a(msg)>(__VA_ARGS__)
#define LOG_DEBUG(msg, ...)   logger::emit_level<logger::LogLevel::Debug,   fnv1a(msg)>(__VA_ARGS__)

// Composite policy macros
#define LOG_ERROR_EMERGENCY(msg, ...) \
    do { \
        if (LOG_ERROR(msg, __VA_ARGS__) == logger::LogResult::BufferFull) { \
            logger::drop_oldest_message(); \
            LOG_ERROR(msg, __VA_ARGS__); \
        } \
    } while(0)

#define LOG_SAFE(level, msg, ...) \
    do { \
        auto result = LOG_##level(msg, __VA_ARGS__); \
        if (result == logger::LogResult::BufferFull) { \
            logger::try_auto_flush(); \
        } \
    } while(0)

#define LOG_NONBLOCK(level, msg, ...) \
    do { \
        if (!logger::is_buffer_nearly_full(90)) { \
            LOG_##level(msg, __VA_ARGS__); \
        } \
    } while(0)



#endif /* LOGGER_LOGGER_HPP_ */

