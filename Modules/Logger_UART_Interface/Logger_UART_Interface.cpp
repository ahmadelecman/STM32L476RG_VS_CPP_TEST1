#include "Logger_UART_Interface.hpp"

Logger_UART_Interface::Logger_UART_Interface(UART_HandleTypeDef* huart)
    : m_uart(huart) {}

void Logger_UART_Interface::write(const uint8_t* data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        size_t chunk = (length - offset) > kMaxChunkSize ? kMaxChunkSize : (length - offset);

        // Wait for previous DMA transfer to complete
        while (HAL_UART_GetState(m_uart) != HAL_UART_STATE_READY) {}

        // Note: HAL expects non-const buffer
        HAL_UART_Transmit_DMA(m_uart, const_cast<uint8_t*>(&data[offset]), chunk);

        // Wait again to ensure DMA is ready before next chunk
        while (HAL_UART_GetState(m_uart) != HAL_UART_STATE_READY) {}

        offset += chunk;
    }
}
