/*
 * Logger_UART_Interface.hpp
 *
 *  Created on: Aug 3, 2025
 *      Author: ahsho
 */

#ifndef LOGGER_UART_INTERFACE_LOGGER_UART_INTERFACE_HPP_
#define LOGGER_UART_INTERFACE_LOGGER_UART_INTERFACE_HPP_

#include "Logger.hpp"
#include "stm32l4xx_hal.h"  

class Logger_UART_Interface : public Logger::ILogOutput {
public:
    explicit Logger_UART_Interface(UART_HandleTypeDef* huart);

    void write(const uint8_t* data, size_t length) override;

private:
    UART_HandleTypeDef* m_uart;
    static constexpr size_t kMaxChunkSize = 128;
};


#endif /* LOGGER_UART_INTERFACE_LOGGER_UART_INTERFACE_HPP_ */

