#ifndef MACPINGDETECTOR_H
#define MACPINGDETECTOR_H

#include <string>
#include <stdexcept>

class MacPingDetector {
private:
    int raw_socket_;       // Raw socket для получения Ethernet фреймов
    int icmp_socket_;      // Socket для отправки ICMP запросов
    std::string target_ip_;// Целевой IP адрес

    // Вычисление контрольной суммы ICMP пакета
    unsigned short calculateChecksum(void* data, int length);

    // Создание и настройка raw socket
    void setupRawSocket();

    // Создание и настройка ICMP socket
    void setupIcmpSocket();

    // Формирование и отправка ICMP Echo Request
    void sendIcmpRequest();

    // Получение и анализ ответа, извлечение MAC адреса
    std::string receiveAndParseResponse();

public:

    MacPingDetector(const std::string& ip_address);
    ~MacPingDetector();

    // Основной метод для получения MAC адреса
    std::string getMacAddress();
};

#endif // MACPINGDETECTOR_H
