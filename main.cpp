#include <iostream>
#include <string>
#include <stdexcept>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <sys/time.h>

// Функция для вычисления контрольной суммы ICMP пакета
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Функция для получения MAC адреса отправителя ping ответа
std::string get_mac_from_ping_response(const std::string& ip_address) {
    // Создаем raw socket для получения Ethernet фреймов
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        throw std::runtime_error("Failed to create raw socket");
    }

    // Создаем обычный socket для отправки ICMP запроса
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        close(sockfd);
        throw std::runtime_error("Failed to create ICMP socket");
    }

    // Устанавливаем таймаут на получение ответа
    struct timeval tv;
    tv.tv_sec = 2;  // 2 секунды таймаут
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Подготавливаем ICMP Echo Request
    struct icmp icmp_packet;
    memset(&icmp_packet, 0, sizeof(icmp_packet));
    icmp_packet.icmp_type = ICMP_ECHO;
    icmp_packet.icmp_code = 0;
    icmp_packet.icmp_id = getpid() & 0xFFFF;
    icmp_packet.icmp_seq = 1;
    icmp_packet.icmp_cksum = checksum(&icmp_packet, sizeof(icmp_packet));

    // Адрес назначения
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_address.c_str(), &dest_addr.sin_addr) <= 0) {
        close(sockfd);
        close(icmp_sock);
        throw std::runtime_error("Invalid IP address");
    }

    // Отправляем ICMP запрос
    if (sendto(icmp_sock, &icmp_packet, sizeof(icmp_packet), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        close(sockfd);
        close(icmp_sock);
        throw std::runtime_error("Failed to send ICMP request");
    }

    // Буфер для приема Ethernet фрейма
    char buffer[ETH_FRAME_LEN];
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;

    // Получаем ответ
    while (true) {
        ssize_t packet_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (packet_size <= 0) {
            close(sockfd);
            close(icmp_sock);
            throw std::runtime_error("Timeout or error receiving packet");
        }

        // Анализируем заголовки
        eth_header = (struct ethhdr *)buffer;
        ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        // Проверяем, что это IP пакет
        if (ntohs(eth_header->h_proto) != ETH_P_IP) {
            continue;
        }

        // Проверяем, что это ICMP пакет
        if (ip_header->protocol != IPPROTO_ICMP) {
            continue;
        }

        icmp_header = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + (ip_header->ihl * 4));

        // Проверяем, что это ответ на наш запрос
        if (icmp_header->type == ICMP_ECHOREPLY &&
            icmp_header->un.echo.id == (getpid() & 0xFFFF)) {
            // Форматируем MAC адрес
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     eth_header->h_source[0], eth_header->h_source[1],
                     eth_header->h_source[2], eth_header->h_source[3],
                     eth_header->h_source[4], eth_header->h_source[5]);

            close(sockfd);
            close(icmp_sock);
            return std::string(mac_str);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <IPv4 address>" << std::endl;
        return 1;
    }

    try {
        std::string ip_address(argv[1]);
        std::string mac_address = get_mac_from_ping_response(ip_address);
        std::cout << "MAC address: " << mac_address << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
