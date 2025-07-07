#include "MacPingDetector.h"
#include <iostream>
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

MacPingDetector::MacPingDetector(const std::string& ip_address)
    : target_ip_(ip_address), raw_socket_(-1), icmp_socket_(-1) {}

MacPingDetector::~MacPingDetector() {
    if (raw_socket_ != -1) close(raw_socket_);
    if (icmp_socket_ != -1) close(icmp_socket_);
}

unsigned short MacPingDetector::calculateChecksum(void* data, int length) {
    unsigned short* buffer = (unsigned short*)data;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; length > 1; length -= 2) {
        sum += *buffer++;
    }

    if (length == 1) {
        sum += *(unsigned char*)buffer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void MacPingDetector::setupRawSocket() {
    raw_socket_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket_ < 0) {
        throw std::runtime_error("Ошибка создания raw socket");
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(raw_socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

void MacPingDetector::setupIcmpSocket() {
    icmp_socket_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_socket_ < 0) {
        throw std::runtime_error("Ошибка создания ICMP socket");
    }
}

void MacPingDetector::sendIcmpRequest() {
    struct icmp packet;
    memset(&packet, 0, sizeof(packet));
    packet.icmp_type = ICMP_ECHO;
    packet.icmp_code = 0;
    packet.icmp_id = getpid() & 0xFFFF;
    packet.icmp_seq = 1;
    packet.icmp_cksum = calculateChecksum(&packet, sizeof(packet));

    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip_.c_str(), &destination.sin_addr) <= 0) {
        throw std::runtime_error("Неверный IP адрес");
    }

    if (sendto(icmp_socket_, &packet, sizeof(packet), 0,
               (struct sockaddr*)&destination, sizeof(destination)) <= 0) {
        throw std::runtime_error("Ошибка отправки ICMP запроса");
    }
}

std::string MacPingDetector::receiveAndParseResponse() {
    char buffer[ETH_FRAME_LEN];
    struct ethhdr* ethernet_header;
    struct iphdr* ip_header;
    struct icmphdr* icmp_header;

    while (true) {
        ssize_t packet_size = recvfrom(raw_socket_, buffer, sizeof(buffer), 0, NULL, NULL);
        if (packet_size <= 0) {
            throw std::runtime_error("Таймаут или ошибка приема пакета");
        }

        ethernet_header = (struct ethhdr*)buffer;
        if (ntohs(ethernet_header->h_proto) != ETH_P_IP) {
            continue;
        }

        ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        if (ip_header->protocol != IPPROTO_ICMP) {
            continue;
        }

        icmp_header = (struct icmphdr*)(buffer + sizeof(struct ethhdr) + (ip_header->ihl * 4));

        if (icmp_header->type == ICMP_ECHOREPLY &&
                icmp_header->un.echo.id == (getpid() & 0xFFFF)) {
            char mac_string[18];
            snprintf(mac_string, sizeof(mac_string), "%02x:%02x:%02x:%02x:%02x:%02x",
                     ethernet_header->h_source[0], ethernet_header->h_source[1],
                    ethernet_header->h_source[2], ethernet_header->h_source[3],
                    ethernet_header->h_source[4], ethernet_header->h_source[5]);

            return std::string(mac_string);
        }
    }
}

std::string MacPingDetector::getMacAddress() {
    try {
        setupRawSocket();
        setupIcmpSocket();
        sendIcmpRequest();
        return receiveAndParseResponse();
    } catch (const std::exception& e) {
        if (raw_socket_ != -1) close(raw_socket_);
        if (icmp_socket_ != -1) close(icmp_socket_);
        throw;
    }
}
