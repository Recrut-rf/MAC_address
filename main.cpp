#include "MacPingDetector.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Использование: " << argv[0] << " <IPv4 адрес>" << std::endl;
        return 1;
    }

    try {
        MacPingDetector detector(argv[1]);
        std::string mac_address = detector.getMacAddress();
        std::cout << "MAC адрес: " << mac_address << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
