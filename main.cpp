#include <iostream>
#include <sstream>
#include <string>

#include <boost/regex.hpp>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/TcpLayer.h>

#include <args.hxx>

#include "progressbar.hpp"

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

std::string extract_payload(std::string const &payload, std::string const &parameter) {
    boost::regex const pattern(parameter + "=([^&]+)");
    boost::smatch      match;
    if (regex_search(payload, match, pattern)) {
        if (match.size() > 1) {
            return match[1].str();
        }
    }
    return std::string{};
}

std::vector<std::string> extract_multiple_payloads(std::string const &payload, std::string const &parameters) {
    std::vector<std::string> para_contents;
    std::stringstream        ss(parameters);
    std::string              parameter;
    while (std::getline(ss, parameter, ',')) {
        std::string extracted_payload = extract_payload(payload, parameter);
        para_contents.push_back(extracted_payload);
    }
    return para_contents;
}

int main(int argc, char *argv[]) {
    args::ArgumentParser          parser("pcap2para - extract parameter of HTTP from PCAP/PCAPNG traffic files", R"(Example: pcap2rsa.exe -p rsa -o test.txt "D:\Code\PayloadExtract\9.14.pcapng")");
    args::HelpFlag                help(parser, "help", "Display this help menu", {'h', "help"});
    args::CompletionFlag          completion(parser, {"complete"});
    args::ValueFlag<std::string>  extpara(parser, "parameter", "The HTTP parameter to extract", {'p', "parameter"});
    args::Positional<std::string> input_file(parser, "input", "The input pcap(ng) file");
    args::ValueFlag<std::string>  output_file(parser, "output", "The name of output file", {'o', "output"}, "out.txt");
    args::Flag                    debug_mode(parser, "debug", "Display debug information and a progress bar", {'d', "debug"}, args::Options{});

    try {
        parser.ParseCLI(argc, argv);
    } catch (args::Completion const &e) {
        std::cout << e.what();
        return 0;
    } catch (args::Help const &) {
        std::cout << parser;
        return 0;
    } catch (args::ParseError const &e) {
        std::cerr << e.what() << '\n';
        std::cerr << parser;
        return 1;
    }

    bool debug = get(debug_mode);
    if (debug) {
        if (extpara) {
            std::cout << "parameter: " << args::get(extpara) << '\n';
        }
        if (input_file) {
            std::cout << "input_file: " << args::get(input_file) << '\n';
        }
        if (output_file) {
            std::cout << "output_file: " << args::get(output_file) << '\n';
        }
    }

    std::ofstream     fout(args::get(output_file));
    std::string const pcap_path = (args::get(input_file));
    std::string       para(args::get(extpara));

    // TODO: Get total packet count
    pcpp::RawPacket          tmp_packet;
    pcpp::IFileReaderDevice *size_reader = pcpp::IFileReaderDevice::getReader(pcap_path);
    int                      packetCount = 0;

    if (size_reader == nullptr) {
        std::cerr << "Cannot determine reader for file type" << '\n';
        return 1;
    }

    if (!size_reader->open()) {
        std::cerr << "Cannot open " + pcap_path + " for reading" << '\n';
        return 1;
    }

    while (size_reader->getNextPacket(tmp_packet)) {
        packetCount++;
    }
    size_reader->close();
    std::cout << "Total packets: " << packetCount << '\n';

    pcpp::RawPacket          raw_packet;
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(pcap_path);
    reader->open();

    int         idx = 0;
    progressbar pb(100);
    pb.show_bar(debug);
    while (reader->getNextPacket(raw_packet)) {
        if (debug) {
            idx++;
            if (idx % (packetCount / 100) == 0) {
                pb.update();
            }
        }

        pcpp::Packet parsed_packet(&raw_packet);
        if (pcpp::TcpLayer const *tcp_layer = parsed_packet.getLayerOfType<pcpp::TcpLayer>()) {
            uint8_t const *data_ptr = tcp_layer->getData();
            size_t const   size     = tcp_layer->getDataLen();
            std::string    payload(reinterpret_cast<std::string::const_pointer>(data_ptr), size);
            if (para.find(',') != std::string::npos) {
                // multiple parameters
                std::vector<std::string> rsa_list = extract_multiple_payloads(payload, para);
                if (rsa_list.at(0).length() > 16) { // rsa_list.at(0) is always rsa
                    for (size_t i = 0; i < rsa_list.size(); ++i) {
                        fout << rsa_list[i];
                        if (i != rsa_list.size() - 1) {
                            fout << ",";
                        }
                    }
                    fout << '\n';
                }
            } else {
                // single parameter
                std::string rsa = extract_payload(payload, para);
                if (rsa.length() > 16) {
                    fout << rsa << '\n';
                }
            }
        }
    }

    std::cout << std::flush;
    reader->close();

    return 0;
}
