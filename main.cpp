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

std::vector<std::string> extract_payload(std::string const &payload, std::vector<boost::regex> const &regexes) {
    std::vector<std::string> para_contents;
    for (auto const &pattern : regexes) {
        boost::smatch results;
        if (regex_search(payload, results, pattern)) {
            if (results.size() > 1) {
                std::string para_content = results[1].str();
                para_contents.emplace_back(para_content);
            }
        }
    }

    return para_contents;
}

int get_packet_count(std::string const &pcap_path) {
    int                      packet_count = 0;
    pcpp::IFileReaderDevice *size_reader  = pcpp::IFileReaderDevice::getReader(pcap_path);
    pcpp::RawPacket          tmp_packet;

    if (size_reader == nullptr) {
        std::cerr << "Cannot determine reader for file type" << '\n';
        return -1;
    }

    if (!size_reader->open()) {
        std::cerr << "Cannot open " + pcap_path + " for reading" << '\n';
        return -1;
    }

    while (size_reader->getNextPacket(tmp_packet)) {
        packet_count++;
    }

    size_reader->close();
    delete size_reader;

    return packet_count;
}

std::vector<boost::regex> get_regexes(std::string const &parameters) {
    std::vector<boost::regex> pattern_regexes;
    std::stringstream         para_ss(parameters);
    if (parameters.find(',') != std::string::npos) {
        std::string single_parameter;
        // multiple parameters
        while (std::getline(para_ss, single_parameter, ',')) {
            pattern_regexes.emplace_back(single_parameter + "=([^&]+)");
        }
    } else {
        // single parameter
        pattern_regexes.emplace_back(parameters + "=([^&]+)");
    }

    return pattern_regexes;
}

void match_regex_from_reader(bool debug, std::ofstream &fout, std::string const &pcap_path, const int packetCount, std::vector<boost::regex> const &pattern_regexes) {
    pcpp::RawPacket          raw_packet;
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(pcap_path);
    reader->open();

    int         idx = 0;
    progressbar pb(100);
    pb.show_bar(debug);

    while (reader->getNextPacket(raw_packet)) {
        if (debug) {
            idx++;
            // update progress bar every 1% of packets,
            // 100 is ratio which must equal to value in progressbar variable definition above
            if (idx % (packetCount / 100) == 0) {
                pb.update();
            }
        }

        pcpp::Packet          parsed_packet(&raw_packet);
        pcpp::TcpLayer const *tcp_layer = parsed_packet.getLayerOfType<pcpp::TcpLayer>();

        if (tcp_layer == nullptr) {
            continue;
        }

        uint8_t const *data_ptr = tcp_layer->getData();
        size_t const   size     = tcp_layer->getDataLen();

        if (data_ptr == nullptr || size == 0) {
            continue;
        }

        std::string              payload(reinterpret_cast<std::string::const_pointer>(data_ptr), size);
        std::vector<std::string> rsa_list = extract_payload(payload, pattern_regexes);

        if (rsa_list.empty()) {
            continue;
        }

        // rsa_list.at(0) is always rsa string which length greater than 16
        // 16 is not a magic number but a thumb rule because content in rsa is a DES output
        if (rsa_list.at(0).length() > 16) {
            for (size_t i = 0; i < rsa_list.size(); ++i) {
                fout << rsa_list[i];
                if (i != rsa_list.size() - 1) {
                    fout << ",";
                }
            }
            fout << '\n';
        }
    }

    reader->close();
    delete reader;
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
    std::string       parameters(args::get(extpara));

    int packetCount = get_packet_count(pcap_path);

    if (debug) {
        std::cout << "Total packets: " << packetCount << '\n';
    }

    std::vector<boost::regex> pattern_regexes = get_regexes(parameters);

    match_regex_from_reader(debug, fout, pcap_path, packetCount, pattern_regexes);

    return 0;
}
