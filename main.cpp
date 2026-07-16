#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <memory>
#include <sstream>
#include <vector>
#include <filesystem>
#include <fstream>
struct EVP_MD_CTX_DELETER {
	void operator()(EVP_MD_CTX* ctx) const {
		EVP_MD_CTX_free(ctx);
	}
};
struct EVP_PKEY_DELETER {
	void operator()(EVP_PKEY* pkey) const {
		EVP_PKEY_free(pkey);
	}
};
struct EVP_PKEY_CTX_DELETER {
	void operator()(EVP_PKEY_CTX* pkey) const {
		EVP_PKEY_CTX_free(pkey);
	}
};
namespace fs = std::filesystem;
using UniqueMD = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_DELETER>;
using UniquePKEY = std::unique_ptr<EVP_PKEY, EVP_PKEY_DELETER>;
using UniquePKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_DELETER>;

UniquePKEY generate_key() {
	UniquePKEY_CTX ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
	if (!ctx) throw std::runtime_error("Failed create PKEY_CTX");
	if (EVP_PKEY_keygen_init(ctx.get()) <= 0) throw std::runtime_error("Failed init");
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) throw std::runtime_error("Failed to set curve");
	EVP_PKEY* pkey = nullptr;
	if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) throw std::runtime_error("Failed keygen private'");
	UniquePKEY private_key(pkey);
	return private_key;
}
std::vector<uint8_t> sign_data(const UniquePKEY& private_key, const std::string& data) {
	UniqueMD ctx(EVP_MD_CTX_new());
	if (!ctx) throw std::runtime_error("Failed create ctx for sign_data");

	if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, private_key.get()) <= 0) throw std::runtime_error("Fail SignInit");
	if (EVP_DigestSignUpdate(ctx.get(), data.c_str(), data.length()) <= 0) throw std::runtime_error("Failed to update sign");

	size_t sign_len = 0;
	if (EVP_DigestSignFinal(ctx.get(), nullptr, &sign_len) <= 0) throw std::runtime_error("Failed to get true sign_len");
	std::vector<uint8_t> signature(sign_len);
	if (EVP_DigestSignFinal(ctx.get(), signature.data(), &sign_len) <= 0) throw std::runtime_error("Failed to SignFinal");

	signature.resize(sign_len);
	return signature;
}
bool verifySign(const UniquePKEY& public_key, const std::string& data, const std::vector<uint8_t>& signature) {
	UniqueMD ctx(EVP_MD_CTX_new());
	if (!ctx) throw std::runtime_error("Failed create ctx for verifySign");
	if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, public_key.get()) <= 0) throw std::runtime_error("Failed VerifyInit");
	if (EVP_DigestVerifyUpdate(ctx.get(), data.c_str(), data.length()) <= 0) throw std::runtime_error("Failed DigestVerifyUpdate");
	int result = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
	return result == 1;
}
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
	std::stringstream ss;
	for (uint8_t byte : bytes) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
	}
	return ss.str();
}
int main() {
	std::string example_text = "The example.";
	std::string data;
	if (fs::exists("alldata") == 1) {
		if (fs::exists("alldata\\data.txt") != 1) {
			std::cout << "Dont found 'data.txt'\n" << "Create..." << std::endl;
			std::ofstream data("alldata\\data.txt");
			if (data.is_open()) {
				data << example_text;
			}
		}
	}
	else {
		std::cout << "Dont found 'alldata''\n" << "Create..." << std::endl;
		fs::create_directory("alldata");
		if (fs::exists("alldata\\data.txt") != 1) {
			std::cout << "Dont found 'data.txt'\n" << "Create..." << std::endl;
			std::ofstream datafile("alldata\\data.txt");
			if (datafile.is_open()) {
				datafile << "The example.";
			}
		}
	}


	try {
		std::ifstream idatafile("alldata\\data.txt");
		if (idatafile.is_open()) {
			while (std::getline(idatafile, data)) {

			}
		}
		auto private_key = generate_key();
		std::vector<uint8_t> signature = sign_data(private_key, data);
		std::string result = bytes_to_hex(signature);
		std::ofstream ioutput("alldata\\output.txt");
		if (ioutput.is_open()) {
			ioutput.clear();
			ioutput << result;
		}
		std::cout << "All complete!" << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Crypt error:" << e.what() << std::endl;
	}
}