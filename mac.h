#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#define MAC_SIZE 6

struct Mac final {
	static const int SIZE = 6;

	//
	// constructor
	//
	Mac() {}
	Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
	Mac(const std::string r);

	//
	// casting operator
	//
	operator uint8_t*() const { return const_cast<uint8_t*>(mac_); } // default
	explicit operator std::string() const;

	//
	// comparison operator
	//
	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }

protected:
	uint8_t mac_[SIZE];
};
