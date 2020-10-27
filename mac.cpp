#include "mac.h"

Mac::Mac(const std::string r) {
	unsigned int a, b, c, d, e, f;
	int res = sscanf(r.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", &a, &b, &c, &d, &e, &f);
	if (res != SIZE) {
		fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
	mac_[0] = a;
	mac_[1] = b;
	mac_[2] = c;
	mac_[3] = d;
	mac_[4] = e;
	mac_[5] = f;
}

Mac::operator std::string() const {
	char buf[32]; // enough size
	sprintf(buf, "%02x:%02X:%02X:%02X:%02X:%02X",
		mac_[0],
		mac_[1],
		mac_[2],
		mac_[3],
		mac_[4],
		mac_[5]);
	return std::string(buf);
}

#ifdef GTEST
#include <gtest/gtest.h>

TEST(Mac, ctorTest) {
	Mac mac1; // Mac()

	uint8_t buf[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
	Mac mac2(buf); // Mac(const uint8_t* r)

	Mac mac3("12:34:56:78:9A:BC"); // Mac(const std::string r)

	EXPECT_EQ(mac2, mac3);
}

TEST(Mac, castingTest) {
	Mac mac("12:34:56:78:9A:BC");

	uint8_t buf[Mac::SIZE];
	memcpy(buf, mac, Mac::SIZE); // operator uint8_t*()
	EXPECT_TRUE(memcmp(buf, mac, Mac::SIZE) == 0);

	std::string s = std::string(mac); // explicit operator std::string()

	EXPECT_EQ(s, "12:34:56:78:9A:BC");
}

#endif // GTEST
