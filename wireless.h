#pragma once

#include <cstdint>
#include "mac.h"

// radiotap_header https://www.radiotap.org/
#pragma pack(push, 1)
struct ieee80211_radiotap_header
{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ieee80211_MAC_header
{
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    Mac da;
    Mac sa;
    Mac bssid;
    uint16_t seq;

    // type_subtype
    enum : uint8_t
    {
        BEACON = 0x80,
        DEAUTH = 0xC0,
    };
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fixed_parameter
{
    uint16_t reason_code;
};
#pragma pack(pop)