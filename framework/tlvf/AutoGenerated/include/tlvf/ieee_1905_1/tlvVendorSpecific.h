///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TLVF_IEEE_1905_1_TLVVENDORSPECIFIC_H_
#define _TLVF_IEEE_1905_1_TLVVENDORSPECIFIC_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include "tlvf/ieee_1905_1/eTlvType.h"
#include "tlvf/ieee_1905_1/sVendorOUI.h"

namespace ieee1905_1 {


class tlvVendorSpecific : public BaseClass
{
    public:
        tlvVendorSpecific(uint8_t* buff, size_t buff_len, bool parse = false, bool swap_needed = false);
        tlvVendorSpecific(std::shared_ptr<BaseClass> base, bool parse = false, bool swap_needed = false);
        ~tlvVendorSpecific();

        enum eVendorOUI: uint32_t {
            OUI_BYTES = 0x3,
            OUI_INTEL = 0x470300,
        };
        
        const eTlvType& type();
        uint16_t& length();
        sVendorOUI& vendor_oui();
        void class_swap();
        static size_t get_initial_size();

    private:
        bool init();
        eTlvType* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sVendorOUI* m_vendor_oui = nullptr;
};

}; // close namespace: ieee1905_1

#endif //_TLVF/IEEE_1905_1_TLVVENDORSPECIFIC_H_
