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

#include <tlvf/ieee_1905_1/tlvAutoconfigFreqBand.h>
#include <tlvf/tlvflogging.h>

using namespace ieee1905_1;

tlvAutoconfigFreqBand::tlvAutoconfigFreqBand(uint8_t* buff, size_t buff_len, bool parse, bool swap_needed) :
    BaseClass(buff, buff_len, parse, swap_needed) {
    m_init_succeeded = init();
}
tlvAutoconfigFreqBand::tlvAutoconfigFreqBand(std::shared_ptr<BaseClass> base, bool parse, bool swap_needed) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse, swap_needed){
    m_init_succeeded = init();
}
tlvAutoconfigFreqBand::~tlvAutoconfigFreqBand() {
}
const eTlvType& tlvAutoconfigFreqBand::type() {
    return (const eTlvType&)(*m_type);
}

const uint16_t& tlvAutoconfigFreqBand::length() {
    return (const uint16_t&)(*m_length);
}

tlvAutoconfigFreqBand::eValue& tlvAutoconfigFreqBand::value() {
    return (eValue&)(*m_value);
}

std::shared_ptr<tlvAutoconfigFreqBand> tlvAutoconfigFreqBand::castFrom(std::shared_ptr<BaseClass> source) {
    return std::make_shared<tlvAutoconfigFreqBand>(source->getStartBuffPtr(),source->getLen()+source->getBuffRemainingBytes(),true);
}
void tlvAutoconfigFreqBand::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
}

size_t tlvAutoconfigFreqBand::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvType); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(eValue); // value
    return class_size;
}

bool tlvAutoconfigFreqBand::init()
{
    if (getBuffRemainingBytes() < kMinimumLength) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = (eTlvType*)m_buff_ptr__;
    if (!m_parse__) *m_type = eTlvType::TLV_AUTOCONFIG_FREQ_BAND;
    if (!buffPtrIncrementSafe(sizeof(eTlvType))) { return false; }
    m_length = (uint16_t*)m_buff_ptr__;
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) { return false; }
    m_value = (eValue*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(eValue))) { return false; }
    if(m_length && !m_parse__){ (*m_length) += sizeof(eValue); }
    if (m_parse__ && m_swap__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvType::TLV_AUTOCONFIG_FREQ_BAND) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvType::TLV_AUTOCONFIG_FREQ_BAND) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


