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

#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <tlvf/tlvflogging.h>

using namespace beerocks_message;

tlvVsClientAssociationEvent::tlvVsClientAssociationEvent(uint8_t* buff, size_t buff_len, bool parse, bool swap_needed) :
    BaseClass(buff, buff_len, parse, swap_needed) {
    m_init_succeeded = init();
}
tlvVsClientAssociationEvent::tlvVsClientAssociationEvent(std::shared_ptr<BaseClass> base, bool parse, bool swap_needed) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse, swap_needed){
    m_init_succeeded = init();
}
tlvVsClientAssociationEvent::~tlvVsClientAssociationEvent() {
}
sMacAddr& tlvVsClientAssociationEvent::mac() {
    return (sMacAddr&)(*m_mac);
}

sMacAddr& tlvVsClientAssociationEvent::bssid() {
    return (sMacAddr&)(*m_bssid);
}

int8_t& tlvVsClientAssociationEvent::vap_id() {
    return (int8_t&)(*m_vap_id);
}

beerocks::message::sRadioCapabilities& tlvVsClientAssociationEvent::capabilities() {
    return (beerocks::message::sRadioCapabilities&)(*m_capabilities);
}

uint8_t& tlvVsClientAssociationEvent::disconnect_reason() {
    return (uint8_t&)(*m_disconnect_reason);
}

uint8_t& tlvVsClientAssociationEvent::disconnect_source() {
    return (uint8_t&)(*m_disconnect_source);
}

uint8_t& tlvVsClientAssociationEvent::disconnect_type() {
    return (uint8_t&)(*m_disconnect_type);
}

std::shared_ptr<tlvVsClientAssociationEvent> tlvVsClientAssociationEvent::castFrom(BaseClass& source) {
    try {
        return std::make_shared<tlvVsClientAssociationEvent>(source.getBuffPtr(),source.getLen());
    }
    catch(const std::exception& e){
        return nullptr;
    }
}
void tlvVsClientAssociationEvent::class_swap()
{
    m_mac->struct_swap();
    m_bssid->struct_swap();
    m_capabilities->struct_swap();
}

size_t tlvVsClientAssociationEvent::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(sMacAddr); // mac
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(int8_t); // vap_id
    class_size += sizeof(beerocks::message::sRadioCapabilities); // capabilities
    class_size += sizeof(uint8_t); // disconnect_reason
    class_size += sizeof(uint8_t); // disconnect_source
    class_size += sizeof(uint8_t); // disconnect_type
    return class_size;
}

bool tlvVsClientAssociationEvent::init()
{
    if (getBuffRemainingBytes() < kMinimumLength) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_mac = (sMacAddr*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) { return false; }
    if (!m_parse__) { m_mac->struct_init(); }
    m_bssid = (sMacAddr*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) { return false; }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_vap_id = (int8_t*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(int8_t))) { return false; }
    m_capabilities = (beerocks::message::sRadioCapabilities*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(beerocks::message::sRadioCapabilities))) { return false; }
    if (!m_parse__) { m_capabilities->struct_init(); }
    m_disconnect_reason = (uint8_t*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) { return false; }
    m_disconnect_source = (uint8_t*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) { return false; }
    m_disconnect_type = (uint8_t*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) { return false; }
    if (m_parse__ && m_swap__) { class_swap(); }
    return true;
}

tlvVsClientAssociationControlRequest::tlvVsClientAssociationControlRequest(uint8_t* buff, size_t buff_len, bool parse, bool swap_needed) :
    BaseClass(buff, buff_len, parse, swap_needed) {
    m_init_succeeded = init();
}
tlvVsClientAssociationControlRequest::tlvVsClientAssociationControlRequest(std::shared_ptr<BaseClass> base, bool parse, bool swap_needed) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse, swap_needed){
    m_init_succeeded = init();
}
tlvVsClientAssociationControlRequest::~tlvVsClientAssociationControlRequest() {
}
beerocks::net::sIpv4Addr& tlvVsClientAssociationControlRequest::ipv4() {
    return (beerocks::net::sIpv4Addr&)(*m_ipv4);
}

std::shared_ptr<tlvVsClientAssociationControlRequest> tlvVsClientAssociationControlRequest::castFrom(BaseClass& source) {
    try {
        return std::make_shared<tlvVsClientAssociationControlRequest>(source.getBuffPtr(),source.getLen());
    }
    catch(const std::exception& e){
        return nullptr;
    }
}
void tlvVsClientAssociationControlRequest::class_swap()
{
    m_ipv4->struct_swap();
}

size_t tlvVsClientAssociationControlRequest::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(beerocks::net::sIpv4Addr); // ipv4
    return class_size;
}

bool tlvVsClientAssociationControlRequest::init()
{
    if (getBuffRemainingBytes() < kMinimumLength) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_ipv4 = (beerocks::net::sIpv4Addr*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(beerocks::net::sIpv4Addr))) { return false; }
    if (!m_parse__) { m_ipv4->struct_init(); }
    if (m_parse__ && m_swap__) { class_swap(); }
    return true;
}


