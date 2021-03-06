/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "agent_ucc_listener.h"

#include <beerocks/bcl/network/network_utils.h>
#include <beerocks/tlvf/beerocks_message.h>

#include <easylogging++.h>

using namespace beerocks;
using namespace net;

agent_ucc_listener::agent_ucc_listener(uint16_t port, const std::string &vendor,
                                       const std::string &model, const std::string &bridge_iface,
                                       Socket **controller_sd)
    : beerocks_ucc_listener(port), m_vendor(vendor), m_model(model), m_bridge_iface(bridge_iface),
      m_controller_sd(controller_sd)
{
    m_ucc_listener_run_on = eUccListenerRunOn::CONTROLLER;
}

bool agent_ucc_listener::init()
{
    network_utils::iface_info bridge_info;
    if (network_utils::get_iface_info(bridge_info, m_bridge_iface) < 0) {
        LOG(ERROR) << " failed getting iface info on bridge_mac '" << m_bridge_iface << "'";
        should_stop = true;
        return false;
    }

    m_bridge_mac = bridge_info.mac;

    return beerocks_ucc_listener::init();
}

/**
 * @brief Returns string filled with reply to "DEVICE_GET_INFO" command.
 * 
 * @return const std::string Device info in UCC reply format.
 */
std::string agent_ucc_listener::fill_version_reply_string()
{
    return std::string("vendor,") + m_vendor + std::string(",model,") + m_model +
           std::string(",version,") + BEEROCKS_VERSION;

    return std::string();
}

/**
 * @brief Clears configuration on Controller database.
 * 
 * @return None.
 */
void agent_ucc_listener::clear_configuration()
{
    // TODO implement clearing of agent configuration.
    // As part of task: https://github.com/prplfoundation/prplMesh/issues/336
}

/**
 * @brief Return socket to Agent with bridge 'dest_alid` MAC address.
 * 
 * @param[in] dest_alid Agent bridge MAC address.
 * @return Socket* Socket to the Agent.
 */
Socket *agent_ucc_listener::get_dev_send_1905_destination_socket(const std::string &dest_alid)
{
    // On the agent side, the dest_alid is not really needed since the destination socket will
    // always be the controller socket.
    return *m_controller_sd;
}

/**
 * @brief Get preprepared buffer with CMDU in it.
 * 
 * @return std::shared_ptr<uint8_t> Buffer pointer.
 */
std::shared_ptr<uint8_t> agent_ucc_listener::get_buffer_filled_with_cmdu()
{
    // Currently, no such buffer on agent side.
    return std::shared_ptr<uint8_t>(nullptr);
}

/**
 * @brief Send CMDU to destined Agent.
 * 
 * @param[in] sd Agent socket
 * @param[in] cmdu_tx CMDU object
 * @return true if successful, false if not.
 */
bool agent_ucc_listener::send_cmdu_to_destination(Socket *sd, ieee1905_1::CmduMessageTx &cmdu_tx)
{
    if (*m_controller_sd == nullptr) {
        LOG(ERROR) << "socket to controller is nullptr";
        return false;
    }

    return message_com::send_cmdu(*m_controller_sd, cmdu_tx, (*m_controller_sd)->getPeerMac(),
                                  m_bridge_mac);
    return true;
}

/**
 * @brief Handle DEV_SET_CONFIG command. Parse the command and save the parameters on the agent.
 * 
 * @param[in] params Command parameters.
 * @param[out] err_string Contains an error description if the function fails.
 * @return true if successful, false if not.
 */
bool agent_ucc_listener::handle_dev_set_config(std::unordered_map<std::string, std::string> &params,
                                               std::string &err_string)
{

    if (params.find("bss_info") != params.end()) {
        err_string = "parameter 'bss_info' is not relevant to the agent";
        return false;
    }

    if (params.find("backhaul") == params.end()) {
        err_string = "parameter 'backhaul' is missing";
        return false;
    }

    // TODO implement seting of agent configuration.
    // As part of task: https://github.com/prplfoundation/prplMesh/issues/336

    return true;
}
