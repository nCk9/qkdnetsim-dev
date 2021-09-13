/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 LIPTEL.ieee.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 */

#ifndef QKD_APP_CHARGING_HELPER_H
#define QKD_APP_CHARGING_HELPER_H

#include <stdint.h>
#include <string>
#include "ns3/object-factory.h"
#include "ns3/address.h"
#include "ns3/attribute.h"
#include "ns3/net-device.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/application-container.h"

namespace ns3 {

/**
 * \ingroup qkdsend
 * \brief A helper to make it easier to instantiate an ns3::QKDSendApplication
 * on a set of nodes.
 */
class QKDAppChargingHelper
{
public:
  /**
   * Create an QKDAppChargingHelper to make it easier to work with QKDSendApplications
   *
   * \param protocol the name of the protocol to use to send traffic
   *        by the applications. This string identifies the socket
   *        factory type used to create sockets for the applications.
   *        A typical value would be ns3::UdpSocketFactory.
   * \param address the address of the remote node to send traffic
   *        to.
   */
  QKDAppChargingHelper (std::string protocol, Address address);
  QKDAppChargingHelper (std::string protocol, Ipv4Address addressSrc, Ipv4Address addressDst, uint32_t keyRate);
  QKDAppChargingHelper (std::string protocol, Ipv6Address addressSrc, Ipv6Address addressDst, uint32_t keyRate);

  /**
   * Helper function used to set the underlying application attributes, 
   * _not_ the socket attributes.
   *
   * \param name the name of the application attribute to set
   * \param value the value of the application attribute to set
   */
  void SetAttribute (std::string mFactoryName, std::string name, const AttributeValue &value);

  /**
   * Install an ns3::QKDSendApplication on each node of the input container
   * configured with all the attributes set with SetAttribute.
   *
   * \param c NodeContainer of the set of nodes on which an QKDSendApplication
   * will be installed.
   * \returns Container of Ptr to the applications installed.
   */
  //ApplicationContainer Install (NodeContainer c) const;
  void SetSettings ( std::string protocol, Ipv4Address master, Ipv4Address slave, uint32_t keyRate);
  void SetSettings ( std::string protocol, Ipv6Address master, Ipv6Address slave, uint32_t keyRate);

  /**
   * Install an ns3::QKDSendApplication on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QKDSendApplication will be installed.
   * \returns Container of Ptr to the applications installed.
   */
  //ApplicationContainer Install (Ptr<Node> node) const;
  ApplicationContainer Install (Ptr<NetDevice> net1, Ptr<NetDevice> net2) const;

  /**
   * Install an ns3::QKDSendApplication on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param nodeName The node on which an QKDSendApplication will be installed.
   * \returns Container of Ptr to the applications installed.
   */
  //ApplicationContainer Install (std::string nodeName) const;

private:
  /**
   * Install an ns3::QKDSendApplication on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QKDSendApplication will be installed.
   * \returns Ptr to the application installed.
   */ 
  ApplicationContainer InstallPriv (Ptr<NetDevice> net1, Ptr<NetDevice> net2) const;

  ObjectFactory m_factory_master_app; //!< Object factory.
  ObjectFactory m_factory_slave_app; //!< Object factory.
   
  std::string     m_protocol;

  static uint32_t appCounter;

};

} // namespace ns3
 
#endif /* QKD_APP_CHARGING_HELPER_H */

