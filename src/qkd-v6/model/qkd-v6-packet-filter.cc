/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 Universita' degli Studi di Napoli Federico II
 *               2016 University of Washington
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
 * Authors:  Stefano Avallone <stavallo@unina.it>
 *           Tom Henderson <tomhend@u.washington.edu>
 */

#include "ns3/log.h"
#include "ns3/enum.h" 
#include "ns3/socket.h"
#include "ns3/qkd-v6-queue-disc-item.h"
#include "qkd-v6-packet-filter.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDv6PacketFilter");

NS_OBJECT_ENSURE_REGISTERED (QKDv6PacketFilter);

TypeId 
QKDv6PacketFilter::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDv6PacketFilter")
    .SetParent<PacketFilter> ()
    .SetGroupName ("Internet")
  ;
  return tid;
}

QKDv6PacketFilter::QKDv6PacketFilter ()
{
  NS_LOG_FUNCTION (this);
}

QKDv6PacketFilter::~QKDv6PacketFilter()
{
  NS_LOG_FUNCTION (this);
}

bool
QKDv6PacketFilter::CheckProtocol (Ptr<QueueDiscItem> item) const
{
  NS_LOG_FUNCTION (this << item);
  return (DynamicCast<QKDv6QueueDiscItem> (item) != 0);
}

// ------------------------------------------------------------------------- //

NS_OBJECT_ENSURE_REGISTERED (PfifoFastQKDv6PacketFilter);

TypeId 
PfifoFastQKDv6PacketFilter::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::PfifoFastQKDv6PacketFilter")
    .SetParent<QKDv6PacketFilter> ()
    .SetGroupName ("Internet")
    .AddConstructor<PfifoFastQKDv6PacketFilter> ()
    .AddAttribute ("Mode",
                   "Whether to interpret the TOS byte as legacy TOS or DSCP",
                   EnumValue (PF_MODE_TOS),
                   MakeEnumAccessor (&PfifoFastQKDv6PacketFilter::m_trafficClassMode),
                   MakeEnumChecker (PF_MODE_TOS, "TOS semantics",
                                    PF_MODE_DSCP, "DSCP semantics"))
  ;
  return tid;
}

PfifoFastQKDv6PacketFilter::PfifoFastQKDv6PacketFilter ()
{
  NS_LOG_FUNCTION (this);
}

PfifoFastQKDv6PacketFilter::~PfifoFastQKDv6PacketFilter()
{
  NS_LOG_FUNCTION (this);
}

int32_t
PfifoFastQKDv6PacketFilter::DoClassify (Ptr<QueueDiscItem> item) const
{
  NS_LOG_FUNCTION (this << item);
  uint32_t band;
  Ptr<QKDv6QueueDiscItem> qkdItem = DynamicCast<QKDv6QueueDiscItem> (item);

  NS_ASSERT (qkdItem != 0);

  if (m_trafficClassMode == PF_MODE_TOS)
    {

      uint8_t tos = 0;
      bool found = false;

      SocketIpTosTag ipTosTag;
      Ptr<Packet> copy = qkdItem->GetPacket ()->Copy ();
      found = copy->PeekPacketTag (ipTosTag);

      if (found)
        tos = ipTosTag.GetTos ();
      
      band = TosToBand (tos);
      NS_LOG_DEBUG ("Found Ipv4 packet; TOS " << (uint32_t) tos << " band " << band);
    }
  else
    {
      /*
      NOT IMPLEMENTED FOR NOW! - no DSCP in NS-3 for now
      Ipv6Header::DscpType dscp = qkdItem->GetHeader ().GetDscp ();
      band = DscpToBand (dscp);
      NS_LOG_DEBUG ("Found Ipv4 packet; DSCP " << qkdItem->GetHeader ().DscpTypeToString (dscp) << " band " << band);
      */
    }

  return band;
}

uint32_t
PfifoFastQKDv6PacketFilter::TosToBand (uint8_t tos) const
{
  NS_LOG_FUNCTION (this << (uint16_t) tos);

  uint32_t band =  prio2band[tos & 0x0f];
  NS_LOG_DEBUG ("Band returned:  " << band);
  
  return band;
}

uint32_t
PfifoFastQKDv6PacketFilter::DscpToBand (Ipv6Header::DscpType dscpType) const
{
  NS_LOG_FUNCTION (this);

  uint32_t band = 1;
  switch (dscpType) {
    case Ipv6Header::DSCP_EF :
    case Ipv6Header::DSCP_AF13 :
    case Ipv6Header::DSCP_AF23 :
    case Ipv6Header::DSCP_AF33 :
    case Ipv6Header::DSCP_AF43 :
    case Ipv6Header::DscpDefault :
    case Ipv6Header::DSCP_CS2 :
    case Ipv6Header::DSCP_CS3 :
      band = 1;
      break;
    case Ipv6Header::DSCP_AF11 :
    case Ipv6Header::DSCP_AF21 :
    case Ipv6Header::DSCP_AF31 :
    case Ipv6Header::DSCP_AF41 :
    case Ipv6Header::DSCP_CS1 :
      band = 2;
      break;
    case Ipv6Header::DSCP_AF12 :
    case Ipv6Header::DSCP_AF22 :
    case Ipv6Header::DSCP_AF32 :
    case Ipv6Header::DSCP_AF42 :
    case Ipv6Header::DSCP_CS4 :
    case Ipv6Header::DSCP_CS5 :
    case Ipv6Header::DSCP_CS6 :
    case Ipv6Header::DSCP_CS7 :
      band = 0;
      break;
    default :
      band = 1;
  }
  NS_LOG_DEBUG ("Band returned:  " << band);
  return band;
}

} // namespace ns3
