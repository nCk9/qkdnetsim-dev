/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 Universita' degli Studi di Napoli Federico II
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

#include "ns3/log.h"
#include "qkd-v6-queue-disc-item.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDv6QueueDiscItem");

QKDv6QueueDiscItem::QKDv6QueueDiscItem (Ptr<Packet> p, 
    const Ipv6Address & source, 
    const Ipv6Address & destination, 
    uint8_t protocol, 
    Ptr<Ipv6Route> route
)
  : QueueDiscItem (p, Address(destination), protocol),
    m_source (source),
    m_destination (destination),
    m_route (route)
{
}

QKDv6QueueDiscItem::~QKDv6QueueDiscItem()
{
  NS_LOG_FUNCTION (this);
}

void 
QKDv6QueueDiscItem::AddHeader (void){}

uint32_t QKDv6QueueDiscItem::GetSize(void) const
{
  Ptr<Packet> p = GetPacket ();
  NS_ASSERT (p != 0);
  uint32_t ret = p->GetSize ();
  return ret;
}

Ipv6Address
QKDv6QueueDiscItem::GetSource (void) const
{
  return m_source;
}

Ipv6Address
QKDv6QueueDiscItem::GetDestination (void) const
{
  return m_destination;
}

Ptr<Ipv6Route>
QKDv6QueueDiscItem::GetRoute (void) const
{
  return m_route;
}

void
QKDv6QueueDiscItem::Print (std::ostream& os) const
{ 
  os << GetPacket () << " "
     << "Dst addr " << GetAddress () << " "
     << "proto " << (uint16_t) GetProtocol () << " "
     << "txq " << (uint8_t) GetTxQueueIndex ()
  ;
}

bool
QKDv6QueueDiscItem::Mark (void)
{
  return false;
}

} // namespace ns3
