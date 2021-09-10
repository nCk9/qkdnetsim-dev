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

#ifndef QKD_V6_QUEUE_DISC_ITEM_H
#define QKD_V6_QUEUE_DISC_ITEM_H

#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/net-device.h"
#include "ns3/traced-value.h"
#include "ns3/queue-disc.h" 
#include "ns3/ipv6-route.h"

namespace ns3 {

/**
 * \ingroup qkd
 * \class QKDv6QueueDiscItem
 * \brief QKDv6QueueDiscItem is a subclass of QueueDiscItem which stores IPv4 packets.
 * Header and payload are kept separate to allow the queue disc to manipulate
 * the header, which is added to the packet when the packet is dequeued.
 *
 * \note Only difference between QueueDiscItem is that QKDv6QueueDiscItem
 * stores info about the source (source IPv6Address) which is needed
 * in QKDL4 implementation in QKDNetwork (if used).
 */
class QKDv6QueueDiscItem : public QueueDiscItem {
public:
    /**
    * \brief Create an QKD queue disc item containing a packet.
    * \param p the packet included in the created item.
    * \param addr the IP source address
    * \param addr the IP destination address
    * \param protocol the protocol number
    * \param IPv4 Route (if any)
    */
    QKDv6QueueDiscItem (
        Ptr<Packet> p, 
        const Ipv6Address & source, 
        const Ipv6Address & destination, 
        uint8_t protocol, 
        Ptr<Ipv6Route> route
    );

    virtual ~QKDv6QueueDiscItem ();

    /**
    * \return the correct packet size (header plus payload).
    */
    virtual uint32_t GetSize (void) const;

    /**
    * \brief Print the item contents.
    * \param os output stream in which the data should be printed.
    */
    virtual void Print (std::ostream &os) const;

    virtual void AddHeader (void);

    Ipv6Address GetSource (void) const;

    Ipv6Address GetDestination (void) const;

    Ptr<Ipv6Route> GetRoute (void) const;

    virtual bool Mark (void);

private:
  /**
   * \brief Default constructor
   *
   * Defined and unimplemented to avoid misuse
   */
  QKDv6QueueDiscItem ();
  /**
   * \brief Copy constructor
   *
   * Defined and unimplemented to avoid misuse
   */
  QKDv6QueueDiscItem (const QKDv6QueueDiscItem &);
  /**
   * \brief Assignment operator
   *
   * Defined and unimplemented to avoid misuse
   * \returns
   */
  QKDv6QueueDiscItem &operator = (const QKDv6QueueDiscItem &);

    Ipv6Address     m_source;
    Ipv6Address     m_destination;
    Ptr<Ipv6Route>  m_route;
};

} // namespace ns3

#endif /* QKD_V6_QUEUE_DISC_ITEM_H */
