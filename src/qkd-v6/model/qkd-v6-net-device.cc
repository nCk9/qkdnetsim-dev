/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 VSB-TU Ostrava
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
 * Author:  Miralem Mehic  <miralem.mehic@ieee.org>
 */

#include "ns3/log.h"
#include "ns3/queue.h"
#include "ns3/simulator.h"
#include "ns3/mac48-address.h"
#include "ns3/llc-snap-header.h"
#include "ns3/error-model.h"
#include "qkd-v6-net-device.h"
#include "ns3/pointer.h"
#include "ns3/channel.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/uinteger.h"

#include <vector>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDv6NetDevice"); 
NS_OBJECT_ENSURE_REGISTERED (QKDv6NetDevice);

TypeId
QKDv6NetDevice::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDv6NetDevice")
    .SetParent<NetDevice> ()
    .AddConstructor<QKDv6NetDevice> ()
    .AddAttribute ("Mtu", "The MAC-level Maximum Transmission Unit",
                   UintegerValue (1500),
                   MakeUintegerAccessor (&QKDv6NetDevice::SetMtu,
                                         &QKDv6NetDevice::GetMtu),
                   MakeUintegerChecker<uint16_t> ())
    .AddTraceSource ("MacTx", 
                     "Trace source indicating a packet has arrived for transmission by this device",
                     MakeTraceSourceAccessor (&QKDv6NetDevice::m_macTxTrace),
                     "ns3::QKDv6NetDevice::MacTx")
    .AddTraceSource ("MacTxDrop", 
                     "Trace source indicating a packet has been dropped "
                     "by the device before transmission",
                     MakeTraceSourceAccessor (&QKDv6NetDevice::m_macTxDropTrace),
                     "ns3::Packet::MacTxDrop")
    .AddTraceSource ("MacPromiscRx", 
                     "A packet has been received by this device, has been passed up from the physical layer "
                     "and is being forwarded up the local protocol stack.  This is a promiscuous trace,",
                     MakeTraceSourceAccessor (&QKDv6NetDevice::m_macPromiscRxTrace),
                     "ns3::QKDv6NetDevice::MacPromiscRx")
    .AddTraceSource ("MacRx", 
                     "A packet has been received by this device, has been passed up from the physical layer "
                     "and is being forwarded up the local protocol stack.  This is a non-promiscuous trace,",
                     MakeTraceSourceAccessor (&QKDv6NetDevice::m_macRxTrace),
                     "ns3::QKDv6NetDevice::MacRx")
    //
    // Transmit queueing discipline for the device which includes its own set
    // of trace hooks.
    //
    .AddAttribute ("TxQueue", 
                   "A queue to use as the transmit queue in the device.",
                   PointerValue (),
                   MakePointerAccessor (&QKDv6NetDevice::m_queue),
                   MakePointerChecker<Queue<Packet> > ())
    //
    // Trace sources designed to simulate a packet sniffer facility (tcpdump). 
    //
    .AddTraceSource ("Sniffer", 
                     "Trace source simulating a non-promiscuous packet sniffer attached to the device",
                     MakeTraceSourceAccessor (&QKDv6NetDevice::m_snifferTrace),
                     "ns3::QKDv6NetDevice::Sniffer")
    .AddTraceSource ("PromiscSniffer", 
                     "Trace source simulating a promiscuous packet sniffer attached to the device",
                     MakeTraceSourceAccessor (&QKDv6NetDevice::m_promiscSnifferTrace),
                     "ns3::QKDv6NetDevice::PromiscSniffer")
    ;
    return tid;
}

QKDv6NetDevice::QKDv6NetDevice ()
{
  m_needsArp = false;
  m_supportsSendFrom = true;
  m_isPointToPoint = true;
}


void
QKDv6NetDevice::SetSendCallback (SendCallback sendCb)
{
  m_sendCb = sendCb;
}

void
QKDv6NetDevice::SetNeedsArp (bool needsArp)
{
  m_needsArp = needsArp;
}

void
QKDv6NetDevice::SetSupportsSendFrom (bool supportsSendFrom)
{
  m_supportsSendFrom = supportsSendFrom;
}

void
QKDv6NetDevice::SetIsPointToPoint (bool isPointToPoint)
{
  m_isPointToPoint = isPointToPoint;
}

bool
QKDv6NetDevice::SetMtu (const uint16_t mtu)
{
  m_mtu = mtu;
  return true;
}


QKDv6NetDevice::~QKDv6NetDevice()
{
  NS_LOG_FUNCTION_NOARGS ();
}


void QKDv6NetDevice::DoDispose ()
{
  NS_LOG_FUNCTION_NOARGS ();
  m_node = 0;
  NetDevice::DoDispose ();
}

void
QKDv6NetDevice::SetQueue (Ptr<Queue<Packet> > q)
{
  NS_LOG_FUNCTION (this << q);
  m_queue = q;
}
 
Ptr<Queue<Packet> >
QKDv6NetDevice::GetQueue (void) const
{ 
  NS_LOG_FUNCTION (this);
  return m_queue;
}

bool
QKDv6NetDevice::IsReady (void) const
{
  NS_LOG_FUNCTION (this);  
  return true;//!(m_queue->IsFull ());
}


void
QKDv6NetDevice::SetIfIndex (const uint32_t index)
{
  m_index = index;
}

uint32_t
QKDv6NetDevice::GetIfIndex (void) const
{
  return m_index;
}

Ptr<Channel>
QKDv6NetDevice::GetChannel (void) const
{
  return Ptr<Channel> ();
}

Address
QKDv6NetDevice::GetAddress (void) const
{
  return m_myAddress;
}

void
QKDv6NetDevice::SetAddress (Address addr)
{
  m_myAddress = addr;
}

uint16_t
QKDv6NetDevice::GetMtu (void) const
{
  return m_mtu;
}

bool
QKDv6NetDevice::IsLinkUp (void) const
{
  return true;
}

void
QKDv6NetDevice::AddLinkChangeCallback (Callback<void> callback)
{
}

bool
QKDv6NetDevice::IsBroadcast (void) const
{
  return true;
}

Address
QKDv6NetDevice::GetBroadcast (void) const
{
  return Mac48Address ("ff:ff:ff:ff:ff:ff");
}

bool
QKDv6NetDevice::IsMulticast (void) const
{
  return false;
}

Address QKDv6NetDevice::GetMulticast (Ipv4Address multicastGroup) const
{
  return Mac48Address ("ff:ff:ff:ff:ff:ff");
}

Address QKDv6NetDevice::GetMulticast (Ipv6Address addr) const
{
  return Mac48Address ("ff:ff:ff:ff:ff:ff");
}


bool
QKDv6NetDevice::IsPointToPoint (void) const
{
  return m_isPointToPoint;
}
 
bool
QKDv6NetDevice::Send (Ptr<Packet> p, const Address& dest, uint16_t protocolNumber)
{
    NS_LOG_FUNCTION (this << dest << p->GetSize ()  ); 
    m_macTxTrace (p);
 
    NS_LOG_FUNCTION( this << " sends packet " << p->GetUid() << " of size " << p->GetSize() << "\n" << p);
    

    /*
    std::cout << "\n###################################################\n";
    p->Print(std::cout);
    std::cout << "\n###################################################\n";
    */

    if (m_sendCb (p, GetAddress (), dest, protocolNumber)){
        m_snifferTrace (p);
        m_promiscSnifferTrace (p); 
    }else{
        m_macTxDropTrace (p);
        return false;
    } 
    return true;
}


bool
QKDv6NetDevice::Receive (Ptr<Packet> p, uint16_t protocol,
                       const Address &source, const Address &destination,
                       PacketType packetType)
{
    NS_LOG_FUNCTION (this << p->GetSize ()  << p );

    // 
    // For all kinds of packetType we receive, we hit the promiscuous sniffer
    // hook and pass a copy up to the promiscuous callback.  Pass a copy to 
    // make sure that nobody messes with our packet.
    //
    m_promiscSnifferTrace (p);
    if (!m_promiscRxCallback.IsNull ())
    {
      m_macPromiscRxTrace (p);
      m_promiscRxCallback (this, p, protocol, source, destination, packetType);
    }

    //
    // If this packet is not destined for some other host, it must be for us
    // as either a broadcast, multicast or unicast.  We need to hit the mac
    // packet received trace hook and forward the packet up the stack.
    //
    if (packetType != PACKET_OTHERHOST)
    {
      m_snifferTrace (p);
      m_macRxTrace (p);
      m_rxCallback (this, p, protocol, source);
    } 

    return true;
        
}


bool
QKDv6NetDevice::SendFrom (Ptr<Packet> packet, const Address& source, const Address& dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this << packet << source << dest << protocolNumber);
  return false;
}

Ptr<Node>
QKDv6NetDevice::GetNode (void) const
{
  return m_node;
}

void
QKDv6NetDevice::SetNode (Ptr<Node> node)
{
  m_node = node;
}

bool
QKDv6NetDevice::NeedsArp (void) const
{
  return m_needsArp;
}

void
QKDv6NetDevice::SetReceiveCallback (NetDevice::ReceiveCallback cb)
{
  m_rxCallback = cb;
}

void
QKDv6NetDevice::SetPromiscReceiveCallback (NetDevice::PromiscReceiveCallback cb)
{
  m_promiscRxCallback = cb;
}

bool
QKDv6NetDevice::SupportsSendFrom () const
{
  return m_supportsSendFrom;
}

bool QKDv6NetDevice::IsBridge (void) const
{
  return false;
}

} // namespace ns3
