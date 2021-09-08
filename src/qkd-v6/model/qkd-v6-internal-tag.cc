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
 * Author: Nitya Chandra <nityachandra6@gmail.com>
 */

#include "ns3/log.h" 
#include "ns3/object-vector.h"
#include "ns3/pointer.h"
#include "ns3/uinteger.h"
#include "qkd-v6-internal-tag.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDv6InternalTag");

 
NS_OBJECT_ENSURE_REGISTERED (QKDv6CommandTag);
 
TypeId 
QKDv6CommandTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDv6CommandTag")
    .SetParent<Tag> ()
    .AddConstructor<QKDv6CommandTag> () 
  ;
  return tid;
}
TypeId 
QKDv6CommandTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
QKDv6CommandTag::GetSerializedSize (void) const
{
  return sizeof(uint8_t) + sizeof(uint32_t);
} 

void
QKDv6CommandTag::Serialize (TagBuffer i) const
{ 
    i.WriteU8 ((uint8_t) m_command);  
    i.WriteU32 ((uint32_t) m_routingProtocolNumber);
}

void
QKDv6CommandTag::Deserialize (TagBuffer i)
{  
    m_command = i.ReadU8 ();   
    m_routingProtocolNumber = i.ReadU32 ();   
    NS_LOG_DEBUG ("Deserialize m_command: " << m_command );
}

void
QKDv6CommandTag::Print (std::ostream &os) const
{  
    os << "Command: " << m_command << "\n";
    os << "m_routingProtocolNumber: " << m_routingProtocolNumber ;
}

void    
QKDv6CommandTag::SetCommand (char value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_command = value;
}

char  
QKDv6CommandTag::GetCommand (void) const{

    NS_LOG_FUNCTION  (this << m_command); 
    return m_command;
}

void    
QKDv6CommandTag::SetRoutingProtocolNumber (uint32_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_routingProtocolNumber = value;
}

uint32_t  
QKDv6CommandTag::GetRoutingProtocolNumber (void) const{

    NS_LOG_FUNCTION  (this << m_routingProtocolNumber); 
    return m_routingProtocolNumber;
}






 
NS_OBJECT_ENSURE_REGISTERED (QKDv6InternalTOSTag);


TypeId 
QKDv6InternalTOSTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDv6InternalTOSTag")
    .SetParent<Tag> ()
    .AddConstructor<QKDv6InternalTOSTag> () 
  ;
  return tid;
}
TypeId 
QKDv6InternalTOSTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
QKDv6InternalTOSTag::GetSerializedSize (void) const
{
  return sizeof(uint8_t); //+ 2 * sizeof(uint32_t)
}
void 
QKDv6InternalTOSTag::Serialize (TagBuffer i) const
{    
    i.WriteU8 (m_tos);

}
void 
QKDv6InternalTOSTag::Deserialize (TagBuffer i)
{   
    m_tos = i.ReadU8 ();
}
void 
QKDv6InternalTOSTag::Print (std::ostream &os) const
{
    NS_LOG_FUNCTION (this);     
    os << "m_tos=" << m_tos;
} 
void 
QKDv6InternalTOSTag::SetTos (uint8_t value)
{
    NS_LOG_FUNCTION (this << (uint32_t) value);
    m_tos = value;
}
uint8_t 
QKDv6InternalTOSTag::GetTos (void) const
{
    NS_LOG_FUNCTION (this << (uint32_t) m_tos);
    return m_tos;
} 


NS_OBJECT_ENSURE_REGISTERED (QKDv6InternalTag);


TypeId 
QKDv6InternalTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDv6InternalTag")
    .SetParent<Tag> ()
    .AddConstructor<QKDv6InternalTag> ()
    .AddAttribute ("Encrypt",
                   "Should Enrypt",
                   EmptyAttributeValue (),
                   MakeUintegerAccessor (&QKDv6InternalTag::GetEncryptValue),
                   MakeUintegerChecker<uint8_t> ())
    .AddAttribute ("Authenticate",
                   "Should Authenticate",
                   EmptyAttributeValue (),
                   MakeUintegerAccessor (&QKDv6InternalTag::GetAuthenticateValue),
                   MakeUintegerChecker<uint8_t> ())
  ;
  return tid;
}
TypeId 
QKDv6InternalTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
QKDv6InternalTag::GetSerializedSize (void) const
{
  return 2 * sizeof(uint8_t) + sizeof(uint32_t);
}
void 
QKDv6InternalTag::Serialize (TagBuffer i) const
{
  i.WriteU8 (m_encryptValue);
  i.WriteU8 (m_authenticateValue);
  i.WriteU32 (m_maxDelay);
}
void 
QKDv6InternalTag::Deserialize (TagBuffer i)
{
  m_encryptValue = i.ReadU8 ();
  m_authenticateValue = i.ReadU8 ();
  m_maxDelay = i.ReadU32 ();
}
void 
QKDv6InternalTag::Print (std::ostream &os) const
{
    NS_LOG_FUNCTION (this);
    os << "e=" << (uint32_t)m_encryptValue << "a=" << (uint32_t)m_authenticateValue;
}
void 
QKDv6InternalTag::SetAuthenticateValue (uint8_t value)
{
    NS_LOG_FUNCTION (this);
    m_authenticateValue = value;
}
uint8_t 
QKDv6InternalTag::GetAuthenticateValue (void) const
{
    NS_LOG_FUNCTION (this);
    return m_authenticateValue;
}
void 
QKDv6InternalTag::SetEncryptValue (uint8_t value)
{
    NS_LOG_FUNCTION (this);
    m_encryptValue = value;
}
uint8_t 
QKDv6InternalTag::GetEncryptValue (void) const
{
    NS_LOG_FUNCTION (this);
    return m_encryptValue;
} 

void 
QKDv6InternalTag::SetMaxDelayValue (uint32_t value)
{
    NS_LOG_FUNCTION (this);
    m_maxDelay = value;
}
uint32_t 
QKDv6InternalTag::GetMaxDelayValue (void) const
{
    NS_LOG_FUNCTION (this);
    return m_maxDelay;
} 


} // namespace ns3
