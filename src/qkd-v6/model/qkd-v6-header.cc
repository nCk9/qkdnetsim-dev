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
#include "qkd-v6-header.h"

namespace ns3 {
 
NS_LOG_COMPONENT_DEFINE ("QKDv6Header");

NS_OBJECT_ENSURE_REGISTERED (QKDv6CommandHeader);
 
QKDv6CommandHeader::QKDv6CommandHeader (){ 
    m_command = 'A';  
}

TypeId
QKDv6CommandHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::QKDv6CommandHeader")
    .SetParent<Header> ()
    .AddConstructor<QKDv6CommandHeader> ()
  ;
  return tid;
}

TypeId
QKDv6CommandHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
QKDv6CommandHeader::GetSerializedSize () const
{
  return sizeof(uint8_t) + sizeof(uint16_t);
}

void
QKDv6CommandHeader::Serialize (Buffer::Iterator i) const
{  
    i.WriteHtonU16 ((uint16_t) m_protocol);  
    i.WriteU8 ((uint8_t) m_command); 
}

uint32_t
QKDv6CommandHeader::Deserialize (Buffer::Iterator start)
{ 
    Buffer::Iterator i = start;  
    m_protocol = i.ReadNtohU16 ();  
    m_command = i.ReadU8 (); 
 
    NS_LOG_DEBUG ("Deserialize m_command: " << m_command  << " \n m_protocol: " << m_protocol);
   
    uint32_t dist = i.GetDistanceFrom (start);
    NS_ASSERT (dist == GetSerializedSize ());
    return dist;
}

void
QKDv6CommandHeader::Print (std::ostream &os) const
{  
    os << "Command: " << m_command << "\t"
       << "Protocol: " << (uint16_t) m_protocol << "\n";
}

bool
QKDv6CommandHeader::operator== (QKDv6CommandHeader const & o) const
{ 
    return (m_command == o.m_command);
}

std::ostream &
operator<< (std::ostream & os, QKDv6CommandHeader const & h)
{
    h.Print (os);
    return os;
} 


void 		
QKDv6CommandHeader::SetCommand (char value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_command = value;
}

char 	
QKDv6CommandHeader::GetCommand (void) const{

    NS_LOG_FUNCTION  (this << m_command); 
    return m_command;
}

void 		
QKDv6CommandHeader::SetProtocol (uint16_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_protocol = value;
}

uint16_t 	
QKDv6CommandHeader::GetProtocol (void) const{

    NS_LOG_FUNCTION  (this << m_protocol); 
    return m_protocol;
}


//////////////////////////////
//  QKD DELIMITER HEADER
///////////////////////////////




NS_OBJECT_ENSURE_REGISTERED (QKDv6DelimiterHeader);
 
QKDv6DelimiterHeader::QKDv6DelimiterHeader (){ 
    m_delimiter = 0;  
}

TypeId
QKDv6DelimiterHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::QKDv6DelimiterHeader")
    .SetParent<Header> ()
    .AddConstructor<QKDv6DelimiterHeader> ()
  ;
  return tid;
}

TypeId
QKDv6DelimiterHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
QKDv6DelimiterHeader::GetSerializedSize () const
{
  return sizeof(uint8_t);
}

void
QKDv6DelimiterHeader::Serialize (Buffer::Iterator i) const
{  
    i.WriteU8 ((uint8_t) m_delimiter);
}

uint32_t
QKDv6DelimiterHeader::Deserialize (Buffer::Iterator start)
{ 
    Buffer::Iterator i = start;  
    m_delimiter = i.ReadU8 ();   
 
    NS_LOG_DEBUG ("Deserialize m_delimiter: " << m_delimiter);
   
    uint32_t dist = i.GetDistanceFrom (start);
    NS_ASSERT (dist == GetSerializedSize ());
    return dist;
}

void
QKDv6DelimiterHeader::Print (std::ostream &os) const
{  
    os << "m_delimiter: " << (uint32_t) m_delimiter << "\n";
}

bool
QKDv6DelimiterHeader::operator== (QKDv6DelimiterHeader const & o) const
{ 
    return (m_delimiter == o.m_delimiter);
}

std::ostream &
operator<< (std::ostream & os, QKDv6DelimiterHeader const & h)
{
    h.Print (os);
    return os;
} 


void        
QKDv6DelimiterHeader::SetDelimiterSize (uint32_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_delimiter = value;
}

uint32_t    
QKDv6DelimiterHeader::GetDelimiterSize (void) const{

    NS_LOG_FUNCTION  (this << m_delimiter); 
    return (uint32_t) m_delimiter;
}
 

///////////////////////////////////
//  QKD HEADER
/////////////////////////////////



NS_OBJECT_ENSURE_REGISTERED (QKDv6Header);
 
QKDv6Header::QKDv6Header ():m_valid (true)
{ 
    m_length = 0;
    m_messageId = 0;
    m_encryped = 0;
    m_authenticated = 0;
    m_zipped = 0;
    m_version = 2;
    m_reserved = 0; 
    m_channelId = 0; 
    m_encryptionKeyId = 0;
    m_authenticationKeyId = 0; 
}

TypeId
QKDv6Header::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::QKDv6Header")
    .SetParent<Header> ()
    .AddConstructor<QKDv6Header> ()
  ;
  return tid;
}

TypeId
QKDv6Header::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
QKDv6Header::GetSerializedSize () const
{
  return 4  * sizeof(uint32_t) 
       + 1  * sizeof(uint16_t)
       + 5  * sizeof(uint8_t)
       + 33 * sizeof(uint8_t); //authTag 
}

void
QKDv6Header::Serialize (Buffer::Iterator i) const
{
    i.WriteHtonU32 ((uint32_t) m_length);
    i.WriteHtonU32 ((uint32_t) m_messageId);

    i.WriteU8 ((uint8_t) m_encryped);
    i.WriteU8 ((uint8_t) m_authenticated);
    i.WriteU8 ((uint8_t) m_zipped);
    i.WriteU8 ((uint8_t) m_version);
    i.WriteU8 ((uint8_t) m_reserved);
    i.WriteHtonU16 ((uint16_t) m_channelId);  
  
    i.WriteHtonU32 ((uint32_t) m_encryptionKeyId);
    i.WriteHtonU32 ((uint32_t) m_authenticationKeyId);  
    
    char tmpBuffer [m_authTag.length() + 1];
    NS_LOG_FUNCTION( "AUTHTAG:" << sizeof(tmpBuffer)/sizeof(tmpBuffer[0]) << " ---- " << m_authTag.length()  );
    strcpy (tmpBuffer, m_authTag.c_str());
    i.Write ((uint8_t *)tmpBuffer, m_authTag.length() + 1);
}

uint32_t
QKDv6Header::Deserialize (Buffer::Iterator start)
{

    Buffer::Iterator i = start; 
    m_valid = false;

    m_length = i.ReadNtohU32 (); 
    m_messageId = i.ReadNtohU32 ();

    m_encryped = i.ReadU8 ();
    m_authenticated = i.ReadU8 (); 
    m_zipped = i.ReadU8 ();
    m_version = i.ReadU8 (); 
    m_reserved = i.ReadU8 ();
    m_channelId = i.ReadNtohU16 (); 

    m_encryptionKeyId = i.ReadNtohU32 ();
    m_authenticationKeyId = i.ReadNtohU32 ();

    if(m_version == 2)
        m_valid = true;
     
    uint32_t len = 33;
    char tmpBuffer [len];
    i.Read ((uint8_t*)tmpBuffer, len);
    m_authTag = tmpBuffer;

    NS_LOG_DEBUG ("Deserialize m_length: " << (uint32_t) m_length 
                << " m_messageId: " << (uint32_t) m_messageId
                << " m_encryped: " << (uint32_t) m_encryped
                << " m_authenticated: " << (uint32_t) m_authenticated
                << " m_zipped: " << (uint32_t) m_zipped
                << " m_version: " << (uint32_t) m_version  
                << " m_reserved: " << m_reserved
                << " m_channelId: " << (uint32_t) m_channelId  
                << " m_encryptionKeyId: " << (uint32_t) m_encryptionKeyId
                << " m_authenticationKeyId: " << (uint32_t) m_authenticationKeyId 
                << " m_valid: " << (uint32_t) m_valid 
                << " m_authTag: " << m_authTag
    );
   
    uint32_t dist = i.GetDistanceFrom (start);
    NS_LOG_FUNCTION( this << dist << GetSerializedSize() );
    NS_ASSERT (dist == GetSerializedSize ());
    return dist;
}

void
QKDv6Header::Print (std::ostream &os) const
{  
    os << "\n"
       << "MESSAGE ID: "    << (uint32_t) m_messageId << "\t"
       << "Length: "        << (uint32_t) m_length << "\t"

       << "Authenticated: " << (uint32_t) m_authenticated << "\t"
       << "Encrypted: "     << (uint32_t) m_encryped << "\t"
       << "Zipped: "        << (uint32_t) m_zipped << "\t"
       << "Version: "       << (uint32_t) m_version << "\t"
       << "Reserved: "       << (uint32_t) m_reserved << "\t"
       << "ChannelID: "     << (uint32_t) m_channelId << "\t" 

       << "EncryptKeyID: "  << (uint32_t) m_encryptionKeyId << "\t" 
       << "AuthKeyID: "     << (uint32_t) m_authenticationKeyId << "\t"  
       
       << "AuthTag: "       << m_authTag << "\t\n";
       
}

bool
QKDv6Header::operator== (QKDv6Header const & o) const
{ 
    return (m_messageId == o.m_messageId && m_authenticationKeyId == o.m_authenticationKeyId && m_authTag == o.m_authTag);
}

std::ostream &
operator<< (std::ostream & os, QKDv6Header const & h)
{
    h.Print (os);
    return os;
} 
 

void 		
QKDv6Header::SetLength (uint32_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_length = value;
}
uint32_t 	
QKDv6Header::GetLength (void) const{

    NS_LOG_FUNCTION  (this << m_length); 
    return m_length;
}

void 		
QKDv6Header::SetMessageId (uint32_t value){
    
    NS_LOG_FUNCTION  (this << value); 
    m_messageId = value;
}
uint32_t 	
QKDv6Header::GetMessageId (void) const{
    
    NS_LOG_FUNCTION  (this << m_messageId); 
    return m_messageId;
}


void 		
QKDv6Header::SetEncrypted (uint32_t value){
    
    NS_LOG_FUNCTION  (this << value); 
    m_encryped = value;
}
uint32_t 	
QKDv6Header::GetEncrypted (void) const{

    NS_LOG_FUNCTION  (this << m_encryped); 
    return (uint32_t) m_encryped;
}


void 		
QKDv6Header::SetAuthenticated (uint32_t value){

    NS_LOG_FUNCTION  (this << value);
    m_authenticated = value;
}
uint32_t 	
QKDv6Header::GetAuthenticated (void) const{

    NS_LOG_FUNCTION  (this << m_authenticated); 
    return (uint32_t) m_authenticated;
}


void 		
QKDv6Header::SetZipped (uint8_t value){

    NS_LOG_FUNCTION  (this << value); 
    m_zipped = value;
}
uint8_t 	
QKDv6Header::GetZipped (void) const{

    NS_LOG_FUNCTION  (this << m_zipped); 
    return m_zipped;
}


void 		
QKDv6Header::SetVersion (uint8_t value){

    NS_LOG_FUNCTION  (this << value); 
    m_version = value;
}
uint8_t 	    
QKDv6Header::GetVersion (void) const{

    NS_LOG_FUNCTION  (this << m_version); 
    return m_version;
}

 
void 		
QKDv6Header::SetChannelId (uint16_t value){

    NS_LOG_FUNCTION  (this << value); 
    m_channelId = value;
}
uint16_t 	
QKDv6Header::GetChannelId (void) const{

    NS_LOG_FUNCTION  (this << m_channelId); 
    return m_channelId ; 
}


void 		
QKDv6Header::SetEncryptionKeyId (uint32_t value){

    NS_LOG_FUNCTION  (this << value); 
    m_encryptionKeyId = value; 
}
uint32_t 	
QKDv6Header::GetEncryptionKeyId (void) const{

    NS_LOG_FUNCTION  (this << m_encryptionKeyId); 
    return m_encryptionKeyId;
}


void 		
QKDv6Header::SetAuthenticationKeyId (uint32_t value){

    NS_LOG_FUNCTION  (this << value);  
    m_authenticationKeyId = value; 
}
uint32_t 	
QKDv6Header::GetAuthenticationKeyId (void) const{

    NS_LOG_FUNCTION  (this << m_authenticationKeyId); 
    return m_authenticationKeyId;
}


void 		
QKDv6Header::SetAuthTag (std::string value){

    NS_LOG_FUNCTION  (this << value << value.size());
    m_authTag = value;
}
std::string
QKDv6Header::GetAuthTag (void) const{

    NS_LOG_FUNCTION  (this << m_authTag << m_authTag.size());
    return m_authTag;
}
 

} // namespace ns3
