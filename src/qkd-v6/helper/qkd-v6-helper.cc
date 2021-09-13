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

#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/queue.h"
#include "ns3/config.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/names.h"
#include "ns3/mpi-interface.h"
#include "ns3/mpi-receiver.h"
#include "ns3/qkd-v6-net-device.h" 
#include "ns3/qkd-v6-manager.h" 
#include "ns3/internet-module.h"
#include "ns3/random-variable-stream.h"
#include "ns3/trace-helper.h" 
#include "ns3/qkd-l4-traffic-control-layer.h"
#include "ns3/traffic-control-module.h"
#include "ns3/virtual-ipv6-l3-protocol.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/virtual-tcp-l4-protocol.h"
#include "ns3/qkd-v6-graph-manager.h" 
#include "qkd-v6-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDv6Helper");

QKDv6Helper::QKDv6Helper ()
{ 
    m_deviceFactory.SetTypeId ("ns3::QKDv6NetDevice"); 
    m_tcpFactory.SetTypeId ("ns3::VirtualTcpL4Protocol");

    m_useRealStorages = false;
    m_portOverlayNumber = 667; 
    m_channelID = 0; 
    m_routing = 0; 
    m_counter = 0;
    m_QCrypto = CreateObject<QKDv6Crypto> (); 
    m_supportQKDL4 = 1;
}  

void 
QKDv6Helper::SetDeviceAttribute (std::string n1, const AttributeValue &v1)
{
    m_deviceFactory.Set (n1, v1);
}

/**
*   Enable Pcap recording
*/
void 
QKDv6Helper::EnablePcapInternal (std::string prefix, Ptr<NetDevice> nd, bool promiscuous, bool explicitFilename)
{
     
    //
    // All of the Pcap enable functions vector through here including the ones
    // that are wandering through all of devices on perhaps all of the nodes in
    // the system.  We can only deal with devices of type QKDv6NetDevice.
    //
    Ptr<QKDv6NetDevice> device = nd->GetObject<QKDv6NetDevice> ();
    if (device == 0 || device->GetNode()->GetObject<QKDv6Manager> () == 0)
    {
      NS_LOG_INFO ("QKDv6Helper::EnablePcapInternal(): Device " << device << " is not related with QKD TCP/IP stack");
      return;
    }

    PcapHelper pcapHelper;

    std::string filename;
    if (explicitFilename)
    {
      filename = prefix;
    }
    else
    {
      filename = pcapHelper.GetFilenameFromDevice (prefix, device);
    }

    Ptr<PcapFileWrapper> file = pcapHelper.CreateFile (filename, std::ios::out, 
                                                     PcapHelper::DLT_RAW  );
    pcapHelper.HookDefaultSink<QKDv6NetDevice> (device, "PromiscSniffer", file);  
}

/**
*   Enable ASCII recording
*/
void 
QKDv6Helper::EnableAsciiInternal (
  Ptr<OutputStreamWrapper> stream, 
  std::string prefix, 
  Ptr<NetDevice> nd,
  bool explicitFilename)
{
     
    //
    // All of the ascii enable functions vector through here including the ones
    // that are wandering through all of devices on perhaps all of the nodes in
    // the system.  We can only deal with devices of type QKDv6NetDevice.
    //
    Ptr<QKDv6NetDevice> device = nd->GetObject<QKDv6NetDevice> ();
    if (device == 0)
    {
      NS_LOG_INFO ("QKDv6Helper::EnableAsciiInternal(): Device " << device << 
                   " not of type ns3::QKDv6NetDevice");
      return;
    }

    //
    // Our default trace sinks are going to use packet printing, so we have to 
    // make sure that is turned on.
    //
    Packet::EnablePrinting ();

    //
    // If we are not provided an OutputStreamWrapper, we are expected to create 
    // one using the usual trace filename conventions and do a Hook*WithoutContext
    // since there will be one file per context and therefore the context would
    // be redundant.
    //
    if (stream == 0)
    {
      //
      // Set up an output stream object to deal with private ofstream copy 
      // constructor and lifetime issues.  Let the helper decide the actual
      // name of the file given the prefix.
      //
      AsciiTraceHelper asciiTraceHelper;

      std::string filename;
      if (explicitFilename)
        {
          filename = prefix;
        }
      else
        {
          filename = asciiTraceHelper.GetFilenameFromDevice (prefix, device);
        }

      Ptr<OutputStreamWrapper> theStream = asciiTraceHelper.CreateFileStream (filename);

      //
      // The MacRx trace source provides our "r" event.
      //
      asciiTraceHelper.HookDefaultReceiveSinkWithoutContext<QKDv6NetDevice> (device, "MacRx", theStream);

      //
      // The "+", '-', and 'd' events are driven by trace sources actually in the
      // transmit queue.
      // 
      Ptr<Queue<Packet> > queue = device->GetQueue ();
      asciiTraceHelper.HookDefaultEnqueueSinkWithoutContext<Queue<Packet> > (queue, "Enqueue", theStream);
      asciiTraceHelper.HookDefaultDropSinkWithoutContext<Queue<Packet> > (queue, "Drop", theStream);
      asciiTraceHelper.HookDefaultDequeueSinkWithoutContext<Queue<Packet> > (queue, "Dequeue", theStream);

      // PhyRxDrop trace source for "d" event
      asciiTraceHelper.HookDefaultDropSinkWithoutContext<QKDv6NetDevice> (device, "PhyRxDrop", theStream);

      return;
    }

    //
    // If we are provided an OutputStreamWrapper, we are expected to use it, and
    // to providd a context.  We are free to come up with our own context if we
    // want, and use the AsciiTraceHelper Hook*WithContext functions, but for 
    // compatibility and simplicity, we just use Config::Connect and let it deal
    // with the context.
    //
    // Note that we are going to use the default trace sinks provided by the 
    // ascii trace helper.  There is actually no AsciiTraceHelper in sight here,
    // but the default trace sinks are actually publicly available static 
    // functions that are always there waiting for just such a case.
    //
    uint32_t nodeid = nd->GetNode ()->GetId ();
    uint32_t deviceid = nd->GetIfIndex ();
    std::ostringstream oss;

    oss << "/NodeList/" << nd->GetNode ()->GetId () << "/DeviceList/" << deviceid << "/$ns3::QKDv6NetDevice/MacRx";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultReceiveSinkWithContext, stream));

    oss.str ("");
    oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::QKDv6NetDevice/TxQueue/Enqueue";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultEnqueueSinkWithContext, stream));

    oss.str ("");
    oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::QKDv6NetDevice/TxQueue/Dequeue";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultDequeueSinkWithContext, stream));

    oss.str ("");
    oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::QKDv6NetDevice/TxQueue/Drop";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultDropSinkWithContext, stream));

    oss.str ("");
    oss << "/NodeList/" << nodeid << "/DeviceList/" << deviceid << "/$ns3::QKDv6NetDevice/PhyRxDrop";
    Config::Connect (oss.str (), MakeBoundCallback (&AsciiTraceHelper::DefaultDropSinkWithContext, stream));
}

/**
*   ADD QKDGraph
*   @param  Ptr<Node>       sourceNode
*   @param  Ptr<NetDevice>  device
*/
void 
QKDv6Helper::AddGraph(Ptr<Node> node, Ptr<NetDevice> device)
{
    AddGraph(node, device, "", "png");
}

/**
*   ADD QKDGraph
*   @param  Ptr<Node>       sourceNode
*   @param  Ptr<NetDevice>  device
*   @param  std::string     graphName    
*/
void 
QKDv6Helper::AddGraph(Ptr<Node> node, Ptr<NetDevice> device, std::string graphName)
{
    AddGraph(node, device, graphName, "png");
}
/**
*   ADD QKDGraph
*   @param  Ptr<Node>       sourceNode
*   @param  Ptr<NetDevice>  device
*   @param  std::string     graphName    
*   @param  std::string     graphType    
*/
void 
QKDv6Helper::AddGraph(Ptr<Node> node, Ptr<NetDevice> device, std::string graphName, std::string graphType)
{   

    NS_ASSERT (node != 0);
    NS_ASSERT (device != 0);

    uint32_t bufferPosition = node->GetObject<QKDv6Manager> ()->GetBufferPosition ( device->GetAddress() ); 
    NS_LOG_FUNCTION(this << node->GetId() << bufferPosition << device ); 

    Ptr<QKDv6Buffer> buffer = node->GetObject<QKDv6Manager> ()->GetBufferByBufferPosition (bufferPosition); 
    NS_ASSERT (buffer != 0);

    NS_LOG_FUNCTION(this << buffer << buffer->FetchState() << node->GetObject<QKDv6Manager> ()->GetNBuffers() );

    QKDv6GraphManager *QKDv6GraphManager = QKDv6GraphManager::getInstance();
    QKDv6GraphManager->AddBuffer(node->GetId(), bufferPosition, graphName, graphType);
}

/**
*   Print QKDGraphs
*/
void 
QKDv6Helper::PrintGraphs()
{    
    QKDv6GraphManager *QKDv6GraphManager = QKDv6GraphManager::getInstance();
    QKDv6GraphManager->PrintGraphs();
}

/**
*   Install QKDv6Manager on the node
*   @param  NodeContainer&  n
*/ 
void
QKDv6Helper::InstallQKDv6Manager (NodeContainer& n)
{   
    ObjectFactory factory;    
    factory.SetTypeId ("ns3::QKDv6Manager");
 
    for(uint16_t i=0; i< n.GetN(); i++)
    {   
        if(n.Get(i)->GetObject<QKDv6Manager> () == 0){
            Ptr<Object> manager = factory.Create <Object> ();  //one factory can be used to make a single type of object only
            n.Get(i)->AggregateObject (manager);  
            n.Get(i)->GetObject<QKDv6Manager> ()->UseRealStorages(m_useRealStorages);
        } 
    }
}

/**
*   Set routing protocol to be used in overlay QKDNetwork
*   @param  Ipv6RoutingHelper&  routing       
*/
void 
QKDv6Helper::SetRoutingHelper (const Ipv6RoutingHelper &routing)
{
  delete m_routing;
  m_routing = routing.Copy ();
}

/**
*   Help function used to aggregate protocols to the node such as virtual-tcp, virtual-udp, virtual-ipv6-l3
*   @param  Ptr<Node>           node
*   @param  const std::string   typeID
*/
void
QKDv6Helper::CreateAndAggregateObjectFromTypeId (Ptr<Node> node, const std::string typeId)
{
    ObjectFactory factory;
    factory.SetTypeId (typeId);
    Ptr<Object> protocol = factory.Create <Object> ();
    node->AggregateObject (protocol);
}

/**
*   Help function used to install and set overlay QKD network using default settings
*   and random values for QKDv6Buffers in single TCP/IP network. Usefull for testing
*   @param  Ptr<NetDevice>  a
*   @param  Ptr<NetDevice>  b
*/ 
NetDeviceContainer 
QKDv6Helper::InstallQKD (
    Ptr<NetDevice> a, 
    Ptr<NetDevice> b
)
{ 
    //################################
    //  SINGLE TCP/IP NETWORK
    //################################

    Ptr<UniformRandomVariable> random = CreateObject<UniformRandomVariable> (); 
    return InstallQKD (
        a, 
        b,  
        1000000,    //1 Megabit
        0, 
        100000000, //1000 Megabit
        random->GetValue ( 1000000, 100000000)
    ); 
}


/**
*   Help function used to install and set overlay QKD network using default settings
*   and random values for QKDv6Buffers in OVERLAY NETWORK. Usefull for testing
*   @param  Ptr<NetDevice>  a
*   @param  Ptr<NetDevice>  b
*/ 
NetDeviceContainer 
QKDv6Helper::InstallOverlayQKD (
    Ptr<NetDevice> a, 
    Ptr<NetDevice> b
)
{
    //################################
    //  OVERLAY NETWORK
    //################################
 
    std::string address;

    // address = "2001:1::" + (++m_counter); 
    Ipv6InterfaceAddress da (Ipv6Address ("2001:1::"),  Ipv6Prefix (64));

    // address = "11.0.0." + (++m_counter);
    Ipv6InterfaceAddress db (Ipv6Address ("2001:1::"),  Ipv6Prefix (64));
    
    Ptr<UniformRandomVariable> random = CreateObject<UniformRandomVariable> ();

    return InstallOverlayQKD (
        a, 
        b, 
        da, 
        db, 
        1000000,    //1 Megabit
        0, 
        1000000000, //1000 Megabit
        random->GetValue ( 1000000, 1000000000)
    ); 
}


 
/**
*   Install and setup OVERLAY QKD link between the nodes
*   @param  Ptr<NetDevice>          IPa
*   @param  Ptr<NetDevice>          IPb
*   @param  Ipv6InterfaceAddress    IPQKDaddressA
*   @param  Ipv6InterfaceAddress    IPQKDaddressB
*   @param  uint32_t                Mmin
*   @param  uint32_t                Mthr
*   @param  uint32_t                Mmmax
*   @param  uint32_t                Mcurrent
*/
NetDeviceContainer
QKDv6Helper::InstallOverlayQKD(
    Ptr<NetDevice>          IPa, //IP Net device of underlay network on node A
    Ptr<NetDevice>          IPb, //IP Net device of underlay network on node B
    Ipv6InterfaceAddress    IPQKDaddressA,  //IP address of overlay network on node A
    Ipv6InterfaceAddress    IPQKDaddressB,  //IP address of overlay network on node B  
    uint32_t                Mmin, //Buffer details
    uint32_t                Mthr, //Buffer details
    uint32_t                Mmax, //Buffer details
    uint32_t                Mcurrent //Buffer details
){
    return InstallOverlayQKD(
        IPa, //IP Net device of underlay network on node A
        IPb, //IP Net device of underlay network on node B
        IPQKDaddressA,  //IP address of overlay network on node A
        IPQKDaddressB,  //IP address of overlay network on node B  
        Mmin, //Buffer details
        Mthr, //Buffer details
        Mmax, //Buffer details
        Mcurrent, //Buffer details
        "ns3::UdpSocketFactory"
    );
}
 
/**
*   Install and setup OVERLAY QKD link between the nodes
*   @param  Ptr<NetDevice>          IPa
*   @param  Ptr<NetDevice>          IPb
*   @param  Ipv6InterfaceAddress    IPQKDaddressA
*   @param  Ipv6InterfaceAddress    IPQKDaddressB
*   @param  uint32_t                Mmin
*   @param  uint32_t                Mthr
*   @param  uint32_t                Mmmax
*   @param  uint32_t                Mcurrent
*   @param  std::string             Underlying protocol type
*/
NetDeviceContainer
QKDv6Helper::InstallOverlayQKD(
    Ptr<NetDevice>          IPa,            //IP Net device of underlay network on node A
    Ptr<NetDevice>          IPb,            //IP Net device of underlay network on node B
    Ipv6InterfaceAddress    IPQKDaddressA,  //IP address of overlay network on node A
    Ipv6InterfaceAddress    IPQKDaddressB,  //IP address of overlay network on node B  
    uint32_t                Mmin,           //Buffer details
    uint32_t                Mthr,           //Buffer details
    uint32_t                Mmax,           //Buffer details
    uint32_t                Mcurrent,       //Buffer details
    const std::string       typeId         //Protocol which is used in the underlying network for connection
)
{
    //################################
    //  OVERLAY NETWORK
    //################################
 
    /////////////////////////////////
    // Virtual IPv6L3 Protocol
    /////////////////////////////////

    Ptr<Node> a = IPa->GetNode();    
    Ptr<Node> b = IPb->GetNode();

    NS_LOG_FUNCTION(this << a->GetId() << b->GetId());

    // Set virtual IPv6L3 on A     
    if (a->GetObject<VirtualIpv6L3Protocol> () == 0){
        CreateAndAggregateObjectFromTypeId (a, "ns3::VirtualIpv6L3Protocol");  
  
        //Install Routing Protocol
        Ptr<VirtualIpv6L3Protocol> Virtualipv6a_temp = a->GetObject<VirtualIpv6L3Protocol> ();
        Ptr<Ipv6RoutingProtocol> ipv6Routinga_temp = m_routing->Create (a);
        Virtualipv6a_temp->SetRoutingProtocol (ipv6Routinga_temp);
    } 

    if( m_supportQKDL4 && a->GetObject<QKDL4TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (a, "ns3::QKDL4TrafficControlLayer");

    if( a->GetObject<TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (a, "ns3::TrafficControlLayer");

    //Install UDPL4 and TCPL4 
    if( a->GetObject<VirtualUdpL4Protocol> () == 0){ 
        CreateAndAggregateObjectFromTypeId (a, "ns3::VirtualUdpL4Protocol"); 
        a->AggregateObject (m_tcpFactory.Create<Object> ()); 
    }

    NS_ASSERT (a->GetObject<VirtualIpv6L3Protocol> () != 0);


    /////////////////////////////////
    //          NODE A
    /////////////////////////////////

    //install new QKDv6NetDevice on node A
    Ptr<QKDv6NetDevice> devA = m_deviceFactory.Create<QKDv6NetDevice> (); 
    devA->SetAddress (Mac48Address::Allocate ()); 
    devA->SetSendCallback (MakeCallback (&QKDv6Manager::VirtualSendOverlay, a->GetObject<QKDv6Manager> () ));
    a->AddDevice (devA);

    //Setup QKD NetDevice and interface    
    Ptr<VirtualIpv6L3Protocol> Virtualipv6a = a->GetObject<VirtualIpv6L3Protocol> ();  
    uint32_t i = Virtualipv6a->AddInterface (devA); 
    Virtualipv6a->AddAddress (i, IPQKDaddressA);
    Virtualipv6a->SetUp (i);

    //Get address of classical device which is used for connection on the lower layer
    Ptr<Ipv6> ipv6a = a->GetObject<Ipv6L3Protocol> ();
    uint32_t interfaceOfClassicalDeviceOnNodeA = ipv6a->GetInterfaceForDevice(IPa);
    Ipv6InterfaceAddress netA = ipv6a->GetAddress (interfaceOfClassicalDeviceOnNodeA, 0);

 
    /////////////////////////////////
    //          NODE B
    /////////////////////////////////

    // Set virtual IPv6L3 on B
    if (b->GetObject<VirtualIpv6L3Protocol> () == 0){
        CreateAndAggregateObjectFromTypeId (b, "ns3::VirtualIpv6L3Protocol");
        //Install Routing Protocol
        Ptr<VirtualIpv6L3Protocol> Virtualipv6b_temp = b->GetObject<VirtualIpv6L3Protocol> ();
        Ptr<Ipv6RoutingProtocol> ipv6Routingb_temp = m_routing->Create (b);
        Virtualipv6b_temp->SetRoutingProtocol (ipv6Routingb_temp); 
    }
         
    if( m_supportQKDL4 && b->GetObject<QKDL4TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (b, "ns3::QKDL4TrafficControlLayer");
    
    if( b->GetObject<TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (b, "ns3::TrafficControlLayer");

    //Install UDPL4 and TCPL4 
    if( b->GetObject<VirtualUdpL4Protocol> () == 0){
        CreateAndAggregateObjectFromTypeId (b, "ns3::VirtualUdpL4Protocol");  
        b->AggregateObject (m_tcpFactory.Create<Object> ()); 
    }
    NS_ASSERT (b->GetObject<VirtualIpv6L3Protocol> () != 0); 

    //install new QKDv6NetDevice on node B 
    Ptr<QKDv6NetDevice> devB = m_deviceFactory.Create<QKDv6NetDevice> ();
    devB->SetAddress (Mac48Address::Allocate ()); 
    devB->SetSendCallback (MakeCallback (&QKDv6Manager::VirtualSendOverlay, b->GetObject<QKDv6Manager> () ));
    b->AddDevice (devB);

    //Setup QKD NetDevice and interface 
    Ptr<VirtualIpv6L3Protocol> Virtualipv6b = b->GetObject<VirtualIpv6L3Protocol> ();
    uint32_t j = Virtualipv6b->AddInterface (devB);
    Virtualipv6b->AddAddress (j, IPQKDaddressB);
    Virtualipv6b->SetUp (j); 

    //Get address of classical device which is used for connection of QKDv6NetDevice on lower layer
    Ptr<Ipv6> ipv6b = b->GetObject<Ipv6L3Protocol> ();
    uint32_t interfaceOfClassicalDeviceOnNodeB = ipv6b->GetInterfaceForDevice(IPb);
    Ipv6InterfaceAddress netB = ipv6b->GetAddress (interfaceOfClassicalDeviceOnNodeB, 0);    
    
    Ptr<Socket> m_socketA;
    Ptr<Socket> m_socketB;
    Ptr<Socket> m_socketA_sink;
    Ptr<Socket> m_socketB_sink;


    /////////////////////////////////
    // QKD Traffic Control  - queues on QKD Netdevices (L2)
    // Optional usage, that is the reason why the length of the queue is only 1
    /////////////////////////////////
    
    //TCH for net devices on overlay L2
    NetDeviceContainer qkdv6NetDevices;
    qkdv6NetDevices.Add(devA);
    qkdv6NetDevices.Add(devB);
     
    //TCH for net devices on underlay L2
    NetDeviceContainer UnderlayNetDevices;
    UnderlayNetDevices.Add(IPa);
    UnderlayNetDevices.Add(IPb);

    TrafficControlHelper tchUnderlay;
    tchUnderlay.Uninstall(UnderlayNetDevices);
    uint16_t handleUnderlay = tchUnderlay.SetRootQueueDisc ("ns3::QKDL2PfifoFastQueueDisc");
    tchUnderlay.AddInternalQueues (handleUnderlay, 3, "ns3::DropTailQueue<QueueDiscItem>", "MaxSize", StringValue ("1000p"));
    //tchUnderlay.AddPacketFilter (handleUnderlay, "ns3::PfifoFastIpv6PacketFilter");
    QueueDiscContainer qdiscsUnderlay = tchUnderlay.Install (UnderlayNetDevices);  
    


    /*
        In NS3, TCP is not bidirectional. Therefore, we need to create separate sockets for listening and sending
    */
    if(typeId == "ns3::TcpSocketFactory"){

        Address inetAddrA (Inet6SocketAddress (ipv6a->GetAddress (interfaceOfClassicalDeviceOnNodeA, 0).GetAddress (), m_portOverlayNumber) ); 
        Address inetAddrB (Inet6SocketAddress (ipv6b->GetAddress (interfaceOfClassicalDeviceOnNodeB, 0).GetAddress (), m_portOverlayNumber) );
        
        // SINK SOCKETS
     
        //create TCP Sink socket on A
        m_socketA_sink = Socket::CreateSocket (a, TypeId::LookupByName ("ns3::TcpSocketFactory"));
        m_socketA_sink->Bind ( inetAddrA ); 
        m_socketA_sink->BindToNetDevice ( IPa );
        m_socketA_sink->Listen ();
        m_socketA_sink->ShutdownSend ();   
        m_socketA_sink->SetRecvCallback (MakeCallback (&QKDv6Manager::VirtualReceive, a->GetObject<QKDv6Manager> () ));
        m_socketA_sink->SetAcceptCallback (
            MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
            MakeCallback (&QKDv6Manager::HandleAccept, a->GetObject<QKDv6Manager> () )
        );

        
        //create TCP Sink socket on B
        m_socketB_sink = Socket::CreateSocket (b, TypeId::LookupByName ("ns3::TcpSocketFactory"));
        m_socketB_sink->Bind ( inetAddrB ); 
        m_socketB_sink->BindToNetDevice ( IPb );
        m_socketB_sink->Listen ();
        m_socketB_sink->ShutdownSend ();  
        m_socketB_sink->SetRecvCallback (MakeCallback (&QKDv6Manager::VirtualReceive, b->GetObject<QKDv6Manager> () ));
        m_socketB_sink->SetAcceptCallback (
            MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
            MakeCallback (&QKDv6Manager::HandleAccept, b->GetObject<QKDv6Manager> () )
        );

        // SEND SOCKETS
        
        //create TCP Send socket 
        m_socketA = Socket::CreateSocket (a, TypeId::LookupByName ("ns3::TcpSocketFactory"));
        m_socketA->Bind ();  
        m_socketA->SetConnectCallback (
            MakeCallback (&QKDv6Manager::ConnectionSucceeded, a->GetObject<QKDv6Manager> () ),
            MakeCallback (&QKDv6Manager::ConnectionFailed,    a->GetObject<QKDv6Manager> () )); 
        m_socketA->Connect ( inetAddrB ); 
        m_socketA->ShutdownRecv ();

        //create TCP Send socket 
        m_socketB = Socket::CreateSocket (b, TypeId::LookupByName ("ns3::TcpSocketFactory"));
        m_socketB->Bind ();  
        m_socketB->SetConnectCallback (
            MakeCallback (&QKDv6Manager::ConnectionSucceeded, b->GetObject<QKDv6Manager> () ),
            MakeCallback (&QKDv6Manager::ConnectionFailed,    b->GetObject<QKDv6Manager> () )); 
        m_socketB->Connect ( inetAddrA ); 
        m_socketB->ShutdownRecv (); 
 
    } else {

        //create UDP socket
        Inet6SocketAddress inetAddrA (ipv6a->GetAddress (interfaceOfClassicalDeviceOnNodeA, 0).GetAddress (), m_portOverlayNumber);
        m_socketA = Socket::CreateSocket (a, TypeId::LookupByName ("ns3::UdpSocketFactory"));
        m_socketA->Bind ( inetAddrA );
        m_socketA->BindToNetDevice ( IPa );
        m_socketA->SetRecvCallback (MakeCallback (&QKDv6Manager::VirtualReceive, a->GetObject<QKDv6Manager> () )); 

        //create UDP socket
        Inet6SocketAddress inetAddrB (ipv6b->GetAddress (interfaceOfClassicalDeviceOnNodeB, 0).GetAddress (), m_portOverlayNumber);
        m_socketB = Socket::CreateSocket (b, TypeId::LookupByName ("ns3::UdpSocketFactory"));
        m_socketB->Bind ( inetAddrB ); 
        m_socketB->BindToNetDevice ( IPb );
        m_socketB->SetRecvCallback (MakeCallback (&QKDv6Manager::VirtualReceive, b->GetObject<QKDv6Manager> () ));
         
        m_socketA_sink = m_socketA;
        m_socketB_sink = m_socketB;
    }

    /////////////////////////////////
    // UDP AND TCP SetDownTarget to QKD Priority Queues which sit between L3 and L4
    /////////////////////////////////

    //------------------------------------------
    // Forward from TCP/UDP L4 to QKD Queues
    //------------------------------------------
    if( m_supportQKDL4 ){

        QKDL4TrafficControlHelper qkdTch;
        uint16_t QKDhandle = qkdTch.SetRootQueueDisc ("ns3::QKDL4PfifoFastQueueDisc");
        qkdTch.AddInternalQueues (QKDhandle, 3, "ns3::DropTailQueue<QueueDiscItem>", "MaxSize", StringValue ("1000p"));
        //qkdTch.AddPacketFilter (QKDhandle, "ns3::PfifoFastQKDPacketFilter");
        QueueDiscContainer QKDqdiscsA = qkdTch.Install (a);
        QueueDiscContainer QKDqdiscsB = qkdTch.Install (b);

        //NODE A
        //Forward UDP communication from L4 to QKD Queues
        Ptr<VirtualUdpL4Protocol> udpA = a->GetObject<VirtualUdpL4Protocol> (); 
        udpA->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, a->GetObject<QKDL4TrafficControlLayer> ()));

        //Forward TCP communication from L4 to QKD Queues
        Ptr<VirtualTcpL4Protocol> tcpA = a->GetObject<VirtualTcpL4Protocol> (); 
        tcpA->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, a->GetObject<QKDL4TrafficControlLayer> ()));

        //NODE B
        //Forward UDP communication from L4 to QKD Queues
        Ptr<VirtualUdpL4Protocol> udpB = b->GetObject<VirtualUdpL4Protocol> (); 
        udpB->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, b->GetObject<QKDL4TrafficControlLayer> () ));

        //Forward TCP communication from L4 to QKD Queues
        Ptr<VirtualTcpL4Protocol> tcpB = b->GetObject<VirtualTcpL4Protocol> (); 
        tcpB->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, b->GetObject<QKDL4TrafficControlLayer> ()));
        
        //------------------------------------------
        // Forward from QKD Queues to Virtual IPv6 L3
        //------------------------------------------

        //Forward TCP communication from L4 to Virtual L3
        Ptr<QKDL4TrafficControlLayer> QKDTCLa = a->GetObject<QKDL4TrafficControlLayer> (); 
        QKDTCLa->SetDownTarget6 (MakeCallback (&VirtualIpv6L3Protocol::Send, a->GetObject<VirtualIpv6L3Protocol> ()));

        //Forward TCP communication from L4 to Virtual L3
        Ptr<QKDL4TrafficControlLayer> QKDTCLb = b->GetObject<QKDL4TrafficControlLayer> (); 
        QKDTCLb->SetDownTarget6 (MakeCallback (&VirtualIpv6L3Protocol::Send, b->GetObject<VirtualIpv6L3Protocol> ()));

    }

    /////////////////////////////////
    // Store details in QKD Managers
    // which are in charge to create QKD buffers  
    /////////////////////////////////
 
    //MASTER on node A
    if(a->GetObject<QKDv6Manager> () != 0){
        a->GetObject<QKDv6Manager> ()->AddNewLink( 
            devA, //QKDv6NetDevice on node A
            devB, //QKDv6NetDevice on node B
            IPa,  //IPNetDevice on node A
            IPb,  //IPNetDevice on node B
            m_QCrypto,
            m_socketA,
            m_socketA_sink,
            typeId,
            m_portOverlayNumber, 
            IPQKDaddressA, //QKD IP Src Address - overlay device
            IPQKDaddressB, //QKD IP Dst Address - overlay device 
            netA,  //IP Src Address - underlay device
            netB,  //IP Dst Address - underlay device 
            true,  
            Mmin, 
            Mthr, 
            Mmax, 
            Mcurrent,
            m_channelID
        ); 
    }
    
    //SLAVE on node B
    if(b->GetObject<QKDv6Manager> () != 0){
        b->GetObject<QKDv6Manager> ()->AddNewLink( 
            devB, //QKDv6NetDevice on node B
            devA, //QKDv6NetDevice on node A
            IPb,  //IPNetDevice on node B
            IPa,  //IPNetDevice on node A
            m_QCrypto,
            m_socketB,
            m_socketB_sink,
            typeId,
            m_portOverlayNumber, 
            IPQKDaddressB, //QKD IP Dst Address - overlay device 
            IPQKDaddressA, //QKD IP Src Address - overlay device
            netB,  //IP Dst Address - underlay device 
            netA,  //IP Src Address - underlay device
            false,              
            Mmin, 
            Mthr, 
            Mmax, 
            Mcurrent,
            m_channelID++
        ); 
    } 

    /**
    *   Initial load in QKD Buffers
    *   @ToDo: Currently buffers do not whole real data due to reduction of simlation time and computation complexity.
    *           Instead, they only keep the number of current amount of key material, but not the real key material in memory
    */
    if(m_useRealStorages){ 
        Ptr<QKDv6Buffer> bufferA = a->GetObject<QKDv6Manager> ()->GetBufferBySourceAddress(IPQKDaddressA.GetAddress ()); 
        Ptr<QKDv6Buffer> bufferB = b->GetObject<QKDv6Manager> ()->GetBufferBySourceAddress(IPQKDaddressB.GetAddress ());

        NS_LOG_FUNCTION(this << "!!!!!!!!!!!!!!" << bufferA->GetBufferId() << bufferB->GetBufferId() );

        uint32_t packetSize = 32;
        for(uint32_t i = 0; i < Mcurrent; i++ )
        {
            bufferA->AddNewContent(packetSize);
            bufferB->AddNewContent(packetSize);
        }
    }

    
    if(typeId == "ns3::TcpSocketFactory")
        m_portOverlayNumber++;

    return qkdv6NetDevices;
}

/**
*   Install and setup SINGLE TCP/IP QKD link between the nodes
*   @param  Ptr<NetDevice>          IPa
*   @param  Ptr<NetDevice>          IPb 
*   @param  uint32_t                Mmin
*   @param  uint32_t                Mthr
*   @param  uint32_t                Mmmax
*   @param  uint32_t                Mcurrent 
*/
NetDeviceContainer
QKDv6Helper::InstallQKD(
    Ptr<NetDevice>          IPa,            //IP Net device of underlay network on node A
    Ptr<NetDevice>          IPb,            //IP Net device of underlay network on node B
    uint32_t                Mmin,           //Buffer details
    uint32_t                Mthr,           //Buffer details
    uint32_t                Mmax,           //Buffer details
    uint32_t                Mcurrent        //Buffer details
)
{
    //################################
    //  SINGLE TCP/IP NETWORK
    //################################ 

    IPa->SetSniffPacketFromDevice(false);
    IPb->SetSniffPacketFromDevice(false);

    /////////////////////////////////
    // IPv6L3 Protocol and QKDL2 Traffic controller
    /////////////////////////////////

    Ptr<Node> a = IPa->GetNode();    
    Ptr<Node> b = IPb->GetNode();

    NS_LOG_FUNCTION(this << a->GetId() << b->GetId());

    /////////////////////////////////
    //          NODE A
    /////////////////////////////////

    if( m_supportQKDL4 && a->GetObject<QKDL4TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (a, "ns3::QKDL4TrafficControlLayer");

    if( a->GetObject<TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (a, "ns3::TrafficControlLayer");

    //Get address of classical device which is used for connection on the lower layer
    Ptr<Ipv6> ipv6a = a->GetObject<Ipv6L3Protocol> ();
    uint32_t interfaceOfClassicalDeviceOnNodeA = ipv6a->GetInterfaceForDevice(IPa);
    Ipv6InterfaceAddress netA = ipv6a->GetAddress (interfaceOfClassicalDeviceOnNodeA, 0);
      
    /////////////////////////////////
    //          NODE B
    /////////////////////////////////
   
    if( m_supportQKDL4 && b->GetObject<QKDL4TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (b, "ns3::QKDL4TrafficControlLayer");
    
    if( b->GetObject<TrafficControlLayer> () == 0)
        CreateAndAggregateObjectFromTypeId (b, "ns3::TrafficControlLayer");

    //Get address of classical device which is used for connection of QKDv6NetDevice on lower layer
    Ptr<Ipv6> ipv6b = b->GetObject<Ipv6L3Protocol> ();
    uint32_t interfaceOfClassicalDeviceOnNodeB = ipv6b->GetInterfaceForDevice(IPb);
    Ipv6InterfaceAddress netB = ipv6b->GetAddress (interfaceOfClassicalDeviceOnNodeB, 0);    
    
    Ptr<Socket> m_socketA;
    Ptr<Socket> m_socketB;
    Ptr<Socket> m_socketA_sink;
    Ptr<Socket> m_socketB_sink;

    /////////////////////////////////
    // UDP AND TCP SetDownTarget to QKD Priority Queues which sit between L3 and L4
    /////////////////////////////////

    //------------------------------------------
    // Forward from TCP/UDP L4 to QKD Queues
    //------------------------------------------

    if (m_supportQKDL4) {

        QKDL4TrafficControlHelper qkdTch;
        uint16_t QKDhandle = qkdTch.SetRootQueueDisc ("ns3::QKDL4PfifoFastQueueDisc");
        qkdTch.AddInternalQueues (QKDhandle, 3, "ns3::DropTailQueue<QueueDiscItem>", "MaxSize", StringValue ("1000p"));
        //qkdTch.AddPacketFilter (QKDhandle, "ns3::PfifoFastQKDPacketFilter");
        QueueDiscContainer QKDqdiscsA = qkdTch.Install (a);
        QueueDiscContainer QKDqdiscsB = qkdTch.Install (b);


        //------------------------------------------
        // Forward from QKD Queues to IPv6 L3
        //------------------------------------------

       //Forward L4 communication to IPv6 L3
        Ptr<QKDL4TrafficControlLayer> QKDTCLa = a->GetObject<QKDL4TrafficControlLayer> (); 
        IpL4Protocol::DownTargetCallback qkdl4DownTarget_a = QKDTCLa->GetDownTarget();

        //Set it only once, otherwise we will finish in infinite loop
        if(qkdl4DownTarget_a.IsNull()){
        
            //Node A
            Ptr<UdpL4Protocol> udpA = a->GetObject<UdpL4Protocol> (); 
            Ptr<TcpL4Protocol> tcpA = a->GetObject<TcpL4Protocol> (); 

            IpL4Protocol::DownTargetCallback udpA_L4_downTarget = udpA->GetDownTarget ();
            IpL4Protocol::DownTargetCallback tcpA_L4_downTarget = tcpA->GetDownTarget ();

            if(!udpA_L4_downTarget.IsNull ())
                QKDTCLa->SetDownTarget (udpA_L4_downTarget);
            else if(!tcpA_L4_downTarget.IsNull ())
                QKDTCLa->SetDownTarget (tcpA_L4_downTarget);
            else
                NS_ASSERT (!udpA_L4_downTarget.IsNull ());
            //QKDTCLa->SetDownTarget (MakeCallback (&Ipv6L3Protocol::Send, a->GetObject<Ipv6L3Protocol> ()));

            //NODE A
            //Forward UDP communication from L4 to QKD Queues
            udpA->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, a->GetObject<QKDL4TrafficControlLayer> ()));
            //Forward TCP communication from L4 to QKD Queues
            tcpA->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, a->GetObject<QKDL4TrafficControlLayer> ()));

        }



        Ptr<QKDL4TrafficControlLayer> QKDTCLb = b->GetObject<QKDL4TrafficControlLayer> (); 
        IpL4Protocol::DownTargetCallback qkdl4DownTarget_b = QKDTCLb->GetDownTarget();
        
        //Set it only once, otherwise we will finish in infinite loop
        if(qkdl4DownTarget_b.IsNull()){

            //Node B
            Ptr<UdpL4Protocol> udpB = b->GetObject<UdpL4Protocol> (); 
            Ptr<TcpL4Protocol> tcpB = b->GetObject<TcpL4Protocol> (); 

            //Forward L4 communication to IPv6 L3
            IpL4Protocol::DownTargetCallback udpB_L4_downTarget = udpB->GetDownTarget ();
            IpL4Protocol::DownTargetCallback tcpB_L4_downTarget = tcpB->GetDownTarget ();

            if(!udpB_L4_downTarget.IsNull ())
                QKDTCLb->SetDownTarget (udpB_L4_downTarget);
            else if(!tcpB_L4_downTarget.IsNull ())
                QKDTCLb->SetDownTarget (tcpB_L4_downTarget);
            else
                NS_ASSERT (!udpB_L4_downTarget.IsNull ());
            //QKDTCLb->SetDownTarget (MakeCallback (&Ipv6L3Protocol::Send, b->GetObject<Ipv6L3Protocol> ()));
     
            //NODE B
            //Forward UDP communication from L4 to QKD Queues
            udpB->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, b->GetObject<QKDL4TrafficControlLayer> () ));
            //Forward TCP communication from L4 to QKD Queues
            tcpB->SetDownTarget (MakeCallback (&QKDL4TrafficControlLayer::Send, b->GetObject<QKDL4TrafficControlLayer> ()));
            
        }

    } 

    /////////////////////////////////
    // QKD Traffic Control  - queues on QKD Netdevices (L2)
    // Optional usage
    /////////////////////////////////

    NetDeviceContainer qkdv6NetDevices;
    qkdv6NetDevices.Add(IPa);
    qkdv6NetDevices.Add(IPb);

    TrafficControlHelper tch;
    tch.Uninstall(qkdv6NetDevices); 
    uint16_t handle = tch.SetRootQueueDisc ("ns3::QKDL2SingleTCPIPPfifoFastQueueDisc");
    tch.AddInternalQueues (handle, 3, "ns3::DropTailQueue<QueueDiscItem>", "MaxSize", StringValue ("1000p"));
    //tch.AddPacketFilter (handle, "ns3::PfifoFastIpv6PacketFilter");
    QueueDiscContainer qdiscs = tch.Install (qkdv6NetDevices);     
    
    ///ONLY FOR SINGLE TCP/IP STACK NETWORK (not overlay)
    //Forward packet from NETDevice to QKDv6Manager to be processed (decrypted and authentication check);

    Ptr<TrafficControlLayer> tc_a = a->GetObject<TrafficControlLayer> ();
    NS_ASSERT (tc_a != 0);

    Ptr<TrafficControlLayer> tc_b = b->GetObject<TrafficControlLayer> ();
    NS_ASSERT (tc_b != 0);
 
    /**
    *   QKDv6Manager sits between NetDevice and TrafficControlLayer
    *   Therefore, we need unregister existing callbacks and create new callbakcs to QKDv6Manager  
    */
    a->UnregisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc_a ));//One for IP
    a->UnregisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc_a ));//One for ARP
 
    //a->UnregisterProtocolHandler (MakeCallback (&QKDv6Manager::VirtualReceiveSimpleNetwork, a->GetObject<QKDv6Manager> () ));
    //a->UnregisterProtocolHandler (MakeCallback (&QKDv6Manager::VirtualReceiveSimpleNetwork, a->GetObject<QKDv6Manager> () ));
    
    a->RegisterProtocolHandler (MakeCallback (&QKDv6Manager::VirtualReceiveSimpleNetwork, a->GetObject<QKDv6Manager> ()),
                                   Ipv6L3Protocol::PROT_NUMBER, IPa);
    a->RegisterProtocolHandler (MakeCallback (&QKDv6Manager::VirtualReceiveSimpleNetwork, a->GetObject<QKDv6Manager> ()),
                                   ArpL3Protocol::PROT_NUMBER, IPa);
      
    /**
    *   QKDv6Manager sits between NetDevice and TrafficControlLayer
    *   Therefore, we need unregister existing callbacks and create new callbakcs to QKDv6Manager 
    */
    b->UnregisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc_b ));//One for IP
    b->UnregisterProtocolHandler (MakeCallback (&TrafficControlLayer::Receive, tc_b ));//One for ARP
 
    //b->UnregisterProtocolHandler (MakeCallback (&QKDv6Manager::VirtualReceiveSimpleNetwork, b->GetObject<QKDv6Manager> () ));
    //b->UnregisterProtocolHandler (MakeCallback (&QKDv6Manager::VirtualReceiveSimpleNetwork, b->GetObject<QKDv6Manager> () ));

    b->RegisterProtocolHandler (MakeCallback (&QKDv6Manager::VirtualReceiveSimpleNetwork, b->GetObject<QKDv6Manager> ()),
                                   Ipv6L3Protocol::PROT_NUMBER, IPb);
    b->RegisterProtocolHandler (MakeCallback (&QKDv6Manager::VirtualReceiveSimpleNetwork, b->GetObject<QKDv6Manager> ()),
                                   ArpL3Protocol::PROT_NUMBER, IPb);
 
    /////////////////////////////////
    // Store details in QKD Managers
    // which are in charge to create QKD buffers  
    /////////////////////////////////
 
    //MASTER on node A
    if(a->GetObject<QKDv6Manager> () != 0){
        a->GetObject<QKDv6Manager> ()->AddNewLink( 
            0, //QKDv6NetDevice on node A
            0, //QKDv6NetDevice on node B
            IPa,  //IPNetDevice on node A
            IPb,  //IPNetDevice on node B
            m_QCrypto,
            0, //m_socketA = 0
            0, //m_socketA_sink = 0
            "", //sockettypeID
            m_portOverlayNumber, 
            netA, //QKD IP Src Address - overlay device - same as underlay
            netB, //QKD IP Dst Address - overlay device - same as underlay
            netA,  //IP Src Address - underlay device
            netB,  //IP Dst Address - underlay device 
            true,  
            Mmin, 
            Mthr, 
            Mmax, 
            Mcurrent,
            m_channelID
        ); 
    }
    
    //SLAVE on node B
    if(b->GetObject<QKDv6Manager> () != 0){
        b->GetObject<QKDv6Manager> ()->AddNewLink( 
            0, //QKDv6NetDevice on node B
            0, //QKDv6NetDevice on node A
            IPb,  //IPNetDevice on node B
            IPa,  //IPNetDevice on node A
            m_QCrypto,
            0, //m_socketB = 0
            0, //m_socketB_sink = 0
            "", //sockettypeID
            m_portOverlayNumber, 
            netB, //QKD IP Dst Address - overlay device - same as underlay
            netA, //QKD IP Src Address - overlay device - same as underlay
            netB,  //IP Dst Address - underlay device 
            netA,  //IP Src Address - underlay device
            false,              
            Mmin, 
            Mthr, 
            Mmax, 
            Mcurrent,
            m_channelID++
        ); 
    }  

    /**
    *   Initial load in QKD Buffers
    *   @ToDo: Currently buffers do not whole real data due to reduction of simlation time and computation complexity.
    *           Instead, they only keep the number of current amount of key material, but not the real key material in memory
    */
    if(m_useRealStorages){

        //Get buffer on node A which is pointed from netA 
        Ptr<QKDv6Buffer> bufferA = a->GetObject<QKDv6Manager> ()->GetBufferBySourceAddress(netA.GetAddress ());

        //Get buffer on node B which is pointed from netB 
        Ptr<QKDv6Buffer> bufferB = b->GetObject<QKDv6Manager> ()->GetBufferBySourceAddress(netB.GetAddress ()); 

        NS_LOG_FUNCTION(this << "!!!!!!!!!!!!!!" << bufferA->GetBufferId() << bufferB->GetBufferId() );

        uint32_t packetSize = 32;
        for(uint32_t i = 0; i < Mcurrent; i++ )
        {
            bufferA->AddNewContent(packetSize);
            bufferB->AddNewContent(packetSize);
        }
    }

    return qkdv6NetDevices;

    }
} // namespace ns3
