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

// Network topology
//              n1(Eve)
//                |
//                |
//         n0 ---p2p--- n2
//           |---qkd---|
//
// - udp flows from n0 to n2

#include <fstream>
#include <cstdlib>
#include "ns3/core-module.h" 
#include "ns3/applications-module.h"
#include "ns3/internet-module.h" 
#include "ns3/flow-monitor-module.h" 
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/gnuplot.h" 

#include "ns3/qkd-helper.h" 
#include "ns3/qkd-app-charging-helper.h"
#include "ns3/qkd-send.h"

#include "ns3/aodv-module.h" 
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
 
#include "ns3/network-module.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/internet-apps-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_CHANNEL_TEST");
   
uint32_t m_bytes_total = 0; 
uint32_t m_bytes_received = 0; 
uint32_t m_bytes_sent = 0; 
uint32_t m_packets_received = 0; 
double m_time = 0;

void
SentPacket(std::string context, Ptr<const Packet> p){

    m_bytes_sent += p->GetSize();  
}

void
ReceivedPacket(std::string context, Ptr<const Packet> p, const Address& addr){
     
    m_bytes_received += p->GetSize(); 
    m_bytes_total += p->GetSize(); 
    m_packets_received++;

}

void
Ratio(uint32_t m_bytes_sent, uint32_t m_packets_sent ){
    std::cout << "Sent (bytes):\t" <<  m_bytes_sent
    << "\tReceived (bytes):\t" << m_bytes_received 
    << "\nSent (Packets):\t" <<  m_packets_sent
    << "\tReceived (Packets):\t" << m_packets_received 
    
    << "\nRatio (bytes):\t" << (float)m_bytes_received/(float)m_bytes_sent
    << "\tRatio (packets):\t" << (float)m_packets_received/(float)m_packets_sent << "\n";
}

 
int main (int argc, char *argv[])
{
    Packet::EnablePrinting(); 
    PacketMetadata::Enable ();
    //
    // Explicitly create the nodes required by the topology (shown above).
    //
    NS_LOG_INFO ("Create nodes.");
    NodeContainer n;
    n.Create (2); 
    // NodeContainer n1; //for eavesdropper
    // n1.Create(1);

    NodeContainer n0n1 = NodeContainer (n.Get(0), n.Get (1));
    // NodeContainer node2 = NodeContainer (n1.Get(0));
    //Enable OLSR
    //AodvHelper routingProtocol;
    OlsrHelper routingProtocol;
    // DsdvHelper routingProtocol; 
      
    InternetStackHelper internet;
    // internet.Install()
    internet.SetRoutingHelper (routingProtocol);
    internet.Install (n);
    // internet.Install(n1);
    // InternetStackHelper internet2;
    // // internet.Install()
    // internet2.SetRoutingHelper (routingProtocol);
    // // internet.Install (n);
    // internet2.Install(n1);
    // Set Mobility for all nodes
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
    positionAlloc ->Add(Vector(0, 200, 0)); // node0 
    positionAlloc ->Add(Vector(200, 200, 0)); // node1
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);

    // MobilityHelper mobility2; //locating node 2, Eve the attacker
    // Ptr<ListPositionAllocator> positionAlloc2 = CreateObject <ListPositionAllocator>();
    // positionAlloc2 ->Add(Vector(400, 200, 0)); // node2 
    // mobility2.SetPositionAllocator(positionAlloc2);
    // mobility2.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    // mobility2.Install(n1);   
    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 

    NetDeviceContainer d0d1 = p2p.Install (n0n1); 
    //
    // We've got the "hardware" in place.  Now we need to add IP addresses.
    // 
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;

    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i1 = ipv4.Assign (d0d1);
    // Ipv4AddressHelper ipv4Eve;
    // ipv4Eve.SetBase ("10.1.2.0", "255.255.255.0");
    // Ipv4Address address = ipv4Eve.NewAddress();
    // std :: cout << "Attacker's address : " << address << "\n";
    //
    // Explicitly create the channels required by the topology (shown above).
    //
    //  install QKD Managers on the nodes 
    QKDHelper QHelper;  
    QHelper.InstallQKDManager (n); 
 

    //create QKD connection between nodes 0 and 1 
    NetDeviceContainer qkdNetDevices01 = QHelper.InstallQKD (
        d0d1.Get(0), d0d1.Get(1),
        1048576,    //min
        11324620, //thr
        52428800,   //max
        52428800     //current    //20485770
    );
   
    //Create graph to monitor buffer changes
    QHelper.AddGraph(n.Get(0), d0d1.Get(0)); //srcNode, destinationAddress, BufferTitle
 
    //Create graph to monitor buffer changes
    // QHelper.AddGraph(n.Get(1), d0d1.Get(0)); //srcNode, destinationAddress, BufferTitle

    NS_LOG_INFO ("Create Applications.");

    std::cout << "Source IP address: " << i0i1.GetAddress(0) << std::endl;
    std::cout << "Destination IP address: " << i0i1.GetAddress(1) << std::endl;
    //polarization assignment
    int N = 10000; //number of qbits (photons)
    std :: vector<int> alice (N, 0);
    std :: vector<int> bob (N, 0);
    srand(time(NULL));
    // std :: cout << "Alice's polarzations: ";
    for(int i=0; i<N; i++)
    {
        long int num = rand()%4 + 1;
        alice[i] = num;
        // std :: cout << alice[i] << " ";
    }
    // std :: cout << "\nBob's polarization: ";
    for(int i=0; i<N; i++)
    {
        long int num = rand()%4 + 1;
        bob[i] = num;
        // std :: cout << bob[i] << " ";
    }
    int ct=0, ct_1=0, ct_2=0, ct_3=0, ct_4=0;
    std :: vector<int> key(N, 0);
    for(int i=0; i<N; i++)
    {
        if(alice[i] == bob[i])
            key[i] = alice[i],
            ct++;
        if(key[i] == 1)
            ct_1++;
        else if(key[i] == 2)
            ct_2++;
        else if(key[i] == 3)
            ct_3++;
        else if(key[i] == 4)
            ct_4++;
    }
        
    std :: cout << "QKD key length: " << ct << "\n";
    std :: cout << "ct_1: " << ct_1 << " ct_2: " << ct_2 << " ct_3: " << ct_3 << " ct_4: " << ct_4 << "\n";

    // //man in the middle attack
    // std :: vector<int> attacker (N, 0);
    // int p=1;
    // for(int i=0; i<ct; i++)
    // {
    //     attacker[i] = p;
    //     p++;
    //     if(p == 4)
    //         p %= 4;
    // }

    /* QKD APPs for charging  */
    QKDAppChargingHelper qkdChargingApp("ns3::TcpSocketFactory", i0i1.GetAddress(0),  i0i1.GetAddress(1), 3072000);
    ApplicationContainer qkdChrgApps = qkdChargingApp.Install ( d0d1.Get(0), d0d1.Get(1) );
    qkdChrgApps.Start (Seconds (5.));
    qkdChrgApps.Stop (Seconds (1500.)); 

    /* Create user's traffic between v0 and v1 */
    /* Create sink app */
    uint16_t sinkPort = 8080;
    QKDSinkAppHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
    ApplicationContainer sinkApps = packetSinkHelper.Install (n.Get (1));
    sinkApps.Start (Seconds (25.));
    sinkApps.Stop (Seconds (300.));
    

    /* Create source app  */
    Address sinkAddress (InetSocketAddress (i0i1.GetAddress(1), sinkPort));
    Address sourceAddress (InetSocketAddress (i0i1.GetAddress(0), sinkPort));
    Ptr<Socket> socket = Socket::CreateSocket (n.Get (0), UdpSocketFactory::GetTypeId ());
 
    Ptr<QKDSend> app = CreateObject<QKDSend> ();
    app->Setup (socket, sourceAddress, sinkAddress, 640, 5, DataRate ("160kbps"));
    n.Get (0)->AddApplication (app);
    app->SetStartTime (Seconds (25.));
    app->SetStopTime (Seconds (300.));
  
    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////

    //if we need we can create pcap files
    p2p.EnablePcapAll ("QKD_channel_test");  

    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDSend/Tx", MakeCallback(&SentPacket));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDSink/Rx", MakeCallback(&ReceivedPacket));
 
    Simulator::Stop (Seconds (50));
    Simulator::Run ();

    Ratio(app->sendDataStats(), app->sendPacketStats());
 
    //Finally print the graphs
    QHelper.PrintGraphs();
    Simulator::Destroy ();
}
