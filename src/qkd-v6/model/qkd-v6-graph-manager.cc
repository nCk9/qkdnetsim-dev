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
 *
 * QKDv6GraphManager is a singleton class!
 */

#include "ns3/qkd-v6-graph-manager.h" 
 
namespace ns3 {
 
NS_LOG_COMPONENT_DEFINE ("QKDv6GraphManager");

NS_OBJECT_ENSURE_REGISTERED (QKDv6GraphManager);

TypeId QKDv6GraphManager::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::QKDv6GraphManager")
    .SetParent<Object> () 
    ; 
  return tid;
}

bool QKDv6GraphManager::instanceFlag = false;
Ptr<QKDv6TotalGraph> QKDv6GraphManager::m_totalGraph = 0;
QKDv6GraphManager* QKDv6GraphManager::single = NULL;
QKDv6GraphManager* QKDv6GraphManager::getInstance()
{
    if(!instanceFlag){
		m_totalGraph = CreateObject<QKDv6TotalGraph> ("QKD Total Graph", "png");
		single = new QKDv6GraphManager();
		instanceFlag = true;
    }
    return single;
}

QKDv6GraphManager::~QKDv6GraphManager(){
	instanceFlag = false;
	delete single;

}

Ptr<QKDv6TotalGraph> 
QKDv6GraphManager::GetTotalGraph(){
	return m_totalGraph;
}

void
QKDv6GraphManager::PrintGraphs(){ 

    NS_LOG_FUNCTION (this);
	m_totalGraph->PrintGraph();
	for (std::vector<std::vector<QKDv6Graph *> >::iterator i = m_graphs.begin();i != m_graphs.end(); ++i)
	{   
		for (std::vector<QKDv6Graph *>::iterator j = i->begin(); j != i->end(); ++j)
        { 
            if((*j)!=0)
            {
		        (*j)->PrintGraph();
		        delete *j;
            }
        }
	}  
}
 
 
void
QKDv6GraphManager::SendCurrentChangeValueToGraph(const uint32_t& nodeID,const uint32_t& bufferPosition,const uint32_t& value){

    NS_LOG_FUNCTION (this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMCurrent(value);
}

void
QKDv6GraphManager::SendStatusValueToGraph(const uint32_t& nodeID, const uint32_t& bufferPosition,const uint32_t& value){

    NS_LOG_FUNCTION (this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMStatus(value);
}

void
QKDv6GraphManager::SendThresholdValueToGraph(const uint32_t& nodeID, const uint32_t& bufferPosition, const uint32_t& value){

    NS_LOG_FUNCTION (this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMThrStatus(value);
}

void 
QKDv6GraphManager::ProcessCurrentChange(std::string context, uint32_t value)
{ 
	//std::cout << Simulator::Now() << "\t" << context << value << "\t\n" ;
	int nodeId=0; 
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/$ns3::QKDManager/BufferList/%d/*", &nodeId, &bufferPosition);
 
	QKDv6GraphManager::single->SendCurrentChangeValueToGraph (nodeId, bufferPosition, value);  
}

void 
QKDv6GraphManager::ProcessStatusChange(std::string context, uint32_t value)
{
	//NodeList/0/$ns3::QKDManager/BufferList/0/CurrentChange
	int nodeId=0;
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/$ns3::QKDManager/BufferList/%d/*", &nodeId, &bufferPosition);

	QKDv6GraphManager::single->SendStatusValueToGraph (nodeId, bufferPosition, value);  
}

void 
QKDv6GraphManager::ProcessThresholdChange(std::string context, uint32_t value)
{
	//NodeList/0/$ns3::QKDManager/BufferList/0/ThresholdChange
	int nodeId=0; 
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/$ns3::QKDManager/BufferList/%d/*", &nodeId, &bufferPosition);
 
	QKDv6GraphManager::single->SendThresholdValueToGraph (nodeId, bufferPosition, value);  
}


// FOR QKD TOTAL GRAPH 
void 
QKDv6GraphManager::ProcessCurrentIncrease(std::string context, uint32_t value)
{
 	m_totalGraph->ProcessMCurrent(value, '+');
}

// FOR QKD TOTAL GRAPH 
void 
QKDv6GraphManager::ProcessCurrentDecrease(std::string context, uint32_t value)
{ 
	m_totalGraph->ProcessMCurrent(value, '-');
}

// FOR QKD TOTAL GRAPH 
void 
QKDv6GraphManager::ProcessThresholdIncrease(std::string context, uint32_t value)
{
	m_totalGraph->ProcessMThr(value, '+');
}

// FOR QKD TOTAL GRAPH 
void 
QKDv6GraphManager::ProcessThresholdDecrease(std::string context, uint32_t value)
{ 
	m_totalGraph->ProcessMThr(value, '-');
}
 
void 
QKDv6GraphManager::AddBuffer(uint32_t nodeID, uint32_t bufferPosition, std::string graphName, std::string graphType)
{ 	    
    NS_LOG_FUNCTION (this << nodeID << bufferPosition << graphName);
	  
	if(m_graphs.size() <= nodeID)
		m_graphs.resize(nodeID+1);
	
	if(m_graphs.size() == 0)
		m_graphs[nodeID] = std::vector<QKDv6Graph *> ();

	if(m_graphs[nodeID].size() <= bufferPosition)
		m_graphs[nodeID].resize(bufferPosition+1);

	//only svg,png and tex graph file are allowd for now
	std::string graphTypeFilter = (graphType=="svg" || graphType=="png" || graphType=="tex") ? graphType : "png";	
	m_graphs[nodeID][bufferPosition] = new QKDv6Graph (nodeID, bufferPosition, graphName, graphTypeFilter);

	std::ostringstream currentPath;
	currentPath << "/NodeList/" << nodeID << "/$ns3::QKDManager/BufferList/" << bufferPosition << "/CurrentChange"; 
 	
	std::string query(currentPath.str());
    Config::Connect(query, MakeCallback (&QKDv6GraphManager::ProcessCurrentChange));
    NS_LOG_FUNCTION (this << query);

	std::ostringstream statusPath; 
	statusPath << "/NodeList/" << nodeID << "/$ns3::QKDManager/BufferList/" << bufferPosition << "/StatusChange";
	std::string query2(statusPath.str());
    Config::Connect(query2, MakeCallback (&QKDv6GraphManager::ProcessStatusChange)); 
    NS_LOG_FUNCTION (this << query2);

	std::ostringstream MthrPath; 
	MthrPath << "/NodeList/" << nodeID << "/$ns3::QKDManager/BufferList/" << bufferPosition << "/ThresholdChange";
	std::string query3 (MthrPath.str());
    Config::Connect (query3, MakeCallback (&QKDv6GraphManager::ProcessThresholdChange)); 
    NS_LOG_FUNCTION (this << query3);

    //FOR QKD TOTAL GRAPH

	std::ostringstream currentPathIncrease;
	currentPathIncrease << "/NodeList/" << nodeID << "/$ns3::QKDManager/BufferList/" << bufferPosition << "/CurrentIncrease"; 
	std::string query4(currentPathIncrease.str());
    Config::Connect(query4, MakeCallback (&QKDv6GraphManager::ProcessCurrentIncrease));
    NS_LOG_FUNCTION (this << query4);

	std::ostringstream currentPathDecrease;
	currentPathDecrease << "/NodeList/" << nodeID << "/$ns3::QKDManager/BufferList/" << bufferPosition << "/CurrentDecrease"; 
	std::string query5(currentPathDecrease.str());
    Config::Connect(query5, MakeCallback (&QKDv6GraphManager::ProcessCurrentDecrease));
    NS_LOG_FUNCTION (this << query5);

	std::ostringstream currentPathMthrIncrease;
	currentPathMthrIncrease << "/NodeList/" << nodeID << "/$ns3::QKDManager/BufferList/" << bufferPosition << "/ThresholdIncrease"; 
	std::string query6(currentPathMthrIncrease.str());
    Config::Connect(query6, MakeCallback (&QKDv6GraphManager::ProcessThresholdIncrease));
    NS_LOG_FUNCTION (this << query6);

	std::ostringstream currentPathMthrDecrease;
	currentPathMthrDecrease << "/NodeList/" << nodeID << "/$ns3::QKDManager/BufferList/" << bufferPosition << "/ThresholdDecrease"; 
	std::string query7(currentPathMthrDecrease.str());
    Config::Connect(query7, MakeCallback (&QKDv6GraphManager::ProcessThresholdDecrease));
    NS_LOG_FUNCTION (this << query7);

    m_graphs[nodeID][bufferPosition]->InitTotalGraph();
}
}

