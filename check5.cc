
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/wave-module.h"
#include "ns3/yans-wifi-helper.h"
#include <string>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include "Vehicle.h"

using std::cin ;
using std::cout ;
using std::endl ;
using std::string ;


NS_LOG_COMPONENT_DEFINE("WaveProtocolExample");

//Global Variables
static int indexa = 1 ;
Ipv4Address taAddress ;
pairing_t pairing;
element_t P0 ;
element_t P ;
NodeContainer nodes;
Ipv4InterfaceContainer interfaces ;

TypeId Vehicle::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::Vehicle")
        .SetParent<Application>()
        .AddConstructor<Vehicle>();
    return tid;
}

int Vehicle::count = 2220 ;

Vehicle::Vehicle() {
    NS_LOG_INFO("Vehicle created.");
    element_init_Zr(privKeyTA, pairing) ;
    element_init_G1(partialPrivKey, pairing) ;
    element_init_G1(privKeyV, pairing) ;
    element_init_G1(X, pairing) ;
    element_init_G1(Y, pairing) ;
    element_init_G1(Q, pairing) ;
    count++ ;
}
void Vehicle::setPartialPrivKey(element_t value) {
    element_set(partialPrivKey, value);
}

void Vehicle::getPartialPrivKey(element_t k) {
    element_set(k, partialPrivKey) ;
}
void Vehicle::setPrivKeyV(element_t value) {
    element_set(privKeyV, value);
}

void Vehicle::getPrivKeyV(element_t k) {
    element_set(k, privKeyV) ;
}
void Vehicle::setPrivKeyTA(element_t value) {
    element_set(privKeyTA, value);
}

void Vehicle::getPrivKeyTA(element_t k) {
    element_set(k, privKeyTA) ;
}

void Vehicle::getPublicKey(element_t x, element_t y) {
    element_set(x, X) ;
    element_set(y, Y) ;
}
void Vehicle::setPublicKey(element_t x, element_t y) {
    element_set(X, x) ;
    element_set(Y, y) ;
}

void Vehicle::setID(){
    ID = std::to_string(count) ;
}

string Vehicle::getID(){
    return ID ;
}

void Vehicle::setQ(element_t value){
    element_set(Q, value) ;
} 

void Vehicle::getQ(element_t k){
    element_set(k, Q) ;
} 

void sendID (Ptr<Socket> socket, const uint8_t* m, int s)
{
  Ptr<Packet> packet = Create<Packet>(m, s);
  socket->Send (packet);
}

void receiveIdAndSendPartialPrivateKey(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from))) {
        uint32_t size = packet->GetSize();
        uint8_t *buffer = new uint8_t[size];
        packet->CopyData(buffer, size);

        std::string str(reinterpret_cast<char*>(buffer), size);
        cout << "\n*********************************************************************************************\n" ;
        cout << "Vehicle ID : " << str << endl ;


        Ipv4Address ipaddress = (InetSocketAddress::ConvertFrom(from)).GetIpv4() ;
        cout << "\n*********************************************************************************************\n" ;
        cout << "Messages to " << ipaddress << endl ;
        
        element_t Q ;
        element_init_G1(Q, pairing) ;
        element_from_hash(Q,buffer, size) ;
        
        element_t s;
        element_init_Zr(s, pairing) ;
        Ptr<Application> baseApp = nodes.Get(0)->GetApplication(0);
        Ptr<Vehicle> ta = DynamicCast<Vehicle>(baseApp);
        ta->getPrivKeyTA(s) ;
        
        element_t D ;
        element_init_G1(D, pairing) ;
        element_mul_zn(D, Q, s) ;

        Ptr<Application> b = nodes.Get(indexa)->GetApplication(0);
        Ptr<Vehicle> v = DynamicCast<Vehicle>(b);
        v->setQ(Q) ;
        v->setPartialPrivKey(D) ;

        element_printf("TA : Your ID is\t\t\t= %B\n", Q) ;
        element_printf("TA : Your Partial Private Key \t= %B\n", D) ;
        // element_printf("TA : My private key \t\t= %B\n", s) ;
        delete[] buffer;

        
        int size_of_partial_key = element_length_in_bytes(D);
        uint8_t *buffer_partial_key = new uint8_t[size_of_partial_key];
        element_to_bytes(buffer_partial_key, D);
        socket->SendTo(Create<Packet>(buffer_partial_key, size_of_partial_key), 0, from);
    }
}

void ClientReceive(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))){
        Ipv4Address ipaddress = (InetSocketAddress::ConvertFrom(from)).GetIpv4() ;
            if(ipaddress == taAddress){
                cout << "\n*********************************************************************************************\n" ;
                cout << ipaddress << ": My Various Parameters are " << endl ;
                cout << "\n*********************************************************************************************\n" ;
                element_t x ;
                element_init_Zr(x, pairing) ;
                element_random(x) ;

                element_t D ;
                element_init_G1(D, pairing) ;

                Ptr<Application> b = nodes.Get(indexa++)->GetApplication(0);
                Ptr<Vehicle> v = DynamicCast<Vehicle>(b);
                v->getPartialPrivKey(D) ;

                element_t S ;
                element_init_G1(S, pairing) ;
                element_mul_zn(S, D, x) ;
                v->setPrivKeyV(S) ;

                element_t X ;
                element_init_G1(X, pairing) ;
                element_t Y ;
                element_init_G1(Y, pairing) ;
                element_mul_zn(X, P, x);
                element_mul_zn(Y, P0, x) ;
                v->setPublicKey(X, Y) ;

                element_t ATUL , ATUL2;
                element_init_G1(ATUL, pairing) ;
                element_init_G1(ATUL2, pairing) ;
                v->getQ(ATUL) ;
                element_printf("Q = %B\n", ATUL) ;
                v->getPartialPrivKey(ATUL) ;
                element_printf("D = %B\n", ATUL) ;
                v->getPrivKeyV(ATUL) ;
                element_printf("S = %B\n", ATUL) ;
                v->getPublicKey(ATUL, ATUL2) ;
                element_printf("X = %B\n", ATUL) ;
                element_printf("Y = %B\n", ATUL2) ;
            }
            else {
                cout << "I am somewhere else" << endl ;
            }
    }
    cout << "--------------------------------------------------------------------------\n" ;
}
int flag1 = 0 ;
element_t vR ;
element_t UR ;
element_t YR ;
    
void vehicle1Receive(Ptr<Socket> socket){    
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from))){
        uint32_t size = packet->GetSize();
        uint8_t *buffer = new uint8_t[size];
        packet->CopyData(buffer, size);

        if(flag1 == 0){
            std::string str(reinterpret_cast<char*>(buffer), size);
            // cout << str << endl ;
            flag1++ ;
            element_init_Zr(vR, pairing) ;
            element_init_G1(UR, pairing) ;
            element_init_G1(YR, pairing) ;
        }
        else if(flag1 == 1 ){
            element_from_bytes(vR, buffer) ;
            element_printf("received v = %B\n", vR) ;
            flag1++ ;
        }
        else if(flag1 == 2 ){
            element_from_bytes(UR, buffer) ;
            element_printf("received U = %B\n", UR) ;
            flag1++ ;
        }
        else if(flag1 == 3 ){
            element_from_bytes(YR, buffer) ;
            element_printf("received Y = %B\n", YR) ;
            flag1++ ;
            element_t nY ;
            element_init_G1(nY, pairing) ;
            element_invert(nY, YR) ;

            Ptr<Application> baseApp = nodes.Get(2)->GetApplication(0);
            Ptr<Vehicle> app1 = DynamicCast<Vehicle>(baseApp);
            element_t Q; element_init_G1(Q, pairing) ;
            app1->getQ(Q) ;
            // element_printf("Q here = %B\n", Q) ;
            
            element_t T1, B, T2 ;
            element_init_GT(T1, pairing) ;
            element_init_GT(T2, pairing) ;
            element_init_GT(B, pairing) ;
            pairing_apply(T1, UR, P, pairing) ;
            // element_printf("U = %B\n", UR) ;
            
            // element_printf("T1 = %B\n", T1) ;
            pairing_apply(B, Q, nY, pairing) ;
            // element_printf("B = %B\n", B) ;
            element_pow_zn(T2, B, vR);
            // element_printf("T2 = %B\n", T2) ;
            element_t R ;
            element_init_GT(R, pairing) ;
            element_mul(R, T1, T2) ;
            element_printf("Calculated R = %B\n", R) ;

            element_t V ;
            element_init_Zr(V, pairing) ;
            int size_of_r = element_length_in_bytes(R);
            uint8_t *buffer_r = new uint8_t[size_of_r];
            element_to_bytes(buffer_r, R);
            element_from_hash(V,buffer_r, size_of_r) ;
            element_printf("Calculated v = %B\n", V) ;


            if(element_cmp(V, vR)){
                cout << "Not Authorized as received and calculated v are not equal\n" << endl ;
            }
            else{
                cout << "Authorized as received and calculated v are equal\n" << endl ;
            }
            flag1 = 0 ;
            cout << "**********************************************************************************************\n" ;
        }
    }
}

void vehicle2Receive(Ptr<Socket> socket){
    cout << "Atul" << endl ;
}

void f(){
    Ptr<Socket> recvSocket1 = Socket::CreateSocket(nodes.Get(1), UdpSocketFactory::GetTypeId());
    InetSocketAddress l = InetSocketAddress(Ipv4Address::GetAny(), 10);
    recvSocket1->Bind(l);  // Bind to port 9
    recvSocket1->SetRecvCallback(MakeCallback(&vehicle1Receive));

    Ptr<Socket> vsocket = Socket::CreateSocket(nodes.Get(2), UdpSocketFactory::GetTypeId());
    vsocket->Bind() ;
    vsocket->Connect(InetSocketAddress(interfaces.GetAddress(1), 10));
    vsocket->SetRecvCallback(MakeCallback(&vehicle2Receive)) ;

    cout << "\n*********************************************************************************************\n" ;
    cout << "Communication between V1 and V2" ;
    cout << "\n*********************************************************************************************\n" ;
    for (uint32_t i = 1; i < nodes.GetN(); ++i) {
        Ptr<Node> node = nodes.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();  // Get the Ipv4 object

        Ipv4Address ipAddress = ipv4->GetAddress(1, 0).GetLocal();  // Get the IP address of interface 1
        std::cout << "Vehicle " << i << " IP Address\t: " << ipAddress << std::endl;
    }
    
    std::string message = "BRAKE NOT WORKING" ;

    Ptr<Application> baseApp = nodes.Get(2)->GetApplication(0);
    Ptr<Vehicle> app2 = DynamicCast<Vehicle>(baseApp);

    element_t a ;
    element_init_Zr(a, pairing) ;
    element_random(a) ;

    element_t r ;
    element_t base ;
    element_init_GT(base, pairing) ;
    pairing_apply(base, P, P, pairing) ;
    element_init_GT(r, pairing) ;
    element_pow_zn(r, base, a);

    element_t v ;
    element_init_Zr(v, pairing) ;
    int size_of_r = element_length_in_bytes(r);
    uint8_t *buffer_r = new uint8_t[size_of_r];
    element_to_bytes(buffer_r, r);
    element_from_hash(v,buffer_r, size_of_r) ;

    element_t U ;
    element_init_G1(U, pairing) ;
    element_t VSA ;
    element_init_G1(VSA, pairing) ;
    element_t AP ;
    element_init_G1(AP, pairing) ;
    element_mul_zn(AP, P, a) ;
    element_t S2 ;
    element_init_G1(S2, pairing) ;
    app2->getPrivKeyV(S2) ;
    element_mul_zn(VSA, S2, v) ;
    element_add(U, VSA, AP) ;
    element_t X2, Y2 ;
    element_init_G1(Y2, pairing) ;
    element_init_G1(X2, pairing) ;
    app2->getPublicKey(X2, Y2) ;
    element_printf("Y2 originally \t= %B\n", Y2) ;
    // element_printf("S2 here = %B\n", S2) ;
    element_printf("U originally \t= %B\n", U) ;
    element_printf("v originally \t= %B\n", v) ;
    element_printf("r originally \t= %B\n", r) ;
    cout << endl ;
    cout << "\n*********************************************************************************************\n" ;
    
    
    Simulator::Schedule(Seconds(20.0), &sendID, vsocket, (const uint8_t*)message.c_str(), message.size());

    int size_of_v = element_length_in_bytes(v);
    uint8_t *buffer_v = new uint8_t[size_of_v];
    element_to_bytes(buffer_v, v);
    // vsocket->Send(Create<Packet>(buffer_v, size_of_v));
    std::string str2(reinterpret_cast<char*>(buffer_v), size_of_v);
    Simulator::Schedule(Seconds(60.0), &sendID, vsocket, buffer_v, size_of_v);  

    int size_of_U = element_length_in_bytes(U);
    uint8_t *buffer_U = new uint8_t[size_of_U];
    element_to_bytes(buffer_U, U);
    std::string str3(reinterpret_cast<char*>(buffer_U), size_of_U);
    Simulator::Schedule(Seconds(100.0), &sendID, vsocket, buffer_U, size_of_U);  
   


    int size_of_Y2 = element_length_in_bytes(Y2);
    uint8_t *buffer_Y2 = new uint8_t[size_of_Y2];
    element_to_bytes(buffer_Y2, Y2);
    std::string str4(reinterpret_cast<char*>(buffer_Y2), size_of_Y2);
    Simulator::Schedule(Seconds(140.0), &sendID, vsocket, buffer_Y2, size_of_Y2);  



    Simulator::Schedule(Seconds(200.0), &sendID, vsocket, (const uint8_t*)message.c_str(), message.size());

    // int size_of_v = element_length_in_bytes(v);
    // uint8_t *buffer_v = new uint8_t[size_of_v];
    // element_to_bytes(buffer_v, v);
    // vsocket->Send(Create<Packet>(buffer_v, size_of_v));
    // std::string str2(reinterpret_cast<char*>(buffer_v), size_of_v);
    Simulator::Schedule(Seconds(240.0), &sendID, vsocket, buffer_v, size_of_v);  

    // int size_of_U = element_length_in_bytes(U);
    // uint8_t *buffer_U = new uint8_t[size_of_U];
    // element_to_bytes(buffer_U, U);
    // std::string str3(reinterpret_cast<char*>(buffer_U), size_of_U);
    Simulator::Schedule(Seconds(280.0), &sendID, vsocket, buffer_U, size_of_U);  
   


    int size_of_X2 = element_length_in_bytes(X2);
    uint8_t *buffer_X2 = new uint8_t[size_of_X2];
    element_to_bytes(buffer_X2, X2);
    // std::string str4(reinterpret_cast<char*>(buffer_Y2), size_of_Y2);
    Simulator::Schedule(Seconds(300.0), &sendID, vsocket, buffer_X2, size_of_X2);  
}
int main(int argc, char *argv[])
{
    CommandLine cmd;
    cmd.Parse(argc, argv);

    // Set time resolution to nanoseconds
    Time::SetResolution(Time::NS);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    
    pbc_param_t param;
    pbc_param_init_a_gen(param, 160, 512);
    pairing_init_pbc_param(pairing, param);
    cout << "\n*********************************************************************************************\n" ;

    /*************************************************************************************************************** */
    
    element_init_G1(P, pairing);
    element_random(P);
    element_printf("Generator P \t= %B\n", P) ;
    
    element_t s ;
    element_init_Zr(s, pairing) ;
    element_random(s) ;
    element_printf("Master key s \t= %B\n", s);
    
    element_init_G1(P0, pairing);
    element_mul_zn(P0, P, s) ;
    element_printf("Public Key  \t=%B\n", P0);
    /*************************************************************************************************************** */

    nodes.Create(3);

    
    // Configure the mobility model (nodes are placed statically for simplicity)
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0),
                                  "MinY", DoubleValue(0.0),
                                  "DeltaX", DoubleValue(50.0),
                                  "DeltaY", DoubleValue(0.0),
                                  "GridWidth", UintegerValue(2),
                                  "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // Configure the physical layer and channel
    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default();
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    Ptr<YansWifiChannel> channel = wifiChannel.Create ();
    wifiPhy.SetChannel (channel);
    // wifiPhy.SetChannel(wifiChannel.Create());
    wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11);
    NqosWaveMacHelper wifi80211pMac = NqosWaveMacHelper::Default ();
    Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default ();
    // if (verbose)
    // {
    //     wifi80211p.EnableLogComponents ();      // Turn on all Wifi 802.11p logging
    // }

    wifi80211p.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                      "DataMode",StringValue ("OfdmRate6MbpsBW10MHz"),
                                      "ControlMode",StringValue ("OfdmRate6MbpsBW10MHz"));

  // Set Tx Power
    wifiPhy.Set ("TxPowerStart",DoubleValue (20.0));
    wifiPhy.Set ("TxPowerEnd", DoubleValue (20.0));

    NetDeviceContainer devices = wifi80211p.Install (wifiPhy, wifi80211pMac, nodes);
 
    wifiPhy.EnablePcap("wave-simulation", devices.Get(0));

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    interfaces = address.Assign(devices);

    Ptr<Node> node1 = nodes.Get(0);
    Ptr<Ipv4> ipv41 = node1->GetObject<Ipv4>(); 
    taAddress = ipv41->GetAddress(1, 0).GetLocal();  
    std::cout << "TA IP Address\t\t: " << taAddress << std::endl;

    for (uint32_t i = 1; i < nodes.GetN(); ++i) {
        Ptr<Node> node = nodes.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();  // Get the Ipv4 object

        Ipv4Address ipAddress = ipv4->GetAddress(1, 0).GetLocal();  // Get the IP address of interface 1
        std::cout << "Vehicle " << i << " IP Address\t: " << ipAddress << std::endl;
    }

    Ptr<Socket> recvSocket = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 9);
    recvSocket->Bind(local);  // Bind to port 9
    recvSocket->SetRecvCallback(MakeCallback(&receiveIdAndSendPartialPrivateKey));
   
    
    Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(1), UdpSocketFactory::GetTypeId());
    socket->Bind() ;
    socket->Connect(InetSocketAddress(interfaces.GetAddress(0), 9));
    socket->SetRecvCallback(MakeCallback(&ClientReceive));
    // InetSocketAddress v1local = InetSocketAddress(v1Address);
    // socket->Bind(v1local) ;
    
   

    Ptr<Socket> socket2 = Socket::CreateSocket(nodes.Get(2), UdpSocketFactory::GetTypeId());
    socket2->Bind() ;
    socket2->Connect(InetSocketAddress(interfaces.GetAddress(0), 9));
    socket2->SetRecvCallback(MakeCallback(&ClientReceive));
    // InetSocketAddress v2local = InetSocketAddress(v2Address);
    // socket2->Bind(v2local) ;
    
    

    Ptr<Vehicle> app0 = CreateObject<Vehicle>();
    nodes.Get(0)->AddApplication(app0);
    app0->setPrivKeyTA(s);
   
    Ptr<Vehicle> app1 = CreateObject<Vehicle>();
    nodes.Get(1)->AddApplication(app1);
    app1->setID() ;
    string id1 = app1->getID() ;

    cout << "\n*********************************************************************************************\n" ;
    cout << "Vehicle1 : Sending my ID " << id1 << " to TA" << endl ;
    // Ptr<Packet> packet1 = Create<Packet>((const uint8_t*)id1.c_str(), id1.size());
    // socket->Send(packet1);
    Simulator::Schedule(Seconds(20.0), &sendID, socket, (const uint8_t*)id1.c_str(), id1.size());
    // sleep(5) ;

    Ptr<Vehicle> app2 = CreateObject<Vehicle>();
    nodes.Get(2)->AddApplication(app2);
    app2->setID() ;
    string id2 = app2->getID() ;
    cout << "Vehicle2 : Sending my ID " << id2 << " to TA" << endl ;
    // Ptr<Packet> packet2 = Create<Packet>((const uint8_t*)id2.c_str(), id2.size());
    Simulator::Schedule(Seconds(40.0), &sendID, socket2, (const uint8_t*)id2.c_str(), id2.size());
    // socket2->Send(packet2);
    // socket2->Close() ;
    // socket->Close() ;
    

    // cout << "\n*********************************************************************************************\n" ;
    
    // sleep(20) ;
    // socket->Close() ;
    // socket2->Close() ;
    // recvSocket->Close() ;

 
    
    // vsocket->Send(Create<Packet>(buffer_Y2, size_of_Y2));

    Simulator::Schedule(Seconds(200.0), &f);
    
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
