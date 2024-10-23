#include "ns3/node.h"
#include "ns3/nstime.h"
#include <pbc/pbc.h>
#include "ns3/application.h"

using  namespace ns3 ;

class Vehicle : public Application {
    public:
        static TypeId GetTypeId(void);
        Vehicle();
        void setPrivKeyTA(element_t value);
        void getPrivKeyTA(element_t k);
        void setPrivKeyV(element_t value);
        void getPrivKeyV(element_t k);
        void setQ(element_t value) ;
        void getQ(element_t k) ;
        void setPartialPrivKey(element_t value);
        void getPartialPrivKey(element_t k);
        void getPublicKey(element_t x, element_t y) ;
        void setPublicKey(element_t x, element_t y) ;
        void setID() ;
        std::string getID() ;

    private:
        static int count ;
        element_t privKeyTA;
        element_t privKeyV ;
        element_t partialPrivKey ;
        element_t X ;
        element_t Y ;
        element_t Q ;
        std::string ID ;

};

 // namespace ns3
