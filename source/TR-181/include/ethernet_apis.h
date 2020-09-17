/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#ifndef  _ETHERNET_APIS_H
#define  _ETHERNET_APIS_H

#include "vlan_mgr_apis.h"
#include "ssp_global.h"
#include "vlan_eth_hal.h"
#include "platform_hal.h"

#define ETHERNET_IF_STATUS_ERROR         7
#define ETHERNET_IF_STATUS_NOT_PRESENT   5
#ifdef _HUB4_PRODUCT_REQ_
#define ETHERNET_VLAN_ID                 101
#define ETHERNET_LINK_PATH               "Device.X_RDK_Ethernet.Link."
#define DSL_IFC_STR                      "dsl"
#define DEFAULT_VLAN_ID                  (-1)
#endif
#define WAN_INTERFACE_NAME              "erouter0"

/* * Telemetry Markers */
#define ETH_MARKER_VLAN_IF_CREATE          "RDKB_VLAN_CREATE"
#define ETH_MARKER_VLAN_IF_DELETE          "RDKB_VLAN_DELETE"
#define ETH_MARKER_VLAN_TABLE_CREATE       "RDKB_VLAN_TABLE_CREATE"
#define ETH_MARKER_VLAN_TABLE_DELETE       "RDKB_VLAN_TABLE_DELETE"
#define ETH_MARKER_NOTIFY_WAN_BASE         "RDKB_WAN_NOTIFY"
#define ETH_MARKER_VLAN_REFRESH            "RDKB_VLAN_REFRESH"

/***********************************
    Actual definition declaration
************************************/
/*
    ETHERNET Part
*/
typedef enum { Up = 1, 
               Down, 
               Unknown, 
               Dormant, 
               NotPresent, 
               LowerLayerDown, 
               Error 
}ethernet_link_status_e;

typedef enum
_VLAN_REFRESH_CALLER_ENUM
{
    VLAN_REFRESH_CALLED_FROM_VLANCREATION               = 1,
    VLAN_REFRESH_CALLED_FROM_DML
} VLAN_REFRESH_CALLER_ENUM;

typedef  struct
_COSA_DML_MARKING
{
    ULONG      InstanceNumber;
    UINT       SKBPort;
    INT        EthernetPriorityMark;
}
COSA_DML_MARKING,  *PCOSA_DML_MARKING;

typedef  struct
_DML_ETHERNET
{
    ULONG                InstanceNumber;
    BOOLEAN              Enable;
    ethernet_link_status_e   Status;
    CHAR                 Alias[64];
    CHAR                 Name[64];
    CHAR                 Path[128];
    UINT                 LastChange;
    CHAR                 LowerLayers[1024];
    CHAR                 MACAddress[17];
    BOOLEAN              PriorityTagging;
    UINT                 NumberofMarkingEntries;
    PCOSA_DML_MARKING    pstDataModelMarking;
}
DML_ETHERNET,  *PDML_ETHERNET;

typedef  struct
_VLAN_REFRESH_CFG
{
    CHAR                             WANIfName[64];
    INT                              iWANInstance;
    VLAN_REFRESH_CALLER_ENUM         enRefreshCaller;
    vlan_configuration_t             stVlanCfg;
}
VLAN_REFRESH_CFG,  *PVLAN_REFRESH_CFG;

#define DML_ETHERNET_INIT(pEth)                   \
{                                                 \
    (pEth)->Enable                 = FALSE;       \
    (pEth)->NumberofMarkingEntries = 0;           \
    (pEth)->pstDataModelMarking    = NULL;        \
}                                                 \

/*
Description:
    This callback routine is provided for backend to call middle layer
Arguments:
    hDml          Opaque handle passed in from DmlEthInit.
    pEntry        Pointer to ETHERNET vlan mapping to receive the generated values.
Return:
    Status of operation


*/
typedef ANSC_STATUS
(*PFN_DML_ETHERNET_GEN)
    (
        ANSC_HANDLE                 hDml
);


/*************************************
    The actual function declaration
**************************************/

/*
Description:
    This is the initialization routine for ETHERNET backend.
Arguments:
    hDml        Opaque handle from DM adapter. Backend saves this handle for calling pValueGenFn.
    phContext       Opaque handle passed back from backend, needed by CosaDmlETHERNETXyz() routines.
    pValueGenFn Function pointer to instance number/alias generation callback.
Return:
Status of operation.

*/
ANSC_STATUS
DmlEthInit
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext,
        PFN_DML_ETHERNET_GEN        pValueGenFn
    );
/* APIs for ETHERNET */

PDML_ETHERNET
DmlGetEthCfgs
    (
        ANSC_HANDLE                 hContext,
        PULONG                      pulCount,
        BOOLEAN                     bCommit
    );

ANSC_STATUS
DmlAddEth
    (
        ANSC_HANDLE                 hContext,
        PDML_ETHERNET               pEntry
    );

ANSC_STATUS
DmlGetEthCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       InstanceNum,
        PDML_ETHERNET               p_Eth
    );

ANSC_STATUS
DmlGetEthCfgIfStatus
    (
        ANSC_HANDLE                 hContext,
        PDML_ETHERNET               p_Eth
    );

ANSC_STATUS
DmlSetEthCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_ETHERNET               p_Eth
    );

ANSC_STATUS
DmlCreateEthInterface
    (
        ANSC_HANDLE                 hContext,
        PDML_ETHERNET               p_Eth
    );

ANSC_STATUS
DmlDeleteEthInterface
    (
        ANSC_HANDLE                 hContext,
        PDML_ETHERNET               p_Eth
    ); 

ANSC_STATUS
DmlEthSetWanStatusForBaseManager
    (
        char *ifname,
        char *WanStatus
    );

ANSC_STATUS DmlEthSetVlanRefresh( char *ifname, VLAN_REFRESH_CALLER_ENUM  enRefreshCaller, vlan_configuration_t *pstVlanCfg );
ANSC_STATUS getInterfaceStatus(const char *iface, vlan_interface_status_e *status);
ANSC_STATUS DmlGetHwAddressUsingIoctl( const char *pIfNameInput, char *pMACOutput, size_t t_MacLength );
ANSC_STATUS GetVlanId(INT *pVlanId, PDML_ETHERNET pEntry);
#endif
