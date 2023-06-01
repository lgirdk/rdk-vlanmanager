/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 Sky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright [2014] [Cisco Systems, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef  _ETHERNET_APIS_H
#define  _ETHERNET_APIS_H

#include "vlan_mgr_apis.h"
#include "ssp_global.h"
#include "vlan_eth_hal.h"
#include "platform_hal.h"

#define ETHERNET_IF_STATUS_NOT_PRESENT   5
#define DEFAULT_VLAN_ID                  (-1)

/* * Telemetry Markers */
#define ETH_MARKER_VLAN_IF_CREATE          "RDKB_VLAN_CREATE"
#define ETH_MARKER_VLAN_IF_DELETE          "RDKB_VLAN_DELETE"
#define ETH_MARKER_NOTIFY_WAN_BASE         "RDKB_WAN_NOTIFY"
#define ETH_MARKER_VLAN_REFRESH            "RDKB_VLAN_REFRESH"

extern ANSC_HANDLE bus_handle;

#define CCSP_SUBSYS "eRT."
#define PSM_VALUE_GET_VALUE(name, str) PSM_Get_Record_Value2(bus_handle, CCSP_SUBSYS, name, NULL, &(str))

#define PSM_ENABLE_STRING_TRUE  "TRUE"
#define PSM_ENABLE_STRING_FALSE  "FALSE"

#define PSM_ETHLINK_COUNT        "dmsb.ethlink.ifcount"
#define PSM_ETHLINK_ENABLE       "dmsb.ethlink.%d.Enable"
#define PSM_ETHLINK_ALIAS        "dmsb.ethlink.%d.alias"
#define PSM_ETHLINK_NAME         "dmsb.ethlink.%d.name"
#define PSM_ETHLINK_LOWERLAYERS  "dmsb.ethlink.%d.lowerlayers"
#define PSM_ETHLINK_MACOFFSET    "dmsb.ethlink.%d.macoffset"
#define PSM_ETHLINK_BASEIFACE    "dmsb.ethlink.%d.baseiface"

//PAM
#define RDKB_PAM_COMPONENT_NAME           "eRT.com.cisco.spvtg.ccsp.pam"
#define RDKB_PAM_DBUS_PATH                "/com/cisco/spvtg/ccsp/pam"
#define PAM_BASE_MAC_ADDRESS              "Device.DeviceInfo.X_CISCO_COM_BaseMacAddress"

/***********************************
    Actual definition declaration
************************************/
/*
    ETHERNET Part
*/
typedef enum { 
               ETH_IF_UP = 1, 
               ETH_IF_DOWN, 
               ETH_IF_UNKNOWN, 
               ETH_IF_DORMANT, 
               ETH_IF_NOTPRESENT, 
               ETH_IF_LOWERLAYERDOWN, 
               ETH_IF_ERROR 
}ethernet_link_status_e;

typedef  struct
_COSA_DML_MARKING
{
    ULONG      InstanceNumber;
    CHAR       Alias[32];
    UINT       SKBPort;
    INT        SKBMark;
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
    CHAR                 BaseInterface[64];
    CHAR                 Path[128];
    UINT                 LastChange;
    CHAR                 LowerLayers[1024];
    CHAR                 MACAddress[18];
    ULONG                MACAddrOffSet;
    BOOLEAN              PriorityTagging;
    UINT                 NumberofMarkingEntries;
    PCOSA_DML_MARKING    pstDataModelMarking;
}
DML_ETHERNET,  *PDML_ETHERNET;

static inline void DML_ETHERNET_INIT(PDML_ETHERNET pEth)
{
    pEth->Enable                 = FALSE;
    pEth->PriorityTagging        = FALSE;
    pEth->Status                 = ETH_IF_DOWN;
    pEth->NumberofMarkingEntries = 0;
    pEth->pstDataModelMarking    = NULL;
}

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
EthLink_Init
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext
    );
/* APIs for ETHERNET */

ANSC_STATUS
EthLink_GetStatus
    (
        PDML_ETHERNET               p_Eth
    );

ANSC_STATUS
EthLink_Enable
    (
        PDML_ETHERNET               p_Eth
    );

ANSC_STATUS
EthLink_Disable
    (
        PDML_ETHERNET               p_Eth
    ); 

ANSC_STATUS EthLink_TriggerVlanRefresh( PDML_ETHERNET pEntry );
ANSC_STATUS EthLink_GetMacAddr( PDML_ETHERNET pEntry );
ANSC_STATUS EthLink_SendWanStatusForBaseManager(char *ifname, char *WanStatus);
ANSC_STATUS EthLink_AddMarking(PDML_ETHERNET pEntry);
ANSC_STATUS DmlEthGetParamValues(char *pComponent, char *pBus, char *pParamName, char *pReturnVal);
ANSC_STATUS EthLink_GetMarking(char *ifname, vlan_configuration_t *pVlanCfg);
#endif
