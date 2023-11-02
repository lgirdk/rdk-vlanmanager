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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <syscfg/syscfg.h>

#include "vlan_mgr_apis.h"
#include "ethernet_apis.h"
#include "ethernet_internal.h"
#include <sysevent/sysevent.h>
#include "plugin_main_apis.h"
#include "vlan_internal.h"
#include "vlan_dml.h"
#include "vlan_eth_hal.h"

/* **************************************************************************************************** */
#define DATAMODEL_PARAM_LENGTH 256
#define PARAM_SIZE 10
#define PARAM_SIZE_32 32
#define PARAM_SIZE_64 64

/*TODO:
 * Need to be Reviewed After Unification Finalised.
 */
//ETH Agent.
#define ETH_DBUS_PATH                     "/com/cisco/spvtg/ccsp/ethagent"
#define ETH_COMPONENT_NAME                "eRT.com.cisco.spvtg.ccsp.ethagent"
#define ETH_STATUS_PARAM_NAME             "Device.Ethernet.X_RDK_Interface.%d.WanStatus"
#define ETH_NOE_PARAM_NAME                "Device.Ethernet.X_RDK_InterfaceNumberOfEntries"
#define ETH_IF_PARAM_NAME                 "Device.Ethernet.X_RDK_Interface.%d.Name"
//DSL Agent.
#define DSL_DBUS_PATH                     "/com/cisco/spvtg/ccsp/xdslmanager"
#define DSL_COMPONENT_NAME                "eRT.com.cisco.spvtg.ccsp.xdslmanager"
#define DSL_LINE_WAN_STATUS_PARAM_NAME    "Device.DSL.Line.%d.X_RDK_WanStatus"

/*TODO:
 * Need to Reviewed Marking Table Handling After Unification Finalised.
 */
//WAN Agent
#define WAN_DBUS_PATH                     "/com/cisco/spvtg/ccsp/wanmanager"
#define WAN_COMPONENT_NAME                "eRT.com.cisco.spvtg.ccsp.wanmanager"

#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
#define WAN_IF_LINK_STATUS                "Device.X_RDK_WanManager.Interface.%d.VirtualInterface.1.VlanStatus"
#define WAN_MARKING_NOE_PARAM_NAME        "Device.X_RDK_WanManager.Interface.%d.MarkingNumberOfEntries"
#define WAN_MARKING_TABLE_NAME            "Device.X_RDK_WanManager.Interface.%d.Marking."
#else
#define WAN_IF_LINK_STATUS                "Device.X_RDK_WanManager.CPEInterface.%d.Wan.LinkStatus"
#define WAN_MARKING_NOE_PARAM_NAME        "Device.X_RDK_WanManager.CPEInterface.%d.MarkingNumberOfEntries"
#define WAN_MARKING_TABLE_NAME            "Device.X_RDK_WanManager.CPEInterface.%d.Marking."
#endif /* WAN_MANAGER_UNIFICATION_ENABLED */

extern ANSC_HANDLE                        g_MessageBusHandle;
        int                               sysevent_fd = -1;
        token_t                           sysevent_token;

static ANSC_STATUS DmlEthSetParamValues(const char *pComponent, const char *pBus, const char *pParamName, const char *pParamVal, enum dataType_e type, unsigned int bCommitFlag);
static ANSC_STATUS DmlEthGetParamNames(char *pComponent, char *pBus, char *pParamName, char a2cReturnVal[][256], int *pReturnSize);
static int EthLink_SyseventInit( void );

static ANSC_STATUS EthLink_GetUnTaggedVlanInterfaceStatus(const char *iface, ethernet_link_status_e *status);

static ANSC_STATUS EthLink_GetVlanIdAndTPId(const PDML_ETHERNET pEntry, INT *pVlanId, ULONG *pTPId);
static int EthLink_GetActiveWanInterfaces(char *Alias);
static ANSC_STATUS EthLink_DeleteMarking(PDML_ETHERNET pEntry);
static ANSC_STATUS EthLink_CreateUnTaggedInterface(PDML_ETHERNET pEntry);
/*TODO
* Need to be Reviewed after Unification finalised.
*/
static ANSC_STATUS EthLink_GetLowerLayersInstanceFromEthAgent(char *ifname, INT *piInstanceNumber);
static ANSC_STATUS EthLink_CreateMarkingTable(PDML_ETHERNET pEntry, vlan_configuration_t* pVlanCfg);
static ANSC_STATUS EthLink_AddMarking(PDML_ETHERNET pEntry);
static ANSC_STATUS EthLink_TriggerVlanRefresh(PDML_ETHERNET pEntry );
#if !defined(VLAN_MANAGER_HAL_ENABLED)
static ANSC_STATUS EthLink_SetEgressQoSMap( vlan_configuration_t *pVlanCfg );
static ANSC_STATUS EthLink_SetMacAddr( PDML_ETHERNET pEntry );
#endif

/* *************************************************************************************************** */

/* * EthLink_SyseventInit() */
static int EthLink_SyseventInit( void )
{
    char sysevent_ip[] = "127.0.0.1";
    char sysevent_name[] = "vlanmgr";

    sysevent_fd =  sysevent_open( sysevent_ip, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, sysevent_name, &sysevent_token );

    if ( sysevent_fd < 0 )
        return -1;

    return 0;
}

/**********************************************************************

    caller:     self

    prototype:

        BOOL
        EthLink_Init
            (
                ANSC_HANDLE                 hDml,
                PANSC_HANDLE                phContext
            );

        Description:
            This is the initialization routine for ETHERNET backend.

        Arguments:
            hDml               Opaque handle from DM adapter. Backend saves this handle for calling pValueGenFn.
             phContext       Opaque handle passed back from backend, needed by CosaDmlETHERNETXyz() routines.

        Return:
            Status of operation.

**********************************************************************/
ANSC_STATUS
EthLink_Init
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext
    )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    // Initialize sysevent
    if ( EthLink_SyseventInit( ) < 0 )
    {
        return ANSC_STATUS_FAILURE;
    }

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        EthLink_GetStatus
            (
                ANSC_HANDLE         hThisObject,
                PDML_ETHERNET      pEntry
            );

    Description:
        The API updated current state of a ETHERNET interface
    Arguments:
        pAlias      The entry is identified through Alias.
        pEntry      The new configuration is passed through this argument, even Alias field can be changed.

    Return:
        Status of the operation

**********************************************************************/
ANSC_STATUS
EthLink_GetStatus
    (
        PDML_ETHERNET      pEntry
    )
{
    ANSC_STATUS             returnStatus  = ANSC_STATUS_SUCCESS;
    ethernet_link_status_e status;

    if (pEntry != NULL) {
        if ( ANSC_STATUS_SUCCESS != EthLink_GetUnTaggedVlanInterfaceStatus(pEntry->Name, &status)) {
            pEntry->Status = ETH_IF_ERROR;
            CcspTraceError(("%s %d - %s: Failed to get interface status for this\n", __FUNCTION__,__LINE__, pEntry->Name));
        }
        else {
            pEntry->Status = status;
        }
    }
    return returnStatus;
}

/* Set Wan Virtual Interface Vlan Status */
ANSC_STATUS EthLink_SendVirtualIfaceVlanStatus(char *path, char *vlanStatus)
{
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = {0};

    if ((NULL == path) || (strlen(path) <= 0) || (NULL == vlanStatus))
    {
        CcspTraceError(("%s Path Or vlanStatus Null\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Set WAN Virtual Iface VlanStatus
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, "%s.%s", path, "VlanStatus");
    DmlEthSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName, vlanStatus, ccsp_string, TRUE);
    CcspTraceInfo(("%s-%d:Successfully set the Virtual Interface(%s) VLAN Status(%s) \n", __FUNCTION__, __LINE__, path, vlanStatus));
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        EthLink_Enable
            (
                PDML_ETHERNET      pEntry
            );

    Description:
        The API enable the designated ETHERNET interface
    Arguments:
        pEntry      The new configuration is passed through this argument, even Alias field can be changed.

    Return:
        Status of the operation

**********************************************************************/
ANSC_STATUS EthLink_Enable(PDML_ETHERNET  pEntry)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    ethernet_link_status_e status = ETH_IF_DOWN;
    int iIterator = 0;

    if (NULL == pEntry)
    {
        CcspTraceError(("%s : Failed to Enable EthLink \n",__FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //create marking table in ethlink here. no need to delete if ethlink is disabled.
    /* TODO: Retry add making if DM gert fails. 
     * Currently we continue to create VLAN link, if Marking get fails to avoid WAN failure.
     */
    if (EthLink_AddMarking(pEntry) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("[%s-%d] Failed to Add Marking. Creating VLAN without Marking \n", __FUNCTION__, __LINE__));
    }

    if (pEntry->PriorityTagging == FALSE)
    {

        //Delete UnTagged Vlan Interface
        returnStatus = EthLink_GetUnTaggedVlanInterfaceStatus(pEntry->Name, &status);
        if (returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("[%s-%d] - %s: Failed to get VLAN interface status\n", __FUNCTION__, __LINE__, pEntry->Name));
            return returnStatus;
        }
#if defined(VLAN_MANAGER_HAL_ENABLED)
        if ( ( status != ETH_IF_NOTPRESENT ) && ( status != ETH_IF_ERROR ) )
        {
            returnStatus = vlan_eth_hal_deleteInterface(pEntry->Name, pEntry->InstanceNumber);
            if (ANSC_STATUS_SUCCESS != returnStatus)
            {
                CcspTraceError(("[%s-%d] Failed to delete UnTagged VLAN interface(%s)\n", __FUNCTION__, __LINE__, pEntry->Name));
            }
        }
#endif
        //Create UnTagged Vlan Interface
        returnStatus = EthLink_CreateUnTaggedInterface(pEntry);
        if (ANSC_STATUS_SUCCESS != returnStatus)
        {
            pEntry->Status = ETH_IF_ERROR;
            CcspTraceError(("[%s][%d]Failed to create UnTagged VLAN interface \n", __FUNCTION__, __LINE__));
            return returnStatus;
        }

        while(iIterator < 10)
        {
            if (ANSC_STATUS_FAILURE == EthLink_GetUnTaggedVlanInterfaceStatus(pEntry->Name, &status))
            {
                CcspTraceError(("%s-%d: Failed to Get UnTagged Vlan Interface=%s Status \n", __FUNCTION__, __LINE__, pEntry->Name));
                return ANSC_STATUS_FAILURE;
            }

            if (status == ETH_IF_UP)
            {
                EthLink_SendVirtualIfaceVlanStatus(pEntry->Path, "Up");
                break;
            }

            iIterator++;
            sleep(2);
            CcspTraceInfo(("%s-%d: Interface Status(%d), retry-count=%d \n", __FUNCTION__, __LINE__, status, iIterator));
        }
        pEntry->Status = ETH_IF_UP;
        CcspTraceInfo(("%s - %s:Successfully created UnTagged VLAN Interface(%s)\n",__FUNCTION__, ETH_MARKER_VLAN_IF_CREATE, pEntry->Name));
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        EthLink_Disable
            (
                PDML_ETHERNET      pEntry
            );

    Description:
        The API delete the designated ETHERNET interface from the system
    Arguments:
        pEntry      The new configuration is passed through this argument, even Alias field can be changed.

    Return:
        Status of the operation

**********************************************************************/

ANSC_STATUS EthLink_Disable(PDML_ETHERNET  pEntry)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    ethernet_link_status_e status;

    if (pEntry == NULL )
    {
        CcspTraceError(("[%s-%d] Invalid parameter error! \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_BAD_PARAMETER;
    }

    //create makring table in ethlink here. no need to delete if ethlink is disabled.
    if (EthLink_DeleteMarking(pEntry) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("[%s-%d] Failed to Delete Marking \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if (pEntry->PriorityTagging == FALSE)
    {
        returnStatus = EthLink_GetUnTaggedVlanInterfaceStatus(pEntry->Name, &status);
        if (returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("[%s-%d] - %s: Failed to get VLAN interface status\n", __FUNCTION__, __LINE__, pEntry->Name));
            return returnStatus;
        }
#if defined(VLAN_MANAGER_HAL_ENABLED)
        //Delete Untagged VLAN interface
        if ( ( status != ETH_IF_NOTPRESENT ) && ( status != ETH_IF_ERROR ) )
        {
            returnStatus = vlan_eth_hal_deleteInterface(pEntry->Name, pEntry->InstanceNumber);
            if (ANSC_STATUS_SUCCESS != returnStatus)
            {
                CcspTraceError(("[%s-%d] Failed to delete UnTagged VLAN interface(%s)\n", __FUNCTION__, __LINE__, pEntry->Name));
            }
        }
#else
        v_secure_system("ip link delete %s", pEntry->Name);
#endif
        pEntry->Status = ETH_IF_DOWN;
        //Notify Vlan Status to WAN Manager.
        EthLink_SendVirtualIfaceVlanStatus(pEntry->Path, "Down");
        CcspTraceInfo(("[%s-%d] Successfully Updated Vlan Status to WanManager \n", __FUNCTION__, __LINE__));

        CcspTraceInfo(("[%s-%d]  %s:Successfully deleted %s VLAN interface \n", __FUNCTION__, __LINE__, ETH_MARKER_VLAN_IF_DELETE, pEntry->Name)); 
    }

    return returnStatus;
}

/* * DmlEthGetParamValues() */
ANSC_STATUS DmlEthGetParamValues(
    char *pComponent,
    char *pBus,
    char *pParamName,
    char *pReturnVal)
{
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t **retVal = NULL;
    char *ParamName[1];
    int ret = 0,
        nval;

    //Assign address for get parameter name
    ParamName[0] = pParamName;

    ret = CcspBaseIf_getParameterValues(
        bus_handle,
        pComponent,
        pBus,
        ParamName,
        1,
        &nval,
        &retVal);

    //Copy the value
    if (CCSP_SUCCESS == ret)
    {
        if (NULL != retVal[0]->parameterValue)
        {
            memcpy(pReturnVal, retVal[0]->parameterValue, strlen(retVal[0]->parameterValue) + 1);
        }

        if (retVal)
        {
            free_parameterValStruct_t(bus_handle, nval, retVal);
        }

        return ANSC_STATUS_SUCCESS;
    }

    if (retVal)
    {
        free_parameterValStruct_t(bus_handle, nval, retVal);
    }

    return ANSC_STATUS_FAILURE;
}

/* * DmlEthSetParamValues() */
static ANSC_STATUS DmlEthSetParamValues(
    const char *pComponent,
    const char *pBus,
    const char *pParamName,
    const char *pParamVal,
    enum dataType_e type,
    unsigned int bCommitFlag)
{
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)g_MessageBusHandle;
    parameterValStruct_t param_val[1] = {0};
    char *faultParam = NULL;
    int ret = 0;

    param_val[0].parameterName = pParamName;
    param_val[0].parameterValue = pParamVal;
    param_val[0].type = type;

    ret = CcspBaseIf_setParameterValues(
        bus_handle,
        pComponent,
        pBus,
        0,
        0,
        param_val,
        1,
        bCommitFlag,
        &faultParam);

    if ((ret != CCSP_SUCCESS) && (faultParam != NULL))
    {
        CcspTraceError(("[%s][%d] Failed to set %s\n", __FUNCTION__, __LINE__, pParamName));
        bus_info->freefunc(faultParam);
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

/* *DmlEthGetParamNames() */
static ANSC_STATUS DmlEthGetParamNames(
    char *pComponent,
    char *pBus,
    char *pParamName,
    char a2cReturnVal[][256],
    int *pReturnSize)
{
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterInfoStruct_t **retInfo = NULL;
    char *ParamName[1];
    int ret = 0,
        nval;

    ret = CcspBaseIf_getParameterNames(
        bus_handle,
        pComponent,
        pBus,
        pParamName,
        1,
        &nval,
        &retInfo);

    if (CCSP_SUCCESS == ret)
    {
        int iLoopCount;

        *pReturnSize = nval;

        for (iLoopCount = 0; iLoopCount < nval; iLoopCount++)
        {
            if (NULL != retInfo[iLoopCount]->parameterName)
            {
                snprintf(a2cReturnVal[iLoopCount], strlen(retInfo[iLoopCount]->parameterName) + 1, "%s", retInfo[iLoopCount]->parameterName);
            }
        }

        if (retInfo)
        {
            free_parameterInfoStruct_t(bus_handle, nval, retInfo);
        }

        return ANSC_STATUS_SUCCESS;
    }

    if (retInfo)
    {
        free_parameterInfoStruct_t(bus_handle, nval, retInfo);
    }

    return ANSC_STATUS_FAILURE;
}

/*TODO
 * Need to be Reviewed after Unification is finalised.
 */
static ANSC_STATUS EthLink_GetLowerLayersInstanceFromEthAgent(
    char *ifname,
    INT *piInstanceNumber)
{
    char acTmpReturnValue[256] = {0};
    INT iLoopCount,
        iTotalNoofEntries;
    if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(ETH_COMPONENT_NAME, ETH_DBUS_PATH, ETH_NOE_PARAM_NAME, acTmpReturnValue))
    {
        CcspTraceError(("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    //Total count
    iTotalNoofEntries = atoi(acTmpReturnValue);
    
    CcspTraceInfo(("[%s][%d]TotalNoofEntries:%d\n", __FUNCTION__, __LINE__, iTotalNoofEntries));
    if ( 0 >= iTotalNoofEntries )
    {
        return ANSC_STATUS_SUCCESS;
    }
    //Traverse from loop
    for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
    {
        char acTmpQueryParam[256] = {0};
        snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), ETH_IF_PARAM_NAME, iLoopCount + 1);
        memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
        if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(ETH_COMPONENT_NAME, ETH_DBUS_PATH, acTmpQueryParam, acTmpReturnValue))
        {
            CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
            continue;
	}

        if (0 == strcmp(acTmpReturnValue, ifname))
        {
            *piInstanceNumber = iLoopCount + 1;
             break;
        }
    }
    return ANSC_STATUS_SUCCESS;
}

/*TODO
 * Below Lists of APIs Need to be Reviewed after Unification if finalised:
 * EthLink_GetActiveWanInterfaces
 * EthLink_DeleteMarking
 * EthLink_AddMarking
 * EthLink_GetMarking
 */
static int EthLink_GetActiveWanInterfaces(char *Alias)
{
    char paramName[PARAM_SIZE_64] = {0};
    char *strValue                = NULL;
    char *endptr                  = NULL;
    int wanIfCount                = 0;
    int activeIface               = -1;
    int numOfVrIface              = 0;
    int retPsmGet                 = CCSP_SUCCESS;

    if (Alias[0] == '\0')
    {
	CcspTraceError(("%s-%d: Alias is Null \n",__FUNCTION__, __LINE__));
        return activeIface;
    }

    strcpy(paramName, "dmsb.wanmanager.wanifcount");
    retPsmGet = PSM_VALUE_GET_VALUE(paramName, strValue);
    if((retPsmGet == CCSP_SUCCESS) && (strValue != NULL))
    {
        wanIfCount = strtol(strValue, &endptr, 10);
        Ansc_FreeMemory_Callback(strValue);
        strValue = NULL;
    }

    for(int i = 1; i <= wanIfCount; i++)
    {
       memset(paramName, 0, sizeof(paramName));
       sprintf(paramName, "dmsb.wanmanager.if.%d.Name", i);
       retPsmGet = PSM_VALUE_GET_VALUE(paramName, strValue);
       if((retPsmGet == CCSP_SUCCESS) && (strValue != NULL))
       {
           if(0 == strcmp(strValue, Alias))
           {
              activeIface = i;

              Ansc_FreeMemory_Callback(strValue);
              strValue = NULL;

              break;
           }
           Ansc_FreeMemory_Callback(strValue);
           strValue = NULL;
       }
    }

    if(-1 != activeIface)
    {
        return(activeIface);
    }
    
    return -1;
}

static ANSC_STATUS EthLink_DeleteMarking(PDML_ETHERNET pEntry)
{
    if (pEntry == NULL )
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if (pEntry->NumberofMarkingEntries > 0)
    {
        if(pEntry->pstDataModelMarking != NULL)
        {
            free(pEntry->pstDataModelMarking);
            pEntry->pstDataModelMarking = NULL;
        }
	pEntry->NumberofMarkingEntries = 0;
    }

    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS EthLink_AddMarking(PDML_ETHERNET pEntry)
{
    char acGetParamName[256] = {0};
    char acSetParamName[256] = {0};
    char acTmpReturnValue[256] = {0};
    char a2cTmpTableParams[16][256] = {0};
    INT iLoopCount = 0;
    INT iTotalNoofEntries = 0;
    INT iWANInstance   = -1;
    vlan_configuration_t VlanCfg;

    if (pEntry == NULL )
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    iWANInstance = EthLink_GetActiveWanInterfaces(pEntry->Alias);
    if (-1 == iWANInstance)
    {
        CcspTraceError(("%s %d Eth instance not present\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d Wan Interface Instance:%d\n", __FUNCTION__, __LINE__, iWANInstance));

    //Get Marking entries
    memset(acGetParamName, 0, sizeof(acGetParamName));
    snprintf(acGetParamName, sizeof(acGetParamName), WAN_MARKING_NOE_PARAM_NAME, iWANInstance);
    if ( ANSC_STATUS_FAILURE == DmlEthGetParamValues( WAN_COMPONENT_NAME, WAN_DBUS_PATH, acGetParamName, acTmpReturnValue ) )
    {
        CcspTraceError(("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    iTotalNoofEntries = atoi(acTmpReturnValue);

    VlanCfg.skbMarkingNumOfEntries = iTotalNoofEntries;

    if( VlanCfg.skbMarkingNumOfEntries > 0 )
    {
       VlanCfg.skb_config = (vlan_skb_config_t*)malloc( iTotalNoofEntries * sizeof(vlan_skb_config_t) );

       if( NULL == VlanCfg.skb_config )
       {
          return ANSC_STATUS_FAILURE;
       }

       iTotalNoofEntries = 0;

       memset(acGetParamName, 0, sizeof(acGetParamName));
       snprintf(acGetParamName, sizeof(acGetParamName), WAN_MARKING_TABLE_NAME, iWANInstance);

       if ( ANSC_STATUS_FAILURE == DmlEthGetParamNames(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acGetParamName, a2cTmpTableParams, &iTotalNoofEntries))
       {
           CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
           return ANSC_STATUS_FAILURE;
       }

       for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
       {
           char acTmpQueryParam[256];

           //Alias
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sAlias", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           snprintf(VlanCfg.skb_config[iLoopCount].alias, sizeof(VlanCfg.skb_config[iLoopCount].alias), "%s", acTmpReturnValue);

           //SKBPort
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sSKBPort", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           VlanCfg.skb_config[iLoopCount].skbPort = atoi(acTmpReturnValue);

           //SKBMark
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sSKBMark", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           VlanCfg.skb_config[iLoopCount].skbMark = atoi(acTmpReturnValue);

           //EthernetPriorityMark
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sEthernetPriorityMark", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           VlanCfg.skb_config[iLoopCount].skbEthPriorityMark = atoi(acTmpReturnValue);

           CcspTraceInfo(("WAN Marking - Ins[%d] Alias[%s] SKBPort[%u] SKBMark[%u] EthernetPriorityMark[%d]\n",
                                                                iLoopCount + 1,
                                                                VlanCfg.skb_config[iLoopCount].alias,
                                                                VlanCfg.skb_config[iLoopCount].skbPort,
                                                                VlanCfg.skb_config[iLoopCount].skbMark,
                                                                VlanCfg.skb_config[iLoopCount].skbEthPriorityMark ));
        }
    }
    //Create and initialise Marking data models
    EthLink_CreateMarkingTable(pEntry, &VlanCfg);

    //Free VlanCfg skb_config memory
    if (VlanCfg.skb_config != NULL)
    {
        free(VlanCfg.skb_config);
        VlanCfg.skb_config = NULL;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS EthLink_GetMarking(char *ifname, vlan_configuration_t *pVlanCfg)
{
    INT iLoopCount = 0;
    BOOL Found = FALSE;
    ANSC_STATUS returnStatus = ANSC_STATUS_FAILURE;

    if ((ifname == NULL) || (pVlanCfg == NULL))
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    PDATAMODEL_ETHERNET    pMyObject    = (PDATAMODEL_ETHERNET)g_pBEManager->hEth;
    PDML_ETHERNET          p_EthLink    = NULL;

    if (pMyObject->ulEthlinkInstanceNumber > 0)
    {
        for(iLoopCount = 0; iLoopCount < pMyObject->ulEthlinkInstanceNumber; iLoopCount++)
        {
            p_EthLink = (PDML_ETHERNET)&(pMyObject->EthLink[iLoopCount]);
            if (p_EthLink != NULL)
            {
                if (strncmp(p_EthLink->Alias, ifname, strlen(ifname)) == 0)
                {
                    Found = TRUE;
                    break;
                }
            }
        }
        if (Found && (p_EthLink != NULL))
        {
            //Vlan Marking Info
            CcspTraceInfo(("%s-%d: NumberofMarkingEntries=%d \n", __FUNCTION__, __LINE__, p_EthLink->NumberofMarkingEntries));
            if (p_EthLink->NumberofMarkingEntries > 0)
            {
                //allocate memory to vlan_skb_config_t, free it once used.
                pVlanCfg->skbMarkingNumOfEntries = p_EthLink->NumberofMarkingEntries;
                pVlanCfg->skb_config = (vlan_skb_config_t*)malloc( p_EthLink->NumberofMarkingEntries * sizeof(vlan_skb_config_t) );
                for(int i = 0; i < p_EthLink->NumberofMarkingEntries; i++)
                {
                    PCOSA_DML_MARKING pDataModelMarking = (PCOSA_DML_MARKING)&(p_EthLink->pstDataModelMarking[i]);
                    if ((pDataModelMarking != NULL) && (pVlanCfg->skb_config != NULL))
                    {
                        strcpy(pVlanCfg->skb_config[i].alias, pDataModelMarking->Alias);
                        pVlanCfg->skb_config[i].skbPort = pDataModelMarking->SKBPort;
                        pVlanCfg->skb_config[i].skbMark = pDataModelMarking->SKBMark;
                        pVlanCfg->skb_config[i].skbEthPriorityMark = pDataModelMarking->EthernetPriorityMark;
                        CcspTraceInfo(("%s-%d: Ins[%d] Alias[%s] SKBPort[%u] SKBMark[%u] EthernetPriorityMark[%d]\n", __FUNCTION__,
                                        __LINE__, (i + 1), pVlanCfg->skb_config[i].alias, pVlanCfg->skb_config[i].skbPort,
                                         pVlanCfg->skb_config[i].skbMark, pVlanCfg->skb_config[i].skbEthPriorityMark ));
                    }
                    else
                    {
                          CcspTraceError(("%s-%d: pDataModelMarking Or pVlanCfg->skb_config are Null \n", __FUNCTION__, __LINE__));
                          return ANSC_STATUS_FAILURE;
                    }
                }
            }
            returnStatus = ANSC_STATUS_SUCCESS;
        }
    }

    return returnStatus;
}

static ANSC_STATUS EthLink_CreateUnTaggedInterface(PDML_ETHERNET pEntry)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    vlan_configuration_t VlanCfg;

    if (pEntry == NULL)
    {
        CcspTraceError(("%s-%d: Failed to Create Tagged Vlan Interface\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    memset (&VlanCfg, 0, sizeof(vlan_configuration_t));

    strncpy(VlanCfg.BaseInterface, pEntry->BaseInterface, sizeof(VlanCfg.BaseInterface) - 1);
    strncpy(VlanCfg.L3Interface, pEntry->Name, sizeof(VlanCfg.L3Interface) - 1);
    strncpy(VlanCfg.L2Interface, pEntry->BaseInterface, sizeof(VlanCfg.L2Interface) - 1);
    VlanCfg.VLANId = DEFAULT_VLAN_ID;
    VlanCfg.TPId   = 0;

    if (EthLink_GetMarking(pEntry->Alias, &VlanCfg) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("%s Failed to Get Marking, so Can't Create Vlan Interface(%s) \n", __FUNCTION__, pEntry->Alias));
        return ANSC_STATUS_FAILURE;
    }
#if defined(VLAN_MANAGER_HAL_ENABLED)
    vlan_eth_hal_createInterface(&VlanCfg);
#else
    v_secure_system("ip link add link %s name %s type macvlan", pEntry->Alias, pEntry->Name);
    v_secure_system("ip link set %s up", pEntry->Name);

    if (EthLink_SetMacAddr(pEntry) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("%s Failed to Set MacAddress \n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    return returnStatus;
#endif
    //Free VlanCfg skb_config memory
    if (VlanCfg.skb_config != NULL)
    {
        free(VlanCfg.skb_config);
        VlanCfg.skb_config = NULL;
    }

    return returnStatus;
}

/* Start Vlan Refresh Handle Thread */
void* EthLink_RefreshHandleThread(void *Arg)
{
    PDML_ETHERNET pEntry = (PDML_ETHERNET)Arg;

    if ( NULL == pEntry )
    {
        CcspTraceError(("%s-%d: Failed to Start Refresh Handle Thread, Arg pEntry Null \n", __FUNCTION__, __LINE__));
        pthread_exit(NULL);
    }

    pthread_detach(pthread_self());

    /* TODO: Retry add making if DM gert fails. 
     * Currently we continue to create VLAN link, if Marking get fails to avoid WAN failure.
     */
    if (EthLink_AddMarking(pEntry) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("[%s-%d] Failed to Update Refreshed Marking. Creating VLAN without Marking. \n", __FUNCTION__, __LINE__));
    }
    if (EthLink_TriggerVlanRefresh(pEntry) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("[%s-%d] Failed to Trigger Vlan Refresh \n", __FUNCTION__, __LINE__));
    }

    pthread_exit(NULL);
}

/* Trigger VLAN Refresh */
static ANSC_STATUS EthLink_TriggerVlanRefresh(PDML_ETHERNET pEntry )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    ethernet_link_status_e status = ETH_IF_DOWN;
    vlan_configuration_t VlanCfg;
    INT iIterator = 0;

    if (pEntry == NULL)
    {
        CcspTraceError(("%s-%d: Failed to Trigger Vlan Refresh for Interface=%s \n", __FUNCTION__, __LINE__, pEntry->Alias));
        return ANSC_STATUS_FAILURE;
    }

    memset (&VlanCfg, 0, sizeof(vlan_configuration_t));

    strncpy(VlanCfg.BaseInterface, pEntry->BaseInterface, sizeof(VlanCfg.BaseInterface) - 1);
    strncpy(VlanCfg.L3Interface, pEntry->Name, sizeof(VlanCfg.L3Interface) - 1);
    strncpy(VlanCfg.L2Interface, pEntry->BaseInterface, sizeof(VlanCfg.L2Interface) - 1);
    VlanCfg.VLANId = 0;
    VlanCfg.TPId   = 0;
    if (EthLink_GetVlanIdAndTPId(pEntry, &VlanCfg.VLANId, &VlanCfg.TPId) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("%s Failed to Get VLANId and TPId for Interface(%s) \n", __FUNCTION__, pEntry->Alias));
    }

    /* TODO: Retry add making if DM gert fails. 
     * Currently we continue to create VLAN link, if Marking get fails to avoid WAN failure.
     */
    if (EthLink_GetMarking(pEntry->Alias, &VlanCfg) == ANSC_STATUS_FAILURE)
    {
        CcspTraceError(("%s Failed to Get Marking, Creating Vlan Interface(%s) without marking \n", __FUNCTION__, pEntry->Alias));
    }
#if defined(VLAN_MANAGER_HAL_ENABLED)
    vlan_eth_hal_setMarkings(&VlanCfg);
#else
    if ( EthLink_SetEgressQoSMap(&VlanCfg) != ANSC_STATUS_FAILURE)
    {
        CcspTraceInfo(("%s - Successfully Set QoS Marking \n",__FUNCTION__));
    }
#endif
    //Free VlanCfg skb_config memory
    if (VlanCfg.skb_config != NULL)
    {
        free(VlanCfg.skb_config);
        VlanCfg.skb_config = NULL;
    }

   /*TODO
    * Need to be Reviewed the below code after Unification is finalised..
    */
    //Get status of VLAN link
    while(iIterator < 10)
    {
        char interface_name[IF_NAMESIZE] = {0};

        snprintf(interface_name, sizeof(interface_name), "%s", pEntry->Name);

        if (ANSC_STATUS_FAILURE == EthLink_GetUnTaggedVlanInterfaceStatus(interface_name, &status))
        {
            CcspTraceError(("%s-%d: Failed to Get Vlan Interface=%s Status \n", __FUNCTION__, __LINE__, pEntry->Name));
            return ANSC_STATUS_FAILURE;
        }

        if (status == ETH_IF_UP)
        {
            //Notify Vlan Status to WAN Manager.
            EthLink_SendVirtualIfaceVlanStatus(pEntry->Path, "Up");
            CcspTraceInfo(("[%s-%d] Successfully Updated Vlan Status to WanManager \n", __FUNCTION__, __LINE__));
            break;
        }

        iIterator++;
        sleep(2);
        CcspTraceInfo(("%s-%d: Interface Status(%d), retry-count=%d \n", __FUNCTION__, __LINE__, status, iIterator));
    }

    if(!strncmp(pEntry->Alias, "veip", 4))
    {
        v_secure_system("/etc/gpon_vlan_init.sh");
    }

    CcspTraceInfo(("%s - %s:Successfully Triggered VLAN Refresh for Interface(%s)\n", __FUNCTION__, ETH_MARKER_VLAN_REFRESH, pEntry->Alias));

    return returnStatus;
}

/*TODO
 *Need to be Reviewed and Write one Generic API for Marking Table Creation.
 */

static ANSC_STATUS EthLink_CreateMarkingTable( PDML_ETHERNET pEntry, vlan_configuration_t* pVlanCfg)
{
    if (NULL == pVlanCfg)
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    PDML_ETHERNET          p_EthLink    = NULL;
    int                    iLoopCount   = 0;

    p_EthLink = (PDML_ETHERNET) pEntry;
    if(p_EthLink == NULL)
    {
        CcspTraceError(("%s : Failed, EthLink Null\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if(p_EthLink->pstDataModelMarking != NULL)
    {
        free(p_EthLink->pstDataModelMarking);
        p_EthLink->pstDataModelMarking = NULL;
    }

    p_EthLink->NumberofMarkingEntries = pVlanCfg->skbMarkingNumOfEntries;
    p_EthLink->pstDataModelMarking = (PCOSA_DML_MARKING) malloc(sizeof(COSA_DML_MARKING)*(p_EthLink->NumberofMarkingEntries));
    if(p_EthLink->pstDataModelMarking == NULL)
    {
        CcspTraceError(("%s Failed to allocate Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    memset(p_EthLink->pstDataModelMarking, 0, (sizeof(COSA_DML_MARKING)*(p_EthLink->NumberofMarkingEntries)));
    for(iLoopCount = 0; iLoopCount < p_EthLink->NumberofMarkingEntries; iLoopCount++)
    {
        PCOSA_DML_MARKING pDataModelMarking = (PCOSA_DML_MARKING)&(p_EthLink->pstDataModelMarking[iLoopCount]);
        if (pDataModelMarking != NULL)
        {
            strcpy( pDataModelMarking->Alias, pVlanCfg->skb_config[iLoopCount].alias);
            pDataModelMarking->SKBPort = pVlanCfg->skb_config[iLoopCount].skbPort;
            pDataModelMarking->SKBMark = pVlanCfg->skb_config[iLoopCount].skbMark;
            pDataModelMarking->EthernetPriorityMark = pVlanCfg->skb_config[iLoopCount].skbEthPriorityMark;
        }
    }

    CcspTraceError(("%s : Successfully Created EthLinkTable\n", __FUNCTION__));
    return ANSC_STATUS_SUCCESS;
}

#if !defined(VLAN_MANAGER_HAL_ENABLED)
static ANSC_STATUS EthLink_SetEgressQoSMap( vlan_configuration_t *pVlanCfg )
{
    INT SKBMark = 0;
    INT EthPriority = 0;

    if ((pVlanCfg == NULL) || (pVlanCfg->skb_config == NULL))
    {
        CcspTraceError(("%s-%d: Failed to Set Egress QoS\n",__FUNCTION__, __LINE__));
        ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s-%d: skbMarkingNumOfEntries=%d \n",__FUNCTION__, __LINE__, pVlanCfg->skbMarkingNumOfEntries));
    if (pVlanCfg->skbMarkingNumOfEntries > 0)
    {
        for(int i = 0; i < pVlanCfg->skbMarkingNumOfEntries; i++)
        {

            SKBMark = pVlanCfg->skb_config[i].skbMark;
            EthPriority = pVlanCfg->skb_config[i].skbEthPriorityMark;
            v_secure_system("ip link set %s.%d type vlan egress-qos-map %d:%d", pVlanCfg->L3Interface, pVlanCfg->VLANId, SKBMark, EthPriority);
        }
    }

    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS EthLink_SetMacAddr( PDML_ETHERNET pEntry )
{
    unsigned long long int number, new_mac;
    char acTmpReturnValue[256] = {0};
    char hex[32];
    char macStr[32];
    int i, j = 0;
    int retry_count = 0;

    do
    {
        uint32_t b[6] = {0};

        if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(RDKB_PAM_COMPONENT_NAME, RDKB_PAM_DBUS_PATH, PAM_BASE_MAC_ADDRESS, acTmpReturnValue))
        {
            CcspTraceError(("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__));
            return ANSC_STATUS_FAILURE;
        }

        if (strlen(acTmpReturnValue) != 17 || (6 != sscanf(acTmpReturnValue, "%02X:%02X:%02X:%02X:%02X:%02X", &b[5], &b[4], &b[3], &b[2], &b[1], &b[0])))
        {
            usleep(500000);
            retry_count++;
            CcspTraceInfo(("%s-%d invalid mac=%s, retry_count=%d\n", __FUNCTION__, __LINE__, acTmpReturnValue, retry_count));
        }
        else
        {
            CcspTraceInfo(("%s-%d valid mac=%s, retry_count=%d\n", __FUNCTION__, __LINE__, acTmpReturnValue, retry_count));
            break;
        }
    } while (retry_count < 10);

    for(i = 0; acTmpReturnValue[i] != '\0'; i++)
    {
        if(acTmpReturnValue[i] != ':')
        {
            acTmpReturnValue[j++] = acTmpReturnValue[i];
        }
    }
    acTmpReturnValue[j] = '\0';
    sscanf(acTmpReturnValue, "%64llx", &number);

    new_mac = number + pEntry->MACAddrOffSet;

    snprintf(hex, sizeof(hex), "%08llx", new_mac);
    snprintf(macStr, sizeof(macStr), "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
    hex[0], hex[1], hex[2], hex[3], hex[4], hex[5], hex[6], hex[7], hex[8], hex[9], hex[10], hex[11]);

    v_secure_system("ip link set dev %s address %s\n",pEntry->Name, macStr);

    return ANSC_STATUS_SUCCESS;
}

#endif //VLAN_MANAGER_HAL_ENABLED

static ANSC_STATUS EthLink_GetUnTaggedVlanInterfaceStatus(const char *iface, ethernet_link_status_e *status)
{
    int sfd;
    int flag = FALSE;
    struct ifreq intf;

    if(iface == NULL) {
       *status = ETH_IF_NOTPRESENT;
       return ANSC_STATUS_FAILURE;
    }

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        *status = ETH_IF_ERROR;
        return ANSC_STATUS_FAILURE;
    }

    memset (&intf, 0, sizeof(struct ifreq));
    strncpy(intf.ifr_name, iface, sizeof(intf.ifr_name) - 1);

    if (ioctl(sfd, SIOCGIFFLAGS, &intf) == -1) {
        *status = ETH_IF_ERROR;
    } else {
        flag = (intf.ifr_flags & IFF_RUNNING) ? TRUE : FALSE;
    }

    if(flag == TRUE)
        *status = ETH_IF_UP;
    else
        *status = ETH_IF_DOWN;

    close(sfd);

    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS EthLink_GetVlanIdAndTPId(const PDML_ETHERNET pEntry, INT *pVlanId, ULONG *pTPId)
{
    INT VLANInstance = -1;
    ULONG VlanCount = 0;
    ANSC_HANDLE pNewEntry = NULL;
    CHAR BaseInterface[64] = {0};

    if (pVlanId == NULL || pEntry == NULL)
    {
        CcspTraceError(("[%s-%d] Invalid argument \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_BAD_PARAMETER;
    }

    VlanCount = Vlan_GetEntryCount(NULL);
    for (int i = 0; i < VlanCount; i++)
    {
        pNewEntry = Vlan_GetEntry(NULL, i, &VLANInstance);
        if (pNewEntry != NULL)
        {
            memset(BaseInterface, 0, sizeof(BaseInterface));
            if (Vlan_GetParamStringValue(pNewEntry, "X_RDK_BaseInterface", BaseInterface, sizeof(BaseInterface)) == 0)
            {
                if( 0 == strncmp(pEntry->BaseInterface, BaseInterface, 3) )
                    break;
            }
        }
        pNewEntry = NULL;
    }

    //Get VLAN Term.
    CcspTraceInfo(("%s VLANInstance=%d \n", __FUNCTION__, VLANInstance));
    if ((-1 == VLANInstance) || (pNewEntry == NULL))
    {
        CcspTraceError(("%s Failed to get VLAN Instance \n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Get VLANID
    if (Vlan_GetParamIntValue(pNewEntry, "VLANID", pVlanId) != TRUE)
    {
        CcspTraceError(("%s - Failed to set VLANID data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Get TPID
    if (Vlan_GetParamUlongValue(pNewEntry, "TPID", pTPId) != TRUE)
    {
        CcspTraceError(("%s - Failed to set TPID data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS EthLink_GetMacAddr( PDML_ETHERNET pEntry )
{
    char acTmpReturnValue[256] = {0};
    char hex[32];
    char buff[2] = {0};
    char arr[12] = {0};
    char c;
    char macStr[32];
    int i, j = 0;

    if (pEntry->InstanceNumber <= 0)
    {
        CcspTraceError(("%s-%d: Failed to get Mac Address, EthLinkInstance=%d ", __FUNCTION__, __LINE__, pEntry->InstanceNumber));
        return ANSC_STATUS_FAILURE;
    }

    if(ANSC_STATUS_FAILURE == DmlEthGetParamValues(RDKB_PAM_COMPONENT_NAME, RDKB_PAM_DBUS_PATH, PAM_BASE_MAC_ADDRESS, acTmpReturnValue))
    {
        CcspTraceError(("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    for(i = 0; acTmpReturnValue[i] != '\0'; i++)
    {
        if(acTmpReturnValue[i] != ':')
        {
            acTmpReturnValue[j++] = acTmpReturnValue[i];
        }
    }

    acTmpReturnValue[j] = '\0';
    for (int k=0;k<12;k++)
    {
        c = acTmpReturnValue[k];
        buff[0] = c;
        arr[k] = strtol(buff,NULL,16);
    }

    arr[11] = arr[11] + pEntry->MACAddrOffSet;

    snprintf(hex, sizeof(hex), "%x%x%x%x%x%x%x%x%x%x%x%x", 
    arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9], arr[10], arr[11]);

    snprintf(macStr, sizeof(macStr), "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
    hex[0], hex[1], hex[2], hex[3], hex[4], hex[5], hex[6], hex[7], hex[8], hex[9], hex[10], hex[11]);

    strcpy(pEntry->MACAddress, macStr);

    return ANSC_STATUS_SUCCESS;
 }

