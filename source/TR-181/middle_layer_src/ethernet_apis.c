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
#include "vlan_mgr_apis.h"
#include "ethernet_apis.h"
#include "ethernet_internal.h"
#include <sysevent/sysevent.h>
#include "plugin_main_apis.h"
#include "vlan_internal.h"
#include "vlan_dml.h"

#include <syscfg.h>

/* **************************************************************************************************** */
#define SYSEVENT_ETH_WAN_MAC                       "eth_wan_mac"

#ifdef _HUB4_PRODUCT_REQ_
//VLAN ID
#ifdef ENABLE_VLAN100
#define VLANID_VALUE    100
#else
#define VLANID_VALUE    101
#endif
#endif // _HUB4_PRODUCT_REQ_

#define DATAMODEL_PARAM_LENGTH 256

//ETH Agent.
#define ETH_DBUS_PATH                     "/com/cisco/spvtg/ccsp/ethagent"
#define ETH_COMPONENT_NAME                "eRT.com.cisco.spvtg.ccsp.ethagent"
#define ETH_NOE_PARAM_NAME                "Device.Ethernet.X_RDK_InterfaceNumberOfEntries"
#define ETH_STATUS_PARAM_NAME             "Device.Ethernet.X_RDK_Interface.%d.WanStatus"
#define ETH_IF_PARAM_NAME                 "Device.Ethernet.X_RDK_Interface.%d.Name"

//DSL Agent.
#define DSL_DBUS_PATH                     "/com/cisco/spvtg/ccsp/xdslmanager"
#define DSL_COMPONENT_NAME                "eRT.com.cisco.spvtg.ccsp.xdslmanager"
#define DSL_LINE_NOE_PARAM_NAME           "Device.DSL.LineNumberOfEntries"
#define DSL_LINE_WAN_STATUS_PARAM_NAME    "Device.DSL.Line.%d.X_RDK_WanStatus"
#define DSL_LINE_PARAM_NAME               "Device.DSL.Line.%d.Name"

//WAN Agent
#define WAN_DBUS_PATH                     "/com/cisco/spvtg/ccsp/wanmanager"
#define WAN_COMPONENT_NAME                "eRT.com.cisco.spvtg.ccsp.wanmanager"
#define WAN_NOE_PARAM_NAME                "Device.X_RDK_WanManager.CPEInterfaceNumberOfEntries"
#define WAN_IF_VLAN_NAME_PARAM            "Device.X_RDK_WanManager.CPEInterface.%d.Wan.Name"
#define WAN_IF_NAME_PARAM_NAME            "Device.X_RDK_WanManager.CPEInterface.%d.Name"
#define WAN_IF_LINK_STATUS                "Device.X_RDK_WanManager.CPEInterface.%d.Wan.LinkStatus"
#define WAN_IF_STATUS_PARAM_NAME          "Device.X_RDK_WanManager.CPEInterface.%d.Wan.Status"

#define WAN_MARKING_NOE_PARAM_NAME        "Device.X_RDK_WanManager.CPEInterface.%d.MarkingNumberOfEntries"
#define WAN_MARKING_TABLE_NAME            "Device.X_RDK_WanManager.CPEInterface.%d.Marking."

extern void* g_pDslhDmlAgent;
extern ANSC_HANDLE                        g_MessageBusHandle;
extern COSAGetSubsystemPrefixProc         g_GetSubsystemPrefix;
extern char                               g_Subsystem[32];
extern  ANSC_HANDLE                       bus_handle;
        int                               sysevent_fd = -1;
        token_t                           sysevent_token;

static ANSC_STATUS DmlEthSetParamValues(const char *pComponent, const char *pBus, const char *pParamName, const char *pParamVal, enum dataType_e type, unsigned int bCommitFlag);
static ANSC_STATUS DmlEthGetParamNames(char *pComponent, char *pBus, char *pParamName, char a2cReturnVal[][256], int *pReturnSize);
static ANSC_STATUS DmlEthGetLowerLayersInstance(char *pLowerLayers, INT *piInstanceNumber);
static ANSC_STATUS DmlCreateVlanLink(PDML_ETHERNET pEntry);
static ANSC_STATUS DmlEthGetParamValues(char *pComponent, char *pBus, char *pParamName, char *pReturnVal);
static ANSC_STATUS DmlEthDeleteVlanLink(PDML_ETHERNET pEntry);
static BOOL DmlEthCheckVlanTaggedIfaceExists (char* ifName);
static ANSC_STATUS DmlEthGetLowerLayersInstanceFromEthAgent(char *ifname, INT *piInstanceNumber);
static ANSC_STATUS DmlEthGetLowerLayersInstanceFromWanManager(char *ifname, INT *piInstanceNumber);
static void* DmlEthHandleVlanRefreshThread( void *arg );
#ifdef _HUB4_PRODUCT_REQ_
static ANSC_STATUS DmlEthCreateMarkingTable(vlan_configuration_t* pVlanCfg);
#endif
static int DmlEthSyseventInit( void );
static int DmlGetDeviceMAC( char *pMACOutput, int iMACLength );
static ANSC_STATUS DmlUpdateEthWanMAC( void );
static ANSC_STATUS DmlDeleteUnTaggedVlanLink(const PDML_ETHERNET pEntry);
static ANSC_STATUS DmlCreateUnTaggedVlanLink(const PDML_ETHERNET pEntry);
/* *************************************************************************************************** */

ANSC_STATUS
SEthListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCONTEXT_LINK_OBJECT        pCosaContext
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PCONTEXT_LINK_OBJECT            pCosaContextEntry = (PCONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContext->InstanceNumber < pCosaContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pCosaContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}

PCONTEXT_LINK_OBJECT
SEthListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PCONTEXT_LINK_OBJECT            pCosaContextEntry = (PCONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        return NULL;
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContextEntry->InstanceNumber == InstanceNumber )
            {
                return pCosaContextEntry;
            }
        }
    }

    return NULL;
}

/* * DmlEthSyseventInit() */
static int DmlEthSyseventInit( void )
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
        DmlEthInit
            (
                ANSC_HANDLE                 hDml,
                PANSC_HANDLE                phContext,
                PFN_DML_ETHERNET_GEN        pValueGenFn
            );

        Description:
            This is the initialization routine for ETHERNET backend.

        Arguments:
            hDml               Opaque handle from DM adapter. Backend saves this handle for calling pValueGenFn.
             phContext       Opaque handle passed back from backend, needed by CosaDmlETHERNETXyz() routines.
            pValueGenFn    Function pointer to instance number/alias generation callback.

        Return:
            Status of operation.

**********************************************************************/
ANSC_STATUS
DmlEthInit
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext,
        PFN_DML_ETHERNET_GEN        pValueGenFn
    )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    // Initialize sysevent
    if ( DmlEthSyseventInit( ) < 0 )
    {
        return ANSC_STATUS_FAILURE;
    }

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        PDML_ETHERNET
        DmlGetEthCfg
            (
                ANSC_HANDLE                 hContext,
                PULONG                      instanceNum
            )
        Description:
            This routine is to retrieve the ETHERNET instances.

        Arguments:
            InstanceNum.

        Return:
            The pointer to ETHERNET table, allocated by calloc. If no entry is found, NULL is returned.

**********************************************************************/

ANSC_STATUS
DmlGetEthCfg
    (
        ANSC_HANDLE                 hContext,
        ULONG                       InstanceNum,
        PDML_ETHERNET          p_Eth
    )
{
    BOOL                            bSetBack     = FALSE;
    ULONG                           ulIndex      = 0;
    int                             rc           = 0;
    int                             count = 0;
    if ( p_Eth == NULL )
    {
        CcspTraceWarning(("DmlGetEthCfg pTrigger is NULL!\n"));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlGetEthCfgIfStatus
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
DmlGetEthCfgIfStatus
    (
        ANSC_HANDLE         hContext,
        PDML_ETHERNET      pEntry          /* Identified by InstanceNumber */
    )
{
    ANSC_STATUS             returnStatus  = ANSC_STATUS_FAILURE;
    vlan_interface_status_e status;

    if (pEntry != NULL) {
        if( pEntry->Enable) {
            if ( ANSC_STATUS_SUCCESS != getInterfaceStatus (pEntry->Name, &status)) {
                pEntry->Status = ETHERNET_IF_STATUS_ERROR;
                CcspTraceError(("%s %d - %s: Failed to get interface status for this %s\n", __FUNCTION__,__LINE__, pEntry->Name));
            }
            else {
                pEntry->Status = status;
                returnStatus = ANSC_STATUS_SUCCESS;
            }
        }
    }
    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlCreateEthInterface
            (
                ANSC_HANDLE         hThisObject,
                PDML_ETHERNET      pEntry
            );

    Description:
        The API create the designated ETHERNET interface
    Arguments:
        pAlias      The entry is identified through Alias.
        pEntry      The new configuration is passed through this argument, even Alias field can be changed.

    Return:
        Status of the operation

**********************************************************************/

ANSC_STATUS
DmlCreateEthInterface
    (
        ANSC_HANDLE         hContext,
        PDML_ETHERNET  pEntry          /* Identified by InstanceNumber */
    )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_FAILURE;

    //When enable flag is true
    if ( TRUE == pEntry->Enable)
    {
        returnStatus = DmlSetEthCfg(hContext, pEntry);

        if( ANSC_STATUS_SUCCESS == returnStatus )
        {
            CcspTraceInfo(("%s - %s:Successfully created VLAN\n", __FUNCTION__,ETH_MARKER_VLAN_IF_CREATE));
        }
        else
        {
            CcspTraceInfo(("%s - %s:Failed to create VLAN ErrorCode:%ld\n", __FUNCTION__,ETH_MARKER_VLAN_IF_CREATE,returnStatus));
        }
    }

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlDeleteEthInterface
            (
                ANSC_HANDLE         hThisObject,
                PDML_ETHERNET      pEntry
            );

    Description:
        The API delete the designated ETHERNET interface from the system
    Arguments:
        pAlias      The entry is identified through Alias.
        pEntry      The new configuration is passed through this argument, even Alias field can be changed.

    Return:
        Status of the operation

**********************************************************************/

ANSC_STATUS
DmlDeleteEthInterface
    (
        ANSC_HANDLE         hContext,
        PDML_ETHERNET  pEntry          /* Identified by InstanceNumber */
    )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    pthread_t VlanObjDeletionThread;
    int iErrorCode = 0;
    int ret;
    char region[16] = {0};
    vlan_interface_status_e status;
    hal_param_t req_param;

    /*
     * 1. Check any tagged vlan interface exists. This can be confirmed by checking the existence
     *    VLANTermination. instance.
     * 2. In case of any untagged interface exists, delete it.
     *
     * In case if vlanId is >= 0  indicates , a tagged vlan interface required in the region,
     * else required untagged interface
     */
    int vlanid = DEFAULT_VLAN_ID;
    returnStatus = GetVlanId(&vlanid, pEntry);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceError (("[%s-%d] Failed to get the vlan id \n", __FUNCTION__, __LINE__));
        return returnStatus;
    }

    if (vlanid >= 0)
    {
        if (ANSC_STATUS_SUCCESS != DmlEthDeleteVlanLink(pEntry))
        {
            CcspTraceError(("%s %s:Failed to delete VLANTermination table\n ",__FUNCTION__,ETH_MARKER_VLAN_IF_DELETE));
            return ANSC_STATUS_FAILURE;
        }

         CcspTraceInfo(("%s %s:Successfully deleted VLANTermination table\n",__FUNCTION__,ETH_MARKER_VLAN_IF_DELETE));
        return ANSC_STATUS_SUCCESS;
    }
    else /* Untagged */
    {
        /**
         * @note Delete Untagged VLAN interface
        */
        if (ANSC_STATUS_SUCCESS != DmlDeleteUnTaggedVlanLink(pEntry))
        {
            CcspTraceError(("[%s-%d] Failed to delete Untagged VLAN interface\n ", __FUNCTION__, __LINE__));
            return ANSC_STATUS_FAILURE;
        }
        else
        {
            /**
             * @note Notify WanStatus to WAN Manager and Base Manager.
            */
            DmlEthSendWanStatusForBaseManager(pEntry->BaseInterface, "Down");
            CcspTraceInfo(("[%s-%d] Successfully deleted Untagged VLAN interface \n", __FUNCTION__, __LINE__));
        }
    }

    return returnStatus;
}

static BOOL DmlEthCheckVlanTaggedIfaceExists( char *ifName )
{
    INT iVLANInstance = -1;

    //Validate buffer
    if ( NULL == ifName )
    {
        CcspTraceError(("%s %d - Invalid Memory\n", __FUNCTION__,__LINE__));
        return FALSE;
    }

    //Get Instance for corresponding lower layer
    DmlEthGetLowerLayersInstance( ifName, &iVLANInstance );

    //Index is not present. so no need to do anything any ETH Link instance
    if ( -1 == iVLANInstance )
    {
        CcspTraceError(("%s - Vlan link instance not present\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

/* * DmlSetEthCfg() */
ANSC_STATUS
DmlSetEthCfg
    (
        ANSC_HANDLE         hContext,
        PDML_ETHERNET       pEntry          /* Identified by InstanceNumber */
    )
{
    ANSC_STATUS               returnStatus = ANSC_STATUS_FAILURE;
    int                       ret;
    char                      region[16]   = { 0 };
    vlan_configuration_t      vlan_conf    = { 0 };
    pthread_t                 VlanObjCreationThread;
    int                       iErrorCode   = 0;
    vlan_interface_status_e   status;
    hal_param_t req_param;

    /*
     * First check any VLAN interface exists or not for this interface.
     *
     * 1. Check router region to identify tagged/untagged vlan interface required/created.
     * 2. For Tagged VLAN interface, create VLANTermination instance.
     * 3. For Untagged VLAN interface, check we have any VLAN interface available in the
     *    system with the requested alias. If exists, delete it and the create new one.
     *    Hal API will return the existence of this VLAN interface.
     *
     * In case if vlanId is >= 0  indicates , a tagged vlan interface required in the region,
     * else required untagged interface.
     */
    int vlanid = 0;
    returnStatus = GetVlanId(&vlanid, pEntry);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceError (("[%s-%d] Failed to get the vlan id \n", __FUNCTION__, __LINE__));
        return returnStatus;
    }

    if (vlanid >= 0)
    {
        if (ANSC_STATUS_SUCCESS != DmlCreateVlanLink(pEntry))
        {
            CcspTraceInfo(("%s - Failed to create VLAN interface(%s)\n",__FUNCTION__, pEntry->Name));
        }
        CcspTraceInfo(("%s - Successfully created tagged interface(%s)\n",__FUNCTION__, pEntry->Name));
    }
    else
    {
        if (ANSC_STATUS_SUCCESS != DmlCreateUnTaggedVlanLink(pEntry))
        {
            CcspTraceInfo(("%s - Failed to create VLAN interface(%s)\n",__FUNCTION__, pEntry->Name));
        }
        CcspTraceInfo(("%s - Successfully created untagged interface(%s)\n",__FUNCTION__, pEntry->Name));
    }

    return ANSC_STATUS_SUCCESS;
}

/* * DmlCreateVlanLink() */
static ANSC_STATUS DmlCreateVlanLink( PDML_ETHERNET pEntry )
{
    INT iVLANInstance = -1;
    INT iVLANId = DEFAULT_VLAN_ID;
    INT iIterator = 0;
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = {0};
    char acSetParamValue[DATAMODEL_PARAM_LENGTH] = {0};
    char region[16] = {0};
    INT ifType = 0;
    INT VlanId = 0;
    INT TPId = 0;
    PDATAMODEL_VLAN    pVLAN    = (PDATAMODEL_VLAN)g_pBEManager->hVLAN;
    PDML_VLAN_CFG      pVlanCfg = NULL;
    ANSC_HANDLE pNewEntry = NULL;

    if (NULL == pEntry)
    {
        CcspTraceError(("%s Invalid buffer\n",__FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if( 0 == strncmp(pEntry->BaseInterface, "dsl", 3))
    {
       ifType = DSL;
    }
    else if( 0 == strncmp(pEntry->BaseInterface, "eth", 3))
    {
       ifType = WANOE;
    }
    else if( 0 == strncmp(pEntry->Alias, "veip", 4) )
    {
       ifType = GPON;
    }

    if (NULL != pVLAN)
    {
        int ret = platform_hal_GetRouterRegion(region);

        if( ret == RETURN_OK )
        {
            for (int nIndex=0; nIndex< pVLAN->ulVlanCfgInstanceNumber; nIndex++)
            {
                if ( pVLAN->VlanCfg && nIndex < pVLAN->ulVlanCfgInstanceNumber )
                {
                    pVlanCfg = pVLAN->VlanCfg+nIndex;

                    if( pVlanCfg->InterfaceType == ifType &&
                        ( 0 ==strncmp(region, pVlanCfg->Region , sizeof(pVlanCfg->Region))))
                    {
                        VlanId = pVlanCfg->VLANId;
                        TPId = pVlanCfg->TPId;
                        CcspTraceInfo(("%s VlanCfg found at nIndex[%d] !!!\n",__FUNCTION__, nIndex));
                    }
                }
            }
        }
    }
    else
    {
        CcspTraceError(("%s pVLAN(NULL)\n",__FUNCTION__));
    }

    DmlEthGetLowerLayersInstance(pEntry->Path, &iVLANInstance);

    //Create VLAN Link.
    if (-1 == iVLANInstance)
    {
        char acTableName[128] = {0};
        pNewEntry = Vlan_AddEntry(NULL, &iVLANInstance);

        if (pNewEntry == NULL)
        {
           CcspTraceError(("%s Failed to add table \n", __FUNCTION__));
           return ANSC_STATUS_FAILURE;
        }
    }
    else
    {
        CcspTraceError(("%s Interface already exists \n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s - Instance:%d\n", __FUNCTION__, iVLANInstance));

    //Set VLANID
    if (Vlan_SetParamUlongValue(pNewEntry, "VLANID", VlanId) != TRUE)
    {
        CcspTraceError(("%s - Failed to set VLANID data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Set TPID
    if (Vlan_SetParamUlongValue(pNewEntry, "TPID", TPId) != TRUE)
    {
        CcspTraceError(("%s - Failed to set TPId data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Set BaseInterface.
    if (Vlan_SetParamStringValue(pNewEntry, "X_RDK_BaseInterface", pEntry->BaseInterface) != TRUE)
    {
        CcspTraceError(("%s - Failed to set X_RDK_BaseInterface data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Set Alias
    if (Vlan_SetParamStringValue(pNewEntry, "Alias", pEntry->Alias) != TRUE)
    {
        CcspTraceError(("%s - Failed to set Alias data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Set VLAN Inetrfacename.
    if (Vlan_SetParamStringValue(pNewEntry, "Name", pEntry->Name) != TRUE)
    {
        CcspTraceError(("%s - Failed to set Name data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Set lowerlayers.
    if (Vlan_SetParamStringValue(pNewEntry, "LowerLayers", pEntry->Path) != TRUE)
    {
        CcspTraceError(("%s - Failed to set LowerLayers data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Set Enable.
    if (Vlan_SetParamBoolValue(pNewEntry, "Enable", TRUE) != TRUE)
    {
        CcspTraceError(("%s - Failed to set Enable data model\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Commit
    if (Vlan_Commit(pNewEntry) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s - Failed to commit data model changes\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s - %s:Successfully created vlan interface %s\n", __FUNCTION__, ETH_MARKER_VLAN_TABLE_CREATE, pEntry->Name));

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlEthDeleteVlanLink
            (
                const char *ifName,
            );

    Description:
        The API delete the VLANTermination instance..
    Arguments:
        ifName      Base Interface name

    Return:
        Status of the operation

**********************************************************************/
ANSC_STATUS DmlEthDeleteVlanLink(PDML_ETHERNET pEntry)
{
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = {0};
    char acSetParamValue[DATAMODEL_PARAM_LENGTH] = {0};
    char acTableName[128] = {0};
    INT LineIndex = -1;
    INT iVLANInstance = -1;
    char iface_alias[64] = {0};
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;

    //Validate buffer
    if (pEntry == NULL)
    {
        CcspTraceError(("[%s][%d]Invalid Memory\n", __FUNCTION__,__LINE__));
        return ANSC_STATUS_FAILURE;
    }
    strncpy(iface_alias, pEntry->Alias, sizeof(pEntry->Alias));

    //Get Instance for corresponding lower layer
    DmlEthGetLowerLayersInstance(pEntry->Path, &iVLANInstance);

    //Index is not present. so no need to do anything any ETH Link instance
    if (-1 == iVLANInstance)
    {
        CcspTraceError(("[%s][%d] Vlan link instance not present\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    //Set Enable - False
    UINT uInstanceNumber = 0;
    ANSC_HANDLE pVlanEntry = Vlan_GetEntry(NULL, (iVLANInstance - 1), &uInstanceNumber);
    if (pVlanEntry != NULL)
    {
        if (Vlan_SetParamBoolValue(pVlanEntry, "Enable", FALSE) != TRUE)
        {
            CcspTraceInfo(("[%s][%d] Failed to set Enable data model to false \n", __FUNCTION__, __LINE__));
            ret = ANSC_STATUS_FAILURE;
            goto EXIT;
        }
        if (Vlan_Commit(pVlanEntry) != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s - Failed to delete VLAN table instance (%d)\n", __FUNCTION__, uInstanceNumber));
            ret = ANSC_STATUS_FAILURE;
            goto EXIT;
        }

        //Delete Instance.
        if (Vlan_DelEntry(NULL, pVlanEntry) != ANSC_STATUS_SUCCESS)
        {
            ret = ANSC_STATUS_FAILURE;
            goto EXIT;
        }
    }

EXIT:
    /* Notify WanStatus to down for Base Manager. */
    DmlEthSendWanStatusForBaseManager(pEntry->BaseInterface, "Down");
    return ret;
}

/* * DmlEthGetLowerLayersInstance() */
static ANSC_STATUS DmlEthGetLowerLayersInstance( char *pLowerLayers, INT *piInstanceNumber )
{
    char acTmpReturnValue[256] = {0};
    INT iLoopCount, iTotalNoofEntries;
    UINT uInstanceNumber = 0;
    ULONG uSize = 0;

    //Total count
    iTotalNoofEntries = Vlan_GetEntryCount(NULL);

    if (0 >= iTotalNoofEntries)
    {
        return ANSC_STATUS_SUCCESS;
    }

    //Traverse from loop
    for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
    {
        //Query for LowerLayers
        ANSC_HANDLE pVlanEntry = Vlan_GetEntry(NULL, iLoopCount, &uInstanceNumber);
        if (pVlanEntry != NULL)
        {
            if (Vlan_GetParamStringValue(pVlanEntry, "LowerLayers", acTmpReturnValue, &uSize) == -1)
            {
                CcspTraceError(("[%s][%d] Failed to get LowerLayers value\n", __FUNCTION__, __LINE__));
                continue;
            }
        }

        //Compare lowerlayers
        if (0 == strcmp(acTmpReturnValue, pLowerLayers))
        {
            *piInstanceNumber = uInstanceNumber;
            break;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/* * DmlEthGetParamValues() */
static ANSC_STATUS DmlEthGetParamValues(
    char *pComponent,
    char *pBus,
    char *pParamName,
    char *pReturnVal)
{
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t **retVal;
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
        //CcspTraceWarning(("[%s][%d]parameterValue[%s]\n", __FUNCTION__, __LINE__,retVal[0]->parameterValue));

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

    //CcspTraceInfo(("Value being set [%s,%s][%d] \n", acParameterName,acParameterValue,ret));

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
    parameterInfoStruct_t **retInfo;
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
/**********************************************************************

    caller:     self

    prototype:

        PDML_ETHERNET
        DmlGetEthCfgs
            (
                ANSC_HANDLE                 hContext,
                PULONG                      pulCount,
                BOOLEAN                     bCommit
            )
        Description:
            This routine is to retrieve vlan table.

        Arguments:
            pulCount  is to receive the actual number of entries.

        Return:
            The pointer to the array of ETHERNET table, allocated by calloc. If no entry is found, NULL is returned.

**********************************************************************/

PDML_ETHERNET
DmlGetEthCfgs
    (
        ANSC_HANDLE                 hContext,
        PULONG                      pulCount,
        BOOLEAN                     bCommit
    )
{
    if ( !pulCount )
    {
        CcspTraceWarning(("CosaDmlGetEthCfgs pulCount is NULL!\n"));
        return NULL;
    }

    *pulCount = 0;

    return NULL;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlAddEth
            (
                ANSC_HANDLE                 hContext,
                PDML_ETHERNET      pEntry
            )

    Description:
        The API adds one vlan entry into ETHERNET table.

    Arguments:
        pEntry      Caller does not need to fill in Status or Alias fields. Upon return, callee fills in the generated Alias and associated Status.

    Return:
        Status of the operation.

**********************************************************************/

ANSC_STATUS
DmlAddEth
    (
        ANSC_HANDLE                 hContext,
        PDML_ETHERNET      pEntry
    )
{
    if (!pEntry)
    {
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS
DmlEthGetLowerLayersInstanceFromEthAgent(
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

    //CcspTraceInfo(("[%s][%d]TotalNoofEntries:%d\n", __FUNCTION__, __LINE__, iTotalNoofEntries));

    if ( 0 >= iTotalNoofEntries )
    {
        return ANSC_STATUS_SUCCESS;
    }

    //Traverse from loop
    for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
    {
        char acTmpQueryParam[256] = {0};

        //Query
        snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), ETH_IF_PARAM_NAME, iLoopCount + 1);

        memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
        if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(ETH_COMPONENT_NAME, ETH_DBUS_PATH, acTmpQueryParam, acTmpReturnValue))
        {
            CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
            continue;
        }

        //Compare name
        if (0 == strcmp(acTmpReturnValue, ifname))
        {
            *piInstanceNumber = iLoopCount + 1;
             break;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS
DmlEthGetLowerLayersInstanceFromDslAgent(
    char *ifname,
    INT *piInstanceNumber)
{
    char acTmpReturnValue[256] = {0};
    INT iLoopCount,
        iTotalNoofEntries;

    if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(DSL_COMPONENT_NAME, DSL_DBUS_PATH, DSL_LINE_NOE_PARAM_NAME, acTmpReturnValue))
    {
        CcspTraceError(("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    //Total count
    iTotalNoofEntries = atoi(acTmpReturnValue);

    if ( 0 >= iTotalNoofEntries )
    {
        return ANSC_STATUS_SUCCESS;
    }

    //Traverse from loop
    for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
    {
        char acTmpQueryParam[256] = {0};

        //Query
        snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), DSL_LINE_PARAM_NAME, iLoopCount + 1);

        memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
        if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(DSL_COMPONENT_NAME, DSL_DBUS_PATH, acTmpQueryParam, acTmpReturnValue))
        {
            CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
            continue;
        }

        //Compare name
        if (0 == strcmp(acTmpReturnValue, ifname))
        {
            *piInstanceNumber = iLoopCount + 1;
             break;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/* Set wan status event to Eth or DSL Agent */
ANSC_STATUS DmlEthSendWanStatusForBaseManager(char *ifname, char *WanStatus)
{
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = {0};
    INT iWANInstance = -1;
    INT iIsDSLInterface = 0;
    INT iIsWANOEInterface = 0;

    //Validate buffer
    if ((NULL == ifname) || (NULL == WanStatus))
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Like dsl0, dsl0 etc
    if( 0 == strncmp(ifname, "dsl", 3) )
    {
       iIsDSLInterface = 1;
    }
    else if( 0 == strncmp(ifname, "eth", 3) ) //Like eth3, eth0 etc
    {
       iIsWANOEInterface = 1;
    }
    else if( 0 == strncmp(ifname, "veip", 4) ) //Like veip0
    {
       iIsWANOEInterface = 1;
    }
    else
    {
        CcspTraceError(("%s Invalid WAN interface \n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if( iIsWANOEInterface )
    {
       //Get Instance for corresponding name
       DmlEthGetLowerLayersInstanceFromEthAgent(ifname, &iWANInstance);

       //Index is not present. so no need to do anything any WAN instance
       if (-1 == iWANInstance)
       {
          CcspTraceError(("%s %d Eth instance not present\n", __FUNCTION__, __LINE__));
          return ANSC_STATUS_FAILURE;
       }

       CcspTraceInfo(("%s - %s:WANOE ETH Link Instance:%d\n", __FUNCTION__, ETH_MARKER_NOTIFY_WAN_BASE, iWANInstance));

       //Set WAN Status
       snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, ETH_STATUS_PARAM_NAME, iWANInstance);
       DmlEthSetParamValues(ETH_COMPONENT_NAME, ETH_DBUS_PATH, acSetParamName, WanStatus, ccsp_string, TRUE);
    }
    else if( iIsDSLInterface )
    {
       //Get Instance for corresponding name
       DmlEthGetLowerLayersInstanceFromDslAgent(ifname, &iWANInstance);

       //Index is not present. so no need to do anything any WAN instance
       if (-1 == iWANInstance)
       {
          CcspTraceError(("%s %d DSL instance not present\n", __FUNCTION__, __LINE__));
          return ANSC_STATUS_FAILURE;
       }

       CcspTraceInfo(("%s - %s:DSL Line Instance:%d\n", __FUNCTION__, ETH_MARKER_NOTIFY_WAN_BASE, iWANInstance));

       //Set WAN Status
       snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, DSL_LINE_WAN_STATUS_PARAM_NAME, iWANInstance);
       DmlEthSetParamValues(DSL_COMPONENT_NAME, DSL_DBUS_PATH, acSetParamName, WanStatus, ccsp_string, TRUE);
    }

    CcspTraceInfo(("%s - %s:Successfully notified %s event to base WAN interface for %s interface \n", __FUNCTION__, ETH_MARKER_NOTIFY_WAN_BASE, WanStatus, ifname));

    return ANSC_STATUS_SUCCESS;
}

/* Set wan status event to WAN Manager */
ANSC_STATUS DmlEthSendLinkStatusForWanManager(char *ifname, char *LinkStatus)
{
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = {0};
    INT iWANInstance = -1;
    INT iIsDSLInterface = 0;
    INT iIsWANOEInterface = 0;

    //Validate buffer
    if ((NULL == ifname) || (NULL == LinkStatus))
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Get Instance for corresponding name
    DmlEthGetLowerLayersInstanceFromWanManager(ifname, &iWANInstance);

    //Index is not present. so no need to do anything any WAN instance
    if (-1 == iWANInstance)
    {
      CcspTraceError(("%s %d Interface instance not present\n", __FUNCTION__, __LINE__));
      return ANSC_STATUS_FAILURE;
    }


    //Set WAN LinkStatus
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, WAN_IF_LINK_STATUS, iWANInstance);
    DmlEthSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName, LinkStatus, ccsp_string, TRUE);

    CcspTraceInfo(("%s - %s:Successfully notified %s event to WAN Manager for %s interface \n", __FUNCTION__, ETH_MARKER_NOTIFY_WAN_BASE, LinkStatus, ifname));

    return ANSC_STATUS_SUCCESS;
}

static ANSC_STATUS
DmlEthGetLowerLayersInstanceFromWanManager(
    char *ifname,
    INT *piInstanceNumber)
{
    char acTmpReturnValue[256] = {0};
    INT iLoopCount,
        iTotalNoofEntries;

    if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, WAN_NOE_PARAM_NAME, acTmpReturnValue))
    {
        CcspTraceError(("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    //Total count
    iTotalNoofEntries = atoi(acTmpReturnValue);

    if (0 >= iTotalNoofEntries)
    {
        return ANSC_STATUS_SUCCESS;
    }

    //Traverse from loop
    for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
    {
        char acTmpQueryParam[256] = {0};

        //Query
        snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), WAN_IF_NAME_PARAM_NAME, iLoopCount + 1);

        memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
        if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue))
        {
            CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
            continue;
        }

        //Compare name
        if (0 == strcmp(acTmpReturnValue, ifname))
        {
            *piInstanceNumber = iLoopCount + 1;
             break;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/* VLAN Refresh Thread */
static void* DmlEthHandleVlanRefreshThread( void *arg )
{
    PVLAN_REFRESH_CFG        pstRefreshCfg = (PVLAN_REFRESH_CFG)arg;
    char                     acGetParamName[256],
                             acSetParamName[256],
                             acTmpReturnValue[256],
                             a2cTmpTableParams[16][256] = {0};
    vlan_interface_status_e  status = VLAN_IF_DOWN;
    INT                      iIterator = 0;
    ANSC_STATUS              returnStatus;

    //Validate buffer
    if ( NULL == pstRefreshCfg )
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        pthread_exit(NULL);
    }

    //detach thread from caller stack
    pthread_detach(pthread_self());

    returnStatus = VlanManager_SetVlanMarkings( pstRefreshCfg->WANIfName, &(pstRefreshCfg->stVlanCfg), FALSE);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceError(("[%s][%d]Failed to create VLAN interface \n", __FUNCTION__, __LINE__));
        goto EXIT;
    }


    //Get status of VLAN link
    while(iIterator < 10)
    {
        if (ANSC_STATUS_FAILURE == getInterfaceStatus(pstRefreshCfg->stVlanCfg.L3Interface, &status))
        {
            CcspTraceError(("[%s][%d] getInterfaceStatus failed for %s !! \n", __FUNCTION__, __LINE__, pstRefreshCfg->stVlanCfg.L3Interface));
            goto EXIT;
        }
        if (status == VLAN_IF_UP)
        {
            //Needs to inform base interface is UP after vlan refresh
            DmlEthSendLinkStatusForWanManager(pstRefreshCfg->stVlanCfg.BaseInterface, "Up");
            break;
        }

        iIterator++;
        sleep(2);
    }

    CcspTraceInfo(("%s - %s:Successfully refreshed VLAN WAN interface(%s)\n", __FUNCTION__, ETH_MARKER_VLAN_REFRESH, pstRefreshCfg->WANIfName));

EXIT:

    //Free allocated resource
    if( NULL != pstRefreshCfg )
    {
        free(pstRefreshCfg);
        pstRefreshCfg = NULL;
    }

    //Clean exit
    pthread_exit(NULL);

    return NULL;
}



ANSC_STATUS VlanManager_SetVlanMarkings( char *ifname, vlan_configuration_t *pVlanCfg, BOOL vlan_creation)
{
    char                     acGetParamName[256] = {0},
                             acSetParamName[256] = {0},
                             acTmpReturnValue[256] = {0},
                             a2cTmpTableParams[16][256] = {0};
    INT                      iLoopCount,
                             iTotalNoofEntries = 0,
                             iWANInstance   = -1;

    //Validate buffer
    if ( ( NULL == ifname ) || ( NULL == pVlanCfg ) )
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }
    //Get Instance for corresponding name
    DmlEthGetLowerLayersInstanceFromWanManager(pVlanCfg->BaseInterface, &iWANInstance);

    //Index is not present. so no need to do anything any WAN instance
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

    //Total count
    iTotalNoofEntries = atoi(acTmpReturnValue);

    CcspTraceInfo(("%s Wan Instance(%d) Marking Entries:%d\n", __FUNCTION__, iWANInstance, iTotalNoofEntries));

#ifdef _HUB4_PRODUCT_REQ_
    //Allocate resource for marking
    pVlanCfg->skbMarkingNumOfEntries = iTotalNoofEntries;

    //Allocate memory when non-zero entries
    if( pVlanCfg->skbMarkingNumOfEntries > 0 )
    {
       pVlanCfg->skb_config = (vlan_skb_config_t*)malloc( iTotalNoofEntries * sizeof(vlan_skb_config_t) );

       if( NULL == pVlanCfg->skb_config )
       {
          return ANSC_STATUS_FAILURE;
       }

       //Fetch all the marking names
       iTotalNoofEntries = 0;

       memset(acGetParamName, 0, sizeof(acGetParamName));
       snprintf(acGetParamName, sizeof(acGetParamName), WAN_MARKING_TABLE_NAME, iWANInstance);

       if ( ANSC_STATUS_FAILURE == DmlEthGetParamNames(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acGetParamName, a2cTmpTableParams, &iTotalNoofEntries))
       {
           CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
           return ANSC_STATUS_FAILURE;
       }

       //Traverse from loop
       for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
       {
           char acTmpQueryParam[256];

           //Alias
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sAlias", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           snprintf(pVlanCfg->skb_config[iLoopCount].alias, sizeof(pVlanCfg->skb_config[iLoopCount].alias), "%s", acTmpReturnValue);

           //SKBPort
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sSKBPort", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           pVlanCfg->skb_config[iLoopCount].skbPort = atoi(acTmpReturnValue);

           //SKBMark
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sSKBMark", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           pVlanCfg->skb_config[iLoopCount].skbMark = atoi(acTmpReturnValue);

           //EthernetPriorityMark
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sEthernetPriorityMark", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           pVlanCfg->skb_config[iLoopCount].skbEthPriorityMark = atoi(acTmpReturnValue);

           CcspTraceInfo(("WAN Marking - Ins[%d] Alias[%s] SKBPort[%u] SKBMark[%u] EthernetPriorityMark[%d]\n",
                                                                iLoopCount + 1,
                                                                pVlanCfg->skb_config[iLoopCount].alias,
                                                                pVlanCfg->skb_config[iLoopCount].skbPort,
                                                                pVlanCfg->skb_config[iLoopCount].skbMark,
                                                                pVlanCfg->skb_config[iLoopCount].skbEthPriorityMark ));
        }
    }
    //Create and initialise Marking data models
    DmlEthCreateMarkingTable(pVlanCfg);

    //Only refresh
    if( vlan_creation != TRUE )
    {
        //Configure SKB Marking entries
        vlan_eth_hal_setMarkings(pVlanCfg);
    }
    else
    {
        //Create vlan interface
        vlan_eth_hal_createInterface(pVlanCfg);
    }
#else
    //Create vlan interface
    vlan_eth_hal_createInterface(pVlanCfg);
#endif

    //Needs to set eth_wan_mac for ETHWAN case
    DmlUpdateEthWanMAC( );

    /* This sleep is inevitable as we noticed hung issue with DHCP clients
    when we start the clients quickly after we assign the MAC address on the interface
    where it going to run. Even though we check the interface status using ioctl
    SIOCGIFFLAGS call, the hung issue still reproducible. Not observed this issue with a
    two seconds delay after MAC assignment. */
    sleep(2);

    return ANSC_STATUS_SUCCESS;
}



/* Set VLAN Refresh */
ANSC_STATUS DmlEthSetVlanRefresh( char *ifname, VLAN_REFRESH_CALLER_ENUM  enRefreshCaller, vlan_configuration_t *pstVlanCfg )
{
    pthread_t                refreshThreadId;
    PVLAN_REFRESH_CFG        pstRefreshCfg  = NULL;
    INT                      iWANInstance   = -1,
                             *piWANInstance = NULL,
                             iErrorCode     = -1;

    //Validate buffer
    if ( ( NULL == ifname ) || ( NULL == pstVlanCfg ) )
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

     //Get Instance for corresponding name
    DmlEthGetLowerLayersInstanceFromWanManager(ifname, &iWANInstance);

    //Index is not present. so no need to do anything any WAN instance
    if (-1 == iWANInstance)
    {
        CcspTraceError(("%s %d Eth instance not present\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s %d Wan Interface Instance:%d\n", __FUNCTION__, __LINE__, iWANInstance));

    pstRefreshCfg = (PVLAN_REFRESH_CFG)malloc(sizeof(VLAN_REFRESH_CFG));
    if( NULL == pstRefreshCfg )
    {
        CcspTraceError(("%s %d Failed to allocate memory\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    //Assigning WAN params for thread
    memset(pstRefreshCfg, 0, sizeof(VLAN_REFRESH_CFG));

    pstRefreshCfg->iWANInstance     = iWANInstance;
    snprintf( pstRefreshCfg->WANIfName, sizeof(pstRefreshCfg->WANIfName), "%s", ifname );
    pstRefreshCfg->enRefreshCaller  = enRefreshCaller;
    memcpy( &pstRefreshCfg->stVlanCfg, pstVlanCfg, sizeof(vlan_configuration_t) );

    //VLAN refresh thread
    iErrorCode = pthread_create( &refreshThreadId, NULL, &DmlEthHandleVlanRefreshThread, (void*)pstRefreshCfg );

    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start VLAN refresh thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return ANSC_STATUS_FAILURE;
    }

    if(pstRefreshCfg == NULL) {
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

/* * DmlUpdateEthWanMAC() */
static ANSC_STATUS DmlUpdateEthWanMAC( void )
{
   char   acTmpETHWANFlag[ 16 ]  = { 0 },
          acTmpMACBuffer[ 64 ]   = { 0 };
   INT    iIsETHWANEnabled       = 0;

   //Check whether eth wan is enabled or not
   if ( syscfg_get( NULL, "eth_wan_enabled", acTmpETHWANFlag, sizeof( acTmpETHWANFlag ) ) == 0 )
   {
       if( 0 == strncmp( acTmpETHWANFlag, "true", strlen("true") ) )
       {
           iIsETHWANEnabled = 1;
       }
   }

   //Configure only for ethwan case
   if ( ( 1 == iIsETHWANEnabled ) && ( 0 == DmlGetDeviceMAC( acTmpMACBuffer, sizeof( acTmpMACBuffer ) ) ) )
   {
      sysevent_set( sysevent_fd, sysevent_token, SYSEVENT_ETH_WAN_MAC, acTmpMACBuffer , 0 );

      return ANSC_STATUS_SUCCESS;
   }

   return ANSC_STATUS_FAILURE;
}

/* * DmlGetDeviceMAC() */
static int DmlGetDeviceMAC( char *pMACOutput, int iMACLength )
{
   char   acTmpBuffer[32]   = { 0 };
   FILE   *fp = NULL;

   if( NULL == pMACOutput )
   {
       return -1;
   }

   //Get erouter0 MAC address
   fp = popen( "cat /sys/class/net/erouter0/address", "r" );

   if( NULL != fp )
   {
       char *p = NULL;

       fgets( acTmpBuffer, sizeof( acTmpBuffer ), fp );

       /* we need to remove the \n char in buffer */
       if ((p = strchr(acTmpBuffer, '\n'))) *p = 0;

       //Copy buffer
       snprintf( pMACOutput, iMACLength, "%s", acTmpBuffer );
       CcspTraceInfo(("%s %d - Received deviceMac from netfile [%s]\n", __FUNCTION__,__LINE__,acTmpBuffer));

       pclose(fp);
       fp = NULL;

       return 0;
   }

   return -1;
}

#ifdef _HUB4_PRODUCT_REQ_
static ANSC_STATUS DmlEthCreateMarkingTable(vlan_configuration_t* pVlanCfg)
{
    if (NULL == pVlanCfg)
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    PDATAMODEL_ETHERNET    pMyObject    = (PDATAMODEL_ETHERNET)g_pBEManager->hEth;
    PSINGLE_LINK_ENTRY     pSListEntry  = NULL;
    PCONTEXT_LINK_OBJECT   pCxtLink     = NULL;
    PDML_ETHERNET          p_EthLink    = NULL;
    int                    iLoopCount   = 0;

    pSListEntry = AnscSListGetEntryByIndex(&pMyObject->Q_EthList, 0);
    if(pSListEntry == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    pCxtLink   = (PCONTEXT_LINK_OBJECT) pSListEntry;
    if(pCxtLink == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    p_EthLink = (PDML_ETHERNET) pCxtLink->hContext;
    if(p_EthLink == NULL)
    {
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
       (p_EthLink->pstDataModelMarking + iLoopCount)->SKBPort = pVlanCfg->skb_config[iLoopCount].skbPort;
       (p_EthLink->pstDataModelMarking + iLoopCount)->EthernetPriorityMark = pVlanCfg->skb_config[iLoopCount].skbEthPriorityMark;
    }

    return ANSC_STATUS_SUCCESS;
}
#endif //_HUB4_PRODUCT_REQ_

ANSC_STATUS getInterfaceStatus(const char *iface, vlan_interface_status_e *status)
{
    int sfd;
    int flag = FALSE;
    struct ifreq intf;

    if(iface == NULL) {
       *status = VLAN_IF_NOTPRESENT;
       return ANSC_STATUS_FAILURE;
    }

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        *status = VLAN_IF_ERROR;
        return ANSC_STATUS_FAILURE;
    }

    strcpy(intf.ifr_name, iface);

    if (ioctl(sfd, SIOCGIFFLAGS, &intf) == -1) {
        *status = VLAN_IF_ERROR;
    } else {
        flag = (intf.ifr_flags & IFF_RUNNING) ? TRUE : FALSE;
    }

    if(flag == TRUE)
        *status = VLAN_IF_UP;
    else
        *status = VLAN_IF_DOWN;

    close(sfd);

    return ANSC_STATUS_SUCCESS;
}

/* * DmlGetHwAddressUsingIoctl() */
ANSC_STATUS DmlGetHwAddressUsingIoctl( const char *pIfNameInput, char *pMACOutput, size_t t_MacLength )
{
             int    sockfd;
    struct   ifreq  ifr;
    unsigned char  *ptr;

    if ( ( NULL == pIfNameInput ) || ( NULL == pMACOutput ) || ( t_MacLength  < sizeof( "00:00:00:00:00:00" ) ) )
    {
        CcspTraceError(("%s %d - Invalid input param\n",__FUNCTION__,__LINE__));
        return ANSC_STATUS_FAILURE;
    }

    if ( ( sockfd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 )
    {
        CcspTraceError(("%s %d - Socket error\n",__FUNCTION__,__LINE__));
        perror("socket");
        return ANSC_STATUS_FAILURE;
    }

    //Copy ifname into struct buffer
    snprintf( ifr.ifr_name, sizeof( ifr.ifr_name ), "%s", pIfNameInput );

    if ( ioctl( sockfd, SIOCGIFHWADDR, &ifr ) == -1 )
    {
        CcspTraceError(("%s %d - Ioctl error\n",__FUNCTION__,__LINE__));
        perror("ioctl");
        close( sockfd );
        return -1;
    }

    //Convert mac address
    ptr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    snprintf( pMACOutput, t_MacLength, "%02x:%02x:%02x:%02x:%02x:%02x",
            ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5] );

    close( sockfd );

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS GetVlanId(INT *pVlanId, const PDML_ETHERNET pEntry)
{
    if (pVlanId == NULL || pEntry == NULL)
    {
        CcspTraceError(("[%s-%d] Invalid argument \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_BAD_PARAMETER;
    }
#ifdef _HUB4_PRODUCT_REQ_
    char region[16] = {0};
    /**
     * @note  Retrieve vlan id based on the region.
     * The current implementation handles the following cases:
     *  1. UK and ITALY with DSL Line - Tagged Interface
     *  2. ITALY with WANOE - Tagged Interface
     *  3. UK with WANOE - UnTagged Interface
     *  4. All other regions - UnTagged Interface
     */
    INT ret = RETURN_OK;
    ret = platform_hal_GetRouterRegion(region);
    if (ret == RETURN_OK)
    {
        if ((strncmp(region, "IT", strlen("IT")) == 0) ||
            ( (strncmp(region, "GB", strlen("GB")) == 0) && (strstr(pEntry->BaseInterface, DSL_IFC_STR) != NULL)))
        {
            *pVlanId = VLANID_VALUE;
        }
        else
        {
            *pVlanId = DEFAULT_VLAN_ID;
        }
    }
    else
    {
        CcspTraceError(("[%s-%d] Failed to get router region \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_INTERNAL_ERROR;
    }

    CcspTraceInfo(("[%s-%d] Region = [%s] , Basename = [%s], Alias = [%s], VlanID = [%d] \n", __FUNCTION__, __LINE__, region, pEntry->Name, pEntry->Alias, *pVlanId));
#else
    *pVlanId = DEFAULT_VLAN_ID;
#endif // _HUB4_PRODUCT_REQ_
    return ANSC_STATUS_SUCCESS;
}


/**
 * @note Delete untagged vlan link interface.
 * Check if the interface exists and delete it.
 */
static ANSC_STATUS DmlDeleteUnTaggedVlanLink(const PDML_ETHERNET pEntry)
{
    if (pEntry == NULL)
    {
        CcspTraceError(("[%s-%d] Invalid parameter error! \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_BAD_PARAMETER;
    }

    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    vlan_interface_status_e status;

    returnStatus = getInterfaceStatus (pEntry->Name, &status);
    if (returnStatus != ANSC_STATUS_SUCCESS )
    {
        CcspTraceError(("[%s-%d] - %s: Failed to get VLAN interface status\n", __FUNCTION__, __LINE__, pEntry->Name));
        return returnStatus;
    }

    if ( ( status != VLAN_IF_NOTPRESENT ) && ( status != VLAN_IF_ERROR ) )
    {
        returnStatus = vlan_eth_hal_deleteInterface(pEntry->Name, pEntry->InstanceNumber);
        if (ANSC_STATUS_SUCCESS != returnStatus)
        {
            CcspTraceError(("[%s-%d] Failed to delete VLAN interface(%s)\n", __FUNCTION__, __LINE__, pEntry->Name));
        }
        else
        {
            CcspTraceInfo(("[%s-%d]  %s:Successfully deleted this %s VLAN interface \n", __FUNCTION__, __LINE__, ETH_MARKER_VLAN_IF_DELETE, pEntry->Name));
        }
    }
    return returnStatus;
}

/**
 * @note Create untagged VLAN interface.
 */
static ANSC_STATUS DmlCreateUnTaggedVlanLink(const PDML_ETHERNET pEntry)
{
    vlan_interface_status_e  status = VLAN_IF_DOWN;
    int iIterator = 0;

    if (pEntry == NULL )
    {
        CcspTraceError(("[%s-%d] Invalid parameter error! \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_BAD_PARAMETER;
    }

    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    /**
     * @note Delete vlan interface if it exists first.
     */
    DmlDeleteUnTaggedVlanLink(pEntry);

    /**
     * Create untagged vlan interface.
     */
    vlan_configuration_t vlan_conf = {0};
    strncpy(vlan_conf.BaseInterface, pEntry->BaseInterface, sizeof(vlan_conf.BaseInterface));
    strncpy(vlan_conf.L3Interface, pEntry->Name, sizeof(vlan_conf.L3Interface));
    strncpy(vlan_conf.L2Interface, pEntry->Alias, sizeof(vlan_conf.L2Interface));
    vlan_conf.VLANId = DEFAULT_VLAN_ID; /* Untagged interface */
    vlan_conf.TPId = 0;

    //Set Vlan Markings
    returnStatus = VlanManager_SetVlanMarkings(pEntry->Alias, &vlan_conf, TRUE);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        pEntry->Status = VLAN_IF_STATUS_ERROR;
        CcspTraceError(("[%s][%d]Failed to create VLAN interface \n", __FUNCTION__, __LINE__));
        return returnStatus;
    }

    //Get status of VLAN link
    while(iIterator < 10)
    {
        if (ANSC_STATUS_FAILURE == getInterfaceStatus(vlan_conf.L3Interface, &status))
        {
            CcspTraceError(("[%s][%d] getInterfaceStatus failed for %s !! \n", __FUNCTION__, __LINE__, vlan_conf.L3Interface));
            return ANSC_STATUS_FAILURE;
        }
        if (status == VLAN_IF_UP)
        {
            //Needs to inform base interface is UP after vlan creation
            DmlEthSendWanStatusForBaseManager(pEntry->BaseInterface, "Up");
            break;
        }

        iIterator++;
        sleep(2);
    }

    return ANSC_STATUS_SUCCESS;
}
