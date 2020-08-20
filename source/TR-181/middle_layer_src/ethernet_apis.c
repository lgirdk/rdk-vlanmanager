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

//VLAN Agent - VLANTermination
#define VLAN_DBUS_PATH                             "/com/cisco/spvtg/ccsp/vlanmanager"
#define VLAN_COMPONENT_NAME                        "eRT.com.cisco.spvtg.ccsp.vlanmanager"
#define VLAN_TERMINATION_TABLE_NAME                "Device.X_RDK_Ethernet.VLANTermination."
#define VLAN_TERMINATION_NOE_PARAM_NAME            "Device.X_RDK_Ethernet.VLANTerminationNumberOfEntries"
#define VLAN_TERMINATION_PARAM_VLANID              "Device.X_RDK_Ethernet.VLANTermination.%d.VLANID"
#define VLAN_TERMINATION_PARAM_TPID                "Device.X_RDK_Ethernet.VLANTermination.%d.TPID"
#define VLAN_TERMINATION_PARAM_ALIAS               "Device.X_RDK_Ethernet.VLANTermination.%d.Alias"
#define VLAN_TERMINATION_PARAM_BASEIFACE           "Device.X_RDK_Ethernet.VLANTermination.%d.X_RDK_BaseInterface"
#define VLAN_TERMINATION_PARAM_L3NAME              "Device.X_RDK_Ethernet.VLANTermination.%d.Name"
#define VLAN_TERMINATION_PARAM_LOWERLAYER          "Device.X_RDK_Ethernet.VLANTermination.%d.LowerLayers"
#define VLAN_TERMINATION_PARAM_ENABLE              "Device.X_RDK_Ethernet.VLANTermination.%d.Enable"
#define VLAN_TERMINATION_PARAM_STATUS             "Device.X_RDK_Ethernet.VLANTermination.%d.Status"

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


pthread_mutex_t mDeletionMutex; //Mutex to check the deletion status.
pthread_mutex_t mUpdationMutex; //Mutex to check the deletion status.

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
static void *VlanAgent_DMLUpdationHandlerThread(void *arg);
static void *VlanAgent_DMLDeletionHandlerThread(void *arg);
static BOOL DmlEthCheckVlanTaggedIfaceExists (char* ifName);
static ANSC_STATUS DmlEthGetLowerLayersInstanceFromEthAgent(char *ifname, INT *piInstanceNumber);
static ANSC_STATUS DmlEthSetWanManagerWanIfaceName(char *ifname, char *vlanifname);
static ANSC_STATUS DmlEthGetLowerLayersInstanceFromWanManager(char *ifname, INT *piInstanceNumber);
static void* DmlEthHandleVlanRefreshThread( void *arg );
#ifdef _HUB4_PRODUCT_REQ_
static ANSC_STATUS DmlEthCreateMarkingTable(PVLAN_REFRESH_CFG pstRefreshCfg);
#endif
static int DmlEthSyseventInit( void );
static int DmlGetDeviceMAC( char *pMACOutput, int iMACLength );
static ANSC_STATUS DmlUpdateEthWanMAC( void );
static ANSC_STATUS DmlEthSetWanLinkStatusForWanAgent(char *ifname, char *status);
static ANSC_STATUS DmlDeleteUnTaggedVlanLink(const CHAR *ifName, const PDML_ETHERNET pEntry);
static ANSC_STATUS DmlCreateUnTaggedVlanLink(const CHAR *ifName, const PDML_ETHERNET pEntry);
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

    pthread_mutex_init(&mDeletionMutex, NULL);
    pthread_mutex_init(&mUpdationMutex, NULL);

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
            if ( ANSC_STATUS_SUCCESS != getInterfaceStatus (WAN_INTERFACE_NAME, &status)) {
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
        /*
         * To check any VLAN tagged interface and to create a new one if not,
         * we need to start a new thread to check the existence and creation.
         * Otherwise it resulted in 2 minutes delay to create and execute the
         * VLAN termination.
         * To avoid multiple simultaneous execution protect it using mutex.
         */
         iErrorCode = pthread_create( &VlanObjDeletionThread, NULL, VlanAgent_DMLDeletionHandlerThread, (void *)pEntry );
         if ( iErrorCode != 0 )
         {
             CcspTraceError(("%s %d - Failed to start deletion handler thread\n",__FUNCTION__, __LINE__));
             return ANSC_STATUS_FAILURE;
         }

         return ANSC_STATUS_SUCCESS;
    }
    else /* Untagged */
    {

        char intf_name[64] = {'\0'};
        strncpy(intf_name, pEntry->Alias, sizeof(intf_name));
        /**
         * @note Delete Untagged VLAN interface
         */
        if (ANSC_STATUS_SUCCESS != DmlDeleteUnTaggedVlanLink(WAN_INTERFACE_NAME, pEntry))
        {
            CcspTraceError(("[%s-%d] Failed to delete Untagged VLAN interface\n ", __FUNCTION__, __LINE__));
        }
        else
        {
            CcspTraceInfo(("[%s-%d] Successfully deleted Untagged VLAN interface \n", __FUNCTION__, __LINE__));
            /**
             * @note Notify LinkStatus to WanAgent.
             */
            DmlEthSetWanLinkStatusForWanAgent(intf_name, "Down");
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
        return ANSC_STATUS_FAILURE;
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
        /*
         * In case of tagged VLAN interface creation, we need to start a new thread
         * and create VLANTermination Instance. Otherwise, we have noticed a delay
         * to create and update the VLANTermination instance and its parameters.
         */
         iErrorCode = pthread_create(&VlanObjCreationThread, NULL, VlanAgent_DMLUpdationHandlerThread, (void *)pEntry);
         if (iErrorCode != 0)
         {
             CcspTraceError(("%s %d - Failed to start the handler thread\n",__FUNCTION__, __LINE__));
             return ANSC_STATUS_FAILURE;
         }
 
         CcspTraceInfo(("%s %d - Successfully started VLAN creation thread\n",__FUNCTION__, __LINE__));
         return ANSC_STATUS_SUCCESS;
    }
    else
    {
        /**
         * @note Untagged interface creation.
         */
        if (ANSC_STATUS_SUCCESS == DmlCreateUnTaggedVlanLink(WAN_INTERFACE_NAME,pEntry))
        {
            CcspTraceInfo(("[%s-%d] %s:Successfully created untagged VLAN interface (%s)\n", __FUNCTION__, __LINE__, ETH_MARKER_VLAN_IF_CREATE, WAN_INTERFACE_NAME));
        }
        else
        {
            CcspTraceInfo(("[%s-%d] - Failed to create untagged VLAN interface(%s)\n", __FUNCTION__, __LINE__, WAN_INTERFACE_NAME));
        }
    }

    return ANSC_STATUS_SUCCESS;
}

/* * VlanAgent_DMLUpdationHandlerThread() */
static void *VlanAgent_DMLUpdationHandlerThread( void *arg )
{

    PDML_ETHERNET    pEntry = (PDML_ETHERNET)arg;
    INT              ret = 0;

    if ( NULL == pEntry )
    {
        CcspTraceError(("%s Invalid Argument\n",__FUNCTION__));
        pthread_exit(NULL);
    }

    //detach thread from caller stack
    pthread_detach(pthread_self());

    pthread_mutex_lock(&mUpdationMutex);

    /*
     *
     * Tagged interface creation.
     * Create VLANTERMINATION instance and update.
     *
     */
    if (ANSC_STATUS_SUCCESS == DmlCreateVlanLink(pEntry))
    {
        CcspTraceInfo(("%s - %s:Successfully created VLAN interface(%s)\n",__FUNCTION__,ETH_MARKER_VLAN_IF_CREATE,pEntry->Name));
    }
    else
    {
        CcspTraceInfo(("%s - Failed to create VLAN interface(%s)\n",__FUNCTION__,pEntry->Name));
    }

    pthread_mutex_unlock(&mUpdationMutex);

    //Exit thread.
    pthread_exit(NULL);
}

/* * VlanAgent_DMLDeletionHandlerThread() */
static void *VlanAgent_DMLDeletionHandlerThread( void *arg )
{

    PDML_ETHERNET    pEntry = (PDML_ETHERNET)arg;
    INT              ret    = 0;

    if ( NULL == pEntry )
    {
        CcspTraceError(("%s Invalid Argument\n",__FUNCTION__));
        pthread_exit(NULL);
    }

    //detach thread from caller stack
    pthread_detach(pthread_self());

    pthread_mutex_lock(&mDeletionMutex);

    //Delete VLANTERMINATION INSTANCE.
    if (ANSC_STATUS_SUCCESS != DmlEthDeleteVlanLink(pEntry))
    {
        CcspTraceError(("%s %s:Failed to delete VLANTermination table\n ",__FUNCTION__,ETH_MARKER_VLAN_IF_DELETE));
    }
    else
    {
        CcspTraceInfo(("%s %s:Successfully deleted VLANTermination table\n",__FUNCTION__,ETH_MARKER_VLAN_IF_DELETE));
    }

    pthread_mutex_unlock(&mDeletionMutex);

    //Exit thread.
    pthread_exit(NULL);
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

    if (NULL == pEntry)
    {
        CcspTraceError(("%s Invalid buffer\n",__FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }


    if( 0 == strncmp(pEntry->Alias, "dsl", 3) )
    {
       ifType = DSL;
    }
    else if( 0 == strncmp(pEntry->Alias, "eth", 3) )
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
                        CcspTraceError(("%s VlanCfg found at nIndex[%d] !!!\n",__FUNCTION__, nIndex));
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
        INT iNewTableInstance = -1;

        sprintf(acTableName, "%s", VLAN_TERMINATION_TABLE_NAME);
        if (CCSP_SUCCESS != CcspBaseIf_AddTblRow(
                                bus_handle,
                                VLAN_COMPONENT_NAME,
                                VLAN_DBUS_PATH,
                                0, /* session id */
                                acTableName,
                                &iNewTableInstance))
        {
           CcspTraceError(("%s Failed to add table %s\n", __FUNCTION__,acTableName));
           return ANSC_STATUS_FAILURE;
        }

        //Assign new instance
        iVLANInstance = iNewTableInstance;
    }

    CcspTraceInfo(("%s - %s Instance:%d\n", __FUNCTION__, VLAN_TERMINATION_TABLE_NAME, iVLANInstance));

    //Set VLANID
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, VLAN_TERMINATION_PARAM_VLANID, iVLANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%d", VlanId);
    if (ANSC_STATUS_SUCCESS != DmlEthSetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_unsignedInt, FALSE))
    {
        CcspTraceError(("%s - Failed to set [%s]\n", __FUNCTION__, VLAN_TERMINATION_PARAM_VLANID, iVLANInstance));
        return ANSC_STATUS_FAILURE;
    }

    //Set TPID
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, VLAN_TERMINATION_PARAM_TPID, iVLANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%d", TPId);
    if (ANSC_STATUS_SUCCESS != DmlEthSetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_unsignedInt, FALSE))
    {
        CcspTraceError(("%s - Failed to set [%s]\n", __FUNCTION__, VLAN_TERMINATION_PARAM_TPID, iVLANInstance));
        return ANSC_STATUS_FAILURE;
    }

    //Set BaseInterface.
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, VLAN_TERMINATION_PARAM_BASEIFACE, iVLANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", pEntry->Name);
    if (ANSC_STATUS_SUCCESS != DmlEthSetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_string, FALSE))
    {
        CcspTraceError(("%s - Failed to set [%s]\n", __FUNCTION__, VLAN_TERMINATION_PARAM_BASEIFACE, iVLANInstance));
        return ANSC_STATUS_FAILURE;
    }

    //Set Alias
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, VLAN_TERMINATION_PARAM_ALIAS, iVLANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", pEntry->Alias);
    if (ANSC_STATUS_SUCCESS != DmlEthSetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_string, FALSE))
    {
        CcspTraceError(("%s - Failed to set [%s]\n", __FUNCTION__, VLAN_TERMINATION_PARAM_ALIAS, iVLANInstance));
        return ANSC_STATUS_FAILURE;
    }

    //Set VLAN Inetrfacename.
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, VLAN_TERMINATION_PARAM_L3NAME, iVLANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", WAN_INTERFACE_NAME);
    if (ANSC_STATUS_SUCCESS != DmlEthSetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_string, FALSE))
    {
        CcspTraceError(("%s - Failed to set [%s]\n", __FUNCTION__, VLAN_TERMINATION_PARAM_L3NAME, iVLANInstance));
        return ANSC_STATUS_FAILURE;
    }

    //Set lowerlayers.
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, VLAN_TERMINATION_PARAM_LOWERLAYER, iVLANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", pEntry->Path);
    if (ANSC_STATUS_SUCCESS != DmlEthSetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_string, FALSE))
    {
        CcspTraceError(("%s - Failed to set [%s]\n", __FUNCTION__, VLAN_TERMINATION_PARAM_LOWERLAYER, iVLANInstance));
        return ANSC_STATUS_FAILURE;
    }
    //Set Enable.
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, VLAN_TERMINATION_PARAM_ENABLE, iVLANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", "true");
    if (ANSC_STATUS_SUCCESS != DmlEthSetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_boolean, TRUE))
    {
        CcspTraceError(("%s - Failed to set [%s]\n", __FUNCTION__, VLAN_TERMINATION_PARAM_ENABLE, iVLANInstance));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s - %s:Successfully created %s for vlan interface %s\n", __FUNCTION__, ETH_MARKER_VLAN_TABLE_CREATE, VLAN_TERMINATION_TABLE_NAME, pEntry->Name));

    //Set actual VLAN interface name for WAN interface
    DmlEthSetWanManagerWanIfaceName( pEntry->Alias, WAN_INTERFACE_NAME );

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
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, VLAN_TERMINATION_PARAM_ENABLE, iVLANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "false");
    if ( (ret = DmlEthSetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acSetParamName, acSetParamValue, ccsp_boolean, TRUE)) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceInfo(("[%s][%d] Failed to set [%s] , error [%d] \n", __FUNCTION__, __LINE__, VLAN_TERMINATION_PARAM_ENABLE, iVLANInstance, ret));
        goto EXIT;
    }

    sleep(1);

    //Delete Instance.
    sprintf(acTableName, "%s%d.", VLAN_TERMINATION_TABLE_NAME, iVLANInstance);
    int ccsp_ret = CcspBaseIf_DeleteTblRow(
        bus_handle,
        VLAN_COMPONENT_NAME,
        VLAN_DBUS_PATH,
        0, /* session id */
        acTableName);

    if (CCSP_SUCCESS != ccsp_ret)
    {
        CcspTraceError(("%s - Failed to delete table(%s), error (%d)\n", __FUNCTION__, acTableName, ret));
        ret = ANSC_STATUS_FAILURE;
        goto EXIT;
    }

EXIT:
    /* Notify WanStatus to down for Base Manager. */
    DmlEthSetWanStatusForBaseManager(iface_alias, "Down");
    return ret;
}

/* * DmlEthGetLowerLayersInstance() */
static ANSC_STATUS DmlEthGetLowerLayersInstance( char *pLowerLayers, INT *piInstanceNumber )
{
    char acTmpReturnValue[256] = {0},
         a2cTmpTableParams[16][256] = {0};
    INT iLoopCount,
        iTotalNoofEntries;

    if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, VLAN_TERMINATION_NOE_PARAM_NAME, acTmpReturnValue))
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

    //Get table names
    iTotalNoofEntries = 0;
    if (ANSC_STATUS_FAILURE == DmlEthGetParamNames(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, VLAN_TERMINATION_TABLE_NAME, a2cTmpTableParams, &iTotalNoofEntries))
    {
        CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    //Traverse from loop
    for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
    {
        char acTmpQueryParam[256] = {0};

        //Query
        snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sLowerLayers", a2cTmpTableParams[iLoopCount]);

        memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
        if (ANSC_STATUS_FAILURE == DmlEthGetParamValues(VLAN_COMPONENT_NAME, VLAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue))
        {
            CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
            continue;
        }

        //Compare lowerlayers
        if (0 == strcmp(acTmpReturnValue, pLowerLayers))
        {
            char tmpTableParam[256] = {0};
            const char *last_two;

            //Copy table param
            snprintf(tmpTableParam, sizeof(tmpTableParam), "%s", a2cTmpTableParams[iLoopCount]);

            //Get last two chareters from return value and cut the instance
            last_two = &tmpTableParam[strlen(tmpTableParam) - 2];

            *piInstanceNumber = atoi(last_two);
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
ANSC_STATUS DmlEthSetWanStatusForBaseManager(char *ifname, char *WanStatus)
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

/* Set VLAN name to Device.X_RDK_WanManager.CPEInterface.{i}.Wan.Name */
static ANSC_STATUS DmlEthSetWanManagerWanIfaceName(char *ifname, char *vlanifname)
{
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = {0};
    INT iWANInstance = -1;

    //Validate buffer
    if ((NULL == ifname) || (NULL == vlanifname))
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

    //Set WAN actual interface name like ptm0.101
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, WAN_IF_VLAN_NAME_PARAM, iWANInstance);
    DmlEthSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName, vlanifname, ccsp_string, TRUE);

    CcspTraceInfo(("%s - %s:Successfully assigned %s vlan ifname to WAN Agent for %s interface\n", __FUNCTION__, ETH_MARKER_NOTIFY_WAN_BASE,vlanifname, ifname));

    return ANSC_STATUS_SUCCESS;
}

/* Set LinkStatus to Device.X_RDK-Central_COM_WanAgent.Interface.{i}.Wan.LinkStatus */
static ANSC_STATUS DmlEthSetWanLinkStatusForWanAgent(char *ifname, char *status)
{
    char acSetParamName[256] = {0};
    INT iWANInstance = -1;

    //Validate buffer
    if ((NULL == ifname) || (NULL == status))
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

    //Set WAN LinkStatus field
    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, WAN_IF_LINK_STATUS, iWANInstance);
    DmlEthSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName, status, ccsp_string, TRUE);

    CcspTraceInfo(("%s - %s:Successfully assigned %s link status to WAN Agent for %s interface\n", __FUNCTION__, ETH_MARKER_NOTIFY_WAN_BASE, status, ifname));
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
    INT                      *piWANInstance = (INT*)arg,
                             iWANInstance   = -1,
                             iLoopCount,
                             iTotalNoofEntries = 0,
                             iIterator = 0;

    //Validate buffer
    if ( NULL == pstRefreshCfg )
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        pthread_exit(NULL);
    }

    //detach thread from caller stack
    pthread_detach(pthread_self());

    iWANInstance = pstRefreshCfg->iWANInstance;

    //Get Marking entries
    memset(acGetParamName, 0, sizeof(acGetParamName));
    snprintf(acGetParamName, sizeof(acGetParamName), WAN_MARKING_NOE_PARAM_NAME, iWANInstance);
    if ( ANSC_STATUS_FAILURE == DmlEthGetParamValues( WAN_COMPONENT_NAME, WAN_DBUS_PATH, acGetParamName, acTmpReturnValue ) )
    {
        CcspTraceError(("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__));
        goto EXIT;
    }

    //Total count
    iTotalNoofEntries = atoi(acTmpReturnValue);

    CcspTraceInfo(("%s Wan Instance(%d) Marking Entries:%d\n", __FUNCTION__, iWANInstance, iTotalNoofEntries));

    //Allocate resource for marking
    pstRefreshCfg->stVlanCfg.skbMarkingNumOfEntries = iTotalNoofEntries;

    //Allocate memory when non-zero entries
    if( pstRefreshCfg->stVlanCfg.skbMarkingNumOfEntries > 0 )
    {
       pstRefreshCfg->stVlanCfg.skb_config = (vlan_skb_config_t*)malloc( iTotalNoofEntries * sizeof(vlan_skb_config_t) );

       if( NULL == pstRefreshCfg->stVlanCfg.skb_config )
       {
          goto EXIT;
       }

       //Fetch all the marking names
       iTotalNoofEntries = 0;

       memset(acGetParamName, 0, sizeof(acGetParamName));
       snprintf(acGetParamName, sizeof(acGetParamName), WAN_MARKING_TABLE_NAME, iWANInstance);

       if ( ANSC_STATUS_FAILURE == DmlEthGetParamNames(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acGetParamName, a2cTmpTableParams, &iTotalNoofEntries))
       {
           CcspTraceError(("[%s][%d] Failed to get param value\n", __FUNCTION__, __LINE__));
           goto EXIT;
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
           snprintf(pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].alias, sizeof(pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].alias), "%s", acTmpReturnValue);

           //SKBPort
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sSKBPort", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].skbPort = atoi(acTmpReturnValue);

           //SKBMark
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sSKBMark", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].skbMark = atoi(acTmpReturnValue);

           //EthernetPriorityMark
           memset(acTmpQueryParam, 0, sizeof(acTmpQueryParam));
           snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), "%sEthernetPriorityMark", a2cTmpTableParams[iLoopCount]);
           memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
           DmlEthGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue);
           pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].skbEthPriorityMark = atoi(acTmpReturnValue);

           CcspTraceInfo(("WAN Marking - Ins[%d] Alias[%s] SKBPort[%u] SKBMark[%u] EthernetPriorityMark[%d]\n",
                                                                iLoopCount + 1,
                                                                pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].alias,
                                                                pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].skbPort,
                                                                pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].skbMark,
                                                                pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].skbEthPriorityMark ));
        }
    }
#ifdef _HUB4_PRODUCT_REQ_
    //Create and initialise Marking data models
    DmlEthCreateMarkingTable(pstRefreshCfg);

    //Coming for actual refresh
    if( VLAN_REFRESH_CALLED_FROM_DML == pstRefreshCfg->enRefreshCaller )
    {
        //Configure SKB Marking entries
        vlan_eth_hal_setMarkings( &(pstRefreshCfg->stVlanCfg) );
    }
    else
    {
        //Create vlan interface
        vlan_eth_hal_createInterface( &(pstRefreshCfg->stVlanCfg) );
    }
#else
    //Create vlan interface
    vlan_eth_hal_createInterface( &(pstRefreshCfg->stVlanCfg) );
#endif

    //Needs to set eth_wan_mac for ETHWAN case
    DmlUpdateEthWanMAC( );

    /* This sleep is inevitable as we noticed hung issue with DHCP clients
    when we start the clients quickly after we assign the MAC address on the interface
    where it going to run. Even though we check the interface status using ioctl 
    SIOCGIFFLAGS call, the hung issue still reproducible. Not observed this issue with a
    two seconds delay after MAC assignment. */
    sleep(2);

    //Get status of VLAN link
    if ( VLAN_REFRESH_CALLED_FROM_VLANCREATION == pstRefreshCfg->enRefreshCaller )
    {
        while(iIterator < 10)
        {
            if (ANSC_STATUS_FAILURE == getInterfaceStatus(pstRefreshCfg->stVlanCfg.L3Interface, &status))
            {
                CcspTraceError(("[%s][%d] getInterfaceStatus failed for %s !! \n", __FUNCTION__, __LINE__, pstRefreshCfg->stVlanCfg.L3Interface));
                return ANSC_STATUS_FAILURE;
            }
            if (status == VLAN_IF_UP)
            {
                //Needs to inform base interface is UP after vlan refresh
                DmlEthSetWanStatusForBaseManager(pstRefreshCfg->WANIfName, "Up");
                break;
            }

            iIterator++;
            sleep(2);
        }
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
static ANSC_STATUS DmlEthCreateMarkingTable(PVLAN_REFRESH_CFG pstRefreshCfg)
{
    if (NULL == pstRefreshCfg)
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

    p_EthLink->NumberofMarkingEntries = pstRefreshCfg->stVlanCfg.skbMarkingNumOfEntries;
    p_EthLink->pstDataModelMarking = (PCOSA_DML_MARKING) malloc(sizeof(COSA_DML_MARKING)*(p_EthLink->NumberofMarkingEntries));
    if(p_EthLink->pstDataModelMarking == NULL)
    {
        CcspTraceError(("%s Failed to allocate Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    memset(p_EthLink->pstDataModelMarking, 0, (sizeof(COSA_DML_MARKING)*(p_EthLink->NumberofMarkingEntries)));
    for(iLoopCount = 0; iLoopCount < p_EthLink->NumberofMarkingEntries; iLoopCount++)
    {
       (p_EthLink->pstDataModelMarking + iLoopCount)->SKBPort = pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].skbPort;
       (p_EthLink->pstDataModelMarking + iLoopCount)->EthernetPriorityMark = pstRefreshCfg->stVlanCfg.skb_config[iLoopCount].skbEthPriorityMark;
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
            ( (strncmp(region, "GB", strlen("GB")) == 0) && (strstr(pEntry->Alias, DSL_IFC_STR) != NULL)))
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
static ANSC_STATUS DmlDeleteUnTaggedVlanLink(const CHAR *ifName, const PDML_ETHERNET pEntry)
{
    if (pEntry == NULL || ifName == NULL)
    {
        CcspTraceError(("[%s-%d] Invalid parameter error! \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_BAD_PARAMETER;
    }

    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    vlan_interface_status_e status;

    returnStatus = getInterfaceStatus (ifName, &status);
    if (returnStatus != ANSC_STATUS_SUCCESS )
    {
        CcspTraceError(("[%s-%d] - %s: Failed to get VLAN interface status\n", __FUNCTION__, __LINE__, ifName));
        return returnStatus;
    }

    if ( ( status != VLAN_IF_NOTPRESENT ) && ( status != VLAN_IF_ERROR ) )
    {
        returnStatus = vlan_eth_hal_deleteInterface(ifName);
        if (ANSC_STATUS_SUCCESS != returnStatus)
        {
            CcspTraceError(("[%s-%d] Failed to delete VLAN interface(%s)\n", __FUNCTION__, __LINE__, ifName));
        }
        else
        {
            CcspTraceInfo(("[%s-%d]  %s:Successfully deleted this %s VLAN interface \n", __FUNCTION__, __LINE__, ETH_MARKER_VLAN_IF_DELETE, ifName));
            /**
             * @note Notify WanStatus to Base Agent.
             */
             DmlEthSetWanStatusForBaseManager(pEntry->Alias, "Down");
        }
    }
    return returnStatus;
}

/**
 * @note Create untagged VLAN interface.
 */
static ANSC_STATUS DmlCreateUnTaggedVlanLink(const CHAR *ifName, const PDML_ETHERNET pEntry)
{
    if (pEntry == NULL || ifName == NULL)
    {
        CcspTraceError(("[%s-%d] Invalid parameter error! \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_BAD_PARAMETER;
    }

    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    /**
     * @note Delete vlan interface if it exists first.
     */
    DmlDeleteUnTaggedVlanLink(ifName, pEntry);

    /**
     * Create untagged vlan interface.
     */
    vlan_configuration_t vlan_conf = {0};
    strncpy(vlan_conf.L3Interface, ifName, sizeof(vlan_conf.L3Interface));
    strncpy(vlan_conf.L2Interface, pEntry->Name, sizeof(vlan_conf.L2Interface));
    vlan_conf.VLANId = DEFAULT_VLAN_ID; /* Untagged interface */
    vlan_conf.TPId = 0;
    /**
     * @note Read All Marking and Create Untagged VLAN interface
     * VLAN_REFRESH_CALLED_FROM_VLANCREATION = 1
     * VLAN_REFRESH_CALLED_FROM_DML          = 2
     */
    returnStatus = DmlEthSetVlanRefresh(pEntry->Alias, VLAN_REFRESH_CALLED_FROM_VLANCREATION, &vlan_conf);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceError(("[%s-%d] Failed to create VLAN interface \n", __FUNCTION__, __LINE__));
        return returnStatus;
    }

    CcspTraceInfo(("[%s-%d] Successfully created for vlan interface [%s] on top of [%s] \n", __FUNCTION__, __LINE__, ifName, pEntry->Alias));

    /**
     * @note Needs to set eth_wan_mac for ETHWAN case
     */
    DmlUpdateEthWanMAC();

    /**
     * @note Set actual VLAN interface name for WAN interface
     */
    DmlEthSetWanManagerWanIfaceName(pEntry->Alias, ifName);

    /**
     * @note Set LinkStatus for WAN interface
     */
    DmlEthSetWanLinkStatusForWanAgent(pEntry->Alias, "Up");

    return ANSC_STATUS_SUCCESS;
}
