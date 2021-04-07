/*
 * Copyright (C) 2020 Sky
 * --------------------------------------------------------------------------
 * THIS SOFTWARE CONTRIBUTION IS PROVIDED ON BEHALF OF SKY PLC.
 * BY THE CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED
 * ******************************************************************
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
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
#include "vlan_mgr_apis.h"
#include "vlan_apis.h"
#include "vlan_internal.h"
#include "plugin_main_apis.h"
#include "vlan_eth_hal.h"

#ifdef FEATURE_MAPT
#include "sysevent/sysevent.h"

#define IS_EMPTY_STRING(s)    ((s == NULL) || (*s == '\0'))
#define SYSEVENT_WAN_IFACE_NAME "wan_ifname"
#define BUFLEN_64 64
extern int sysevent_fd;
extern token_t sysevent_token;
#endif


extern void* g_pDslhDmlAgent;
extern ANSC_HANDLE                        g_MessageBusHandle;
extern COSAGetSubsystemPrefixProc         g_GetSubsystemPrefix;
extern char                 g_Subsystem[32];
extern  ANSC_HANDLE                        bus_handle;

extern ANSC_STATUS DmlEthSetWanStatusForBaseManager(char *ifname, char *WanStatus);

ANSC_STATUS
SListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCONTEXT_LINK_OBJECT        pContext
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PCONTEXT_LINK_OBJECT            pContextEntry     = (PCONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pContextEntry = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pContext->InstanceNumber < pContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}

PCONTEXT_LINK_OBJECT
SListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PCONTEXT_LINK_OBJECT            pContextEntry     = (PCONTEXT_LINK_OBJECT)NULL;
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
            pContextEntry = ACCESS_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry   = AnscSListGetNextEntry(pSLinkEntry);

            if ( pContextEntry->InstanceNumber == InstanceNumber )
            {
                return pContextEntry;
            }
        }
    }

    return NULL;
}

/**********************************************************************

    caller:     self

    prototype:

        BOOL
        DmlVlanInit
            (
                ANSC_HANDLE                 hDml,
                PANSC_HANDLE                phContext,
                PFN_COSA_DML_VLAN_GEN        pValueGenFn
            );

        Description:
            This is the initialization routine for VLAN backend.

        Arguments:
            hDml               Opaque handle from DM adapter. Backend saves this handle for calling pValueGenFn.
             phContext       Opaque handle passed back from backend, needed by CosaDmlVLANXyz() routines.
            pValueGenFn    Function pointer to instance number/alias generation callback.

        Return:
            Status of operation.

**********************************************************************/
ANSC_STATUS
DmlVlanInit
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext,
        PFN_DML_VLAN_GEN            pValueGenFn
    )
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    returnStatus != vlan_eth_hal_init();
    if (returnStatus != ANSC_STATUS_SUCCESS) {
        printf("vlan_eth_hal_init failed \n");
    }

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        PDML_VLAN
        DmlGetVlan
            (
                ANSC_HANDLE                 hContext,
                PULONG                      instanceNum
            )
        Description:
            This routine is to retrieve the VLAN instances.

        Arguments:
            InstanceNum.

        Return:
            The pointer to VLAN table, allocated by calloc. If no entry is found, NULL is returned.

**********************************************************************/

ANSC_STATUS
DmlGetVlan
    (
        ANSC_HANDLE                 hContext,
        ULONG                       InstanceNum,
        PDML_VLAN                   p_Vlan
    )
{
    BOOL                            bSetBack     = FALSE;
    ULONG                           ulIndex      = 0;
    int                             rc           = 0;
    int                             count = 0;
    if ( p_Vlan == NULL )
    {
        CcspTraceWarning(("DmlGetVlan pTrigger is NULL!\n"));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlGetVlanIfStatus
            (
                ANSC_HANDLE         hThisObject,
                PCOSA_DML_VLAN      pEntry
            );

    Description:
        The API updated current state of a VLAN interface
    Arguments:
        pAlias      The entry is identified through Alias.
        pEntry      The new configuration is passed through this argument, even Alias field can be changed.

    Return:
        Status of the operation

**********************************************************************/
ANSC_STATUS
DmlGetVlanIfStatus
    (
        ANSC_HANDLE         hContext,
        PDML_VLAN           pEntry          /* Identified by InstanceNumber */
    )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_FAILURE;
    vlan_interface_status_e status;

    if ( pEntry != NULL )
    {
        if (ANSC_STATUS_SUCCESS != getInterfaceStatus(pEntry->Name, &status))
        {
            pEntry->Status = VLAN_IF_STATUS_ERROR;
            CcspTraceError(("[%s][%d] %s: getInterfaceStatus failed \n", __FUNCTION__, __LINE__, pEntry->Name));
        }
        else
        {
            pEntry->Status = status;
            returnStatus   = ANSC_STATUS_SUCCESS;
        }
    }
    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlCreateVlanInterface
            (
                ANSC_HANDLE         hThisObject,
                PCOSA_DML_VLAN      pEntry
            );

    Description:
        The API create the designated VLAN interface
    Arguments:
        pAlias      The entry is identified through Alias.
        pEntry      The new configuration is passed through this argument, even Alias field can be changed.

    Return:
        Status of the operation

**********************************************************************/

ANSC_STATUS
DmlCreateVlanInterface
    (
        ANSC_HANDLE         hContext,
        PDML_VLAN           pEntry          /* Identified by InstanceNumber */
    )
{
    ANSC_STATUS  returnStatus  =  ANSC_STATUS_FAILURE;
    if(pEntry->Enable) {
        returnStatus = DmlSetVlan(hContext, pEntry);
    }
    return returnStatus;
}

#ifdef FEATURE_MAPT
/**********************************************************************

    caller:     self

    prototype:

        static int
        get_wan_interface_name(char *wan_if)

    Description:
        The API gets the wan interface name.

**********************************************************************/
static int get_wan_interface_name(char *wan_if)
{
    int ret = 0;
    char wan_ifname[BUFLEN_64] = {0};

    if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_WAN_IFACE_NAME,  wan_ifname, sizeof(wan_ifname)) == 0)
    {
        strcpy(wan_if, wan_ifname);
        ret = 1;
    }

    return ret;

}

/**********************************************************************

    caller:     self

    prototype:

        void
        mapt_ivi_check()

    Description:
        The API check the ivi.ko loaded or not. If present unload it before delete the vlan interface.

**********************************************************************/
void mapt_ivi_check() {
    FILE *file;
    char line[64];

    file = popen("cat /proc/modules | grep ivi","r");

    if( file == NULL) {
        CcspTraceError(("[%s][%d]Failed to open  /proc/modules \n", __FUNCTION__, __LINE__));
    }
    else {
        if( fgets (line, 64, file)!=NULL ) {
            if( strstr(line, "ivi")) {
                system("ivictl -q");
                system("rmmod -f /lib/modules/`uname -r`/extra/ivi.ko");
                sleep(1);
                CcspTraceInfo(("%s - ivi.ko removed\n", __FUNCTION__));
            }
        }
        pclose(file);
    }
}
#endif
/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlDeleteVlanInterface
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
DmlDeleteVlanInterface
    (
        ANSC_HANDLE         hContext,
        PDML_VLAN           pEntry          /* Identified by InstanceNumber */
    )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    int ret;
    vlan_interface_status_e status;

    if (!pEntry->Enable)
    {
#ifdef FEATURE_MAPT
        char wan_ifname[BUFLEN_64] = {0};

        if(get_wan_interface_name(wan_ifname) ) {
            CcspTraceInfo(("[%s][%d]wan_ifname %s \n", __FUNCTION__, __LINE__, wan_ifname));
            if(! strcmp(pEntry->Name, wan_ifname)) {
               mapt_ivi_check();
            }
        }
#endif
        /**
         * 1. Check any vlan interface exists for this configuration in the CPE.
         *    if so , delete it.
         */
        ret = getInterfaceStatus (pEntry->Name, &status);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("[%s][%d] %s: Failed to get vlan interface status \n", __FUNCTION__, __LINE__, pEntry->Name));
            return ANSC_STATUS_FAILURE;
        }

        if ( ( status != VLAN_IF_NOTPRESENT ) && ( status != VLAN_IF_ERROR ) )
        {
            returnStatus = vlan_eth_hal_deleteInterface(pEntry->Name, pEntry->InstanceNumber);
            if ( ANSC_STATUS_SUCCESS != returnStatus )
            {
                CcspTraceError(("%s - Failed to delete VLAN interface %s\n", __FUNCTION__, pEntry->Name));
                return returnStatus;
            }
            CcspTraceInfo(("%s - %s:Successfully deleted VLAN interface %s\n", __FUNCTION__, VLAN_MARKER_VLAN_IF_CREATE, pEntry->Name));
        }
        else
        {
            CcspTraceInfo(("%s - No VLAN interface found with this name %s\n", __FUNCTION__, pEntry->Name));
        }
    }

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlSetVlan
            (
                ANSC_HANDLE         hThisObject,
                PDML_VLAN      pEntry
            );

    Description:
        The API re-configures the designated VLAN table entry.
    Arguments:
        pAlias      The entry is identified through Alias.
        pEntry      The new configuration is passed through this argument, even Alias field can be changed.

    Return:
        Status of the operation

**********************************************************************/

ANSC_STATUS
DmlSetVlan
    (
        ANSC_HANDLE         hContext,
        PDML_VLAN           pEntry          /* Identified by InstanceNumber */
    )
{
    ANSC_STATUS             returnStatus  = ANSC_STATUS_SUCCESS;
    vlan_configuration_t    vlan_conf;
    strncpy(vlan_conf.BaseInterface, pEntry->BaseInterface, sizeof(vlan_conf.BaseInterface));
    strncpy(vlan_conf.L3Interface, pEntry->Name, sizeof(vlan_conf.L3Interface));
    strncpy(vlan_conf.L2Interface, pEntry->Alias, sizeof(vlan_conf.L2Interface));
    vlan_conf.VLANId = pEntry->VLANId;
    vlan_conf.TPId   = pEntry->TPId;
    vlan_conf.IfaceInstanceNumber = pEntry->InstanceNumber;
    vlan_interface_status_e status;
    INT iIterator = 0;

    if (pEntry != NULL) {
        if(pEntry->Enable) {
            /**
             * 1. Check vlan interface already exists.
             *      a) If exists delete it and then create new one.
             *      b) else directly create interface.
             */
            if (getInterfaceStatus(pEntry->Name, &status) != ANSC_STATUS_SUCCESS)
            {
                CcspTraceError(("[%s][%d]Failed to get vlan interface status \n", __FUNCTION__, __LINE__));
                return ANSC_STATUS_FAILURE;
            }

            if ( ( status != VLAN_IF_NOTPRESENT ) && ( status != VLAN_IF_ERROR ) )
            {
                CcspTraceInfo(("%s %s:VLAN interface(%s) already exists, delete it first\n", __FUNCTION__, VLAN_MARKER_VLAN_IF_CREATE, vlan_conf.L3Interface));
                returnStatus = vlan_eth_hal_deleteInterface(pEntry->Name, pEntry->InstanceNumber);
                if (ANSC_STATUS_SUCCESS != returnStatus)
                {
                    CcspTraceError(("%s - Failed to delete the existing VLAN interface %s\n", __FUNCTION__, vlan_conf.L3Interface));
                    return returnStatus;
                }

                CcspTraceInfo(("%s - %s:Successfully deleted VLAN interface %s\n", __FUNCTION__, VLAN_MARKER_VLAN_IF_DELETE, vlan_conf.L3Interface));
            }

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
        }
    }

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        PCOSA_DML_VLAN
        DmlGetVlans
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
            The pointer to the array of VLAN table, allocated by calloc. If no entry is found, NULL is returned.

**********************************************************************/

PDML_VLAN
DmlGetVlans
    (
        ANSC_HANDLE                 hContext,
        PULONG                      pulCount,
        BOOLEAN                     bCommit
    )
{
    if ( !pulCount )
    {
        CcspTraceWarning(("CosaDmlGetVlans pulCount is NULL!\n"));
        return NULL;
    }

    *pulCount = 0;

    return NULL;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        DmlAddVlan
            (
                ANSC_HANDLE                 hContext,
                PDML_VLAN      pEntry
            )

    Description:
        The API adds one vlan entry into VLAN table.

    Arguments:
        pEntry      Caller does not need to fill in Status or Alias fields. Upon return, callee fills in the generated Alias and associated Status.

    Return:
        Status of the operation.

**********************************************************************/

ANSC_STATUS
DmlAddVlan
    (
        ANSC_HANDLE                 hContext,
        PDML_VLAN                   pEntry
    )
{
    if (!pEntry)
    {
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}
