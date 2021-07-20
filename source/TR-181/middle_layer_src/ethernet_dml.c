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

#include "ansc_platform.h"
#include "ethernet_dml.h"
#include "ethernet_apis.h"
#include "plugin_main_apis.h"
#include "ethernet_internal.h"

/***********************************************************************
 IMPORTANT NOTE:

 According to TR69 spec:
 On successful receipt of a SetParameterValues RPC, the CPE MUST apply
 the changes to all of the specified Parameters atomically. That is, either
 all of the value changes are applied together, or none of the changes are
 applied at all. In the latter case, the CPE MUST return a fault response
 indicating the reason for the failure to apply the changes.

 The CPE MUST NOT apply any of the specified changes without applying all
 of them.

 In order to set parameter values correctly, the back-end is required to
 hold the updated values until "Validate" and "Commit" are called. Only after
 all the "Validate" passed in different objects, the "Commit" will be called.
 Otherwise, "Rollback" will be called instead.

 The sequence in COSA Data Model will be:

 SetParamBoolValue/SetParamIntValue/SetParamUlongValue/SetParamStringValue
 -- Backup the updated values;

 if( Validate_XXX())
 {
     Commit_XXX();    -- Commit the update all together in the same object
 }
 else
 {
     Rollback_XXX();  -- Remove the update at backup;
 }

***********************************************************************/
/***********************************************************************

 APIs for Object:

    Ethernet.Link.{i}.

    *  EthLink_GetEntryCount
    *  EthLink_GetEntry
    *  EthLink_AddEntry
    *  EthLink_DelEntry
    *  EthLink_GetParamBoolValue
    *  EthLink_GetParamUlongValue
    *  EthLink_GetParamStringValue
    *  EthLink_SetParamBoolValue
    *  EthLink_SetParamUlongValue
    *  EthLink_SetParamStringValue
    *  EthLink_Validate
    *  EthLink_Commit
    *  EthLink_Rollback

***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        EthLink_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/

ULONG
EthLink_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PDATAMODEL_ETHERNET             pEthLink         = (PDATAMODEL_ETHERNET)g_pBEManager->hEth;

    return AnscSListQueryDepth( &pEthLink->Q_EthList );

}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        EthLink_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/

ANSC_HANDLE
EthLink_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    PDATAMODEL_ETHERNET             pMyObject         = (PDATAMODEL_ETHERNET)g_pBEManager->hEth;
    PSINGLE_LINK_ENTRY              pSListEntry       = NULL;
    PCONTEXT_LINK_OBJECT            pCxtLink          = NULL;

    pSListEntry       = AnscSListGetEntryByIndex(&pMyObject->Q_EthList, nIndex);

    if ( pSListEntry )
    {
        pCxtLink      = ACCESS_CONTEXT_LINK_OBJECT(pSListEntry);
        *pInsNumber   = pCxtLink->InstanceNumber;
    }

    return (ANSC_HANDLE)pSListEntry;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        EthLink_AddEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to add a new entry.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle of new added entry.

**********************************************************************/

ANSC_HANDLE
EthLink_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    )
{
    ANSC_STATUS                          returnStatus   = ANSC_STATUS_SUCCESS;
    PDATAMODEL_ETHERNET                  pEthLink       = (PDATAMODEL_ETHERNET)g_pBEManager->hEth;
    PDML_ETHERNET                        p_EthLink      = NULL;
    PCONTEXT_LINK_OBJECT                 pEthCxtLink    = NULL;
    PSINGLE_LINK_ENTRY                   pSListEntry       = NULL;
    BOOL                                 bridgeMode;

    p_EthLink = (PDML_ETHERNET)AnscAllocateMemory(sizeof(DML_ETHERNET));

    if ( !p_EthLink )
    {
        return NULL;
    }

    pEthCxtLink = (PCONTEXT_LINK_OBJECT)AnscAllocateMemory(sizeof(CONTEXT_LINK_OBJECT));
    if ( !pEthCxtLink )
    {
        goto EXIT;
    }

    /* now we have this link content */
    pEthCxtLink->hContext = (ANSC_HANDLE)p_EthLink;
    pEthCxtLink->bNew     = TRUE;

    /* Get InstanceNumber and Alias */
    EthGenForTriggerEntry(NULL, p_EthLink);

    pEthCxtLink->InstanceNumber = p_EthLink->InstanceNumber ;
    *pInsNumber                 = p_EthLink->InstanceNumber ;

    SEthListPushEntryByInsNum(&pEthLink->Q_EthList, (PCONTEXT_LINK_OBJECT)pEthCxtLink);

    return (ANSC_HANDLE)pEthCxtLink;

EXIT:
    AnscFreeMemory(p_EthLink);

    return NULL;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        EthLink_DelEntry
            (
                ANSC_HANDLE                 hInsContext,
                ANSC_HANDLE                 hInstance
            );

    description:

        This function is called to delete an exist entry.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ANSC_HANDLE                 hInstance
                The exist entry handle;

    return:     The status of the operation.

**********************************************************************/

ULONG
EthLink_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    )
{
    ANSC_STATUS               returnStatus      = ANSC_STATUS_SUCCESS;
    PDATAMODEL_ETHERNET       pEthLink          = (PDATAMODEL_ETHERNET)g_pBEManager->hEth;
    PCONTEXT_LINK_OBJECT      pEthCxtLink       = (PCONTEXT_LINK_OBJECT)hInstance;
    PDML_ETHERNET             p_EthLink         = (PDML_ETHERNET)pEthCxtLink->hContext;


    if ( pEthCxtLink->bNew )
    {
        /* Set bNew to FALSE to indicate this node is not going to save to SysRegistry */
        pEthCxtLink->bNew = FALSE;
    }

    if ( AnscSListPopEntryByLink(&pEthLink->Q_EthList, &pEthCxtLink->Linkage) )
    {
        AnscFreeMemory(pEthCxtLink->hContext);
        AnscFreeMemory(pEthCxtLink);
    }

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        EthLink_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
EthLink_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    PCONTEXT_LINK_OBJECT       pCxtLink   = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET              p_EthLink  = (PDML_ETHERNET   )pCxtLink->hContext;

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = p_EthLink->Enable;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "PriorityTagging", TRUE))
    {
        *pBool = p_EthLink->PriorityTagging;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_Refresh", TRUE))
    {
        *pBool = FALSE;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        EthLink_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
EthLink_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PCONTEXT_LINK_OBJECT    pCxtLink      = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET           p_EthLink     = (PDML_ETHERNET   )pCxtLink->hContext;

    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        if(ANSC_STATUS_SUCCESS == DmlGetEthCfgIfStatus(NULL, p_EthLink)) {
            *puLong = p_EthLink->Status;
        }
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        EthLink_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/

ULONG
EthLink_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PCONTEXT_LINK_OBJECT       pCxtLink      = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET              p_EthLink     = (PDML_ETHERNET   )pCxtLink->hContext;
    PUCHAR                     pString       = NULL;

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        if ( AnscSizeOfString(p_EthLink->Alias) < *pUlSize)
        {
            AnscCopyString(pValue, p_EthLink->Alias);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(p_EthLink->Alias)+1;
            return 1;
        }
    }
    if( AnscEqualString(ParamName, "Name", TRUE))
    {
        if ( AnscSizeOfString(p_EthLink->Name) < *pUlSize)
        {
            AnscCopyString(pValue, p_EthLink->Name);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(p_EthLink->Name)+1;
            return 1;
        }
    }
    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        if ( AnscSizeOfString(p_EthLink->LowerLayers) < *pUlSize)
        {   
            AnscCopyString(pValue, p_EthLink->LowerLayers);
            return 0;
        }
        else
        {   
            *pUlSize = AnscSizeOfString(p_EthLink->LowerLayers)+1;
            return 1;
        }

        return 0;
    }
    if( AnscEqualString(ParamName, "MACAddress", TRUE))
    {
        //Get MAC from corresponding interface
        DmlGetHwAddressUsingIoctl( p_EthLink->Name, p_EthLink->MACAddress, sizeof(p_EthLink->MACAddress) );

        if ( AnscSizeOfString(p_EthLink->MACAddress) < *pUlSize)
        {
            AnscCopyString(pValue, p_EthLink->MACAddress);
            return 0;
        }
        else
        {
            *pUlSize = AnscSizeOfString(p_EthLink->MACAddress)+1;
            return 1;
        }

        AnscCopyString(pValue, p_EthLink->MACAddress);
        return 0;
    }
    if( AnscEqualString(ParamName, "X_RDK_BaseInterface", TRUE))
    {
        if ( AnscSizeOfString(p_EthLink->BaseInterface) < *pUlSize)
        {   
            AnscCopyString(pValue, p_EthLink->BaseInterface);
            return 0;
        }
        else
        {   
            *pUlSize = AnscSizeOfString(p_EthLink->BaseInterface)+1;
            return 1;
        }

        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        EthLink_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
EthLink_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    PCONTEXT_LINK_OBJECT       pCxtLink  = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET             p_EthLink  = (PDML_ETHERNET) pCxtLink->hContext;

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        //Check whether enable param changed or not
        if( bValue == p_EthLink->Enable )
        {
            return TRUE;
        }

        /* save update to backup */
        p_EthLink->Enable  = bValue;

        if(!p_EthLink->Enable)
        {
            DmlDeleteEthInterface(NULL, p_EthLink);
        }
        else
        {
            DmlCreateEthInterface(NULL, p_EthLink);
        }

        return TRUE;
    }

    if( AnscEqualString(ParamName, "PriorityTagging", TRUE))
    {
        p_EthLink->PriorityTagging = bValue;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_Refresh", TRUE))
    {
#ifdef _HUB4_PRODUCT_REQ_
        //Handle Ethernet Link Refresh
        if( TRUE == bValue )
        { 
            vlan_configuration_t stVlanCfg = { 0 };

            stVlanCfg.IfaceInstanceNumber = p_EthLink->InstanceNumber;
            snprintf( stVlanCfg.BaseInterface, sizeof(stVlanCfg.BaseInterface), "%s", p_EthLink->BaseInterface );
            snprintf( stVlanCfg.L3Interface, sizeof(stVlanCfg.L3Interface), "%s", p_EthLink->Name );
            snprintf( stVlanCfg.L2Interface, sizeof(stVlanCfg.L2Interface), "%s", p_EthLink->Alias );
            int iVlanId = DEFAULT_VLAN_ID;
            if (ANSC_STATUS_SUCCESS != GetVlanId(&iVlanId, p_EthLink))
            {
                CcspTraceError(("[%s-%d] Failed to get the vlan id \n", __FUNCTION__, __LINE__));
                return FALSE;
            }
            stVlanCfg.VLANId = iVlanId;
            stVlanCfg.TPId   = 0;

            DmlEthSetVlanRefresh( p_EthLink->BaseInterface, VLAN_REFRESH_CALLED_FROM_DML, &stVlanCfg );
        }
#endif //_HUB4_PRODUCT_REQ_
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        EthLink_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
EthLink_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    PCONTEXT_LINK_OBJECT       pCxtLink  = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET             p_EthLink  = (PDML_ETHERNET   )pCxtLink->hContext;

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        EthLink_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
EthLink_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PDATAMODEL_ETHERNET        pEthLink       = (PDATAMODEL_ETHERNET      )g_pBEManager->hEth;
    PCONTEXT_LINK_OBJECT       pCxtLink       = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET              p_EthLink      = (PDML_ETHERNET   )pCxtLink->hContext;


    /* check the parameter name and set the corresponding value */
   
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        AnscCopyString(p_EthLink->Alias, pString);
        return TRUE;
    }
    if( AnscEqualString(ParamName, "Name", TRUE))
    {
        AnscCopyString(p_EthLink->Name, pString);
        return TRUE;
    }
    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        AnscCopyString(p_EthLink->LowerLayers, pString);
        return TRUE;
    }
    if( AnscEqualString(ParamName, "MACAddress", TRUE))
    {
        AnscCopyString(p_EthLink->MACAddress, pString);
        return TRUE;
    }
    if( AnscEqualString(ParamName, "X_RDK_BaseInterface", TRUE))
    {
        AnscCopyString(p_EthLink->BaseInterface, pString);
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        EthLink_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/

BOOL
EthLink_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        EthLink_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/

ULONG
EthLink_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ANSC_STATUS                     returnStatus  = ANSC_STATUS_SUCCESS;
    PCONTEXT_LINK_OBJECT            pCxtLink      = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET                   p_EthLink     = (PDML_ETHERNET   )pCxtLink->hContext;
    PDATAMODEL_ETHERNET             pEthLink      = (PDATAMODEL_ETHERNET      )g_pBEManager->hEth;

    if ( pCxtLink->bNew )
    {
        returnStatus = DmlAddEth(NULL, p_EthLink );

        if ( returnStatus == ANSC_STATUS_SUCCESS )
        {
            pCxtLink->bNew = FALSE;
        }
        else
        {
            DML_ETHERNET_INIT(p_EthLink);
        }
    }
    
    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        EthLink_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/

ULONG
EthLink_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ANSC_STATUS  returnStatus  = ANSC_STATUS_SUCCESS;

    return returnStatus;
}

/***********************************************************************

 APIs for Object:

    Device.Ethernet.Link.{i}.X_RDK_Marking.{i}.

    *  Marking_GetEntryCount
    *  Marking_GetEntry
    *  Marking_IsUpdated
    *  Marking_Synchronize
    *  Marking_GetParamBoolValue
    *  Marking_GetParamIntValue
    *  Marking_GetParamUlongValue
    *  Marking_GetParamStringValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        Marking_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/

ULONG
Marking_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCONTEXT_LINK_OBJECT            pCxtLink      = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET                   p_EthLink     = (PDML_ETHERNET   )pCxtLink->hContext;

    if(p_EthLink == NULL) {
        return 0;
    }

    return p_EthLink->NumberofMarkingEntries;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        Marking_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/

ANSC_HANDLE
Marking_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    PCONTEXT_LINK_OBJECT            pCxtLink      = (PCONTEXT_LINK_OBJECT)hInsContext;
    PDML_ETHERNET                   p_EthLink     = (PDML_ETHERNET   )pCxtLink->hContext;

    if ( nIndex < p_EthLink->NumberofMarkingEntries)
    {
        *pInsNumber = (nIndex + 1);
        return (ANSC_HANDLE)(p_EthLink->pstDataModelMarking + nIndex);
    }
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Marking_IsUpdated
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is checking whether the table is updated or not.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     TRUE or FALSE.

**********************************************************************/

BOOL
Marking_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    BOOL    bIsUpdated   = TRUE;
    return bIsUpdated;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        Marking_Synchronize
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to synchronize the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/

ULONG
Marking_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Marking_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
Marking_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PCOSA_DML_MARKING   p_EthMarking  = (PCOSA_DML_MARKING)hInsContext;

    if(p_EthMarking == NULL) {
        CcspTraceError(("%s %d - Invalid memory \n",__FUNCTION__, __LINE__));
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "SKBPort", TRUE))
    {
        *puLong = p_EthMarking->SKBPort;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Marking_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Marking_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    PCOSA_DML_MARKING   p_EthMarking  = (PCOSA_DML_MARKING)hInsContext;

    if(p_EthMarking == NULL) {
        CcspTraceError(("%s %d - Invalid memory \n",__FUNCTION__, __LINE__));
        return FALSE;
    }
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "EthernetPriorityMark", TRUE))
    {
        *pInt =  p_EthMarking->EthernetPriorityMark;
        return TRUE;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}
