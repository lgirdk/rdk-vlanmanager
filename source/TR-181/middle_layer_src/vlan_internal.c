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

#include "vlan_mgr_apis.h"
#include "vlan_apis.h"
#include "vlan_internal.h"
#include "plugin_main_apis.h"
#include "poam_irepfo_interface.h"
#include "sys_definitions.h"

extern void * g_pDslhDmlAgent;
extern char                     g_Subsystem[32];
extern ANSC_HANDLE              bus_handle;

#define PSM_VLANMANAGER_CFG_COUNT  "dmsb.vlanmanager.cfg.count"
#define PSM_VLANMANAGER_CFG_REGION "dmsb.vlanmanager.cfg.%d.region"
#define PSM_VLANMANAGER_CFG_IFTYPE "dmsb.vlanmanager.cfg.%d.iftype"
#define PSM_VLANMANAGER_CFG_VLANID "dmsb.vlanmanager.cfg.%d.vlanid"
#define PSM_VLANMANAGER_CFG_TPID   "dmsb.vlanmanager.cfg.%d.tpid"

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        CosaVlanCreate
            (
            );

    description:

        This function constructs cosa vlan object and return handle.

    argument:

    return:     newly created vlan object.

**********************************************************************/

ANSC_HANDLE
VlanCreate
    (
        VOID
    )
{
    ANSC_STATUS                 returnStatus = ANSC_STATUS_SUCCESS;
    PDATAMODEL_VLAN             pMyObject    = (PDATAMODEL_VLAN)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PDATAMODEL_VLAN)AnscAllocateMemory(sizeof(DATAMODEL_VLAN));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    //pMyObject->Oid             = DATAMODEL_VLAN_OID;
    pMyObject->Create            = VlanCreate;
    pMyObject->Remove            = VlanRemove;
    pMyObject->Initialize        = VlanInitialize;

    pMyObject->Initialize   ((ANSC_HANDLE)pMyObject);

    return  (ANSC_HANDLE)pMyObject;
}

int DmlVlanGetPSMRecordValue ( char *pPSMEntry, char *pOutputString )
{
    int   retPsmGet = CCSP_SUCCESS;
    char *strValue  = NULL;

    //Validate buffer
    if( ( NULL == pPSMEntry ) && ( NULL == pOutputString ) )
    {
        CcspTraceError(("%s %d Invalid buffer\n",__FUNCTION__,__LINE__));
        return retPsmGet;
    }

    retPsmGet = PSM_Get_Record_Value2( bus_handle, g_Subsystem, pPSMEntry, NULL, &strValue );
    if ( retPsmGet == CCSP_SUCCESS )
    {
        //Copy till end of the string
        snprintf( pOutputString, strlen( strValue ) + 1, "%s", strValue );

        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }

    return retPsmGet;
}


void VlanCfgInitialize( ANSC_HANDLE hThisObject)
{
    PDATAMODEL_VLAN pMyObject = (PDATAMODEL_VLAN)hThisObject;
    char acPSMQuery[128]    = { 0 };
    char acPSMValue[64]     = { 0 };
    INT vlancfgCount = 0;
    INT nIndex = 0;

    /* get cfg count */
    memset(acPSMQuery, 0, sizeof(acPSMQuery));
    memset(acPSMValue, 0, sizeof(acPSMValue));
    snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_CFG_COUNT );
    if (  CCSP_SUCCESS == DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue ) )
    {
        vlancfgCount = atoi (acPSMValue);
    }

    pMyObject->ulVlanCfgInstanceNumber = vlancfgCount ;
    PDML_VLAN_CFG pVlanCfg = (PDML_VLAN_CFG)AnscAllocateMemory(sizeof(DML_VLAN_CFG)* vlancfgCount);
    memset(pVlanCfg, 0, sizeof(pVlanCfg));

    for(nIndex = 0; nIndex < vlancfgCount; nIndex++)
    {
        pVlanCfg[nIndex].InstanceNumber = nIndex + 1;

        /* get cfg region from psm */
        memset(acPSMQuery, 0, sizeof(acPSMQuery));
        memset(acPSMValue, 0, sizeof(acPSMValue));
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_CFG_REGION, nIndex + 1 );
        if (  CCSP_SUCCESS == DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue ) )
        {
            strcpy(pVlanCfg[nIndex].Region, acPSMValue);
        }

        /* get cfg interfaceType from psm */
        memset(acPSMQuery, 0, sizeof(acPSMQuery));
        memset(acPSMValue, 0, sizeof(acPSMValue));
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_CFG_IFTYPE, nIndex + 1 );
        if (  CCSP_SUCCESS == DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue ) )
        {
            if(0 == strncmp(acPSMValue,"DSL",3) )
            {
                pVlanCfg[nIndex].InterfaceType = DSL;
            }
            else if (0 == strncmp(acPSMValue,"WANOE",5))
            {
                pVlanCfg[nIndex].InterfaceType = WANOE;
            }
            else if (0 == strncmp(acPSMValue,"GPON",4))
            {
                pVlanCfg[nIndex].InterfaceType = GPON;
            }
        }

        /* get cfg vlanid from psm */
        memset(acPSMQuery, 0, sizeof(acPSMQuery));
        memset(acPSMValue, 0, sizeof(acPSMValue));
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_CFG_VLANID, nIndex + 1 );
        if (  CCSP_SUCCESS == DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue ) )
        {
            pVlanCfg[nIndex].VLANId =  atoi (acPSMValue);
        }

        /* get cfg tpid from psm */
        memset(acPSMQuery, 0, sizeof(acPSMQuery));
        memset(acPSMValue, 0, sizeof(acPSMValue));
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_CFG_TPID, nIndex + 1 );
        if (  CCSP_SUCCESS == DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue ) )
        {
            pVlanCfg[nIndex].TPId = atoi (acPSMValue);
        }
    }

    pMyObject->VlanCfg = pVlanCfg;

}
/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        VlanInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa vlan object and return handle.

    argument:	ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
VlanInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus     = ANSC_STATUS_SUCCESS;
    PDATAMODEL_VLAN                 pMyObject        = (PDATAMODEL_VLAN)hThisObject;
    PSLAP_VARIABLE                  pSlapVariable    = (PSLAP_VARIABLE             )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoCOSA  = NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoVLAN   = NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoVLANPt = NULL;

    /* Call Initiation */
    returnStatus = DmlVlanInit(NULL, NULL, VlanGen);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        return returnStatus;
    }

    VlanCfgInitialize( pMyObject );

    /* Initiation all functions */
    AnscSListInitializeHeader( &pMyObject->VLANPMappingList );
    AnscSListInitializeHeader( &pMyObject->Q_VlanList );
    pMyObject->MaxInstanceNumber        = 0;
    pMyObject->ulPtNextInstanceNumber   = 1;
    pMyObject->PreviousVisitTime        = 0;

    /*Create VLAN folder in configuration */
    pPoamIrepFoCOSA = (PPOAM_IREP_FOLDER_OBJECT)g_GetRegistryRootFolder(g_pDslhDmlAgent);

    if ( !pPoamIrepFoCOSA )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto  EXIT;
    }

    pPoamIrepFoVLAN =
        (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoCOSA->GetFolder
            (
                (ANSC_HANDLE)pPoamIrepFoCOSA,
                IREP_FOLDER_NAME_VLAN
            );

    if ( !pPoamIrepFoVLAN )
    {
        pPoamIrepFoCOSA->EnableFileSync((ANSC_HANDLE)pPoamIrepFoCOSA, FALSE);

        pPoamIrepFoVLAN =
            pPoamIrepFoCOSA->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoCOSA,
                    IREP_FOLDER_NAME_VLAN,
                    0
                );

        pPoamIrepFoCOSA->EnableFileSync((ANSC_HANDLE)pPoamIrepFoCOSA, TRUE);
    }

    if ( !pPoamIrepFoVLAN )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto  EXIT;
    }
    else
    {
        pMyObject->hIrepFolderVLAN = (ANSC_HANDLE)pPoamIrepFoVLAN;
    }

    pPoamIrepFoVLANPt =
        (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoVLAN->GetFolder
            (
                (ANSC_HANDLE)pPoamIrepFoVLAN,
                IREP_FOLDER_NAME_PORTTRIGGER
            );

    if ( !pPoamIrepFoVLANPt )
    {
        /* pPoamIrepFoCOSA->EnableFileSync((ANSC_HANDLE)pPoamIrepFoCOSA, FALSE); */

        pPoamIrepFoVLANPt =
            pPoamIrepFoCOSA->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoVLAN,
                    IREP_FOLDER_NAME_PORTTRIGGER,
                    0
                );

        /* pPoamIrepFoCOSA->EnableFileSync((ANSC_HANDLE)pPoamIrepFoCOSA, TRUE); */
    }

    if ( !pPoamIrepFoVLANPt )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto  EXIT;
    }
    else
    {
        pMyObject->hIrepFolderVLANPt = (ANSC_HANDLE)pPoamIrepFoVLANPt;
    }

    /* Retrieve the next instance number for Port Trigger */

    if ( TRUE )
    {
        if ( pPoamIrepFoVLANPt )
        {
            pSlapVariable =
                (PSLAP_VARIABLE)pPoamIrepFoVLANPt->GetRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoVLANPt,
                        DML_RR_NAME_VLANNextInsNumber,
                        NULL
                    );

            if ( pSlapVariable )
            {
                pMyObject->ulPtNextInstanceNumber = pSlapVariable->Variant.varUint32;

                SlapFreeVariable(pSlapVariable);
            }
        }
    }

EXIT:

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        VlanRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa vlan object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
VlanRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PDATAMODEL_VLAN                 pMyObject    = (PDATAMODEL_VLAN)hThisObject;
    PSINGLE_LINK_ENTRY              pLink        = NULL;
    PCONTEXT_LINK_OBJECT            pVLAN         = NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFo  = (PPOAM_IREP_FOLDER_OBJECT)pMyObject->hIrepFolderVLAN;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepPt  = (PPOAM_IREP_FOLDER_OBJECT)pMyObject->hIrepFolderVLANPt;



    /* Remove resource of writable entry link */
    for( pLink = AnscSListPopEntry(&pMyObject->VLANPMappingList); pLink; )
    {
        pVLAN = (PCONTEXT_LINK_OBJECT)ACCESS_CONTEXT_LINK_OBJECT(pLink);
        pLink = AnscSListGetNextEntry(pLink);

        AnscFreeMemory(pVLAN->hContext);
        AnscFreeMemory(pVLAN);
    }

    for( pLink = AnscSListPopEntry(&pMyObject->Q_VlanList); pLink; )
    {
        pVLAN = (PCONTEXT_LINK_OBJECT)ACCESS_CONTEXT_LINK_OBJECT(pLink);
        pLink = AnscSListGetNextEntry(pLink);

        AnscFreeMemory(pVLAN->hContext);
        AnscFreeMemory(pVLAN);
    }

    if ( pPoamIrepPt )
    {
        pPoamIrepPt->Remove( (ANSC_HANDLE)pPoamIrepPt);
    }

    if ( pPoamIrepFo )
    {
        pPoamIrepFo->Remove( (ANSC_HANDLE)pPoamIrepFo);
    }

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}

ANSC_STATUS
VlanGen
    (
        ANSC_HANDLE                 hDml
    )
{
    ANSC_STATUS                 returnStatus      = ANSC_STATUS_SUCCESS;
    PDATAMODEL_VLAN             pVLAN             = (PDATAMODEL_VLAN)g_pBEManager->hVLAN;

    /*
            For dynamic and writable table, we don't keep the Maximum InstanceNumber.
            If there is delay_added entry, we just jump that InstanceNumber.
        */
    do
    {
        pVLAN->MaxInstanceNumber++;

        if ( pVLAN->MaxInstanceNumber <= 0 )
        {
            pVLAN->MaxInstanceNumber   = 1;
        }

        if ( !SListGetEntryByInsNum(&pVLAN->VLANPMappingList, pVLAN->MaxInstanceNumber) )
        {
            break;
        }
    }while(1);

    //pEntry->InstanceNumber            = pVLAN->MaxInstanceNumber;

    return returnStatus;
}

ANSC_STATUS
VlanGenForTriggerEntry
    (
        ANSC_HANDLE    hDml,
        PDML_VLAN      pEntry
    )
{
    ANSC_STATUS                 returnStatus      = ANSC_STATUS_SUCCESS;
    PDATAMODEL_VLAN             pVLAN             = (PDATAMODEL_VLAN)g_pBEManager->hVLAN;

    /*
            For dynamic and writable table, we don't keep the Maximum InstanceNumber.
            If there is delay_added entry, we just jump that InstanceNumber.
        */
    do
    {
        if ( pVLAN->ulPtNextInstanceNumber == 0 )
        {
            pVLAN->ulPtNextInstanceNumber   = 1;
        }

        if ( !SListGetEntryByInsNum(&pVLAN->Q_VlanList, pVLAN->ulPtNextInstanceNumber) )
        {
            break;
        }
        else
        {
            pVLAN->ulPtNextInstanceNumber++;
        }
    }while(1);

    pEntry->InstanceNumber            = pVLAN->ulPtNextInstanceNumber;

    if ( pEntry->Alias[0] == '\0' )
    {
        _ansc_sprintf( pEntry->Alias, "VLAN_%d", pEntry->InstanceNumber );
        DML_VLAN_INIT(pEntry);

        _ansc_sprintf(pEntry->Name, "erouter%d", pEntry->InstanceNumber);
        pEntry->Status = VLAN_IF_STATUS_NOT_PRESENT;
    }

    pVLAN->ulPtNextInstanceNumber++;

    return returnStatus;
}
