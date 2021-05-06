/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
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

#include "vlan_mgr_apis.h"
#include "ethernet_apis.h"
#include "ethernet_internal.h"
#include "plugin_main_apis.h"
#include "poam_irepfo_interface.h"
#include "sys_definitions.h"

extern void * g_pDslhDmlAgent;

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        EthernetCreate
            (
            );

    description:

        This function constructs cosa ethernet object and return handle.

    argument:

    return:     newly created ethernet object.

**********************************************************************/

ANSC_HANDLE
EthernetCreate
    (
        VOID
    )
{
    ANSC_STATUS                returnStatus = ANSC_STATUS_SUCCESS;
    PDATAMODEL_ETHERNET        pMyObject    = (PDATAMODEL_ETHERNET) NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PDATAMODEL_ETHERNET)AnscAllocateMemory(sizeof(DATAMODEL_ETHERNET));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    //pMyObject->Oid             = DATAMODEL_ETHERNET_OID;
    pMyObject->Create            = EthernetCreate;
    pMyObject->Remove            = EthernetRemove;
    pMyObject->Initialize        = EthernetInitialize;

    pMyObject->Initialize   ((ANSC_HANDLE)pMyObject);

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        EthernetInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate cosa ethernet object and return handle.

    argument:	ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
EthernetInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus     = ANSC_STATUS_SUCCESS;
    PDATAMODEL_ETHERNET             pMyObject        = (PDATAMODEL_ETHERNET)hThisObject;
    PSLAP_VARIABLE                  pSlapVariable    = (PSLAP_VARIABLE             )NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoCOSA  = NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoEthernet   = NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoEthernetPt = NULL;

    /* Call Initiation */
    returnStatus = DmlEthInit(NULL, NULL, EthernetGen);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        return returnStatus;
    }

    /* Initiation all functions */
    AnscSListInitializeHeader( &pMyObject->EthPMappingList );
    AnscSListInitializeHeader( &pMyObject->Q_EthList );
    pMyObject->MaxInstanceNumber        = 0;
    pMyObject->ulPtNextInstanceNumber   = 1;
    pMyObject->PreviousVisitTime        = 0;

    /*Create ETHERNET folder in configuration */
    pPoamIrepFoCOSA = (PPOAM_IREP_FOLDER_OBJECT)g_GetRegistryRootFolder(g_pDslhDmlAgent);

    if ( !pPoamIrepFoCOSA )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto  EXIT;
    }

    pPoamIrepFoEthernet =
        (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoCOSA->GetFolder
            (
                (ANSC_HANDLE)pPoamIrepFoCOSA,
                IREP_FOLDER_NAME_ETHERNET
            );

    if ( !pPoamIrepFoEthernet )
    {
        pPoamIrepFoCOSA->EnableFileSync((ANSC_HANDLE)pPoamIrepFoCOSA, FALSE);

        pPoamIrepFoEthernet =
            pPoamIrepFoCOSA->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoCOSA,
                    IREP_FOLDER_NAME_ETHERNET,
                    0
                );

        pPoamIrepFoCOSA->EnableFileSync((ANSC_HANDLE)pPoamIrepFoCOSA, TRUE);
    }

    if ( !pPoamIrepFoEthernet )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto  EXIT;
    }
    else
    {
        pMyObject->hIrepFolderEthernet = (ANSC_HANDLE)pPoamIrepFoEthernet;
    }

    pPoamIrepFoEthernetPt =
        (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoEthernet->GetFolder
            (
                (ANSC_HANDLE)pPoamIrepFoEthernet,
                IREP_FOLDER_NAME_PORTTRIGGER
            );

    if ( !pPoamIrepFoEthernetPt )
    {
        /* pPoamIrepFoCOSA->EnableFileSync((ANSC_HANDLE)pPoamIrepFoCOSA, FALSE); */

        pPoamIrepFoEthernetPt =
            pPoamIrepFoCOSA->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoEthernet,
                    IREP_FOLDER_NAME_PORTTRIGGER,
                    0
                );

        /* pPoamIrepFoCOSA->EnableFileSync((ANSC_HANDLE)pPoamIrepFoCOSA, TRUE); */
    }

    if ( !pPoamIrepFoEthernetPt )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto  EXIT;
    }
    else
    {
        pMyObject->hIrepFolderEthernetPt = (ANSC_HANDLE)pPoamIrepFoEthernetPt;
    }

    /* Retrieve the next instance number for Port Trigger */

    if ( TRUE )
    {
        if ( pPoamIrepFoEthernetPt )
        {
            pSlapVariable =
                (PSLAP_VARIABLE)pPoamIrepFoEthernetPt->GetRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoEthernetPt,
                        DML_RR_NAME_EthNextInsNumber,
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
        EthernetRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa ethernet object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
EthernetRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PDATAMODEL_ETHERNET             pMyObject    = (PDATAMODEL_ETHERNET)hThisObject;
    PSINGLE_LINK_ENTRY              pLink        = NULL;
    PCONTEXT_LINK_OBJECT            pEthernet    = NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFo  = (PPOAM_IREP_FOLDER_OBJECT)pMyObject->hIrepFolderEthernet;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepPt  = (PPOAM_IREP_FOLDER_OBJECT)pMyObject->hIrepFolderEthernetPt;



    /* Remove resource of writable entry link */
    for( pLink = AnscSListPopEntry(&pMyObject->EthPMappingList); pLink; )
    {
        pEthernet = (PCONTEXT_LINK_OBJECT)ACCESS_CONTEXT_LINK_OBJECT(pLink);
        pLink = AnscSListGetNextEntry(pLink);

        AnscFreeMemory(pEthernet->hContext);
        AnscFreeMemory(pEthernet);
    }

    for( pLink = AnscSListPopEntry(&pMyObject->Q_EthList); pLink; )
    {
        pEthernet = (PCONTEXT_LINK_OBJECT)ACCESS_CONTEXT_LINK_OBJECT(pLink);
        pLink = AnscSListGetNextEntry(pLink);

        AnscFreeMemory(pEthernet->hContext);
        AnscFreeMemory(pEthernet);
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
EthernetGen
    (
        ANSC_HANDLE                 hDml
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PDATAMODEL_ETHERNET             pEthernet         = (PDATAMODEL_ETHERNET)g_pBEManager->hEth;

    /*
            For dynamic and writable table, we don't keep the Maximum InstanceNumber.
            If there is delay_added entry, we just jump that InstanceNumber.
        */
    do
    {
        pEthernet->MaxInstanceNumber++;

        if ( pEthernet->MaxInstanceNumber <= 0 )
        {
            pEthernet->MaxInstanceNumber   = 1;
        }

        if ( !SEthListGetEntryByInsNum(&pEthernet->EthPMappingList, pEthernet->MaxInstanceNumber) )
        {
            break;
        }
    }while(1);

    //pEntry->InstanceNumber            = pEthernet->MaxInstanceNumber;

    return returnStatus;
}

ANSC_STATUS
EthGenForTriggerEntry
    (
        ANSC_HANDLE                 hDml,
        PDML_ETHERNET               pEntry
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PDATAMODEL_ETHERNET             pEthernet         = (PDATAMODEL_ETHERNET)g_pBEManager->hEth;

    /*
            For dynamic and writable table, we don't keep the Maximum InstanceNumber.
            If there is delay_added entry, we just jump that InstanceNumber.
        */
    do
    {
        if ( pEthernet->ulPtNextInstanceNumber == 0 )
        {
            pEthernet->ulPtNextInstanceNumber   = 1;
        }

        if ( !SEthListGetEntryByInsNum(&pEthernet->Q_EthList, pEthernet->ulPtNextInstanceNumber) )
        {
            break;
        }
        else
        {
            pEthernet->ulPtNextInstanceNumber++;
        }
    }while(1);

    pEntry->InstanceNumber            = pEthernet->ulPtNextInstanceNumber;

    _ansc_sprintf( pEntry->Path, "%s%d", ETHERNET_LINK_PATH, pEntry->InstanceNumber );
    DML_ETHERNET_INIT(pEntry);
    pEntry->Status = ETHERNET_IF_STATUS_NOT_PRESENT;

    pEthernet->ulPtNextInstanceNumber++;

    return returnStatus;
}
