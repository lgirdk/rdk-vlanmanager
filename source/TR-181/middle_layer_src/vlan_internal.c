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

#include "vlan_mgr_apis.h"
#include "vlan_apis.h"
#include "vlan_internal.h"
#include "plugin_main_apis.h"
#include "poam_irepfo_interface.h"
#include "sys_definitions.h"
#include "ccsp_psm_helper.h"

extern void * g_pDslhDmlAgent;
extern char                     g_Subsystem[32];
extern ANSC_HANDLE              bus_handle;


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

ANSC_STATUS DmlVlanGetPSMRecordValue ( char *pPSMEntry, char *pOutputString )
{
    int ret_val = ANSC_STATUS_SUCCESS;
    int   retPsmGet = CCSP_SUCCESS;
    char *strValue  = NULL;

    //Validate buffer
    if( ( NULL == pPSMEntry ) && ( NULL == pOutputString ) )
    {
        CcspTraceError(("%s %d Invalid buffer\n",__FUNCTION__,__LINE__));
        return retPsmGet;
    }

    retPsmGet = PSM_VALUE_GET_VALUE(pPSMEntry, strValue);
    if ( retPsmGet == CCSP_SUCCESS )
    {
        //Copy till end of the string
        snprintf( pOutputString, strlen( strValue ) + 1, "%s", strValue );

        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }

    return ret_val;
}

void VlanTerminationInitialize( ANSC_HANDLE hThisObject)
{
    PDATAMODEL_VLAN pMyObject = (PDATAMODEL_VLAN)hThisObject;
    char acPSMQuery[128]    = { 0 };
    char acPSMValue[64]     = { 0 };
    INT vlanCount = 0;
    INT nIndex = 0;
    int ret ;

    /* delay to let it initialize */
    sleep(2);
    /* get cfg count */
    snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_COUNT );
    ret = DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue )   ;
    if ( ret == 0)
    {
        vlanCount = atoi (acPSMValue);
    }

    pMyObject->ulVlantrInstanceNumber = vlanCount ;

    PDML_VLAN pVlan = (PDML_VLAN)AnscAllocateMemory(sizeof(DML_VLAN)* vlanCount);
    memset(pVlan, 0, sizeof(pVlan));

    for(nIndex = 0; nIndex < vlanCount; nIndex++)
    {
        pVlan[nIndex].InstanceNumber = nIndex + 1;
        /* get enable from psm */
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_ENABLE, nIndex + 1 );
        ret = DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue );
        if ( ret == 0)
        {
            if(strcmp(acPSMValue,PSM_ENABLE_STRING_TRUE) == 0)
            {
                pVlan[nIndex].Enable = TRUE;
            }
            else
            {
                pVlan[nIndex].Enable = FALSE;
            }
        }

        /* get alias from psm */
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_ALIAS, nIndex + 1 );
        ret = DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue );
        if ( ret == 0)
        {
             strcpy(pVlan[nIndex].Alias,acPSMValue);
        }

        /* get name from psm */
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_NAME, nIndex + 1 );
        ret = DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue );
        if ( ret == 0)
        {
             strcpy(pVlan[nIndex].Name,acPSMValue);
        }
        /* get lowerlayes from psm */
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_LOWERLAYERS, nIndex + 1 );
        ret = DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue );
        if ( ret == 0)
        {
             strcpy(pVlan[nIndex].LowerLayers,acPSMValue);
        }

        /* get vlanid from psm */
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_VLANID, nIndex + 1 );
        ret = DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue );
        if ( ret == 0)
        {
             pVlan[nIndex].VLANId = atoi(acPSMValue) ;
        }

        /* get cfg tpid from psm */
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_TPID, nIndex + 1 );
        ret = DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue );
        if ( ret == 0)
        {
             pVlan[nIndex].TPId = atoi(acPSMValue) ;
        }

        /* get base interface from psm */
        snprintf( acPSMQuery, sizeof( acPSMQuery ), PSM_VLANMANAGER_BASEINTERFACE, nIndex + 1 );
        ret = DmlVlanGetPSMRecordValue( acPSMQuery, acPSMValue );
        if ( ret == 0)
        {
             strcpy(pVlan[nIndex].BaseInterface,acPSMValue);
        }
     }

    pMyObject->VlanTer = pVlan;
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

    /* Call Initiation */
    returnStatus = DmlVlanInit(NULL, NULL);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        return returnStatus;
    }

    VlanTerminationInitialize( pMyObject );
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

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}

