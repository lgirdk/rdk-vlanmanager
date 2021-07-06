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
#include "plugin_main_apis.h"
#include "ccsp_trace.h"
#include "ccsp_syslog.h"
#include "vlan_dml.h"
#include "vlan_internal.h"

ULONG VlanCfg_GetEntryCount ( ANSC_HANDLE hInsContext )
{
    PDATAMODEL_VLAN pVLAN = (PDATAMODEL_VLAN)g_pBEManager->hVLAN;
    if (pVLAN)
    {
        return (pVLAN->ulVlanCfgInstanceNumber);
    }
    else
    {
        return 0;
    }
}

ANSC_HANDLE VlanCfg_GetEntry ( ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber )
{
    PDATAMODEL_VLAN                      pVLAN             = (PDATAMODEL_VLAN)g_pBEManager->hVLAN;
    PDML_VLAN_CFG          pVlanCfg = NULL;

    if ( pVLAN->VlanCfg && nIndex < pVLAN->ulVlanCfgInstanceNumber )
    {
        pVlanCfg = pVLAN->VlanCfg+nIndex;

        *pInsNumber = pVlanCfg->InstanceNumber;

        return pVlanCfg;
    }

    return NULL;
}

LONG VlanCfg_GetParamStringValue ( ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize )
{
      PDML_VLAN_CFG          pVlanCfg           = (PDML_VLAN_CFG)hInsContext;

    ANSC_STATUS status = ANSC_STATUS_FAILURE;

    if (!pVlanCfg || !pValue)
    {
        return -1;
    }

    if( AnscEqualString(ParamName, "Region", TRUE))
    {
        AnscCopyString(pValue, pVlanCfg->Region);
        return 0;
    }

    return -1;
}

BOOL VlanCfg_SetParamStringValue ( ANSC_HANDLE hInsContext, char* ParamName, char* pString )
{
    PDML_VLAN_CFG          pVlanCfg           = (PDML_VLAN_CFG)hInsContext;

    ANSC_STATUS status = ANSC_STATUS_FAILURE;

    if (!pVlanCfg || !pString)
    {
        return FALSE;
    }

    if( AnscEqualString(ParamName, "Region", TRUE))
    {
          AnscCopyString(pVlanCfg->Region, pString);
         return TRUE;
    }
    return FALSE;
}

BOOL VlanCfg_GetParamUlongValue ( ANSC_HANDLE hInsContext, char* ParamName, ULONG* pValue )
{

     PDML_VLAN_CFG          pVlanCfg           = (PDML_VLAN_CFG)hInsContext;

    ANSC_STATUS status = ANSC_STATUS_FAILURE;

    if (!pVlanCfg || !pValue)
    {
        return FALSE;
    }

    if( AnscEqualString(ParamName, "VLANId", TRUE))
    {
         *pValue = pVlanCfg->VLANId;
         return TRUE;
    }
    if( AnscEqualString(ParamName, "InterfaceType", TRUE))
    {
        *pValue =  pVlanCfg->InterfaceType;
        return TRUE;
    }

    else if( AnscEqualString(ParamName, "TPId", TRUE))
    {
        *pValue = pVlanCfg->TPId;
        return TRUE;
    }

    return FALSE;
}

BOOL VlanCfg_SetParamUlongValue ( ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue )
{

     PDML_VLAN_CFG          pVlanCfg           = (PDML_VLAN_CFG)hInsContext;

    ANSC_STATUS status = ANSC_STATUS_FAILURE;

    if (!pVlanCfg || !uValue)
    {
        return FALSE;
    }
    if( AnscEqualString(ParamName, "VLANId", TRUE))
    {
         pVlanCfg->VLANId = uValue;
         return TRUE;
    }
    else if( AnscEqualString(ParamName, "TPId", TRUE))
    {
        pVlanCfg->TPId = uValue;
        return TRUE;
    }
    else if( AnscEqualString(ParamName, "InterfaceType", TRUE))
    {
        pVlanCfg->InterfaceType = uValue;
        return TRUE;
    }
    return FALSE;
}

BOOL VlanCfg_Validate ( ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength )
{
    return TRUE;
}

ULONG VlanCfg_Commit ( ANSC_HANDLE hInsContext )
{
    return 0;
}

ULONG VlanCfg_Rollback ( ANSC_HANDLE hInsContext )
{
    return 0;
}

