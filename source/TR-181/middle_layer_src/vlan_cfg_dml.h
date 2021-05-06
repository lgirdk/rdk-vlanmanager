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

#ifndef __VLAN_CFG_DML_H__
#define __VLAN_CFG_DML_H__

ULONG VlanCfg_GetEntryCount ( ANSC_HANDLE hInsContext );

ANSC_HANDLE VlanCfg_GetEntry ( ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber );

LONG VlanCfg_GetParamStringValue ( ANSC_HANDLE hInsContext, char* ParamName, char* pValue, ULONG* pUlSize );

BOOL VlanCfg_SetParamStringValue ( ANSC_HANDLE hInsContext, char* ParamName, char* pString );

BOOL VlanCfg_GetParamUlongValue ( ANSC_HANDLE hInsContext, char* ParamName, ULONG* pValue );

BOOL VlanCfg_SetParamUlongValue ( ANSC_HANDLE hInsContext, char* ParamName, ULONG uValue );

BOOL VlanCfg_Validate ( ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength );

ULONG VlanCfg_Commit ( ANSC_HANDLE hInsContext );

ULONG VlanCfg_Rollback ( ANSC_HANDLE hInsContext );

#endif
