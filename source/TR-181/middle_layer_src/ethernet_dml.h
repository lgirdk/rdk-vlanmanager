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

#ifndef  _ETHLINK_DML_H
#define  _ETHLINK_DML_H

/***********************************************************************

 APIs for Object:

    Ethernet.Link.{i}.

    *  EthLink_GetEntryCount
    *  EthLink_GetEntry
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

ULONG
EthLink_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE
EthLink_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );


BOOL
EthLink_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
EthLink_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );

ULONG
EthLink_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
EthLink_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
EthLink_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );

BOOL
EthLink_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

BOOL
EthLink_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
EthLink_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
EthLink_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    Device.Ethernet.Link.{i}.X_RDK_Marking.{i}.

    *  Marking_GetEntryCount
    *  Marking_GetEntry
    *  Marking_IsUpdated
    *  Marking_Synchronize
    *  Marking_GetParamIntValue
    *  Marking_GetParamUlongValue

***********************************************************************/
ULONG
Marking_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
Marking_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

BOOL
Marking_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
Marking_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL
Marking_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
Marking_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

#endif
