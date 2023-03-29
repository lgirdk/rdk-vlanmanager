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

#ifndef  _VLAN_INTERNAL_H
#define  _VLAN_INTERNAL_H

#include "vlan_mgr_apis.h"
#include "vlan_apis.h"
/***********************************
    Actual definition declaration
************************************/
#define  IREP_FOLDER_NAME_VLAN                       "VLAN"
#define  IREP_FOLDER_NAME_PORTTRIGGER               "PORTTRIGGER"
#define  DML_RR_NAME_VLANNextInsNumber               "NextInstanceNumber"
#define  DML_RR_NAME_VLANAlias                       "Alias"
#define  DML_RR_NAME_VLANbNew                        "bNew"

#define  DATAMODEL_VLAN_CLASS_CONTENT                                                   \
    /* duplication of the base object class content */                                                \
    COSA_BASE_CONTENT                                                                       \
    /* start of VLAN object class content */                                                        \
    SLIST_HEADER                    VLANPMappingList;                                        \
    SLIST_HEADER                    Q_VlanList;                                        \
    ULONG                           MaxInstanceNumber;                                      \
    ULONG                           ulPtNextInstanceNumber;                                 \
    ULONG                           PreviousVisitTime;                                      \
    UCHAR                           AliasOfPortMapping[64];                                 \
    ANSC_HANDLE                     hIrepFolderVLAN;                                         \
    ANSC_HANDLE                     hIrepFolderVLANPt;                                       \
    ULONG                           ulVlanCfgInstanceNumber;                                 \
    ULONG                           ulVlantrInstanceNumber;                                 \
    PDML_VLAN                       VlanTer;                                             \

typedef  struct
_DATAMODEL_VLAN
{
    DATAMODEL_VLAN_CLASS_CONTENT
}
DATAMODEL_VLAN,  *PDATAMODEL_VLAN;

/*
*  This struct is for creating entry context link in writable table when call GetEntry()
*/

/**********************************
    Standard function declaration
***********************************/
ANSC_HANDLE
VlanCreate
    (
        VOID
    );

ANSC_STATUS
VlanInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
VlanRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
VlanGen
    (
        ANSC_HANDLE                 hDml
    );

ANSC_STATUS
VlanGenForTriggerEntry
    (
        ANSC_HANDLE    hDml,
        PDML_VLAN      pEntry
    );

#endif
