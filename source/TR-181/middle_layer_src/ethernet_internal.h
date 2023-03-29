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

#ifndef  _ETHERNET_INTERNAL_H
#define  _ETHERNET_INTERNAL_H

#include "vlan_mgr_apis.h"
#include "ethernet_apis.h"

/***********************************
    Actual definition declaration
************************************/
#define  IREP_FOLDER_NAME_ETHERNET                   "ETH"
#define  IREP_FOLDER_NAME_PORTTRIGGER                "PORTTRIGGER"
#define  DML_RR_NAME_EthNextInsNumber                "NextInstanceNumber"
#define  DML_RR_NAME_EthAlias                        "Alias"
#define  DML_RR_NAME_EthbNew                         "bNew"

#define  DATAMODEL_ETH_CLASS_CONTENT                                                   \
    /* duplication of the base object class content */                                      \
    COSA_BASE_CONTENT                                                                       \
    SLIST_HEADER                    EthPMappingList;                                        \
    SLIST_HEADER                    Q_EthList;                                              \
    ULONG                           MaxInstanceNumber;                                      \
    ULONG                           ulPtNextInstanceNumber;                                 \
    ULONG                           PreviousVisitTime;                                      \
    UCHAR                           AliasOfPortMapping[64];                                 \
    ANSC_HANDLE                     hIrepFolderEthernet;                                    \
    ANSC_HANDLE                     hIrepFolderEthernetPt;                                  \
    ULONG                           ulEthlinkInstanceNumber;                                \
    PDML_ETHERNET                   EthLink;                                                \

typedef  struct
_DATAMODEL_ETHERNET
{
    DATAMODEL_ETH_CLASS_CONTENT
}
DATAMODEL_ETHERNET,  *PDATAMODEL_ETHERNET;

/*
*  This struct is for creating entry context link in writable table when call GetEntry()
*/

/**********************************
    Standard function declaration
***********************************/
ANSC_HANDLE
EthernetCreate
    (
        VOID
    );

ANSC_STATUS
EthernetInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
EthernetRemove
    (
        ANSC_HANDLE                 hThisObject
    );

#endif
