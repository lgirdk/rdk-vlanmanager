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

/**********************************************************************

    module:	vlan_mgr_dml_api_common.h

        For Data Model Library Implementation (DML),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines the common data structure and
        constants for DML API.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    revision:

        09/12/2019    initial revision.

**********************************************************************/


#ifndef  _VLAN_MGR_DML_API_COMMON_
#define  _VLAN_MGR_DML_API_COMMON_

#include "ansc_platform.h"

/*
 *  Define custom trace module ID
 */
#ifdef   ANSC_TRACE_MODULE_ID
    #undef  ANSC_TRACE_MODULE_ID
#endif

#define  ANSC_TRACE_MODULE_ID                       ANSC_TRACE_ID_DM_API


/**********************************************************************
                STRUCTURE AND CONSTANT DEFINITIONS
**********************************************************************/

typedef  enum
_DML_IF_STATUS
{
    DML_IF_STATUS_Up               = 1,
    DML_IF_STATUS_Down,
    DML_IF_STATUS_Unknown,
    DML_IF_STATUS_Dormant,
    DML_IF_STATUS_NotPresent,
    DML_IF_STATUS_LowerLayerDown,
    DML_IF_STATUS_Error
}
DML_IF_STATUS, *PDML_IF_STATUS;


typedef  struct
_DML_IF_STATS
{
    ULONG                           BytesSent;
    ULONG                           BytesReceived;
    ULONG                           PacketsSent;
    ULONG                           PacketsReceived;
    ULONG                           ErrorsSent;
    ULONG                           ErrorsReceived;
    ULONG                           UnicastPacketsSent;
    ULONG                           UnicastPacketsReceived;
    ULONG                           DiscardPacketsSent;
    ULONG                           DiscardPacketsReceived;
    ULONG                           MulticastPacketsSent;
    ULONG                           MulticastPacketsReceived;
    ULONG                           BroadcastPacketsSent;
    ULONG                           BroadcastPacketsReceived;
    ULONG                           UnknownProtoPacketsReceived;
}
DML_IF_STATS, *PDML_IF_STATS;


typedef  enum
_DML_STATUS
{
    DML_STATUS_Disabled    = 1,
    DML_STATUS_Enabled,
    DML_STATUS_Error_Misconfigured,
    DML_STATUS_Error
}
DML_STATUS, *PDML_STATUS;


#endif

