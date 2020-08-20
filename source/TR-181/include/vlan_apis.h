/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
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

#ifndef  _VLAN_APIS_H
#define  _VLAN_APIS_H

#include "vlan_mgr_apis.h"
#include "ssp_global.h"

#define VLAN_IF_STATUS_ERROR 7
#define VLAN_IF_STATUS_NOT_PRESENT 5

/* * Telemetry Markers */
#define VLAN_MARKER_VLAN_IF_CREATE          "RDKB_VLAN_CREATE"
#define VLAN_MARKER_VLAN_IF_DELETE          "RDKB_VLAN_DELETE"

/***********************************
    Actual definition declaration
************************************/
/*
    VLAN Part
*/
typedef enum { Up = 1, 
               Down, 
               Unknown, 
               Dormant, 
               NotPresent, 
               LowerLayerDown, 
               Error 
}vlan_link_status_e;

typedef  struct
_DML_VLAN
{
    ULONG                InstanceNumber;
    BOOLEAN              Enable;
    vlan_link_status_e   Status;
    CHAR                 Alias[64];
    CHAR                 Name[64];
    UINT                 LastChange;
    CHAR                 LowerLayers[1024];
    CHAR                 BaseInterface[64];
    UINT                 VLANId;
    UINT                 TPId;
}
DML_VLAN,  *PDML_VLAN;

#define DML_VLAN_INIT(pVlan)                                            \
{                                                                                  \
    (pVlan)->Enable            = FALSE;                                      \
}                                                                                  \

/*
Description:
    This callback routine is provided for backend to call middle layer
Arguments:
    hDml          Opaque handle passed in from CosaDmlVlanInit.
    pEntry        Pointer to VLAN vlan mapping to receive the generated values.
Return:
    Status of operation


*/
typedef ANSC_STATUS
(*PFN_DML_VLAN_GEN)
    (
        ANSC_HANDLE                 hDml
);


/*************************************
    The actual function declaration
**************************************/

/*
Description:
    This is the initialization routine for VLAN backend.
Arguments:
    hDml        Opaque handle from DM adapter. Backend saves this handle for calling pValueGenFn.
    phContext       Opaque handle passed back from backend, needed by CosaDmlVLANXyz() routines.
    pValueGenFn Function pointer to instance number/alias generation callback.
Return:
Status of operation.

*/
ANSC_STATUS
DmlVlanInit
    (
        ANSC_HANDLE                 hDml,
        PANSC_HANDLE                phContext,
        PFN_DML_VLAN_GEN            pValueGenFn
    );
/* APIs for VLAN */

PDML_VLAN
DmlGetVlans
    (
        ANSC_HANDLE                 hContext,
        PULONG                      pulCount,
        BOOLEAN                     bCommit
    );

ANSC_STATUS
DmlAddVlan
    (
        ANSC_HANDLE                 hContext,
        PDML_VLAN                   pEntry
    );

ANSC_STATUS
DmlGetVlan
    (
        ANSC_HANDLE                 hContext,
        ULONG                       InstanceNum,
        PDML_VLAN                   p_Vlan
    );

ANSC_STATUS
DmlGetVlanIfStatus
    (
        ANSC_HANDLE                 hContext,
        PDML_VLAN                   p_Vlan
    );

ANSC_STATUS
DmlSetVlan
    (
        ANSC_HANDLE                 hContext,
        PDML_VLAN                   p_Vlan
    );

ANSC_STATUS
DmlCreateVlanInterface
    (
        ANSC_HANDLE                 hContext,
        PDML_VLAN                   p_Vlan
    );

ANSC_STATUS
DmlDeleteVlanInterface
    (
        ANSC_HANDLE                 hContext,
        PDML_VLAN                   p_Vlan
    );
#endif
