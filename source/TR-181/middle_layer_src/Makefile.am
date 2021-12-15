################################################################################
#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2020 Sky
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#/*
# * Copyright [2014] [Cisco Systems, Inc.]
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *     http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
#*/
####################################################################################
AM_CFLAGS =

ACLOCAL_AMFLAGS = -I m4

noinst_LTLIBRARIES = libRdkVlanManager_middle_layer_src.la

libRdkVlanManager_middle_layer_src_la_CPPFLAGS = -I$(top_srcdir)/source/TR-181/include -I$(top_srcdir)/source/TR-181/board_sbapi -I$(top_srcdir)/source/TR-181/middle_layer_src -I$(top_srcdir)/source/RdkVlanManager
libRdkVlanManager_middle_layer_src_la_SOURCES = plugin_main.c plugin_main_apis.c vlan_apis.c vlan_dml.c vlan_internal.c ethernet_internal.c ethernet_dml.c ethernet_apis.c vlan_eth_hal.c
libRdkVlanManager_middle_layer_src_la_LDFLAGS = -lccsp_common -lhal_platform -lsyscfg -lsysevent -lpthread -lsecure_wrapper
