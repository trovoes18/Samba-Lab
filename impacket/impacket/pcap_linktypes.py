# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

LINKTYPE_NULL = 0
DLT_NULL = LINKTYPE_NULL
LINKTYPE_ETHERNET = 1
DLT_EN10MB = LINKTYPE_ETHERNET
LINKTYPE_AX25 = 3
DLT_AX25 = LINKTYPE_AX25
NKTYPE_IEEE802_5 = 6
DLT_IEEE802 = NKTYPE_IEEE802_5
LINKTYPE_ARCNET_BSD = 7
DLT_ARCNET = LINKTYPE_ARCNET_BSD
LINKTYPE_SLIP = 8
DLT_SLIP = LINKTYPE_SLIP
LINKTYPE_PPP = 9
DLT_PPP = LINKTYPE_PPP
LINKTYPE_FDDI = 10
DLT_FDDI = LINKTYPE_FDDI
LINKTYPE_PPP_HDLC = 50
DLT_PPP_SERIAL = LINKTYPE_PPP_HDLC
LINKTYPE_PPP_ETHER = 51
DLT_PPP_ETHER = LINKTYPE_PPP_ETHER
LINKTYPE_ATM_RFC1483 = 100
DLT_ATM_RFC1483 = LINKTYPE_ATM_RFC1483
LINKTYPE_RAW = 101
DLT_RAW = LINKTYPE_RAW
LINKTYPE_C_HDLC = 104
DLT_C_HDLC = LINKTYPE_C_HDLC
LINKTYPE_IEEE802_11 = 105
DLT_IEEE802_11 = LINKTYPE_IEEE802_11
LINKTYPE_FRELAY = 107
DLT_FRELAY = LINKTYPE_FRELAY
LINKTYPE_LOOP = 108
DLT_LOOP = LINKTYPE_LOOP
LINKTYPE_LINUX_SLL = 113
DLT_LINUX_SLL = LINKTYPE_LINUX_SLL
LINKTYPE_LTALK = 114
DLT_LTALK = LINKTYPE_LTALK
LINKTYPE_PFLOG = 117
DLT_PFLOG = LINKTYPE_PFLOG
LINKTYPE_IEEE802_11_PRISM = 119
DLT_PRISM_HEADER = LINKTYPE_IEEE802_11_PRISM
LINKTYPE_IP_OVER_FC = 122
DLT_IP_OVER_FC = LINKTYPE_IP_OVER_FC
LINKTYPE_SUNATM = 123
DLT_SUNATM = LINKTYPE_SUNATM
LINKTYPE_IEEE802_11_RADIOTAP = 127
DLT_IEEE802_11_RADIO = LINKTYPE_IEEE802_11_RADIOTAP
LINKTYPE_ARCNET_LINUX = 129
DLT_ARCNET_LINUX = LINKTYPE_ARCNET_LINUX
LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138
DLT_APPLE_IP_OVER_IEEE1394 = LINKTYPE_APPLE_IP_OVER_IEEE1394
LINKTYPE_MTP2_WITH_PHDR = 139
DLT_MTP2_WITH_PHDR = LINKTYPE_MTP2_WITH_PHDR
LINKTYPE_MTP2 = 140
DLT_MTP2 = LINKTYPE_MTP2
LINKTYPE_MTP3 = 141
DLT_MTP3 = LINKTYPE_MTP3
LINKTYPE_SCCP = 142
DLT_SCCP = LINKTYPE_SCCP
LINKTYPE_DOCSIS = 143
DLT_DOCSIS = LINKTYPE_DOCSIS
LINKTYPE_LINUX_IRDA = 144
DLT_LINUX_IRDA = LINKTYPE_LINUX_IRDA
LINKTYPE_IEEE802_11_AVS = 163
DLT_IEEE802_11_RADIO_AVS = LINKTYPE_IEEE802_11_AVS
LINKTYPE_BACNET_MS_TP = 165
DLT_BACNET_MS_TP = LINKTYPE_BACNET_MS_TP
LINKTYPE_PPP_PPPD = 166
DLT_PPP_PPPD = LINKTYPE_PPP_PPPD
LINKTYPE_GPRS_LLC = 169
DLT_GPRS_LLC = LINKTYPE_GPRS_LLC
LINKTYPE_LINUX_LAPD = 177
DLT_LINUX_LAPD = LINKTYPE_LINUX_LAPD
LINKTYPE_BLUETOOTH_HCI_H4 = 187
DLT_BLUETOOTH_HCI_H4 = LINKTYPE_BLUETOOTH_HCI_H4
LINKTYPE_USB_LINUX = 189
DLT_USB_LINUX = LINKTYPE_USB_LINUX
LINKTYPE_PPI = 192
DLT_PPI = LINKTYPE_PPI
LINKTYPE_IEEE802_15_4 = 195
DLT_IEEE802_15_4 = LINKTYPE_IEEE802_15_4
LINKTYPE_SITA = 196
DLT_SITA = LINKTYPE_SITA
LINKTYPE_ERF = 197
DLT_ERF = LINKTYPE_ERF
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR
LINKTYPE_AX25_KISS = 202
DLT_AX25_KISS = LINKTYPE_AX25_KISS
LINKTYPE_LAPD = 203
DLT_LAPD = LINKTYPE_LAPD
LINKTYPE_PPP_WITH_DIR = 204
DLT_PPP_WITH_DIR = LINKTYPE_PPP_WITH_DIR
LINKTYPE_C_HDLC_WITH_DIR = 205
DLT_C_HDLC_WITH_DIR = LINKTYPE_C_HDLC_WITH_DIR
LINKTYPE_FRELAY_WITH_DIR = 206
DLT_FRELAY_WITH_DIR = LINKTYPE_FRELAY_WITH_DIR
LINKTYPE_IPMB_LINUX = 209
DLT_IPMB_LINUX = LINKTYPE_IPMB_LINUX
LINKTYPE_IEEE802_15_4_NONASK_PHY = 215
DLT_IEEE802_15_4_NONASK_PHY = LINKTYPE_IEEE802_15_4_NONASK_PHY
LINKTYPE_USB_LINUX_MMAPPED = 220
DLT_USB_LINUX_MMAPPED = LINKTYPE_USB_LINUX_MMAPPED
LINKTYPE_FC_2 = 224
DLT_FC_2 = LINKTYPE_FC_2
LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225
DLT_FC_2_WITH_FRAME_DELIMS = LINKTYPE_FC_2_WITH_FRAME_DELIMS
LINKTYPE_IPNET = 226
DLT_IPNET = LINKTYPE_IPNET
LINKTYPE_CAN_SOCKETCAN = 227
DLT_CAN_SOCKETCAN = LINKTYPE_CAN_SOCKETCAN
LINKTYPE_IPV4 = 228
DLT_IPV4 = LINKTYPE_IPV4
LINKTYPE_IPV6 = 229
DLT_IPV6 = LINKTYPE_IPV6
LINKTYPE_IEEE802_15_4_NOFCS = 230
DLT_IEEE802_15_4_NOFCS = LINKTYPE_IEEE802_15_4_NOFCS
LINKTYPE_DBUS = 231
DLT_DBUS = LINKTYPE_DBUS
LINKTYPE_DVB_CI = 235
DLT_DVB_CI = LINKTYPE_DVB_CI
LINKTYPE_MUX27010 = 236
DLT_MUX27010 = LINKTYPE_MUX27010
LINKTYPE_STANAG_5066_D_PDU = 237
DLT_STANAG_5066_D_PDU = LINKTYPE_STANAG_5066_D_PDU
LINKTYPE_NFLOG = 239
DLT_NFLOG = LINKTYPE_NFLOG
LINKTYPE_NETANALYZER = 240
DLT_NETANALYZER = LINKTYPE_NETANALYZER
LINKTYPE_NETANALYZER_TRANSPARENT = 241
DLT_NETANALYZER_TRANSPARENT = LINKTYPE_NETANALYZER_TRANSPARENT
LINKTYPE_IPOIB = 242
DLT_IPOIB = LINKTYPE_IPOIB
LINKTYPE_MPEG_2_TS = 243
DLT_MPEG_2_TS = LINKTYPE_MPEG_2_TS
LINKTYPE_NG40 = 244
DLT_NG40 = LINKTYPE_NG40
LINKTYPE_NFC_LLCP = 245
DLT_NFC_LLCP = LINKTYPE_NFC_LLCP
LINKTYPE_INFINIBAND = 247
DLT_INFINIBAND = LINKTYPE_INFINIBAND
LINKTYPE_SCTP = 248
DLT_SCTP = LINKTYPE_SCTP
LINKTYPE_USBPCAP = 249
DLT_USBPCAP = LINKTYPE_USBPCAP
LINKTYPE_RTAC_SERIAL = 250
DLT_RTAC_SERIAL = LINKTYPE_RTAC_SERIAL
LINKTYPE_BLUETOOTH_LE_LL = 251
DLT_BLUETOOTH_LE_LL = LINKTYPE_BLUETOOTH_LE_LL
LINKTYPE_NETLINK = 253
DLT_NETLINK = LINKTYPE_NETLINK
LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254
DLT_BLUETOOTH_LINUX_MONITOR = LINKTYPE_BLUETOOTH_LINUX_MONITOR
LINKTYPE_BLUETOOTH_BREDR_BB = 255
DLT_BLUETOOTH_BREDR_BB = LINKTYPE_BLUETOOTH_BREDR_BB
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_BLUETOOTH_LE_LL_WITH_PHDR = LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
LINKTYPE_PROFIBUS_DL = 257
DLT_PROFIBUS_DL = LINKTYPE_PROFIBUS_DL
LINKTYPE_PKTAP = 258
DLT_PKTAP = LINKTYPE_PKTAP
LINKTYPE_EPON = 259
DLT_EPON = LINKTYPE_EPON
LINKTYPE_IPMI_HPM_2 = 260
DLT_IPMI_HPM_2 = LINKTYPE_IPMI_HPM_2