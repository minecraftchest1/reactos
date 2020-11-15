/*
 * wdmguid.h
 *
 * GUID definitions for PnP device classes and device events.
 *
 * This file is part of the w32api package.
 *
 * Contributors:
 *   Created by Filip Navara <xnavara@volny.cz>.
 *
 * THIS SOFTWARE IS NOT COPYRIGHTED
 *
 * This source code is offered for use in the public domain. You may
 * use, modify or distribute it freely.
 *
 * This code is distributed in the hope that it will be useful but
 * WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 * DISCLAIMED. This includes but is not limited to warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __WDMGUID_H
#define __WDMGUID_H

DEFINE_GUID(GUID_HWPROFILE_QUERY_CHANGE,
  0xcb3a4001, 0x46f0, 0x11d0, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f);
DEFINE_GUID(GUID_HWPROFILE_CHANGE_CANCELLED,
  0xcb3a4002, 0x46f0, 0x11d0, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f);
DEFINE_GUID(GUID_HWPROFILE_CHANGE_COMPLETE,
  0xcb3a4003, 0x46f0, 0x11d0, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f);
DEFINE_GUID(GUID_DEVICE_INTERFACE_ARRIVAL,
  0xcb3a4004, 0x46f0, 0x11d0, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f);
DEFINE_GUID(GUID_DEVICE_INTERFACE_REMOVAL,
  0xcb3a4005, 0x46f0, 0x11d0, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f);
DEFINE_GUID(GUID_TARGET_DEVICE_QUERY_REMOVE,
  0xcb3a4006, 0x46f0, 0x11d0, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f);
DEFINE_GUID(GUID_TARGET_DEVICE_REMOVE_CANCELLED,
  0xcb3a4007, 0x46f0, 0x11d0, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f);
DEFINE_GUID(GUID_TARGET_DEVICE_REMOVE_COMPLETE,
  0xcb3a4008, 0x46f0, 0x11d0, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f);
DEFINE_GUID(GUID_PNP_CUSTOM_NOTIFICATION,
  0xaca73f8e, 0x8d23, 0x11d1, 0xac, 0x7d, 0x00, 0x00, 0xf8, 0x75, 0x71, 0xd0);
DEFINE_GUID(GUID_PNP_POWER_NOTIFICATION,
  0xc2cf0660, 0xeb7a, 0x11d1, 0xbd, 0x7f, 0x00, 0x00, 0xf8, 0x75, 0x71, 0xd0);

DEFINE_GUID(GUID_BUS_INTERFACE_STANDARD,
  0x496b8280, 0x6f25, 0x11d0, 0xbe, 0xaf, 0x08, 0x00, 0x2b, 0xe2, 0x09, 0x2f);
DEFINE_GUID(GUID_PCI_BUS_INTERFACE_STANDARD,
  0x496b8281, 0x6f25, 0x11d0, 0xbe, 0xaf, 0x08, 0x00, 0x2b, 0xe2, 0x09, 0x2f);
DEFINE_GUID(GUID_AGP_TARGET_BUS_INTERFACE_STANDARD,
  0xb15cfce8, 0x06d1, 0x4d37, 0x9d, 0x4c, 0xbe, 0xdd, 0xe0, 0xc2, 0xa6, 0xff);
DEFINE_GUID(GUID_ARBITER_INTERFACE_STANDARD,
  0xe644f185, 0x8c0e, 0x11d0, 0xbe, 0xcf, 0x08, 0x00, 0x2b, 0xe2, 0x09, 0x2f);
DEFINE_GUID(GUID_TRANSLATOR_INTERFACE_STANDARD,
  0x6c154a92, 0xaacf, 0x11d0, 0x8d, 0x2a, 0x00, 0xa0, 0xc9, 0x06, 0xb2, 0x44);
DEFINE_GUID(GUID_ACPI_INTERFACE_STANDARD,
  0xb091a08a, 0xba97, 0x11d0, 0xbd, 0x14, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a);
DEFINE_GUID(GUID_INT_ROUTE_INTERFACE_STANDARD,
  0x70941bf4, 0x0073, 0x11d1, 0xa0, 0x9e, 0x00, 0xc0, 0x4f, 0xc3, 0x40, 0xb1);
DEFINE_GUID(GUID_PCMCIA_BUS_INTERFACE_STANDARD,
  0x76173af0, 0xc504, 0x11d1, 0x94, 0x7f, 0x00, 0xc0, 0x4f, 0xb9, 0x60, 0xee);
DEFINE_GUID(GUID_ACPI_REGS_INTERFACE_STANDARD,
  0x06141966, 0x7245, 0x6369, 0x46, 0x2e, 0x4e, 0x65, 0x6c, 0x73, 0x6f, 0x6e);
DEFINE_GUID(GUID_LEGACY_DEVICE_DETECTION_STANDARD,
  0x50feb0de, 0x596a, 0x11d2, 0xa5, 0xb8, 0x00, 0x00, 0xf8, 0x1a, 0x46, 0x19);
DEFINE_GUID(GUID_PCI_DEVICE_PRESENT_INTERFACE,
  0xd1b82c26, 0xbf49, 0x45ef, 0xb2, 0x16, 0x71, 0xcb, 0xd7, 0x88, 0x9b, 0x57);
DEFINE_GUID(GUID_MF_ENUMERATION_INTERFACE,
  0xaeb895f0, 0x5586, 0x11d1, 0x8d, 0x84, 0x00, 0xa0, 0xc9, 0x06, 0xb2, 0x44);
DEFINE_GUID(GUID_ACPI_CMOS_INTERFACE_STANDARD,
  0x3a8d0384, 0x6505, 0x40ca, 0xbc, 0x39, 0x56, 0xc1, 0x5f, 0x8c, 0x5f, 0xed);
DEFINE_GUID(GUID_ACPI_PORT_RANGES_INTERFACE_STANDARD,
  0xf14f609b, 0xcbbd, 0x4957, 0xa6, 0x74, 0xbc, 0x00, 0x21, 0x3f, 0x1c, 0x97);
DEFINE_GUID(GUID_PNP_LOCATION_INTERFACE,
  0x70211b0e, 0x0afb, 0x47db, 0xaf, 0xc1, 0x41, 0x0b, 0xf8, 0x42, 0x49, 0x7a);
DEFINE_GUID(GUID_D3COLD_SUPPORT_INTERFACE,
  0xb38290e5, 0x3cd0, 0x4f9d, 0x99, 0x37, 0xf5, 0xfe, 0x2b, 0x44, 0xd4, 0x7a);
DEFINE_GUID(GUID_REENUMERATE_SELF_INTERFACE_STANDARD,
  0x2aeb0243, 0x6a6e, 0x486b, 0x82, 0xfc, 0xd8, 0x15, 0xf6, 0xb9, 0x70, 0x06);

DEFINE_GUID(GUID_BUS_TYPE_INTERNAL,
  0x1530ea73, 0x086b, 0x11d1, 0xa0, 0x9f, 0x00, 0xc0, 0x4f, 0xc3, 0x40, 0xb1);
DEFINE_GUID(GUID_BUS_TYPE_PCMCIA,
  0x09343630, 0xaf9f, 0x11d0, 0x92, 0xE9, 0x00, 0x00, 0xf8, 0x1e, 0x1b, 0x30);
DEFINE_GUID(GUID_BUS_TYPE_PCI,
  0xc8ebdfb0, 0xb510, 0x11d0, 0x80, 0xe5, 0x00, 0xa0, 0xc9, 0x25, 0x42, 0xe3);
DEFINE_GUID(GUID_BUS_TYPE_ISAPNP,
  0xe676f854, 0xd87d, 0x11d0, 0x92, 0xb2, 0x00, 0xa0, 0xc9, 0x05, 0x5f, 0xc5);
DEFINE_GUID(GUID_BUS_TYPE_EISA,
  0xddc35509, 0xf3fc, 0x11d0, 0xa5, 0x37, 0x00, 0x00, 0xf8, 0x75, 0x3e, 0xd1);
DEFINE_GUID(GUID_BUS_TYPE_MCA,
  0x1c75997a, 0xdc33, 0x11d0, 0x92, 0xb2, 0x00, 0xa0, 0xc9, 0x05, 0x5f, 0xc5);
DEFINE_GUID(GUID_BUS_TYPE_LPTENUM,
  0xc4ca1000, 0x2ddc, 0x11d5, 0xa1, 0x7a, 0x00, 0xc0, 0x4f, 0x60, 0x52, 0x4d);
DEFINE_GUID(GUID_BUS_TYPE_USBPRINT,
  0x441ee000, 0x4342, 0x11d5, 0xa1, 0x84, 0x00, 0xc0, 0x4f, 0x60, 0x52, 0x4d);
DEFINE_GUID(GUID_BUS_TYPE_DOT4PRT,
  0x441ee001, 0x4342, 0x11d5, 0xa1, 0x84, 0x00, 0xc0, 0x4f, 0x60, 0x52, 0x4d);
DEFINE_GUID(GUID_BUS_TYPE_SERENUM,
  0x77114a87, 0x8944, 0x11d1, 0xbd, 0x90, 0x00, 0xa0, 0xc9, 0x06, 0xbe, 0x2d);
DEFINE_GUID(GUID_BUS_TYPE_USB,
  0x9d7debbc, 0xc85d, 0x11d1, 0x9e, 0xb4, 0x00, 0x60, 0x08, 0xc3, 0xa1, 0x9a);
DEFINE_GUID(GUID_BUS_TYPE_1394,
  0xf74e73eb, 0x9ac5, 0x45eb, 0xbe, 0x4d, 0x77, 0x2c, 0xc7, 0x1d, 0xdf, 0xb3);
DEFINE_GUID(GUID_BUS_TYPE_HID,
  0xeeaf37d0, 0x1963, 0x47c4, 0xaa, 0x48, 0x72, 0x47, 0x6d, 0xb7, 0xcf, 0x49);
DEFINE_GUID(GUID_BUS_TYPE_AVC,
  0xc06ff265, 0xae09, 0x48f0, 0x81, 0x2c, 0x16, 0x75, 0x3d, 0x7c, 0xba, 0x83);
DEFINE_GUID(GUID_BUS_TYPE_IRDA,
  0x7ae17dc1, 0xc944, 0x44d6, 0x88, 0x1f, 0x4c, 0x2e, 0x61, 0x05, 0x3b, 0xc1);
DEFINE_GUID(GUID_BUS_TYPE_SD,
  0xe700cc04, 0x4036, 0x4e89, 0x95, 0x79, 0x89, 0xeb, 0xf4, 0x5f, 0x00, 0xcd);

DEFINE_GUID(GUID_POWER_DEVICE_ENABLE,
  0x827c0a6fL, 0xfeb0, 0x11d0, 0xbd, 0x26, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a);
DEFINE_GUID(GUID_POWER_DEVICE_TIMEOUTS,
  0xa45da735L, 0xfeb0, 0x11d0, 0xbd, 0x26, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a);
DEFINE_GUID(GUID_POWER_DEVICE_WAKE_ENABLE,
  0xa9546a82L, 0xfeb0, 0x11d0, 0xbd, 0x26, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a);

#endif /* __WDMGUID_H */
