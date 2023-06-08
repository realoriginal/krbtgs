/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Downloads an arbitrary file to TeamServer. The
 * file can be found at `View` -> `Downloads`.
 *
!*/
VOID BeaconDownload( _In_ PVOID Buffer, _In_ ULONG Length, _In_ PCHAR FileName );
