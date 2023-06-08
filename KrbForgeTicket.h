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
 * Forges a ticket to the DC using the specified
 * encryption algorithm. Downloads the Key and
 * APREQ to a file on TeamServer.
 *
!*/
BOOL KrbForgeTicket( _In_ PWCHAR ServicePrincipalName, _In_ ULONG EncryptionType, _In_ PCHAR ApReqFileName, _In_ PCHAR KeyFileName );
