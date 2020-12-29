/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/cc/pin.c
 * PURPOSE:         Implements cache managers pinning interface
 *
 * PROGRAMMERS:     ?
                    Pierre Schweitzer (pierre@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern NPAGED_LOOKASIDE_LIST iBcbLookasideList;

/* Counters:
 * - Number of calls to CcMapData that could wait
 * - Number of calls to CcMapData that couldn't wait
 * - Number of calls to CcPinRead that could wait
 * - Number of calls to CcPinRead that couldn't wait
 * - Number of calls to CcPinMappedDataCount
 */
ULONG CcMapDataWait = 0;
ULONG CcMapDataNoWait = 0;
ULONG CcPinReadWait = 0;
ULONG CcPinReadNoWait = 0;
ULONG CcPinMappedDataCount = 0;

/* FUNCTIONS *****************************************************************/

static
PINTERNAL_BCB
NTAPI
CcpFindBcb(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Pinned)
{
    PINTERNAL_BCB Bcb;
    BOOLEAN Found = FALSE;
    PLIST_ENTRY NextEntry;

    for (NextEntry = SharedCacheMap->BcbList.Flink;
         NextEntry != &SharedCacheMap->BcbList;
         NextEntry = NextEntry->Flink)
    {
        Bcb = CONTAINING_RECORD(NextEntry, INTERNAL_BCB, BcbEntry);

        if (Bcb->PFCB.MappedFileOffset.QuadPart <= FileOffset->QuadPart &&
            (Bcb->PFCB.MappedFileOffset.QuadPart + Bcb->PFCB.MappedLength) >=
            (FileOffset->QuadPart + Length))
        {
            if ((Pinned && Bcb->PinCount > 0) || (!Pinned && Bcb->PinCount == 0))
            {
                Found = TRUE;
                break;
            }
        }
    }

    return (Found ? Bcb : NULL);
}

static
VOID
CcpDereferenceBcb(
    IN PINTERNAL_BCB Bcb)
{
    ULONG RefCount;
    KIRQL OldIrql;

    PROS_SHARED_CACHE_MAP SharedCacheMap = Bcb->SharedCacheMap;

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    RefCount = --Bcb->RefCount;
    if (RefCount == 0)
    {
        RemoveEntryList(&Bcb->BcbEntry);
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        ASSERT(Bcb->PinCount == 0);

        MmUnmapViewInSystemSpace(Bcb->SystemMap);

        ExDeleteResourceLite(&Bcb->Lock);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, Bcb);
    }
    else
    {
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }
}

static
PVOID
CcpGetAppropriateBcb(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG PinFlags,
    IN BOOLEAN ToPin)
{
    KIRQL OldIrql;
    BOOLEAN Result;
    PINTERNAL_BCB iBcb, DupBcb;
    NTSTATUS Status;
    SIZE_T ViewSize;

    iBcb = ExAllocateFromNPagedLookasideList(&iBcbLookasideList);

    RtlZeroMemory(iBcb, sizeof(*iBcb));
    iBcb->PFCB.NodeTypeCode = 0xDE45; /* Undocumented (CAPTIVE_PUBLIC_BCB_NODETYPECODE) */
    iBcb->PFCB.NodeByteSize = sizeof(PUBLIC_BCB);
    iBcb->PFCB.MappedLength = Length;
    iBcb->PFCB.MappedFileOffset = *FileOffset;
    iBcb->PinCount = 0;
    iBcb->RefCount = 1;
    iBcb->SharedCacheMap = SharedCacheMap;

    iBcb->SystemMap = NULL;
    ViewSize = Length;
    Status = MmMapViewInSystemSpaceEx(SharedCacheMap->Section, &iBcb->SystemMap, &ViewSize, &iBcb->PFCB.MappedFileOffset);
    if (!NT_SUCCESS(Status))
    {
        ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);
        ExRaiseStatus(Status);
    }
    Status = RtlSIZETToULong(ViewSize, &iBcb->PFCB.MappedLength);
    if (!NT_SUCCESS(Status))
    {
        MmUnmapViewInSystemSpace(iBcb->SystemMap);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);
        ExRaiseStatus(Status);
    }
    ExInitializeResourceLite(&iBcb->Lock);

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);

    /* Check if we raced with another BCB creation */
    DupBcb = CcpFindBcb(SharedCacheMap, FileOffset, Length, ToPin);
    /* Yes, and we've lost */
    if (DupBcb != NULL)
    {
        /* We will return that BCB */
        ++DupBcb->RefCount;
        Result = TRUE;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (ToPin)
        {
            if (BooleanFlagOn(PinFlags, PIN_EXCLUSIVE))
            {
                Result = ExAcquireResourceExclusiveLite(&iBcb->Lock, BooleanFlagOn(PinFlags, PIN_WAIT));
            }
            else
            {
                Result = ExAcquireSharedStarveExclusive(&iBcb->Lock, BooleanFlagOn(PinFlags, PIN_WAIT));
            }

            if (Result)
            {
                DupBcb->PinCount++;
            }
            else
            {
                CcpDereferenceBcb(DupBcb);
                DupBcb = NULL;
            }
        }

        if (DupBcb != NULL)
        {
            /* Delete the loser */
            ExDeleteResourceLite(&iBcb->Lock);
            Status = MmUnmapViewInSystemSpace(iBcb->SystemMap);
            /* Unmapping must succeed in this case */
            if (!NT_SUCCESS(Status))
                KeBugCheck(CACHE_MANAGER);

            ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);
        }

        /* Return the winner */
        iBcb = DupBcb;
    }
    /* Nope, insert ourselves */
    else
    {
        if (ToPin)
        {
            iBcb->PinCount++;

            if (BooleanFlagOn(PinFlags, PIN_EXCLUSIVE))
            {
                Result = ExAcquireResourceExclusiveLite(&iBcb->Lock, BooleanFlagOn(PinFlags, PIN_WAIT));
            }
            else
            {
                Result = ExAcquireSharedStarveExclusive(&iBcb->Lock, BooleanFlagOn(PinFlags, PIN_WAIT));
            }

            ASSERT(Result);
        }

        InsertTailList(&SharedCacheMap->BcbList, &iBcb->BcbEntry);
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }

    return iBcb;
}

static
BOOLEAN
CcpPinData(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG Flags,
    OUT	PVOID * Bcb,
    OUT	PVOID * Buffer)
{
    PINTERNAL_BCB NewBcb;
    KIRQL OldIrql;
    LONGLONG MapStart;
    LONGLONG MapEnd;
    NTSTATUS Status;
    ULONG BcbOffset;

    /* Validate input */
    MapStart = FileOffset->QuadPart;
    Status = RtlLongLongAdd(MapStart, Length, &MapEnd);
    if (!NT_SUCCESS(Status))
        ExRaiseStatus(Status);

    /* Ensure the underlying memory is resident */
    while (MapStart < MapEnd)
    {
        BOOLEAN Result;
        PROS_VACB Vacb;
        ULONG VacbOffset = (ULONG)(MapStart % VACB_MAPPING_GRANULARITY);
        ULONG VacbLength = min(MapEnd - MapStart, VACB_MAPPING_GRANULARITY - VacbOffset);

        Status = CcRosGetVacb(SharedCacheMap, MapStart, &Vacb);
        if (!NT_SUCCESS(Status))
            ExRaiseStatus(Status);

        _SEH2_TRY
        {
            Result = CcRosEnsureVacbResident(Vacb,
                                             BooleanFlagOn(Flags, PIN_WAIT),
                                             BooleanFlagOn(Flags, PIN_NO_READ),
                                             VacbOffset, VacbLength);
        }
        _SEH2_FINALLY
        {
            CcRosReleaseVacb(SharedCacheMap, Vacb, TRUE, FALSE, FALSE);
        }
        _SEH2_END;

        if (!Result)
            return FALSE;

        MapStart += VacbLength;
    }

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    NewBcb = CcpFindBcb(SharedCacheMap, FileOffset, Length, TRUE);
    if (NewBcb != NULL)
    {
        BOOLEAN Result;

        ++NewBcb->RefCount;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (BooleanFlagOn(Flags, PIN_EXCLUSIVE))
            Result = ExAcquireResourceExclusiveLite(&NewBcb->Lock, BooleanFlagOn(Flags, PIN_WAIT));
        else
            Result = ExAcquireSharedStarveExclusive(&NewBcb->Lock, BooleanFlagOn(Flags, PIN_WAIT));

        if (!Result)
        {
            CcpDereferenceBcb(NewBcb);
            return FALSE;
        }

        NewBcb->PinCount++;
    }
    else
    {
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (BooleanFlagOn(Flags, PIN_IF_BCB))
        {
            return FALSE;
        }

        NewBcb = CcpGetAppropriateBcb(SharedCacheMap, FileOffset, Length, Flags, TRUE);
        if (NewBcb == NULL)
        {
            return FALSE;
        }
    }

    *Bcb = NewBcb;
    ASSERT(FileOffset->QuadPart >= NewBcb->PFCB.MappedFileOffset.QuadPart);
    ASSERT((FileOffset->QuadPart - NewBcb->PFCB.MappedFileOffset.QuadPart) < MAXULONG);
    BcbOffset = FileOffset->QuadPart - NewBcb->PFCB.MappedFileOffset.QuadPart;
    *Buffer = Add2Ptr(NewBcb->SystemMap, BcbOffset);
    return TRUE;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
CcMapData (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG Flags,
    OUT PVOID *pBcb,
    OUT PVOID *pBuffer)
{
    KIRQL OldIrql;
    PINTERNAL_BCB iBcb;
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    NTSTATUS Status;
    LONGLONG MapStart;
    LONGLONG MapEnd;
    ULONG BcbOffset;

    CCTRACE(CC_API_DEBUG, "CcMapData(FileObject 0x%p, FileOffset 0x%I64x, Length %lu, Flags 0x%lx,"
           " pBcb 0x%p, pBuffer 0x%p)\n", FileObject, FileOffset->QuadPart,
           Length, Flags, pBcb, pBuffer);

    ASSERT(FileObject);
    ASSERT(FileObject->SectionObjectPointer);
    ASSERT(FileObject->SectionObjectPointer->SharedCacheMap);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    ASSERT(SharedCacheMap);

    /* Validate input */
    MapStart = FileOffset->QuadPart;
    Status = RtlLongLongAdd(MapStart, Length, &MapEnd);
    if (!NT_SUCCESS(Status))
        ExRaiseStatus(Status);

    if (Flags & MAP_WAIT)
    {
        ++CcMapDataWait;
    }
    else
    {
        ++CcMapDataNoWait;
    }

    /* Ensure the underlying VACBs is resident */
    while (MapStart < MapEnd)
    {
        BOOLEAN Result;
        PROS_VACB Vacb;
        ULONG VacbOffset = (ULONG)(MapStart % VACB_MAPPING_GRANULARITY);
        ULONG VacbLength = min(MapEnd - MapStart, VACB_MAPPING_GRANULARITY - VacbOffset);

        Status = CcRosGetVacb(SharedCacheMap, MapStart, &Vacb);
        if (!NT_SUCCESS(Status))
            ExRaiseStatus(Status);

        _SEH2_TRY
        {
            Result = CcRosEnsureVacbResident(Vacb,
                                             BooleanFlagOn(Flags, PIN_WAIT),
                                             BooleanFlagOn(Flags, PIN_NO_READ),
                                             VacbOffset, VacbLength);
        }
        _SEH2_FINALLY
        {
            CcRosReleaseVacb(SharedCacheMap, Vacb, TRUE, FALSE, FALSE);
        }
        _SEH2_END;

        if (!Result)
            return FALSE;

        MapStart += VacbLength;
    }

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    iBcb = CcpFindBcb(SharedCacheMap, FileOffset, Length, FALSE);

    if (iBcb == NULL)
    {
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        iBcb = CcpGetAppropriateBcb(SharedCacheMap, FileOffset, Length, 0, FALSE);
        if (iBcb == NULL)
        {
            CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
                SharedCacheMap->FileObject, FileOffset, Length, Flags);
            return FALSE;
        }
    }
    else
    {
        ++iBcb->RefCount;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }

    *pBcb = iBcb;
    ASSERT(FileOffset->QuadPart >= iBcb->PFCB.MappedFileOffset.QuadPart);
    ASSERT((FileOffset->QuadPart - iBcb->PFCB.MappedFileOffset.QuadPart) < MAXULONG);
    BcbOffset = FileOffset->QuadPart - iBcb->PFCB.MappedFileOffset.QuadPart;
    *pBuffer = Add2Ptr(iBcb->SystemMap, BcbOffset);

    CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> TRUE Bcb=%p, Buffer %p\n",
        FileObject, FileOffset, Length, Flags, *pBcb, *pBuffer);
    return TRUE;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPinMappedData (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	ULONG Flags,
    OUT	PVOID * Bcb)
{
    BOOLEAN Result;
    PVOID Buffer;
    PINTERNAL_BCB iBcb;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx\n",
        FileObject, FileOffset, Length, Flags);

    ASSERT(FileObject);
    ASSERT(FileObject->SectionObjectPointer);
    ASSERT(FileObject->SectionObjectPointer->SharedCacheMap);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    ASSERT(SharedCacheMap);
    if (!SharedCacheMap->PinAccess)
    {
        DPRINT1("FIXME: Pinning a file with no pin access!\n");
        return FALSE;
    }

    iBcb = *Bcb;

    ++CcPinMappedDataCount;

    Result = CcpPinData(SharedCacheMap, FileOffset, Length, Flags, Bcb, &Buffer);
    if (Result)
    {
        CcUnpinData(iBcb);
    }

    return Result;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPinRead (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	ULONG Flags,
    OUT	PVOID * Bcb,
    OUT	PVOID * Buffer)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "FileOffset=%p FileOffset=%p Length=%lu Flags=0x%lx\n",
        FileObject, FileOffset, Length, Flags);

    ASSERT(FileObject);
    ASSERT(FileObject->SectionObjectPointer);
    ASSERT(FileObject->SectionObjectPointer->SharedCacheMap);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    ASSERT(SharedCacheMap);
    if (!SharedCacheMap->PinAccess)
    {
        DPRINT1("FIXME: Pinning a file with no pin access!\n");
        return FALSE;
    }

    if (Flags & PIN_WAIT)
    {
        ++CcPinReadWait;
    }
    else
    {
        ++CcPinReadNoWait;
    }

    return CcpPinData(SharedCacheMap, FileOffset, Length, Flags, Bcb, Buffer);
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPreparePinWrite (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	BOOLEAN Zero,
    IN	ULONG Flags,
    OUT	PVOID * Bcb,
    OUT	PVOID * Buffer)
{
    CCTRACE(CC_API_DEBUG, "FileOffset=%p FileOffset=%p Length=%lu Zero=%d Flags=0x%lx\n",
        FileObject, FileOffset, Length, Zero, Flags);

    /*
     * FIXME: This is function is similar to CcPinRead, but doesn't
     * read the data if they're not present. Instead it should just
     * prepare the VACBs and zero them out if Zero != FALSE.
     *
     * For now calling CcPinRead is better than returning error or
     * just having UNIMPLEMENTED here.
     */
    if (!CcPinRead(FileObject, FileOffset, Length, Flags, Bcb, Buffer))
        return FALSE;

    if (!BooleanFlagOn(Flags, PIN_CALLER_TRACKS_DIRTY_DATA))
        CcSetDirtyPinnedData(Bcb, NULL);

    return TRUE;
}

/*
 * @implemented
 */
VOID NTAPI
CcSetDirtyPinnedData (
    IN PVOID Bcb,
    IN PLARGE_INTEGER Lsn)
{
    PINTERNAL_BCB iBcb = Bcb;
    LONGLONG MapStart = iBcb->PFCB.MappedFileOffset.QuadPart;
    LONGLONG MapEnd = MapStart + iBcb->PFCB.MappedLength;

    CCTRACE(CC_API_DEBUG, "Bcb=%p Lsn=%p\n",
        Bcb, Lsn);

    /* Tell Mm */
    MmMakePagesDirty(NULL, iBcb->SystemMap, iBcb->PFCB.MappedLength);

    /* Find all the VACBs and mark them dirty */
    while (MapStart < MapEnd)
    {
        PROS_VACB Vacb;
        NTSTATUS Status = CcRosGetVacb(iBcb->SharedCacheMap, MapStart, &Vacb);

        if (NT_SUCCESS(Status))
            CcRosReleaseVacb(iBcb->SharedCacheMap, Vacb, TRUE, TRUE, FALSE);
        MapStart += VACB_MAPPING_GRANULARITY;
    }
}


/*
 * @implemented
 */
VOID NTAPI
CcUnpinData (
    IN PVOID Bcb)
{
    CCTRACE(CC_API_DEBUG, "Bcb=%p\n", Bcb);

    CcUnpinDataForThread(Bcb, (ERESOURCE_THREAD)PsGetCurrentThread());
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcUnpinDataForThread (
    IN	PVOID Bcb,
    IN	ERESOURCE_THREAD ResourceThreadId)
{
    PINTERNAL_BCB iBcb = Bcb;

    CCTRACE(CC_API_DEBUG, "Bcb=%p ResourceThreadId=%lu\n", Bcb, ResourceThreadId);

    if (iBcb->PinCount != 0)
    {
        ExReleaseResourceForThreadLite(&iBcb->Lock, ResourceThreadId);
        iBcb->PinCount--;
    }

    CcpDereferenceBcb(iBcb);
}

/*
 * @implemented
 */
VOID
NTAPI
CcRepinBcb (
    IN	PVOID Bcb)
{
    PINTERNAL_BCB iBcb = Bcb;

    CCTRACE(CC_API_DEBUG, "Bcb=%p\n", Bcb);

    iBcb->RefCount++;
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcUnpinRepinnedBcb (
    IN	PVOID Bcb,
    IN	BOOLEAN WriteThrough,
    IN	PIO_STATUS_BLOCK IoStatus)
{
    PINTERNAL_BCB iBcb = Bcb;
    KIRQL OldIrql;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "Bcb=%p WriteThrough=%d\n", Bcb, WriteThrough);

    SharedCacheMap = iBcb->SharedCacheMap;
    IoStatus->Status = STATUS_SUCCESS;

    if (WriteThrough)
    {
        CcFlushCache(iBcb->SharedCacheMap->FileObject->SectionObjectPointer,
                     &iBcb->PFCB.MappedFileOffset,
                     iBcb->PFCB.MappedLength,
                     IoStatus);
    }
    else
    {
        IoStatus->Status = STATUS_SUCCESS;
        IoStatus->Information = 0;
    }

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    if (--iBcb->RefCount == 0)
    {
        NTSTATUS Status;

        RemoveEntryList(&iBcb->BcbEntry);
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (iBcb->PinCount != 0)
        {
            ExReleaseResourceLite(&iBcb->Lock);
            iBcb->PinCount--;
            ASSERT(iBcb->PinCount == 0);
        }

        /* Unmapping must succeed */
        Status = MmUnmapViewInSystemSpace(iBcb->SystemMap);
        if (!NT_SUCCESS(Status))
            KeBugCheck(CACHE_MANAGER);

        ExDeleteResourceLite(&iBcb->Lock);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);
    }
    else
    {
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }
}
