/*++

Copyright (c) 1990  Microsoft Corporation

Module Name:

    service.c

Abstract:

    ACPI Embedded Controller Driver

Author:

    Ken Reneris

Environment:

Notes:


Revision History:

--*/

#include "ecp.h"


VOID
AcpiEcServiceDevice (
    IN PECDATA          EcData
    )
/*++

Routine Description:

    This routine starts or continues servicing the device's work queue

Arguments:

    EcData  - Pointer to embedded controller to service.

Return Value:

    None

--*/
{
    KIRQL               OldIrql;

    //
    // Even though the device is unloaded, there might still be a
    // service call which occurs until the timer is canceled
    //

    if (EcData->DeviceState > EC_DEVICE_UNLOAD_PENDING) {
        return;
    }

    //
    // Acquire device lock and signal function was entered
    //

    KeAcquireSpinLock (&EcData->Lock, &OldIrql);
    EcData->InServiceLoop = TRUE;

    //
    // If not already in service, enter InService
    //

    if (!EcData->InService) {
        EcData->InService = TRUE;

        //
        // Disable the device's interrupt
        //

        if (EcData->InterruptEnabled) {
            EcData->InterruptEnabled = FALSE;

            //
            // Call ACPI to disable the device's interrupt
            //
            AcpiInterfaces.GpeDisableEvent (AcpiInterfaces.Context,
                                            EcData->GpeVectorObject);
        }

        //
        // While service invocation pending, loop
        //

        while (EcData->InServiceLoop) {
            EcData->InServiceLoop = FALSE;

            //
            // Determine service action
            //

            KeReleaseSpinLock (&EcData->Lock, OldIrql);

            //
            // Dispatch service handler
            //

            AcpiEcServiceIoLoop (EcData);

            //
            // Loop and re-service
            //

            KeAcquireSpinLock (&EcData->Lock, &OldIrql);

        }

        //
        // No longer in service loop
        //

        EcData->InService = FALSE;

        //
        // If unload is pending, check to see if the device can be unloaded now
        //

        if (EcData->DeviceState != EC_DEVICE_WORKING) {
            AcpiEcUnloadPending (EcData);
        }

        //
        // Enable the device's interrupt
        //

        if (!EcData->InterruptEnabled) {
            EcData->InterruptEnabled = TRUE;

            //
            // Call ACPI to enable the device's interrupt
            //
            AcpiInterfaces.GpeEnableEvent (AcpiInterfaces.Context,
                                            EcData->GpeVectorObject);
        }
    }

    KeReleaseSpinLock (&EcData->Lock, OldIrql);
}

VOID
AcpiEcServiceIoLoop (
    IN PECDATA      EcData
    )
/*++

Routine Description:

    Main embedded controller device service loop.  Services EC events,
    and processes IO queue.  Terminate when the controller is busy (e.g.,
    wait for interrupt to continue) or when all servicing has been completed.

    N.B. Caller must be the owner of the device InService flag

Arguments:

    EcData  - Pointer to embedded controller to service.

Return Value:

    none

--*/
{
    PIO_STACK_LOCATION  IrpSp;
    PLIST_ENTRY         Link;
    PIRP                Irp;
    PUCHAR              WritePort;
    UCHAR               WriteData;
    UCHAR               Status;
    UCHAR               Data;
    BOOLEAN             EcBusy;
    BOOLEAN             BurstEnabled;
    BOOLEAN             ProcessQuery;
    ULONG               NoWorkStall;
    ULONG               StallAccumulator;
    PULONG              Timeout;
    KIRQL               OldIrql;
    LIST_ENTRY          CompleteQueue;
    ULONG               i, j;


    EcBusy = TRUE;
    Timeout = NULL;
    WritePort = NULL;
    NoWorkStall = 0;
    BurstEnabled = FALSE;
    ProcessQuery = FALSE;
    StallAccumulator = 0;

    InitializeListHead (&CompleteQueue);

    //
    // Loop while busy
    //

    for (; ;) {

        //
        // If there's outgoing data write it, issue the device required
        // stall and indicate work is being done (clear noworkstall)
        //

        if (WritePort) {
            EcPrint(EC_IO, ("AcpiEcServiceIO: Write = %x at %x\n", WriteData, WritePort));
            WRITE_PORT_UCHAR (WritePort, WriteData);
            KeStallExecutionProcessor (1);
            StallAccumulator += 1;
            WritePort = NULL;
            NoWorkStall = 0;        // work was done
        }

        //
        // If work was done, clear pending timeout condition if it exists to
        // continue servicing the device
        //

        if (NoWorkStall == 0  &&  Timeout) {
            Timeout = NULL;
            EcBusy = TRUE;
        }

        //
        // If NoWorkStall is non-zero, then no work was performed.  Determine
        // if the type of delay to issue while waiting (spinning) for the device
        //

        if (NoWorkStall) {

            //
            // No work was done the last time around.
            // If its time to timeout, exit the service loop.
            //

            if (Timeout) {
                break;
            }

            //
            // If device is idle, setup as if a timeout is occuring.  This
            // will acquire the device lock, clear the gpe sts bit and terminate
            // the service loop (or if the device is now busy, continue)
            //

            if (!EcBusy) {

                if (Status & EC_BURST) {
                    //
                    // Before exiting, clear burst mode for embedded controller.
                    // Has no response, no need to wait for EC to read it.
                    //

                    EcPrint (EC_IO, ("AcpiEcServiceIO: Clear Burst mode - Write = %x at %x\n", EC_CANCEL_BURST, EcData->CommandPort));
                    WRITE_PORT_UCHAR (EcData->CommandPort, EC_CANCEL_BURST);
                    Timeout = &EcData->BurstComplete;

                } else {

                    Timeout = &i;
                }

            } else {

                //
                // Interject stalls while spinning on device
                //

                StallAccumulator += NoWorkStall;
                KeStallExecutionProcessor (NoWorkStall);

                //
                // If wait is over the limit, prepare for a timeout.
                //

                if (!(Status & EC_BURST)) {
                    if (NoWorkStall >= EcData->MaxNonBurstStall) {
                        Timeout = &EcData->NonBurstTimeout;
                    }
                } else {
                    if (NoWorkStall >= EcData->MaxBurstStall) {
                        Timeout = &EcData->BurstTimeout;
                    }
                }
            }

            if (Timeout) {

                //
                // Over time limit, clear the GPE status bit
                //
                AcpiInterfaces.GpeClearStatus (AcpiInterfaces.Context,
                                                EcData->GpeVectorObject);
            }
        }


        //
        // Increase stall time and indicate no work was done
        //

        NoWorkStall += 1;

        //
        // Check Status
        //

        Status = READ_PORT_UCHAR (EcData->StatusPort);
        EcPrint(EC_IO, ("AcpiEcServiceIO: Status Read = %x at %x\n", Status, EcData->StatusPort));

        //
        // Keep bursts dropped by the EC stat
        //

        if (BurstEnabled && !(Status & EC_BURST)) {
            EcData->BurstAborted += 1;
            BurstEnabled = FALSE;
            Status |= EC_BURST;     // move one char
        }

        //
        // If Embedded controller has data for us, process it
        //

        if (Status & EC_OUTPUT_FULL) {

            Data = READ_PORT_UCHAR (EcData->DataPort);
            EcPrint(EC_IO, ("AcpiEcServiceIO: Data Read = %x at %x\n", Data, EcData->DataPort));

            switch (EcData->IoState) {

                case EC_IO_READ_QUERY:
                    //
                    // Response to a read query.  Get the query value and set it
                    //

                    EcPrint(EC_NOTE, ("AcpiEcServiceIO: Query %x\n", Data));

                    if (Data) {
                        //
                        // If not set, set pending bit
                        //

                        KeAcquireSpinLock (&EcData->Lock, &OldIrql);

                        i = Data / BITS_PER_ULONG;
                        j = 1 << (Data % BITS_PER_ULONG);
                        if (!(EcData->QuerySet[i] & j)) {
                            EcData->QuerySet[i] |= j;

                            //
                            // Queue the query or vector operation
                            //

                            if (EcData->QueryType[i] & j) {
                                //
                                // This is a vector, put it in the vector pending list
                                //

                                Data = EcData->QueryMap[Data];
                                EcData->VectorTable[Data].Next = EcData->VectorHead;
                                EcData->VectorHead = Data;

                            } else {
                                //
                                // This is a query, put in in the query pending list
                                //

                                EcData->QueryMap[Data] = EcData->QueryHead;
                                EcData->QueryHead = Data;
                            }
                        }

                        KeReleaseSpinLock (&EcData->Lock, OldIrql);
                        ProcessQuery = TRUE;
                    }

                    EcData->IoState = EC_IO_NONE;
                    break;

                case EC_IO_READ_BYTE:
                    //
                    // Read transfer. Read the data byte
                    //

                    *EcData->IoBuffer = Data;
                    EcData->IoState   = EC_IO_NEXT_BYTE;
                    break;

                case EC_IO_BURST_ACK:
                    //
                    // Burst ACK byte
                    //

                    EcData->IoState      = EcData->IoBurstState;
                    EcData->IoBurstState = EC_IO_UNKNOWN;
                    EcData->TotalBursts += 1;
                    BurstEnabled = TRUE;
                    break;

                default:
//                    EcPrint(EC_ERROR,
//                            ("AcpiEcService: Spurious data received State = %x, Data = %x\n",
//                             EcData->IoState, Data)
//                          );

                    EcData->Errors += 1;
                    break;
            }

            NoWorkStall = 0;
            continue;
        }

        if (Status & EC_INPUT_FULL) {
            //
            // The embedded controllers input buffer is full, wait
            //

            continue;
        }

        //
        // Embedded controller is ready to receive data, see if anything
        // is already being sent
        //

        switch (EcData->IoState) {

            case EC_IO_NEXT_BYTE:
                //
                // Data transfer.
                //

                if (EcData->IoRemain) {

                    if (!(Status & EC_BURST)) {
                        //
                        // Not in burst mode.  Write burst mode command
                        //

                        EcData->IoState      = EC_IO_BURST_ACK;
                        EcData->IoBurstState = EC_IO_NEXT_BYTE;

                        WritePort = EcData->CommandPort;
                        WriteData = EC_BURST_TRANSFER;

                    } else {
                        //
                        // Send command to transfer next byte
                        //

                        EcData->IoBuffer  += 1;
                        EcData->IoAddress += 1;
                        EcData->IoRemain  -= 1;
                        EcData->IoState   = EC_IO_SEND_ADDRESS;

                        WritePort = EcData->CommandPort;
                        WriteData = EcData->IoTransferMode;
                    }

                } else {
                    //
                    // Transfer complete
                    //

                    EcData->IoState  = EC_IO_NONE;
                    EcData->IoRemain = 0;

                    Irp = EcData->DeviceObject->CurrentIrp;
                    EcData->DeviceObject->CurrentIrp = NULL;

                    Irp->IoStatus.Status = STATUS_SUCCESS;
                    Irp->IoStatus.Information = EcData->IoLength;

                    InsertTailList (&CompleteQueue, &Irp->Tail.Overlay.ListEntry);
                }
                break;

            case EC_IO_SEND_ADDRESS:
                //
                // Send address of transfer request
                //

                WritePort = EcData->DataPort;
                WriteData = EcData->IoAddress;


                //
                // Wait or send data byte next
                //

                if (EcData->IoTransferMode == EC_READ_BYTE) {
                    EcData->IoState = EC_IO_READ_BYTE;
                } else {
                    EcData->IoState = EC_IO_WRITE_BYTE;
                }
                break;

            case EC_IO_WRITE_BYTE:
                //
                // Write transfer - write the data byte
                //

                EcData->IoState = EC_IO_NEXT_BYTE;
                WritePort = EcData->DataPort;
                WriteData = *EcData->IoBuffer;
                break;
        }

        //
        // If something to write, loop and handle it
        //

        if (WritePort) {
            continue;
        }

        //
        // If state is NONE, then nothing is pending see what should be
        // initiated
        //

        if (EcData->IoState == EC_IO_NONE) {

            if (Status & EC_QEVT_PENDING) {

                //
                // Embedded Controller has some sort of event pending
                //

                EcData->IoState = EC_IO_READ_QUERY;
                WritePort = EcData->CommandPort;
                WriteData = EC_QUERY_EVENT;

            } else {

                //
                // Get next tranfer from IO queue
                //

                Link = ExInterlockedRemoveHeadList (&EcData->WorkQueue, &EcData->Lock);

                //
                // If there's a transfer initiate it
                //

                if (Link) {

//                    EcPrint(EC_HANDLER, ("AcpiEcServiceIO: Got next work item %x\n", Link));

                    Irp = CONTAINING_RECORD (
                                Link,
                                IRP,
                                Tail.Overlay.ListEntry
                                );

                    EcData->DeviceObject->CurrentIrp = Irp;

                    IrpSp = IoGetCurrentIrpStackLocation(Irp);
                    EcData->IoBuffer  = Irp->AssociatedIrp.SystemBuffer;
                    EcData->IoAddress = (UCHAR) IrpSp->Parameters.Read.ByteOffset.LowPart;
                    EcData->IoLength  = (UCHAR) IrpSp->Parameters.Read.Length;
                    EcData->IoTransferMode =
                        IrpSp->MajorFunction == IRP_MJ_READ ? EC_READ_BYTE : EC_WRITE_BYTE;

                    //
                    // Set it up via EC_IO_NEXT_BYTE and back up one byte
                    //

                    EcData->IoBuffer  -= 1;
                    EcData->IoAddress -= 1;
                    EcData->IoRemain  = EcData->IoLength;
                    EcData->IoState   = EC_IO_NEXT_BYTE;
                    NoWorkStall = 0;

                } else {

                    //
                    // Nothing but nothing to do.
                    //

                    EcBusy = FALSE;
                }
            }
        }
    }

    //
    // Keep stat as to why service loop terminated
    //

    *Timeout += 1;

    //
    // Track maximum service loop stall accumulator
    //

    if (StallAccumulator > EcData->MaxServiceLoop) {
        EcData->MaxServiceLoop = StallAccumulator;
    }

    //
    // Complete processed io requests
    //

    while (!IsListEmpty(&CompleteQueue)) {
        Link = RemoveHeadList(&CompleteQueue);
        Irp = CONTAINING_RECORD (
                    Link,
                    IRP,
                    Tail.Overlay.ListEntry
                    );

        EcPrint(EC_IO, ("AcpiEcServiceIO: IOComplete: Irp=%Lx\n", Irp));

        IoCompleteRequest (Irp, IO_NO_INCREMENT);
    }

    //
    // If queries occured, dispatch them
    //

    if (ProcessQuery) {
        AcpiEcDispatchQueries (EcData);
    }
}


