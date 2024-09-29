// (C) Copyright Gert-Jan de Vos and Jan Wilmans 2013.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "Win32/Win32Lib.h"
#include "CobaltFusion/stringbuilder.h"
#include "DebugViewppLib/EtwReader.h"
#include "DebugViewppLib/LineBuffer.h"
#include <array>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <initguid.h>
#include <windows.h>
#include <evntprov.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "tdh.lib")

#include <tdh.h>
#include <iostream>
#include <Windows.h>
#include <evntcons.h>
#include <strsafe.h>

#define RURIWO_LOGGER_NAME  L"RuriwoLogger"

DEFINE_GUID(RuriwoLoggerGuid, 0xD2E52D7A, 0xCE12, 0xBA8B, 0x6C, 0x84, 0x9C, 0x26, 0x55, 0x96, 0x73, 0xC4);

namespace fusion {
    namespace debugviewpp {

        VOID WINAPI EventRecordCallback(PEVENT_RECORD EventRecord)
        {
            auto pReader = (EtwReader*)EventRecord->UserContext;

            pReader->EventRecord(EventRecord);
        }

        ULONG WINAPI EventBufferCallback(PEVENT_TRACE_LOGFILEW Logfile)
        {
            return 0;
        }

        ULONG EtwReader::RegisterLogger(GUID ProviderGuid)
        {
            ULONG Status = ERROR_SUCCESS;
            TRACEHANDLE TraceHandle = INVALID_PROCESSTRACE_HANDLE;

            ULONG PropertiesSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(RURIWO_LOGGER_NAME) + 2;
            PEVENT_TRACE_PROPERTIES Properties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(malloc(PropertiesSize));

            while (TRUE) {
                RtlZeroMemory(Properties, PropertiesSize);

                Properties->Wnode.BufferSize = PropertiesSize;
                Properties->Wnode.Guid = RuriwoLoggerGuid;
                Properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                Properties->Wnode.ClientContext = 1;

                Properties->LogFileMode |= EVENT_TRACE_REAL_TIME_MODE;

                Properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
                Properties->FlushTimer = 1;

                Status = StartTraceW(&TraceHandle, RURIWO_LOGGER_NAME, Properties);

                //printf("StartTraceW result %08X\n", Status);

                if (ERROR_SUCCESS == Status) {
                    auto Status2 =
                        EnableTraceEx(&ProviderGuid,
                            nullptr,
                            TraceHandle,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE,
                            0xFFFFFFFFFFFFFFFF,
                            0,
                            0,
                            nullptr);

                    // printf("EnableTraceEx result %08X\n", Status2);
                    break;
                }
                else if (ERROR_ALREADY_EXISTS == Status) {
                    Status = ControlTraceW(0, RURIWO_LOGGER_NAME, Properties, EVENT_TRACE_CONTROL_STOP);

                    //printf("ControlTraceW result %08X\n", Status);
                    if (ERROR_SUCCESS != Status) {
                        break;
                    }
                }
                else {
                    break;
                }
            }

            free(Properties);
            return Status;
        }

        EtwReader::EtwReader(Timer& timer, ILineBuffer& lineBuffer, GUID ProviderGuid, long pollFrequency) :
            PolledLogSource(timer, SourceType::Pipe, lineBuffer, pollFrequency),
            m_ProviderGuid(ProviderGuid),
            m_TraceHandle(INVALID_PROCESSTRACE_HANDLE)
        {
            RegisterLogger(ProviderGuid);

            ULONG Status = ERROR_SUCCESS;
            EVENT_TRACE_LOGFILEW EventTraceLogFile = { 0 };

            WCHAR wszLoggerName[] = RURIWO_LOGGER_NAME;
            EventTraceLogFile.LoggerName = wszLoggerName;
            EventTraceLogFile.ProcessTraceMode |= PROCESS_TRACE_MODE_REAL_TIME;
            EventTraceLogFile.ProcessTraceMode |= PROCESS_TRACE_MODE_EVENT_RECORD;
            EventTraceLogFile.BufferCallback = EventBufferCallback;
            EventTraceLogFile.EventRecordCallback = EventRecordCallback;
            EventTraceLogFile.Context = this;
            m_TraceHandle = OpenTraceW(&EventTraceLogFile);

            SetDescription(wstringbuilder() << L"Etw Message");
            StartThread();
        }

        EtwReader::~EtwReader()
        {
            if(m_TraceHandle != INVALID_PROCESSTRACE_HANDLE)
                CloseTrace(m_TraceHandle);
        }

        void EtwReader::Abort()
        {
            if (m_TraceHandle != INVALID_PROCESSTRACE_HANDLE)
                 CloseTrace(m_TraceHandle);
        }

        bool EtwReader::Peek() const
        {
            auto Status = ProcessTrace(&m_TraceHandle, 1, NULL, NULL);

            return ERROR_SUCCESS == Status ? true : false;
        }

        bool EtwReader::AtEnd() const
        {
            return LogSource::AtEnd();
        }

        void EtwReader::Poll()
        {
            Poll(*this);
        }

        void EtwReader::Poll(PolledLogSource& logsource)
        {
            Peek();
        }

        VOID EtwReader::EventRecord(PEVENT_RECORD EventRecord)
        {
            // ?????????
            PTRACE_EVENT_INFO pEventInfo = nullptr;
            ULONG BufferSize = 0;
            ULONG Status = TdhGetEventInformation(
                EventRecord, 0, nullptr, pEventInfo, &BufferSize);

            if (Status == ERROR_INSUFFICIENT_BUFFER)
            {
                pEventInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
                Status = TdhGetEventInformation(EventRecord, 0, nullptr, pEventInfo, &BufferSize);
            }

            if (Status != ERROR_SUCCESS)
            {
                printf("TdhGetEventInformation failed with %08X\n", Status);

                if (pEventInfo)
                {
                    free(pEventInfo);
                }
                return;  // ????????,????
            }

            // ????????,?? "message" ??,????????
            for (ULONG i = 0; i < pEventInfo->TopLevelPropertyCount; i++)
            {
                PEVENT_PROPERTY_INFO pPropertyInfo = &pEventInfo->EventPropertyInfoArray[i];
                LPWSTR PropertyName = (LPWSTR)((PBYTE)pEventInfo + pPropertyInfo->NameOffset);

                // ??????????? "message" (?????)
                if (wcscmp(PropertyName, L"message") == 0)
                {
                    // ?????????
                    ULONG PropertySize = 0;
                    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
                    DataDescriptor.PropertyName = (ULONGLONG)PropertyName;
                    DataDescriptor.ArrayIndex = ULONG_MAX;  // ?????

                    Status = TdhGetPropertySize(EventRecord, 0, nullptr, 1, &DataDescriptor, &PropertySize);

                    if (Status == ERROR_SUCCESS && PropertySize > 0)
                    {
                        // ??????????????
                        PBYTE PropertyBuffer = (PBYTE)malloc(PropertySize);
                        if (!PropertyBuffer)
                        {
                            free(pEventInfo);
                            return;
                        }

                        Status = TdhGetProperty(
                            EventRecord, 0, nullptr, 1, &DataDescriptor, PropertySize, PropertyBuffer);

                        if (Status == ERROR_SUCCESS)
                        {
                            // ?? "message" ??? ANSI ???
                            std::string MessageString((char*)PropertyBuffer, PropertySize - 1);  // -1 ???? '\0'
                            std::cout << MessageString << std::endl;

                           AddMessage(4, "System", MessageString);
                        }
                        else
                        {
                            printf("TdhGetProperty failed with %08X\n", Status);
                        }

                        free(PropertyBuffer);
                    }
                    else
                    {
                        printf("TdhGetPropertySize failed with %08X\n", Status);
                    }
                    break;
                }
            }

            // ????? Event ????
            if (pEventInfo)
            {
                free(pEventInfo);
            }
        }

    } // namespace debugviewpp
} // namespace fusion
