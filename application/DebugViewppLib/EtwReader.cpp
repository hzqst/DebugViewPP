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
#include <psapi.h>
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

            if (!Properties)
                return ERROR_OUTOFMEMORY;

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

                if (ERROR_SUCCESS == Status)
                {
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

                    break;
                }
                else if (ERROR_ALREADY_EXISTS == Status)
                {
                    Status = ControlTraceW(0, RURIWO_LOGGER_NAME, Properties, EVENT_TRACE_CONTROL_STOP);

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

        void EtwReader::UnicodeToANSI(const std::wstring& str, std::string& out)
        {
            int len = WideCharToMultiByte(CP_ACP, 0, str.c_str(), str.length(), NULL, 0, NULL, NULL);
            out.resize(len);
            WideCharToMultiByte(CP_ACP, 0, str.c_str(), str.length(), (LPSTR)out.data(), len, NULL, NULL);
        }

        bool EtwReader::GetEventPropertyValueAsString(PEVENT_RECORD pEventRecord, PTRACE_EVENT_INFO pInfo, LPCWSTR propertyName, std::string& value)
        {
            ULONG propertyIndex = ULONG_MAX;
            for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i)
            {
                PEVENT_PROPERTY_INFO pPropertyInfo = &pInfo->EventPropertyInfoArray[i];
                LPWSTR pName = (LPWSTR)((PBYTE)pInfo + pPropertyInfo->NameOffset);
                if (wcscmp(pName, propertyName) == 0)
                {
                    propertyIndex = i;
                    break;
                }
            }

            if (propertyIndex == ULONG_MAX)
            {
                // ?????
                return false;
            }

            // ?????????
            PROPERTY_DATA_DESCRIPTOR dataDescriptor;
            RtlZeroMemory(&dataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
            dataDescriptor.PropertyName = (ULONGLONG)propertyName;
            dataDescriptor.ArrayIndex = ULONG_MAX;  // ???

            ULONG propertySize = 0;
            ULONG status = TdhGetPropertySize(pEventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
            if (status != ERROR_SUCCESS)
            {
                return false;
            }

            std::vector<BYTE> buffer(propertySize);

            status = TdhGetProperty(pEventRecord, 0, NULL, 1, &dataDescriptor, propertySize, buffer.data());
            if (status != ERROR_SUCCESS)
            {
                return false;
            }

            // ?? InType ????
            PEVENT_PROPERTY_INFO pPropertyInfo = &pInfo->EventPropertyInfoArray[propertyIndex];
            USHORT inType = pPropertyInfo->nonStructType.InType;

            switch (inType)
            {
            case TDH_INTYPE_UNICODESTRING: {
                std::wstring ustr((WCHAR*)buffer.data(), buffer.size() / sizeof(WCHAR) - 1);
                UnicodeToANSI(ustr, value);
                break;
            }
            case TDH_INTYPE_ANSISTRING: {
                value.assign((CHAR*)buffer.data(), buffer.size() - 1);
                break;
            }
            case TDH_INTYPE_COUNTEDSTRING: // 300
            {
                USHORT stringLength = *(USHORT*)buffer.data();
                if (stringLength > 0 && (stringLength + sizeof(USHORT)) <= buffer.size())
                {
                    WCHAR* pwStr = (WCHAR*)(buffer.data() + sizeof(USHORT));
                    std::wstring ustr(pwStr, stringLength / sizeof(WCHAR));
                    UnicodeToANSI(ustr, value);
                }
                else
                {
                    value.clear();
                }
                break;
            }
            case TDH_INTYPE_COUNTEDANSISTRING: // 301
            {
                USHORT stringLength = *(USHORT*)buffer.data();
                if (stringLength > 0 && (stringLength + sizeof(USHORT)) <= buffer.size())
                {
                    CHAR* pStr = (CHAR*)(buffer.data() + sizeof(USHORT));
                    value.assign(pStr, stringLength);
                }
                else
                {
                    value.clear();
                }
                break;
            }
            default:
                return false;
            }

            return true;
        }

        bool EtwReader::GetEventPropertyValueAsInt32(PEVENT_RECORD pEventRecord, PTRACE_EVENT_INFO pInfo, LPCWSTR propertyName, int32_t& value)
        {
            ULONG propertyIndex = ULONG_MAX;
            for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i)
            {
                PEVENT_PROPERTY_INFO pPropertyInfo = &pInfo->EventPropertyInfoArray[i];
                LPWSTR pName = (LPWSTR)((PBYTE)pInfo + pPropertyInfo->NameOffset);
                if (wcscmp(pName, propertyName) == 0)
                {
                    propertyIndex = i;
                    break;
                }
            }

            if (propertyIndex == ULONG_MAX)
            {
                return false;
            }

            PROPERTY_DATA_DESCRIPTOR dataDescriptor;
            RtlZeroMemory(&dataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
            dataDescriptor.PropertyName = (ULONGLONG)propertyName;
            dataDescriptor.ArrayIndex = ULONG_MAX;

            ULONG propertySize = 0;
            ULONG status = TdhGetPropertySize(pEventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
            if (status != ERROR_SUCCESS)
            {
                return false;
            }

            if (propertySize != sizeof(int32_t))
            {
                return false;
            }

            status = TdhGetProperty(pEventRecord, 0, NULL, 1, &dataDescriptor, propertySize, (PBYTE)&value);
            if (status != ERROR_SUCCESS)
            {
                return false;
            }

            return true;
        }

        // ?? ProcessId ??????
        std::string EtwReader::UtilGetProcessNameFromProcessId(DWORD processId)
        {
            if (processId <= 4)
            {
                return "System";
            }

            std::string processName = "<unknown>";

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (hProcess != NULL)
            {
                WCHAR szProcessName[MAX_PATH] = L"<unknown>";

                if (GetModuleBaseNameW(hProcess, NULL, szProcessName, MAX_PATH))
                {
                    UnicodeToANSI(szProcessName, processName);
                }
                CloseHandle(hProcess);
            }

            return processName;
        }

        VOID EtwReader::EventRecord(PEVENT_RECORD EventRecord)
        {
            PTRACE_EVENT_INFO pEventInfo = nullptr;
            ULONG BufferSize = 0;

            ULONG Status = TdhGetEventInformation(EventRecord, 0, nullptr, pEventInfo, &BufferSize);

            if (Status == ERROR_INSUFFICIENT_BUFFER)
            {
                pEventInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
                Status = TdhGetEventInformation(EventRecord, 0, nullptr, pEventInfo, &BufferSize);
            }

            if (Status != ERROR_SUCCESS)
            {
                if (pEventInfo)
                {
                    free(pEventInfo);
                }
                return;
            }

            DWORD ProcessId = EventRecord->EventHeader.ProcessId;
            std::string ProcessName;

            int32_t eventProcessId = 0;
            if (GetEventPropertyValueAsInt32(EventRecord, pEventInfo, L"process_id", eventProcessId))
            {
                ProcessId = static_cast<DWORD>(eventProcessId);
            }

            if (!GetEventPropertyValueAsString(EventRecord, pEventInfo, L"process_name", ProcessName))
            {
                ProcessName = UtilGetProcessNameFromProcessId(ProcessId);
            }

            std::string MessageString;
            if (GetEventPropertyValueAsString(EventRecord, pEventInfo, L"message", MessageString))
            {
               // std::cout << "ProcessId: " << ProcessId << ", ProcessName: " << ProcessName << ", Message: " << MessageString << std::endl;
                AddMessage(ProcessId, ProcessName, MessageString);
            }

            if (pEventInfo)
            {
                free(pEventInfo);
            }
        }


    } // namespace debugviewpp
} // namespace fusion
