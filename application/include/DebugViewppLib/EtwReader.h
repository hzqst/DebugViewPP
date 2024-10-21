// (C) Copyright Gert-Jan de Vos and Jan Wilmans 2013.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include "PolledLogSource.h"

#include <evntrace.h>
#include <tdh.h>

namespace fusion {
namespace debugviewpp {

class ILineBuffer;

class EtwReader : public PolledLogSource
{
public:
    EtwReader(Timer& timer, ILineBuffer& lineBuffer, GUID ProviderGuid, long pollFrequency);
    virtual ~EtwReader();

    void Abort() override;
    bool AtEnd() const override;
    void Poll() override;
    void Poll(PolledLogSource& logSource);

     ULONG RegisterLogger(GUID ProviderGuid);

    VOID EventRecord(PEVENT_RECORD EventRecord);

    private:
    void UnicodeToANSI(const std::wstring& str, std::string& out);
    std::string UtilGetProcessNameFromProcessId(DWORD processId);
    bool GetEventPropertyValueAsInt32(PEVENT_RECORD pEventRecord, PTRACE_EVENT_INFO pInfo, LPCWSTR propertyName, int32_t& value);
    bool GetEventPropertyValueAsString(PEVENT_RECORD pEventRecord, PTRACE_EVENT_INFO pInfo, LPCWSTR propertyName, std::string& value);
    bool Peek() const;

    GUID m_ProviderGuid;
    mutable TRACEHANDLE m_TraceHandle;
    std::string m_buffer;
};

} // namespace debugviewpp
} // namespace fusion
