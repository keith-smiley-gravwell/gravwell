//go:build windows && (amd64 || arm64)

/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

import "unsafe"

// Structures from evntrace.h, evntcons.h, evntprov.h and tdh.h.  These are
// only declared for 64-bit Windows, where Go's struct layout rules match the
// C compiler's.  Sizes are asserted in types_windows_test.go.

const (
	wnodeFlagTracedGUID = 0x00020000

	eventTraceRealTimeMode = 0x00000100

	eventTraceControlQuery = 0
	eventTraceControlStop  = 1
	eventTraceControlFlush = 3

	eventControlCodeDisableProvider = 0
	eventControlCodeEnableProvider  = 1

	enableTraceParametersVersion2 = 2
	eventFilterTypeEventID        = 0x80000200

	processTraceModeRealTime    = 0x00000100
	processTraceModeEventRecord = 0x10000000

	invalidProcessTraceHandle = 0xffffffffffffffff

	eventHeaderFlagStringOnly  = 0x0004
	eventHeaderFlag32BitHeader = 0x0020
	eventHeaderFlag64BitHeader = 0x0040

	eventHeaderExtTypeRelatedActivityID = 0x0001

	maxSessionNameLen = 1024 // characters, including the terminator
)

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              GUID
	ClientContext     uint32
	Flags             uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type eventTraceHeader struct {
	Size          uint16
	FieldTypeFlag uint16
	Version       uint32
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	Guid          GUID
	ProcessorTime uint64
}

type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGuid       GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

type systemTime struct {
	Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds uint16
}

type timeZoneInformation struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate systemTime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate systemTime
	DaylightBias int32
}

type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGuid    GUID
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           timeZoneInformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventTrace
	LogfileHeader       traceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      GUID
}

type etwBufferContext struct {
	ProcessorIndex uint16
	LoggerID       uint16
}

type eventHeaderExtendedDataItem struct {
	Reserved1 uint16
	ExtType   uint16
	Linkage   uint16
	DataSize  uint16
	DataPtr   unsafe.Pointer
}

type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      *eventHeaderExtendedDataItem
	UserData          unsafe.Pointer
	UserContext       uintptr
}

type eventFilterDescriptor struct {
	Ptr  uint64
	Size uint32
	Type uint32
}

type enableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceID         GUID
	EnableFilterDesc *eventFilterDescriptor
	FilterDescCount  uint32
}

type traceEventInfo struct {
	ProviderGUID          GUID
	EventGUID             GUID
	EventDescriptor       eventDescriptor
	DecodingSource        uint32
	ProviderNameOffset    uint32
	LevelNameOffset       uint32
	ChannelNameOffset     uint32
	KeywordsNameOffset    uint32
	TaskNameOffset        uint32
	OpcodeNameOffset      uint32
	EventMessageOffset    uint32
	ProviderMessageOffset uint32
	BinaryXMLOffset       uint32
	BinaryXMLSize         uint32
	EventNameOffset       uint32
	EventAttributesOffset uint32
	PropertyCount         uint32
	TopLevelPropertyCount uint32
	Flags                 uint32
	// EventPropertyInfoArray follows
}

const (
	propertyStruct           = 0x1
	propertyParamLength      = 0x2
	propertyParamCount       = 0x4
	propertyParamFixedLength = 0x10
	propertyParamFixedCount  = 0x20
)

type eventPropertyInfo struct {
	Flags      uint32
	NameOffset uint32
	// nonStructType: InType, OutType, MapNameOffset
	// structType: StructStartIndex, NumOfStructMembers, padding
	InType        uint16
	OutType       uint16
	MapNameOffset uint32
	Count         uint16
	Length        uint16
	Reserved      uint32
}

func (p *eventPropertyInfo) structStartIndex() uint16   { return p.InType }
func (p *eventPropertyInfo) numOfStructMembers() uint16 { return p.OutType }

type eventMapInfo struct {
	NameOffset uint32
	Flag       uint32
	EntryCount uint32
	ValueType  uint32
}

const (
	eventMapInfoFlagManifestBitmap = 0x2
	eventMapInfoFlagWbemBitmap     = 0x10
)

type providerEnumerationInfo struct {
	NumberOfProviders uint32
	Reserved          uint32
}

type traceProviderInfo struct {
	ProviderGUID       GUID
	SchemaSource       uint32
	ProviderNameOffset uint32
}

type providerFieldInfoArray struct {
	NumberOfElements uint32
	FieldType        uint32
}

type providerFieldInfo struct {
	NameOffset        uint32
	DescriptionOffset uint32
	Value             uint64
}
