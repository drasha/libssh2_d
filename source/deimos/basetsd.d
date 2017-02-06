module deimos.basetsd;

alias __int64 = long;

version (Win32)
{
  alias __int3264 = int;
  immutable uint ADDRESS_TAG_BIT = 0x80000000;
}
else
{
  alias __int3264 = long;
  immutable ulong ADDRESS_TAG_BIT = 0x40000000000; 
}

alias INT8     = byte;
alias INT16    = short;
alias LONG32   = int;
alias PLONG32  = int*;
alias INT32    = int;
alias PINT32   = int*;
alias UINT8    = ubyte;
alias UINT16   = ushort;
alias ULONG32  = uint;
alias PULONG32 = uint*;
alias DWORD32  = uint;
alias PDWORD32 = uint*;
alias UINT32   = uint;
alias PUINT32  = uint*;

version(Win32)
{
  alias INT_PTR    = int;
  alias PINT_PTR   = int*;
  alias UINT_PTR   = uint;
  alias PUINT_PTR  = uint*;
  alias LONG_PTR   = int;
  alias PLONG_PTR  = int*;
  alias ULONG_PTR  = uint;
  alias PULONG_PTR = uint*;
  alias UHALF_PTR  = ushort;
  alias PUHALF_PTR = ushort*;
  alias HALF_PTR   = short;
  alias PHALF_PTR  = short*;
  alias HANDLE_PTR = uint;

  uint HandleToUlong(const void* h)
  { return(cast(uint)h); }
  int HandleToLong(const void* h)
  { return(cast(int)h); }
  void* LongToHandle(const int h)
  { return(cast(void*)h);}
  uint PtrToUlong(const void* p)
  { return(cast(uint) p); }
  int PtrToLong(const void* p)
  { return(cast(int) p); }
  uint PtrToUint(const void* p)
  { return(cast(uint) p); }
  int PtrToInt(const void* p)
  { return(cast(int) p); }
  ushort PtrToUshort(const void* p)
  { return(cast(ushort) cast(uint) p);}
  short PtrToShort(const void* p)
  { return(cast(short) cast(uint) p);}
  void* IntToPtr(const int i)
  { return(cast(void*)i); }
  void* UIntToPtr(const uint ui)
  { return(cast(void*)ui); }
  alias UintToPtr = UIntToPtr;
  void* LongToPtr(const int l)
  { return(cast(void*)l); }
  void* ULongToPtr(const uint ul)
  { return(cast(void*)ul); }
  alias UlongToPtr = ULongToPtr;
}
else
{
  alias INT_PTR    = long;
  alias PINT_PTR   = long*;
  alias UINT_PTR   = ulong;
  alias PUINT_PTR  = ulong*;
  alias LONG_PTR   = long;
  alias PLONG_PTR  = long*;
  alias ULONG_PTR  = ulong;
  alias PULONG_PTR = ulong*;
  alias HANDLE_PTR = ulong*;
  alias UHALF_PTR  = uint;
  alias PUHALF_PTR = uint*;
  alias HALF_PTR   = int;
  alias PHALF_PTR  = int*;
  
  version(none)
  {
    /* TODO when WIN64 is here */
    ulong HandleToUlong(const void* h )
    { return(cast(ulong) h ); }
    long HandleToLong( const void* h )
    { return(cast(long) h ); }
    void* LongToHandle( const long h )
    { return(cast(void*) cast(INT_PTR) h ); }
    ulong PtrToUlong( const void* p)
    { return(cast(ulong) p ); }
    uint PtrToUint( const void* p )
    { return(cast(uint) p ); }
    ushort PtrToUshort( const void* p )
    { return(cast(ushort) p ); }
    long PtrToLong( const void* p )
    { return(cast(long) p ); }
    int PtrToInt( const void* p )
    { return(cast(int) p ); }
    short PtrToShort( const void* p )
    { return(cast(short) p ); }
    void* IntToPtr( const int i )
    { return( cast(void*) cast(INT_PTR)i ); }
    void* UIntToPtr(const uint ui)
    { return( cast(void*) cast(UINT_PTR)ui ); }
    void* LongToPtr( const long l )
    { return( cast(void*) cast(LONG_PTR)l ); }
    void* ULongToPtr( const ulong ul )
    { return( cast(void*) cast(ULONG_PTR)ul ); }
  }
}

alias SIZE_T     = ULONG_PTR;
alias PSIZE_T    = PULONG_PTR;
alias SSIZE_T    = LONG_PTR;
alias PSSIZE_T   = PLONG_PTR;
alias DWORD_PTR  = ULONG_PTR;
alias PDWORD_PTR = PULONG_PTR;
alias LONG64     = long;
alias PLONG64    = long*;
alias INT64      = long;
alias PINT64     = long*;
alias ULONG64    = ulong;
alias PULONG64   = ulong*;
alias DWORD64    = ulong;
alias PDWORD64   = ulong*;
alias UINT64     = ulong;
alias PUINT64    = ulong*;

immutable MAXUINT_PTR = uint.max;
immutable MAXINT_PTR  = int.max;
immutable MININT_PTR  = int.min;
immutable MAXUHALF_PTR = ushort.max;
immutable MAXHALF_PTR  = short.max;
immutable MINHALF_PTR  = short.min;

version(Win32)
{
  immutable MAXULONG_PTR = uint.max;
  immutable MAXLONG_PTR  = int.max;
  immutable MINLONG_PTR  = int.min;
}
else
{
  immutable MAXULONG_PTR = ulong.max;
  immutable MAXLONG_PTR  = long.max;
  immutable MINLONG_PTR  = long.min;
}
