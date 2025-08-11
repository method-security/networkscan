# NDR
This project is a fork and extension of [jcmturner/rpc/v2/ndr](https://github.com/jcmturner/rpc)
which is an NDR decoder trying to follow the specification of
[DCE 1.1:Remote Procedure Call - Transfer Syntax NDR](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm).
My addition to the fork is a partial implementation of an NDR encoder which is
very much a work in progress and far from complete. I have also extended the decoder to
better support top-level pointers.

## Structs from IDL
[Interface Definition Language (IDL)](http://pubs.opengroup.org/onlinepubs/9629399/chap4.htm)

### Is an array conformant and/or varying?
An array is conformant if the IDL definition includes one of the following attributes:
* min_is
* max_is
* size_is

An array is varying if the IDL definition includes one of the following attributes: 
* last_is
* first_is 
* length_is

#### Examples:
SubAuthority[] is conformant in the example below:
```
 typedef struct _RPC_SID {
   unsigned char Revision;
   unsigned char SubAuthorityCount;
   RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
   [size_is(SubAuthorityCount)] unsigned long SubAuthority[];
 } RPC_SID,
  *PRPC_SID,
  *PSID;
```

Buffer is a pointer to a conformant varying array in the example below:
```
 typedef struct _RPC_UNICODE_STRING {
   unsigned short Length;
   unsigned short MaximumLength;
   [size_is(MaximumLength/2), length_is(Length/2)] 
     WCHAR* Buffer;
 } RPC_UNICODE_STRING,
  *PRPC_UNICODE_STRING;
```

## Algorith for deferral of referents
When deferring a referent, the data a pointer points to, the placement of the
defered data in the octet stream defends on where the pointer is placed.

In general, a defered referent is placed after the structure the pointer is
embedded in. For pointers inside nested structs, the referent is placed after
the outermost struct.

If there are multiple defered referents, they are placed in the order the
pointers occur in the structures.

A special case is a top-level pointer in which case the referent is NOT defered
but written directly following the pointer. If a top-level pointer's referent
contains embedded pointers, the embedded pointers's referent are placed after
the top-level pointer's referent rather than after the top-level pointer's
parent structure.

## RPC_UNICODE_STRING
A simplification has been made to handle RPC_UNICODE_STRING structs as
strings instead of byte buffers to represent the actual string.
This introduces a problem because in NDR, strings must be null terminated,
but since an RPC_UNIODE_STRING is actually a byte array, it should not be
null terminated. So to handle this an additional tag has been introduced
to indicate that a string field in a struct should NOT be null terminated
which provides a bit more flexibility.

## Top-level pointers
The RPC method arguments, or in this case, the fields in the request and
response structs are considered top-level arguments. If any of these fields is
a pointer, this should be treated as a top-level pointer which is handled
differently from embedded pointers.
By default, a top-level pointer is considered a referent pointer and is
represented by the referent marshalled directly without any pointer
representation first.
If the IDL specification adds the unique or ptr attribute, this becomes a full
top-level pointer in which case a 4 byte pointer representation is written and
is directly followed by the representation of the referent.
So in both cases, the referent is written directly and is NOT deferred to later.

If a top-level pointer points to a struct which contains pointers, those
pointers are considered embedded pointers. The referent of embedded pointers
are deferred until later in the byte stream by default, but in the case of
embedded pointers in the referent of a top-level pointer, the embedded pointer's
referent is placed directly after the top-level pointer's referent instead of
after the parent structure.

To handle this, two additional tags have been introduced to mark a struct field
as a top-level pointer and to indicate if it is a full pointer.

