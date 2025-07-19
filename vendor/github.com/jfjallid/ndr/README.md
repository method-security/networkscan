# NDR
This project is a fork and extension of [jcmturner/rpc/v2/ndr](https://github.com/jcmturner/rpc)
which is an NDR decoder trying to follow the specification of
[DCE 1.1:Remote Procedure Call - Transfer Syntax NDR](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm).
My addition to the fork is a partial implementation of an NDR encoder which is
very much a work in progress and far from complete.

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
