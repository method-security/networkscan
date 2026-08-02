# NDR
This project is a fork and extension of [jcmturner/rpc/v2/ndr](https://github.com/jcmturner/rpc)
which is an NDR decoder trying to follow the specification of
[DCE 1.1:Remote Procedure Call - Transfer Syntax NDR](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm).
My addition to the fork is an extension of the decoder to support more of the NDR specification,
and an implementation of an NDR encoder which is is a work in progress.

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

To handle this, two additional tags have been introduced: `toplevel` marks a
struct field as a top-level pointer, and `fullpointer` indicates it is a full
(`[unique]` / `[ptr]`) pointer rather than a reference pointer.

## Struct tag reference

| Tag | Meaning |
|-----|---------|
| `conformant` | Array carries a `max_count` (hoisted to the beginning of the enclosing struct). |
| `varying` | Array carries an `offset` and `actual_count` inline. |
| `pointer` | Embedded `[ref]` pointer: 4-byte referent_id inline, referent deferred, **null not allowed**. |
| `fullpointer` | On an embedded pointer makes it `[unique]`/`[ptr]` (nullable, writes 0 when nil). On a top-level pointer combined with `toplevel` makes it a full top-level pointer. |
| `toplevel` | Top-level RPC parameter pointer. Alone = `[ref]` (no pointer representation, inline referent, cannot be null). With `fullpointer` = 4-byte pointer representation then inline referent, can be null. |
| `notnullptr` | Forces a non-null referent_id for an embedded pointer whose Go value is the zero value. Used for `[in,out]` buffers where the client pre-allocates storage (`Length=0, MaxLength=N`) but still needs to send a non-NULL `Buffer`. |
| `skipnull` | On a string: skip the NDR null terminator (for `RPC_UNICODE_STRING` whose `Length`/`MaxLength` already describe the byte buffer). |
| `maxcount:FieldName` | Derive a string's conformant `max_count` from a sibling uint16 field (value/2 → UTF-16 code units). |
| `pipe` | NDR pipe (chunked streaming). |
| `unionTag`, `unionField`, `encapsulated` | Discriminated-union construction. |

### Pointer tag mapping

| IDL | Tag |
|-----|-----|
| Top-level `[ref]` | `toplevel` |
| Top-level `[unique]` / `[ptr]` | `toplevel,fullpointer` |
| Embedded `[ref]` | `pointer` |
| Embedded `[unique]` / `[ptr]` | `pointer,fullpointer` (or `fullpointer` alone) |

## Intentional deviations from C706 NDR 1.1

The following depart from a strict reading of C706 §14 but are kept for
MS-RPC interoperability or because the underlying Go representation does not
admit a direct mapping:

* **Referent IDs start at `0x00020000` and increment by 4.** C706 §14.3.12.1
  suggests `1..n`. Microsoft implementations use the `0x00020000` base and
  this library follows suit so wire captures compare cleanly against real
  traffic.
* **Varying arrays are always written with `offset = 0`.** Go slices have no
  notion of a non-zero lower bound, so the encoder cannot express a non-zero
  lower slice index. The decoder still accepts non-zero offsets on input.
* **`readChar` returns `rune`** rather than a 1-octet byte. Cosmetic — every
  valid 1-octet character fits in a `rune` without loss.
* **Conformant arrays of conformant strings use a single common `max_count`**
  — the longest string's UTF-16 code-unit length (plus one for the null
  terminator unless `skipnull` is set) — rather than hoisting a separate
  `max_count` per string as pure NDR §14.3.7.1 describes. This matches what
  Microsoft's RPC runtime emits for string arrays and is what the decoder
  expects on input.
* **Varying strings are padded to a 4-byte boundary after the UTF-16 data.**
  C706 §14.3.2 specifies pre-value alignment only; the trailing pad is added
  to match MS-RPCE wire traffic, where a string is commonly followed by
  another 4-byte-aligned primitive.
* **Fixed-size arrays of strings (`[N]string`) encode each element as a full
  varying string** (offset + actual_count + data). C706 fixed arrays carry no
  per-element metadata; this library treats every string as varying, so fixed
  arrays of strings inherit that per-element metadata.

## Unsupported encodings

Only **ASCII** character encoding and **IEEE 754** floating-point
representation are supported. Any other value parsed from a common header,
or set on the `Encoder`'s `CommonHeader` before calling `Encode`, returns a
`Malformed` error. Non-IEEE float formats (VAX/Cray/IBM) and non-ASCII
character encodings (EBCDIC) are not implemented.
