package main

//https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf
// Chapter 14
/*
NDR defines a set of 13 primitive data types to represent Boolean values, characters, four sizes
of signed and unsigned integers, two sizes of floating-point numbers, and uninterpreted octets

14.2.2 Alignment of Primitive Types
NDR enforces NDR alignment of primitive data; that is, any primitive of size n octets is aligned at
a octet stream index that is a multiple of n. (In this version of NDR, n is one of {1, 2, 4, 8}.) An
octet stream index indicates the number of an octet in an octet stream when octets are
numbered, beginning with 0, from the first octet in the stream. Where necessary, an alignment
gap, consisting of octets of unspecified value, precedes the representation of a primitive. The gap
is of the smallest size sufficient to align the primitive.


---
So, if I want to place a boolean (1 byte value) first in a stream,
and then follow with a 4 byte integer, I have to leave 3 bytes of padding since the
size of the integer (n) is 4 so it has to be placed on a 4 byte boundary. Either on index 0, 4, 8, 12, etc.


14.3 NDR Constructed Types
NDR supports data types that are constructed from the NDR primitive data types described in
the previous section. The NDR constructed types include arrays, strings, structures, unions,
variant structures, pipes and pointers.
NDR represents every NDR constructed type as a sequence of NDR primitive values. The
representation formats for these primitive values are identified in the NDR format label.
All NDR constructed data types are integer multiples of octets in length.

NOTE
Not sure I want to implement this as it is sooo complex and annoying to do in Golang.
Seems to be more suited to C and C++.
*/

/*
Update 2024-03-05
It might be worth it to implement high level marshal/unmarshal functions for Structs?

Perhaps I should change all the structs defined in DCERPC to not contain UnicodeStr, or ReferentID ptrs,
and leave it up to each marshal/unmarshal function to add them where needed?
Atleast that would make the rest of the code a bit cleaner?
*/
