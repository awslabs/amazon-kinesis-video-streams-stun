## amazon-kinesis-video-streams-stun

The goal of the Session Traversal Utilities for NAT (STUN) library is to provide
STUN Serializer and Deserializer functionalities.

## What is STUN?

[Session Traversal Utilities for NAT (STUN)](https://en.wikipedia.org/wiki/STUN),
described in [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489), is a
protocol that helps an endpoint behind the NAT to determine the IP address and
port allocated to it by NAT.

 A STUN message consist of 20 bytes header followed by zero or more attributes.

```
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |0 0|     STUN Message Type     |         Message Length        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Magic Cookie                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                     Transaction ID (96 bits)                  |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                         Format of STUN Message Header
```
 A STUN attribute is TLV encoded with a 16-bit type, 16-bit length and value.

```
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |         Type                  |            Length             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Value (variable)                ....
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                          Format of STUN Attributes
```

 This STUN library provides standalone implementation of STUN serializer and
 STUN deserializer.

## Using the library

### Serializer

1. Call `StunSerializer_Init()` to start creating an STUN message.
2. Keep appending attributes by calling corresponding APIs of the form `StunSerializer_AddAttribute<AttributeName>`:
   - To append priority attribute, call `StunSerializer_AddAttributePriority()`.
   - To append Username attribute, call `StunSerializer_AddAttributeUsername()`.
   - etc.
3. After appending all attributes, Call `StunSerializer_Finalize()` to get the
  serialized STUN message.

### Deserializer

1. Call `StunDeserializer_Init()` to start deserializing an STUN message.
2. Keep calling `StunDeserializer_GetNextAttribute()` to get next attribute in
   the STUN message.
3. Call corresponding parse APIs to parse the attribute string, obtained using
   `StunDeserializer_GetNextAttribute()`, into a structure:
   - If attribute type is `STUN_ATTRIBUTE_TYPE_PRIORITY`, call
     `StunDeserializer_ParseAttributePriority()`.
   - If attribute type is `STUN_ATTRIBUTE_TYPE_USERNAME`, call
     `StunDeserializer_ParseAttributeUsername()`.
   - etc.
4. Repeat step 2 and 3 till `StunDeserializer_GetNextAttribute()` returns
   `STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND`.

## License

This project is licensed under the Apache-2.0 License.

