/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Serializer includes. */
#include "stun_serializer.h"

int main( void )
{
    StunResult_t result;
    StunContext_t stunContext;
    uint8_t stunMessageBuffer[ 1024 ]; /* Buffer to write the STUN message in. */
    size_t stunMessageLength;
    StunHeader_t header;
    StunAttributeAddress_t stunMappedAddress;
    uint8_t transactionId[] = { 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
                                0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE };
    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    /* Initialise stun address attribute */
    stunMappedAddress.padding = 0x0;
    stunMappedAddress.family = STUN_ADDRESS_IPv6;
    stunMappedAddress.port = 32853;
    memcpy( stunMappedAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );

    /* STUN header. */
    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    memcpy( &( header.transactionId[ 0 ] ),
            &( transactionId[ 0 ] ),
             STUN_HEADER_TRANSACTION_ID_LENGTH );

    /* Create a STUN message. */
    result = StunSerializer_Init( &( stunContext ),
                                  &( stunMessageBuffer[ 0 ] ),
                                  1024,
                                  &( header ) );

    /* Add priority attribute. */
    if( result == STUN_RESULT_OK )
    {
        result = StunSerializer_AddAttributePriority( &( stunContext ), 42 );
    }

    /* Add username attribute. */
    if( result == STUN_RESULT_OK )
    {
        result = StunSerializer_AddAttributeUsername( &( stunContext ),
                                                      "guest",
                                                      strlen( "guest" ) );
    }

    /* Add mapped address attribute. */
    if( result == STUN_RESULT_OK )
    {
        result = StunSerializer_AddAttributeMappedAddress( &( stunContext ),
                                                           &( stunMappedAddress ) );
    }

    /* Add XOR mapped address attribute. */
    if( result == STUN_RESULT_OK )
    {
        result = StunSerializer_AddAttributeXORMappedAddress( &( stunContext ),
                                                              &( stunMappedAddress ),
                                                              transactionId );
    }

    /* Obtain the length of the serialized message. */
    if( result == STUN_RESULT_OK )
    {
        result = StunSerializer_Finalize( &( stunContext ),
                                          NULL,
                                          &( stunMessageLength ) );
    }

    if ( result == STUN_RESULT_OK )
    {
        printf( "Serialization Successful! Serialized Message Length: %ld\n", stunMessageLength );
        printf( "Serialized Message :\n" );
        for( int i=0 ; i < stunMessageLength; i++ )
        {
            printf( "0x%02x ", stunMessageBuffer[ i ] );
        }
        printf( "\n" );
    }
    else
    {
        printf( "Serialization Failed! \n" );
    }

    return 0;
}
