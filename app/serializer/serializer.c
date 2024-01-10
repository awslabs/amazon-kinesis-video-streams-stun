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
    uint8_t transactionId[] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x11,
                                0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };

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
