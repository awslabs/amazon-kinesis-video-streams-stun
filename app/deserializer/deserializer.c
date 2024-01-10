/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deserializer includes. */
#include "stun_deserializer.h"

uint8_t stunMessage[] = { 0x00, 0x01, 0x00, 0x20, 0x21, 0x12, 0xa4, 0x42, 0x21, 0x8d,
                          0x70, 0xf0, 0x9c, 0xcd, 0x89, 0x06, 0x62, 0x25, 0x89, 0x97,
                          0x00, 0x06, 0x00, 0x11, 0x36, 0x61, 0x30, 0x35, 0x66, 0x38, 0x34, 0x38,
                          0x3a, 0x38, 0x61, 0x63, 0x33, 0x65, 0x39, 0x30, 0x32, 0x00, 0x00, 0x00,
                          0x00, 0x24, 0x00, 0x04, 0x7e, 0x7f, 0x00, 0xff };

int main( void )
{
    StunResult_t result;
    StunContext_t stunContext;
    StunHeader_t header;
    StunAttribute_t stunAttribute;

    /* Initialize STUN context for deserializing. */
    result = StunDeserializer_Init( &( stunContext ),
                                    &( stunMessage[ 0 ] ),
                                    sizeof( stunMessage ),
                                    &( header )  );

    if( result == STUN_RESULT_OK )
    {
        printf( "Stun Message Type = %d\n", header.messageType );
        printf( "Transaction ID: " );
        for( int i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++ )
        {
            printf( "0x%02x ", header.transactionId[ i ] );
        }
        printf( "\n" );
    }

    while( result == STUN_RESULT_OK )
    {
        result = StunDeserializer_GetNextAttribute( &( stunContext ),
                                                    &( stunAttribute ) );

        if( result == STUN_RESULT_OK )
        {
            switch( stunAttribute.attributeType )
            {
                case STUN_ATTRIBUTE_TYPE_USERNAME:
                {
                    const char * pUsername;
                    uint16_t usernameLength;

                    result = StunDeserializer_ParseAttributeUsername( &( stunAttribute ),
                                                                        &( pUsername ),
                                                                        &( usernameLength ) );

                    if( result == STUN_RESULT_OK )
                    {
                        printf( "Username: %.*s\n", usernameLength, pUsername );
                    }
                }
                break;

                case STUN_ATTRIBUTE_TYPE_PRIORITY:
                {
                    uint32_t priority;

                    result = StunDeserializer_ParseAttributePriority( &( stunAttribute ),
                                                                      &( priority ) );

                    if( result == STUN_RESULT_OK )
                    {
                        printf( "Priority: 0x%0X\n", priority );
                    }
                }
                break;

                default:
                    break;
            }
        }
    }

    return 0;
}
