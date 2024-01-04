
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stun_serializer.h"


int main( void )
{
    StunResult_t result = STUN_RESULT_OK;
    StunContext_t stunContext;
    size_t bufferLength=0, stunMessageLength;
    uint8_t * pBuffer, transactionId[STUN_HEADER_TRANSACTION_ID_LENGTH];
    uint32_t priority = 0x7E7F00FF;
    StunHeader_t stunHeader;
    StunAttribute_t stunAttribute;
    const uint8_t * pStunMessage;
    char *userName = "6a05f848:8ac3e902";
    uint16_t usernameLen = strlen(userName);

    memcpy(transactionId, (char *) "ABCDEFGHIJKL", STUN_HEADER_TRANSACTION_ID_LENGTH);

    //Calculate required buffer size
    bufferLength = STUN_HEADER_LENGTH + STUN_ATTRIBUTE_TOTAL_LENGTH(sizeof(priority)) + STUN_ATTRIBUTE_TOTAL_LENGTH(ALIGN_SIZE_TO_WORD(usernameLen)); // HEADER + Priority Attribute  + UserName Attribute

    pBuffer = malloc(bufferLength);
    if( pBuffer == NULL )
    {
        result = STUN_RESULT_OUT_OF_MEMORY;
    }

    /* --------------------- Serialisation --------------------- */

    if ( result == STUN_RESULT_OK )
    {
        result = StunSerializer_Init( &stunContext, pBuffer, bufferLength );
    }

    if ( result == STUN_RESULT_OK )
    {  
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        memcpy( stunHeader.transactionId, transactionId, STUN_HEADER_TRANSACTION_ID_LENGTH );
        /* Message length is updated in finalize. */

        result = StunSerializer_AddHeader( &stunContext, &stunHeader );
    }

    if ( result == STUN_RESULT_OK )
    {
        result = StunSerializer_AddAttributePriority( &stunContext, priority );
    }

    if ( result == STUN_RESULT_OK )
    {
        result = StunSerializer_AddAttributeUsername( &stunContext, userName, usernameLen );
    }
    
    if ( result == STUN_RESULT_OK )
    {
        result = StunSerializer_Finalize( &stunContext, &pStunMessage, &stunMessageLength );
    }
    
    if ( result == STUN_RESULT_OK )
    {
        printf("Serialised Message Length %ld\n",stunMessageLength );
        printf("Serialised Message :\n" );
        for( int i=0 ; i < stunMessageLength; i++ )
        {
            printf("0x%02x ", pStunMessage[i] );
        }

        printf("\n\n----Result : Test Passed----\n\n");
    }
    else
    {
        printf("\n\n----Result : Test Failed----\n\n");
    }
    return 0;
}
