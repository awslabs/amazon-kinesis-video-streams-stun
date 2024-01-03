
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stun_serializer.h"


int main( void )
{
    StunResult_t result = STUN_RESULT_OK;
    uint8_t transactionId[STUN_HEADER_TRANSACTION_ID_LENGTH];
    StunContext_t stunDContext;
    StunHeader_t stunHeader;
    StunAttribute_t stunAttribute;
    size_t stunMessageLength;
    uint8_t *userName;
    uint16_t userNameLength;
    uint32_t priority;
    

    uint8_t serializesMessage[] = {  0x00, 0x01, 0x00, 0x4c, 0x21, 0x12, 0xa4, 0x42, 0x21, 0x8d,
                                     0x70, 0xf0, 0x9c, 0xcd, 0x89, 0x06, 0x62, 0x25, 0x89, 0x97, 
                                     0x00, 0x06, 0x00, 0x11, 0x36, 0x61, 0x30, 0x35, 0x66, 0x38, 0x34, 0x38,
                                     0x3a, 0x38, 0x61, 0x63, 0x33, 0x65, 0x39, 0x30, 0x32, 0x00, 0x00, 0x00, 
                                     0x00, 0x24, 0x00, 0x04, 0x7e, 0x7f, 0x00, 0xff };
    stunMessageLength = sizeof(serializesMessage);

    /* --------------------- Deserialisation --------------------- */

    result = StunDeserializer_Init( &stunDContext, serializesMessage, stunMessageLength);

    if(result == STUN_RESULT_OK)
    {  
        result = StunDeserializer_GetHeader( &stunDContext, &stunHeader );
    }

    if(result == STUN_RESULT_OK)
    {
        while( stunDContext.currentIndex < stunDContext.totalLength )
        {
            result = StunDeserializer_GetNextAttribute(&stunDContext, &stunAttribute);
            
            if( result == STUN_RESULT_OK)
            {
                switch ( stunAttribute.attributeType ) {

                    case STUN_ATTRIBUTE_TYPE_USERNAME:
                        StunDeserializer_ParseAttributeUsername(&stunAttribute, userName, userNameLength);
                        break;

                    case STUN_ATTRIBUTE_TYPE_PRIORITY:
                        StunDeserializer_ParseAttributePriority(&stunAttribute, &priority);
                        break;
                    
                    default:
                        // Skip over the unknown attributes
                        break;
                }
            }
        }
    }
    
    if(result == STUN_RESULT_OK || result == STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND)
    {
        printf("\n\n----Result : Test Passed----\n\n");
    }
    else
    {
        printf("\n\n----Result : Test Failed----\nreturn Val : %d\n",result );
    }
    return 0;
}
