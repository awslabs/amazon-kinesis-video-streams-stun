
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stun_deserializer.h"


int main( void )
{
    StunResult_t result = STUN_RESULT_OK;
    StunContext_t stunDContext;
    StunHeader_t stunHeader;
    StunAttribute_t stunAttribute;
    size_t stunMessageLength;
    uint8_t *userName;
    uint8_t expectedUserName[]="6a05f848:8ac3e902";
    uint16_t userNameLength;
    uint32_t priority, expectedPriority = 0x7E7F00FF;
    

    uint8_t serializesMessage[] = {  0x00, 0x01, 0x00, 0x20, 0x21, 0x12, 0xa4, 0x42, 0x21, 0x8d,
                                     0x70, 0xf0, 0x9c, 0xcd, 0x89, 0x06, 0x62, 0x25, 0x89, 0x97, 
                                     0x00, 0x06, 0x00, 0x11, 0x36, 0x61, 0x30, 0x35, 0x66, 0x38, 0x34, 0x38,
                                     0x3a, 0x38, 0x61, 0x63, 0x33, 0x65, 0x39, 0x30, 0x32, 0x00, 0x00, 0x00, 
                                     0x00, 0x24, 0x00, 0x04, 0x7e, 0x7f, 0x00, 0xff };

    stunMessageLength = sizeof(serializesMessage);

    /* --------------------- Deserialisation --------------------- */

    result = StunDeserializer_Init( &stunDContext, serializesMessage, stunMessageLength);

    if( result == STUN_RESULT_OK )
    {  
        result = StunDeserializer_GetHeader( &stunDContext, &stunHeader );
        printf("Stun messageType = %d\n",stunHeader.messageType);
        printf("Stun messageLength = %d\n\n",stunHeader.messageLength);
    }

    while( result == STUN_RESULT_OK && stunDContext.currentIndex < stunDContext.totalLength )
    {
        result = StunDeserializer_GetNextAttribute(&stunDContext, &stunAttribute);
        printf("Type %x ValLen %x\n", stunAttribute.attributeType, stunAttribute.attributeValueLength);
            
        if( result == STUN_RESULT_OK)
        {
            switch ( stunAttribute.attributeType )
            {
                case STUN_ATTRIBUTE_TYPE_USERNAME:
                        result = StunDeserializer_ParseAttributeUsername((const StunAttribute_t *)&stunAttribute, (const char **)&userName, &userNameLength);
                        if(!memcmp(userName, expectedUserName, stunAttribute.attributeValueLength))
                            printf("STUN_ATTRIBUTE_TYPE_USERNAME %s\n", userName);
                        break;

                case STUN_ATTRIBUTE_TYPE_PRIORITY:
                        result = StunDeserializer_ParseAttributePriority(&stunAttribute, &priority);
                        if(priority == expectedPriority)
                            printf("STUN_ATTRIBUTE_TYPE_PRIORITY %x\n", priority);
                        break;
                    
                default:
                        // Skip over the Unknown/Other attributes
                        break;
            }
        }
    }
    
    if( result == STUN_RESULT_OK )
    {
        printf("\n\n----Result : Test Passed----\n\n");
    }
    else
    {
        printf("\n\n----Result : Test Failed----\nreturn Val : %d\n",result );
    }
    return 0;
}
